#####################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-Grant
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$eRef = $entitlementContext | ConvertFrom-Json

$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
$auditLogsWarning = [System.Collections.Generic.List[PSCustomObject]]::new()
$subPermissions = [System.Collections.Generic.List[PSCustomObject]]::new()
# Connector Configuration for pointing to the Fierit Custom Contract Property
$contractCustomProperty = { $_.Custom.FieritECDEmploymentIdentifier }

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

#region functions
function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = ''
            FriendlyMessage  = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -eq $ErrorObject.Exception.Response) {
                $httpErrorObj.ErrorDetails = $ErrorObject.Exception.Message
                $httpErrorObj.FriendlyMessage = $ErrorObject.Exception.Message
            } else {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                $httpErrorObj.ErrorDetails = "$($ErrorObject.Exception.Message) $streamReaderResponse"
                if ($null -ne $streamReaderResponse) {
                    $errorResponse = ( $streamReaderResponse | ConvertFrom-Json)
                    $httpErrorObj.FriendlyMessage = switch ($errorResponse) {
                        { $_.error_description } { $errorResponse.error_description }
                        { $_.issue.details } { $errorResponse.issue.details }
                        { $_.error.message } { "Probably OrganisationId or Environment not found: Error: $($errorResponse.error.message)" }
                        default { ($errorResponse | ConvertTo-Json) }
                    }
                }
            }
        } else {
            $httpErrorObj.ErrorDetails = $ErrorObject.Exception.Message
            $httpErrorObj.FriendlyMessage = $ErrorObject.Exception.Message
        }
        Write-Output $httpErrorObj
    }
}

function Get-AccessToken {
    [CmdletBinding()]
    param ()
    try {
        $tokenHeaders = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $tokenHeaders.Add('Content-Type', 'application/x-www-form-urlencoded')
        $body = @{
            grant_type     = 'client_credentials'
            client_id      = $config.ClientId
            client_secret  = $config.ClientSecret
            organisationId = $config.OrganisationId
            environment    = $config.Environment
        }
        $response = Invoke-RestMethod $config.TokenUrl -Method 'POST' -Headers $tokenHeaders -Body $body -Verbose:$false
        Write-Output $response.access_token
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Set-AuthorizationHeaders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Token
    )
    try {
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        #$headers.Add('Accept', 'application/json; charset=utf-8')
        $headers.Add('Content-Type', 'application/json')
        $headers.Add('Authorization', "Bearer $token")

        Write-Output $headers
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Compare-Join {
    [OutputType([array], [array], [array])] # $Left , $Right, $common
    param(
        [parameter()]
        [string[]]$ReferenceObject,

        [parameter()]
        [string[]]$DifferenceObject
    )
    if ($null -eq $DifferenceObject) {
        $Left = $ReferenceObject
    } elseif ($null -eq $ReferenceObject ) {
        $right = $DifferenceObject
    } else {
        $left = [string[]][Linq.Enumerable]::Except($ReferenceObject, $DifferenceObject)
        $right = [string[]][Linq.Enumerable]::Except($DifferenceObject, $ReferenceObject)
        $common = [string[]][Linq.Enumerable]::Intersect($ReferenceObject, $DifferenceObject)
    }
    Write-Output $Left.Where({ -not [string]::IsNullOrEmpty($_) }) , $Right, $common
}

function Confirm-BusinessRulesInputData {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $Contracts,

        [parameter(Mandatory)]
        $ContractReferenceProperty,


        [parameter()]
        $AccountReferences,


        [parameter()]
        $AccountReferencesReferenceProperty,

        [parameter()]
        [switch]
        $InConditions

    )
    try {
        if ($null -eq $AccountReferences) {
            throw  "No account Reference found. Shouldn't happen"
        }
        $desiredEmploymentList = ($Contracts | Select-Object -Property  *, $ContractReferenceProperty   | Where-Object { $_.Context.InConditions -eq $InConditions })

        Compare-Join -ReferenceObject $AccountReferences.$AccountReferencesReferenceProperty -DifferenceObject $desiredEmploymentList.$ContractReferenceProperty

    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-FieritWebRequest {
    [CmdletBinding()]
    param(
        [System.Uri]
        $Uri,

        [string]
        $Method = 'Get',

        $Headers,

        [switch]
        $UseBasicParsing,


        $body
    )
    try {
        $splatWebRequest = @{
            Uri             = $Uri
            Method          = $Method
            Headers         = $Headers
            UseBasicParsing = $UseBasicParsing
        }

        if ( -not [string]::IsNullOrEmpty( $body )) {
            $splatWebRequest['Body'] = $body
        }
        $rawResult = Invoke-WebRequest @splatWebRequest -Verbose:$false -ErrorAction Stop
        if ($null -ne $rawResult.Headers -and (-not [string]::IsNullOrEmpty($($rawResult.Headers['processIdentifier'])))) {
            Write-Verbose "WebCall executed. Successfull [URL: $($Uri.PathAndQuery) Method: $($Method) ProcessID: $($rawResult.Headers['processIdentifier'])]"
        }
        if ($rawResult.Content) {
            Write-Output ($rawResult.Content | ConvertFrom-Json )
        }
    } catch {
        if ($null -ne $_.Exception.Response.Headers -and (-not [string]::IsNullOrEmpty($($_.Exception.Response.Headers['processIdentifier'])))) {
            Write-Verbose "WebCall executed. Failed [URL: $($Uri.PathAndQuery) Method: $($Method) ProcessID: $($_.Exception.Response.Headers['processIdentifier'])]" -Verbose
        }
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion
try {
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    # Generate Audit logging which checks for incorrect BusinessRules Configuration
    $splatCofirm = @{
        Contracts                          = $p.Contracts
        ContractReferenceProperty          = $contractCustomProperty
        AccountReferences                  = $aRef
        AccountReferencesReferenceProperty = 'EmployeeId'
        InConditions                       = $true
    }

    $aRefNotInScope , $aRefNotFound, $aRefFound = Confirm-BusinessRulesInputData @splatCofirm

    if ($aRefNotFound) {
        $auditLogsWarning.Add([PSCustomObject]@{
                Message = "[Warning] Fierit-ECD Teams entitlement [$($pRef.Name)] cannot be granted for account(s) [$( $aRefNotFound -join ', ')], Due to a missing dependency: No HelloId Account reference found. (See Readme)"
                IsError = $true
            })
    }


    foreach ($employee in $aRef) {
        try {
            $action = 'grant'

            [array]$contractsinScope = ($p.contracts | Select-Object -Property  *, $contractCustomProperty ) | Where-Object  $contractCustomProperty -eq $employee.EmployeeId | Where-Object { $_.Context.InConditions -eq $true }
            if ($contractsinScope.length -eq 0) {
                # account out of scope
                if ($employee.EmployeeId -notin $eRef.CurrentPermissions.Reference.UserExternalId ) {
                    Write-Verbose "Account Reference [$($employee.EmployeeId)] not in Conditions. It will be Skipped.."
                    $action = 'skip'
                    continue
                } else {
                    $action = 'revoke'
                }
            }

            $splatRequestUser = @{
                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($employee.EmployeeId)"
                Method  = 'GET'
                Headers = $headers
            }

            Write-Verbose "Getting employee with code [$($employee.EmployeeId)]"
            $user = Invoke-FieritWebRequest @splatRequestUser -UseBasicParsing

            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] $action Fierit-ECD Team entitlement: [$($pRef.name)] to: [$($p.DisplayName)] will be executed during enforcement"
            }

            if (-not($dryRun -eq $true)) {
                switch ($action ) {
                    'grant' {
                        Write-Verbose "Granting Fierit-ECD Team entitlement: [$($pRef.name)] for employee: [$($employee.EmployeeId)]"
                        $newTeam = [PSCustomObject]@{
                            id        = $pRef.id
                            startdate = (Get-Date -f "yyyy-MM-dd")
                        }

                        if (![bool]($user.PSobject.Properties.name -match "team")) {
                            $user | Add-Member -NotePropertyName team -NotePropertyValue $null
                        }

                        if ($null -eq $user.team -Or -not($user.team.id -Contains $newTeam.id )) {
                            $user.team += $newTeam

                            $splatRequestUpdateUser = @{
                                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                                Method  = 'PATCH'
                                Headers = $headers
                                Body    = ($user | ConvertTo-Json -Depth 10)
                            }
                            $null = Invoke-FieritWebRequest @splatRequestUpdateUser -UseBasicParsing

                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Employee: [$($employee.EmployeeId)], Grant Fierit-ECD Team entitlement: [$($pRef.name)] was successful"
                                    IsError = $false
                                })
                        } else {
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Employee: [$($employee.EmployeeId)] Grant Fierit-ECD team entitlement: [$($pRef.name)]. Already present"
                                    IsError = $false
                                })
                        }
                        $subPermissions.Add(
                            [PSCustomObject]@{
                                DisplayName = "[$($employee.EmployeeId)][$($pRef.Name)]"
                                Reference   = [PSCustomObject]@{

                                    Id             = "[$($employee.EmployeeId)][$($pRef.Name)]"
                                    UserExternalId = "$($employee.EmployeeId)"
                                }
                            }
                        )
                    }
                    'Revoke' {
                        if ($user.team.id -Contains $pRef.id) {
                            $user.team = [array]($user.team | Where-Object { $_.id -ne $pRef.id })
                            if ($null -eq $user.team) {
                                $null = $user.PSObject.Properties.Remove('team')
                            }

                            $splatRequestUpdateUser = @{
                                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                                Method  = 'PATCH'
                                Headers = $headers
                                Body    = ($user | ConvertTo-Json -Depth 10)
                            }
                            $null = Invoke-FieritWebRequest @splatRequestUpdateUser -UseBasicParsing

                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Employee: [$($employee.EmployeeId)], Revoke Fierit-ECD Team entitlement: [$($pRef.name)] was successful"
                                    IsError = $false
                                })

                        } else {
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "Employee: [$($employee.EmployeeId)], Revoke Fierit-ECD Team entitlement: [$($pRef.name)] Already removed."
                                    IsError = $false
                                })
                        }
                    }
                }
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employee.EmployeeId)] Could not Grant Fierit-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employee.EmployeeId)] Could not Grant Fierit-ECD Team entitlement. Error: $($errorObj.FriendlyMessage)"
                    IsError = $true
                })
        }
    }
    if (-not ($auditLogs.isError -contains $true)) {
        $success = $true
    }
    $auditLogs.AddRange($auditLogsWarning)
} catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not Grant Fierit-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Fierit-ECD Team entitlement entitlement.Error: $($errorObj.FriendlyMessage)"

            IsError = $true
        })
} finally {
    # With a successful result. HelloId require always Subpermissions.
    if ( $subPermissions.count -eq 0 -and $success -eq $true) {
        $subPermissions.Add(
            [PSCustomObject]@{
                DisplayName = 'No Permissions'
                Reference   = [PSCustomObject]@{
                    id = 'No Permissions'
                }
            })
    }
    $result = [PSCustomObject]@{
        Success        = $success
        Auditlogs      = $auditLogs
        SubPermissions = $subPermissions
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}