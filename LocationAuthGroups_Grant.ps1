####################################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-GranLocationAuthGroup
#
# Version: 1.0.0
####################################################################
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
function Get-AccessToken {
    [CmdletBinding()]
    param ()
    try {
        $tokenHeaders = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $tokenHeaders.Add('Content-Type', 'application/x-www-form-urlencoded')
        $body = @{
            grant_type     = 'client_credentials'#'urn:ietf:params:oauth:grant-type:token-exchange'
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

#endregion

try {
    Write-Verbose 'Setting authorization header'
    $accessToken = Get-AccessToken
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    #$headers.Add('Accept', 'application/json; charset=utf-8')
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization', "Bearer $accessToken")


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
                Message = "[Warning] Fierit-ECD locationAuthGroup entitlement [$($pRef.Name)] cannot be granted for account(s) [$( $aRefNotFound -join ', ')], Due to a missing dependency: No HelloId Account reference found. (See Readme)"
                IsError = $true
            })
    }

    foreach ($employment in $aRef) {
        try {
            $action = 'grant'
            [array]$contractsinScope = ($p.contracts | Select-Object -Property  *, $contractCustomProperty ) | Where-Object  $contractCustomProperty -eq $employment.EmployeeId | Where-Object { $_.Context.InConditions -eq $true }
            if ($contractsinScope.length -eq 0) {
                # account out of scope
                if ($employment.userid -notin $eRef.CurrentPermissions.Reference.UserExternalId) {
                    Write-Verbose "Account Reference [$($employment.EmployeeId)] not in Conditions. It will be Skipped.."
                    $action = 'skip'
                    continue
                } else {
                    $action = 'revoke'
                }
            }

            Write-Verbose "Getting user with usercode [$($employment.UserId)]"
            $splatParams = @{
                Uri     = "$($config.BaseUrl)/users/user?usercode=$($employment.UserId)"
                Method  = 'GET'
                Headers = $headers
            }
            $responseUser = Invoke-RestMethod @splatParams -Verbose:$false
            if ($responseUser.Length -eq 0) {
                throw "A user with usercode [$($employment.UserId)] could not be found"
            }
            $existingUser = $responseUser[0]

            $desiredLocationAuthGroups = [System.Collections.Generic.List[object]]::new()
            if ($existingUser.locationauthorisationgroup.Length -gt 0) {
                Write-Verbose 'Adding currently assigned locationAuthGroups'
                $desiredLocationAuthGroups.AddRange($existingUser.locationauthorisationgroup)
            }


            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] $action Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)] to: [$($p.DisplayName)] will be executed during enforcement"
            }

            if (-not($dryRun -eq $true)) {
                switch ($action ) {
                    'grant' {
                        Write-Verbose "Granting Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)]"
                        if ($desiredLocationAuthGroups.code -contains $pRef.code) {
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "[$($employment.UserId)] Grant Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)]. Already present"
                                    IsError = $false
                                })
                        } else {
                            Write-Verbose 'Adding new locationAuthGroup to the list'
                            if (-not  [bool]($existingUser.PSobject.Properties.Name -match 'locationauthorisationgroup')) {
                                $existingUser | Add-Member -NotePropertyMembers @{
                                    locationauthorisationgroup = $null
                                }
                            }
                            $newLocationAuthGroup = @{
                                code = $pRef.Code
                            }
                            $desiredLocationAuthGroups.Add($newLocationAuthGroup)

                            $existingUser.locationauthorisationgroup = $desiredLocationAuthGroups

                            $splatPatchUserParams = @{
                                Uri     = "$($config.BaseUrl)/users/user"
                                Method  = 'PATCH'
                                Headers = $headers
                                Body    = ($existingUser | ConvertTo-Json -Depth 10)
                            }
                            $null = Invoke-RestMethod @splatPatchUserParams -UseBasicParsing -Verbose:$false
                            $auditLogs.Add([PSCustomObject]@{
                                    Message = "[$($employment.UserId)] Grant Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)] was successful"
                                    IsError = $false
                                })
                        }
                        $subPermissions.Add(
                            [PSCustomObject]@{
                                DisplayName = "[$($employment.UserId)] [$($pRef.Name)]"
                                Reference   = [PSCustomObject]@{
                                    Id             = "$($employment.UserId)-$($pRef.Name)"
                                    UserExternalId = "$($employment.UserId)"
                                }
                            }
                        )
                    }
                    'revoke' {
                        if (($existingUser.locationauthorisationgroup.Length -eq 0) -or
                            ($existingUser.locationauthorisationgroup.code -notcontains $pRef.code)) {
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)]. Already removed"
                        } else {
                            $null = $desiredLocationAuthGroups.Remove(($desiredLocationAuthGroups | Where-Object { $_.code -eq $pRef.code }))
                            $existingUser.locationauthorisationgroup = $desiredLocationAuthGroups
                            if ($existingUser.locationauthorisationgroup.count -eq 0) {
                                $existingUser.locationauthorisationgroup = $null
                            }
                            $splatPatchUserParams = @{
                                Uri     = "$($config.BaseUrl)/users/user"
                                Method  = 'PATCH'
                                Headers = $headers
                                Body    = ($existingUser | ConvertTo-Json -Depth 10)
                            }
                            $null = Invoke-RestMethod @splatPatchUserParams -UseBasicParsing -Verbose:$false
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD locationAuthGroup entitlement: [$($pRef.Name)] was successful"
                        }
                        $auditLogs.Add([PSCustomObject]@{
                                Message = $auditMessage
                                IsError = $false
                            })
                    }
                }
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employment.UserId)] Could not Grant Fierit-ECD locationAuthGroup entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employment.UserId)] Could not Grant Fierit-ECD locationAuthGroup entitlement. Error: $($errorObj.FriendlyMessage)"
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
    Write-Verbose "Could not Grant Fierit-ECD locationAuthGroup entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Fierit-ECD locationAuthGroup entitlement.Error: $($errorObj.FriendlyMessage)"
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
