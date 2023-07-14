########################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-GrantRole
#
# Version: 1.0.2
########################################################
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

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.IsDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Added due to a bug in HelloId, when the toggle is not switched it returns null
if ($null -eq $config.UseMappingSelectionAuthorisationGroup) {
    $config.UseMappingSelectionAuthorisationGroup = $false
}

# Required for Selection Authorisation Group mapping.
$mappingLookupProperty1 = { $_.Department.ExternalId }
$mappingLookupProperty2 = { $_.Title.ExternalId }  # Optional

$contractCustomProperty = { $_.Custom.FieritECDEmploymentIdentifier }

# Primary Contract Calculation foreach employment.
$firstProperty = @{ Expression = { $_.Details.Fte } ; Descending = $true }
$secondProperty = @{ Expression = { $_.Details.HoursPerWeek }; Descending = $true }
# Priority Calculation Order (High priority -> Low priority)
$splatSortObject = @{
    Property = @(
        $firstProperty,
        $secondProperty
        #etc..
    )
}

#region functions
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

function Get-FieritSAGroupFromHelloIDContract {
    [Cmdletbinding()]
    param(
        [parameter(Mandatory)]
        $ContractLookupField1,

        $ContractLookupField2,

        [parameter(Mandatory)]
        $Contract,

        $Mapping,

        [string]
        $MappingColumnName1,

        [string]
        $MappingColumnName2
    )
    try {
        $tableLookupValue1 = ($contract | Select-Object $ContractLookupField1).$ContractLookupField1

        if ($null -eq $tableLookupValue1) {
            throw "Calculation error. No results when filtering contracts in scope [$($contract.count)] on Header [$MappingColumnName1] Value [$ContractLookupField1]"
        }
        $tableLookupValue2 = ($contract | Select-Object $ContractLookupField2).$ContractLookupField2
        Write-Verbose "Values found in Contract [$ContractLookupField1 | $tableLookupValue1] and [$ContractLookupField2 | $tableLookupValue2]"
        if ($null -ne $ContractLookupField2) {
            if ($null -eq $tableLookupValue2) {
                throw "Calculation error. No results when filtering contracts in scope [$($contract.count)] on Header [$MappingColumnName2] Value [$ContractLookupField2]"
            }
            $result = $Mapping | Where-Object {
                (
                    $_.$MappingColumnName1 -eq $tableLookupValue1 -and
                    $_.$MappingColumnName2 -eq $tableLookupValue2 ) -or
                (
                    $_.$MappingColumnName1 -eq $tableLookupValue1 -and
                    [string]::IsNullOrEmpty($_.$MappingColumnName2 )
                )
            }
        } else {
            $result = $Mapping | Where-Object {
                (
                    $_.$MappingColumnName1 -eq $tableLookupValue1
                )
            }
        }
        if ($null -eq $result) {
            throw "Calculation error. No entry found in the CSV file for [$ContractLookupField1]: [$tableLookupValue1] and [$ContractLookupField2] : [$tableLookupValue2]? (Second is optional)"
        }
        if ($result.Length -gt 1) {
            throw  "Calculation error. Multiple mappings found for [$ContractLookupField1]: [$tableLookupValue1] and [$ContractLookupField2] : [$tableLookupValue2]? (Second is optional)"
        }
        Write-Output $result
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
            $utf8Encoding = [System.Text.Encoding]::UTF8
            $encodedBody = $utf8Encoding.GetBytes($body)
            $splatWebRequest['Body'] = $encodedBody
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
    Write-Verbose 'Get Contracts InConditions'
    [array]$contractsInConditions = $p.Contracts | Where-Object { $_.Context.InConditions -eq $true }
    $contractsInConditionsGrouped = $contractsInConditions | Group-Object -Property $contractCustomProperty -AsHashTable -AsString
    if ($contractsInConditions.length -lt 1) {
        Write-Verbose 'No Contracts in scope [InConditions] found!' -Verbose
        throw 'No Contracts in scope [InConditions] found!'
    }

    if ($config.UseMappingSelectionAuthorisationGroup) {
        Write-Verbose "Retreive external Mapping file for Selection Authorisation Group [$($config.MappingSelectionAuthGroupFileLocation)]"
        [array]$mappingSelectionAuthGroups = Import-Csv "$($config.MappingSelectionAuthGroupFileLocation)" -Delimiter $config.csvDelimiter
        if ($null -eq $mappingSelectionAuthGroups -or $mappingSelectionAuthGroups.count -lt 1) {
            throw 'Selection Authorisation Group mapping Not Found!'
        }
    }

    Write-Verbose 'Setting authorization header'
    $accessToken = Get-AccessToken
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    #$headers.Add('Accept', 'application/json; charset=utf-8')
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization', "Bearer $accessToken")
    $headers.Add('callingParty', 'Tools4ever')
    $headers.Add('callingApplication', 'HelloID')

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
                Message = "[Warning] Fierit-ECD Roles entitlement [$($pRef.Name)] cannot be granted for account(s) [$( $aRefNotFound -join ', ')], Due to a missing dependency: No HelloId Account reference found. (See Readme)"
                IsError = $true
            })
    }


    foreach ($employment in $aRef) {
        try {
            $action = 'grant'
            [array]$contractsinScope = ($p.contracts | Select-Object -Property  *, $contractCustomProperty ) | Where-Object  $contractCustomProperty -eq $employment.EmployeeId | Where-Object { $_.Context.InConditions -eq $true }
            if ($contractsinScope.length -eq 0) {
                # account out of scope
                if ($employment.userid -notin $eRef.CurrentPermissions.Reference.UserExternalId ) {
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
            $responseUser = Invoke-FieritWebRequest @splatParams -UseBasicParsing
            if ($null -eq $responseUser){
                throw "A user with usercode [$($employment.userId)] could not be found"
            }

            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                if ($config.UseMappingSelectionAuthorisationGroup) {
                    Write-Warning "[DryRun] [$($employment.UserId)] $action Fierit-ECD role entitlement: [$($pRef.Name) | $mappedSelectionAuthorisationGroupCode] to: [$($p.DisplayName)] will be executed during enforcement"
                } else {
                    Write-Warning "[DryRun] [$($employment.UserId)] $action Fierit-ECD role entitlement: [$($pRef.Name)] to: [$($p.DisplayName)] will be executed during enforcement"
                }
            }

            if (-not($dryRun -eq $true)) {
                switch ($action ) {
                    'grant' {
                        Write-Verbose "Granting Fierit-ECD role entitlement: [$($pRef.Name)]"
                        if ($config.UseMappingSelectionAuthorisationGroup) {
                            Write-Verbose "Calculate primary contract for Employment [$($employment.EmployeeId)]"
                            $primaryContract = $contractsInConditionsGrouped[$employment.EmployeeId] | Sort-Object @splatSortObject  | Select-Object -First 1

                            $splat = @{
                                ContractLookupField1 = $mappingLookupProperty1
                                ContractLookupField2 = $mappingLookupProperty2
                                Contract             = $primaryContract
                                Mapping              = $mappingSelectionAuthGroups
                                MappingColumnName1   = 'department.id'
                                MappingColumnName2   = 'title.id'
                            }
                            $mappedSelectionAuthorisationGroupCode = (Get-FieritSAGroupFromHelloIDContract @splat).FieritSelectionAuthorisationGroup
                        }


                        $desiredRoles = [System.Collections.Generic.List[object]]::new()

                        if ($responseUser.Role.Length -gt 0) {
                            Write-Verbose 'Adding currently assigned role(s)'
                            $desiredRoles.AddRange($responseUser.Role)
                        }

                        # Can be Enabled to remove the default role when present
                        # if ($desiredRoles.id -contains "$($config.DefaultTeamAssignmentGuid)") {
                        #     Write-Verbose "Removing Default Role [$($config.DefaultTeamAssignmentGuid)]"
                        #     $roleToRemove = $desiredRoles | Where-Object { $_.id -eq $($config.DefaultTeamAssignmentGuid) }
                        #     $desiredRoles.Remove($roleToRemove)
                        # }

                        Write-Verbose 'Adding new role to the list'
                        $newRole = @{
                            id        = $pRef.Id
                            startdate = (Get-Date).ToString('yyyy-MM-dd')
                            enddate   = $null
                        }

                        $existingRole = $null
                        $existingRole = $desiredRoles | Where-Object { $_.id -eq $newRole.id }
                        if ( $null -ne $existingRole -and $config.UseMappingSelectionAuthorisationGroup -eq $false) {
                            $auditMessage = "Grant Fierit-ECD role entitlement: [$($pRef.Name)]. Already present"

                        } elseif (($null -ne $existingRole) -and (($config.UseMappingSelectionAuthorisationGroup -eq $true) -and ($existingRole.selectionauthorisationgroup.code -eq $mappedSelectionAuthorisationGroupCode))) {
                            $auditMessage = "Grant Fierit-ECD role entitlement: [$($pRef.Name)]. Already present with correct SelectionAuthorisationGroup"

                        } else {
                            if ($config.UseMappingSelectionAuthorisationGroup) {
                                $null = $desiredRoles.Remove($existingRole)

                                Write-Verbose "Adding SelectionAuthorisationGroup [$mappedSelectionAuthorisationGroupCode] to Role"
                                $newRole['selectionauthorisationgroup'] = @{
                                    code = $mappedSelectionAuthorisationGroupCode
                                }
                            }
                            $desiredRoles.Add($newRole)
                            $responseUser.role = $desiredRoles

                            $splatPatchUserParams = @{
                                Uri     = "$($config.BaseUrl)/users/user"
                                Method  = 'PATCH'
                                Headers = $headers
                                Body    = ($responseUser | ConvertTo-Json -Depth 10)
                            }
                            $responseUser = Invoke-FieritWebRequest @splatPatchUserParams -UseBasicParsing

                            if ($config.UseMappingSelectionAuthorisationGroup) {
                                $auditMessage = "Grant Fierit-ECD role entitlement: [$($pRef.Name)] with Selection Group [$mappedSelectionAuthorisationGroupCode] was successful"
                            } else {
                                $auditMessage = "Grant Fierit-ECD role entitlement: [$($pRef.Name)] was successful"
                            }
                        }
                        $auditLogs.Add([PSCustomObject]@{
                                Message = "[$($employment.UserId)] $auditMessage"
                                IsError = $false
                            })

                        if ($config.UseMappingSelectionAuthorisationGroup) {
                            $subPermissionDisplayName = "[$($employment.UserId)] [$($pRef.Name)] [$mappedSelectionAuthorisationGroupCode]"
                        } else {
                            $subPermissionDisplayName = "[$($employment.UserId)] [$($pRef.Name)]"
                        }

                        $subPermissions.Add(
                            [PSCustomObject]@{
                                DisplayName = $subPermissionDisplayName
                                Reference   = [PSCustomObject]@{
                                    Id             = $subPermissionDisplayName
                                    UserExternalId = "$($employment.UserId)"
                                }
                            }
                        )
                    }
                    'revoke' {
                        if (($responseUser.Role.Length -eq 0) -or (($responseUser.Role.id -notcontains $pRef.id))) {
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD Role entitlement: [$($pRef.Name)]. Already removed"
                        } else {
                            Write-Verbose 'Creating list of currently assigned roles'
                            $currentRoles = [System.Collections.Generic.List[object]]::new()
                            $currentRoles.AddRange($responseUser.Role)

                            Write-Verbose 'Removing role from the list'
                            $roleToRemove = $currentRoles | Where-Object { $_.id -eq $pRef.id }
                            [void]$currentRoles.Remove($roleToRemove)
                            $responseUser.role = $currentRoles

                            Write-Verbose 'Adding default Role after revoking last Entitlements'
                            if ($responseUser.role.count -eq 0) {
                                $responseUser.role = @(
                                    @{
                                        id        = "$($config.DefaultTeamAssignmentGuid)"
                                        startdate = (Get-Date -f 'yyyy-MM-dd')
                                        enddate   = $null
                                    }
                                )
                            }

                            $splatPatchUserParams = @{
                                Uri     = "$($config.BaseUrl)/users/user"
                                Method  = 'PATCH'
                                Body    = ($responseUser | ConvertTo-Json -Depth 10)
                                Headers = $headers
                            }
                            $responseUser = Invoke-FieritWebRequest @splatPatchUserParams -UseBasicParsing
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD role entitlement: [$($pRef.Name)] was successful"
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
            Write-Verbose "[$($employment.UserId)] Could not Grant Fierit-ECD Role entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employment.UserId)] Could not Grant Fierit-ECD Role entitlement. Error: $($errorObj.FriendlyMessage)"
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
    Write-Verbose "Could not Grant Fierit-ECD Role entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Fierit-ECD Role entitlement. Error: $($errorObj.FriendlyMessage)"
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
