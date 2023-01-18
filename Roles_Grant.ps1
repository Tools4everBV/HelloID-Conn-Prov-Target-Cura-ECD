########################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-GrantRole
#
# Version: 1.0.0
########################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
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
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Content-Type', 'application/x-www-form-urlencoded')
        $body = @{
            grant_type        = 'urn:ietf:params:oauth:grant-type:token-exchange'
            client_id         = $config.ClientId
            client_secret     = $config.ClientSecret
            organisationId    = $config.OrganisationId
            environment       = $config.Environment
            audience          = $config.Audience
            requested_subject = $config.RequestedSubject
        }
        $response = Invoke-RestMethod $config.TokenUrl -Method 'POST' -Headers $headers -Body $body -Verbose:$false
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
    $headers.Add('Accept', 'application/json; charset=utf-8')
    $headers.Add('Content-Type', 'application/json; charset=utf-8')
    $headers.Add('Authorization', "Bearer $accessToken")

    foreach ($employment in $aRef) {
        try {
            [array]$contractsinScope = ($p.contracts | Select-Object -Property  *, $contractCustomProperty ) | Where-Object  $contractCustomProperty -eq $employment.EmployeeId | Where-Object { $_.Context.InConditions -eq $true }
            if ($contractsinScope.length -eq 0) {
                Write-Verbose "Account reference [$($employment.EmployeeId)] not in Scope... Skipping."
                continue
            }

            Write-Verbose "Getting user with usercode [$($employment.UserId)]"
            $splatParams = @{
                Uri     = "$($config.BaseUrl)/users/user?usercode=$($employment.UserId)"
                Method  = 'GET'
                Headers = $headers
            }
            $responseUser = Invoke-RestMethod @splatParams -Verbose:$false
            if ($responseUser.Length -eq 0) {
                throw "A user with usercode [$($employment.userId)] could not be found"
            }

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

            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                if ($config.UseMappingSelectionAuthorisationGroup) {
                    Write-Warning "[DryRun] [$($employment.UserId)] Grant Fierit-ECD role entitlement: [$($pRef.Name) | $mappedSelectionAuthorisationGroupCode] to: [$($p.DisplayName)] will be executed during enforcement"
                } else {
                    Write-Warning "[DryRun] [$($employment.UserId)] Grant Fierit-ECD role entitlement: [$($pRef.Name)] to: [$($p.DisplayName)] will be executed during enforcement"
                }
            }

            if (-not($dryRun -eq $true)) {
                Write-Verbose "Granting Fierit-ECD role entitlement: [$($pRef.Name)]"
                $desiredRoles = [System.Collections.Generic.List[object]]::new()

                if ($responseUser[0].Role.Length -gt 0) {
                    Write-Verbose 'Adding currently assigned role(s)'
                    $desiredRoles.AddRange($responseUser[0].Role)
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
                    $responseUser[0].role = $desiredRoles

                    $splatPatchUserParams = @{
                        Uri     = "$($config.BaseUrl)/users/user"
                        Method  = 'PATCH'
                        Headers = $headers
                        Body    = ($responseUser[0] | ConvertTo-Json -Depth 10)
                    }
                    $responseUser = Invoke-RestMethod @splatPatchUserParams -UseBasicParsing -Verbose:$false

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
                    }
                )
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
} catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not Grant Fierit-ECD Role entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Fierit-ECD Role entitlement. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success        = $success
        Auditlogs      = $auditLogs
        SubPermissions = $subPermissions
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
