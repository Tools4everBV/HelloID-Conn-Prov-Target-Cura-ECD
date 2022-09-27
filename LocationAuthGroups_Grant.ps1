####################################################################
# HelloID-Conn-Prov-Target-CuraECD-Entitlement-GranLocationAuthGroup
#
# Version: 1.0.0
####################################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
$subPermissions = [System.Collections.Generic.List[PSCustomObject]]::new()

# Connector Configuration for pointing to the Cura Custom Contract Property
$contractCustomProperty = { $_.Custom.CuraECDEmploymentIdentifier }
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
#endregion

try {
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
                Write-Verbose "Account Reference [$($employment.EmployeeId)] not in Conditions. It will be Skipped.."
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
                throw "A user with usercode [$($employment.UserId)] could not be found"
            }

            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Grant CuraECD locationAuthGroup entitlement: [$($pRef.Name)] to: [$($p.DisplayName)] will be executed during enforcement"
            }

            if (-not($dryRun -eq $true)) {
                Write-Verbose "Granting CuraECD locationAuthGroup entitlement: [$($pRef.Name)]"
                $desiredLocationAuthGroups = [System.Collections.Generic.List[object]]::new()
                if ($responseUser[0].locationauthorisationgroup.Length -gt 0) {
                    Write-Verbose 'Adding currently assigned locationAuthGroups'
                    $desiredLocationAuthGroups.AddRange($responseUser[0].locationauthorisationgroup)
                }
                Write-Verbose 'Adding new locationAuthGroup to the list'
                $newLocationAuthGroup = @{
                    code = $pRef.Code
                }

                if ($desiredLocationAuthGroups.code -contains $newLocationAuthGroup.code) {
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "[$($employment.UserId)] Grant Cura-ECD locationAuthGroup entitlement: [$($pRef.Name)]. Already present"
                            IsError = $false
                        })
                } else {
                    $desiredLocationAuthGroups.Add($newLocationAuthGroup)
                    if (-not  [bool]($responseUser[0].PSobject.Properties.Name -match 'locationauthorisationgroup')) {
                        $responseUser[0] | Add-Member -NotePropertyMembers @{
                            locationauthorisationgroup = $null
                        }
                    }
                    $responseUser[0].locationauthorisationgroup = $desiredLocationAuthGroups

                    $splatPatchUserParams = @{
                        Uri     = "$($config.BaseUrl)/users/user"
                        Method  = 'PATCH'
                        Headers = $headers
                        Body    = ($responseUser[0] | ConvertTo-Json -Depth 10)
                    }
                    $responseUser = Invoke-RestMethod @splatPatchUserParams -UseBasicParsing -Verbose:$false
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "[$($employment.UserId)] Grant Cura-ECD locationAuthGroup entitlement: [$($pRef.Name)] was successful"
                            IsError = $false
                        })
                }
                $subPermissions.Add(
                    [PSCustomObject]@{
                        DisplayName = "[$($employment.UserId)] [$($pRef.Name)]"
                    }
                )
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employment.UserId)] Could not Grant Cura-ECD locationAuthGroup entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employment.UserId)] Could not Grant Cura-ECD locationAuthGroup entitlement. Error: $($errorObj.FriendlyMessage)"
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
    Write-Verbose "Could not Grant Cura-ECD locationAuthGroup entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Cura-ECD locationAuthGroup entitlement.Error: $($errorObj.FriendlyMessage)"
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
