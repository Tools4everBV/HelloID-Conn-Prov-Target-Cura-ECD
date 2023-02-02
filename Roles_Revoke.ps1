#########################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-RevokeRole
#
# Version: 1.0.0
#########################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

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
#endregion

try {
    Write-Verbose 'Setting authorization header'
    $accessToken = Get-AccessToken
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    #$headers.Add('Accept', 'application/json; charset=utf-8')
    $headers.Add('Content-Type', 'application/json')
    $headers.Add('Authorization', "Bearer $accessToken")

    foreach ($employment in $aRef) {
        try {
            Write-Verbose "Getting user with usercode [$($employment.UserId)]"
            $splatParams = @{
                Uri     = "$($config.BaseUrl)/users/user?usercode=$($employment.UserId)"
                Method  = 'GET'
                Headers = $headers
            }
            $responseUser = Invoke-RestMethod @splatParams -Verbose:$false
            if ($responseUser.Length -eq 0) {
                $userFound = 'NotFound'
                if ($dryRun -eq $true) {
                    Write-Warning "[DryRun] [$($employment.UserId)] Fierit-ECD account not found. Possibly already deleted, skipping action."
                }
            } else {
                $userFound = 'Found'
            }

            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] [$($employment.UserId)] Revoke Fierit-ECD role entitlement: [$($pRef.Name)] to: [$($p.DisplayName)] will be executed during enforcement"
            }

            if (-not($dryRun -eq $true)) {
                switch ($userFound) {
                    'Found' {
                        Write-Verbose "Revoking Fierit-ECD role entitlement: [$($pRef.Name)]"

                        if (($responseUser[0].Role.Length -eq 0) -or (($responseUser[0].Role.id -notcontains $pRef.id))) {
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD Role entitlement: [$($pRef.Name)]. Already removed"
                        } else {
                            Write-Verbose 'Creating list of currently assigned roles'
                            $currentRoles = [System.Collections.Generic.List[object]]::new()
                            $currentRoles.AddRange($responseUser[0].Role)

                            Write-Verbose 'Removing role from the list'
                            $roleToRemove = $currentRoles | Where-Object { $_.id -eq $pRef.id }
                            [void]$currentRoles.Remove($roleToRemove)
                            $responseUser[0].role = $currentRoles

                            Write-Verbose 'Adding default Role after revoking last Entitlements'
                            if ($responseUser[0].role.count -eq 0) {
                                $responseUser[0].role = @(
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
                                Body    = ($responseUser[0] | ConvertTo-Json -Depth 10)
                                Headers = $headers
                            }
                            $responseUser = Invoke-RestMethod @splatPatchUserParams -UseBasicParsing -Verbose:$false
                            $auditMessage = "[$($employment.UserId)] Revoke Fierit-ECD role entitlement: [$($pRef.Name)] was successful"
                        }
                        $auditLogs.Add([PSCustomObject]@{
                                Message = $auditMessage
                                IsError = $false
                            })
                    }
                    'NotFound' {
                        $auditLogs.Add([PSCustomObject]@{
                                Message = "[$($employment.UserId)] Fierit-ECD account not found. Possibly already deleted, skipping action."
                                IsError = $false
                            })
                    }
                }
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employment.UserId)] Could not Revoke Fierit-ECD Role entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employment.UserId)] Could not Revoke Fierit-ECD Role entitlement. Error: $($errorObj.FriendlyMessage)"
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
    Write-Verbose "Could not Revoke Fierit-ECD Role entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Revoke Fierit-ECD Role entitlement. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
