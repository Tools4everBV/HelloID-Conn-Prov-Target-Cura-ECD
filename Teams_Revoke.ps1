#####################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Entitlement-Revoke
#
# Version: 1.0.0
#####################################################
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
            }
            else {
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
        }
        else {
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
    }
    catch {
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
    foreach ($employee in $aRef) {
        try {
            $splatRequestUser = @{
                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($employee.EmployeeId)"
                Method  = 'GET'
                Headers = $headers
            }
            Write-Verbose "Getting employee with code [$($employee.EmployeeId)]"
            $user = Invoke-FieritWebRequest @splatRequestUser -UseBasicParsing

            if ($null -eq $user) {
                $userFound = 'NotFound'
                if ($dryRun -eq $true) {
                    Write-Warning "[DryRun] [$($employee.EmployeeId)] Fierit-ECD account not found. Possibly already deleted, skipping action."
                }
            }
            else {
                $userFound = 'Found'
            }

            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Revoke Fierit-ECD Team entitlement: [$($pRef.name)] from: [$($p.DisplayName)] will be executed during enforcement"
            }

            if (-not($dryRun -eq $true)) {
                switch ($userFound) {
                    'Found' {
                        Write-Verbose "Revoking Fierit-ECD Team entitlement: [$($pRef.name)] for employee: [$($employee.EmployeeId)]"

                        $removeTeam = [PSCustomObject]@{
                            id = $pRef.id
                        }

                        if ($user.team.id -Contains $removeTeam.id) {
                            $user.team = [array]($user.team | Where-Object { $_.id –ne $removeTeam.id })

                            if ($null -eq $user.team) {
                               $null =  $user.PSObject.Properties.Remove('team')
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
                        }
                        else
                        {
                            $auditLogs.Add([PSCustomObject]@{
                                Message = "Employee: [$($employee.EmployeeId)], Revoke Fierit-ECD Team entitlement: [$($pRef.name)] Already removed."
                                IsError = $false
                            })
                        }
                    }
                    'NotFound' {
                        $auditLogs.Add([PSCustomObject]@{
                                Message = "[$($employee.EmployeeId)] Fierit-ECD account not found. Possibly already deleted, skipping action."
                                IsError = $false
                            })
                    }
                }
            }
        }
        catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employee.EmployeeId)] Could not Revoke Fierit-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employee.EmployeeId)] Could not Revoke Fierit-ECD Team entitlement. Error: $($errorObj.FriendlyMessage)"
                    IsError = $true
                })
        }
        if (-not ($auditLogs.isError -contains $true)) {
            $success = $true
        }
    }
}
catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not Revoke Fierit-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Revoke Fierit-ECD Team entitlement. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
}

finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Auditlogs = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}