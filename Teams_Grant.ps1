#####################################################
# HelloID-Conn-Prov-Target-Cura-ECD-Entitlement-Grant
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
            grant_type        = 'urn:ietf:params:oauth:grant-type:token-exchange'
            client_id         = $config.ClientId
            client_secret     = $config.ClientSecret
            organisationId    = $config.OrganisationId
            environment       = $config.Environment
            audience          = $config.Audience
            requested_subject = $config.RequestedSubject
        }
        $response = Invoke-RestMethod $config.TokenUrl -Method 'POST' -Headers $tokenHeaders -Body $body -Verbose:$false
        Write-Output $response.access_token
    }
    catch {
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
        $headers.Add('Accept', 'application/json; charset=utf-8')
        $headers.Add('Content-Type', 'application/json; charset=utf-8')
        $headers.Add('Authorization', "Bearer $token")
        Write-Output $headers
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

#endregion
try {
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    foreach ($employee in $aRef) {
        try {
            [array]$contractsinScope = ($p.contracts | Select-Object -Property  *, $contractCustomProperty ) | Where-Object  $contractCustomProperty -eq $employee.EmployeeId | Where-Object { $_.Context.InConditions -eq $true }
            if ($contractsinScope.length -eq 0) {
                Write-Verbose -Verbose "Account reference: [$($employee.EmployeeId)] not in in scope. It will be skipped."
                continue
            }
            $splatRequestUser = @{
                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($employee.EmployeeId)"
                Method  = 'GET'
                Headers = $headers
            }
            Write-Verbose "Getting employee with code [$($employee.UserId)]"
            $user = Invoke-RestMethod @splatRequestUser -UseBasicParsing -Verbose:$false

            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Grant Cura-ECD Team entitlement: [$($pRef.name)] to: [$($p.DisplayName)] will be executed during enforcement"
            }
        
            if (-not($dryRun -eq $true)) {
                Write-Verbose "Granting Cura-ECD Team entitlement: [$($pRef.name)] for employee: [$($employee.EmployeeId)]"
                $newTeam = [PSCustomObject]@{
                    id        = $pRef.id
                    startdate = (Get-Date -f "yyyy-MM-dd")
                }

                if (![bool]($user[0].PSobject.Properties.name -match "team")) {
                    $user[0] | Add-Member -NotePropertyName team -NotePropertyValue $null
                }
    
                if ($null -eq $user[0].team -Or -not($user[0].team.id -Contains $newTeam.id )) {
                    $user[0].team += $newTeam
                
                    $splatRequestUpdateUser = @{
                        Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                        Method  = 'PATCH'
                        Headers = $headers
                        Body    = ($user[0] | ConvertTo-Json -Depth 10)
                    }
                    $null = Invoke-RestMethod @splatRequestUpdateUser -UseBasicParsing -Verbose:$false

                    $auditLogs.Add([PSCustomObject]@{
                        Message = "Employee: [$($employee.EmployeeId)], Grant Cura-ECD Team entitlement: [$($pRef.name)] was successful"
                        IsError = $false
                    })
                }
                else {
                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Employee: [$($employee.EmployeeId)] Grant Cura-ECD team entitlement: [$($pRef.name)]. Already present"
                            IsError = $false
                        })
                }
                $subPermissions.Add(
                    [PSCustomObject]@{
                        DisplayName = "[$($employee.EmployeeId)][$($pRef.Name)]"
                    }
                )
            }
        }
        catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($employee.EmployeeId)] Could not Grant Cura-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($employee.EmployeeId)] Could not Grant Cura-ECD Team entitlement. Error: $($errorObj.FriendlyMessage)"
                    IsError = $true
                })
        }
    }
    if (-not ($auditLogs.isError -contains $true)) {
        $success = $true
    }
}
catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not Grant Cura-ECD Team entitlement. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Grant Cura-ECD Team entitlement entitlement.Error: $($errorObj.FriendlyMessage)"

            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        Success        = $success
        Auditlogs      = $auditLogs
        SubPermissions = $subPermissions
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}