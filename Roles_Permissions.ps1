#####################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-PermissionRoles
#
# Version: 1.0.0
#####################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json

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

    Write-Verbose 'Retrieving all roles'
    $splatParams = @{
        Uri     = "$($config.BaseUrl)/rootdata/roles?includehistory=true&cssrole=false"
        Method  = 'GET'
        Headers = $headers
    }
    $responseRoles = Invoke-RestMethod @splatParams -Verbose:$false
    foreach ($role in $responseRoles) {
        $returnObject = @{
            DisplayName    = "Role - $($role.name)"
            Identification = @{
                Id        = $role.id
                Name      = $role.name
                Code      = $role.code
                StartDate = $role.startdate
                EndDate   = $role.enddate
                Type      = 'Role'
            }
        }
        Write-Output $returnObject | ConvertTo-Json -Depth 10
    }
} catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not retrieve Fierit-ECD Role permissions. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not retrieve Fierit-ECD Role permissions. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
}
