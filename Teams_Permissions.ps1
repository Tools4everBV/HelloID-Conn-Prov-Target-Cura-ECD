#####################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Permissions
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
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
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
#endregion
try {
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    $splatRequestTeams = @{
        Uri     = "$($config.BaseUrl.Trim('/'))/rootdata/teams?includehistory=true"
        Method  = 'GET'
        Headers = $headers
    }

    $permissions = Invoke-RestMethod @splatRequestTeams -UseBasicParsing -Verbose:$false
    Write-Information "Successfully retrieved teams from Fierit-ECD. Result count: $($permissions.Key.Count)"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-HTTPError -ErrorObject $ex
        $errorMessage = "Could not retrieve Fierit-ECD permissions. Error: $($errorObj.ErrorMessage)"
    }
    else {
        $errorMessage = "Could not retrieve Fierit-ECD permissions. Error: $($ex.Exception.Message)"
    }
    Write-Verbose $errorMessage
}

foreach ($permission in $permissions) {
    $returnObject = @{
        DisplayName    = "Team - $($permission.name)"
        Identification = @{
            id   = $permission.id
            Name = $permission.name
            Type = "Team"
        }
    }
    Write-Output $returnObject | ConvertTo-Json -Depth 10
}