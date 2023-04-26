################################################################
# Get Fierit ECD Functions
#
# Version: 1.0.0
################################################################
# Initialize default values
$config = $configuration | ConvertFrom-Json

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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

function Set-AuthorizationHeaders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $Token
    )
    try {
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Content-Type', 'application/json')
        $headers.Add('Authorization', "Bearer $token")

        Write-Output $headers
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion

try {
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    $splatParams = @{
        Uri     = "$($config.BaseUrl)/rootdata/functions"
        Method  = 'GET'
        Headers = $headers    }
    $responseFunctions = Invoke-RestMethod @splatParams -UseBasicParsing

    Write-Output $responseFunctions

} catch {
    if ($_.ErrorDetails) {
        $errorExceptionDetails = $_.ErrorDetails
    } elseif ($_.Exception.Response) {
        $result = $_.Exception.Response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($result)
        $responseReader = $reader.ReadToEnd()
        $reader.Dispose()
    }
    Write-Verbose "ErrorExceptionDetails:   $errorExceptionDetails"  -Verbose
    Write-Verbose "ResponseReader:          $responseReader" -Verbose
    Write-Verbose "Exception.Mesasge:       $($_.Exception.Mesasge)" -Verbose

}
