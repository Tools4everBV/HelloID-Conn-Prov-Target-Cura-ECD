#####################################################
# HelloID-Conn-Prov-Target-Fierit-ECD-Create
#
# Version: 1.0.0
#####################################################

# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
$accountReferenceList = [System.Collections.Generic.List[PSCustomObject]]::new()

$contractCustomProperty = { $_.Custom.FieritECDEmploymentIdentifier }

# Primary Contract Calculation foreach employment
$firstProperty = @{ Expression = { $_.Details.Fte } ; Descending = $true }
$secondProperty = @{ Expression = { $_.Details.HoursPerWeek }; Descending = $true }
# $thirdProperty =  @{ Expression = { $_.Details.Percentage };      Descending = $false }

#Priority Calculation Order (High priority -> Low priority)
$splatSortObject = @{
    Property = @(
        $firstProperty,
        $secondProperty
        #etc..
    )
}

$gender = 'M'
if ( $p.Details.Gender -eq 'Vrouw') {
    $gender = 'V'
}

# Account mapping
$accountEmployee = [PSCustomObject]@{
    # $contractCustomProperty Will be added during the processing below.
    employeecode     = $null
    gender           = $gender # M / V
    dateofbirth      = $p.Details.BirthDate
    begindate        = $null  # Calculated based on empoyement primary contract in conditions
    movetimetoroster = $false
    name             = [PSCustomObject]@{
        firstname      = $p.Name.NickName
        initials       = $p.Name.Initials
        prefix         = $p.Name.FamilyNamePrefix
        surname        = $p.Name.FamilyName
        partnerprefix  = $p.Name.FamilyNamePartnerPrefix
        partnersurname = $p.Name.FamilyNamePartner
        nameassembly   = 'Eigennaam'  # 'Partnernaam'
    }
    contact          = @(
        # When choose to update the existing contact objects are overridden.
        [PSCustomObject]@{
            device = 'vast'
            type   = 'werk'
            value  = $p.Contact.Business.Phone.Mobile
        },
        [PSCustomObject]@{
            device = 'email'
            type   = 'werk'
            value  = $p.Contact.Business.Email
        }
    )
}

# Not all properties are suitable to be updated during correlation. By default, only the Name property will be updated
# Code : $contractCustomProperty Will be added during the processing below.
# Employeecode: $contractCustomProperty Will be added during the processing below.
# The employee Code is used for the relation between Employee and the user account (See readme)
# A Role is Mandatory when creating a new User account
$accountUser = [PSCustomObject]@{
    code         = $null
    name         = "$($p.Name.GivenName) $($p.Name.FamilyName)".trim(' ')
    ssoname      = $p.Accounts.MicrosoftActiveDirectory.mail
    mfaname      = $p.Accounts.MicrosoftActiveDirectory.mail
    active       = $false
    employeecode = $null
    role         = @(
        @{
            id        = "$($config.DefaultTeamAssignmentGuid)"
            startdate = (Get-Date -f 'yyyy-MM-dd')
            enddate   = $null
        }
    )
}

# Set to true if accounts in the target system must be updated
$updatePerson = $true

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

function Merge-Object {
    # With the exception of arrays, these are overridden by the array from the $updates, but only if the array does exist in $updates.
    [CmdletBinding()]
    param(
        [PSCustomObject]
        $Object,

        [PSCustomObject]
        $Updates

    )
    foreach ($property in $Updates.PSObject.Properties) {
        if (
            -not (
                $property.TypeNameOfValue -eq 'System.Object[]' -or
                $property.TypeNameOfValue -eq 'System.Management.Automation.PSCustomObject' -or
                $property.TypeNameOfValue -eq 'System.Collections.Hashtable'
            )
        ) {
            Write-Verbose ('Existing: ' + $($property.Name) + ':' + $Object.$($property.Name))
            Write-Verbose ('New:      ' + $($property.Name) + ':' + $Updates.$($property.Name))
            # Override Properties at the current object if exist in the acocunt object
            if ($Object.PSObject.Properties.Name -eq $($property.Name)) {
                $Object.$($property.Name) = $Updates.$($property.Name)
            } else {
                $Object | Add-Member -NotePropertyMembers @{
                    $($property.Name) = $Updates.$($property.Name)
                }
            }
        } else {
            if ($property.TypeNameOfValue -eq 'System.Object[]') {
                # Override objects in array if exist in the acocunt object
                if ($null -ne $Object.$($property.Name)) {
                    $Object.$($property.Name) = $Updates.$($property.Name)
                } else {
                    $Object | Add-Member -NotePropertyMembers @{
                        $($property.Name) = $Updates.$($property.Name)
                    }
                }
            } else {
                # One level lower
                Merge-Object -Object $Object.$($property.name) -Updates $Updates.$($property.name)
            }
        }
    }
}

function Find-SingleActiveUserAccount {
    [CmdletBinding()]
    param(
        $UserAccountList
    )
    $userAccount = [array]$UserAccountList | Where-Object { $_.active -eq $true }
    if ($userAccount.Length -eq 0) {
        throw "Mulitple user accounts found without a single active for Employee [$($UserAccountList.employeecode|Select -First 1)], Codes: [$($userAcUserAccountListcount.code -join ',')] Currently not Supported"

    } elseif ($userAccount.Length -gt 1) {
        throw "Mulitple active user accounts found for Employee [$($userAccount.employeecode |Select -First 1)], Codes: [$($userAccount.code -join ',')] Currently not Supported"
    }
    Write-Output $userAccount
}

#endregion

# Begin
try {
    # Verify if a user must be either [created and correlated], [updated and correlated] or just [correlated]
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    [array]$desiredContracts = $p.Contracts | Where-Object { $_.Context.InConditions -eq $true }
    [array]$employmentsToCreate = $desiredContracts | Group-Object -Property $contractCustomProperty

    if ($desiredContracts.length -lt 1) {
        Write-Verbose 'No Contracts in scope [InConditions] found!' -Verbose
        throw 'No Contracts in scope [InConditions] found!'
    }

    if ((($desiredContracts | Select-Object $contractCustomProperty).$contractCustomProperty | Measure-Object).count -ne $desiredContracts.count) {
        Write-Verbose "Not all contracts hold a value with the Custom Property [$contractCustomProperty]. Verify the custom Property or your source mapping." -Verbose
        throw  "Not all contracts hold a value with the Custom Property [$contractCustomProperty]. Verify the custom Property or your source mapping."
    }

    foreach ($employment in $employmentsToCreate) {
        try {
            # Update Account object with employment Information
            $accountEmployee.employeecode = $employment.Name
            $accountUser.employeecode = $employment.Name
            $accountUser.code = $employment.Name

            $primaryContract = $employment.Group | Sort-Object @splatSortObject | Select-Object -First 1
            $accountEmployee.begindate = $primaryContract.StartDate

            # Get Employee
            $splatGetEmployee = @{
                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($accountEmployee.employeecode)"
                Method  = 'GET'
                Headers = $headers
            }
            $responseEmployee = Invoke-RestMethod @splatGetEmployee -UseBasicParsing -Verbose:$false

            if ($responseEmployee.Length -eq 0) {
                $action = 'Create-Correlate'
            } elseif ($updatePerson -eq $true) {
                $action = 'Update-Correlate'
            } else {
                $action = 'Correlate'
            }

            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] $action Fierit-ECD account [$($employment.Name)] for: [$($p.DisplayName)], will be executed during enforcement"
            }

            # Process
            if (-not($dryRun -eq $true)) {
                switch ($action) {
                    'Create-Correlate' {
                        Write-Verbose 'Creating and correlating Fierit-ECD account'
                        # Create employee
                        Write-Verbose "Create employee [$($accountEmployee.employeecode)]"
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($accountEmployee | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false

                        # Create User
                        Write-Verbose "Create User [$($accountUser.employeecode)]"
                        $splatNewUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($accountUser | ConvertTo-Json  -Depth 10)
                        }
                        $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false

                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployee.employeecode)
                                UserId     = $($responseUser.code)
                            })
                        break
                    }

                    'Update-Correlate' {
                        Write-Verbose 'Updating and correlating Fierit-ECD account'
                        Write-Verbose "Update employee [$($accountEmployee.employeecode)]"
                        Merge-Object -Object $responseEmployee[0] -Updates $accountEmployee  -Verbose:$false
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'PATCH'
                            Headers = $headers
                            body    = ($responseEmployee[0] | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false

                        # Get user
                        Write-Verbose "Get user with employeeCode [$($accountUser.employeecode)]"
                        $splatGetUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user?employeecode=$($accountUser.employeecode)"
                            Method  = 'GET'
                            Headers = $headers
                        }
                        $responseUser = Invoke-RestMethod @splatGetUser -UseBasicParsing -Verbose:$false

                        $userAction = switch ($responseUser.Length) {
                            { $_ -eq 0 } { 'Create-User' }
                            { $_ -gt 0 } { 'Update-Correlate-User' }
                        }

                        switch ($userAction) {
                            'Create-User' {
                                Write-Verbose "Create user [$($accountUser.code)]"
                                $splatNewUser = @{
                                    Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                    Method  = 'POST'
                                    Headers = $headers
                                    body    = ($accountUser | ConvertTo-Json  -Depth 10)
                                }
                                $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                            }
                            'Update-Correlate-User' {
                                if ($responseUser.Length -gt 1) {
                                    $responseUser = [array](Find-SingleActiveUserAccount -UserAccountList $responseUser)
                                }
                                Write-Verbose "Update user [$($responseUser.code)]"
                                $responseUser[0].name = $accountUser.name

                                $splatNewUser = @{
                                    Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                    Method  = 'Patch'
                                    Headers = $headers
                                    body    = ($responseUser[0] | ConvertTo-Json -Depth 10)
                                }
                                $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                            }
                        }
                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployee.employeecode)
                                UserId     = $($responseUser.code)
                            })
                        break
                    }

                    'Correlate' {
                        Write-Verbose 'Correlating Fierit-ECD account'
                        Write-Verbose "Get User with employeeCode [$($accountUser.employeecode)]"
                        $splatGetUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user?employeecode=$($accountUser.employeecode)"
                            Method  = 'GET'
                            Headers = $headers
                        }
                        $responseUser = Invoke-RestMethod @splatGetUser -UseBasicParsing -Verbose:$false
                        $userAction = switch ($responseUser.Length) {
                            { $_ -eq 0 } { 'Create-User' }
                            { $_ -gt 0 } { 'Correlate-User' }
                        }

                        switch ($userAction) {
                            'Create-User' {
                                Write-Verbose "Create user [$($accountUser.code)]"
                                $splatNewUser = @{
                                    Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                    Method  = 'POST'
                                    Headers = $headers
                                    body    = ($accountUser | ConvertTo-Json)
                                }
                                $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                                break
                            }
                            'Correlate-User' {
                                if ($responseUser.Length -gt 1) {
                                    $responseUser = [array](Find-SingleActiveUserAccount -UserAccountList $responseUser)
                                }
                            }
                        }
                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployee.employeecode)
                                UserId     = $($responseUser.code)
                            })
                    }
                }
                $auditLogs.Add([PSCustomObject]@{
                        Message = "$action account was successful. Employee Reference is: [$($accountEmployee.employeecode)] account: [$($responseUser.code)]"
                        IsError = $false
                    })
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($accountEmployee.employeecode)] Could not $action Fierit-ECD account. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($accountEmployee.employeecode)] Could not $action Fierit-ECD account. Error: $($errorObj.FriendlyMessage)"
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
    Write-Verbose "Could not $action Fierit-ECD account. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not $action Fierit-ECD account. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $accountReferenceList
        Auditlogs        = $auditLogs
        Account          = $accountEmployee
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
