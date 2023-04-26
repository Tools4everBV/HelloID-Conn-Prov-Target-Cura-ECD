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

# Calculated based on employment primary contract in conditions. And will be added to the accountEmployee object seperate for each employement.
$contractMapping = @{
    begindate    = { $_.StartDate }
    enddate      = { $_.endDate }
    costcentre   = { $_.CostCenter.code }
    locationcode = { $_.Department.ExternalId }
}

$emzfunctionMapping = @{
    code      = { $_.Title.Name }
    begindate = { $_.StartDate }
    enddate   = { $_.endDate }
}

# Account mapping
# $employeecode Will be added during the processing below.
# EmzFunction Will be added based on the [emzfunctionMapping]
$accountEmployee = [PSCustomObject]@{
    employeecode        = $null
    gender              = $gender # M / V
    dateofbirth         = $p.Details.BirthDate
    caregivercode       = ''
    functiondescription = $p.PrimaryContract.Title.Name
    salutation          = $p.Details.HonorificPrefix  #  Fixedvalue    # Dhr. | Mevr. | .?
    movetimetoroster    = $false
    emzfunction         = @()
    name                = [PSCustomObject]@{
        firstname      = $p.Name.NickName
        initials       = $p.Name.Initials
        prefix         = $p.Name.FamilyNamePrefix
        surname        = $p.Name.FamilyName
        partnerprefix  = $p.Name.FamilyNamePartnerPrefix
        partnersurname = $p.Name.FamilyNamePartner
        nameassembly   = 'Eigennaam'  # 'Partnernaam'
    }
    contact             = @(
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
        throw "Mulitple user accounts found without a single active for Employee [$($UserAccountList.employeecode|Select -First 1)], Codes: [$($UserAccountList.code -join ',')] Currently not Supported"

    } elseif ($userAccount.Length -gt 1) {
        throw "Mulitple active user accounts found for Employee [$($userAccount.employeecode |Select -First 1)], Codes: [$($userAccount.code -join ',')] Currently not Supported"
    }
    Write-Output $userAccount
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

function Add-ContractProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $Object,

        [Parameter(Mandatory)]
        [System.Collections.Hashtable]
        $Mapping,

        [Parameter(Mandatory)]
        $Contract,

        [Parameter()]
        [switch]
        $OverrideExisiting
    )
    try {
        foreach ($prop in $Mapping.GetEnumerator()) {
            Write-verbose "Added [$($prop.Name) - $(($Contract | Select-Object -Property $prop.Value).$($prop.value))]" -Verbose
            $Object | Add-Member -NotePropertyMembers @{
                $prop.Name = $(($Contract | Select-Object -Property $prop.Value)."$($prop.value)")
            } -Force:$OverrideExisiting
        }

    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
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
            # Making sure only the properties are added of the current account in the loop
            $accountEmployeeLoop = $accountEmployee.PSObject.Copy()
            $accountEmployeeLoop.emzfunction = $accountEmployee.emzfunction.PSObject.Copy()

            # Update Employee Account object with employment Information
            $primaryContract = $employment.Group | Sort-Object @splatSortObject | Select-Object -First 1
            $accountEmployeeLoop.employeecode = $employment.Name
            $accountEmployeeLoop | Add-ContractProperties -Mapping $contractMapping -Contract $primaryContract

            # Update the emzFunction Object
            $emzObject = [PSCustomObject]::new()
            $emzObject | Add-ContractProperties -Mapping $emzfunctionMapping  -Contract $primaryContract
            $accountEmployeeLoop.emzfunction += $emzObject

            # Update User Account object
            $accountUser.employeecode = $employment.Name
            $accountUser.code = $employment.Name

            # Get Employee
            $splatGetEmployee = @{
                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($accountEmployeeLoop.employeecode)"
                Method  = 'GET'
                Headers = $headers
            }
            $responseEmployee = Invoke-FieritWebRequest @splatGetEmployee -UseBasicParsing

            if ($null -eq $responseEmployee) {
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
                        Write-Verbose "Create employee [$($accountEmployeeLoop.employeecode)]"
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($accountEmployeeLoop | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-FieritWebRequest @splatNewEmployee -UseBasicParsing

                        # Create User
                        Write-Verbose "Create User [$($accountUser.employeecode)]"
                        $splatNewUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($accountUser | ConvertTo-Json  -Depth 10)
                        }
                        $responseUser = Invoke-FieritWebRequest @splatNewUser -UseBasicParsing

                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployeeLoop.employeecode)
                                UserId     = $($responseUser.code)
                            })
                        break
                    }

                    'Update-Correlate' {
                        Write-Verbose 'Updating and correlating Fierit-ECD account'
                        Write-Verbose "Update employee [$($accountEmployeeLoop.employeecode)]"
                        Merge-Object -Object $responseEmployee -Updates $accountEmployeeLoop  -Verbose:$false
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'PATCH'
                            Headers = $headers
                            body    = ($responseEmployee | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-FieritWebRequest @splatNewEmployee -UseBasicParsing

                        # Get user
                        Write-Verbose "Get user with employeeCode [$($accountUser.employeecode)]"
                        $splatGetUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user?employeecode=$($accountUser.employeecode)"
                            Method  = 'GET'
                            Headers = $headers
                        }
                        $responseUser = Invoke-FieritWebRequest @splatGetUser -UseBasicParsing

                        if ($null -eq $responseUser) {
                            $userAction = 'Create-User'
                        } else {
                            $userAction = 'Update-Correlate-User'
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
                                $responseUser = Invoke-FieritWebRequest @splatNewUser -UseBasicParsing
                            }
                            'Update-Correlate-User' {
                                if ($responseUser.Length -gt 1) {
                                    $responseUser = (Find-SingleActiveUserAccount -UserAccountList $responseUser)
                                }
                                Write-Verbose "Update user [$($responseUser.code)]"
                                $responseUser.name = $accountUser.name

                                $splatNewUser = @{
                                    Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                    Method  = 'Patch'
                                    Headers = $headers
                                    body    = ($responseUser | ConvertTo-Json -Depth 10)
                                }
                                $responseUser = Invoke-FieritWebRequest @splatNewUser -UseBasicParsing
                            }
                        }
                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployeeLoop.employeecode)
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
                        $responseUser = Invoke-FieritWebRequest @splatGetUser -UseBasicParsing
                        if ($null -eq $responseUser) {
                            $userAction = 'Create-User'
                        } else {
                            $userAction = 'Update-Correlate-User'
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
                                $responseUser = Invoke-FieritWebRequest @splatNewUser -UseBasicParsing
                                break
                            }
                            'Correlate-User' {
                                if ($responseUser.Length -gt 1) {
                                    $responseUser = (Find-SingleActiveUserAccount -UserAccountList $responseUser)
                                }
                            }
                        }
                        $accountReferenceList.Add(@{
                                EmployeeId = $($accountEmployeeLoop.employeecode)
                                UserId     = $($responseUser.code)
                            })
                    }
                }
                $auditLogs.Add([PSCustomObject]@{
                        Message = "$action account was successful. Employee Reference is: [$($accountEmployeeLoop.employeecode)] account: [$($responseUser.code)]"
                        IsError = $false
                    })
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            Write-Verbose "[$($accountEmployeeLoop.employeecode)] Could not $action Fierit-ECD account. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
            $auditLogs.Add([PSCustomObject]@{
                    Message = "[$($accountEmployeeLoop.employeecode)] Could not $action Fierit-ECD account. Error: $($errorObj.FriendlyMessage)"
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
