#####################################################
# HelloID-Conn-Prov-Target-Cura-ECD-Update
#
# Version: 1.0.0
#####################################################

# Initialize default values
$config = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
# $pp = $previousPerson | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()
$accountReferenceList = [System.Collections.Generic.List[PSCustomObject]]::new()

# Account mapping

# Employeecode : $contractCustomProperty Will be added during the processing below.
# When choose to update the existing contact objects are overridden.

$accountEmployee = [PSCustomObject]@{
    employeecode = $null
    gender       = 'M' # V etc..
    dateofbirth  = # $p.Details.BirthDate
    begindate    = $null
    name         = [PSCustomObject]@{
        firstname      = $p.Name.NickName
        initials       = $p.Name.Initials
        prefix         = $p.Name.FamilyNamePrefix
        surname        = $p.Name.FamilyName
        partnerprefix  = $p.Name.FamilyNamePartnerPrefix
        partnersurname = $p.Name.FamilyNamePartner
        nameassembly   = 'Eigennaam'  # 'Partnernaam'
    }
    contact      = @(
        [PSCustomObject]@{
            device = 'vast'
            type   = 'werk'
            value  = $p.Contact.Business.Phone.Fixed
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
# Active : Account created in the Update script needed to be Active, Because there is no Enable or Disable process triggered.
# A Role is Mandatory when creating a new User account

$accountUser = [PSCustomObject]@{
    code         = $null
    name         = "$($p.Name.GivenName) $($p.Name.FamilyName)".trim(' ')
    ssoname      = $p.Accounts.MicrosoftActiveDirectory.mail
    mfaname      = $p.Accounts.MicrosoftActiveDirectory.mail
    active       = $true
    employeecode = $null
    role         = @(
        @{
            id        = "$($config.DefaultTeamAssignmentGuid)"
            startdate = (Get-Date -f 'yyyy-MM-dd')
            enddate   = $null
        }
    )
}

$contractCustomProperty = { $_.Custom.CuraECDEmploymentIdentifier }

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
        $headers.Add('Accept', 'application/json; charset=utf-8')
        $headers.Add('Content-Type', 'application/json; charset=utf-8')
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
function Compare-Join {
    [OutputType([array], [array], [array])] # $Left , $Right, $common
    param(
        [parameter()]
        [string[]]$ReferenceObject,

        [parameter()]
        [string[]]$DifferenceObject
    )
    if ($null -eq $DifferenceObject) {
        $Left = $ReferenceObject
    } elseif ($null -eq $ReferenceObject ) {
        $right = $DifferenceObject
    } else {
        $left = [string[]][Linq.Enumerable]::Except($ReferenceObject, $DifferenceObject)
        $right = [string[]][Linq.Enumerable]::Except($DifferenceObject, $ReferenceObject)
        $common = [string[]][Linq.Enumerable]::Intersect($ReferenceObject, $DifferenceObject)
    }
    Write-Output $Left.Where({ -not [string]::IsNullOrEmpty($_) }) , $Right, $common
}
#endregion

try {
    #region Calculate desired accounts
    [array]$desiredContracts = $p.Contracts | Where-Object { $_.Context.InConditions -eq $true }
    if ($desiredContracts.length -lt 1) {
        Write-Verbose 'No Contracts in scope [InConditions] found!' -Verbose
        throw 'No Contracts in scope [InConditions] found!'
    }
    if ((($desiredContracts | Select-Object $contractCustomProperty).$contractCustomProperty | Measure-Object).count -ne $desiredContracts.count) {
        Write-Verbose "Not all contracts hold a value with the Custom Property [$contractCustomProperty]. Verify the custom Property or your source mapping." -Verbose
        throw  "Not all contracts hold a value with the Custom Property [$contractCustomProperty]. Verify the custom Property or your source mapping."
    }
    $desiredContractsGrouped = $desiredContracts | Group-Object -Property $contractCustomProperty

    [array]$accountToCreate, [array]$accountToRevoke, [array]$accountToUpdate = Compare-Join -ReferenceObject $desiredContractsGrouped.Name -DifferenceObject ($aRef.EmployeeId)
    Write-Verbose "[$($p.DisplayName)] Account(s) To Create [$($accountToCreate -join ', ')]"
    Write-Verbose "[$($p.DisplayName)] Account(s) To Revoke [$($accountToRevoke -join ', ')]"
    Write-Verbose "[$($p.DisplayName)] Account(s) To Update [$($accountToUpdate -join ', ')]"
    #endregion


    #region Initialize account Objects
    $token = Get-AccessToken
    $headers = Set-AuthorizationHeaders -Token $token

    $allAccounts = [System.Collections.Generic.List[object]]::new()
    $allAccounts.AddRange($accountToCreate)
    $allAccounts.AddRange($accountToRevoke)
    $allAccounts.AddRange($accountToUpdate)
    $currentAccountList = @{}
    foreach ($accountNr in $allAccounts ) {
        $accountEmployeeLoop = $accountEmployee.psobject.copy()
        $accountEmployeeLoop.employeecode = "$accountNr"

        $accountUserLoop = $accountUser.psobject.copy()
        $accountUserLoop.employeecode = "$accountNr"
        $accountUserLoop.code = "$accountNr"

        $primaryContract = $null
        $primaryContract = ($desiredContractsGrouped | Where-Object { $_.name -eq $accountNr }).Group | Sort-Object @splatSortObject  | Select-Object -First 1
        if ( $primaryContract) {
            $accountEmployeeLoop.begindate = ([datetime]($primaryContract.StartDate)).ToString('yyyy-MM-dd')
        }

        $currentAref = $null
        $currentAref = $aref | Where-Object { $_.employeeId -eq $accountNr }
        if ($null -ne $currentAref ) {
            $accountUserLoop.code = $currentAref.UserId
        }

        # Get Employee
        Write-Verbose "Get Employee with employeeCode [$($accountNr)]"
        $splatGetEmployee = @{
            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee?employeecode=$($accountNr)"
            Method  = 'GET'
            Headers = $headers
        }
        $currentEmployee = $null
        $currentEmployee = Invoke-RestMethod @splatGetEmployee -UseBasicParsing -Verbose:$false

        # Get User
        Write-Verbose "Get user with employeeCode [$($accountNr)]"
        $splatGetUser = @{
            Uri     = "$($config.BaseUrl.Trim('/'))/users/user?employeecode=$($accountNr)"
            Method  = 'GET'
            Headers = $headers
        }
        $currentUser = $null
        $currentUser = (Invoke-RestMethod @splatGetUser -UseBasicParsing -Verbose:$false)

        $currentAccountList["$accountNr"] += @{
            CurrentEmployee = $currentEmployee | Select-Object -First 1
            EmployeeFound   = "$(if ($currentEmployee.Length -eq 0) { 'NotFound' } Else { 'Found' })"
            accountEmployee = $accountEmployeeLoop
            CurrentUser     = $currentUser | Select-Object -First 1
            UserFound       = "$(if ($currentUser.Length -eq 0) { 'NotFound' } Else { 'Found' })"
            accountUser     = $accountUserLoop
        }

    }
    #endregion


    #region Process Account to Create
    foreach ($accountNr in $accountToCreate ) {
        try {
            $currentAccount = $null
            $currentAccount = $currentAccountList[$accountNr]
            # Add an auditMessage showing what will happen during enforcement
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Create Cura-ECD account [$accountNr] for: [$($p.DisplayName)], will be executed during enforcement"
            } else {
                switch ($currentAccount.EmployeeFound) {
                    'Found' {
                        $splatCompareProperties = @{
                            ReferenceObject  = @($currentAccount.accountEmployee.PSObject.Properties)
                            DifferenceObject = @($currentAccount.CurrentEmployee.PSObject.Properties)
                        }
                        $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({ $_.SideIndicator -eq '=>' })
                        if ($propertiesChanged) {
                            # Update Emploee

                            Write-Verbose "Correlate + Update employee [$($currentAccount.CurrentEmployee.employeecode)]"
                            Merge-Object -Object $currentAccount.CurrentEmployee -Updates $currentAccount.accountEmployee  -Verbose:$false
                            $splatNewEmployee = @{
                                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                                Method  = 'PATCH'
                                Headers = $headers
                                body    = ($currentAccount.CurrentEmployee | ConvertTo-Json  -Depth 10)
                            }
                            $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false
                        } else {
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = 'CreateAccount'
                                    Message = "[$accountNr] Correlate account was successful. Employee Reference is: [$($currentAccount.CurrentEmployee.employeecode)] account: [$($currentAccount.CurrentUser.code)]"
                                    IsError = $false
                                })
                        }
                        break
                    }
                    'NotFound' {
                        # Create Employee
                        Write-Verbose "Create employee [$($currentAccount.accountEmployee.employeecode)]"
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($currentAccount.accountEmployee | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false
                        break
                    }
                }

                switch ($currentAccount.UserFound) {
                    'Found' {
                        Write-Verbose "Correlate + Update User [$($currentAccount.CurrentUser.code)]"

                        # Update Properties
                        $currentAccount.CurrentUser.name = $currentAccount.accountUser.name
                        $currentAccount.CurrentUser.active = $true

                        $splatNewUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                            Method  = 'Patch'
                            Headers = $headers
                            body    = ( $currentAccount.CurrentUser | ConvertTo-Json -Depth 10)
                        }
                        $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                        break;
                    }
                    'NotFound' {
                        # Create User
                        Write-Verbose "Create User [$($currentAccount.accountUser.code)]"
                        $splatNewUser = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                            Method  = 'POST'
                            Headers = $headers
                            body    = ($currentAccount.accountUser | ConvertTo-Json  -Depth 10)
                        }
                        $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                        break
                    }
                }
                $accountReferenceList.Add(@{
                        EmployeeId = $($currentAccount.accountEmployee.employeecode)
                        UserId     = $($currentAccount.accountUser.code)
                    })

                $auditLogs.Add([PSCustomObject]@{
                        Action  = 'CreateAccount'
                        Message = "[$accountNr] Create account was successful. Employee Reference is: [$($currentAccount.accountEmployee.employeecode)] account: [$($currentAccount.accountUser.code)]"
                        IsError = $false
                    })
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            $errorMessage = "[$accountNr] Could not Create Cura-ECD account. Error:  $($ex.Exception.Message), $($errorObj.FriendlyMessage)"
            Write-Verbose $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Action  = 'CreateAccount'
                    Message = $errorMessage
                    IsError = $true
                })
        }
    }
    #endregion


    #region Process Account to Update
    foreach ($accountNr in $accountToUpdate ) {
        try {
            $currentAccount = $null
            $currentAccount = $currentAccountList[$accountNr]
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Update Cura-ECD account [$accountNr] for: [$($p.DisplayName)], will be executed during enforcement"
            } else {
                #($dryRun -eq $true) {
                switch ($currentAccount.EmployeeFound) {
                    'Found' {
                        # Emploee
                        $splatCompareProperties = @{
                            ReferenceObject  = @($currentAccount.accountEmployee.PSObject.Properties)
                            DifferenceObject = @($currentAccount.CurrentEmployee.PSObject.Properties)
                        }
                        $currentAccount.CurrentEmployee.name.psobject.Properties.Remove('sortname')

                        $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where({ $_.SideIndicator -eq '=>' })
                        if ($propertiesChanged) {

                            Write-Verbose "Update employee [$($currentAccount.accountEmployee.employeecode)]"
                            Merge-Object -Object $currentAccount.CurrentEmployee -Updates $currentAccount.accountEmployee  -Verbose:$false
                            $splatNewEmployee = @{
                                Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                                Method  = 'PATCH'
                                Headers = $headers
                                body    = ($currentAccount.CurrentEmployee | ConvertTo-Json  -Depth 10)
                            }
                            $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false

                            switch ($currentAccount.UserFound) {
                                'Found' {
                                    # User
                                    Write-Verbose "Update User [$($currentAccount.accountUser.code)]"
                                    $currentAccount.CurrentUser.name = $currentAccount.accountUser.name
                                    $splatNewUser = @{
                                        Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                        Method  = 'Patch'
                                        Headers = $headers
                                        body    = ( $currentAccount.CurrentUser | ConvertTo-Json -Depth 10)
                                    }
                                    $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false
                                    $accountReferenceList.Add(@{
                                            EmployeeId = $($currentAccount.accountEmployee.employeecode)
                                            UserId     = $($currentAccount.accountUser.code)
                                        })

                                    $auditLogs.Add([PSCustomObject]@{
                                            Action  = 'UpdateAccount'
                                            Message = "[$accountNr] Update account was successful. Employee Reference is: [$($currentAccount.CurrentEmployee.employeecode)] account: [$($currentAccount.CurrentUser.code)]"
                                            IsError = $false
                                        })
                                    break
                                }
                                'NotFound' {
                                    # User
                                    $auditLogs.Add([PSCustomObject]@{
                                            Action  = 'UpdateAccount'
                                            Message = "[$accountNr] Could not Update Cura-ECD account User Acocunt seems to be deleted from Cura"
                                            IsError = $true
                                        })
                                    break
                                }
                            }
                        } else {
                            $accountReferenceList.Add(@{
                                    EmployeeId = $($currentAccount.CurrentEmployee.employeecode)
                                    UserId     = $($currentAccount.CurrentUser.code)
                                })
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = 'UpdateAccount'
                                    Message = "[$accountNr] Update account was successful. Employee Reference is: [$($currentAccount.CurrentEmployee.employeecode)] account: [$($currentAccount.CurrentUser.code)], No Change required"
                                    IsError = $false
                                })
                        }
                        break
                    }
                    'NotFound' {
                        # Employee
                        $auditLogs.Add([PSCustomObject]@{
                                Action  = 'UpdateAccount'
                                Message = "[$accountNr] Could not Update Cura-ECD account, Employee Acocunt seems to be deleted from Cura"
                                IsError = $true
                            })
                        break
                    }
                }
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            $errorMessage = "[$accountNr] Could not Update Cura-ECD account. Error:  $($ex.Exception.Message), $($errorObj.FriendlyMessage)"
            Write-Verbose $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Action  = 'UpdateAccount'
                    Message = $errorMessage
                    IsError = $true
                })
        }
    }
    #endregion


    #region Process Account to Delete
    foreach ($accountNr in $accountToRevoke ) {
        try {
            $auditLogsIfRevokeSuccess = [System.Collections.Generic.List[PSCustomObject]]::new()
            $currentAccount = $null
            $currentAccount = $currentAccountList[$accountNr]
            if ($dryRun -eq $true) {
                Write-Warning "[DryRun] Delete Cura-ECD account [$accountNr] for: [$($p.DisplayName)], will be executed during enforcement"
            } else {
                switch ($currentAccount.EmployeeFound) {
                    'Found' {
                        # Update Emploee
                        Write-Verbose "Revoke employee [$($currentAccount.accountEmployee.employeecode)]"

                        if ($currentAccount.CurrentEmployee.team.Length -gt 0) {
                            Write-Verbose "Revoke All Teams assigned to the employee [$($currentAccount.CurrentEmployee.team.name -join ',')]"
                            $auditLogsIfRevokeSuccess.Add([PSCustomObject]@{
                                    Action  = 'DeleteAccount'
                                    Message = "[$accountNr] Revoke CuraECD Team entitlement(s): [$($currentAccount.CurrentEmployee.team.name -join ',')] was successful"
                                    IsError = $false
                                })
                            $currentAccount.CurrentEmployee.PSObject.Properties.Remove('team')
                        }
                        $splatNewEmployee = @{
                            Uri     = "$($config.BaseUrl.Trim('/'))/employees/employee"
                            Method  = 'PATCH'
                            Headers = $headers
                            body    = ($currentAccount.CurrentEmployee | ConvertTo-Json  -Depth 10)
                        }
                        $responseEmployee = Invoke-RestMethod @splatNewEmployee -UseBasicParsing -Verbose:$false

                        if ($currentAccount.UserFound) {
                            # Update User
                            Write-Verbose "Update User [$($currentAccount.accountUser.code)]"

                            Write-Verbose ($currentAccount.CurrentUser | ConvertTo-Json) -Verbose

                            Write-Verbose "Disable userAccount [$($currentAccount.accountUser.code)]"
                            $currentAccount.CurrentUser.active = $false
                            $auditLogsIfRevokeSuccess.Add([PSCustomObject]@{
                                    Action  = 'DeleteAccount'
                                    Message = "[$accountNr]  Disable account [$($currentAccount.accountUser.code)] was successful"
                                    IsError = $false
                                })

                            if ($currentAccount.CurrentUser.locationauthorisationgroup.Length -gt 0) {
                                Write-Verbose "Revoke All Locationauthorisationgroup(s) [$($currentAccount.CurrentUser.locationauthorisationgroup.code -join ',')]"
                                $auditLogsIfRevokeSuccess.Add([PSCustomObject]@{
                                        Action  = 'DeleteAccount'
                                        Message = "[$accountNr] Revoke CuraECD locationAuthGroup entitlement(s): [$($currentAccount.CurrentUser.locationauthorisationgroup.code -join ',')] was successful"
                                        IsError = $false
                                    })
                                $currentAccount.CurrentUser.Locationauthorisationgroup = $null
                            }

                            if ($currentAccount.CurrentUser.role.Length -gt 0 -and $currentAccount.CurrentUser.role -notcontains $($config.DefaultTeamAssignmentGuid)) {
                                Write-Verbose "Revoke All assigned roles and assign default group [$($currentAccount.CurrentUser.Role.code -join ',')]"
                                $auditLogsIfRevokeSuccess.Add([PSCustomObject]@{
                                        Action  = 'DeleteAccount'
                                        Message = "[$accountNr] Revoke CuraECD Role entitlement(s): [$($currentAccount.CurrentUser.Role.code -join ',')] was successful"
                                        IsError = $false
                                    })
                                $currentAccount.CurrentUser.role = @(@{
                                        id        = "$($config.DefaultTeamAssignmentGuid)"
                                        startdate = (Get-Date -f 'yyyy-MM-dd')
                                        enddate   = $null
                                    }
                                )

                            }
                            $splatNewUser = @{
                                Uri     = "$($config.BaseUrl.Trim('/'))/users/user"
                                Method  = 'Patch'
                                Headers = $headers
                                body    = ( $currentAccount.CurrentUser | ConvertTo-Json -Depth 10)
                            }
                            $responseUser = Invoke-RestMethod @splatNewUser -UseBasicParsing -Verbose:$false

                            $auditLogs.AddRange($auditLogsIfRevokeSuccess)
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = 'DeleteAccount'
                                    Message = "[$accountNr] Delete account was successful"
                                    IsError = $false
                                })
                        } else {
                            $auditLogs.Add([PSCustomObject]@{
                                    Action  = 'DeleteAccount'
                                    Message = "[$accountNr] Cura-ECD User account not found. Possibly already deleted, skipping action."
                                    IsError = $false
                                })
                            break
                        }
                        break
                    }
                    'NotFound' {
                        $auditLogs.Add([PSCustomObject]@{
                                Action  = 'DeleteAccount'
                                Message = "[$accountNr] Cura-ECD Employee account not found. Possibly already deleted, skipping action."
                                IsError = $false
                            })
                        break
                    }
                }
            }
        } catch {
            $ex = $PSItem
            $errorObj = Resolve-HTTPError -ErrorObject $ex
            $errorMessage = "[$accountNr] Could not Delete Cura-ECD account. Error:  $($ex.Exception.Message), $($errorObj.FriendlyMessage)"
            Write-Verbose $errorMessage
            $auditLogs.Add([PSCustomObject]@{
                    Action  = 'DeleteAccount'
                    Message = $errorMessage
                    IsError = $true
                })
        }
    }
    #endregion

    # Verify Success
    if (-not ($auditLogs.isError -contains $true)) {
        $success = $true
    }
} catch {
    $ex = $PSItem
    $errorObj = Resolve-HTTPError -ErrorObject $ex
    Write-Verbose "Could not Update Cura-ECD account. Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    $auditLogs.Add([PSCustomObject]@{
            Message = "Could not Update Cura-ECD account. Error: $($errorObj.FriendlyMessage)"
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        AccountReference = $accountReferenceList
        Success          = $success
        Auditlogs        = $auditLogs
    }
    Write-Output $result | ConvertTo-Json -Depth 10
}
