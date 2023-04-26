
# HelloID-Conn-Prov-Target-Fierit-ECD

| :warning: Warning |
|:---------------------------|
| Note that this is a complex connector. Please contact Tools4ever before implementing this connector! |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

> :warning: **_Information_**
> It is important to note that the processing order of this connector may work slightly differently from other connectors in the HelloID platform. This is because this connector supports multiple accounts per HelloID Person. *(See Remark: [Business Rules Validation Check](#business-rules-validation-check) and [Processing Multiple Accounts Fierit](#processing-multiple-accounts-fierit)*

<p align="center">
  <img src="https://tenzinger.com/wp-content/uploads/2021/06/Tenzinger_600x600.jpg"
   alt="drawing" style="width:300px;"/>
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-Fierit-ECD](#helloid-conn-prov-target-fierit-ecd)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Connection settings](#connection-settings)
    - [Prerequisites](#prerequisites)
    - [Creation process](#creation-process)
    - [Correlation process](#correlation-process)
  - [Provisioning](#provisioning)
    - [Supported Features](#supported-features)
        - [Supported Action Details](#supported-action-details)
    - [Remarks](#remarks)
      - [IP-Whitelisting](#ip-whitelisting)
      - [Concurrent sessions](#concurrent-sessions)
      - [Default Role Create user](#default-role-create-user)
      - [Permission update script](#permission-update-script)
      - [Reboarding](#reboarding)
      - [Direct values from HR- Source System](#direct-values-from-hr--source-system)
      - [Input Validation Check](#input-validation-check)
      - [ProcessIdentifier](#processidentifier)
      - [(EMZ) Function Title](#emz-function-title)
      - [Account Object - Additional Mapping](#account-object---additional-mapping)
      - [Location - CostCenter](#location---costcenter)
      - [Business Rules Validation Check](#business-rules-validation-check)
      - [Processing Multiple Accounts Fierit](#processing-multiple-accounts-fierit)
  - [Setup the connector](#setup-the-connector)
    - [Configuration settings](#configuration-settings)
      - [Script Settings](#script-settings)
        - [Create.ps1](#createps1)
        - [Update.ps1](#updateps1)
        - [All Permissions Scripts *(Grant)*](#all-permissions-scripts-grant)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Fierit-ECD_ is a _target_ connector. Fierit-ECD, formerly known as CURA-ECD, provides a set of REST APIs that allow you to programmatically interact with its data. The connector manages the Fierit Employee, User account, Employee Teams, User LocationAuthorisationGroups, and User Roles with or without selectionAuthorisationGroup. The Employees and Account are both supported in the account LifeCycle, and there are three types of permissions to manage the authorizations. It supports multiple accounts for a HelloId Person based on Employment.


## Getting started

### Connection settings

The following settings are required to connect to the API.

| Setting      | Description                        | Mandatory   |
| ------------ | -----------                        | ----------- |
| ClientId              | The ClientId to connect to the API        | Yes         |
| ClientSecret          | The ClientSecret to connect to the API    | Yes         |
| OrganisationId        | The OrganisationId to connect to the API  | Yes         |
| Environment           | Test pr Production                        | Yes         |
| Audience              | Test or Production                   | Yes         |
| BaseUrl               | The URL to the API                 | Yes         |
| TokenUrl              | The Token URL to the API.  *Example: https://{{CustomerUrl}}l:8443/fierit/api*                | Yes         |
| DefaultTeamAssignmentGuid      | The URL to the API.   *Example: https://{{CustomerUrl}}.nl:8443/fierit/api/token/development-test*    | Yes         |
| UseMappingSelectionAuthorisationGroup    | Use SelectionAuthorisationGroup Mapping, when disabled the default from Fierit is used.            | Yes         |
| MappingSelectionAuthGroupFileLocation      | The Path to the mapping file (HR => SelectionAuthorisationGroup 1=1) Example can be found in the asset folder            | Yes         |
| csvDelimiter          | Mapping File CSV Separation Character              | Yes         |
| IsDebug               | The URL to the API                 | Yes         |


### Prerequisites
 - IP Address is whitelisted (local Agent)
 - Connection Settings
 - An additional mapping between HR departments and/or Titles to SelectionAuthorisationGroup to assign a "Scope" on a Role
- A custom property on the HelloID contract with a combination of the employeeCode and EmploymentCode named: [custom.FieritECDEmploymentIdentifier]
Example:
```JavaScript
  function getValue() {
      return sourceContract.PersonCode + "-" + sourceContract.EmploymentCode
  }
  getValue();
  ```

### Creation process
New functionality is the possibility to update the account in the target system during the correlation process. By default, this behavior is disabled. Meaning, the account will only be created or correlated.
You can change this behavior in the `create.ps1` by setting the boolean `$updatePerson` to the value of `$true`.

### Correlation process
Since Fierit-ECD has both employee and user account objects, we need to create or correlate both objects when creating a new account *(Also in the creation section of the Update.ps1 script).* The employee object is always correlated with the EmployeeCode, which is a combination of the employee number and contract number. However, the relationship in Fierit-ECD between an employee and a user account is one-to-many, but we have been advised by the vendor to use a one-to-one relationship, which we currently manage ourselves in the connector. The connector checks if an account is already associated with the employee object and correlates it, after which it is managed in HelloID.

Unfortunately, there are cases where multiple accounts are linked to an employee. If this happens, the connector looks for an active account. When one is found, it is correlated. If more than one or none are found, the action produces an error message that needs to be resolved manually. This will always be the case when reboarding an employee with multiple accounts, as removing the entitlement will deactivate the account.
> :bulb: **How to Solve:** In the case described above you must remove all user accounts but one for the specific Employee. Or make one account `Active` and re-run the HelloID Enforcement.

## Provisioning

### Supported Features

| What       |Supported ||
| ----------- | --------------|--------------
| Managing Employee accounts                                      |Yes | |
| Managing User Accounts                                          |Yes | |
| Authorizations Teams for Employee Accounts                      |Yes | |
| Authorizations LocationAuthorisationGroup for User Accounts     |Yes | |
| Authorizations Role for User Accounts                           |Yes | |
|Set custom SelectionAuthorisationGroup to Role for User Accounts |Yes||


##### Supported Action Details
Using this connector you will have the ability to create and manage the following items in Fierit ECD:

| Files       |Description |Employee Account | User Account        |
| ----------- | --------------|--------------    |-----------
| Create.ps1  |Account for each employment| Create / Correlate Update Whole account object | Create / Corrolate Update only DisplayName
| Update.ps1  |Calculate accounts based on  employment in the business Rules against accountReferences  |</li><li>**New account:** Create or correlate Update, Enable correlated Account and add accountReference.</li><li>**Update account:** Update account except for the assignments</li></ul> </li><li>**Remove Account:** Revoke permissions (Teams) and Remove AccountReference </li></ul>|</li><li>**New account:** Create or correlate Update, Enable correlated Account and add AccountReference.</li><li>**Update account:**  Update only displayName.</li></ul> </li><li>**Remove Account:** Disable account, Revoke permissions (Role, LocationAuthorisationGroup and Team), Role assignment back to Dummy role, and Remove AccountReference </li></ul>|
| Delete.ps1  |Based on accountReferences | -   | Disable account(s) in accountReference
| Enable.ps1  | Based on accountReferences| -   | Enable account(s) in accountReference
| Disable.ps1  |Based on accountReferences|  -   |Disable account(s) in accountReference
| Permission.ps1 *(Teams)*| Based on accountReferences| Grant and Revoke Teams                | -
| Permission.ps1 *(Role)*| Based on accountReferences|- | Grant and Revoke Roles and assign default role if latest entitlement is revoked
| Permission.ps1 *(LocationAuthorisationGroup)*|Based on accountReferences|-|Grant and Revoke LocationAuthorisationGroup
| Entitlements.ps1  | Get Teams, Roles and LocationAuthorisationGroup | -|-
| Resource.ps1  | - |-|-

### Remarks
#### IP-Whitelisting
The web service is only Accessible with whitelisted IP addresses. So an Agent server is required. *Not sure if Fierit supports DNS whitelisting*

#### Concurrent sessions
The web service does not support Patch requests. So the user is retrieved from Fierit, adds the new permission, and the user is updated with the current permission and new permission. Therefore, concurrent sessions must be set to 1.

#### Default Role Create user
A dummy or Default Role for creating new users. It's required to set a role when creating a new User. Because the create take place in the account lifecycle the first role cannot be managed through entitlements. There you can specify a default role in the connection setting.

<p>
  <img src="assets/DefaultTeamAssignment.png"/>
</p>

#### Permission update script
Because the Connector Support multiplies account per Person, the permission Update script must also be used. You can place the Grant script here since this works in both situations.

#### Reboarding
In some cases re-boarding is **not supported**. Which mean that a manual action is required. See: [Correlation process](#correlation-process)

#### Direct values from HR- Source System
The connector assumes that the function codes and location codes in Fierit are identical to those in the HR-source system, without requiring additional mapping. Consequently, the values from the source system must also be present in Fierit. The webservice verifies whether the specified values exist, and if not, it stops the creation or update process. To obtain the current values of the functions or locations from Fierit, two scripts have been added to the Asset folder: `Get-Fierit-Functions.ps1` and `Get-Fierit-Locations.ps1`.

#### Input Validation Check
In addition, building upon the remark [Direct values from HR- Source System](#direct-values-from-hr--source-system), No validation check is conducted on the input values coming from the HelloId contracts. If a property does not exist in Fierit, such as locations and function codes, the Fireit web service will throw explanatory an error.

#### ProcessIdentifier
To aid in troubleshooting within the Fierit, the supplier has requested that a ProcessIdentifier be included in the support request for the relevant web calls. The connector logs these ProcessIdentifiers. Failed web requests will always be logged, whereas successful requests will only be logged when the debug logging toggle is enabled.

#### (EMZ) Function Title
The EMZfunction in Fierit allows for a list of function titles with start and end dates, but the connector does not maintain the history of previous titles. Instead, it only synchronizes the current title of the primary contract for an employment, which results in the overriding of any existing function titles.

#### Account Object - Additional Mapping
Please note that the account object has been extended with an additional mapping, which is shown below. This mapping is necessary to determine values for a specific employment. It allows for the creation of multiple accounts for a single person with a specific job title or location. There is a distinction between properties that apply to all accounts/employment and those that are specific to an employment. The "normal" account object contains the general properties, while the mapping contains the specific ones. Where `$_` represent a contract to dynamically access the properties in the contracts array.
> :bulb: Note! These mapping applies to the Create and the Update script

  ```PowerShell
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
 ```

#### Location - CostCenter
The location related with the CostCenter will always be used (and ignore the location code from the request). If the CostCenter is empty or the CostCenter is not linked to location the default location will be used from stuurcode 100.
Consequently, an employee location code cannot be cleared, and will instead be set to the default "stuurcode" when requested.

#### Business Rules Validation Check

In certain situations, an employment with the reference number 1000467-1 may have an account entitlement, while another employment with the reference number 1000467-2 has been granted permission. This leads to a mismatch between the account reference and the contracts in scope. This mismatch is a result of an incorrect configuration of the Business Rules. The connector checks for this mismatch and will generate a "warning" audit log, but the connector will still complete successfully without processing the permission. It is important to ensure that by granting permissions to specific employment, they also have an associated account entitlement.

#### Processing Multiple Accounts Fierit

Due to the support for multiple accounts within Fierit, the Update task may result in the removal of an account. This scenario presents a problem, as the default process order for revoking a trigger is to first revoke the permissions and then revoke the account entitlement. As a result, permissions are revoked before the account entitlement is outside of scope. This process is described in the HelloID documentation. However, in our particular scenario, the process operates differently. The update task first removes the account, resulting in the process order being reversed, with the account revocation occurring before the permission is revoked. This difference in process order leads to the removed account reference not appearing in the permission task, making it impossible to remove the associated permissions. The difference in processing orders forces the removal of all the permission during the removal in the Update.ps1. The permission script subsequently performs a cleanup process of the previously removed accounts (Remove the deprecated sub-permissions) during the next run. However, this is not a straightforward process and will only be triggered during the next specific permission update or when manually prompted to update the permissions.

> :bulb: Tip: To get a closing solution, you can specify the account and permission entitlements in distinct business rules. Additionally, it is suggested to configure the permission entitlement to be out of scope before the account entitlement during off-boarding or re-boarding procedures... To prevent out-of-sync permissions.


## Setup the connector

### Configuration settings
* Make sure to set the **Concurrent Action limited to one** and runs on a local agent server.
* Make sure the sub Permissions are enabled for all permissions configurations


#### Script Settings
* Besides the configuration tab, you can also configure script variables. To decide which property from a HelloID contract is used to look up a value in the mapping table, this is known as the HR Location or HR Team. And you can configure the primary contract calculation for each employment. Please note that some "same" configuration takes place in multiple scripts. Shown as below:
- Also Check the information [Account Object - Additional Mapping](#account-object---additional-mapping)

##### Create.ps1

  ```PowerShell
# Primary Contract Calculation for each employment
$firstProperty = @{ Expression = { $_.Details.Fte } ; Descending = $true }
$secondProperty = @{ Expression = { $_.Details.HoursPerWeek }; Descending = $true }

$employmentContractFilter     = { $_.Custom.FieritECDEmploymentIdentifier }  # Dienstverband

 # Set to true if accounts in the target system must be updated
$updatePerson = $true
  ```

##### Update.ps1

  ```PowerShell
# Primary Contract Calculation for each employment
$firstProperty = @{ Expression = { $_.Details.Fte } ; Descending = $true }
$secondProperty = @{ Expression = { $_.Details.HoursPerWeek }; Descending = $true }

$employmentContractFilter     = { $_.Custom.FieritECDEmploymentIdentifier }  # Dienstverband
  ```

##### All Permissions Scripts *(Grant)*

  ```PowerShell
$employmentContractFilter     = { $_.Custom.FieritECDEmploymentIdentifier }  # Dienstverband
  ```

## Getting help

> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
