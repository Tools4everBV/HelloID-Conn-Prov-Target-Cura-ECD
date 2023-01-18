
# HelloID-Conn-Prov-Target-Fierit-ECD

| :warning: Warning |
|:---------------------------|
| Note that this is a complex connector. Please contact Tools4ever before implementing this connector! |

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<p align="center">
  <img src="https://tenzinger.com/wp-content/uploads/2021/06/Tenzinger_600x600.jpg"
   alt="drawing" style="width:300px;"/>
</p>

## Table of contents

- [Table of contents](#Table-of-contents)
- [Introduction](#Introduction)
- [Getting started](#Getting-started)
  + [Connection settings](#Connection-settings)
  + [Prerequisites](#Prerequisites)
- [Provisioning](#Provisioning)
  + [Supported Features](#Supported-Features)
  + [Supported Action Details](#Supported-Action-Details)
  + [Remarks](#Remarks)
- [Setup the connector](@Setup-The-Connector)
- [Getting help](#Getting-help)
- [HelloID Docs](#HelloID-docs)

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
 - A additional mapping between HR departments and/or Titles to SelectionAuthorisationGroup to assign a "Scope" on a Role
- An custom property on the HelloID contract with a combination of the employeeCode and EmploymentCode named: [custom.FieritECDEmploymentIdentifier]
Example:
```JavaScript
  function getValue() {
      return sourceContract.PersonCode + "-" + sourceContract.EmploymentCode
  }
  getValue();
  ```

#### Creation / correlation process
A new functionality is the possibility to update the account in the target system during the correlation process. By default, this behavior is disabled. Meaning, the account will only be created or correlated.
You can change this behavior in the `create.ps1` by setting the boolean `$updatePerson` to the value of `$true`.

> Be aware that this might have unexpected implications.

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
- The web service is only Accessible with whitelisted IP addresses. So an Agent server is required. *Not sure if Fierit supports DNS whitelisting*
- The web service does not support Patch requests. So the user is retrieved from Fierit, adds the new permission, and the user is updated with the current permission and newly permission. Therefore, concurrent sessions must be set to 1.
 - A dummy or Default Role for creating new users. It's required to set a role when creating a new User. Because they take place in the account lifecycle the first role cannot be managed through entitlements.
 - Because the Connector Support multiplies account per Persons, the permission Update script must also be used. You can place the Grant script here since this works in both situations.


## Setup the connector

### Configuration settings
* Make sure to set the **Concurrent Action limited to one** and runs on a local agent server.
* Make sure the sub Permissions are enabled for all permissions configurations

#### Script Settings
* Besides the configuration tab, you can also configure script variables. To decide which property from a HelloID contract is used to look up a value in the mapping table, this is known as the HR Location or HR Team. And you can configure the primary contract calculation for each employment. Please note that some "same" configuration takes place in multiple scripts. Shown as below:

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
