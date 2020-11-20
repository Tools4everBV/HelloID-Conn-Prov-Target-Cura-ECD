# HelloID-Conn-Prov-Target-Cura-ECD

Note that this is connector is **'a work in progress'** and therefore not ready to use in your  production environment. 

[TOC]

## Todo

| SoapAction            | Description                                                  | Status          |
| --------------------- | ------------------------------------------------------------ | --------------- |
| SyncUsers             | Both the create/update calls have to ability to add/change 'templateUserCodes' and 'locationAuthorisationCodes'. Both of which of [Arrays]. At this point there's no test environment available to implement this functionality. | Not implemented |
| -                     | Sometimes soap calls require HTTP headers containing the SOAP action that needs to be executed. It might not be necessary for this particular connector but it's worth to note. |                 |
| -                     | Since the code currently is developed on 'PowerShell Core 7.0.3.' for Linux, it might still run on 'Windows PowerShell 5.1' . However this is not tested as of yet. |                 |
| FetchSyncedUserList11 | The 'FunctionLib.ps1' contains a few example calls to retrieve data from Cura ECD with only one of them supporting paging. This is because paging is only available for the 'FetchSyncedUserList11' SOAP action. |                 |

- [ ] Develop *'delete.ps1'*
- [ ] Develop *'update.ps1'*


- [ ] Develop *'entitlements.ps1'*
- [ ] Verify if the HTTP headers containing the SOAP action are necessary for each individual SOAP request
- [ ] Implement functionality to add/change the 'templateUserCodes' and 'locationAuthorisationCodes'

## Introduction

## Prerequisites

## Getting Started
