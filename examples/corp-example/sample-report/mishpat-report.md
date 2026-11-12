# GPO change review

**27 differences across 5 GPOs and scope inheritance. Every input was read in full.**

Before: before. After: after. GPOs paired by guid. Generated 2026-11-09T12:00:00Z by mishpat 0.0.0.

## GPOs compared

| Name | GUID | Status | Differences |
| --- | --- | --- | --- |
| Baseline - Servers | 9c3e51b7-2d84-4a6f-8e10-b5f7a2c4d963 | changed | 12 |
| Edge Browser Policy | 73d0c6e8-b2a9-4f15-96c4-8e1b5a7d3f29 | added | 1 |
| Legacy Kiosk Lockdown | e5b94a20-7c16-43d8-85f1-0a6c3d2e9b87 | removed | 1 |
| Staff Desktop Settings | 2f6d8b94-1e57-4c03-b8a6-d9c0e7a31f45 | changed | 3 |
| Workstation Hardening | c71a0e5f-68b3-4d29-9a47-3e8d1f5b0c72 | changed | 8 |
| Default Domain Policy | 4e0b7d1a-93c2-4f68-a1d5-2c7e9b3f6a10 | unchanged | 0 |

## Changes by GPO

### Baseline - Servers (9c3e51b7-2d84-4a6f-8e10-b5f7a2c4d963)

Changed. 12 differences.

- **Status:** computer half enabled; user half enabled
- **WMI filter:** Member servers (Windows Server member servers), id b6f2a1d4-5c37-4e80-9d12-7a4e3c8b0f56, query: 1;3;10;86;WQL;root\\CIMv2;SELECT \* FROM Win32\_OperatingSystem WHERE BuildNumber \>= "20348" AND ProductType = "3";
- **Security filtering:** NT AUTHORITY\\Authenticated Users (S-1-5-11)
- **Links:** corp.example/Servers (enabled, order 1); corp.example/Servers/Web (enabled, order 1)

#### WMI filter

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| WMI filter | changed | name: Member servers; description: Windows Server member servers; query: 1;3;10;83;WQL;root\\CIMv2;SELECT \* FROM Win32\_OperatingSystem WHERE Version LIKE "10.%" AND ProductType = "3"; | name: Member servers; description: Windows Server member servers; query: 1;3;10;86;WQL;root\\CIMv2;SELECT \* FROM Win32\_OperatingSystem WHERE BuildNumber \>= "20348" AND ProductType = "3"; | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml; after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml |

#### Links

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| corp.example/Servers/Web | added | (not set) | enabled: true; enforced: false | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml; after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml |

#### Settings

##### Computer · Administrative Templates

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| Turn off Autoplay | removed | state: Enabled; elements: \[(kind: DropDownList, name: Turn off Autoplay on:, state: Enabled, value: All drives)\] | (not set) | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml Computer/Registry/Policy\[Turn off Autoplay\] |
| Disable Windows Error Reporting | added | (not set) | state: Enabled; elements: \[\] | after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml Computer/Registry/Policy\[Disable Windows Error Reporting\] |
| Configure Automatic Updates | changed | state: Enabled; elements: \[(kind: DropDownList, name: Configure automatic updating:, state: Enabled, value: 3 - Auto download and notify for install), (kind: DropDownList, name: Scheduled install day:, state: Enabled, value: 0 - Every day), (kind: Numeric, name: Scheduled install time:, state: Enabl… (314 characters; full value in the JSON report) | state: Enabled; elements: \[(kind: DropDownList, name: Configure automatic updating:, state: Enabled, value: 4 - Auto download and schedule the install), (kind: DropDownList, name: Scheduled install day:, state: Enabled, value: 0 - Every day), (kind: Numeric, name: Scheduled install time:, state: Ena… (316 characters; full value in the JSON report) | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml Computer/Registry/Policy\[Configure Automatic Updates\]; after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml Computer/Registry/Policy\[Configure Automatic Updates\] |

##### Computer · Advanced Audit

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| Audit Logon | changed | 1 | 3 | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml Computer/Auditing/AuditSetting\[Audit Logon\]; after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml Computer/Auditing/AuditSetting\[Audit Logon\] |
| Audit File Share | removed | 3 | (not set) | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/gpreport.xml Computer/Auditing/AuditSetting\[Audit File Share\] |
| Audit Process Creation | added | (not set) | 1 | after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/gpreport.xml Computer/Auditing/AuditSetting\[Audit Process Creation\] |

##### Computer · Registry.pol

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\\*\*del.UseWUServer | added | (not set) | type: REG\_SZ; data:   | after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/DomainSysvol/GPO/Machine/registry.pol entry 7 |
| Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun | removed | type: REG\_DWORD; data: 255 | (not set) | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/DomainSysvol/GPO/Machine/registry.pol entry 6 |
| Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Disabled | added | (not set) | type: REG\_DWORD; data: 1 | after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/DomainSysvol/GPO/Machine/registry.pol entry 6 |
| Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\AUOptions | changed | type: REG\_DWORD; data: 3 | type: REG\_DWORD; data: 4 | before: corp-before.jsonl:{0D84B6E1-C2A7-4F39-B5D0-7E9A1C3F8B26}/DomainSysvol/GPO/Machine/registry.pol entry 2; after: corp-after.jsonl:{7E3D95A1-0F6C-48B2-8D17-A4C2E9B60F53}/DomainSysvol/GPO/Machine/registry.pol entry 2 |

### Edge Browser Policy (73d0c6e8-b2a9-4f15-96c4-8e1b5a7d3f29)

Added. 1 difference.

- **Status:** computer half enabled; user half enabled
- **WMI filter:** none
- **Security filtering:** NT AUTHORITY\\Authenticated Users (S-1-5-11)
- **Links:** corp.example/Workstations (enabled, order 3)

#### GPO

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| Edge Browser Policy | added | (not set) | (not set) | after: corp-after.jsonl:{9F05E6C2-D3A8-4B71-8E24-1C7B4A0D6E93}/gpreport.xml |

### Legacy Kiosk Lockdown (e5b94a20-7c16-43d8-85f1-0a6c3d2e9b87)

Removed. 1 difference.

#### GPO

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| Legacy Kiosk Lockdown | removed | (not set) | (not set) | before: corp-before.jsonl:{1B7F4E90-A6D3-4C58-9E02-D8C3B5F7A164}/gpreport.xml |

### Staff Desktop Settings (2f6d8b94-1e57-4c03-b8a6-d9c0e7a31f45)

Changed. 3 differences.

- **Status:** computer half disabled; user half enabled
- **WMI filter:** none
- **Security filtering:** NT AUTHORITY\\Authenticated Users (S-1-5-11)
- **Links:** corp.example/Workstations (disabled, order 1)

#### Status

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| computer half | changed | enabled | disabled | before: corp-before.jsonl:{58C0D3B7-E4A1-4296-B7F8-2A9E5D1C6403}/gpreport.xml; after: corp-after.jsonl:{D41B7E03-6A92-4C8F-B150-9E3A2D7C5F08}/gpreport.xml |

#### Permissions (delegation)

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| CORP\\Helpdesk Operators (S-1-5-21-1000-2000-3000-1204) | removed | Read | (not set) | before: corp-before.jsonl:{58C0D3B7-E4A1-4296-B7F8-2A9E5D1C6403}/gpreport.xml; after: corp-after.jsonl:{D41B7E03-6A92-4C8F-B150-9E3A2D7C5F08}/gpreport.xml |

#### Links

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| corp.example/Workstations | changed | enabled: true; enforced: false | enabled: false; enforced: false | before: corp-before.jsonl:{58C0D3B7-E4A1-4296-B7F8-2A9E5D1C6403}/gpreport.xml; after: corp-after.jsonl:{D41B7E03-6A92-4C8F-B150-9E3A2D7C5F08}/gpreport.xml |

### Workstation Hardening (c71a0e5f-68b3-4d29-9a47-3e8d1f5b0c72)

Changed. 8 differences.

- **Status:** computer half enabled; user half enabled
- **WMI filter:** Windows clients (Windows 10 and Windows 11 computers), id 1d9e4b7a-8f25-4c63-a0b1-6e2d5f379c48, query: 1;3;10;83;WQL;root\\CIMv2;SELECT \* FROM Win32\_OperatingSystem WHERE Version LIKE "10.%" AND ProductType = "1";
- **Security filtering:** CORP\\Pilot Workstations (S-1-5-21-1000-2000-3000-1301), NT AUTHORITY\\Authenticated Users (S-1-5-11)
- **Links:** corp.example/Workstations (enabled, enforced, order 2)

#### GPO

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| name | renamed | Workstation Baseline | Workstation Hardening | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml |

#### Security filtering

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| CORP\\Pilot Workstations (S-1-5-21-1000-2000-3000-1301) | added | (not set) | applies | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml |

#### Links

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| corp.example/Workstations | changed | enabled: true; enforced: false | enabled: true; enforced: true | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml |

#### Settings

##### Computer · Security

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| LockoutBadCount | changed | 10 | 5 | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml Computer/Security/Account\[LockoutBadCount\]; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml Computer/Security/Account\[LockoutBadCount\] |
| Interactive logon: Machine inactivity limit | added | (not set) | 900 | after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml Computer/Security/SecurityOptions\[Interactive logon: Machine inactivity limit\] |
| Network security: LAN Manager authentication level | changed | 3 | 5 | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml Computer/Security/SecurityOptions\[Network security: LAN Manager authentication level\]; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml Computer/Security/SecurityOptions\[Network security: LAN Manager authentication level\] |
| Network access: Restrict anonymous access | removed | 1 | (not set) | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml Computer/Security/SecurityOptions\[Network access: Restrict anonymous access\] |
| SeDenyNetworkLogonRight | changed | S-1-5-32-546 | S-1-5-113, S-1-5-32-546 | before: corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml Computer/Security/UserRightsAssignment\[SeDenyNetworkLogonRight\]; after: corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml Computer/Security/UserRightsAssignment\[SeDenyNetworkLogonRight\] |

## Scope inheritance

### Links

| Subject | Kind | Before | After | Note | Sources |
| --- | --- | --- | --- | --- | --- |
| OU=Workstations,DC=corp,DC=example: link order | changed | Workstation Hardening, Staff Desktop Settings | Staff Desktop Settings, Workstation Hardening | Order among the GPOs linked here on both sides; added or removed links are listed under each GPO. | before: corp-before.jsonl structure scope 4; after: corp-after.jsonl structure scope 4 |

### Inheritance

| Subject | Kind | Before | After | Sources |
| --- | --- | --- | --- | --- |
| OU=Web,OU=Servers,DC=corp,DC=example | changed | not blocked | blocked | before: corp-before.jsonl structure scope 3; after: corp-after.jsonl structure scope 3 |

## Inputs

| File | Kind | Bytes | SHA-256 |
| --- | --- | --- | --- |
| corp-before.jsonl | export | 83586 | 82d77f942c418094510310d7e9bcff075051b558701a35e55b89496d454ea842 |
| corp-after.jsonl | export | 84608 | d0da271e200b96b3fe95ef5b1dfaf60085be5c58484fb14b0f0e210d0092079f |

## Limitations

- mishpat compares what the inputs record. It cannot show the effective settings on a computer or for a user, which depend on every GPO that applies, their order, loopback processing, and the computer's site.
- Item-level targeting in Group Policy Preferences is compared as written. mishpat does not evaluate whether an item applies to a computer or user.
- WMI filters are compared by name and description, and by query text only when the input recorded it. mishpat does not evaluate a filter.
- Link order, blocked inheritance and WMI query text are compared only when the input came from the mishpat exporter. Get-GPOReport files and Backup-GPO folders do not record them.
- Security filtering and delegation are compared as the SIDs and rights on the GPO. Group membership is not expanded, so the report does not say who is covered.
- Version numbers, modified times and explanation text are shown for context but are not compared, so saving a GPO without changing a setting shows no difference.
- A difference shows what changed. It does not say whether the change is correct or approved.
