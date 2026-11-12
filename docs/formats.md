# Input formats

mishpat reads three kinds of input. Each side of a comparison is one path, either a file or a folder. mishpat decides the kind from the content, never from the name. A file named `before.xml` that is an export bundle is read as an export bundle.

| Input | How you get it | Read as |
| --- | --- | --- |
| [Get-GPOReport XML](#get-gporeport-xml) | `Get-GPOReport -ReportType Xml` | One file |
| [Backup-GPO folder](#backup-gpo-folder) | `Backup-GPO` | One folder |
| [Export bundle](#export-bundle) | `mishpat exporter` or `mishpat collect` | One file |

Use the export bundle when you can. It records the most. The other two are conveniences, and each one lacks something, as the next section shows.

## How the kind is detected

1. A path that is a folder is read as a [Backup-GPO folder](#backup-gpo-folder). A folder with no `bkupInfo.xml` in it or in the folders below it is refused.
2. A file whose first bytes are `{"mishpat_export":` is an [export bundle](#export-bundle).
3. Any other file is read as [Get-GPOReport XML](#get-gporeport-xml). A file that is not XML, or whose root element is not `GPO` or `GPOS`, is refused.

A path that does not exist, or that cannot be read, is refused. Refusals exit with code `3`. See [Command reference](usage.md#exit-codes).

## What each input records

An input that does not record something is never treated as if the thing were empty. mishpat lists it under [Not compared](output.md#not-compared) and does not invent a difference.

| What | Get-GPOReport XML | Backup-GPO folder | Export bundle |
| --- | --- | --- | --- |
| Settings of every extension | Yes | Yes, from `gpreport.xml` | Yes |
| `Registry.pol` values | No | Yes | Yes |
| Computer and user half enabled | Yes | Yes | Yes |
| Links of a GPO (enabled and enforced state) | Yes | Yes, from `gpreport.xml` | Yes |
| Link order | No | No | Yes |
| Blocked inheritance on a scope | No | No | Yes |
| WMI filter name and description | Yes | Yes | Yes |
| WMI filter ID | No | Yes, from `Backup.xml` | Yes |
| WMI filter query | No | No | Yes |
| Security filtering and delegation | Yes | Yes, from `gpreport.xml` | Yes |
| A whole domain, so a missing GPO was deleted | Only for a `<GPOS>` file | Never | Only when the scope is `all` |

Three rules follow from the table:

- Link order, blocked inheritance, and the WMI filter query are compared only when both inputs are export bundles. Link order and blocked inheritance need both sides to record the domain structure. The query is compared when both sides record it, which only bundles do. See [Limitations](limitations.md#what-the-exports-cannot-show).
- `Registry.pol` values are compared only when both inputs are backups or bundles. See [Registry.pol](#registrypol).
- A GPO that is missing from one input is reported as deleted or created only when both inputs are whole domains. Otherwise it is reported as only in one input. See [Differences](output.md#differences).

## Encoding

mishpat reads XML as text that it decodes itself. It ignores the encoding that the XML declaration names. Many `Get-GPOReport` files are UTF-16 with a byte order mark, and some `-All` captures are UTF-8 bytes whose declaration still says `utf-16`. Trusting the declaration would fail on those files.

The rules, in order:

1. A UTF-8 byte order mark: the rest is UTF-8.
2. A UTF-16 byte order mark, little-endian or big-endian: the rest is UTF-16 in that byte order.
3. No byte order mark: strict UTF-8, unless a NUL character appears in the first 256 characters.
4. Otherwise UTF-16, big-endian when the first byte is `0x00` and little-endian when it is not.

Text that fits none of these is refused. The bundle is JSON and must be UTF-8. The exporter writes pure ASCII.

## Get-GPOReport XML

The output of `Get-GPOReport -ReportType Xml`. Two shapes work:

- One `<GPO>` element in the namespace `http://www.microsoft.com/GroupPolicy/Settings`, from `-Name` or `-Guid`.
- An unnamespaced `<GPOS>` element that wraps many `<GPO>` elements, from `-All`. mishpat treats a `<GPOS>` file as a whole domain.

On an administration workstation with RSAT:

```powershell
Get-GPOReport -Name 'Workstation Baseline' -ReportType Xml -Path .\before.xml
Get-GPOReport -All -ReportType Xml -Path .\before-all.xml
```

mishpat identifies every element by its namespace URI. The prefixes in a file, such as `q1` and `q2`, vary, and they mean nothing.

### What mishpat reads

For each GPO, mishpat reads:

- The GUID (lower case, no braces), domain, and display name.
- Whether the computer half and the user half are enabled.
- The WMI filter name and description. A report with `FilterDataAvailable` set to `false` is recorded as unknown, not as having no filter.
- The links (`LinksTo`): the scope path, enabled, and enforced (`NoOverride`). A report that lists no link gives an empty list of links.
- The security descriptor: each trustee with its SID, name, allow or deny, and rights. A report without `PermissionsPresent` set to `true` gives no permissions, which is recorded as not recorded.
- The settings of every extension, as [Settings](#settings) describes.

mishpat reads the created and modified times, the version numbers, and the explanation and comment text, but it never compares them and the report does not show them. `ReadTime`, `Blocked`, `GPOSettingOrder`, `Explain`, and `Supported` are always left out of values.

### Limits

mishpat refuses a file that:

- Is larger than 256 MiB.
- Declares a `DOCTYPE` or an entity.
- Nests elements more than 64 levels deep.
- Is not well-formed XML.
- Has a root element other than `GPO` or `GPOS`.

A GPO element that cannot be read does not stop the file. mishpat records a [problem](output.md#problems) and reads the others. These are problems:

- A GPO with no identifier or name, or an identifier that is not a GUID.
- A GUID that appears twice in one file. The later GPO is not read.
- An element inside `<GPOS>` that is not a GPO, or a `<GPOS>` element with no GPO.
- A version number that is not a number.
- A setting that lacks what identifies it, such as a policy with no name or a registry setting with no key path.

## Backup-GPO folder

The output of `Backup-GPO`. Each backup is a folder named by a backup ID (a GUID in braces):

```text
{backup-id}/
  bkupInfo.xml
  Backup.xml
  gpreport.xml
  DomainSysvol/GPO/Machine/registry.pol
  DomainSysvol/GPO/User/registry.pol
```

Give mishpat either one backup folder, or a root folder that holds many. A root is any folder that is not itself a backup folder. mishpat searches up to four levels below it for folders that hold `bkupInfo.xml`, and reads each as one GPO. The `manifest.xml` that `Backup-GPO` writes beside the backups is not read.

```powershell
Backup-GPO -All -Path .\before
Backup-GPO -Name 'Workstation Baseline' -Path .\before
```

A root that holds two backups of the same GPO is ambiguous, and mishpat refuses it with exit code `3`. The error names both folders. `Backup-GPO` makes a new folder for each backup, so backing up the same GPO twice into one path gives two backups. Back up each version into its own folder.

### What mishpat reads

mishpat reads four files and ignores the rest. It looks up names without regard to case, and it does not follow links.

| File | What mishpat takes from it |
| --- | --- |
| `bkupInfo.xml` | The GPO GUID and the name, domain, backup ID, backup time, and comment. A backup with no GUID here or in `Backup.xml` is a problem and is not read. |
| `gpreport.xml` | The GPO, read exactly as [Get-GPOReport XML](#get-gporeport-xml). This is the main source. |
| `Backup.xml` | The WMI filter ID, when the filter has the same name in the report. Without a usable `gpreport.xml`, also the name, the domain, which halves are enabled, and the WMI filter name. |
| `registry.pol` | The [`Registry.pol` values](#registrypol) of the computer half (`Machine`) and the user half (`User`). |

Files such as `GptTmpl.inf`, `audit.csv`, and the Preferences XML files are not read. Their content is in `gpreport.xml`.

### A backup without `gpreport.xml`

When `gpreport.xml` is missing or unusable, mishpat records a problem, `gpreport.xml missing: settings other than registry.pol were not compared`, and the comparison is incomplete. It builds the GPO from `bkupInfo.xml` and `Backup.xml` and adds the `Registry.pol` values. It does not record links, security filtering, or settings other than `Registry.pol`, so those appear under [Not compared](output.md#not-compared).

A `gpreport.xml` that holds no GPO with the backup's GUID is also a problem, and a single file larger than 64 MiB is not read.

## Registry.pol

`Registry.pol` holds the registry values that Administrative Templates policies write. A report lists those policies by name and category, so mishpat compares them there. The `Registry.pol` file holds the values the policies set, which the report does not show as registry keys. mishpat reads it from backups and bundles.

mishpat reads the file as the format `[MS-GPREG]` defines: the signature `PReg`, version 1, then entries of the form `[key;value;type;size;data]`.

Each entry becomes one setting in the area `Registry.pol`. Its identity is the key path and the value name, compared without regard to case. Its value is the registry type and the data:

| Type | Data |
| --- | --- |
| `REG_SZ`, `REG_EXPAND_SZ` | Text, without the terminator. |
| `REG_MULTI_SZ` | A list of text. |
| `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_QWORD` | A number. |
| Every other type, including `REG_BINARY` | Lower-case hex. |

An entry whose value name starts with `**` is a directive, such as `**del.` or `**DeleteValues`. mishpat keeps each directive as a setting of its own and never applies it to the values. It compares what the file says, not what the file does when Windows applies it.

When the same key and value name appear more than once, Windows applies the entries in order and the later one wins. mishpat keeps the last entry's value and the first entry's position, and records how many entries there were.

A file that does not start with `PReg`, or that has another version, gives no values, and a problem. A damaged entry stops the read, keeps the entries before it, and gives a problem. Data that does not fit its type, such as a DWORD that is not four bytes, is kept as hex with a problem.

mishpat compares `Registry.pol` values only when both inputs are backups or bundles and every `Registry.pol` file on both sides was read in full. Otherwise it skips them and says so under [Not compared](output.md#not-compared).

## Settings

Every setting has a scope (`Computer`, `User`, or none), an area, a kind, a key, a title, and a value. Two settings with the same scope, area, kind, and key, compared without regard to case, are the same setting. The value is what mishpat compares. A list that is a set, such as the members of a user right, is sorted first, so a new order alone is not a change.

| Area and kind | Key | Value |
| --- | --- | --- |
| Administrative Templates, Policy | Category and policy name | The state, and every element of the policy with its kind, name, state, and value |
| Registry, Registry Setting | Key path and value name | The number or text |
| Security, Account | Type and name | The number or flag |
| Security, Security Option | Key name, or system access policy name | The number or text |
| Security, User Rights Assignment | Right name | The sorted members, by SID, or by name when there is no SID |
| Security, Restricted Group | Group SID, or name | The sorted members and the groups it is a member of |
| Security, System Service | Service name | The startup mode, and the SDDL when present |
| Security, Audit | Audit name | Success and failure |
| Security, Event Log | Log and setting name | The number or flag |
| Advanced Audit, Audit Setting | Policy target and subcategory GUID | The audit setting value |
| Scripts, Script | Script type, in each scope | The ordered list of commands, parameters, and order |
| Preferences: type, one kind per item | The collection path and the item `uid`, or the item's target when it has no `uid` | The item's attributes, properties, and filters |
| Folder Redirection, Folder | The folder ID | The folder's content |
| Any other extension | See [Other extensions](#other-extensions) | The element's content |

The Administrative Templates key is the policy's display name and category as the report writes them. See [Limitations](limitations.md#administrative-templates).

For Preferences items, mishpat leaves out the `changed`, `image`, `status`, `uid`, and `descr` attributes from the value. It keeps item-level targeting, which the report writes as filters, as written. It does not evaluate it.

### Other extensions

An extension that mishpat has no reader for is compared generically. Each child element of the extension becomes one setting. The area is the namespace after `http://www.microsoft.com/GroupPolicy/Settings/`, or the whole namespace for another one. The kind is the element name. The value is the element's attributes, text, and children.

The key is, in this order:

1. The text of a `Name` child, or else an `Id` child.
2. A `Name`, `Id`, or `Type` attribute.
3. Nothing, when the element is the only one of its name in that half of the GPO.
4. A hash of the element's content.

With the fourth rule, a change to the element is a removal and an addition, because the content is its identity. See [Limitations](limitations.md#generic-extensions).

### Settings defined twice

When a report holds two settings with the same identity in one GPO, mishpat keeps both. It adds `#2`, `#3`, and so on to the key of the later ones, in document order, and pairs settings with their copies by that position. Removing the first of two copies then shows as a change to the first and a removal of the second. See [Limitations](limitations.md#settings-defined-twice).

## Export bundle

A bundle is one file that holds the GPOs, as `Backup-GPO` folders, and the structure of the domain: where the GPOs are linked and which WMI filters exist. The exporter script writes it, either on a computer you run it on or on a domain controller over WinRM. [Collecting exports](collecting.md) shows how. [ADR 4](adr/0004-export-bundle.md) records why the format looks like this.

The file is JSON Lines. It is UTF-8, with one JSON object on each line and `\n` between lines. The exporter writes pure ASCII and escapes every other character as `\uXXXX`. `mishpat schema export` prints the JSON Schema. Its identifier is `https://faithful-oversight.github.io/faithful-mishpat/schema/export-v1.schema.json`.

A bundle has these lines, in this order:

1. One header line.
2. Zero or more file lines.
3. One structure line.
4. One trailer line.

### Header

The first line starts, byte for byte, with `{"mishpat_export":`. That marker is how mishpat knows the file. Here is a header:

```json
{"mishpat_export":1,"collector":{"name":"Export-MishpatGpo.ps1","version":"0.1.0"},"domain":"corp.example","collected_at":"2026-11-02T08:00:00Z","scope":"all"}
```

| Property | Meaning |
| --- | --- |
| `mishpat_export` | The format version. Always `1`. |
| `collector` | The `name` and `version` of the program that wrote the file. |
| `domain` | The DNS name of the domain. |
| `collected_at` | When the export ran. A UTC time with a `Z` suffix and up to seven fraction digits. |
| `scope` | `"all"` when every GPO of the domain was exported, otherwise a list of the GUIDs that were asked for. |

The header has exactly these properties. Only a bundle with `scope` set to `"all"` is a whole domain.

### File lines

Each file line holds one file of a `Backup-GPO` folder. The hash and the data text are cut short in this example:

```json
{"path":"{7a1c0e55-1111-4222-8333-444455556666}/gpreport.xml","size":4120,"sha256":"3f6b...","data":"PD94bWwg..."}
```

| Property | Meaning |
| --- | --- |
| `path` | The path inside the bundle. It starts with the backup folder name and uses `/` between names. |
| `size` | The size of the file in bytes, from 0 to 67,108,864 (64 MiB). |
| `sha256` | The SHA-256 of the file's bytes, as 64 lower-case hex digits. |
| `data` | The file's bytes in standard base64 with padding. |

The exporter writes every file that `Backup-GPO` wrote for the GPO, in order of path. That is more than mishpat reads. See [Collecting exports](collecting.md#what-the-bundle-holds).

mishpat checks each file line. A line that fails any check is not used, and mishpat records a problem. The checks are:

- The path is relative and at most 512 characters. Its names are not empty and are not `.` or `..`. It holds no `:`, no `\`, and no control character.
- The path is unique when compared without regard to case, and it is not inside another file.
- The data is valid base64, and its length and SHA-256 match `size` and `sha256`.
- The bundle holds at most 100,000 files and 1 GiB of file bytes in all.

The path rules stop a bundle from naming a place outside the tree that mishpat builds. mishpat never writes these files to disk. It holds them in memory and reads them as it would read a backup folder.

### Structure line

One line holds the structure of the domain:

```json
{"structure":{"scopes":[{"path":"OU=Servers,DC=corp,DC=example","kind":"ou","blocked":false,"gplink":"[LDAP://cn={7a1c0e55-1111-4222-8333-444455556666},cn=policies,cn=system,DC=corp,DC=example;0]"}],"wmi_filters":[{"id":"{c6a4a2f0-0000-4000-8000-000000000001}","name":"Windows 11 only","description":"","query":"SELECT * FROM Win32_OperatingSystem WHERE Version LIKE \"10.0.2%\""}]}}
```

| Property | Meaning |
| --- | --- |
| `scopes` | The domain, every organizational unit, and every site. Each has the distinguished name (`path`), the `kind` (`domain`, `ou`, or `site`), whether it blocks inheritance (`blocked`, from bit 1 of `gPOptions`), and the raw `gPLink` attribute (`gplink`, empty when there are no links). |
| `wmi_filters` | Every WMI filter, with its `id`, `name`, `description`, and the WQL `query`. |
| `gaps` | Present only when the exporter could not read part of the directory. Each entry has `what` and `reason`. |

Each list holds at most 100,000 entries. A second structure line is not used, and mishpat records a problem.

mishpat reads the `gPLink` attribute as [MS-GPOL] defines it. Each link is `[LDAP://cn={GUID},...;options]`. Bit 1 of the options turns the link off. Bit 2 enforces it. The last entry in the string has link order 1. mishpat gives each link its order from that, and takes enabled and enforced from the directory. It adds a link that the directory lists and the GPO's report does not. It writes each link target in the form a report uses, such as `corp.example/Servers`, so a bundle and a report file compare. A site is written as its name.

Each `gaps` entry becomes a problem, `WHAT was not read: REASON`, and the comparison is incomplete.

A bundle with no structure line is accepted, and then it records no link order and no blocked inheritance. The exporter always writes a structure line.

### Trailer line

The last line says the file is whole:

```json
{"end":true,"files":12,"sha256":"cd02..."}
```

| Property | Meaning |
| --- | --- |
| `end` | Always `true`. |
| `files` | How many file lines the bundle holds. |
| `sha256` | The SHA-256 of every byte before the trailer line, each line with its `\n`. |

The hash detects a file that was cut short or damaged. It does not show who wrote the file, because anyone who edits a bundle can compute the hash again. See the [threat model](threat-model.md).

### How mishpat reads a bundle

mishpat reads the file line by line. Only a first line that is not a valid header stops the run, with exit code `3`. Every other fault is a [problem](output.md#problems), the comparison is incomplete, and mishpat uses every line that is fine. These are problems:

- A line that is not valid JSON, has a repeated property name, holds `NaN` or an unpaired surrogate, nests deeper than 8 levels, or does not match the schema. A line may be at most 89,482,584 bytes.
- A file line that fails a check in [File lines](#file-lines).
- A missing or second structure line, or a scope, filter, or gap entry that is not valid.
- A file with no trailer, which was cut short, or with a file count or hash that does not match what mishpat read.
- Anything after the trailer.
- A GUID that the header lists in `scope` and that has no backup in the bundle.

Two backups of the same GPO in one bundle are an input error, as in a folder.
