# Limitations

mishpat is narrow on purpose. This page lists what it cannot do, so nobody relies on it for more than it provides.

## Out of scope

The tool will not:

- Apply, edit, restore, or predict Group Policy. It reads exports and writes reports. It does not change a GPO, a link, a filter, or a file in SYSVOL.
- Show the effective settings on a computer or for a user. What takes effect depends on every GPO that applies, their order and precedence, loopback processing, the computer's site, security filtering, and WMI filters. mishpat compares what each GPO holds, not what takes effect.
- Evaluate WMI filters. It compares a filter's name, description, and query text. It does not run the query or say which computers it matches.
- Evaluate item-level targeting. A Group Policy Preferences item with a filter is compared as written. mishpat does not say whether the item applies to a computer or a user.
- Expand group membership. Security filtering and delegation are compared as the SIDs and rights on the GPO. The report does not say who a change covers.
- Judge whether a change is correct or approved. A difference shows what changed. Whether it should have changed is for you to decide.
- Compare modified times, version numbers, explanation text, or comments. Saving a GPO without changing a setting shows no difference.
- Compare the order of Group Policy Preferences items. It does compare the order of the scripts of one type.
- Monitor or alert in real time. It reads files after the fact.

## What the exports cannot show

mishpat compares what the inputs record. An input that does not record something is not treated as empty. The report lists it under [Not compared](output.md#not-compared).

- **Get-GPOReport files and Backup-GPO folders** do not record link order, blocked inheritance, or the WMI filter query. mishpat compares those only when both inputs are export bundles. [Input formats](formats.md#what-each-input-records) has the full table.
- **Links come from each GPO's own report.** A report lists the scopes a GPO is linked to. It does not list the other GPOs linked there, so it cannot give order.
- **Link order is compared by GUID.** With `--match name`, a GPO that has a different GUID on each side is not part of the link order comparison. mishpat still compares its links GPO by GPO. See [Pairing by name](#pairing-by-name).
- **A scope that exists in one bundle only is not compared.** An organizational unit or site that is new or deleted gives no scope difference and no gap. The links of the GPOs to it still show as link differences.
- **Only the domain, organizational units, and sites are read.** These are the places that hold links in a bundle.
- **User rights and restricted groups show SIDs.** The report shows the members by SID, so a reader may need to look the SID up. The names that the input holds are not shown.
- **An export is not a snapshot.** The exporter backs up the GPOs one after another, then reads the structure. A change made while it runs can show in some parts and not in others. It reads from one controller, so a controller that has not yet replicated a change shows the older state.
- **An added or removed GPO is one difference.** mishpat does not list its settings one by one.
- **A bundle holds more than mishpat reads.** It holds every file of each backup. See [Collecting exports](collecting.md#what-the-bundle-holds).

## Administrative Templates

mishpat has no knowledge of ADMX files. It identifies an Administrative Templates policy by its category and display name, as the report writes them, and compares its state and the value of each of its options, by the option's name.

- **A different name or category is a different policy.** If the text differs between the two reports, mishpat shows one removal and one addition, not a change. A new version of the ADMX files that renames or moves a policy does this. Two reports made with different display languages can do the same.
- **Make both reports the same way.** Use the same computer, or computers with the same ADMX files and display language, for both reports. The same applies to bundles: the names come from the computer that runs the exporter, which for `mishpat collect` is the controller.
- **A policy change often shows twice.** A backup holds the policy in `gpreport.xml` and the registry values it sets in `Registry.pol`. Changing one policy changes both, and mishpat reports both, under the areas `Administrative Templates` and `Registry.pol`. See [Registry.pol](#registrypol).

TODO(verify): confirm on a real domain that `Get-GPOReport` writes policy names and categories in the display language of the computer that runs it, and that two ADMX versions can write different text for one policy. mishpat uses the text as written.

## Generic extensions

An extension that mishpat has no reader for is compared by its XML. See [Other extensions](formats.md#other-extensions).

- The value is the element's attributes, text, and children, so the report shows it as a mapping and not as a sentence.
- An element with no `Name`, `Id`, or `Type`, and with siblings of the same name, is identified by a hash of its content. A change to such an element is a removal and an addition, because the content is its identity.
- Repeated child elements keep their document order, except `Member` elements, which are sorted. A new order of other repeated children is a change.

## Settings defined twice

A report can hold two settings with the same identity in one GPO.

- In a report, mishpat keeps both. It adds `#2`, `#3`, and so on to the key of the later ones, in document order, and pairs settings with their copies by position. Removing the first of two copies shows as a change to the first and a removal of the second.
- In `Registry.pol`, Windows applies the entries in order, and the later one wins. mishpat compares the last entry for each key and value name.

## Registry.pol

- **Only for backups and bundles.** A `Get-GPOReport` file does not hold `Registry.pol`. mishpat compares the values only when both inputs are backups or bundles and every `Registry.pol` file on both sides was read in full. Otherwise it lists `Registry.pol values` under [Not compared](output.md#not-compared).
- **Directives are compared as written.** An entry such as `**del.Name` or `**DeleteValues` is a setting of its own. mishpat never applies it to the values. Removing a directive shows as a removal of that entry.
- **Values show their type and data.** The report shows `type: REG_DWORD; data: 4`. mishpat does not say which policy the value belongs to.

## Pairing by name

`--match name` pairs GPOs by display name. See [Command reference](usage.md#pairing-by-name). It has these limits:

- A name must be unique on each side. A name that appears twice stops the run.
- A GPO with a new name is not paired. It shows as a GPO in one input only.
- Link order is compared by GUID, so it does not cover a GPO with a different GUID on each side.

## Inputs with the same name

A report names each input by its file or folder name only. If the two inputs have the same name, such as `before/gpos.jsonl` and `after/gpos.jsonl`, a problem that names only `gpos.jsonl` does not say which side it came from. Give the inputs different names.

## Paths of links

A report writes a link target as a path such as `corp.example/Servers`. mishpat writes the target of a link from a bundle in the same form, converted from the distinguished name of the scope. mishpat compares them without regard to case.

TODO(verify): the conversion has been checked against synthetic data only. Confirm on a real domain that a link in a `Get-GPOReport` file and the same link in an export bundle give the same path, including for sites and for organizational units whose names hold special characters. If they differ, a comparison of a report with a bundle shows each link as removed and added.

## Size limits

mishpat refuses or reports as a problem:

- A `Get-GPOReport` file larger than 256 MiB.
- A single file inside a backup larger than 64 MiB.
- A bundle with more than 100,000 files, or more than 1 GiB of file bytes.
- XML that nests elements more than 64 levels deep.

## Exporter and collection

- **They have not been run against a real domain, a real domain controller, a real WinRM endpoint, or Windows PowerShell 5.1.** This is a known limitation of this release. See [How far this release has been tested](#how-far-this-release-has-been-tested). Treat the first runs in your environment as a pilot, and report anything unexpected.
- **Rights.** The rights the exporter needs are those Microsoft documents for `Backup-GPO`, for reading the directory, and for PowerShell remoting. mishpat has not tested whether a just-enough-administration endpoint can be narrowed further for the script.
- **One export is one controller at one time.** See [What the exports cannot show](#what-the-exports-cannot-show).
- **A compromised controller can lie.** The end line of a bundle shows that the file arrived whole. It does not show that the controller told the truth. See the [threat model](threat-model.md).
- **Kerberos on Linux and macOS.** `mishpat collect` defaults to Kerberos. On those systems it needs support that the `live` extra does not install. See [Collecting exports](collecting.md#prerequisites).

## How far this release has been tested

- The readers and the report writers are tested on synthetic files. No test in the repository reads a file that Windows wrote.
- The exporter's functions run under PowerShell 7 in the project's checks, with synthetic stand-ins for Active Directory, the Group Policy module, and the computer's name. A separate test checks the script's text: that it is pure ASCII and calls only read-only commands.
- `mishpat collect` is tested with a simulated WinRM client. A test confirms the settings it hands to the real `pypsrp` library: certificate verification on, and message encryption for plain HTTP.
- The example and its sample reports are synthetic, and a test checks that the committed files match what the current code writes.

## Limits of any file-based check

- mishpat sees only what the inputs contain. It cannot detect records an export did not hold.
- A comparison with no differences means the supplied inputs show none. It does not mean two environments behave alike, and it says nothing about whether a change was right.
- Results are only as current as the inputs. Every report shows when it was generated, and a bundle records when it was collected.
- Hashes in the reports and the bundle show that a file is consistent. They do not show who made it. A person who edits a file can compute its hashes again.
