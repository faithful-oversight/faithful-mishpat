# 6. Rules for comparing two versions of Group Policy

- Status: accepted
- Date: 2026-11-11

## Context

A comparison tool can fail in two opposite ways. It can show noise: differences that are not changes, such as a list in a new order or a modified time. Or it can invent: show a difference where an input simply did not record something. Both teach readers to stop trusting the report. A reviewer of a change record needs to see every change and nothing else, and needs to know what the tool could not check.

Group Policy adds problems of its own:

- A GPO has a GUID and a display name, and either can change. A GPO that is deleted and created again has a new GUID. Two generations of a security baseline have different GUIDs for the same policy.
- The three kinds of input record different things. A `Get-GPOReport` file has no link order. A backup has no blocked inheritance. Only the export bundle has the structure of the domain.
- Many values are sets: the members of a user right, security filtering, and delegation. The options of a policy are keyed by name.
- Link order is a property of a scope, not of a GPO. Adding one link to a scope changes the position of every link after it.
- A GPO missing from an input may be deleted, or may not have been exported.
- Administrative Templates settings have no registry key in a report. Their identity is a display name and a category.

## Decision

- **Pairing.** Pair GPOs by GUID. With `--match name`, pair them by display name, compared without regard to case, and refuse a name that is not unique on one side. When the inputs share no GPO by GUID, say so in a notice and suggest `--match name`.
- **Identity per setting type.** A setting's identity is its scope, area, kind, and key, compared without regard to case. The key depends on the type: the category and name of a policy, the key path and value name of a registry setting, the SID or name of a group, the GUID of an audit subcategory, the item `uid` of a Preferences item, and so on. An extension that mishpat has no reader for is compared generically, by the name, the ID, or a hash of the element.
- **Set comparison.** Sort every value that is a set before it is compared, so a new order is never a difference.
- **Gaps instead of invented differences.** Never compare a value that an input does not record. Say what was not compared and why, as a gap. The model keeps *not captured* apart from *empty*, so the comparison can tell them apart. A gap does not make a comparison incomplete. A problem, something that could not be read, does.
- **Leave out what is not a change.** Do not compare modified times, version numbers, explanation text, comments, or the order of Preferences items. Saving a GPO without changing a setting shows no difference.
- **Settings need evidence on both sides.** A setting in one input only is `added` or `removed` only when its source, the report's Computer or User half or that half's `Registry.pol`, was read on both sides. A backup whose `gpreport.xml` is missing or unusable, a report without a Computer or User section, a half in which any element was skipped as malformed (that half's report settings are then read only in part; its `Registry.pol` is judged on its own), and a `Registry.pol` that is a link or cannot be read all leave that source not fully read: the setting is not listed, a gap says why, and a problem marks the input incomplete. An absent `Registry.pol` in a backup that was otherwise read means that half sets no values, so a deleted file is still a removal.
- **Ambiguity is never resolved by choosing.** A part of a report that should appear once (a GPO's Computer or User section, its security descriptor or WMI filter fields, or a half's enabled flag or versions) that appears more than once with different contents is a problem, and that part is not compared; identical copies are read as one. A link listed twice with different settings leaves the GPO's links not compared. Two names in a backup or bundle that Windows could not tell apart (they differ only in case, or a file and a folder share a name) and a WMI filter recorded twice with different queries are problems, not a silent pick.
- **Scopes in one input only.** Report such a scope only when it blocks inheritance, as `added` or `removed` when both inputs are whole domains and as `only-before` or `only-after` otherwise. Its links are already listed under each GPO.
- **Stored passwords.** A Group Policy Preferences `cpassword` is encrypted with a key Microsoft published, so showing it shows the password. Readers replace it, wherever it appears (an attribute, a nested element, or an element that is itself a setting), with a keyed fingerprint of everything it holds, including text between its children, and the key is random for each run. Nothing inside such an element names a setting: one that stands where a setting would start becomes one setting per element name and place, keyed only by that, whose value is the sorted fingerprints of all such elements there. A change is still found, every output shows `(hidden stored password)` instead, and the fingerprint cannot be used to test guesses because its key is never kept.
- **Link order per scope.** Compare the order of links on a scope among the GPOs that are linked there on both sides. A link added or removed shows under its GPO, not as a move of every later link.
- **Whole domains.** Report a GPO that is missing from one input as `removed` or `added` only when both inputs are whole domains. Otherwise report `only-before` or `only-after`, and add a notice.
- **Registry.pol.** Compare `Registry.pol` values only when both inputs are backups or bundles read in full. Keep directives as entries of their own and never apply them.
- **Security filtering and delegation.** Compare security filtering as the set of trustees with an allow entry for Apply Group Policy. Compare every other entry as delegation, by SID, and by allow or deny.
- **Owner, group, and raw descriptor.** Compare the owner and the primary group, and compare a permission entry with no named right by its access mask. Compare the raw SDDL text last and list it only when nothing named explains the change. Whatever the reader cannot interpret is a problem (the comparison is incomplete) or a gap (the input does not record it). The comparison never reports a clean result for a part it did not compare.
- **WMI filters.** Compare name and description. Compare the query only when both inputs record it. Never evaluate a filter.
- **Every difference keeps its sources.** Each difference carries where each side was read, so a reviewer can check it by hand.

## Consequences

Reports are short, and each line is a change. A reader can trust that an absent difference means the inputs showed none, and that a gap names what the inputs could not show.

The rules have costs:

- A policy that is renamed in an ADMX update, or read in another display language, shows as one removal plus one addition.
- Under `--match name`, link order does not cover a GPO that has a different GUID on each side, because the order comes from the scopes, which list GPOs by GUID.
- A change to a generic extension element with no name or ID shows as a removal and an addition.
- A report cannot say who a security filtering change covers, because mishpat does not expand groups.
- Comparing a report with a backup skips `Registry.pol` and says so. Comparing two reports never sees the values.

The [limitations](../limitations.md) page lists these for readers. New kinds of settings get a reader when there is a need and a test, and until then the generic rule applies.
