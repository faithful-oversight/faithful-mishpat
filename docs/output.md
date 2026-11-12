# Reports and output

Every run builds one report document, and every output format renders from it, so the formats always agree. The examples on this page come from the synthetic example, `mishpat example`.

## Output files

| File | For |
| --- | --- |
| `mishpat-report.html` | People. One self-contained page. |
| `mishpat-report.md` | Pull requests and change records. |
| `mishpat-report.json` | Automation. Follows a published, versioned JSON Schema. |
| `mishpat-differences.csv` | Spreadsheets. One row per difference. |
| `mishpat-manifest.json` | Evidence handling. The size and SHA-256 of every other file and of both inputs, written last. |

`--format` chooses which of the first four to write. The manifest is always written.

## Report sections

The Markdown and HTML reports have the same sections, in this order. A section marked "only when" is left out when it would be empty.

| Section | What it holds |
| --- | --- |
| Headline | The count of differences and whether every input was read in full. |
| Notices | Only when there are any. Plain sentences to read first. |
| GPOs compared | Every GPO, with its GUID, its status, and its number of differences. GPOs with differences come first. |
| Changes by GPO | For each GPO with differences: its state in the after input, then its differences grouped by category. |
| Domain structure | Only when there are any. Differences that belong to an organizational unit, a domain, or a site, not to one GPO. |
| Not compared | Only when there are any. What mishpat did not compare, and why. |
| Problems | Only when there are any. What could not be read. |
| Inputs | Each input with its kind, size, and SHA-256. |
| Limitations | What mishpat does not do. Every report states this. |

The headline is one of these:

- `N differences across M GPOs. Every input was read in full.` The sentence adds `and the domain's structure` when a scope has a difference, and says `in the domain's structure` when only a scope does. When GPOs exist in only one input, it adds `(N GPOs in only one input)` after the count.
- `No differences. Every input was read in full.`
- The same count, followed by `Incomplete: N problems with an input, so differences may be missing.`

The headline never says "no differences" without saying whether the inputs were read in full.

Under each GPO that has differences, the report shows its state as the after input records it:

- **Status.** Whether the computer half and the user half are enabled.
- **WMI filter.** The name, description, ID, and query, or `none`, or `not recorded`. The query shows `query not recorded` when the input has none.
- **Security filtering.** The trustees that are allowed to apply the GPO.
- **Links.** Each link with its enabled state, its enforced state, and its order when the input records it.

A GPO that exists only in the before input has no state to show.

The report also records when it was generated, the mishpat version, and how GPOs were paired. All times are UTC.

## What complete means

A comparison is **complete** when every input was read in full: no [problem](#problems) exists on either side. Otherwise it is **incomplete**. The summary holds a `complete` flag, and the exit code of `mishpat compare` follows it. See [Command reference](usage.md#exit-code-of-compare).

Items under [Not compared](#not-compared) and [Notices](#notices) do not make a comparison incomplete. They are limits of the inputs, and the report states them so you do not assume a check was made.

Complete is a statement about what mishpat could read. It is not proof that the two versions behave alike. A complete comparison does not cover:

- Anything the inputs do not record. See [Limitations](limitations.md#what-the-exports-cannot-show).
- Differences in what applies to a computer or a user. mishpat compares what each GPO holds, not what takes effect.
- Whether a change is correct or approved.

## Differences

Each difference has a category, a kind, the GPO it concerns, a subject, the value before and after, and where each side was read. Here is a difference from the example:

```json
{
  "category": "setting",
  "kind": "changed",
  "gpo": "c71a0e5f-68b3-4d29-9a47-3e8d1f5b0c72",
  "gpo_name": "Workstation Hardening",
  "scope": "Computer",
  "area": "Security",
  "subject": "SeDenyNetworkLogonRight",
  "before": ["S-1-5-32-546"],
  "after": ["S-1-5-113", "S-1-5-32-546"],
  "note": "",
  "labels": {
    "S-1-5-113": "NT AUTHORITY\\Local account",
    "S-1-5-32-546": "BUILTIN\\Guests"
  },
  "sources": [
    {
      "file": "corp-before.jsonl:{F92E7A05-3D18-4B6C-8A41-C5B0E6D9273F}/gpreport.xml",
      "detail": "Computer/Security/UserRightsAssignment[SeDenyNetworkLogonRight]"
    },
    {
      "file": "corp-after.jsonl:{2A8C1D64-B7E0-4F95-9A3B-6D5E8C0F1B47}/gpreport.xml",
      "detail": "Computer/Security/UserRightsAssignment[SeDenyNetworkLogonRight]"
    }
  ]
}
```

| Property | Meaning |
| --- | --- |
| `category` | What the difference is about. See [Categories](#categories). |
| `kind` | What happened. See [Kinds](#kinds). |
| `gpo`, `gpo_name` | The GPO's GUID and name on the after side, or on the before side when the GPO was removed. Both are empty for a difference that belongs to a scope. |
| `scope` | `Computer` or `User` for a setting, otherwise empty. |
| `area` | The extension of a setting, such as `Security`. Otherwise empty. |
| `subject` | What changed, in a few words: a setting's title, a link target, a trustee, or a field such as `computer half`. |
| `before`, `after` | The value on each side, or `null` when the item is not there. |
| `note` | Extra words a reader needs. Empty for most differences. |
| `labels` | Words that a reader shows beside a value, keyed by the value as text: the name of an account beside its SID, or the meaning of a security option beside its number. mishpat never compares them. An empty object when there are none. |
| `sources` | Where each side was read, before first. A file inside a bundle is written `bundle.jsonl:path/inside`. When only one side is listed, it is the side that holds the item. |

In Markdown and HTML, a value that is not set shows as `(not set)`. Text with spaces at its edges is shown in quotes. A value that has a label shows it in brackets after the value. When both sides are mappings, only the keys that differ are shown. Then, a list shows as its items joined by commas, and a mapping shows as `name: value` pairs joined by semicolons. The CSV report writes lists and mappings as JSON. The JSON report keeps the exact values.

Differences are in the order of the GPO's name, then the order of the categories, with scope differences last.

### Categories

| Category | What it is about | Kinds | Subject, before, and after |
| --- | --- | --- | --- |
| `gpo` | A GPO that exists in one input only, or that has a new name | `added`, `removed`, `only-before`, `only-after`, `renamed` | The GPO's name. For `renamed`, both names, old first. |
| `status` | The computer half or user half turned on or off | `changed` | `computer half` or `user half`, then `enabled` or `disabled`. |
| `wmi-filter` | The WMI filter of a GPO | `added`, `removed`, `changed` | `WMI filter`, then `null` or the name, description, and query. |
| `security-filtering` | A trustee that is allowed to apply the GPO | `added`, `removed` | The trustee's name and SID, then `applies` or `null`. |
| `permissions` | Every other permission entry on the GPO, which is delegation | `added`, `removed`, `changed` | The trustee, then the sorted rights. |
| `link` | A link of a GPO, or the order of the links on a scope | `added`, `removed`, `changed` | The link target, then `enabled` and `enforced`. For order, the scope, then the GPO names in order. |
| `inheritance` | A scope that starts or stops blocking inheritance, or one that blocks it and is in one input only | `changed`, `added`, `removed`, `only-before`, `only-after` | The scope's path, then `blocked` or `not blocked`. |
| `setting` | A setting in a GPO | `added`, `removed`, `changed` | The setting's title, then its value. |

### Kinds

| Kind | Meaning |
| --- | --- |
| `added` | The item is in the after input only. |
| `removed` | The item is in the before input only. |
| `changed` | The item is in both, and its value differs. |
| `renamed` | The same GPO has a different display name. |
| `only-before` | A GPO is in the before input only, and the inputs are not both whole domains. |
| `only-after` | A GPO is in the after input only, and the inputs are not both whole domains. |

`added` and `removed` describe a GPO only when both inputs are whole domains: a `Get-GPOReport -All` file, or an export bundle whose scope is `all`. Then a GPO that is missing was deleted, and a GPO that is new was created. When either input is a selection, such as one backup or a bundle of chosen GPOs, a GPO missing from the other side may simply not have been exported. mishpat then says `only-before` or `only-after`, and adds a notice that says why.

An added or removed GPO is one difference. mishpat does not list its settings one by one.

### What each category compares

**GPO name.** An `added` or `removed` GPO has its name as both the subject and the value on the side that has it. A change of display name on a GPO that keeps its GUID is `renamed`. With `--match name`, a name is what pairs two GPOs, so a different name gives two unpaired GPOs.

**Status.** The computer half and the user half are compared separately. A half that one input does not record is not compared. See [Not compared](#not-compared).

**WMI filter.** mishpat compares the filter's name and description. It adds the query to the comparison only when both inputs record the query, and then the query is part of the value. In a bundle, the exporter stores the query as the directory holds it, and mishpat writes each query as `namespace: text`, one per line. Text that does not follow the directory's layout is kept as it is. The filter's ID is not compared. mishpat does not evaluate a filter. A change from no filter to a filter is `added`, and the reverse is `removed`.

**Security filtering.** Security filtering is the set of trustees that have an allow entry for Apply Group Policy. mishpat compares the set by SID. A trustee that joins or leaves the set is `added` or `removed`. mishpat does not expand groups, so the report does not say who the change covers.

**Permissions.** Every other permission entry is delegation. mishpat compares them by SID and by allow or deny. The value is the sorted list of rights. An entry that gains or loses a right is `changed`. A deny entry has the note `deny`. A deny entry for Apply Group Policy is listed here, not under security filtering, because only allow entries filter.

**Links.** mishpat compares the links of a GPO by target, without regard to case. A link that appears or disappears is `added` or `removed`. A link whose enabled or enforced state differs is `changed`. A link target is written in the form a report uses, such as `corp.example/Servers`.

Link order is a property of a scope, not of a GPO, so it is a separate difference under [Domain structure](#report-sections). For each scope that both inputs record, mishpat takes the GPOs that are linked there in both inputs and compares their order. A GPO linked on one side only does not count, so adding one link does not make every later link look moved. The difference is `changed`, with the GPO names in order before and after. Its subject is the scope's distinguished name followed by `: link order`.

**Inheritance.** A scope that blocks inheritance on one side only gives a `changed` difference, from `not blocked` to `blocked` or back. A scope that exists in one input only is reported when it blocks inheritance: `added` or `removed` when both inputs are whole domains, otherwise `only-after` or `only-before`, with a note. Its links are listed under each GPO.

**Settings.** Settings are paired by scope, area, kind, and key, without regard to case, and compared by value. The value is the canonical form that [Input formats](formats.md#settings) describes. A setting only the after input holds is `added`, a setting only the before input holds is `removed`, and a setting with different values is `changed`.

mishpat compares sets as sets: the members of a user right, security filtering, and delegation entries are sorted first. The options of a policy are matched by name. A new order alone shows nothing.

mishpat does not compare modified times, version numbers, explanation text, or comments. Saving a GPO without changing a setting shows no difference.

## Not compared

Gaps list what mishpat did not compare, and why. They do not make a comparison incomplete. They are limits of the inputs, and a reader should not assume the check was made.

| Subject | Reason it appears |
| --- | --- |
| `computer half status` or `user half status` | One input does not record whether the half is enabled. |
| `WMI filter` | One input cannot say whether the GPO has a filter. |
| `WMI filter query` | Both versions of the GPO have a filter, and one input does not record the query. Only a bundle records the query. |
| `security filtering and permissions` | One input does not record the permissions of the GPO. |
| `links` | One input does not record the links of the GPO, such as a backup without its `gpreport.xml`. |
| `Registry.pol values` | The inputs are not both backups or bundles read in full. |
| `link order and blocked inheritance` | One input does not record the structure of the domain. Only a bundle does. |

Each entry names the GPO it concerns, when it concerns one. The Markdown and HTML reports list them as `subject (GPO name): reason`.

Here is how the example reads when the before side is a `Backup-GPO` folder:

```text
WMI filter query (Baseline - Servers): only the mishpat exporter records the query text
link order and blocked inheritance: the before input does not record the domain's structure; only the mishpat exporter does
```

## Problems

A problem is something in an input that mishpat could not read, or a conflict. A problem never stops the rest of an input from being read, but the comparison is incomplete, because a difference that the unread part holds is not in the report. A problem has a `file`, a `detail` (the position inside it), and a `reason`.

These produce problems:

- An element of a report or a file of a backup that cannot be read, or that lacks what identifies it.
- A backup without a usable `gpreport.xml`, or a `Registry.pol` file that is damaged.
- A line of a bundle that fails its checks, a bundle that was cut short, a count or hash that does not match, and every gap the exporter recorded.
- A GPO that a bundle's header lists and the bundle does not hold.

[Input formats](formats.md) lists them for each kind of input. The reason does not repeat the content of the record.

## Notices

A notice is a plain sentence that a reader should see first. Three exist:

- The two inputs share no GPO by GUID. The notice suggests `--match name`, for policies that have different GUIDs, such as two generations of a security baseline. With `--match name`, the notice says the inputs share no GPO by name.
- At least one input is a selection of GPOs rather than a whole domain, so a GPO in only one input is listed as only before or only after.
- Part of the inputs could not be read, so the comparison is incomplete. The notice gives the count and points to Problems.

## Shortening

The Markdown and HTML reports shorten any value longer than 300 characters, and say how long it was, but only when the JSON report is written too, as it is by default. When `--format` leaves out `json`, they keep every value whole, because nothing else would hold it.

When the JSON report is written, the Markdown and HTML reports also cap long lists and say how many more the JSON report holds:

| List | Cap |
| --- | --- |
| Notices, items under Not compared, items under Problems, links, and trustees | 25 |
| Rows of the table of GPOs | 100 |
| GPO sections under Changes by GPO | 100 |
| Differences for one GPO, and for the scope section | 200 |

Without the JSON report, they list every row. The JSON report and the CSV file always hold full values.

## Summary counts

The `summary` of the JSON report holds:

| Property | Meaning |
| --- | --- |
| `complete` | Whether every input was read in full. |
| `differences` | The number of differences. |
| `gpos_compared`, `gpos_changed` | How many GPOs were compared, and how many have a difference. |
| `scope_differences` | How many differences belong to a scope, not to a GPO. |
| `problems`, `gaps`, `notices` | The number of each. |
| `by_category`, `by_kind`, `by_status` | Counts by category, by kind, and by the status of each GPO: `changed`, `unchanged`, `added`, `removed`, `only-before`, or `only-after`. A count of zero is left out. |

## CSV

`mishpat-differences.csv` has one row for each difference. The columns are:

`category`, `kind`, `gpo_guid`, `gpo_name`, `scope`, `area`, `subject`, `before`, `after`, `note`, `before_source`, `after_source`, `comparison_complete`.

| Column | Meaning |
| --- | --- |
| `before`, `after` | The value on each side. A value that is a list or a mapping is written as compact JSON. A value that is not set is an empty cell. |
| `before_source`, `after_source` | Where each side was read. When only one side is listed, it is the side that holds the item. |
| `comparison_complete` | `true` or `false`: whether every input was read in full. It is the same on every row, so the caveat travels with the differences when the CSV is the only file kept. |

The CSV holds no notices, gaps, or problems, so read the other reports for those. A run with no differences writes the header row alone.

The file is UTF-8 with no byte order mark, and its rows end with CRLF. A spreadsheet that guesses the encoding wrongly can be told it is UTF-8 when you import. Values are never shortened.

### Formula neutralization

A spreadsheet can run a cell that starts with `=`, `+`, `-`, or `@`, or with a tab, a carriage return, or a line feed, as a formula. Some programs also accept the full-width forms of those four characters. mishpat gives every such cell a leading apostrophe, which spreadsheets show as plain text. Opening the file cannot run anything.

## HTML report

`mishpat-report.html` is a single file. It works offline, follows the system's light or dark setting, and prints cleanly. Its content security policy blocks scripts, network requests, and form submission, and every value from the input is escaped. The page has no script and loads nothing. It contains no links made from data.

## Markdown report

`mishpat-report.md` holds the same content in Markdown, ready to paste into a pull request or change record. Values are escaped so they cannot break a table or inject HTML. Web addresses and email addresses from the input do not turn into links.

## Invisible characters

Group Policy data can hold characters that change how text looks rather than what it says: terminal escape sequences, right-to-left override marks, zero-width characters, soft hyphens, tag characters, and variation selectors. The HTML, Markdown, and CSV reports and the terminal show these as visible escapes. On the terminal, tabs and carriage returns are escaped too, so a value cannot move the cursor back over a line. A character in the Basic Multilingual Plane appears as `‮`, and any other character appears with eight digits, as `\U000e0041`. Tab and line breaks are kept in the reports. The JSON report keeps the exact values.

## JSON schemas

`mishpat schema` prints a schema for the installed version, with no network access:

```shell
mishpat schema report
mishpat schema export
mishpat schema manifest
```

| Schema | Describes |
| --- | --- |
| `report` | `mishpat-report.json`. |
| `export` | One line of an [export bundle](formats.md#export-bundle). |
| `manifest` | `mishpat-manifest.json`. |

The identifier of each schema, such as `https://faithful-oversight.github.io/faithful-mishpat/schema/report-v1.schema.json`, is also where the documentation site serves it once the project is public.

The top-level properties of the report are `$schema`, `schema_version`, `tool`, `generated_at`, `inputs`, `options`, `comparison`, `summary`, `notices`, `gpos`, `differences`, `gaps`, `problems`, and `limitations`. The `schema_version` has the form `1.N`. Validate each report with the schema that the same mishpat version prints. A breaking change to a schema needs a new major release, as [Architecture](architecture.md#rules-the-design-follows) states.

## Manifest

Every run writes `mishpat-manifest.json`, after every other file. It lists each report file from the run with its size in bytes and SHA-256, and each input the same way:

```json
{
  "$schema": "https://faithful-oversight.github.io/faithful-mishpat/schema/manifest-v1.schema.json",
  "schema_version": "1.0",
  "tool": {"name": "mishpat", "version": "0.1.0"},
  "generated_at": "2026-11-09T12:00:00Z",
  "files": [
    {"name": "mishpat-report.json", "size": 25321, "sha256": "9f176a50..."}
  ],
  "inputs": [
    {"name": "corp-before.jsonl", "size": 83586, "sha256": "82d77f94..."}
  ]
}
```

The preceding hashes are shortened. The manifest makes the set checkable as a whole:

- If the manifest is missing, the run did not finish writing.
- If a file's size or SHA-256 differs from the manifest, the file is partial, edited, or from another run.
- If a file the manifest lists is missing, the set is incomplete.
- If an input's SHA-256 differs from the manifest, it is not what the report was made from.

The SHA-256 of an input folder covers the relative path and the SHA-256 of every file in it, in path order, so the same files give the same value wherever the folder is.

The manifest does not list itself. It covers only the files of its own run. A report file it does not list, for example one left from an earlier run with other `--format` choices, belongs to another run.

The hashes show that the files are consistent. They do not show who made them: anyone who edits the files can compute the manifest again.

## Repeatable output

The same inputs and options give the same files, except for the generation time. Set `SOURCE_DATE_EPOCH` to make that repeatable too. See [Command reference](usage.md#repeatable-reports).
