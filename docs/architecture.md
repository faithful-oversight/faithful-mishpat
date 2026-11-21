# Architecture

mishpat is a command-line tool and a Python library with the same core. Reading files needs one runtime dependency beyond the Python standard library: [faithful-core](https://github.com/faithful-oversight/faithful-core), the shared foundation library of the Faithful Oversight tools, pinned to an exact version. Remote collection and the secret providers use optional dependencies, installed as extras.

```text
 admin workstation or domain controller
   Export-MishpatGpo.ps1 ──► export bundle   header, file lines, structure, trailer with SHA-256
 WinRM ──► mishpat collect ─┘                         │
                                                      │
 Get-GPOReport XML, Backup-GPO folders ───────────────┤
                                                      ▼
                  pipeline    fingerprint both inputs (size and SHA-256), refuse identical ones
                                                      │
                                                      ▼
                  inputs      detect each input's kind from its content; formats read it
                  formats     into a Snapshot: GPOs, settings, links, scopes, and problems
                                                      │
                                                      ▼
                  compare     pair GPOs, compare each part, and say what was not compared
                              result: a Comparison (differences, gaps, problems, notices)
                                                      │
                                                      ▼
                  outputs     one report document, rendered as JSON, Markdown, HTML, CSV,
                              plus a manifest
                                                      │
                                                      ▼
                  cli         arguments, file writing, exit codes
```

The exporter and `mishpat collect` write the same bundle. Nothing after the readers knows which kind of input a GPO came from, except through what the input recorded.

## The pipeline

1. `pipeline.run` reads the size and SHA-256 of both inputs, for a folder over the path and hash of every file in it, before it parses either. It refuses two inputs with the same contents.
2. `inputs.read_side` detects the kind of each input from its content and calls the reader. A folder goes to the backup reader. A file that starts with the bundle marker goes to the bundle reader. Any other file goes to the report reader. Each reader returns GPOs and problems, and the result becomes a `Snapshot`.
3. `compare.compare` pairs the GPOs of the two snapshots, compares each part of each pair, compares the structure of the domain when both sides have it, and returns a `Comparison`. It adds a gap for everything that one side does not record.
4. `outputs.build_report` turns the `Comparison` into one report document, a plain dictionary. The renderers for JSON, Markdown, HTML, and CSV read only that dictionary. `outputs.write_reports` writes the files and a manifest.
5. `cli` prints a summary and returns an exit code.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli` | The command-line interface, exit codes, and the `compare`, `schema`, and `example` commands. |
| `arguments` | Argument types shared by the commands: bounded numbers. |
| `errors` | `MishpatError`, which is faithful-core's `FaithfulError`, and the error classes mishpat uses: `InputError`, `CollectionError`, `UsageError`, and `OutputError`. |
| `model` | The plain data every reader produces: `Snapshot`, `Gpo`, `Setting`, `Trustee`, `Link`, `WmiFilter`, `Scope`, `Problem`, and `Source`. |
| `formats` | One reader for each kind of input: `report`, `backup`, `bundle`, and `registrypol`. |
| `inputs` | Detect the kind of an input and read it into a `Snapshot`. |
| `pipeline` | Fingerprint both inputs, read them, and compare them. |
| `compare` | Pair GPOs and compare them. No file access and no output. |
| `differences` | The records `compare` builds: `Comparison`, `Difference`, `Gap`, and `Pair`. |
| `outputs` | Build the report document, render each format, and write the files all together. |
| `collect` | `mishpat collect` and `mishpat exporter`: the export bundle's line checks, the script's parameters, and the commands. |
| `example` | The synthetic bundles for the `example` command and tests. |
| `data` | The PowerShell exporter `Export-MishpatGpo.ps1`. |
| `schema` | JSON Schemas for the report, the export bundle, and the manifest. |

## The model

`model` is the one shape every input is read into. A `Snapshot` is one side of a comparison: the GPOs an input holds, the scopes of management when the input records them, and the problems it had.

The model keeps a difference between *not captured* and *empty*. A field that an input does not record is `None`: the links of a GPO from a backup without `gpreport.xml`, the permissions from a report that lacks them, the WMI filter as the text `unknown`, the scopes of a snapshot with no structure line. A field that an input records as empty is an empty list. `compare` never compares a `None`. It adds a gap that says what was not compared and why.

## The readers

- `faithful_core.xmlsafe` parses the XML for `formats.report` and `formats.backup`, with the standard library's `pyexpat`. It refuses a `DOCTYPE` and entity declarations, limits nesting and size, and decodes the bytes itself, ignoring the declared encoding.
- `formats.report` reads `Get-GPOReport` XML. It identifies each element by its namespace URI and maps every extension to settings. Extensions it does not know are read generically.
- `formats.registrypol` reads `Registry.pol` files.
- `formats.backup` reads backups through an abstract `Tree`, so the same code reads a real folder (`FolderTree`) and the files of a bundle (`MemoryTree`).
- `formats.bundle` reads the export bundle strictly, places its files in a `MemoryTree`, and reads them with the backup reader. It turns the structure line into scopes and fills each GPO's links and WMI filter query from it. It also holds the reference writer used by the example and the tests.

## The comparison

`compare.compare` follows these rules. [ADR 6](adr/0006-comparison-rules.md) records why.

- **Pairing.** GPOs pair by GUID, or by display name with `--match name`.
- **Identity.** A setting's identity is its scope, area, kind, and key, compared without regard to case. The key depends on the kind of setting.
- **Sets.** Members of user rights, security filtering, and delegation entries are sorted. Policy options are keyed by name. A new order is not a change.
- **Gaps, not invented differences.** Context that an input does not record is never compared. It becomes a gap.
- **Link order per scope.** Order is compared among the GPOs linked on a scope in both inputs.
- **Whole domains.** A GPO that is missing from one input is `removed` or `added` only when both inputs are whole domains. Otherwise it is `only-before` or `only-after`.
- **Completeness.** Only problems make a comparison incomplete.

## The collect package

| Module | Responsibility |
| --- | --- |
| `collect.cli` | Registers `collect` and `exporter` and checks their arguments. |
| `collect.remote` | Checks each line the controller sends, its structure line, and its end line, in a private file. It also builds the script's parameters and the result, and hands the connection to faithful-core. |
| `collect.script` | Names the packaged PowerShell script and reads it through faithful-core. |

Both collection paths run the same script, so there is one format to read and one script to review. See [Collecting exports](collecting.md).

## The shared library

faithful-core holds the code that every Faithful Oversight tool needs to behave the same way. mishpat uses it for:

- the base error and the exit codes;
- parsing untrusted XML with limits on size, depth, and element count;
- making untrusted text safe for the terminal, CSV, Markdown, and HTML;
- the report time and the way times are written;
- printing that never changes an exit code;
- publishing a set of files all together, without replacing a file the tool reads;
- the checks on `--server` and `--username`, the secret providers, and the redaction of every resolved secret;
- the WinRM connection, its transport rules, and the loop that takes the controller's output.

The library's own pages describe how each of these works. [ADR 7](adr/0007-shared-core-library.md) records the decision. mishpat's tests cover these through the commands, and the library's tests cover them directly.

## Rules the design follows

- **Separation.** Readers handle input, `compare` is logic, and `outputs` handles output. `compare` never reads files or prints.
- **One shape.** Every kind of input is read into the same model, so nothing after the readers depends on the kind.
- **A problem is a result.** An element or file part that cannot be read becomes a `Problem` in the report, and the comparison is incomplete. It is never skipped silently.
- **Unknowns are results.** What an input does not record becomes a gap in the report. It is never a difference, and it is never a clean pass.
- **Say no more than the inputs say.** The report states what changed, not what it means for a computer.
- **One report document.** Every format is rendered from the same document, so the formats cannot disagree.
- **A versioned contract.** The report, the export bundle, and the manifest follow published JSON Schemas with a version number. Breaking changes to a schema require a major release. See [Reports and output](output.md#json-schemas).
- **No prompts.** The tool never asks questions interactively, so it runs unchanged in scripts and pipelines.
- **Structured exit codes.** `0` success with no differences and nothing unread, `1` differences or an unread input as `--fail-on` sets, `2` usage error, `3` input, output, or collection error, and `4` internal error. Any exception that is not a `MishpatError` ends in exit code `4`, with a message that says it is a bug. This keeps a crash apart from a result.
- **Careful output.** Report files are complete before they appear, are never overwritten without `--force`, and are swapped in with rollback on failure. A manifest of file hashes, written last, makes a partial set detectable, and so does a mixed set.
- **Read-only.** The exporter reads Group Policy and the directory and writes only its own file. The tool does not change the systems it examines.
- **Offline analysis.** `mishpat compare` reads files and writes reports. It never touches the network. Only `mishpat collect` does, and only when you run it. [ADR 5](adr/0005-remote-collection.md) records that exception.

## Packaging

- Python package on PyPI: `faithful-mishpat`, with the command `mishpat`. Its one runtime dependency is `faithful-core`, pinned to an exact version.
- Extras: `live` (`pypsrp`), `keyring`, `vault`, `aws`, and `azure`. See the [README](https://github.com/faithful-oversight/faithful-mishpat#install).
- Further formats, such as a standalone executable or a container image, are added only when a decision record justifies them.

## Decisions

Significant decisions are recorded in [architecture decision records](adr/index.md).
