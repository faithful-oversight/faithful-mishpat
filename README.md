# mishpat

**GPO Change Review.** Produces a readable, reviewable difference between two versions of Group Policy, including links, filters, and inheritance context. It says plainly what it could not compare.

[![CI](https://github.com/faithful-oversight/faithful-mishpat/actions/workflows/ci.yml/badge.svg)](https://github.com/faithful-oversight/faithful-mishpat/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: first release.** mishpat reads Group Policy exports end to end and is tested on synthetic data. The two ways to collect an export, the PowerShell exporter and `mishpat collect`, have not yet been run against a real domain, a real domain controller, a real WinRM endpoint, or Windows PowerShell 5.1. Treat the first runs in your environment as a pilot. See [Limitations](docs/limitations.md).

## About the name

*mishpat* (meesh-PAHT). Hebrew: judgment, ordinance.

## What it does

A change to Group Policy is hard to review. A GPO holds hundreds of settings, and what a setting does depends on where the GPO is linked, in what order, with what filters. mishpat compares two versions and writes the difference in a form you can paste into a pull request or a change record:

| Subject | Kind | Before | After |
| --- | --- | --- | --- |
| LockoutBadCount | changed | 10 | 5 |
| `Network security: LAN Manager authentication level` | changed | 3 | 5 |
| corp.example/Workstations | changed | enabled: true; enforced: false | enabled: true; enforced: true |

mishpat:

- Compares two versions of one GPO, a selection of GPOs, or a whole domain, setting by setting.
- Reads `Get-GPOReport` XML files, `Backup-GPO` folders, and its own export bundle. It detects each from its content.
- Includes the context around each GPO: whether each half is enabled, links with their enabled and enforced state, security filtering and delegation, and the WMI filter. With an export bundle it also compares link order, blocked inheritance on organizational units, and WMI filter queries.
- Treats lists as sets, so members listed in a new order are not a change. It ignores modified times and version numbers, so saving a GPO without a change shows nothing.
- Says what it did not compare. When an input does not record something, such as link order in a `Get-GPOReport` file, the report says so. It does not invent a difference.
- Says whether every input was read in full. A part that could not be read is a problem, and the comparison is then incomplete.
- Writes one report in four forms: JSON, Markdown, HTML, and CSV, plus a manifest with the SHA-256 of every file and both inputs.
- Cites the source of every difference, so a reviewer can check it by hand.

## What it will not do

- Apply, edit, or predict Group Policy. mishpat is read-only. It never changes your files or your domain.
- Show the effective settings on a computer or for a user. That depends on every GPO that applies, their order, loopback processing, and the site. mishpat compares what each GPO holds.
- Evaluate WMI filters. It compares a filter's name, description, and query text. It does not run the query.
- Evaluate item-level targeting in Group Policy Preferences. It compares the targeting as written.
- Judge whether a change is correct or approved. It reports what changed.

See [Limitations](docs/limitations.md) for the full list.

## Install

mishpat needs Python 3.11 or newer. Reading files needs no other packages.

```shell
pipx install faithful-mishpat
```

Remote collection needs the `live` extra. Each secret provider has its own extra:

| Extra | Adds | Needed for |
| --- | --- | --- |
| `live` | `pypsrp` | `mishpat collect` |
| `keyring` | `keyring` | `--secret keyring:...` |
| `vault` | `hvac` | `--secret vault:...` |
| `aws` | `boto3` | `--secret aws:...` |
| `azure` | `azure-identity`, `azure-keyvault-secrets` | `--secret azure:...` |

```shell
pipx install "faithful-mishpat[live]"
pipx install "faithful-mishpat[live,vault]"
```

Until the first release is on PyPI, install the wheel file from a release, or work from source as [CONTRIBUTING.md](CONTRIBUTING.md) describes.

## Quick start

```shell
pipx install faithful-mishpat
mishpat example ./mishpat-demo
mishpat compare ./mishpat-demo/corp-before.jsonl ./mishpat-demo/corp-after.jsonl -o ./mishpat-demo/report
```

Open `./mishpat-demo/report/mishpat-report.html` in any browser. The example describes a made-up domain, `corp.example`, with six GPOs. It shows the state before a change window and after it. It holds every kind of difference the report can show.

mishpat exits with code `1` here, because the two versions differ. That is the expected result. Add `--fail-on never` to see exit code `0`. The same reports are committed in [examples/corp-example](examples/corp-example/).

The [Quickstart](docs/quickstart.md) walks through the output and then shows how to use your own Group Policy.

## Get your Group Policy

You can get Group Policy into mishpat in three ways:

1. **Run the PowerShell exporter** on an administration workstation with RSAT, or on a domain controller. `mishpat exporter -o Export-MishpatGpo.ps1` writes a read-only script. It writes one export bundle, with the GPOs, their links, link order, blocked inheritance, and WMI filter queries.
2. **Collect remotely.** `mishpat collect` runs the same script on a domain controller over PowerShell remoting (WinRM) and writes the same file.
3. **Make the files yourself** with `Get-GPOReport -ReportType Xml` or `Backup-GPO`.

The exporter and `mishpat collect` record the context that a report or a backup lacks. [Input formats](docs/formats.md) shows what each input records.

## Outputs

| File | For |
| --- | --- |
| `mishpat-report.html` | People. One self-contained page that works offline, follows the light or dark setting, and prints cleanly. |
| `mishpat-report.md` | Pull requests and change records. |
| `mishpat-report.json` | Automation. Follows a published, versioned [JSON Schema](src/faithful_mishpat/schema/report-v1.schema.json). |
| `mishpat-differences.csv` | Spreadsheets. One row per difference. Protected against formula injection. |
| `mishpat-manifest.json` | Evidence handling. The size and SHA-256 of every other file and of both inputs, written last. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and there are no differences and every input was read in full, or the level you chose with `--fail-on` was not reached. |
| `1` | `mishpat compare` wrote its reports, and the result reached the `--fail-on` level: by default, there is a difference or an input was not read in full. |
| `2` | The command was used incorrectly. |
| `3` | An input, output, or collection problem. |
| `4` | An internal error in mishpat. This is a bug. |

## Design goals

- **Read-only.** The tool never changes the systems it examines. The exporter only reads.
- **Offline first.** `mishpat compare` reads files and writes reports. It never touches the network. Only the optional `mishpat collect` command uses the network, and only when you run it.
- **Explicit unknowns.** Every report states what the tool could not compare or read. A gap is never left out to make a report look clean.
- **Traceable findings.** Every difference points back to the file and place it was read from, and both inputs are recorded with their SHA-256.
- **Safe output.** Reports escape every input value, and the HTML page cannot run scripts or load anything.
- **Synthetic test data only.** Fixtures are hand-made or generated. No real organization's data is ever committed.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Command reference](docs/usage.md)
- [Input formats](docs/formats.md)
- [Collecting exports](docs/collecting.md)
- [Reports and output](docs/output.md)
- [Limitations](docs/limitations.md)
- [Architecture](docs/architecture.md) and [threat model](docs/threat-model.md)
- [Releasing](docs/releasing.md) and [decision records](docs/adr/)

## Security

Please do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.

## License

Copyright 2026 Faithful Oversight, LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
