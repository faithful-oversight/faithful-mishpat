# mishpat

**GPO Change Review.** Produces a readable, reviewable difference between two versions of Group Policy, including links, filters, and inheritance context.

[![CI](https://github.com/faithful-oversight/faithful-mishpat/actions/workflows/ci.yml/badge.svg)](https://github.com/faithful-oversight/faithful-mishpat/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: pre-release.** The repository holds the project foundation only. No feature is implemented yet, and nothing here is ready for production use.

## About the name

*mishpat* (meesh-PAHT). Hebrew: judgment, ordinance.

## What it will do

- Compare two Group Policy reports or backups setting by setting.
- Include link, security filtering, WMI filter, and inheritance context.
- Render the difference as Markdown or HTML suitable for pull requests and change records.

## What it will not do

- Predict the full effect of a change on every computer or user.
- Apply or edit Group Policy.

See [docs/limitations.md](docs/limitations.md) for the full list.

## Design goals

- **Read-only.** The tool will never change the systems it examines.
- **Offline first.** Inputs will be exported files, with no network access required.
- **Explicit unknowns.** Every report will state what the tool could not see or verify.
- **Traceable findings.** Every finding will point back to its source record and the rule that produced it.
- **Synthetic test data only.** Fixtures are hand-made or generated. No real organization's data is ever committed.

## Installation

Not yet published. Once released, the package will install with:

```shell
pipx install faithful-mishpat
```

To work from source, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```shell
mishpat --version
```

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Limitations](docs/limitations.md)
- [Releasing](docs/releasing.md)
- [Architecture decision records](docs/adr/)

## Security

Please do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md) first.

## License

Copyright 2026 Faithful Oversight, LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
