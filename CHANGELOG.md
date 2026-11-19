# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-14

### Fixed

- A changed GPO owner or primary group, an added trustee with a custom access mask, a changed mask, and a change in the raw security descriptor are now compared. They were passed over while the report said "No differences. Every input was read in full."
- A permission entry or security descriptor text that mishpat cannot read is now a problem, so the comparison is incomplete. An input that records none of the owner, group or descriptor text is listed under Not compared.
- A backup folder more than four levels below the input, or inside another backup, is now a problem. It was skipped while the report said every input was read in full.
- A backup nested inside a backup that was found below the root, such as `Outer/Sub` beside `Outer`, is now a problem too. Only a backup at the root was checked for nested ones, so changing just the inner one still ended with "No differences. Every input was read in full." and exit 0. One search budget is shared by every selected backup.
- The exit code survives a summary that cannot be printed. A closed pipe or a stream that cannot encode a character in a path no longer turns a finished run into exit 4; unencodable characters are written as backslash escapes.
- A number of thousands of digits in a report no longer ends the run with an internal error. Numbers are read as numbers only when they are one to 20 ASCII digits.
- A value that changes only its type, such as the text "5" becoming the number 5, now shows its type in the Markdown, HTML and CSV reports.
- Two scopes in a bundle that read as the same path (such as `OU=A/B` and `OU=B` inside `OU=A`) are now a problem, because a change to one of their links could not be told apart.
- Rendering Markdown and HTML no longer slows down sharply with thousands of changed GPOs.
- A `Registry.pol` file is read up to 1,000,000 entries, and a larger one is a problem (the run exits 1), which bounds memory use. `mishpat compare --max-pol-entries` and `--max-scan-folders` raise or lower the two limits.
- Text that follows a child element, and nested elements named `Blocked` or `ReadTime`, are now compared inside an extension mishpat has no reader for.
- A `Registry.pol` string that starts like the internal password stand-in is no longer shown as a stored password.
- A bundle saved with a byte order mark or as UTF-16 is now named as such instead of as bad XML.
- Error messages for an input that cannot be read now name the path as you gave it, not only the file name.
- The source archive's own tests now run in the build check: it unpacks the archive outside the checkout and runs the whole suite there, instead of only collecting the tests.
- Editing a pull request title now reruns the title check, so a corrected title clears the required check.
- The dependency audit writes its export to a private temporary directory, so a planted link or a second run at the same time cannot interfere.
- The DCO check now fails when it cannot list the commits to check, instead of reporting success.
- The release script now treats only a clean "not found" answer as an absent tag; an authentication, rate-limit, network, or malformed answer stops the release.
- The dependency audit always includes every optional extra, and a new check fails it when a package named by an extra is missing from the audited export.
- The release evidence is now one SBOM per scope: `sbom-base.cdx.json` for the base install, and `sbom-all-extras.cdx.json` when the project defines optional extras. Each states its scope, and tests check what each one holds.
- The sign-off check no longer lets a commit skip sign-off by claiming Dependabot as its author. Dependabot is exempt only on its own pull requests.
- The required "All checks passed" check now fails if a CI job is missing, and a skipped title or sign-off check no longer counts as a pass on a pull request.
- `scripts/check.sh workflows` prints a clear message instead of a stack trace when GitHub rejects the token.
- `SECURITY.md` no longer says that no release has been published. It says the latest release is supported.
- The PowerShell syntax check now fails in CI when PowerShell is missing, instead of skipping.
- On Windows, a closed pipe (reported there as an invalid-argument error rather than a broken pipe) also stops the printing and keeps the real exit code, instead of ending with an internal error or exit 120.
- The exporter no longer hands its directory search results back as one array inside an array. Every scope of management, link and WMI filter was then recorded as a gap (a conversion error), so a full export of a real domain carried no structure. The search now returns one row per object, and the tests run the script's own search code against a stand-in for Active Directory.

### Changed

- Reading XML now limits the elements held in memory at once (default 1,000,000, change it with `mishpat compare --max-xml-elements`), and a `<GPOS>` capture of a whole domain is read one GPO at a time instead of being held whole. A small file of empty elements could otherwise need gigabytes. A file over the limit is refused (exit 3). The shared `xmlsafe.py` now matches faithful-shaar's.
- Reports now show a space that looks like a plain space (a no-break space, for example) as a visible escape, and a plain negative number in the CSV is no longer prefixed with an apostrophe.
- The summary prints through one place, so every command decides its exit code before it prints.
- The README leads with an install route that works today (`pipx install git+https://github.com/faithful-oversight/faithful-mishpat`), a status line, how mishpat differs from other tools, and real output from the example.
- Removed unused code and the unused `moment` argument type.
- Dependabot groups minor and patch updates of runtime dependencies into one pull request.
- `CONTRIBUTING.md` lists every tool a clean machine needs and which checks need network access or a token.
- The releasing guide covers the first PyPI publish, a failed PyPI step, scheduled checks that stop after 60 idle days, both SBOM files, and the pinned tools.

### Security

- A closed output stream can no longer change the exit code of a run, so a pipeline always sees the real result.
- A release now stops with a clear message when the `FO_PUBLIC` setting disagrees with whether the repository is public, so a public release cannot skip provenance and PyPI by mistake.
- Release jobs check the built files against `SHA256SUMS` before attesting, uploading or publishing.
- uv and the Vale style packages used in CI are pinned to exact versions, and the style packages are checked against a SHA-256 before use.
- Khmer and Mongolian marks that draw nothing (U+17B4, U+17B5, U+180B to U+180D, U+180F) now print as visible escapes, and an issue reference such as `#123` from the input is no longer turned into a link in the Markdown report.

## [0.1.0] - 2026-11-11

First release.

### Added

- `mishpat compare`, which compares two versions of Group Policy and writes a report as JSON, Markdown, HTML, and CSV, plus a manifest with the SHA-256 of every file and both inputs.
- Readers for `Get-GPOReport` XML, `Backup-GPO` folders, and the mishpat export bundle. The input kind is detected from content.
- Comparison of GPO status, WMI filters, security filtering, delegation, links, blocked inheritance, link order, and settings, including Administrative Templates, `Registry.pol`, and generic extensions.
- Explicit gaps and problems, so the report says what it could not compare and whether every input was read in full.
- `--match name` to pair GPOs by name, and `--fail-on` to choose when `compare` exits with code 1.
- `mishpat exporter`, which writes a read-only PowerShell script that exports GPOs, links, link order, blocked inheritance, and WMI filter queries to one export bundle.
- `mishpat collect`, which runs the exporter on a domain controller over WinRM (the `live` extra) and supports secret references for `env`, `file`, `keyring`, `vault`, `aws`, and `azure`.
- `mishpat schema` and the published JSON Schemas for the report and the manifest.
- `mishpat example`, which writes a synthetic domain, `corp.example`, before and after a change.
- Support for `SOURCE_DATE_EPOCH`, so the same inputs give the same report.
- User documentation: quickstart, command reference, input formats, collecting exports, reports and output, limitations, architecture, and threat model.
- Decision records 4 to 6: the export bundle, remote collection, and comparison rules.
- Reports never show a Group Policy Preferences stored password (`cpassword`), as an attribute or an element of any shape, and a change anywhere in its content is found. A change to one is still reported, with a note, even beside other changes to the item.
- Links and special files in a backup folder are listed as problems rather than silently skipped, and a named pipe given as an input is refused rather than read.
- A setting is reported as added or removed only when its source was read on both sides. A missing or unusable report, a missing Computer or User section, a half with a setting skipped as malformed, or an unreadable `Registry.pol` gives a gap and a problem instead.
- Names in a backup or bundle that differ only in case, WMI filters recorded twice with different queries, report sections that should appear once but appear twice with different contents, and a link listed twice with different settings are reported as problems instead of one being chosen.
- Attributes in an XML namespace are compared by namespace URI.
- Malformed numbers, non-ASCII base64, and folders that cannot be listed are input problems, never internal errors.
- Project foundation: license, documentation, contribution and security policies, continuous integration, and release pipeline.

### Changed

- The license check reads optional extras and platform-specific dependencies correctly, matching merilo and toledot. It no longer replaces a license a package states with a generic classifier, and reviewed exceptions are pinned to a package version.

### Fixed

- The source archive now includes `scripts`, which its tests import, and the build check collects the tests from an extracted copy.
