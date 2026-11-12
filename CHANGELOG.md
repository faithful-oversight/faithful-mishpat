# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Names in a backup or bundle that differ only in case, and WMI filters recorded twice with different queries, are reported as problems instead of one being chosen.
- Attributes in an XML namespace are compared by namespace URI.
- Malformed numbers, non-ASCII base64, and folders that cannot be listed are input problems, never internal errors.
- Project foundation: license, documentation, contribution and security policies, continuous integration, and release pipeline.

### Changed

- The license check reads optional extras and platform-specific dependencies correctly, matching merilo and toledot. It no longer replaces a license a package states with a generic classifier, and reviewed exceptions are pinned to a package version.

### Fixed

- The source archive now includes `scripts`, which its tests import, and the build check collects the tests from an extracted copy.
