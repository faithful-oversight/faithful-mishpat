# Quickstart

This walk-through takes about ten minutes. It starts with synthetic data, so nothing here touches a real system. It then shows the three ways to get your own Group Policy into mishpat.

## 1. Install

PyPI publishing is being set up. Until a PyPI release exists, install from GitHub:

```shell
pipx install git+https://github.com/faithful-oversight/faithful-mishpat
pipx ensurepath
mishpat --version
```

For a fixed version, add the tag: `...faithful-mishpat@v0.1.1`. `pipx ensurepath` puts the `mishpat` command on your PATH; open a new terminal afterwards if `mishpat` is not found.

mishpat runs on Windows, macOS, and Linux with Python 3.11 or newer. Reading files needs nothing else. Remote collection needs an extra, which [Collecting exports](collecting.md#remote-collection) explains.

## 2. Create the example

```shell
mishpat example ./mishpat-demo
```

This writes two export bundles for a made-up domain, `corp.example`:

| File | What it is |
| --- | --- |
| `corp-before.jsonl` | What the exporter would write for every GPO of the domain on October 5, 2026: six GPOs, the organizational units with their links, and two WMI filters. |
| `corp-after.jsonl` | The same export after a change window, on November 9, 2026. |

Every name, SID, and GUID is invented. The files use mishpat's own [export bundle format](formats.md#export-bundle), the same format the real exporter writes.

## 3. Compare them

```shell
mishpat compare ./mishpat-demo/corp-before.jsonl ./mishpat-demo/corp-after.jsonl -o ./mishpat-demo/report
```

The terminal shows a summary, then the files it wrote:

```text
mishpat 0.1.1
27 differences across 5 GPOs and the domain's structure. Every input was read in full.
  GPO: 3
  Status: 1
  WMI filter: 1
  Security filtering: 1
  Permissions (delegation): 1
  Links: 4
  Inheritance: 1
  Settings: 15
Reports written to mishpat-demo/report: mishpat-report.json, mishpat-report.md, mishpat-report.html, mishpat-differences.csv, mishpat-manifest.json
```

mishpat exits with code `1` because there are differences. That is the expected result here. Add `--fail-on never` to see exit code `0`. The same reports are committed in [examples/corp-example](https://github.com/faithful-oversight/faithful-mishpat/tree/main/examples/corp-example).

## 4. Read the report

Open `./mishpat-demo/report/mishpat-report.html` in a browser. The Markdown version, `mishpat-report.md`, holds the same content, ready to paste into a pull request or a change record.

Read the headline first. It gives the count of differences and says whether every input was read in full. In the example it was. If a part of an input could not be read, the headline says the comparison is incomplete, and a **Problems** section says what and where.

Then read the table **GPOs compared**. Each GPO has a status: `changed`, `unchanged`, `added`, or `removed`. GPOs with differences come first. This is what the example holds:

- **Workstation Hardening** was `Workstation Baseline`. It has a `renamed` difference, a new group in security filtering, a link that became enforced, and changes to account policy, security options, and the user right `SeDenyNetworkLogonRight`. The user right `SeNetworkLogonRight` lists the same members in a new order, and the report shows nothing for it, because a new order is not a change.
- **Baseline - Servers** has a new WMI filter query, a new link, and many setting changes. Several appear twice: once as an Administrative Templates policy and once as the `Registry.pol` value it sets.
- **Staff Desktop Settings** has its computer half turned off, a delegation entry removed, and a link turned off.
- **Edge Browser Policy** is `added` and **Legacy Kiosk Lockdown** is `removed`. Both bundles say they hold a whole domain, so a missing GPO was deleted.
- **Default Domain Policy** is `unchanged`.

Under **Domain structure**, two differences belong to an organizational unit and to no single GPO: the link order on `Workstations` changed, and the `Web` organizational unit started to block inheritance. Only a bundle records these. See [Input formats](formats.md#what-each-input-records).

Each difference has a **Sources** column. It names the file and the place in it that each side was read from, so you can check the difference by hand.

[Reports and output](output.md) explains every part of the report.

## 5. Use your own Group Policy

You can get Group Policy into mishpat in three ways. Use the first or second for the most complete comparison. Use the third when you cannot run a script.

You need two versions to compare. Take the first before your change and the second after it, the same way each time, and give the files different names.

### Run the PowerShell exporter on a computer with RSAT

Write the script from the installed package:

```shell
mishpat exporter -o Export-MishpatGpo.ps1
```

Copy it to an administration workstation that has the Group Policy Management Tools (RSAT), or to a domain controller. Read it first: it is one plain-text file. In PowerShell, run it for every GPO of the domain:

```powershell
.\Export-MishpatGpo.ps1 -All -OutFile C:\Temp\corp-before.jsonl
```

Or for chosen GPOs only:

```powershell
.\Export-MishpatGpo.ps1 -Name 'Workstation Baseline', 'Server Baseline' -OutFile C:\Temp\baseline-before.jsonl
```

The script reads each GPO with `Backup-GPO` into a temporary folder, reads the links, inheritance, and WMI filters from the directory, and writes one file. It prints nothing when it succeeds. It changes nothing in Active Directory or in SYSVOL. Check that the file exists, then copy it to the machine where you run mishpat.

Run the script again after the change, to `corp-after.jsonl`, and compare:

```shell
mishpat compare corp-before.jsonl corp-after.jsonl -o report
```

[Collecting exports](collecting.md#the-exporter-script) has every parameter and the rights it needs. Neither the exporter nor `mishpat collect` has been run against a real domain yet. Treat the first runs as a pilot.

### Collect remotely

`mishpat collect` runs the same script on a domain controller over PowerShell remoting (WinRM), so you install nothing on it. It needs the `live` extra:

```shell
pipx install "faithful-mishpat[live] @ git+https://github.com/faithful-oversight/faithful-mishpat"
export MISHPAT_PASSWORD='...'
mishpat collect --server dc01.corp.example --all --auth ntlm --username 'CORP\auditor' \
  --secret env:MISHPAT_PASSWORD --ca-file corp-root-ca.pem -o corp-before.jsonl
```

With Kerberos and a current ticket, leave out `--username` and `--secret`:

```shell
mishpat collect --server dc01.corp.example --all -o corp-before.jsonl
```

mishpat connects over HTTPS on port 5986 and always verifies the certificate. See [Collecting exports](collecting.md#remote-collection) for the requirements, every option, and why Basic and CredSSP authentication are not offered.

### Use your own Get-GPOReport or Backup-GPO output

If you cannot run the exporter, make the files yourself. On a computer with RSAT:

```powershell
Get-GPOReport -All -ReportType Xml -Path .\before.xml
Backup-GPO -All -Path .\before-backup
```

Compare two reports, or two folders:

```shell
mishpat compare before.xml after.xml -o report
mishpat compare ./before-backup ./after-backup -o report
```

These inputs lack some context. A report or a backup does not record link order, blocked inheritance, or the WMI filter query, and a report does not hold the `Registry.pol` values. mishpat compares what both sides record, and lists the rest under **Not compared**. [Input formats](formats.md#what-each-input-records) shows what each one keeps.

Make each backup into its own folder. A folder that holds two backups of one GPO is refused.

### Pair GPOs by name

If a GPO was deleted and created again, or the two versions are two generations of a baseline, the GPOs have different GUIDs. mishpat then says the inputs share no GPO and suggests `--match name`:

```shell
mishpat compare baseline-v1 baseline-v2 -o report --match name
```

See [Command reference](usage.md#pairing-by-name).

## Next steps

- [Command reference](usage.md) for every command, option, and exit code.
- [Input formats](formats.md) for what each input records.
- [Collecting exports](collecting.md) for the exporter, WinRM, and secrets.
- [Reports and output](output.md) for what each part of the report means.
- [Limitations](limitations.md) before you rely on a comparison as a record of a change.
