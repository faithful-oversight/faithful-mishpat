# Collecting exports

mishpat can read `Get-GPOReport` files and `Backup-GPO` folders that you make yourself. See [Input formats](formats.md). It also has an exporter that writes its own [export bundle](formats.md#export-bundle). The bundle records link order, blocked inheritance, and WMI filter queries, which the other two inputs lack.

> **Status: untested on real systems.** The exporter and `mishpat collect` have not been run against a real domain, a real domain controller, a real WinRM endpoint, or Windows PowerShell 5.1. They are tested with synthetic stand-ins for Active Directory and the Group Policy module, and with a simulated WinRM client. Treat the first runs in your environment as a pilot, and check each bundle by comparing it with a report you trust. See [Limitations](limitations.md#how-far-this-release-has-been-tested).

| Method | Runs | Best for |
| --- | --- | --- |
| PowerShell exporter | On a computer with the Group Policy module, in your session | An administration workstation with RSAT, or a domain controller. Nothing but the script and its output file is involved. |
| `mishpat collect` | Anywhere that can reach a domain controller over WinRM | A collection with nothing copied to the controller. Needs the `live` extra and a WinRM listener. |

Both run the same script, so there is one format to read and one script to review. Both only read. Neither changes a GPO, a link, a filter, or a file in SYSVOL.

## The exporter script

### What it reads

The script `Export-MishpatGpo.ps1` reads Group Policy and the directory, nothing else:

- **The GPOs you choose.** For each GPO it runs `Backup-GPO` into a new folder under `$env:TEMP` with a random name, reads every file in that folder into the bundle, and deletes the folder. `Get-GPOReport` output is inside the backup as `gpreport.xml`. `Backup-GPO` also writes a `manifest.xml` beside the backup folder. The script does not export it.
- **The domain structure.** It reads the domain object, every organizational unit, and every site with ADSI, without the ActiveDirectory module. For each it takes the distinguished name, `gPLink`, and `gPOptions`. It reads the sites from `CN=Sites` in the configuration partition.
- **The WMI filters.** It reads them from the WMIPolicy part of the domain's System container. For each it takes `msWMI-ID`, `msWMI-Name`, `msWMI-Parm1` (the description), and `msWMI-Parm2` (the query).
- **The domain's name.** It takes the domain's DNS name from the directory.

The script does not read group membership, and it does not read any computer's local Group Policy cache.

### What the bundle holds

The bundle holds every file that `Backup-GPO` wrote for each chosen GPO, not only the files mishpat reads. Besides `gpreport.xml`, `Backup.xml`, `bkupInfo.xml`, and `registry.pol`, that can include security template files, audit files, script lists such as `scripts.ini`, and Preferences XML files. Treat a bundle as sensitive. It holds the policy content of the GPOs, and that content can include account names and other data you would not publish.

### Required rights

The script needs:

- The Group Policy module, `GroupPolicy`. It comes with the Group Policy Management Tools in RSAT, and is present on domain controllers. The script stops with an explanation when the module is missing.
- Read access to each GPO you choose, and to its files in SYSVOL. `Backup-GPO` needs this. Domain Admins and Group Policy Creator Owners have it.
- Read access to the domain, the Sites container, and the WMIPolicy container. Authenticated Users have it by default.

The script runs in Windows PowerShell 5.1 or PowerShell 7, as its help states. It is pure ASCII, so Windows PowerShell 5.1 reads it the same as PowerShell 7 does.

If the account cannot read part of the structure, the script does not fail. It records a gap. See [Gaps](#gaps).

### Run it

Write the script from the installed package, then copy it to the computer where you run it:

```shell
mishpat exporter -o Export-MishpatGpo.ps1
```

On the computer with RSAT, in PowerShell:

```powershell
.\Export-MishpatGpo.ps1 -All -OutFile C:\Temp\corp-before.jsonl
.\Export-MishpatGpo.ps1 -Name 'Workstation Baseline', 'Server Baseline' -OutFile C:\Temp\baseline-before.jsonl
```

Read the script before you run it. It is one plain-text file, with its help text at the top. `Get-Help .\Export-MishpatGpo.ps1 -Detailed` shows that help.

If the execution policy blocks the script, run it for one session only. This does not change the policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Export-MishpatGpo.ps1 -All -OutFile C:\Temp\corp-before.jsonl
```

| Parameter | Meaning |
| --- | --- |
| `-Name` | The display names of the GPOs to export, from 1 to 10,000. A name is matched exactly, without regard to case. A name that matches no GPO, or more than one, stops the export. Use `-Guid` for the second case. |
| `-Guid` | The GUIDs of the GPOs to export. Braces are optional. A GUID that matches no GPO stops the export. |
| `-All` | Export every GPO in the domain. The bundle then says its scope is `all`, so a GPO missing from a later export counts as deleted. |
| `-Domain` | The domain to read, as a DNS name. Default: the domain of the computer. |
| `-Server` | The domain controller to read from. Default: any controller. |
| `-OutFile` | The file to write. Required, unless you give `-ToPipeline`. |
| `-Force` | Replace `-OutFile` if it exists. Works with `-OutFile` only. |
| `-ToPipeline` | Write the lines to the output stream instead of a file. `mishpat collect` uses this. |

Give exactly one of `-Name`, `-Guid`, and `-All`. A relative `-OutFile` is resolved against the current PowerShell location, the folder shown at the prompt.

The script prints nothing when it succeeds. Copy the file to the machine where you run `mishpat compare`, and keep the original with your records.

To make a pair for `mishpat compare`, run the script once before a change and once after, with the same selection. Use different file names, such as `corp-before.jsonl` and `corp-after.jsonl`, because reports name each input by its filename.

### How the file is written

The script writes lines as UTF-8 with `\n` line ends to a new temporary file next to `-OutFile`, named `OutFile.RANDOM.part`. It keeps a running SHA-256 of what it writes. It writes the trailer last, with the file count, and the hash. Only then does it move the temporary file to the `-OutFile` name.

- Without `-Force`, the move fails if the name is taken, even by a file that appeared after the script started. The script stops with an error and changes nothing.
- With `-Force`, the script replaces the existing file in one step where the file system allows. A failed run never truncates a good file.
- If the script stops partway, no file appears under the `-OutFile` name, and the script deletes its temporary file.
- A selection error, such as a name that matches no GPO, stops the export before any file is made.
- A file written to the pipeline has no temporary file. The reader reports a pipeline stream that stopped early as cut short. See [Input formats](formats.md#how-mishpat-reads-a-bundle).

### Why it is read-only

- A test in the repository checks that the script calls only these commands: `Set-StrictMode`, `New-Object`, `Write-Output`, `Write-Warning`, `Get-Date`, `Sort-Object`, `ForEach-Object`, `Where-Object`, `Get-Command`, `Import-Module`, `Get-GPO`, and `Backup-GPO`. The test also checks that the script has none of the commands that change Group Policy or the directory, and no `Invoke-Expression`, `Start-Process`, `Remove-Item`, `Set-Content`, or `Out-File`.
- `Backup-GPO` reads a GPO and writes only into the folder it is given. The script gives it a new folder with a random name and removes that folder, with every file in it, when the GPO has been read, even if something fails. If the folder cannot be removed, the script warns and names it.
- The script reads Active Directory with ADSI searches only.
- Its only other write is the file you name.
- It does not parse the files it exports. It reads each one as bytes and encodes it in base64.

### Gaps

A part of the structure that the script cannot read is not fatal. The script names it in the structure line, under `gaps`, and goes on. The comparison then is incomplete, and each gap shows as a [problem](output.md#problems). The parts are the domain object, the organizational units, the sites, and the WMI filters.

A failure to find the domain, the GroupPolicy module, or a chosen GPO stops the export instead.

### What an export cannot show

- **One moment.** The script backs up the GPOs one after another, then reads the structure. It is not a snapshot. A change made while it runs can appear in some parts and not in others.
- **One controller.** It reads from one controller, `-Server` or any. A controller that has not yet replicated a change shows the older state.
- **Effective settings.** It records what each GPO holds and where it is linked. It does not record what applies to a computer or a user.
- **Anything it was not allowed to read.** It records a gap for the structure. For a GPO, it stops.

## Remote collection

`mishpat collect` runs the same script on a domain controller over PowerShell remoting, which uses WinRM. mishpat sends the script text to the controller, runs it with `-ToPipeline`, and streams the lines back. Nothing is installed on the controller. The script reads from that controller, so its directory reads are not a second hop.

```shell
mishpat collect --server dc01.corp.example --all --auth ntlm --username 'CORP\auditor' \
  --secret env:MISHPAT_PASSWORD --ca-file corp-root-ca.pem -o corp-before.jsonl
```

[Command reference](usage.md#collect) lists every option. `mishpat collect` has no `--domain` option: the domain is the one of the controller you name.

### Prerequisites

Install the `live` extra, which adds `pypsrp`:

```shell
pipx install "faithful-mishpat[live] @ git+https://github.com/faithful-oversight/faithful-mishpat"
```

You also need:

- A WinRM listener on the controller that your machine can reach: port **5986** for HTTPS, or **5985** for HTTP with message encryption. mishpat does not create or change a listener.
- For HTTPS, a controller certificate that chains to a root you trust and names the `--server` DNS name. Pass the certificate of your internal CA in PEM format with `--ca-file` when the system does not already trust it.
- An account that may open a PowerShell remoting session on the controller. By default, that is a member of Administrators or Remote Management Users.
- The rights the script needs, listed in [Required rights](#required-rights). The GroupPolicy module must be present on the controller. Domain controllers have it.

The account must hold the remoting right and the rights to read the chosen GPOs. mishpat does not ship a just-enough-administration (JEA) configuration, and running the exporter through one has not been tested.

On Linux and macOS, Kerberos authentication needs support that the `live` extra does not install. `pypsrp` lists it as its optional `kerberos` extra, which adds `pyspnego[kerberos]`, and it needs the system Kerberos libraries. This has not been tested. If Kerberos fails on Linux or macOS, install that extra into the same environment, for example `pipx inject faithful-mishpat "pyspnego[kerberos]"`.

### Security settings

mishpat offers no insecure combination. These are the settings `mishpat collect` gives to `pypsrp`:

- **HTTPS is the default**, on port 5986. mishpat always verifies the certificate. It must chain to a trusted root, which is the system's roots or the authorities in the `--ca-file` PEM file. No option turns verification off.
- **HTTP**, on port 5985, works only with message encryption always required. `pypsrp` then wraps every message with Kerberos, Negotiate, or NTLM encryption. With HTTPS, encryption is `auto`. `--ca-file` with `--transport http` is refused.
- **`--server` must be a fully qualified DNS name**, such as `dc01.corp.example`. mishpat verifies the certificate against that name, and Kerberos asks for a ticket for it. An IP address or a bare host name would fail verification or weaken it, so mishpat refuses both.
- **Authentication is `kerberos` (the default), `negotiate`, or `ntlm`.** None of these sends the password to the server. mishpat does not offer Basic or CredSSP. Basic sends the password itself. CredSSP hands the account's reusable credentials to the server, so a compromised controller could keep them. Prefer Kerberos.
- **Names are checked first.** mishpat checks `--server`, `--username`, and the pairing of `--username` with `--secret` before it reads a secret or opens a connection. `--username` must be `DOMAIN\user` or `user@domain.example`, with the domain the account belongs to.
- **Timeouts.** mishpat waits up to 30 seconds to connect. After that, collection has no overall time limit. It has an idle limit instead. See [Timeouts](#timeouts).

Use a dedicated account that has only the rights listed earlier. Prefer a Kerberos ticket or a secret manager to a stored password.

### Secret references

`--secret` takes a reference, never the password. mishpat reads the secret when it starts and passes it to the authentication library. It never writes the secret to the output file or to a report.

| Provider | Reference | Extra | Notes |
| --- | --- | --- | --- |
| Environment | `env:NAME` | none | The variable must be set and not empty. |
| File | `file:PATH` | none | The first line of the file, read as UTF-8. A byte order mark is accepted. A file that is not UTF-8 is refused. Keep the file readable only by you. mishpat does not check its permissions. |
| Keyring | `keyring:SERVICE/USERNAME` | `keyring` | The operating system keychain entry for that service and username. |
| HashiCorp Vault | `vault:MOUNT/PATH#FIELD` | `vault` | A KV version 2 secret. Uses `VAULT_ADDR` and `VAULT_TOKEN`. `#FIELD` is required. |
| AWS Secrets Manager | `aws:SECRET_ID` or `aws:SECRET_ID#FIELD` | `aws` | Uses the standard AWS credential chain. Without `#FIELD`, the whole secret string is the password. With it, the secret must be JSON and `FIELD` is one key. |
| Azure Key Vault | `azure:VAULT_NAME/SECRET_NAME` | `azure` | Reads `https://VAULT_NAME.vault.azure.net` with `DefaultAzureCredential`. |

A missing provider package produces an error that names the extra to install. An empty secret is refused.

Authentication libraries sometimes put the credential in their own error text. mishpat remembers every secret it resolves and removes it, in its plain, URL-encoded, JSON-escaped, and quoted forms, from any error before it prints the error. Errors from Vault, AWS, and Azure name only the type of the exception.

### Timeouts

mishpat waits up to 30 seconds to connect. After that, collection has no overall time limit. It has an idle limit instead: if the controller sends no line for `--timeout` seconds (default 600), mishpat stops the remote script, deletes the partial file, and fails with exit code `3`.

Exporting many GPOs can take a while between lines, because one line can hold a large file. If collection stops with an idle error on a healthy controller, raise `--timeout`.

### How the output file is written safely

The lines stream into a private temporary file in the same folder as the output, named `.NAME.RANDOM.part`. mishpat checks each line as it arrives. A line must be one line of ASCII text, at most 89,482,584 bytes. The first line must be a mishpat export header that passes the same checks as the file reader's. A line must be a file line, the structure line, or the end line, and nothing may follow the end line. The stream may hold at most one structure line.

When the script ends, mishpat checks the end line against what arrived. The end line must pass the file reader's own checks, and the file count and the SHA-256 of every line before it must match. The export must hold one structure line. Only then does mishpat publish the file, so a stream that `mishpat compare` would refuse at its first line or end line is never published, and an existing file is left as it was.

- Without `--force`, mishpat puts the file in place only if the name is free, so it never replaces a file, even one that appears while collection runs. mishpat also checks at the start and refuses early if the file exists.
- With `--force`, it replaces the file. Even then, mishpat refuses (before it reads a secret or connects) when the output file is the `--ca-file` or the file named by `--secret file:PATH`, by the same path, a symbolic link, or a hard link.
- On any failure, mishpat deletes the temporary file. A partial file is never left behind.
- On Linux and macOS, the temporary file is readable only by your user account.

The check proves that the transfer was whole. It does not check each file line: `mishpat compare` validates every line again, as it does for any bundle, and reports a bad line as a problem. Treat a bundle from a controller like any other untrusted input. See the [threat model](threat-model.md).

The command prints the number of files it exported and each gap the exporter recorded, as `not read:` lines. It then prints the `mishpat compare` command to run with a later export.

### What a collection cannot show

- Only what the one controller you collected from holds, and only as of the moment it ran.
- Anything a compromised controller chooses to hide or invent. The end line proves the file arrived whole, not that the controller told the truth.
- Anything the account was not allowed to read.

## After collecting

Collect again after the change, then compare the two files:

```shell
mishpat compare corp-before.jsonl corp-after.jsonl -o report
```

A bundle holds the files of every GPO it exports. Treat it as sensitive.
