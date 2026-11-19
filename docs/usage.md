# Command reference

```text
mishpat [--version] COMMAND [options]
```

| Command | What it does |
| --- | --- |
| `compare` | Compare two versions of Group Policy and write the reports. |
| `collect` | Export GPOs from a domain controller over PowerShell remoting. Needs the `live` extra. |
| `exporter` | Write the PowerShell exporter, to run on a computer with the Group Policy module yourself. |
| `schema` | Print a JSON Schema: `report`, `export`, or `manifest`. |
| `example` | Write a synthetic before and after to try mishpat with. |

Run `mishpat COMMAND --help` for the options of any command. Running `mishpat` with no command prints the help and exits with code `2`.

## compare

```shell
mishpat compare BEFORE AFTER -o DIR [options]
```

| Option | Meaning |
| --- | --- |
| `BEFORE`, `AFTER` | The two versions. Each is a [Get-GPOReport XML file, a Backup-GPO folder, or an export bundle](formats.md). mishpat detects the kind of each from its content, not its name. |
| `-o`, `--output` | Folder for the reports. Required. Created if needed. |
| `-f`, `--format` | Comma-separated list of `json`, `md`, `html`, `csv`. Default: all four. The manifest is always written. |
| `--match` | How to pair GPOs: `guid` (default) or `name`. See [Pairing by name](#pairing-by-name). |
| `--fail-on` | When to exit with code `1`: `differences` (default), `incomplete`, or `never`. See [Exit code of compare](#exit-code-of-compare). |
| `--max-pol-entries` | Most entries read from one `Registry.pol` file. Default: 1,000,000. A file with more is a problem: the entries after the limit are not read, the report says so, the comparison is incomplete, and the exit code is `1`. Raise it for an unusually large file. |
| `--max-scan-folders` | Most folders listed below the backup search depth, only to look for a backup that would not be read. Default: 200,000. Reaching it is a problem, so the comparison is incomplete and the exit code is `1`. |
| `--max-xml-elements` | Most XML elements held in memory at once while reading one XML file. Default: 1,000,000. A `<GPOS>` file is read one GPO at a time, so this bounds one GPO, not the whole file. A file over the limit is refused (exit code `3`); a small file inside a backup that is over it is a problem (exit code `1`). Raise it only for a single very large GPO. |
| `--force` | Replace report files that already exist. Without it, mishpat refuses. Even with it, mishpat refuses (exit 3, before reading anything) when a report or manifest file is one of the inputs, or would be written inside an input folder. That covers the same path, a symbolic link in either direction, and a hard link. |

The two sides can be different kinds. You can compare a `Backup-GPO` folder with an export bundle, for example. mishpat compares only what both sides record, and it lists the rest under [Not compared](output.md#not-compared).

### Input

mishpat reads the size and SHA-256 of both inputs before it parses either, so the report records the inputs exactly as it read them. It refuses:

- A path that does not exist or cannot be read, with exit code `3`.
- An input that is none of the [three kinds](formats.md#how-the-kind-is-detected), with exit code `3`.
- A root folder that holds two backups of one GPO, with exit code `3`. The error names both folders.
- Two inputs with the same contents, with exit code `2`. The error names both. A comparison of identical inputs can show nothing, and giving one file twice is most likely a mistake. For a folder, the SHA-256 covers the path and the content of every file, so the same files give the same value wherever the folder is.

A problem inside an input does not stop the run. mishpat lists a record or a file part that it could not read as a [problem](output.md#problems), and the comparison is incomplete. Only a file that fails as a whole, such as a bundle with no valid header, is an error.

Give mishpat the backup folder, or the root that holds the backups, and not a parent folder that holds other data. To record the size and SHA-256 of a folder, mishpat reads every file under it, including files it does not parse.

A report names each input by its file or folder name only. When both have the same name, such as `monday/gpos.jsonl` and `friday/gpos.jsonl`, mishpat cites them as `before/gpos.jsonl` and `after/gpos.jsonl`.

### Pairing by name

mishpat pairs the GPOs of the two inputs by GUID. Use `--match name` to pair them by display name instead, compared without regard to case. Use it when the same policy has a different GUID on each side:

- A GPO was deleted and created again. The new GPO has a new GUID and the same name.
- The inputs are two generations of a baseline that you imported, such as the same security baseline at two versions. Each import makes new GUIDs.

With `--match name`:

- A name that appears twice on one side stops the run with exit code `2`. Pair by GUID instead.
- A GPO whose name changed is not paired, because the name is what pairs GPOs. It shows as a GPO that exists in only one input. With the default, a changed name on the same GUID shows as renamed.
- The report shows both GUIDs for a pair, as `AFTER-GUID (before: BEFORE-GUID)`.
- Link order is still compared by GUID. A GPO that has a different GUID on each side is not part of the link order comparison. Its links are still compared GPO by GPO. See [Limitations](limitations.md#pairing-by-name).

When the two inputs share no GPO by GUID, mishpat says so in a notice and suggests `--match name`.

### Exit code of compare

mishpat writes the reports first. The exit code then says whether the result needs attention. Notices and [not compared](output.md#not-compared) items never change it.

| `--fail-on` | Exit code `1` when |
| --- | --- |
| `differences` (default) | Any difference exists, or an input could not be read in full. |
| `incomplete` | An input could not be read in full. Differences alone do not matter. |
| `never` | Never. The run exits with `0` when it writes the reports. |

The comparison is incomplete when any [problem](output.md#problems) exists on either side. Otherwise every input was read in full.

With the default, exit code `0` means there are no differences and every input was read in full. It does not mean the two versions have the same effect. See [Limitations](limitations.md).

### Output files

`mishpat compare` writes the formats you choose with `--format`, then `mishpat-manifest.json`, into the output folder:

| File | Format |
| --- | --- |
| `mishpat-report.json` | Machine-readable report. See [Reports and output](output.md). |
| `mishpat-report.md` | Markdown report for pull requests and change records. |
| `mishpat-report.html` | Self-contained web page. Open it in any browser. |
| `mishpat-differences.csv` | One row per difference. |
| `mishpat-manifest.json` | The size and SHA-256 of every file listed and of both inputs. Written last. |

Files are written in that order whatever order you give to `--format`. A new output folder is readable only by your user account on Linux and macOS, and so are the files. Without `--force`, mishpat never replaces an existing file, even one created while it runs. With `--force`, it moves the old files aside first and puts them back if anything fails, so the folder holds either the old set or the new set.

Run one mishpat at a time per output folder. Only a crash or power loss while writing can leave a partial file, a mix of old and new files, or `.mishpat-old-*` backup files. The manifest lists the size and SHA-256 of every file from its run, so either case is detectable. See [Reports and output](output.md#manifest).

If you leave `json` out of `--format`, the Markdown and HTML reports keep every value and row whole, because nothing else would hold them. See [Shortening](output.md#shortening).

### Repeatable reports

A report records when it was generated. By default that is the clock. Set the environment variable `SOURCE_DATE_EPOCH` to a whole number of seconds since 1970-01-01 UTC, and mishpat uses that time instead. The same inputs and options then give byte-for-byte identical files.

```shell
SOURCE_DATE_EPOCH=1793000000 mishpat compare corp-before.jsonl corp-after.jsonl -o report
```

A value that is not a whole number of seconds, or that is out of range, is ignored, and mishpat uses the clock.

## collect

```shell
mishpat collect --server SERVER (--all | --name NAME [NAME ...] | --guid GUID [GUID ...]) -o FILE [options]
```

Runs the packaged exporter on a domain controller over PowerShell remoting and writes the export bundle. Needs the `live` extra. See [Collecting exports](collecting.md#remote-collection) for requirements, security settings, and secret providers.

| Option | Meaning |
| --- | --- |
| `--server` | The controller's fully qualified DNS name, such as `dc01.corp.example`. Required. An IP address or a bare host name is refused. |
| `--all` | Export every GPO in the domain. The bundle then holds a whole domain. |
| `--name` | Export the GPOs with these display names. Give one or more names. |
| `--guid` | Export the GPOs with these GUIDs. Braces are optional. Give one or more. |
| `--auth` | `kerberos` (default), `negotiate`, or `ntlm`. No other method is offered. |
| `--username` | `DOMAIN\user` or `user@domain.example`. A name with no domain is refused. |
| `--secret` | A reference to where the password is kept: `env:NAME`, `file:PATH`, `keyring:SERVICE/USER`, `vault:MOUNT/PATH#FIELD`, `aws:SECRET_ID[#FIELD]`, or `azure:VAULT/NAME`. Never the password itself. |
| `--transport` | `https` (default) or `http`. HTTP is used only with message encryption. |
| `--port` | From 1 to 65535. Default: 5986 for `https`, 5985 for `http`. |
| `--ca-file` | A PEM file of certificate authorities to verify the HTTPS certificate against. Applies to `https` only. |
| `--timeout` | Stop when the exporter sends nothing for this many seconds, from 1 to 86400. Default: 600. |
| `-o`, `--output` | The bundle file to write. Required. |
| `--force` | Replace an existing file. |

Give exactly one of `--all`, `--name`, and `--guid`.

`--username` and `--secret` go together. Give both, or leave both out to use the current Kerberos ticket. `--auth ntlm` always needs both. mishpat checks the server name, the user name, and these pairings before it reads the secret or makes a connection. A `--secret` without `--username`, a `--username` without `--secret`, and `--auth ntlm` without a user name exit with code `2`. A bad `--server` or `--username`, and `--ca-file` with `--transport http`, exit with code `3`.

A missing `live` extra, a failed connection, a failed login, an unreadable secret, an export that does not match its end line, or an existing output file stops the run with exit code `3`. A part of the structure that the exporter could not read does not stop it. mishpat prints each such gap as a `not read:` line, and the file records it. The command prints the `mishpat compare` command to run next.

## exporter

```shell
mishpat exporter [-o FILE] [--force]
```

Writes `Export-MishpatGpo.ps1`, the read-only PowerShell exporter. The default output is `Export-MishpatGpo.ps1` in the current folder. The command creates the folder if needed, never replaces an existing file unless you give `--force`, and prints the command that runs the script. See [Collecting exports](collecting.md#the-exporter-script).

## schema

```shell
mishpat schema {report|export|manifest}
```

Prints a JSON Schema for the installed version, with no network access. `report` is the report, `export` is one line of the [export bundle](formats.md#export-bundle), and `manifest` is the manifest. See [Reports and output](output.md#json-schemas).

## example

```shell
mishpat example DIR [--force]
```

Writes a synthetic before and after into the folder, creating it if needed, and prints the `mishpat compare` command that uses them. The data is synthetic and describes the reserved domain `corp.example`. Without `--force`, mishpat refuses to replace existing files. See the [Quickstart](quickstart.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `mishpat compare`, the result did not reach the `--fail-on` level, which for the default means there are no differences and every input was read in full. Also `--help`, `--version`, `schema`, `example`, `exporter`, and `collect` when they succeed. |
| `1` | `mishpat compare` wrote its reports, and the result reached the level that `--fail-on` names: by default, there is a difference or an input was not read in full. |
| `2` | The command was used incorrectly. For example, an option is unknown or missing, a value is out of range, two inputs have the same contents, `--match name` meets a name that is not unique, or options that must go together do not. Also `mishpat` run with no command. |
| `3` | An input, output, or collection problem: a missing or unreadable input, an input of no known kind, a bundle with no valid header, a root with two backups of one GPO, a report file that already exists, a report file that is, or would be inside, one of the inputs, or a failed collection. This includes a bad `--server` or `--username` for `mishpat collect`. |
| `4` | An internal error in mishpat. This is a bug. Please report it. |

Exit code `1` never means the tool failed. It means the result needs a look, so read the report.

mishpat decides the exit code of `compare` before it prints the closing summary. A summary that cannot be printed does not change it: a closed pipe, such as `mishpat compare ... | head`, stops the printing and leaves the code as decided, and a terminal or redirect that cannot show a character in a path gets a backslash escape such as `\xe9` in its place. The report files are written whole in either case.

## Use in a pipeline

`mishpat compare` needs no network access and no secrets, so it runs anywhere Python does.

PowerShell:

```powershell
mishpat compare .\corp-before.jsonl .\corp-after.jsonl -o .\report
switch ($LASTEXITCODE) {
    0 { "No differences, and every input was read in full." }
    1 { Write-Warning "Differences or an unreadable input; see .\report\mishpat-report.html" }
    default { throw "mishpat failed with exit code $LASTEXITCODE" }
}
```

Shell:

```shell
mishpat compare corp-before.jsonl corp-after.jsonl -o report || test $? -eq 1
```

To fail a pipeline only when an input could not be read, add `--fail-on incomplete`. To use the reports as an artifact whatever the result, add `--fail-on never`.

Collect on a schedule by giving `mishpat collect` a secret reference that your scheduler or secret store fills in, for example `--secret env:MISHPAT_PASSWORD`. Never put the password on the command line.
