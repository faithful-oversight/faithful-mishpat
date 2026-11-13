# Examples

## corp-example

`corp-example` is a synthetic example. It describes a made-up domain, `corp.example`, with six GPOs, three organizational units, and two WMI filters. The domain SID (`S-1-5-21-1000-2000-3000`), group names, GUIDs, and every other identifier are invented. No real organization's data is here.

| File | What it is |
| --- | --- |
| `corp-before.jsonl` | An export of every GPO in the domain, written the way `Export-MishpatGpo.ps1` writes it, as the domain was on October 5, 2026. |
| `corp-after.jsonl` | The same export after a change window, as the domain was on November 9, 2026. |
| `sample-report/` | The reports `mishpat compare` writes for the two files. |

Both exports hold one `Backup-GPO` folder per GPO, then the domain's organizational units with their raw `gPLink` values and blocked-inheritance flag, and then the WMI filters with their queries. Each file says its scope is `all`, so a GPO missing from one file is reported as added or removed.

The change window touches every kind of difference the report can show. The report has 27 differences: 25 in 5 of the 6 GPOs and 2 on organizational units.

| GPO | What changed |
| --- | --- |
| `Default Domain Policy` | Nothing. The report lists it as unchanged. |
| `Baseline - Servers` | The `Configure Automatic Updates` policy changes its drop-down from `3 - Auto download and notify for install` to `4 - Auto download and schedule the install`. The `Turn off Autoplay` policy is removed and `Disable Windows Error Reporting` is added. In `Registry.pol`, `AUOptions` changes from 3 to 4, `NoDriveTypeAutoRun` is removed, `Disabled` is added under Windows Error Reporting, and a `**del.UseWUServer` directive is added. In Advanced Audit, `Audit Logon` changes from success to success and failure, `Audit File Share` is removed, and `Audit Process Creation` is added. The query of its WMI filter, `Member servers`, changes. The GPO is also linked to the `Web` organizational unit. |
| `Workstation Baseline` | The GPO is renamed `Workstation Hardening`. In Security settings, the account lockout threshold changes from 10 to 5, the LAN Manager authentication level changes from 3 to 5, `Machine inactivity limit` is added, and `Restrict anonymous access` is removed. The user right `SeDenyNetworkLogonRight` (deny access to this computer from the network) gains the `Local account` group. The user right `SeNetworkLogonRight` (access this computer from the network) keeps the same three members and lists them in a new order, so the report shows nothing for it. The group `CORP\Pilot Workstations` is added to security filtering, and the GPO's link to the `Workstations` organizational unit becomes enforced. |
| `Staff Desktop Settings` | The computer half is turned off. The delegation entry for `CORP\Helpdesk Operators` (Read) is removed. The link to the `Workstations` organizational unit is turned off. |
| `Legacy Kiosk Lockdown` | The GPO is deleted. |
| `Edge Browser Policy` | The GPO is created and linked to the `Workstations` organizational unit. |

Two changes are to organizational units and belong to no single GPO:

- On the `Workstations` organizational unit, `Staff Desktop Settings` moves ahead of `Workstation Hardening` in link order.
- The `Web` organizational unit turns on block inheritance.

The report is written to be read, not decoded:

- A policy that changed shows only the option that changed. `Configure Automatic Updates` shows its drop-down going from `3 - Auto download and notify for install` to `4 - Auto download and schedule the install`, not the whole policy.
- Accounts and security option values carry their meaning. The user right shows `S-1-5-113 (NT AUTHORITY\Local account)`, and the LAN Manager authentication level shows `5 (Send NTLMv2 response only. Refuse LM & NTLM)`.
- A WMI filter query reads as `namespace: query` instead of the raw directory attribute.
- A created or deleted GPO shows its name on the side that has it. The organizational unit changes are in a `Domain structure` section, written as paths such as `corp.example/Workstations`.

Open `sample-report/mishpat-report.html` in a browser to see the report. The report files are `mishpat-report.html`, `mishpat-report.md`, `mishpat-report.json`, `mishpat-differences.csv`, and `mishpat-manifest.json`.

### Regenerate the sample

The two export files come from `mishpat example`. The reports come from this command, run from the repository root. `SOURCE_DATE_EPOCH` fixes the generation time, so the same code always writes the same bytes:

```shell
mishpat example examples/corp-example --force
SOURCE_DATE_EPOCH=1794225600 mishpat compare examples/corp-example/corp-before.jsonl examples/corp-example/corp-after.jsonl -o examples/corp-example/sample-report --force
```

mishpat exits with code `1` because the report has differences. A test checks that the committed files match what the current code writes, apart from the tool version.

### Try it yourself

```shell
mishpat example ./mishpat-demo
mishpat compare ./mishpat-demo/corp-before.jsonl ./mishpat-demo/corp-after.jsonl -o ./mishpat-demo/report
```
