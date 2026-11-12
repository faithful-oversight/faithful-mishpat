# 5. Remote collection over WinRM

- Status: accepted
- Date: 2026-11-11

## Context

Running the exporter by hand on each computer is slow. Many teams want to collect from a workstation with nothing copied to the domain controllers. A PowerShell script already does the collection, so remote collection only has to run that script on a controller and bring its output back.

The project rule is that the tool stays read-only and offline unless a decision record says otherwise. Remote collection needs the network, so it needs a record. It also needs a library, and the library must use a license on the allow list in `scripts/check_licenses.py`. The file readers have no runtime dependencies today, and that must stay true for people who never collect remotely.

The credentials matter most. The account that collects can read GPOs and the directory of a domain. A tool that sends that account's password over a channel it does not verify, or that hands it to a server that has not proved itself, would be a risk.

mishpat's sibling tool, toledot, already collects remotely over WinRM with the same library and the same settings. This record adopts them, so an administrator who has set up one has set up both.

Options considered:

- **Users copy the file.** This stays supported, because the script and the file readers need no network. It does not meet the need for collection with nothing copied to the controller.
- **PowerShell remoting over SSH.** It needs an SSH server enabled and set up for PowerShell on each controller, and a second set of credentials and host keys to manage. WinRM is the transport Windows administrators already use for remoting.
- **WMI or DCOM.** It is an older interface. It depends on DCOM and dynamic RPC ports, which are harder to allow through a firewall than one WinRM port.
- **PowerShell remoting over WinRM, with the `pypsrp` library.** `pypsrp` is MIT licensed and pure Python. Its direct dependencies, `pyspnego` (MIT), `requests` (Apache-2.0), and `cryptography` (Apache-2.0 or BSD-3-Clause), also use allowed licenses. It supports HTTPS with certificate verification, message encryption over HTTP, and Kerberos, Negotiate, and NTLM.

## Decision

- Add `mishpat collect`. It sends the packaged exporter script to the controller, runs it there with `-ToPipeline` and `-Server` set to the controller, and streams the lines of the [export bundle](0004-export-bundle.md) back. Reading from the controller the session is on avoids a second hop.
- Use `pypsrp` for WinRM. Install it as the optional `live` extra, so reading files keeps no runtime dependencies. Import it only when collection runs.
- HTTPS on port 5986 is the default. It always verifies the certificate, against the system's roots or the authorities in the file `--ca-file` names. No option turns verification off.
- Plain HTTP on port 5985 is allowed only with message encryption required. `--ca-file` is refused with it.
- Offer only Kerberos (the default), Negotiate, and NTLM. None sends the password to the server. Do not offer Basic, which sends the password itself. Do not offer CredSSP, which delegates the account's reusable credentials to the server, so a compromised controller could keep them.
- Require `--server` to be a fully qualified DNS name. The certificate and the Kerberos service name are checked against it. Refuse an IP address and a bare host name.
- Take the password from a reference, never from the command line: an environment variable, a file, the keyring, HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. Each provider beyond the first two is its own optional extra. Check the server and user names before any secret is read or any connection is made.
- Remember every secret that is resolved, and remove it, in its plain and encoded forms, from any text before it is printed. An authentication library can put the credential in its own error text.
- Treat what the controller sends as untrusted. Check each line as it arrives, and stream into a private temporary file. When the script ends, check the end line's file count and SHA-256 against what arrived, and that the stream held one structure line. Only then publish the file, and never replace an existing file unless `--force` is given. On any failure, delete the temporary file.
- Stop the remote script when the controller sends nothing for `--timeout` seconds, 600 by default. The total time has no limit.
- Change nothing. The script reads Group Policy and the directory and writes only the output stream. Network use is limited to `mishpat collect`: the connection to the controller you name and the secret provider you name. `mishpat compare` stays offline.

## Consequences

Users get an export from one machine, with nothing installed on the controllers. They must still have a WinRM listener on each controller, an account that may open a remoting session and read the GPOs, and the Group Policy module on the controller. mishpat does not create or change a listener. Domain controllers have the module.

The account needs rights in two places: remoting, and Group Policy. mishpat has not tested whether a just-enough-administration endpoint can be narrowed to fit this script.

On Linux and macOS, Kerberos needs support that the `live` extra does not install: the `kerberos` extra of `pypsrp`, and the system Kerberos libraries. The documentation says so, and the behavior has not been tested.

`pypsrp` and its dependencies enter the supply chain, but only for users who install the extra. Locked versions, license checks, and vulnerability scans cover them.

The collection and the WinRM client have been tested with a simulated WinRM client only, plus a check of the settings handed to the real `pypsrp`. They have not been run against a real domain controller or a real WinRM endpoint. This is a known limitation of this release, and the documentation says so.

The end line shows that the export arrived whole. It does not show that the controller is honest. A controller that is compromised can change what the script returns. The [threat model](../threat-model.md) records that risk, and the credential and certificate controls earlier.
