# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The ``collect`` and ``exporter`` commands."""

from __future__ import annotations

import argparse
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_core.collect import names, secrets, winrm
from faithful_core.console import say
from faithful_core.files import refuse_aliases
from faithful_core.safety import command_line, terminal_line

from faithful_mishpat.arguments import bounded
from faithful_mishpat.collect import remote, script
from faithful_mishpat.errors import UsageError
from faithful_mishpat.outputs.files import write_files

if TYPE_CHECKING:
    from typing import Any

_seconds = bounded(1, 86400, "a whole number of seconds")
_port = bounded(1, 65535, "a port")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _gpo_name(text: str) -> str:
    """Check a GPO display name given to ``--name``."""
    if not text.strip() or _CONTROL.search(text):
        msg = "a GPO name must not be empty or hold control characters"
        raise argparse.ArgumentTypeError(msg)
    return text


def _gpo_guid(text: str) -> str:
    """Check a GUID given to ``--guid`` and return it lower-case without braces."""
    try:
        return str(uuid.UUID(text.strip().strip("{}")))
    except ValueError:
        msg = f"{text!r} is not a GUID"
        raise argparse.ArgumentTypeError(msg) from None


def add_arguments(commands: Any) -> None:
    """Register ``collect`` and ``exporter`` on the main parser's subcommands."""
    collect = commands.add_parser(
        "collect",
        help="export GPOs from a domain controller over PowerShell remoting",
        description=(
            "Run mishpat's read-only exporter on a domain controller over PowerShell "
            "remoting and write its export to a file for 'mishpat compare'. HTTPS always "
            "verifies the certificate; HTTP is used only with message encryption."
        ),
    )
    collect.add_argument("--server", required=True, help="the controller's DNS name")
    choice = collect.add_mutually_exclusive_group(required=True)
    choice.add_argument("--all", action="store_true", help="export every GPO in the domain")
    choice.add_argument(
        "--name", nargs="+", action="extend", type=_gpo_name, metavar="NAME",
        help="export the GPOs with these display names",
    )  # fmt: skip
    choice.add_argument(
        "--guid", nargs="+", action="extend", type=_gpo_guid, metavar="GUID",
        help="export the GPOs with these GUIDs",
    )  # fmt: skip
    collect.add_argument("--auth", choices=winrm.AUTHS, default="kerberos")
    collect.add_argument("--username", help="DOMAIN\\user or user@domain.example")
    collect.add_argument(
        "--secret", metavar="REF",
        help="where the password is: env:NAME, file:PATH, keyring:SERVICE/USER, "
        "vault:MOUNT/PATH#FIELD, aws:SECRET_ID[#FIELD], or azure:VAULT/NAME",
    )  # fmt: skip
    collect.add_argument("--transport", choices=winrm.TRANSPORTS, default="https")
    collect.add_argument("--port", type=_port, help="default: 5986 for https, 5985 for http")
    collect.add_argument("--ca-file", type=Path, help="PEM certificate authorities for https")
    collect.add_argument(
        "--timeout", type=_seconds, default=600,
        help="stop when the exporter sends nothing for this many seconds (default: 600)",
    )  # fmt: skip
    collect.add_argument("-o", "--output", required=True, type=Path, metavar="FILE")
    collect.add_argument("--force", action="store_true", help="replace an existing file")
    collect.set_defaults(run=run_collect)

    exporter = commands.add_parser(
        "exporter",
        help="write the PowerShell exporter to run on a domain controller yourself",
        description=f"Write {script.NAME}, the read-only exporter, to a file.",
    )
    exporter.add_argument("-o", "--output", type=Path, default=Path(script.NAME), metavar="FILE")
    exporter.add_argument("--force", action="store_true", help="replace an existing file")
    exporter.set_defaults(run=run_exporter)


def run_collect(args: argparse.Namespace) -> int:
    """Collect over PowerShell remoting. Names are checked before any secret is read."""
    server = names.server_name(args.server)
    username = names.account_name(args.username)
    if args.secret and not username:
        msg = "--secret needs --username"
        raise UsageError(msg)
    if args.auth == "ntlm" and not username:
        msg = "--auth ntlm needs --username and --secret; only Kerberos can use the current logon"
        raise UsageError(msg)
    if username and not args.secret:
        msg = "--username needs --secret; leave both out to use the current Kerberos ticket"
        raise UsageError(msg)
    # Before any secret is read: a collection must never replace a file it was told to use.
    refuse_aliases([args.output], _read_files(args))
    target = winrm.Target(
        server=server,
        auth=args.auth,
        username=username,
        secret=None,
        transport=args.transport,
        port=args.port,
        ca_file=args.ca_file,
        idle_timeout=args.timeout,
    )
    winrm.settings(target)  # refuse a bad combination before the secret is read
    if args.secret:
        secret = secrets.resolve(args.secret, hint=remote.install_hint, keep=("live",))
        target = winrm.Target(**{**vars(target), "secret": secret})
    values = remote.parameters(names=args.name, guids=args.guid, every_gpo=args.all, server=server)
    result = remote.collect(target, script.text(), values, args.output, force=args.force)
    say(
        f"Exported {result.files} files from {terminal_line(server)} "
        f"into {terminal_line(str(result.path))}."
    )
    for gap in result.gaps:
        say(f"  not read: {terminal_line(gap)}")
    command = command_line("mishpat", "compare", str(result.path), "AFTER", "-o", "report")
    say(f"Compare it with a later export using: {terminal_line(command)}")
    return 0


def _read_files(args: argparse.Namespace) -> list[tuple[str, Path]]:
    """The files ``collect`` reads, by role: the CA file and a ``file:`` secret."""
    found: list[tuple[str, Path]] = []
    if args.ca_file:
        found.append(("CA file", args.ca_file))
    provider, _, location = (args.secret or "").partition(":")
    if provider == "file" and location:
        found.append(("secret file", Path(location)))
    return found


def run_exporter(args: argparse.Namespace) -> int:
    """Write the packaged exporter script."""
    path: Path = args.output
    written = write_files(path.parent, {path.name: script.text()}, force=args.force)
    command = f".\\{script.NAME} -All -OutFile corp-gpos.jsonl"
    say(f"Wrote {terminal_line(str(written[0]))}. On a domain controller, in PowerShell:")
    say(f"  {command}")
    return 0
