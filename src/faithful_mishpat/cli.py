# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from enum import IntEnum
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_mishpat import __version__, example, outputs, pipeline
from faithful_mishpat.collect import cli as collect_cli
from faithful_mishpat.collect.secrets import redact
from faithful_mishpat.compare import MATCHES
from faithful_mishpat.errors import MishpatError, UsageError
from faithful_mishpat.outputs import render
from faithful_mishpat.outputs.files import write_files
from faithful_mishpat.outputs.safety import command_line, terminal

if TYPE_CHECKING:
    from collections.abc import Sequence

FORMATS = ("json", "md", "html", "csv")
SCHEMAS = {"report": "report-v1", "export": "export-v1", "manifest": "manifest-v1"}
FAIL_ON = ("differences", "incomplete", "never")


class ExitCode(IntEnum):
    """Process exit codes. These values are part of the public interface."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    INPUT_ERROR = 3
    INTERNAL_ERROR = 4


def _formats(text: str) -> list[str]:
    chosen = [part.strip() for part in text.split(",") if part.strip()]
    unknown = [part for part in chosen if part not in FORMATS]
    if unknown or not chosen:
        msg = f"choose formats from {', '.join(FORMATS)}, separated by commas"
        raise argparse.ArgumentTypeError(msg)
    return list(dict.fromkeys(chosen))


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mishpat",
        description=(
            "GPO Change Review: compare two versions of Group Policy, one GPO or a whole "
            "domain, and write a reviewable difference."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(title="commands", metavar="COMMAND")

    diff = commands.add_parser(
        "compare",
        help="compare two versions of Group Policy",
        description=(
            "Compare two versions of Group Policy. Each side is a Get-GPOReport XML file, a "
            "Backup-GPO folder (one backup or a folder of backups), or an export from "
            "'mishpat collect' or the exporter script. Reading is offline."
        ),
    )
    diff.add_argument("before", type=Path, metavar="BEFORE")
    diff.add_argument("after", type=Path, metavar="AFTER")
    diff.add_argument("-o", "--output", type=Path, required=True, metavar="DIR",
                      help="folder for the reports")  # fmt: skip
    diff.add_argument("-f", "--format", type=_formats, default=list(FORMATS), metavar="LIST",
                      help="comma-separated: json, md, html, csv (default: all)")  # fmt: skip
    diff.add_argument(
        "--match",
        choices=MATCHES,
        default="guid",
        help=(
            "pair GPOs by GUID (default) or by display name, for GPOs that were re-created "
            "or come from two generations of a baseline"
        ),
    )
    diff.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default="differences",
        help=(
            "exit 1 when there is any difference or an input could not be read in full "
            "(differences, the default), only when an input could not be read (incomplete), "
            "or never"
        ),
    )
    diff.add_argument("--force", action="store_true", help="replace existing reports")
    diff.set_defaults(run=_compare)

    schema = commands.add_parser(
        "schema", help="print a JSON schema", description="Print a JSON schema, offline."
    )
    schema.add_argument("name", choices=sorted(SCHEMAS))
    schema.set_defaults(run=_schema)

    sample = commands.add_parser(
        "example",
        help="write a synthetic before and after to try mishpat with",
        description="Write two synthetic exports of one domain. Every name in them is made up.",
    )
    sample.add_argument("directory", type=Path, metavar="DIR")
    sample.add_argument("--force", action="store_true", help="replace existing files")
    sample.set_defaults(run=_example)

    collect_cli.add_arguments(commands)
    return parser


def _now() -> datetime:
    """The report time: the clock, or ``SOURCE_DATE_EPOCH`` for a repeatable report."""
    fixed = os.environ.get("SOURCE_DATE_EPOCH", "")
    if fixed.isascii() and fixed.isdigit():
        try:
            return datetime.fromtimestamp(int(fixed), UTC)
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(UTC).replace(microsecond=0)


def _compare(args: argparse.Namespace) -> int:
    comparison, after, inputs = pipeline.run(args.before, args.after, match=args.match)
    document = outputs.build_report(
        comparison,
        [vars(item) for item in inputs],
        _now(),
        __version__,
        {"match": args.match, "fail_on": args.fail_on},
        after=after,
    )
    written = outputs.write_reports(document, args.output, args.format, force=args.force)
    print(render.terminal_summary(document))  # noqa: T201
    print(terminal(f"Reports written to {args.output}: {', '.join(p.name for p in written)}"))  # noqa: T201
    if args.fail_on == "never":
        return int(ExitCode.OK)
    failed = not comparison.complete or (args.fail_on == "differences" and comparison.differences)
    return int(ExitCode.FINDINGS if failed else ExitCode.OK)


def _schema(args: argparse.Namespace) -> int:
    name = f"schema/{SCHEMAS[args.name]}.schema.json"
    sys.stdout.write(files("faithful_mishpat").joinpath(name).read_text(encoding="utf-8"))
    return int(ExitCode.OK)


def _example(args: argparse.Namespace) -> int:
    data = example.build()
    written = write_files(args.directory, data, force=args.force)
    before, after = (p for p in written if p.name in example.NAMES)
    command = command_line(
        "mishpat", "compare", str(before), str(after), "-o", str(args.directory / "report")
    )
    print(terminal(f"Wrote a synthetic before and after to {args.directory}. Try:\n  {command}"))  # noqa: T201
    return int(ExitCode.OK)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return an exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else int(ExitCode.USAGE)
    if not getattr(args, "run", None):
        parser.print_help(sys.stderr)
        return int(ExitCode.USAGE)
    try:
        return int(args.run(args))
    except MishpatError as exc:
        print(f"mishpat: error: {terminal(redact(str(exc)))}", file=sys.stderr)  # noqa: T201
        return int(ExitCode.USAGE if isinstance(exc, UsageError) else ExitCode.INPUT_ERROR)
    except Exception as exc:  # noqa: BLE001 - last-resort handler keeps crashes distinct
        print(  # noqa: T201
            f"mishpat: internal error: {type(exc).__name__}: {terminal(redact(str(exc)))[:200]}\n"
            "This is a bug in mishpat. Please report it.",
            file=sys.stderr,
        )
        return int(ExitCode.INTERNAL_ERROR)
