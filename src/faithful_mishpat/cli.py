# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

from faithful_core import xmlsafe
from faithful_core.clock import now
from faithful_core.console import finish, prepare, say
from faithful_core.exitcodes import ExitCode
from faithful_core.safety import command_line, terminal_line

from faithful_mishpat import __version__, example, outputs, pipeline
from faithful_mishpat.arguments import bounded
from faithful_mishpat.collect import cli as collect_cli
from faithful_mishpat.collect.secrets import redact
from faithful_mishpat.compare import MATCHES
from faithful_mishpat.errors import MishpatError, UsageError
from faithful_mishpat.formats import backup, registrypol
from faithful_mishpat.outputs import render
from faithful_mishpat.outputs.files import refuse_input_overwrite, write_files

if TYPE_CHECKING:
    from collections.abc import Sequence

FORMATS = ("json", "md", "html", "csv")
SCHEMAS = {"report": "report-v1", "export": "export-v1", "manifest": "manifest-v1"}
FAIL_ON = ("differences", "incomplete", "never")


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
    diff.add_argument(
        "--max-pol-entries", type=_count, default=registrypol.MAX_ENTRIES, metavar="N",
        help=f"most entries read from one Registry.pol (default: {registrypol.MAX_ENTRIES}); "
        "more is a problem, so the run exits 1",
    )  # fmt: skip
    diff.add_argument(
        "--max-scan-folders", type=_count, default=backup.MAX_SCAN_FOLDERS, metavar="N",
        help="most folders listed below the search depth to look for backups "
        f"(default: {backup.MAX_SCAN_FOLDERS}); more is a problem, so the run exits 1",
    )  # fmt: skip
    diff.add_argument(
        "--max-xml-elements", type=_count, default=xmlsafe.MAX_ELEMENTS, metavar="N",
        help="most XML elements held at once while reading one report "
        f"(default: {xmlsafe.MAX_ELEMENTS}); more is refused, so the run exits 3",
    )  # fmt: skip
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


_count = bounded(1, 1_000_000_000, "a whole number")


def _compare(args: argparse.Namespace) -> int:
    # Before anything is read or written: a report must never replace or enter an input.
    refuse_input_overwrite(
        [args.before, args.after],
        args.output,
        [outputs.FILE_NAMES[f] for f in args.format if f in outputs.FILE_NAMES]
        + [outputs.MANIFEST_NAME],
    )
    saved = registrypol.MAX_ENTRIES, backup.MAX_SCAN_FOLDERS, xmlsafe.MAX_ELEMENTS
    registrypol.MAX_ENTRIES = args.max_pol_entries
    backup.MAX_SCAN_FOLDERS = args.max_scan_folders
    xmlsafe.MAX_ELEMENTS = args.max_xml_elements
    try:
        comparison, after, inputs = pipeline.run(args.before, args.after, match=args.match)
    finally:
        registrypol.MAX_ENTRIES, backup.MAX_SCAN_FOLDERS, xmlsafe.MAX_ELEMENTS = saved

    document = outputs.build_report(
        comparison,
        [vars(item) for item in inputs],
        now(),
        __version__,
        {"match": args.match, "fail_on": args.fail_on},
        after=after,
    )
    written = outputs.write_reports(document, args.output, args.format, force=args.force)
    # The exit code is decided before anything is printed, so a summary that cannot be
    # printed (a closed pipe, a path the terminal cannot show) never changes it.
    failed = args.fail_on != "never" and (
        not comparison.complete or (args.fail_on == "differences" and comparison.differences)
    )
    say(render.terminal_summary(document))
    names = ", ".join(terminal_line(p.name) for p in written)
    say(f"Reports written to {terminal_line(str(args.output))}: {names}")
    return int(ExitCode.FINDINGS if failed else ExitCode.OK)


def _schema(args: argparse.Namespace) -> int:
    name = f"schema/{SCHEMAS[args.name]}.schema.json"
    say(files("faithful_mishpat").joinpath(name).read_text(encoding="utf-8"), end="")
    return int(ExitCode.OK)


def _example(args: argparse.Namespace) -> int:
    data = example.build()
    written = write_files(args.directory, data, force=args.force)
    before, after = (p for p in written if p.name in example.NAMES)
    command = command_line(
        "mishpat", "compare", str(before), str(after), "-o", str(args.directory / "report")
    )
    say(
        f"Wrote a synthetic before and after to {terminal_line(str(args.directory))}. Try:\n"
        f"  {terminal_line(command)}"
    )
    return int(ExitCode.OK)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return an exit code."""
    prepare()
    code = _run(argv)
    finish()
    return code


def _run(argv: Sequence[str] | None) -> int:
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
        say(f"mishpat: error: {terminal_line(redact(str(exc)))}", error=True)
        return int(ExitCode.USAGE if isinstance(exc, UsageError) else ExitCode.INPUT_ERROR)
    except Exception as exc:  # noqa: BLE001 - last-resort handler keeps crashes distinct
        shown = terminal_line(redact(str(exc)))[:200]
        say(
            f"mishpat: internal error: {type(exc).__name__}: {shown}\n"
            "This is a bug in mishpat. Please report it.",
            error=True,
        )
        return int(ExitCode.INTERNAL_ERROR)
