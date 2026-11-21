# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Build the versioned report document and write it, in every format, with a manifest.

Every renderer reads only the report dictionary built here, so all formats agree.
The dictionary is plain JSON: the same comparison and arguments always give the same
dictionary, and nothing in it depends on the clock or the environment.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime
from functools import partial
from typing import TYPE_CHECKING, Any

from faithful_mishpat.clock import date_and_time
from faithful_mishpat.differences import CATEGORIES, KINDS
from faithful_mishpat.errors import MishpatError
from faithful_mishpat.formats import hidden
from faithful_mishpat.model import SCOPES
from faithful_mishpat.outputs.files import write_files
from faithful_mishpat.outputs.render import (
    render_csv,
    render_html,
    render_markdown,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from faithful_mishpat.differences import Comparison
    from faithful_mishpat.model import Gpo, Snapshot, Source

SCHEMA_VERSION = "1.0"
SCHEMA_ID = "https://faithful-oversight.github.io/faithful-mishpat/schema/report-v1.schema.json"
MANIFEST_SCHEMA_VERSION = "1.0"
MANIFEST_SCHEMA_ID = (
    "https://faithful-oversight.github.io/faithful-mishpat/schema/manifest-v1.schema.json"
)
STATUSES = ("changed", "unchanged", "added", "removed", "only-before", "only-after")
"""The values of ``Pair.status``, in the order the report counts them."""
FILE_NAMES = {
    "json": "mishpat-report.json",
    "md": "mishpat-report.md",
    "html": "mishpat-report.html",
    "csv": "mishpat-differences.csv",
}
"""Output formats in the order they are written, with their file names."""
MANIFEST_NAME = "mishpat-manifest.json"
INPUT_KEYS = ("name", "kind", "size", "sha256")

LIMITATIONS = (
    (
        "mishpat compares what the inputs record. It cannot show the effective settings on a "
        "computer or for a user, which depend on every GPO that applies, their order, "
        "loopback processing, and the computer's site."
    ),
    (
        "Item-level targeting in Group Policy Preferences is compared as written. mishpat does "
        "not evaluate whether an item applies to a computer or user."
    ),
    (
        "WMI filters are compared by name and description, and by query text only when the "
        "input recorded it. mishpat does not evaluate a filter."
    ),
    (
        "Link order, blocked inheritance and WMI query text are compared only when the input "
        "came from the mishpat exporter. Get-GPOReport files and Backup-GPO folders do not "
        "record them."
    ),
    (
        "Security filtering and delegation are compared as the SIDs and rights on the GPO, "
        "a permission with no named right by its access mask, and the owner, the primary group "
        "and the raw descriptor text when the input records them. Group membership is not "
        "expanded, so the report does not say who is covered."
    ),
    (
        "Version numbers, modified times and policy explanation text are neither compared nor "
        "shown, so saving a GPO without changing a setting shows no difference."
    ),
    "A difference shows what changed. It does not say whether the change is correct or approved.",
)

Report = dict[str, Any]


def format_time(value: datetime) -> str:
    """Write a time as RFC 3339 in UTC with a trailing ``Z``.

    Fractional seconds appear only when they are not zero. A time without a zone is
    taken to be UTC, which is what ``SOURCE_DATE_EPOCH`` gives.
    """
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    text = date_and_time(value)
    if value.microsecond:
        text += f".{value.microsecond:06d}".rstrip("0")
    return text + "Z"


def _source(source: Source) -> dict[str, str]:
    return {"file": source.file, "detail": source.detail}


def _counts(names: Sequence[str], values: Sequence[str]) -> dict[str, int]:
    """Count ``values`` by name, in the order of ``names``, leaving out zero counts."""
    return {name: n for name in names if (n := values.count(name))}


def _context(gpo: Gpo) -> dict[str, Any]:
    """The GPO's context facts, as the report holds them."""
    wmi: Any
    if gpo.wmi_filter is None:
        wmi = "none"
    elif isinstance(gpo.wmi_filter, str):
        wmi = "unknown"
    else:
        wmi = {
            "name": gpo.wmi_filter.name,
            "description": gpo.wmi_filter.description,
            "identifier": gpo.wmi_filter.identifier,
            "query": gpo.wmi_filter.query,
        }
    filtering = None
    if gpo.trustees is not None:
        applying = sorted(
            (t for t in gpo.trustees if t.applies), key=lambda t: (t.name.casefold(), t.sid)
        )
        filtering = [{"sid": t.sid, "name": t.name} for t in applying]
    links = None
    if gpo.links is not None:
        ordered = sorted(
            gpo.links, key=lambda k: (k.order is None, k.order or 0, k.target.casefold())
        )
        links = [
            {"target": k.target, "enabled": k.enabled, "enforced": k.enforced, "order": k.order}
            for k in ordered
        ]
    return {
        "computer_enabled": gpo.computer_enabled,
        "user_enabled": gpo.user_enabled,
        "wmi_filter": wmi,
        "security_filtering": filtering,
        "links": links,
    }


def _note(note: str, before: Any, after: Any) -> str:
    if before is None or after is None or not hidden.password_changed(before, after):
        return note
    said = "A stored password changed; mishpat never shows stored passwords."
    return f"{note} {said}" if note else said


def _check(comparison: Comparison) -> None:
    """Refuse a comparison the schema could not describe: that is a bug in the comparison."""
    for d in comparison.differences:
        if d.category not in CATEGORIES or d.kind not in KINDS or d.scope not in ("", *SCOPES):
            msg = f"difference {d.subject!r} has an unknown category, kind or scope"
            raise ValueError(msg)
    for pair in comparison.pairs:
        if pair.status not in STATUSES:
            msg = f"GPO {pair.name!r} has unknown status {pair.status!r}"
            raise ValueError(msg)


def build_report(  # noqa: PLR0913 - the documented API
    comparison: Comparison,
    inputs: Sequence[Mapping[str, Any]],
    generated_at: datetime,
    tool_version: str,
    options: Mapping[str, str | int | bool | None] | None = None,
    *,
    after: Snapshot | None = None,
) -> Report:
    """Assemble the report document that follows the published schema.

    Args:
        comparison: What mishpat found.
        inputs: One mapping per input with ``name``, ``kind``, ``size`` and ``sha256``.
            Other keys are not copied.
        generated_at: When the report is made. Passed in so the report is repeatable.
        tool_version: mishpat's version.
        options: The options the run used, as scalars; copied in key order.
        after: The after side. With it, each GPO that has differences also carries
            its context (computer and user halves, WMI filter, security filtering and
            links as the after input records them). Without it ``context`` is null.

    Raises:
        ValueError: The comparison holds a category, kind, scope or status that the
            schema does not list.
    """
    _check(comparison)
    diffs = comparison.differences
    gpo_diffs = [d for d in diffs if d.gpo]
    gpos = []
    for pair in comparison.pairs:
        gpo = after.gpos.get(pair.guid) if after is not None and pair.differences else None
        gpos.append(
            {
                "guid": pair.guid,
                "before_guid": pair.before_guid,
                "name": pair.name,
                "status": pair.status,
                "differences": pair.differences,
                "context": None if gpo is None else _context(gpo),
            }
        )
    complete = comparison.complete
    return {
        "$schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "mishpat", "version": tool_version},
        "generated_at": format_time(generated_at),
        "inputs": [{key: item[key] for key in INPUT_KEYS} for item in inputs],
        "options": dict(sorted((options or {}).items())),
        "comparison": {
            "before": comparison.before,
            "after": comparison.after,
            "match": comparison.match,
            "complete": complete,
        },
        "summary": {
            "complete": complete,
            "differences": len(diffs),
            "gpos_compared": len(comparison.pairs),
            "gpos_changed": len({d.gpo for d in gpo_diffs}),
            "scope_differences": len(diffs) - len(gpo_diffs),
            "problems": len(comparison.problems),
            "gaps": len(comparison.gaps),
            "notices": len(comparison.notices),
            "by_category": _counts(CATEGORIES, [d.category for d in diffs]),
            "by_kind": _counts(KINDS, [d.kind for d in diffs]),
            "by_status": _counts(STATUSES, [p.status for p in comparison.pairs]),
        },
        "notices": list(comparison.notices),
        "gpos": gpos,
        "differences": [
            {
                "category": d.category,
                "kind": d.kind,
                "gpo": d.gpo,
                "gpo_name": d.gpo_name,
                "scope": d.scope,
                "area": d.area,
                "subject": d.subject,
                "before": hidden.conceal(copy.deepcopy(d.before)),
                "after": hidden.conceal(copy.deepcopy(d.after)),
                "note": _note(d.note, d.before, d.after),
                "labels": dict(d.labels),
                "sources": [_source(s) for s in d.sources],
            }
            for d in diffs
        ],
        "gaps": [{"subject": g.subject, "reason": g.reason, "gpo": g.gpo} for g in comparison.gaps],
        "problems": [
            {"file": p.source.file, "detail": p.source.detail, "reason": p.reason}
            for p in comparison.problems
        ],
        "limitations": list(LIMITATIONS),
    }


def render_json(report: Report) -> str:
    """Render the report as indented JSON in its documented key order."""
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        # A lone surrogate cannot be written as UTF-8; JSON escapes keep it exactly.
        text = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    return text


def _manifest(report: Report, outputs: Mapping[str, str]) -> str:
    files = []
    for name, text in outputs.items():
        data = text.encode("utf-8")
        files.append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "$schema": MANIFEST_SCHEMA_ID,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": report["tool"],
        "generated_at": report["generated_at"],
        "files": files,
        "inputs": [
            {"name": i["name"], "size": i["size"], "sha256": i["sha256"]} for i in report["inputs"]
        ],
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def write_reports(
    report: Report, directory: Path, formats: Sequence[str], *, force: bool
) -> list[Path]:
    """Write the chosen formats and a manifest, all together or not at all.

    The files are ``mishpat-report.json``, ``mishpat-report.md``,
    ``mishpat-report.html`` and ``mishpat-differences.csv``, always in that order
    whatever order ``formats`` gives. The manifest ``mishpat-manifest.json`` goes
    last and lists the size and SHA-256 of each file and of each input.

    Markdown and HTML shorten values over 300 characters, and cap long lists and
    tables, pointing to the JSON report, only when ``json`` is among ``formats``.
    Otherwise they hold every value and row whole.

    Raises:
        MishpatError: No format was chosen, a format is unknown, a file exists and
            ``force`` is false, or writing failed. Nothing is left half written.
    """
    unknown = sorted(set(formats) - FILE_NAMES.keys())
    if unknown:
        msg = f"unknown report format {unknown[0]!r}; choose from {', '.join(FILE_NAMES)}"
        raise MishpatError(msg)
    if not formats:
        msg = "no report format chosen"
        raise MishpatError(msg)
    # Markdown and HTML shorten a long value only to point at the JSON report, so they
    # do so only when that report is one of the files written.
    shorten = "json" in formats
    renderers: dict[str, Callable[[Report], str]] = {
        "json": render_json,
        "md": partial(render_markdown, shorten=shorten),
        "html": partial(render_html, shorten=shorten),
        "csv": render_csv,
    }
    outputs = {FILE_NAMES[f]: renderers[f](report) for f in FILE_NAMES if f in formats}
    outputs[MANIFEST_NAME] = _manifest(report, outputs)
    return write_files(directory, outputs, force=force)
