# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
r"""Render the report dictionary as Markdown, HTML, and CSV, and as a terminal summary.

Every renderer reads only the report dictionary, so all formats agree. Values from
the inputs are untrusted: Markdown is escaped so a value cannot forge a heading,
link, table, or HTML tag; the HTML page escapes everything, forbids scripts and
network access, and never puts a value in a URL; CSV cells are protected against
formula injection. Long values and long lists are shortened in Markdown and HTML,
with a visible marker, when the JSON report is written beside them, and kept whole
otherwise. CSV and JSON always keep full values.

The CSV is UTF-8 without a byte order mark and uses ``\r\n`` line ends. A
spreadsheet that guesses the encoding wrongly can be told it is UTF-8 when importing.
"""

from __future__ import annotations

import csv
import html
import io
import json
import sys
from typing import TYPE_CHECKING, Any

from faithful_mishpat.differences import CATEGORIES
from faithful_mishpat.model import SCOPES
from faithful_mishpat.outputs.safety import csv_cell, escape_markdown, terminal, visible

if TYPE_CHECKING:
    from collections.abc import Iterable

    from faithful_mishpat.outputs import Report

TITLE = "GPO change review"
MAX_VALUE = 300
"""Longest value shown in full in Markdown and HTML, in characters."""
MAX_LISTED = 25
"""How many notices, gaps, problems, links or trustees Markdown and HTML list."""
MAX_ROWS = 100
"""How many rows of the table of GPOs Markdown and HTML show."""
MAX_GPOS = 100
"""How many GPO sections Markdown and HTML write."""
MAX_DIFFERENCES = 200
"""How many differences Markdown and HTML show for one GPO."""
CSV_COLUMNS = (
    "category", "kind", "gpo_guid", "gpo_name", "scope", "area", "subject", "before", "after",
    "note", "before_source", "after_source", "comparison_complete",
)  # fmt: skip
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"
"""Content security policy: no scripts, no network access, no form submission."""

CATEGORY_TITLES = {
    "gpo": "GPO",
    "status": "Status",
    "wmi-filter": "WMI filter",
    "security-filtering": "Security filtering",
    "permissions": "Permissions (delegation)",
    "link": "Links",
    "inheritance": "Inheritance",
    "setting": "Settings",
}
"""Headings for the categories; the keys are exactly ``CATEGORIES``."""
WORDS = {
    "added": "added",
    "removed": "removed",
    "changed": "changed",
    "renamed": "renamed",
    "unchanged": "unchanged",
    "only-before": "only in before",
    "only-after": "only in after",
}
"""Plain words for difference kinds and GPO statuses."""
_STATE_WORDS = {"complete": "Complete", "incomplete": "Incomplete"}
_HEAD = ("Subject", "Kind", "Before", "After")
_GPO_HEAD = ("Name", "GUID", "Status", "Differences")
_SIDES = (("Before", "before"), ("After", "after"))


# Words ------------------------------------------------------------------------------


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


def headline(report: Report) -> tuple[str, str]:
    """Say what the comparison found and whether it is complete, in plain words.

    The state is ``complete`` when every input was read in full and ``incomplete``
    otherwise. The text is two sentences with their full stops: the count, then the
    completeness. "No differences" is never said without the completeness beside it.
    """
    s = report["summary"]
    n, gpos = s["differences"], s["gpos_changed"]
    alone = s["by_kind"].get("only-before", 0) + s["by_kind"].get("only-after", 0)
    if alone:
        lead, finish = _lead(n, gpos, s), f" ({_plural(alone, 'GPO')} in only one input)"
    else:
        lead, finish = _lead(n, gpos, s), ""
    if s["complete"]:
        return "complete", f"{lead}{finish}. Every input was read in full."
    problems = _plural(s["problems"], "problem")
    return "incomplete", (
        f"{lead}{finish}. Incomplete: {problems} with an input, so differences may be missing."
    )


def _lead(n: int, gpos: int, s: dict[str, Any]) -> str:
    if not n:
        return "No differences"
    if not gpos:
        return f"{_plural(n, 'difference')} in the domain's structure"
    if s["scope_differences"]:
        return (
            f"{_plural(n, 'difference')} across {_plural(gpos, 'GPO')} and the domain's structure"
        )
    return f"{_plural(n, 'difference')} across {_plural(gpos, 'GPO')}"


def value_text(value: Any) -> str:
    """Write a value so a person can read it: scalars inline, lists comma-joined.

    ``None`` is "(not set)". A dictionary is ``key: value`` pairs joined by ``;``.
    Lists and dictionaries inside other values are bracketed so they stay apart.
    """
    if value is None:
        return "(not set)"
    if isinstance(value, list):
        return ", ".join(_nested(item) for item in value) if value else "(empty list)"
    if isinstance(value, dict):
        return (
            "; ".join(f"{k}: {_nested(v)}" for k, v in value.items()) if value else "(no entries)"
        )
    return _scalar(value)


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value == "":
        return "(empty)"
    text = str(value)
    # Text that is only spaces would look empty, and edge spaces would vanish.
    return f'"{text}"' if isinstance(value, str) and text != text.strip() else text


_TYPE_WORDS = ((bool, "true or false"), (int, "number"), (str, "text"))


def _type_word(value: Any) -> str:
    return next(word for kind, word in _TYPE_WORDS if isinstance(value, kind))


def _disambiguate(before: Any, after: Any) -> tuple[Any, Any]:
    """Name the type on each side when only the type differs, so it never looks unchanged.

    ``"5"`` (text) and ``5`` (a number) read the same on a page, but a consumer of a registry
    value treats them differently. Where the two sides write the same and are not the same
    kind of value, both are shown with the kind: ``"5" (text)`` and ``5 (number)``.
    """
    if isinstance(before, dict) and isinstance(after, dict):
        shown_before, shown_after = dict(before), dict(after)
        for key in before.keys() & after.keys():
            shown_before[key], shown_after[key] = _disambiguate(before[key], after[key])
        return shown_before, shown_after
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        pairs = [_disambiguate(b, a) for b, a in zip(before, after, strict=True)]
        return [b for b, _ in pairs], [a for _, a in pairs]
    scalars = not isinstance(before, (dict, list)) and not isinstance(after, (dict, list))
    if (
        scalars
        and before is not None
        and after is not None
        and type(before) is not type(after)
        and _plain(before) == _plain(after)
    ):
        return (
            f"{_quoted(before)} ({_type_word(before)})",
            f"{_quoted(after)} ({_type_word(after)})",
        )
    return before, after


def _plain(value: Any) -> str:
    return ("true" if value else "false") if isinstance(value, bool) else str(value)


def _quoted(value: Any) -> str:
    return f'"{value}"' if isinstance(value, str) else _scalar(value)


def _sides(difference: dict[str, Any]) -> tuple[Any, Any]:
    """The before and after values as a reader should see them.

    When both are mappings, only the keys that differ are shown, so one changed
    option of a policy does not hide among the rest. Values with recorded words,
    such as a SID with its account name, are shown with the words beside them.
    """
    before, after = difference["before"], difference["after"]
    if isinstance(before, dict) and isinstance(after, dict):
        keys = [k for k in dict.fromkeys([*before, *after]) if before.get(k) != after.get(k)]
        if keys and len(keys) < len(before.keys() | after.keys()):
            before = {k: before.get(k) for k in keys}
            after = {k: after.get(k) for k in keys}
    labels = dict(difference.get("labels") or {})
    before, after = _labelled(before, labels), _labelled(after, labels)
    return _disambiguate(before, after)


def _labelled(value: Any, labels: dict[str, str]) -> Any:
    if not labels or value is None:
        return value
    if isinstance(value, list):
        return [_labelled(item, labels) for item in value]
    if isinstance(value, dict):
        return value
    words = labels.get(_scalar(value) if isinstance(value, bool) else str(value))
    return f"{_scalar(value)} ({words})" if words else value


def _nested(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_nested(item) for item in value) + "]"
    if isinstance(value, dict):
        return "(" + ", ".join(f"{k}: {_nested(v)}" for k, v in value.items()) + ")"
    return "(not set)" if value is None else _scalar(value)


def _shorten(value: str, *, shorten: bool = True) -> str:
    """Cut a long value, saying how long it is. The JSON report keeps it whole.

    With ``shorten`` false the value is returned whole: the report format that is being
    written is then the only place the value is, so it must not point elsewhere.
    """
    if not shorten or len(value) <= MAX_VALUE:
        return value
    return f"{value[:MAX_VALUE]}… ({len(value)} characters; full value in the JSON report)"


def _shown(value: Any, *, shorten: bool) -> str:
    return _shorten(value_text(value), shorten=shorten)


def _limit(cap: int, shorten: bool) -> int:  # noqa: FBT001 - mirrors the keyword it is given
    """How many rows to show: the cap when the JSON report holds the rest, else all."""
    return cap if shorten else sys.maxsize


def _more(total: int, shown: int, what: str = "") -> str:
    return f"{total - shown} more{what} in the JSON report."


def _sources(d: dict[str, Any]) -> tuple[str, str]:
    """The source on each side, as ``(before, after)`` text.

    A difference lists its sources before first. When only one is listed, it is the
    side that holds the item: the before side for a removal, the after side otherwise.
    Sources beyond the second go after the after source.
    """
    texts = [f"{s['file']} {s['detail']}".strip() for s in d["sources"]]
    if len(texts) == 1:
        return (texts[0], "") if d["kind"] in {"removed", "only-before"} else ("", texts[0])
    if not texts:
        return "", ""
    return texts[0], "; ".join(texts[1:])


def _sources_line(d: dict[str, Any]) -> str:
    before, after = _sources(d)
    sides = (("before", before), ("after", after))
    return "; ".join(f"{label}: {text}" for label, text in sides if text)


def _scope_rank(scope: str) -> int:
    return SCOPES.index(scope) if scope in SCOPES else len(SCOPES)


def _groups(diffs: list[dict[str, Any]]) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Group differences as ``(category, sub-heading, differences)`` in reading order.

    Categories follow ``CATEGORIES``. Settings split by scope (Computer, User, then
    none) and area. Inside a group the comparison's own order is kept.
    """
    groups: list[tuple[str, str, list[dict[str, Any]]]] = []
    for category in CATEGORIES:
        members = [d for d in diffs if d["category"] == category]
        if category != "setting":
            if members:
                groups.append((category, "", members))
            continue
        keys = sorted(
            {(d["scope"], d["area"]) for d in members},
            key=lambda k: (_scope_rank(k[0]), k[1].casefold(), k[1]),
        )
        groups += [
            (
                category,
                f"{scope or 'No scope'} · {area or 'No area'}",
                [d for d in members if (d["scope"], d["area"]) == (scope, area)],
            )
            for scope, area in keys
        ]
    return groups


def _budget(
    groups: list[tuple[str, str, list[dict[str, Any]]]], limit: int
) -> tuple[list[tuple[str, str, list[dict[str, Any]]]], int]:
    """Keep groups, and the start of the last one, until ``limit`` differences are used.

    Returns the groups to show and how many differences were left out.
    """
    shown: list[tuple[str, str, list[dict[str, Any]]]] = []
    left = limit
    omitted = 0
    for category, sub, members in groups:
        keep = members[: max(left, 0)]
        left -= len(keep)
        omitted += len(members) - len(keep)
        if keep:
            shown.append((category, sub, keep))
    return shown, omitted


def _by_gpo(report: Report) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split the GPOs that have differences, in report order, and the scope-level ones.

    A difference for a GPO that the table does not list still gets a section, after
    the listed ones, so no difference is dropped.
    """
    scope_level = [d for d in report["differences"] if not d["gpo"]]
    listed = {g["guid"] for g in report["gpos"]}
    # One pass over the differences, so the cost grows with their number and not with
    # the number of GPOs times the number of differences.
    groups: dict[str, list[dict[str, Any]]] = {}
    for d in report["differences"]:
        if d["gpo"]:
            groups.setdefault(d["gpo"], []).append(d)
    sections: list[dict[str, Any]] = [
        {**gpo, "list": groups[gpo["guid"]]} for gpo in report["gpos"] if gpo["guid"] in groups
    ]
    sections.extend(
        {
            "guid": guid,
            "before_guid": "",
            "name": mine[0]["gpo_name"],
            "status": "changed",
            "differences": len(mine),
            "context": None,
            "list": mine,
        }
        for guid, mine in groups.items()
        if guid not in listed
    )
    return sections, scope_level


def _ranked_gpos(report: Report) -> list[dict[str, Any]]:
    """GPOs with differences first, each half in name order, so a cap hides quiet ones."""
    return sorted(report["gpos"], key=lambda g: not g["differences"])


def _gpo_guid(g: dict[str, Any]) -> str:
    return f"{g['guid']} (before: {g['before_guid']})" if g["before_guid"] else g["guid"]


def _status_line(g: dict[str, Any]) -> str:
    return f"{WORDS[g['status']].capitalize()}. {_plural(len(g['list']), 'difference')}."


def _names(report: Report) -> dict[str, str]:
    return {g["guid"]: g["name"] for g in report["gpos"]}


def _gap_words(g: dict[str, Any], names: dict[str, str]) -> str:
    who = f" ({names.get(g['gpo'], g['gpo'])})" if g["gpo"] else ""
    return f"{g['subject']}{who}: {g['reason']}"


def _problem_words(p: dict[str, Any]) -> str:
    where = f"{p['file']} {p['detail']}".strip()
    return f"{where}: {p['reason']}"


def _state(enabled: object) -> str:
    return "not recorded" if enabled is None else ("enabled" if enabled else "disabled")


def _link_words(k: dict[str, Any]) -> str:
    flags = "enabled" if k["enabled"] else "disabled"
    flags += ", enforced" if k["enforced"] else ""
    flags += f", order {k['order']}" if k["order"] is not None else ""
    return f"{k['target']} ({flags})"


def _capped(items: list[str], sep: str, *, shorten: bool) -> str:
    shown = items[: _limit(MAX_LISTED, shorten)]
    extra = len(items) - len(shown)
    return sep.join(shown) + (f"{sep}and {extra} more in the JSON report" if extra else "")


def _wmi_words(wmi: Any) -> str:
    if wmi == "none":
        return "none"
    if wmi == "unknown":
        return "not recorded"
    text = str(wmi["name"])
    text += f" ({wmi['description']})" if wmi["description"] else ""
    text += f", id {wmi['identifier']}" if wmi["identifier"] else ""
    return text + (
        f", query: {wmi['query']}" if wmi["query"] is not None else ", query not recorded"
    )


def _context_lines(context: dict[str, Any] | None, *, shorten: bool) -> list[tuple[str, str]]:
    """The GPO's context, as ``(label, text)`` lines, as of the after side."""
    if context is None:
        return []
    lines = [
        (
            "Status",
            (
                f"computer half {_state(context['computer_enabled'])}; "
                f"user half {_state(context['user_enabled'])}"
            ),
        ),
        ("WMI filter", _shorten(_wmi_words(context["wmi_filter"]), shorten=shorten)),
    ]
    filtering = context["security_filtering"]
    if filtering is None:
        text = "not recorded"
    elif not filtering:
        text = "none (no entry allows Apply Group Policy)"
    else:
        text = _capped([f"{t['name']} ({t['sid']})" for t in filtering], ", ", shorten=shorten)
    lines.append(("Security filtering", text))
    links = context["links"]
    if links is None:
        text = "not recorded"
    elif not links:
        text = "none"
    else:
        text = _capped([_link_words(k) for k in links], "; ", shorten=shorten)
    lines.append(("Links", text))
    return lines


# Markdown ---------------------------------------------------------------------------


def _md(value: object) -> str:
    return escape_markdown(str(value))


def _md_table(head: tuple[str, ...], rows: Iterable[Iterable[object]]) -> list[str]:
    lines = ["| " + " | ".join(head) + " |", "|" + " --- |" * len(head)]
    lines += ["| " + " | ".join(_md(cell) for cell in row) + " |" for row in rows]
    return lines


def _md_differences(diffs: list[dict[str, Any]], *, shorten: bool, level: int) -> list[str]:
    """Differences grouped by category; ``level`` is the heading depth of a category."""
    shown, omitted = _budget(_groups(diffs), _limit(MAX_DIFFERENCES, shorten))
    lines: list[str] = []
    last = ""
    for category, sub, members in shown:
        if category != last:
            lines += [f"{'#' * level} {_md(CATEGORY_TITLES[category])}", ""]
            last = category
        if sub:
            lines += [f"{'#' * (level + 1)} {_md(sub)}", ""]
        with_note = any(d["note"] for d in members)
        head = (*_HEAD, *(("Note",) if with_note else ()), "Sources")
        rows = [
            (
                d["subject"],
                WORDS[d["kind"]],
                _shown(_sides(d)[0], shorten=shorten),
                _shown(_sides(d)[1], shorten=shorten),
                *((_shorten(d["note"], shorten=shorten),) if with_note else ()),
                _sources_line(d),
            )
            for d in members
        ]
        lines += [*_md_table(head, rows), ""]
    if omitted:
        lines += [_md(_more(omitted + _count(shown), _count(shown), " differences")), ""]
    return lines


def _count(shown: list[tuple[str, str, list[dict[str, Any]]]]) -> int:
    """How many differences a list of groups holds."""
    return sum(len(members) for _, _, members in shown)


def _md_list(title: str, intro: str, items: list[str], *, shorten: bool) -> list[str]:
    shown = items[: _limit(MAX_LISTED, shorten)]
    lines = [f"## {title}", "", *([intro, ""] if intro else [])]
    lines += [f"- {_md(_shorten(item, shorten=shorten))}" for item in shown]
    if len(items) > len(shown):
        lines.append(f"- {_md(_more(len(items), len(shown)))}")
    return [*lines, ""]


def render_markdown(report: Report, *, shorten: bool = True) -> str:
    """Render Markdown to read top to bottom or paste into a pull request or change ticket.

    Args:
        report: The report dictionary.
        shorten: Cut values over :data:`MAX_VALUE` characters and cap long lists, and
            point to the JSON report. Pass false when the JSON report is not written,
            so nothing is cut.
    """
    _, text = headline(report)
    comparison = report["comparison"]
    lines = [
        f"# {TITLE}",
        "",
        f"**{_md(text)}**",
        "",
        (
            f"Before: {_md(comparison['before'])}. After: {_md(comparison['after'])}. "
            f"GPOs paired by {_md(comparison['match'])}. "
            f"Generated {_md(report['generated_at'])} by mishpat "
            f"{_md(report['tool']['version'])}."
        ),
        "",
    ]
    if report["notices"]:
        lines += _md_list("Notices", "", report["notices"], shorten=shorten)
    lines += ["## GPOs compared", ""]
    ranked = _ranked_gpos(report)
    shown = ranked[: _limit(MAX_ROWS, shorten)]
    if shown:
        rows = [(g["name"], _gpo_guid(g), WORDS[g["status"]], g["differences"]) for g in shown]
        lines += _md_table(_GPO_HEAD, rows)
        if len(ranked) > len(shown):
            lines += ["", _md(_more(len(ranked), len(shown), " GPOs"))]
    else:
        lines.append("No GPOs were compared.")
    lines.append("")
    sections, scope_level = _by_gpo(report)
    lines += ["## Changes by GPO", ""]
    if not sections:
        lines += ["No GPO has a difference.", ""]
    for g in sections[: _limit(MAX_GPOS, shorten)]:
        lines += [f"### {_md(g['name'])} ({_md(g['guid'])})", ""]
        lines += [
            f"{_md(WORDS[g['status']].capitalize())}. {_plural(len(g['list']), 'difference')}.",
            "",
        ]
        context = _context_lines(g["context"], shorten=shorten)
        lines += [f"- **{label}:** {_md(value)}" for label, value in context]
        lines += [""] if context else []
        lines += _md_differences(g["list"], shorten=shorten, level=4)
    if len(sections) > _limit(MAX_GPOS, shorten):
        lines += [_md(_more(len(sections), _limit(MAX_GPOS, shorten), " GPOs")), ""]
    if scope_level:
        lines += ["## Domain structure", ""]
        lines += _md_differences(scope_level, shorten=shorten, level=3)
    names = _names(report)
    if report["gaps"]:
        items = [_gap_words(g, names) for g in report["gaps"]]
        intro = "These were not compared. They are limits of the inputs, not differences."
        lines += _md_list("Not compared", intro, items, shorten=shorten)
    if report["problems"]:
        items = [_problem_words(p) for p in report["problems"]]
        intro = "These could not be read, so differences they hold are not in this report."
        lines += _md_list("Problems", intro, items, shorten=shorten)
    lines += ["## Inputs", ""]
    lines += _md_table(
        ("File", "Kind", "Bytes", "SHA-256"),
        [(i["name"], i["kind"], i["size"], i["sha256"]) for i in report["inputs"]],
    )
    lines += ["", "## Limitations", ""]
    lines += [f"- {_md(item)}" for item in report["limitations"]]
    return "\n".join(lines) + "\n"


# CSV --------------------------------------------------------------------------------


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_csv(report: Report) -> str:
    """Render one row per difference.

    Values are complete, never shortened. A value that is not a scalar is compact JSON;
    a value that is not set is an empty cell. Every cell is protected against formula
    injection. The last column, ``comparison_complete``, is ``true`` or ``false`` on every
    row, so the caveat travels with the differences when this is the only file kept.
    """
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    complete = _csv_value(report["summary"]["complete"])
    for d in report["differences"]:
        before_source, after_source = _sources(d)
        row = (
            d["category"], d["kind"], d["gpo"], d["gpo_name"], d["scope"], d["area"],
            d["subject"], *map(_csv_value, _disambiguate(d["before"], d["after"])), d["note"],
            before_source, after_source, complete,
        )  # fmt: skip
        writer.writerow([csv_cell(cell) for cell in row])
    return buffer.getvalue()


# Terminal ---------------------------------------------------------------------------


def terminal_summary(report: Report) -> str:
    """A few plain lines for the terminal: the version, the headline, and the counts."""
    state, text = headline(report)
    s = report["summary"]
    lines = [f"mishpat {report['tool']['version']}", text]
    lines += [f"  {CATEGORY_TITLES[c]}: {n}" for c, n in s["by_category"].items()]
    if s["notices"]:
        lines.append(f"  {_plural(s['notices'], 'notice')}: read them first.")
    if state != "complete":
        lines.append("  See Problems in the report before relying on this result.")
    return "\n".join(terminal(line) for line in lines)


# HTML -------------------------------------------------------------------------------

_CSS = """
:root{--fg:#1f2328;--muted:#4d5661;--bg:#fff;--panel:#f6f8fa;--line:#d1d9e0;
--ok:#116329;--warn:#7d4e00;--accent:#0550ae;--mark:#fff8c5;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--fg:#e6edf3;--muted:#9da7b3;--bg:#0d1117;
--panel:#151b23;--line:#3d444d;--ok:#56d364;--warn:#e3b341;--accent:#79c0ff;--mark:#3b2e00}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:78rem;margin:0 auto;padding:1rem 1.25rem 4rem}
h1{font-size:1.6rem;margin:1.25rem 0 .25rem}
h2{font-size:1.25rem;margin:2.25rem 0 .6rem;padding-bottom:.25rem;
border-bottom:1px solid var(--line)}
h3{font-size:1.1rem;margin:1.75rem 0 .4rem}
h4{font-size:1rem;margin:1.1rem 0 .3rem}
h5{font-size:.95rem;margin:.9rem 0 .3rem;color:var(--muted)}
a{color:var(--accent)}
.skip{position:absolute;left:-999px;top:0;background:var(--bg);padding:.5rem 1rem;z-index:10}
.skip:focus{left:.5rem;top:.5rem}
nav.top{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line);
padding:.5rem 1.25rem;display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;font-size:.9rem}
.muted{color:var(--muted)}
.small{font-size:.85rem}
.state{border:2px solid currentColor;border-radius:8px;padding:.75rem 1rem;margin:1rem 0;
background:var(--panel);font-weight:600}
.state.complete{color:var(--ok)}.state.incomplete{color:var(--warn)}
.state .word{text-transform:uppercase;letter-spacing:.04em;margin-right:.5rem}
.state span.t{color:var(--fg)}
.tablewrap{overflow-x:auto;margin:.5rem 0 1rem}
table{border-collapse:collapse;width:100%;font-size:.88rem}
caption{position:absolute;left:-999px}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top;
overflow-wrap:anywhere}
thead th{background:var(--panel)}
tbody th{font-weight:600;background:var(--bg)}
.list{padding-left:1.2rem}
.list li{margin:.35rem 0}
.val{white-space:pre-wrap;overflow-wrap:anywhere}
.chg{background:var(--mark);padding:0 .2rem;border-radius:3px}
code,.mono{font:.88em ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
overflow-wrap:anywhere}
.ctx{margin:.3rem 0 .8rem}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
footer{margin-top:3rem}
@media print{nav.top,.skip{display:none}main{max-width:none;padding:0}
a{color:inherit;text-decoration:none}}
"""


def _h(value: object) -> str:
    return html.escape(visible(str(value)), quote=True)


def _hv(value: Any, *, shorten: bool) -> str:
    return f'<span class="val">{_h(_shown(value, shorten=shorten))}</span>'


def _table(caption: str, head: tuple[str, ...], rows: Iterable[Iterable[str]]) -> str:
    """A table whose cells are already escaped HTML; the first cell of a row is its header."""
    heads = "".join(f'<th scope="col">{h}</th>' for h in head)
    body = []
    for row in rows:
        first, *rest = list(row)
        cells = "".join(f"<td>{cell}</td>" for cell in rest)
        body.append(f'<tr><th scope="row">{first}</th>{cells}</tr>')
    return (
        f'<div class="tablewrap"><table><caption>{_h(caption)}</caption>'
        f"<thead><tr>{heads}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _h_list(title: str, anchor: str, intro: str, items: list[str], *, shorten: bool) -> str:
    shown = items[: _limit(MAX_LISTED, shorten)]
    body = "".join(f"<li>{_h(_shorten(item, shorten=shorten))}</li>" for item in shown)
    if len(items) > len(shown):
        body += f"<li>{_h(_more(len(items), len(shown)))}</li>"
    lead = f"<p>{_h(intro)}</p>" if intro else ""
    return f'<h2 id="{anchor}">{_h(title)}</h2>{lead}<ul class="list">{body}</ul>'


def _h_differences(diffs: list[dict[str, Any]], *, shorten: bool, level: int) -> str:
    shown, omitted = _budget(_groups(diffs), _limit(MAX_DIFFERENCES, shorten))
    parts: list[str] = []
    last = ""
    for category, sub, members in shown:
        if category != last:
            parts.append(f"<h{level}>{_h(CATEGORY_TITLES[category])}</h{level}>")
            last = category
        if sub:
            parts.append(f"<h{level + 1}>{_h(sub)}</h{level + 1}>")
        with_note = any(d["note"] for d in members)
        head = (*_HEAD, *(("Note",) if with_note else ()), "Sources")
        rows = [
            (
                _h(d["subject"]),
                _h(WORDS[d["kind"]]),
                _hv(_sides(d)[0], shorten=shorten),
                f'<span class="chg">{_hv(_sides(d)[1], shorten=shorten)}</span>',
                *((_h(_shorten(d["note"], shorten=shorten)),) if with_note else ()),
                _h(_sources_line(d)),
            )
            for d in members
        ]
        parts.append(_table(sub or CATEGORY_TITLES[category], head, rows))
    if omitted:
        parts.append(f"<p>{_h(_more(omitted + _count(shown), _count(shown), ' differences'))}</p>")
    return "".join(parts)


def _h_gpo_table(report: Report, anchors: dict[str, str], *, shorten: bool) -> str:
    ranked = _ranked_gpos(report)
    shown = ranked[: _limit(MAX_ROWS, shorten)]
    if not shown:
        return "<p>No GPOs were compared.</p>"
    rows = []
    for g in shown:
        name = _h(g["name"])
        if g["guid"] in anchors:
            name = f'<a href="#{anchors[g["guid"]]}">{name}</a>'
        rows.append(
            (name, f"<code>{_h(_gpo_guid(g))}</code>", _h(WORDS[g["status"]]), _h(g["differences"]))
        )
    out = _table("GPOs compared", _GPO_HEAD, rows)
    if len(ranked) > len(shown):
        out += f"<p>{_h(_more(len(ranked), len(shown), ' GPOs'))}</p>"
    return out


def render_html(report: Report, *, shorten: bool = True) -> str:
    """Render one self-contained page: no scripts, no external requests, no URLs from data.

    Args:
        report: The report dictionary.
        shorten: Cut values over :data:`MAX_VALUE` characters and cap long lists, and
            point to the JSON report. Pass false when the JSON report is not written,
            so nothing is cut.
    """
    state, text = headline(report)
    icon = "✔" if state == "complete" else "⚠"
    comparison = report["comparison"]
    sections, scope_level = _by_gpo(report)
    shown_sections = sections[: _limit(MAX_GPOS, shorten)]
    anchors = {g["guid"]: f"g{i}" for i, g in enumerate(shown_sections, start=1)}
    changes = []
    for g in shown_sections:
        anchor = anchors[g["guid"]]
        context = "".join(
            f"<li><b>{_h(label)}:</b> {_h(value)}</li>"
            for label, value in _context_lines(g["context"], shorten=shorten)
        )
        changes.append(
            f'<section aria-labelledby="{anchor}"><h3 id="{anchor}">{_h(g["name"])} '
            f'<span class="muted small">{_h(g["guid"])}</span></h3>'
            f"<p>{_h(_status_line(g))}</p>"
            + (f'<ul class="list ctx">{context}</ul>' if context else "")
            + _h_differences(g["list"], shorten=shorten, level=4)
            + "</section>"
        )
    if not sections:
        changes.append("<p>No GPO has a difference.</p>")
    if len(sections) > len(shown_sections):
        more = _more(len(sections), len(shown_sections), " GPOs")
        changes.append(f"<p>{_h(more)}</p>")
    scope = ""
    if scope_level:
        scope = '<h2 id="scope">Domain structure</h2>' + _h_differences(
            scope_level, shorten=shorten, level=3
        )
    names = _names(report)
    notices = (
        _h_list("Notices", "notices", "", report["notices"], shorten=shorten)
        if report["notices"]
        else ""
    )
    gaps = (
        _h_list(
            "Not compared",
            "gaps",
            "These were not compared. They are limits of the inputs, not differences.",
            [_gap_words(g, names) for g in report["gaps"]],
            shorten=shorten,
        )
        if report["gaps"]
        else ""
    )
    problems = (
        _h_list(
            "Problems",
            "problems",
            "These could not be read, so differences they hold are not in this report.",
            [_problem_words(p) for p in report["problems"]],
            shorten=shorten,
        )
        if report["problems"]
        else ""
    )
    inputs = _table(
        "Inputs",
        ("File", "Kind", "Bytes", "SHA-256"),
        [
            (_h(i["name"]), _h(i["kind"]), _h(i["size"]), f"<code>{_h(i['sha256'])}</code>")
            for i in report["inputs"]
        ],
    )
    limits = "".join(f"<li>{_h(item)}</li>" for item in report["limitations"])
    nav = (
        ('<a href="#notices">Notices</a>' if notices else "")
        + '<a href="#gpos">GPOs compared</a><a href="#changes">Changes by GPO</a>'
        + ('<a href="#scope">Domain structure</a>' if scope else "")
        + ('<a href="#gaps">Not compared</a>' if gaps else "")
        + ('<a href="#problems">Problems</a>' if problems else "")
        + '<a href="#inputs">Inputs</a><a href="#limitations">Limitations</a>'
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TITLE}</title>
<style>{_CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to the report</a>
<nav class="top" aria-label="Sections">{nav}</nav>
<main id="main">
<header>
<h1>{TITLE}</h1>
<p class="state {state}" role="status"><span class="word">{icon} {_STATE_WORDS[state]}</span>\
<span class="t">{_h(text)}</span></p>
<p class="muted">Before: {_h(comparison["before"])}. After: {_h(comparison["after"])}. \
GPOs paired by {_h(comparison["match"])}. Generated {_h(report["generated_at"])} by mishpat \
{_h(report["tool"]["version"])}.</p>
</header>
{notices}
<h2 id="gpos">GPOs compared</h2>
{_h_gpo_table(report, anchors, shorten=shorten)}
<h2 id="changes">Changes by GPO</h2>
{"".join(changes)}
{scope}
{gaps}
{problems}
<h2 id="inputs">Inputs</h2>
{inputs}
<h2 id="limitations">Limitations</h2>
<ul class="list">{limits}</ul>
</main>
</body>
</html>
"""
