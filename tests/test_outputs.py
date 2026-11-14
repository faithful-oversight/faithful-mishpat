# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The report document and its Markdown, HTML, CSV, and terminal renderings."""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from html.parser import HTMLParser
from importlib.resources import files
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import validator_for

from faithful_mishpat.differences import CATEGORIES, KINDS, Comparison, Difference, Gap, Pair
from faithful_mishpat.errors import MishpatError
from faithful_mishpat.model import Gpo, Link, Problem, Snapshot, Source, Trustee, WmiFilter
from faithful_mishpat.outputs import (
    FILE_NAMES,
    LIMITATIONS,
    MANIFEST_NAME,
    STATUSES,
    build_report,
    format_time,
    render_json,
    write_reports,
)
from faithful_mishpat.outputs import render as r

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

GENERATED = datetime(2026, 11, 5, 9, 30, tzinfo=UTC)
SHA = "a" * 64
INPUTS = [
    {"name": "before.xml", "kind": "report", "size": 4096, "sha256": SHA, "ignored": "x"},
    {"name": "after.jsonl", "kind": "export", "size": 8192, "sha256": "b" * 64},
]
OPTIONS: dict[str, str | int | bool | None] = {
    "match": "guid",
    "fail_on": "differences",
    "verbose": False,
}
G_SERVERS = "11111111-1111-1111-1111-111111111111"
G_NEW = "22222222-2222-2222-2222-222222222222"
G_OLD = "33333333-3333-3333-3333-333333333333"
G_QUIET = "44444444-4444-4444-4444-444444444444"
G_ONLY_B = "55555555-5555-5555-5555-555555555555"
G_ONLY_A = "66666666-6666-6666-6666-666666666666"
G_RENAMED_B = "77777777-7777-7777-7777-777777777777"
G_RENAMED_A = "88888888-8888-8888-8888-888888888888"
G_UNLISTED = "99999999-9999-9999-9999-999999999999"
SID_ADMINS = "S-1-5-21-1000000000-2000000000-3000000000-512"
SID_STAFF = "S-1-5-21-1000000000-2000000000-3000000000-1104"
RLO = chr(0x202E)
FULL_EQUALS = chr(0xFF1D)
FULL_PLUS = chr(0xFF0B)
FORMULA = '=HYPERLINK("http://203.0.113.9","x")'
PAYLOAD = (
    "\x1b[31m<script>alert(1)</script>" + RLO + "\n# forged [click](http://203.0.113.9) `tick` | x"
)


def schema_check(name: str, document: Any) -> None:
    text = files("faithful_mishpat").joinpath("schema", name).read_text(encoding="utf-8")
    definition = json.loads(text)
    validator = validator_for(definition)
    validator.check_schema(definition)
    validator(definition, format_checker=FormatChecker()).validate(document)


def src(file: str = "before.xml", detail: str = "Computer/Registry/Policy[0]") -> Source:
    return Source(file, detail)


def diff(**kw: Any) -> Difference:
    base: dict[str, Any] = {
        "category": "setting",
        "kind": "changed",
        "gpo": G_SERVERS,
        "gpo_name": "Servers Baseline",
        "subject": "Minimum password length",
        "before": 8,
        "after": 14,
        "scope": "Computer",
        "area": "Security",
        "sources": (src(), src("after.jsonl", "line 4")),
    }
    return Difference(**{**base, **kw})


def pair(guid: str, name: str, status: str, n: int, before_guid: str = "") -> Pair:
    return Pair(guid=guid, name=name, status=status, differences=n, before_guid=before_guid)


def rich_differences() -> list[Difference]:
    """At least one difference of every category and kind, and of every value shape."""
    return [
        diff(
            category="gpo",
            kind="renamed",
            gpo=G_RENAMED_A,
            gpo_name="Workstations 2026",
            subject="name",
            before="Workstations 2025",
            after="Workstations 2026",
            scope="",
            area="",
            note="Paired by name; the GUIDs differ.",
        ),
        diff(
            category="gpo",
            kind="added",
            gpo=G_NEW,
            gpo_name="New Policy",
            subject="GPO",
            before=None,
            after="New Policy",
            scope="",
            area="",
            sources=(src("after.jsonl", ""),),
        ),
        diff(
            category="gpo",
            kind="removed",
            gpo=G_OLD,
            gpo_name="Old Policy",
            subject="GPO",
            before="Old Policy",
            after=None,
            scope="",
            area="",
            sources=(src("before.xml", ""),),
        ),
        diff(
            category="gpo",
            kind="only-before",
            gpo=G_ONLY_B,
            gpo_name="Only Before",
            subject="GPO",
            before="Only Before",
            after=None,
            scope="",
            area="",
            sources=(src("before.xml", ""),),
        ),
        diff(
            category="gpo",
            kind="only-after",
            gpo=G_ONLY_A,
            gpo_name="Only After",
            subject="GPO",
            before=None,
            after="Only After",
            scope="",
            area="",
            sources=(src("after.jsonl", ""),),
        ),
        diff(category="status", subject="user half", before=True, after=False, scope="", area=""),
        diff(
            category="wmi-filter",
            subject="query",
            before="SELECT * FROM Win32_OS",
            after="SELECT * FROM Win32_BIOS",
            scope="",
            area="",
            sources=(),
        ),
        diff(
            category="security-filtering",
            kind="added",
            subject="Staff",
            before=None,
            after={"sid": SID_STAFF, "rights": ["Apply Group Policy", "Read"]},
            scope="",
            area="",
            sources=(src("after.jsonl", "Permissions[2]"),),
        ),
        diff(
            category="permissions",
            kind="changed",
            subject="Domain Admins",
            before=["Edit settings"],
            after=["Edit settings", "Modify security"],
            scope="",
            area="",
            note="Rights changed.",
        ),
        diff(
            category="link",
            kind="removed",
            subject="corp.example/Servers",
            before={"enabled": True, "enforced": False, "order": 1},
            after=None,
            scope="",
            area="",
            sources=(src("before.xml", "LinksTo[1]"),),
        ),
        diff(
            category="link",
            kind="changed",
            subject="corp.example/Workstations",
            before={"order": 2},
            after={"order": 1},
            scope="",
            area="",
        ),
        diff(),
        diff(category="setting", kind="added", subject="Account lockout", before=None, after=5),
        diff(
            category="setting",
            kind="removed",
            subject="Legacy flag",
            before="on",
            after=None,
            sources=(src("before.xml", "Computer/Registry"),),
        ),
        diff(category="setting", subject="Empty things", before="", after=[]),
        diff(
            category="setting",
            subject="Rights",
            before=[SID_ADMINS, SID_STAFF],
            after=[SID_ADMINS],
            area="Security",
            scope="Computer",
            labels=((SID_ADMINS, "CORP\\Domain Admins"), (SID_STAFF, "CORP\\Staff")),
        ),
        diff(
            category="setting",
            subject="Service",
            before={"startup": "Manual"},
            after={"startup": "Automatic", "sddl": None, "acl": {"ace": ["a", "b"], "n": 2}},
            area="Security",
            scope="User",
        ),
        diff(
            category="setting",
            subject="Nothing",
            before={},
            after=[[], {}],
            area="Administrative Templates",
            scope="User",
        ),
        diff(
            category="setting",
            subject="Orphan area",
            before=True,
            after=False,
            scope="",
            area="",
            sources=(src(), src("mid", "x"), src("after.jsonl", "line 9")),
        ),
        diff(
            category="inheritance",
            kind="changed",
            gpo="",
            gpo_name="",
            subject="corp.example/Servers",
            before=False,
            after=True,
            scope="",
            area="",
            note="Blocks inheritance now.",
        ),
    ]


def rich_comparison() -> Comparison:
    return Comparison(
        before="before.xml",
        after="after.jsonl",
        match="guid",
        pairs=[
            pair(G_NEW, "New Policy", "added", 1),
            pair(G_ONLY_A, "Only After", "only-after", 1),
            pair(G_ONLY_B, "Only Before", "only-before", 1),
            pair(G_OLD, "Old Policy", "removed", 1),
            pair(G_QUIET, "Quiet", "unchanged", 0),
            pair(G_SERVERS, "Servers Baseline", "changed", 14),
            pair(G_RENAMED_A, "Workstations 2026", "changed", 3, before_guid=G_RENAMED_B),
        ],
        differences=rich_differences(),
        gaps=[
            Gap("link order", "the before input is a Get-GPOReport file", gpo=G_SERVERS),
            Gap("scopes", "neither input has domain structure"),
            Gap("wmi filter", "unknown to the input", gpo=G_UNLISTED),
        ],
        problems=[Problem(src("bad.xml", "line 3"), "XML is not well formed")],
        notices=["The two inputs share no GPO; try --match name."],
    )


def after_snapshot() -> Snapshot:
    def gpo(guid: str, name: str, **kw: Any) -> Gpo:
        return Gpo(guid=guid, domain="corp.example", name=name, source=src("after.jsonl", ""), **kw)

    trustees = [
        Trustee(SID_STAFF, "Staff", allow=True, rights=("Apply Group Policy", "Read")),
        Trustee(SID_ADMINS, "Domain Admins", allow=True, rights=("Edit settings",)),
        Trustee("S-1-5-11", "Authenticated Users", allow=False, rights=("Apply Group Policy",)),
        Trustee(
            "S-1-5-9", "ENTERPRISE DOMAIN CONTROLLERS", allow=True, rights=("Apply Group Policy",)
        ),
    ]
    links = [
        Link("corp.example/Workstations", enabled=False, enforced=False),
        Link("corp.example/Servers", enabled=True, enforced=True, order=2),
        Link("corp.example/Branch", enabled=True, enforced=False, order=1),
    ]
    flt = WmiFilter("Win11 only", "Windows 11", "{aaaa}", "SELECT * FROM Win32_OS")
    return Snapshot(
        label="after",
        inputs=["after.jsonl"],
        gpos={
            G_SERVERS: gpo(
                G_SERVERS,
                "Servers Baseline",
                computer_enabled=True,
                user_enabled=False,
                trustees=trustees,
                links=links,
                wmi_filter=flt,
            ),
            G_NEW: gpo(G_NEW, "New Policy", wmi_filter=None, trustees=[], links=[]),
            G_ONLY_A: gpo(G_ONLY_A, "Only After", wmi_filter=WmiFilter("Bare")),
            G_RENAMED_A: gpo(G_RENAMED_A, "Workstations 2026"),
            G_QUIET: gpo(G_QUIET, "Quiet", computer_enabled=True),
        },
    )


def make(comparison: Comparison | None = None, **kw: Any) -> dict[str, Any]:
    args: dict[str, Any] = {"after": after_snapshot()}
    args.update(kw)
    return build_report(
        comparison or rich_comparison(), INPUTS, GENERATED, "0.1.0", OPTIONS, **args
    )


@pytest.fixture
def rich_report() -> dict[str, Any]:
    return make()


def empty_comparison(**kw: Any) -> Comparison:
    return Comparison(before="a", after="b", match="guid", **kw)


def hostile_comparison(prefix: str = "") -> Comparison:
    bad = prefix + PAYLOAD
    return Comparison(
        before=bad,
        after=bad,
        match="guid",
        pairs=[pair(bad, bad, "changed", 1, before_guid=bad)],
        differences=[
            diff(
                gpo=bad,
                gpo_name=bad,
                subject=bad,
                before=[bad, {bad: bad}],
                after=bad,
                note=bad,
                scope="Computer",
                area=bad,
                sources=(Source(bad, bad), Source(bad, bad)),
                labels=((bad, bad),),
            ),
            diff(category="inheritance", gpo="", gpo_name="", subject=bad, scope="", area=""),
        ],
        gaps=[Gap(bad, bad, gpo=bad)],
        problems=[Problem(Source(bad, bad), bad)],
        notices=[bad],
    )


def crowded() -> tuple[Comparison, Snapshot]:
    """More of everything than Markdown and HTML list when a JSON report holds the rest."""
    long = "L" * 400
    big = [
        diff(
            subject=f"setting {i}",
            area="Area A" if i < 150 else "Area B" if i < 250 else "Area C",
            before=long,
            after=i,
            note=long,
        )
        for i in range(260)
    ]
    pairs = [pair(G_SERVERS, "Servers Baseline", "changed", 260)]
    differences = list(big)
    for i in range(119):
        guid = f"{i + 1000:08d}-0000-0000-0000-000000000000"
        pairs.append(pair(guid, f"GPO {i:03d}", "changed", 1))
        differences.append(diff(gpo=guid, gpo_name=f"GPO {i:03d}", subject=f"item {i}"))
    pairs += [
        pair(f"{i:08d}-0000-0000-0000-000000000001", f"Quiet {i}", "unchanged", 0)
        for i in range(10)
    ]
    comparison = Comparison(
        before="a",
        after="b",
        match="guid",
        pairs=pairs,
        differences=differences,
        gaps=[Gap(f"gap {i}", "reason", gpo=G_SERVERS) for i in range(30)],
        problems=[Problem(src("in.xml", f"line {i}"), f"problem {i}") for i in range(30)],
        notices=[f"notice {i}" for i in range(30)],
    )
    snapshot = Snapshot(
        label="after",
        inputs=["b"],
        gpos={
            G_SERVERS: Gpo(
                guid=G_SERVERS,
                domain="corp.example",
                name="Servers Baseline",
                source=src(),
                trustees=[
                    Trustee(
                        f"S-1-5-21-1-2-3-{i}",
                        f"group{i}",
                        allow=True,
                        rights=("Apply Group Policy",),
                    )
                    for i in range(30)
                ],
                links=[
                    Link(f"corp.example/OU{i:02d}", enabled=True, enforced=False, order=i + 1)
                    for i in range(30)
                ],
                wmi_filter=WmiFilter("Long", "", "", long),
            )
        },
    )
    return comparison, snapshot


# --- the report document ----------------------------------------------------------------------


def test_the_rich_report_follows_the_schema(rich_report: dict[str, Any]) -> None:
    schema_check("report-v1.schema.json", rich_report)
    assert rich_report["$schema"] == (
        "https://faithful-oversight.github.io/faithful-mishpat/schema/report-v1.schema.json"
    )
    assert rich_report["schema_version"] == "1.0"
    assert rich_report["tool"] == {"name": "mishpat", "version": "0.1.0"}
    assert rich_report["generated_at"] == "2026-11-05T09:30:00Z"
    assert rich_report["options"] == {"fail_on": "differences", "match": "guid", "verbose": False}
    assert list(rich_report["options"]) == sorted(rich_report["options"])


def test_every_category_kind_and_status_is_in_the_rich_data(rich_report: dict[str, Any]) -> None:
    assert {d["category"] for d in rich_report["differences"]} == set(CATEGORIES)
    assert {d["kind"] for d in rich_report["differences"]} == set(KINDS)
    assert {p["status"] for p in rich_report["gpos"]} == set(STATUSES)


def test_an_empty_comparison_and_a_hostile_one_follow_the_schema() -> None:
    schema_check("report-v1.schema.json", build_report(empty_comparison(), [], GENERATED, "0.1.0"))
    schema_check(
        "report-v1.schema.json",
        build_report(hostile_comparison(FORMULA), INPUTS, GENERATED, "0.1.0", OPTIONS),
    )


def test_the_schema_enums_match_the_code() -> None:
    text = files("faithful_mishpat").joinpath("schema", "report-v1.schema.json")
    schema = json.loads(text.read_text(encoding="utf-8"))
    props = schema["properties"]
    item = props["differences"]["items"]["properties"]
    assert item["category"]["enum"] == list(CATEGORIES)
    assert item["kind"]["enum"] == list(KINDS)
    assert props["gpos"]["items"]["properties"]["status"]["enum"] == list(STATUSES)
    summary = props["summary"]["properties"]
    assert summary["by_category"]["propertyNames"]["enum"] == list(CATEGORIES)
    assert summary["by_kind"]["propertyNames"]["enum"] == list(KINDS)
    assert summary["by_status"]["propertyNames"]["enum"] == list(STATUSES)
    assert set(STATUSES) == {
        "changed",
        "unchanged",
        "added",
        "removed",
        "only-before",
        "only-after",
    }
    assert schema["$id"] == rich_id("report")
    manifest = files("faithful_mishpat").joinpath("schema", "manifest-v1.schema.json")
    assert json.loads(manifest.read_text(encoding="utf-8"))["$id"] == rich_id("manifest")


def rich_id(name: str) -> str:
    return f"https://faithful-oversight.github.io/faithful-mishpat/schema/{name}-v1.schema.json"


def test_the_schema_rejects_what_it_should(rich_report: dict[str, Any]) -> None:
    mutations: list[Callable[[dict[str, Any]], object]] = [
        lambda d: d["differences"][0].update(category="other"),
        lambda d: d["differences"][0].update(kind="moved"),
        lambda d: d["gpos"][0].update(status="gone"),
        lambda d: d["differences"][0].update(scope="Both"),
        lambda d: d["differences"][0].pop("before"),
        lambda d: d["differences"][0].pop("labels"),
        lambda d: d["differences"][0].update(labels=["x"]),
        lambda d: d["differences"][0].update(labels={"1": 2}),
        lambda d: d["differences"][0].update(labels={"1": None}),
        lambda d: d["summary"]["by_kind"].update(moved=1),
        lambda d: d.update(extra=1),
    ]
    for mutate in mutations:
        broken = copy.deepcopy(rich_report)
        mutate(broken)
        with pytest.raises(ValidationError):
            schema_check("report-v1.schema.json", broken)


def test_the_summary_counts(rich_report: dict[str, Any]) -> None:
    s = rich_report["summary"]
    assert s["complete"] is False
    assert s["differences"] == 20
    assert s["gpos_compared"] == 7
    assert s["gpos_changed"] == 6
    assert s["scope_differences"] == 1
    assert (s["problems"], s["gaps"], s["notices"]) == (1, 3, 1)
    assert list(s["by_category"]) == list(CATEGORIES)
    assert s["by_category"]["setting"] == 8
    assert list(s["by_kind"]) == list(KINDS)
    assert list(s["by_status"]) == list(STATUSES)
    assert s["by_status"]["unchanged"] == 1
    assert rich_report["comparison"] == {
        "before": "before.xml",
        "after": "after.jsonl",
        "match": "guid",
        "complete": False,
    }
    assert rich_report["limitations"] == list(LIMITATIONS)


def test_inputs_keep_only_the_documented_keys(rich_report: dict[str, Any]) -> None:
    assert rich_report["inputs"][0] == {
        "name": "before.xml",
        "kind": "report",
        "size": 4096,
        "sha256": SHA,
    }


def test_context_is_the_after_side_and_only_for_gpos_with_differences(
    rich_report: dict[str, Any],
) -> None:
    by_guid = {g["guid"]: g for g in rich_report["gpos"]}
    assert by_guid[G_SERVERS]["context"] == {
        "computer_enabled": True,
        "user_enabled": False,
        "wmi_filter": {
            "name": "Win11 only",
            "description": "Windows 11",
            "identifier": "{aaaa}",
            "query": "SELECT * FROM Win32_OS",
        },
        "security_filtering": [
            {"sid": "S-1-5-9", "name": "ENTERPRISE DOMAIN CONTROLLERS"},
            {"sid": SID_STAFF, "name": "Staff"},
        ],
        "links": [
            {"target": "corp.example/Branch", "enabled": True, "enforced": False, "order": 1},
            {"target": "corp.example/Servers", "enabled": True, "enforced": True, "order": 2},
            {
                "target": "corp.example/Workstations",
                "enabled": False,
                "enforced": False,
                "order": None,
            },
        ],
    }
    assert by_guid[G_NEW]["context"] == {
        "computer_enabled": None,
        "user_enabled": None,
        "wmi_filter": "none",
        "security_filtering": [],
        "links": [],
    }
    assert by_guid[G_ONLY_A]["context"]["wmi_filter"] == {
        "name": "Bare",
        "description": "",
        "identifier": "",
        "query": None,
    }
    unknown = by_guid[G_RENAMED_A]["context"]
    assert unknown["wmi_filter"] == "unknown"
    assert unknown["security_filtering"] is None
    assert unknown["links"] is None
    assert by_guid[G_QUIET]["context"] is None  # no differences: no section, no context
    assert by_guid[G_OLD]["context"] is None  # not on the after side
    without = make(after=None)
    assert all(g["context"] is None for g in without["gpos"])
    schema_check("report-v1.schema.json", without)


def test_build_report_does_not_alias_the_comparison() -> None:
    comparison = Comparison(
        before="a",
        after="b",
        match="guid",
        differences=[diff(before=["x"], after={"k": ["y"]})],
    )
    report = build_report(comparison, [], GENERATED, "0.1.0")
    report["differences"][0]["before"].append("changed")
    report["differences"][0]["after"]["k"].append("changed")
    assert comparison.differences[0].before == ["x"]
    assert comparison.differences[0].after == {"k": ["y"]}


@pytest.mark.parametrize(
    ("difference", "pairs"),
    [
        (diff(category="nope"), []),
        (diff(kind="nope"), []),
        (diff(scope="Both"), []),
        (None, [pair(G_QUIET, "Quiet", "nope", 0)]),
    ],
)
def test_a_comparison_the_schema_cannot_describe_is_refused(
    difference: Difference | None, pairs: list[Pair]
) -> None:
    comparison = empty_comparison(
        differences=[] if difference is None else [difference], pairs=pairs
    )
    with pytest.raises(ValueError, match="unknown"):
        build_report(comparison, [], GENERATED, "0.1.0")


def test_the_report_is_repeatable(rich_report: dict[str, Any]) -> None:
    again = make()
    assert again == rich_report
    assert render_json(again) == render_json(rich_report)
    assert r.render_markdown(again) == r.render_markdown(rich_report)
    assert r.render_html(again) == r.render_html(rich_report)
    assert r.render_csv(again) == r.render_csv(rich_report)


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (datetime(2026, 11, 5, 9, 30, tzinfo=UTC), "2026-11-05T09:30:00Z"),
        (datetime(2026, 11, 5, 9, 30), "2026-11-05T09:30:00Z"),  # noqa: DTZ001 - a naive time is the case
        (
            datetime(2026, 11, 5, 9, 30, tzinfo=timezone(timedelta(hours=-5))),
            "2026-11-05T14:30:00Z",
        ),
        (datetime(2026, 11, 5, 9, 30, 1, 500000, tzinfo=UTC), "2026-11-05T09:30:01.5Z"),
        (datetime(1, 1, 1, tzinfo=UTC), "0001-01-01T00:00:00Z"),
    ],
)
def test_times_are_utc_with_z(value: datetime, text: str) -> None:
    assert format_time(value) == text


def test_json_keeps_documented_order_and_a_final_newline(rich_report: dict[str, Any]) -> None:
    text = render_json(rich_report)
    assert text.endswith("}\n")
    assert list(json.loads(text)) == [
        "$schema",
        "schema_version",
        "tool",
        "generated_at",
        "inputs",
        "options",
        "comparison",
        "summary",
        "notices",
        "gpos",
        "differences",
        "gaps",
        "problems",
        "limitations",
    ]
    assert json.loads(text) == rich_report
    assert "é" in render_json({"x": "é"})


def test_json_survives_a_lone_surrogate() -> None:
    text = render_json({"x": "a\ud800b"})
    assert "\\ud800" in text
    assert json.loads(text) == {"x": "a\ud800b"}


def test_limitations_are_plain_sentences() -> None:
    assert len(LIMITATIONS) >= 5
    assert all(item.endswith(".") and "  " not in item for item in LIMITATIONS)
    joined = " ".join(LIMITATIONS)
    for topic in ("effective settings", "Item-level targeting", "WMI", "Link order", "blocked"):
        assert topic in joined
    assert "mishpat exporter" in joined


# --- words ---------------------------------------------------------------------------------


def test_headline_states() -> None:
    def head(**kw: Any) -> tuple[str, str]:
        return r.headline(build_report(empty_comparison(**kw), [], GENERATED, "0.1.0"))

    assert head() == ("complete", "No differences. Every input was read in full.")
    one = head(differences=[diff()])
    assert one == ("complete", "1 difference across 1 GPO. Every input was read in full.")
    two = head(differences=[diff(), diff(gpo=G_NEW, gpo_name="N"), diff(subject="x")])
    assert two[1] == "3 differences across 2 GPOs. Every input was read in full."
    scope = diff(category="inheritance", gpo="", gpo_name="", scope="", area="")
    assert head(differences=[scope])[1] == (
        "1 difference in the domain's structure. Every input was read in full."
    )
    both = head(differences=[diff(), scope])[1]
    assert (
        both
        == "2 differences across 1 GPO and the domain's structure. Every input was read in full."
    )
    bad = [Problem(src("x", ""), "no")]
    assert head(problems=bad) == (
        "incomplete",
        "No differences. Incomplete: 1 problem with an input, so differences may be missing.",
    )
    two_bad = head(problems=bad * 2, differences=[diff()])
    assert two_bad[1].startswith("1 difference across 1 GPO. Incomplete: 2 problems with an input")


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (None, "(not set)"),
        ("", "(empty)"),
        ("plain", "plain"),
        (14, "14"),
        (0, "0"),
        (True, "true"),
        (False, "false"),
        ([], "(empty list)"),
        (["a", "b"], "a, b"),
        ([1, True, None, ""], "1, true, (not set), (empty)"),
        ({}, "(no entries)"),
        ({"a": 1, "b": "x"}, "a: 1; b: x"),
        (
            {"a": [1, 2], "b": {"c": None}, "d": [], "e": {}},
            "a: [1, 2]; b: (c: (not set)); d: []; e: ()",
        ),
        ([["a"], {"k": "v"}], "[a], (k: v)"),
        (" ", '" "'),  # text of only spaces would look empty
        ("   ", '"   "'),
        ("\t", '"\t"'),
        (" lead", '" lead"'),  # edge spaces would vanish
        ("trail ", '"trail "'),
        ("  both  ", '"  both  "'),
        ("in side", "in side"),  # spaces inside are visible: no quotes
        ([" ", "x"], '" ", x'),
        ({"a": " b"}, 'a: " b"'),
    ],
)
def test_values_read_plainly(value: Any, text: str) -> None:
    assert r.value_text(value) == text


def test_titles_and_words_cover_every_category_kind_and_status() -> None:
    assert list(r.CATEGORY_TITLES) == list(CATEGORIES)
    assert set(r.WORDS) >= set(KINDS) | set(STATUSES)


# --- markdown --------------------------------------------------------------------------------


def headings(md: str) -> list[str]:
    return [line for line in md.splitlines() if line.startswith("#")]


def test_markdown_reads_in_the_documented_order(rich_report: dict[str, Any]) -> None:
    md = r.render_markdown(rich_report)
    assert md.startswith("# GPO change review\n")
    order = [
        (
            "**20 differences across 6 GPOs and the domain's structure (2 GPOs in only one input). "
            "Incomplete: 1 problem"
        ),
        "## Notices",
        "## GPOs compared",
        "## Changes by GPO",
        "### Servers Baseline (11111111-1111-1111-1111-111111111111)",
        "#### Status",
        "## Domain structure",
        "## Not compared",
        "## Problems",
        "## Inputs",
        "## Limitations",
    ]
    positions = [md.index(item) for item in order]
    assert positions == sorted(positions)
    assert "Before: before.xml. After: after.jsonl. GPOs paired by guid." in md
    assert "Generated 2026-11-05T09:30:00Z by mishpat 0.1.0." in md
    assert "The two inputs share no GPO; try \\-\\-match name." not in md  # hyphens are not special
    assert "try --match name." in md
    assert "XML is not well formed" in md
    assert "bad.xml line 3" in md
    assert "link order (Servers Baseline): the before input" in md  # a GPO gap names the GPO
    assert "scopes: neither input" in md
    assert f"wmi filter ({'99999999-9999-9999-9999-999999999999'}): unknown" in md  # unlisted GUID
    assert md.endswith("\n")
    assert not md.endswith("\n\n")


def test_markdown_gpo_section_shows_after_side_context(rich_report: dict[str, Any]) -> None:
    md = r.render_markdown(rich_report)
    section = md[md.index("### Servers Baseline") : md.index("### Workstations 2026")]
    assert "Changed. 14 differences." in section
    assert "- **Status:** computer half enabled; user half disabled" in section
    assert (
        "- **WMI filter:** Win11 only (Windows 11), id {aaaa}, query: SELECT \\* FROM Win32\\_OS"
        in section
    )
    assert (
        "- **Security filtering:** ENTERPRISE DOMAIN CONTROLLERS (S-1-5-9), Staff (S-1-5-21"
        in section
    )
    assert (
        "- **Links:** corp.example/Branch (enabled, order 1); "
        "corp.example/Servers (enabled, enforced, order 2); "
        "corp.example/Workstations (disabled)"
    ) in section
    new = md[md.index("### New Policy") : md.index("### Old Policy")]
    assert "- **WMI filter:** none" in new
    assert "- **Security filtering:** none (no entry allows Apply Group Policy)" in new
    assert "- **Links:** none" in new
    assert "- **Status:** computer half not recorded; user half not recorded" in new
    unknown = md[md.index("### Workstations 2026") : md.index("## Domain structure")]
    assert "- **WMI filter:** not recorded" in unknown
    assert "- **Security filtering:** not recorded" in unknown
    assert "- **Links:** not recorded" in unknown
    bare = md[md.index("### Only After") : md.index("### Only Before")]
    assert "- **WMI filter:** Bare, query not recorded" in bare
    old = md[md.index("### Old Policy") : md.index("### Only After")]
    assert "**Status:**" not in old  # not on the after side
    without = r.render_markdown(make(after=None))
    assert "**Status:**" not in without


def test_markdown_groups_by_category_then_scope_and_area(rich_report: dict[str, Any]) -> None:
    md = r.render_markdown(rich_report)
    section = md[md.index("### Servers Baseline") : md.index("### Workstations 2026")]
    cats = [h for h in headings(section) if h.startswith("#### ")]
    assert cats == [
        "#### Status",
        "#### WMI filter",
        "#### Security filtering",
        "#### Permissions \\(delegation\\)".replace("\\(", "(").replace("\\)", ")"),
        "#### Links",
        "#### Settings",
    ]
    subs = [h for h in headings(section) if h.startswith("##### ")]
    assert subs == [
        "##### Computer · Security",
        "##### User · Administrative Templates",
        "##### User · Security",
        "##### No scope · No area",
    ]
    assert "| Subject | Kind | Before | After | Sources |" in section
    assert "| Subject | Kind | Before | After | Note | Sources |" in section  # only when notes
    assert (
        "| Minimum password length | changed | 8 | 14 | "
        "before: before.xml Computer/Registry/Policy[0]; after: after.jsonl line 4 |"
    ) in section.replace("\\[", "[").replace("\\]", "]")
    assert "| Account lockout | added | (not set) | 5 |" in section
    assert "| Legacy flag | removed | on | (not set) |" in section
    assert "| Empty things | changed | (empty) | (empty list) |" in section
    assert (
        f"| Rights | changed | {SID_ADMINS} (CORP\\\\Domain Admins), {SID_STAFF} (CORP\\\\Staff) "
        f"| {SID_ADMINS} (CORP\\\\Domain Admins) |"
    ) in section  # Markdown doubles the backslash of an account name
    assert "startup: Manual" in section
    assert "acl: (ace: [a, b], n: 2)" in section.replace("\\[", "[").replace("\\]", "]")
    assert "Nothing | changed | (no entries) | [], () |" in section.replace("\\[", "[").replace(
        "\\]", "]"
    )
    wmi = md[md.index("#### WMI filter") :]
    assert "| query | changed |" in wmi


def test_markdown_scope_level_section_and_kinds(rich_report: dict[str, Any]) -> None:
    md = r.render_markdown(rich_report)
    scope = md[md.index("## Domain structure") : md.index("## Not compared")]
    assert "### Inheritance" in scope
    assert "| corp.example/Servers | changed | false | true | Blocks inheritance now." in scope
    for word in ("only in before", "only in after", "renamed", "removed", "added"):
        assert word in md
    table = md[md.index("## GPOs compared") : md.index("## Changes by GPO")]
    assert (
        f"| Workstations 2026 | 88888888-8888-8888-8888-888888888888 \\(before: {G_RENAMED_B}\\)"
    ).replace("\\(", "(").replace("\\)", ")") in table.replace("\\(", "(").replace("\\)", ")")
    rows = [line.split(" | ")[0] for line in table.splitlines() if line.startswith("| ")]
    # GPOs with differences first, the quiet one last.
    assert rows[-1] == "| Quiet"


def test_markdown_with_nothing_to_show() -> None:
    md = r.render_markdown(build_report(empty_comparison(), [], GENERATED, "0.1.0"))
    assert "No GPOs were compared." in md
    assert "No GPO has a difference." in md
    assert "## Notices" not in md
    assert "## Not compared" not in md
    assert "## Problems" not in md
    assert "## Domain structure" not in md
    assert "**No differences. Every input was read in full.**" in md
    quiet = empty_comparison(pairs=[pair(G_QUIET, "Quiet", "unchanged", 0)])
    md = r.render_markdown(build_report(quiet, [], GENERATED, "0.1.0"))
    assert "| Quiet |" in md
    assert "No GPO has a difference." in md


def test_a_difference_for_a_gpo_not_in_the_table_still_gets_a_section() -> None:
    comparison = empty_comparison(
        differences=[
            diff(gpo=G_UNLISTED, gpo_name="Stray"),
            diff(gpo=G_UNLISTED, gpo_name="Stray", subject="two"),
        ]
    )
    report = build_report(comparison, [], GENERATED, "0.1.0")
    md = r.render_markdown(report)
    assert f"### Stray ({G_UNLISTED})" in md
    assert "Changed. 2 differences." in md
    assert "Stray" in r.render_html(report)


def test_markdown_with_a_gpo_whose_scope_rows_are_unsorted() -> None:
    comparison = empty_comparison(
        pairs=[pair(G_SERVERS, "S", "changed", 4)],
        differences=[
            diff(scope="User", area="b", subject="1"),
            diff(scope="", area="a", subject="2"),
            diff(scope="Computer", area="B", subject="3"),
            diff(scope="Computer", area="a", subject="4"),
        ],
    )
    md = r.render_markdown(build_report(comparison, [], GENERATED, "0.1.0"))
    subs = [h for h in headings(md) if h.startswith("##### ")]
    assert subs == [
        "##### Computer · a",
        "##### Computer · B",
        "##### User · b",
        "##### No scope · a",
    ]


def tables_are_regular(md: str) -> None:
    pipe = re.compile(r"(?<!\\)\|")
    block: list[int] = []
    for line in [*md.splitlines(), ""]:
        if line.startswith("|"):
            block.append(len(pipe.findall(line)))
        else:
            assert len(set(block)) <= 1, block
            block = []


def test_markdown_cannot_be_forged_by_input_data() -> None:
    md = r.render_markdown(build_report(hostile_comparison(), INPUTS, GENERATED, "0.1.0"))
    assert "\x1b" not in md
    assert RLO not in md
    assert "\\u202e" in md
    assert not re.search(r"(?<!\\)<", md)
    assert not re.search(r"(?<!\\)\]\(", md)
    assert not re.search(r"://(?!⁠)", md)
    expected = re.compile(r"^(#{1,5}) [^#\n]")
    assert all(expected.match(h) for h in headings(md))
    assert not any(line.startswith(("# forged", "[click]", "`tick`")) for line in md.splitlines())
    assert len([h for h in headings(md) if h.startswith("# ")]) == 1
    assert "\n# forged" not in md
    tables_are_regular(md)
    tables_are_regular(r.render_markdown(make()))


def test_markdown_shortens_long_values_only_when_told_to() -> None:
    comparison, snapshot = crowded()
    report = build_report(comparison, [], GENERATED, "0.1.0", after=snapshot)
    short = r.render_markdown(report, shorten=True)
    assert "L" * 300 + "… (400 characters; full value in the JSON report)" in short
    assert "L" * 301 not in short
    whole = r.render_markdown(report, shorten=False)
    assert "L" * 400 in whole
    assert "JSON report" not in whole
    assert r.render_markdown(report) == short  # shortening is the default
    assert r.render_html(report) == r.render_html(report, shorten=True)


def test_a_value_of_exactly_the_limit_is_not_shortened() -> None:
    exact = "x" * r.MAX_VALUE
    report = build_report(
        empty_comparison(differences=[diff(before=exact, after=exact + "y")]),
        [],
        GENERATED,
        "0.1.0",
    )
    for page in (r.render_markdown(report), r.render_html(report)):
        assert "(300 characters" not in page  # the value at the limit is whole
        assert exact + "y" not in page  # the one just over it is cut
        assert "(301 characters; full value in the JSON report)" in page


@pytest.mark.parametrize("renderer", [r.render_markdown, r.render_html])
def test_caps_apply_only_with_the_json_report(renderer: Any) -> None:
    comparison, snapshot = crowded()
    report = build_report(comparison, [], GENERATED, "0.1.0", after=snapshot)
    whole = renderer(report, shorten=False)
    assert "JSON report" not in whole
    last = [
        "notice 29",
        "gap 29",
        "problem 29",
        "GPO 118",
        "Quiet 9",
        "setting 259",
        "OU29",
        "group9 (",
        "item 118",
    ]
    for text in last:
        assert text in whole
    capped = renderer(report, shorten=True)
    for text in (
        "notice 29",
        "gap 29",
        "problem 29",
        "GPO 118",
        "Quiet 9",
        "setting 259",
        "OU29",
        "group9 (",
        "item 118",
    ):
        assert text not in capped
    for text in (
        "5 more in the JSON report.",  # notices: 30 listed 25
        "20 more GPOs in the JSON report.",  # 120 GPOs with differences, 100 sections
        "60 more differences in the JSON report.",
        "and 5 more in the JSON report",  # links and trustees
    ):
        assert text in capped
    assert "GPO 000" in capped
    # Rows: 120 GPOs with differences and 10 quiet ones: 100 listed, 30 more.
    assert "30 more GPOs in the JSON report." in capped


def test_a_cut_group_does_not_leave_a_dangling_heading() -> None:
    comparison, snapshot = crowded()
    capped = r.render_markdown(
        build_report(comparison, [], GENERATED, "0.1.0", after=snapshot), shorten=True
    )
    section = capped[capped.index("### Servers Baseline") : capped.index("### GPO 000")]
    assert "Computer · Area A" in section
    assert "Computer · Area B" in section  # cut part way: 50 of its 100 shown
    assert "Computer · Area C" not in section  # nothing left to show


def test_terminal_summary_is_plain_and_safe(rich_report: dict[str, Any]) -> None:
    text = r.terminal_summary(rich_report)
    lines = text.splitlines()
    assert lines[0] == "mishpat 0.1.0"
    assert lines[1].startswith(
        "20 differences across 6 GPOs and the domain's structure (2 GPOs in only one input). "
        "Incomplete:"
    )
    assert "  Settings: 8" in lines
    assert "  GPO: 5" in lines
    assert "  1 notice: read them first." in lines
    assert lines[-1] == "  See Problems in the report before relying on this result."
    ok = r.terminal_summary(build_report(empty_comparison(), [], GENERATED, "0.1.0"))
    assert ok == "mishpat 0.1.0\nNo differences. Every input was read in full."
    hostile = r.terminal_summary(
        build_report(
            replace(hostile_comparison(), notices=["a", "b"]), [], GENERATED, "0.1.\x1b[2J\r"
        )
    )
    assert "\x1b" not in hostile
    assert "\r" not in hostile
    assert "\\u001b[2J\\r" in hostile
    assert "2 notices: read them first." in hostile


# --- HTML ------------------------------------------------------------------------------------


class Tags(HTMLParser):
    """Collect every tag and attribute a page uses, and flag any that is not expected."""

    ALLOWED_TAGS = frozenset(
        "html head meta title style body a nav main header h1 h2 h3 h4 h5 p span div section "  # noqa: SIM905
        "table caption thead tbody tr th td ul li b code footer".split()
    )
    ALLOWED_ATTRS = frozenset(
        "lang charset http-equiv content name class id href scope role aria-label "  # noqa: SIM905
        "aria-labelledby".split()
    )

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []
        self.bad: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attrs += attrs
        if tag not in self.ALLOWED_TAGS:
            self.bad.append(tag)
        self.bad += [k for k, _ in attrs if k not in self.ALLOWED_ATTRS]


def parse(page: str) -> Tags:
    parser = Tags()
    parser.feed(page)
    return parser


def test_html_cannot_be_forged_by_input_data() -> None:
    page = r.render_html(build_report(hostile_comparison(), INPUTS, GENERATED, "0.1.0"))
    parsed = parse(page)
    assert parsed.bad == []
    assert "script" not in parsed.tags
    assert "img" not in parsed.tags
    hrefs = [v for k, v in parsed.attrs if k == "href"]
    assert hrefs
    assert all(v is not None and re.fullmatch(r"#[a-z]+\d*", v) for v in hrefs)
    assert "\x1b" not in page
    assert RLO not in page
    assert "&lt;script&gt;" in page
    assert "<script" not in page
    assert "http://203.0.113.9" in page  # shown as text, never a link target
    ids = [v for k, v in parsed.attrs if k == "id"]
    assert len(ids) == len(set(ids))


def test_html_is_one_self_contained_accessible_page(rich_report: dict[str, Any]) -> None:
    page = r.render_html(rich_report)
    parsed = parse(page)
    assert parsed.bad == []
    assert "script" not in parsed.tags
    assert re.search(r"https?://", page) is None
    assert f'content="{r.CSP}"' in page
    assert r.CSP == (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"
    )
    assert '<a class="skip" href="#main">' in page
    assert 'id="main"' in page
    assert "prefers-color-scheme:dark" in page
    assert '<html lang="en">' in page
    assert '<th scope="col">' in page
    assert '<th scope="row">' in page
    for anchor in (
        "notices",
        "gpos",
        "changes",
        "scope",
        "gaps",
        "problems",
        "inputs",
        "limitations",
    ):
        assert f'href="#{anchor}"' in page
        assert f'id="{anchor}"' in page
    assert page.count("<h1>") == 1
    assert "⚠ Incomplete" in page
    ids = [v for k, v in parsed.attrs if k == "id"]
    assert len(ids) == len(set(ids))
    hrefs = {v for k, v in parsed.attrs if k == "href"}
    assert {f"#{i}" for i in ids} >= hrefs
    assert 'href="#g' in page  # the table of GPOs links to the sections
    assert "Servers Baseline" in page
    assert "<li><b>Links:</b> corp.example/Branch (enabled, order 1); " in page
    assert "Win11 only (Windows 11)" in page
    assert "<h5>Computer · Security</h5>" in page
    assert '<span class="chg">' in page


def test_html_for_an_empty_comparison_and_a_complete_one() -> None:
    page = r.render_html(build_report(empty_comparison(), [], GENERATED, "0.1.0"))
    assert "No GPOs were compared." in page
    assert "No GPO has a difference." in page
    assert "✔ Complete" in page
    assert 'href="#notices"' not in page
    assert 'href="#scope"' not in page
    assert parse(page).bad == []
    quiet = empty_comparison(pairs=[pair(G_QUIET, "Quiet", "unchanged", 0)])
    page = r.render_html(build_report(quiet, [], GENERATED, "0.1.0"))
    assert "<td>unchanged</td>" in page
    assert "<a href" not in page.split('<h2 id="gpos">')[1].split('<h2 id="changes">')[0]


# --- what changed, with names and meanings ---------------------------------------------------


def one_difference(*differences: Difference, **kw: Any) -> dict[str, Any]:
    pairs = {(d.gpo, d.gpo_name) for d in differences if d.gpo}
    comparison = empty_comparison(
        differences=list(differences),
        pairs=[pair(g, n, "changed", 1) for g, n in sorted(pairs)],
        **kw,
    )
    return build_report(comparison, [], GENERATED, "0.1.0")


def policy(before: dict[str, Any], after: dict[str, Any]) -> Difference:
    return diff(
        subject="Configure Automatic Updates",
        area="Administrative Templates",
        before=before,
        after=after,
        sources=(),
    )


POLICY_BEFORE = {
    "state": "Enabled",
    "Schedule": "0 - Every day",
    "Install day": 3,
    "Quiet": "Disabled",
}


def test_one_changed_policy_option_shows_that_option_alone() -> None:
    report = one_difference(policy(POLICY_BEFORE, {**POLICY_BEFORE, "Install day": 5}))
    md = r.render_markdown(report)
    assert "| Configure Automatic Updates | changed | Install day: 3 | Install day: 5 |" in md
    html = r.render_html(report)
    assert '<span class="val">Install day: 3</span>' in html
    assert '<span class="chg"><span class="val">Install day: 5</span></span>' in html
    for text in (md, html):
        assert "Schedule" not in text
        assert "Quiet" not in text
    assert "Enabled" not in md  # the unchanged state is not repeated
    # The JSON report keeps the whole value, so nothing is lost.
    (found,) = report["differences"]
    assert found["before"] == POLICY_BEFORE
    assert found["after"] == {**POLICY_BEFORE, "Install day": 5}


def test_several_changed_options_show_each_in_the_order_the_policy_lists_them() -> None:
    after = {**POLICY_BEFORE, "state": "Disabled", "Quiet": "Enabled"}
    md = r.render_markdown(one_difference(policy(POLICY_BEFORE, after)))
    assert (
        "| Configure Automatic Updates | changed | state: Enabled; Quiet: Disabled "
        "| state: Disabled; Quiet: Enabled |"
    ) in md
    assert "Schedule" not in md


def test_an_option_that_exists_on_one_side_only_is_shown_as_not_set_on_the_other() -> None:
    added = {**POLICY_BEFORE, "Retries": 2}
    md = r.render_markdown(one_difference(policy(POLICY_BEFORE, added)))
    assert "| Configure Automatic Updates | changed | Retries: (not set) | Retries: 2 |" in md
    md = r.render_markdown(one_difference(policy(added, POLICY_BEFORE)))
    assert "| Configure Automatic Updates | changed | Retries: 2 | Retries: (not set) |" in md


def test_a_nested_list_box_option_is_one_changed_option() -> None:
    def rules(*names: str) -> dict[str, Any]:
        return {"state": "Enabled", "Rules": {"value": list(names), "options": {"Additive": True}}}

    md = r.render_markdown(one_difference(policy(rules("a"), rules("a", "b"))))
    assert (
        "| Configure Automatic Updates | changed "
        "| Rules: (value: \\[a\\], options: (Additive: true)) "
        "| Rules: (value: \\[a, b\\], options: (Additive: true)) |"
    ) in md  # Markdown escapes the brackets
    assert "Enabled" not in md.split("| Subject |")[1]


def test_when_every_key_differs_the_whole_value_is_shown() -> None:
    before = {"state": "Enabled", "Day": "Monday"}
    after = {"state": "Disabled", "Day": "Friday"}
    md = r.render_markdown(one_difference(policy(before, after)))
    assert (
        "| Configure Automatic Updates | changed | state: Enabled; Day: Monday "
        "| state: Disabled; Day: Friday |"
    ) in md
    html = r.render_html(one_difference(policy(before, after)))
    assert '<span class="val">state: Enabled; Day: Monday</span>' in html
    # Keys that exist on one side only count as differing too.
    md = r.render_markdown(one_difference(policy({"a": 1}, {"b": 2})))
    assert "| changed | a: 1 | b: 2 |" in md


def test_equal_mappings_and_mappings_against_other_values_are_shown_whole() -> None:
    def row(before: Any, after: Any) -> str:
        md = r.render_markdown(one_difference(policy(before, after)))
        (line,) = (x for x in md.splitlines() if x.startswith("| Configure Automatic Updates"))
        return line.removesuffix(" |  |")

    base = "| Configure Automatic Updates | changed |"
    assert row({"a": 1}, {"a": 1}) == f"{base} a: 1 | a: 1"  # nothing differs: nothing to narrow to
    assert row({"a": 1}, None) == f"{base} a: 1 | (not set)"
    assert row([1], [2]) == f"{base} 1 | 2"
    assert row({}, {"a": 1}) == f"{base} (no entries) | a: 1"


def labelled(before: Any, after: Any, **labels: str) -> Difference:
    return diff(
        subject="Setting", before=before, after=after, sources=(), labels=tuple(labels.items())
    )


def test_labels_show_beside_list_items_and_scalars_in_markdown_and_html() -> None:
    admins = "S-1-5-32-544"
    users = "S-1-5-32-545"
    rights = labelled(
        [admins, users, "S-1-5-18"],
        [admins],
        **{admins: "BUILTIN\\Administrators", users: "BUILTIN\\Users"},
    )
    level = labelled(3, 5, **{"3": "Send LM and NTLM", "5": "Send NTLMv2 response only"})
    report = one_difference(rights, level)
    md = r.render_markdown(report)
    assert (
        "| Setting | changed | S-1-5-32-544 (BUILTIN\\\\Administrators), S-1-5-32-545 "
        "(BUILTIN\\\\Users), S-1-5-18 | S-1-5-32-544 (BUILTIN\\\\Administrators) |"
    ) in md  # an item without words is shown alone
    assert "| Setting | changed | 3 (Send LM and NTLM) | 5 (Send NTLMv2 response only) |" in md
    html = r.render_html(report)
    assert "S-1-5-32-544 (BUILTIN\\Administrators), S-1-5-32-545 (BUILTIN\\Users), S-1-5-18" in html
    assert '<span class="val">3 (Send LM and NTLM)</span>' in html
    assert "5 (Send NTLMv2 response only)</span></span>" in html


def test_labels_apply_to_booleans_and_text_but_not_to_nothing_or_mappings() -> None:
    flag = diff(subject="Flag", before=True, after=None, sources=(), labels=(("true", "on"),))
    words = labelled("Enabled", {"Enabled": "x"}, Enabled="the feature is on")
    plain = labelled(3, 5)  # no words recorded
    md = r.render_markdown(one_difference(flag, words, plain))
    assert "| Flag | changed | true (on) | (not set) |" in md
    assert "| Setting | changed | Enabled (the feature is on) | Enabled: x |" in md
    assert "| Setting | changed | 3 | 5 |" in md


def test_a_label_goes_beside_a_quoted_value() -> None:
    padded = labelled(" x", "y", **{" x": "a leading space"})
    md = r.render_markdown(one_difference(padded))
    assert '| Setting | changed | " x" (a leading space) | y |' in md


def test_labels_are_in_the_json_report_and_follow_the_schema() -> None:
    report = one_difference(
        labelled(3, 5, **{"5": "Send NTLMv2 response only", "3": "Send LM and NTLM"}),
        diff(subject="Plain", sources=()),
    )
    schema_check("report-v1.schema.json", report)
    with_words, plain = report["differences"]
    assert with_words["labels"] == {"3": "Send LM and NTLM", "5": "Send NTLMv2 response only"}
    assert plain["labels"] == {}
    parsed = json.loads(render_json(report))
    assert parsed["differences"][0]["labels"] == with_words["labels"]
    assert list(with_words)[-2:] == ["labels", "sources"]


def test_labels_are_copied_into_the_report() -> None:
    difference = labelled(3, 5, **{"3": "x"})
    report = one_difference(difference)
    report["differences"][0]["labels"]["3"] = "changed"
    assert difference.labels == (("3", "x"),)


def test_quoted_text_reaches_markdown_html_and_the_terminal_intact() -> None:
    report = one_difference(
        diff(subject="Banner", before=" ", after="  on  ", sources=()),
        diff(subject="Other", before="", after="plain", sources=()),
    )
    md = r.render_markdown(report)
    assert '| Banner | changed | " " | "  on  " |' in md
    assert "| Other | changed | (empty) | plain |" in md
    html = r.render_html(report)
    assert '<span class="val">&quot; &quot;</span>' in html
    assert '<span class="chg"><span class="val">&quot;  on  &quot;</span></span>' in html


def test_the_headline_counts_gpos_in_only_one_input() -> None:
    def head(*differences: Difference, **kw: Any) -> str:
        return r.headline(one_difference(*differences, **kw))[1]

    before = diff(
        category="gpo",
        kind="only-before",
        gpo=G_ONLY_B,
        gpo_name="B",
        subject="GPO",
        before="B",
        after=None,
        scope="",
        area="",
        sources=(),
    )
    after = diff(
        category="gpo",
        kind="only-after",
        gpo=G_ONLY_A,
        gpo_name="A",
        subject="GPO",
        before=None,
        after="A",
        scope="",
        area="",
        sources=(),
    )
    assert head(before) == (
        "1 difference across 1 GPO (1 GPO in only one input). Every input was read in full."
    )
    assert head(before, after) == (
        "2 differences across 2 GPOs (2 GPOs in only one input). Every input was read in full."
    )
    assert head(before, diff()) == (
        "2 differences across 2 GPOs (1 GPO in only one input). Every input was read in full."
    )
    scope = diff(category="inheritance", gpo="", gpo_name="", scope="", area="")
    assert head(before, scope) == (
        "2 differences across 1 GPO and the domain's structure (1 GPO in only one input). "
        "Every input was read in full."
    )
    bad = [Problem(src("x", ""), "no")]
    assert head(before, problems=bad) == (
        "1 difference across 1 GPO (1 GPO in only one input). "
        "Incomplete: 1 problem with an input, so differences may be missing."
    )
    # Added and removed GPOs, from two whole domains, are not "in only one input".
    added = diff(
        category="gpo",
        kind="added",
        gpo=G_NEW,
        gpo_name="N",
        subject="GPO",
        before=None,
        after="N",
        scope="",
        area="",
        sources=(),
    )
    assert "only one input" not in head(added)


def test_the_headline_with_only_one_input_gpos_is_in_every_rendering() -> None:
    report = one_difference(
        diff(
            category="gpo",
            kind="only-before",
            gpo=G_ONLY_B,
            gpo_name="B",
            subject="GPO",
            before="B",
            after=None,
            scope="",
            area="",
            sources=(),
        )
    )
    line = "1 difference across 1 GPO (1 GPO in only one input)."
    assert line in r.render_markdown(report)
    assert line in r.render_html(report)
    assert line in r.terminal_summary(report)


def test_the_domain_structure_section_holds_only_scope_level_differences() -> None:
    scope = diff(
        category="inheritance",
        gpo="",
        gpo_name="",
        subject="corp.example/Servers",
        before="not blocked",
        after="blocked",
        scope="",
        area="",
        sources=(),
    )
    order = diff(
        category="inheritance",
        gpo="",
        gpo_name="",
        scope="",
        area="",
        sources=(),
        subject="corp.example/Servers: link order",
        before=["A", "B"],
        after=["B", "A"],
    )
    report = one_difference(diff(sources=()), scope, order)
    md = r.render_markdown(report)
    assert "## Domain structure\n" in md
    section = md[md.index("## Domain structure") :]
    assert "| corp.example/Servers | changed | not blocked | blocked |" in section
    assert "| corp.example/Servers: link order | changed | A, B | B, A |" in section
    assert "Minimum password length" not in section
    assert "Scope inheritance" not in md
    html = r.render_html(report)
    assert '<h2 id="scope">Domain structure</h2>' in html
    assert '<a href="#scope">Domain structure</a>' in html
    assert "Scope inheritance" not in html
    alone = r.render_markdown(one_difference(diff(sources=())))
    assert "Domain structure" not in alone.replace("the domain's structure", "")


def test_gpo_added_and_removed_rows_show_the_name_on_the_side_that_has_it() -> None:
    def gpo_row(kind: str, before: str | None, after: str | None) -> Difference:
        return diff(
            category="gpo",
            kind=kind,
            gpo=G_NEW,
            gpo_name="Edge Policy",
            subject="GPO",
            before=before,
            after=after,
            scope="",
            area="",
            sources=(),
        )

    md = r.render_markdown(
        one_difference(gpo_row("added", None, "Edge Policy"), gpo_row("removed", "Old", None))
    )
    assert "| GPO | added | (not set) | Edge Policy |" in md
    assert "| GPO | removed | Old | (not set) |" in md
    assert "(not set) | (not set)" not in md


def test_the_comparison_sides_are_named_in_every_report() -> None:
    comparison = Comparison(
        before="corp-before.jsonl",
        after="corp-after.jsonl",
        match="guid",
        differences=[diff()],
        pairs=[pair(G_SERVERS, "Servers Baseline", "changed", 1)],
    )
    report = build_report(comparison, [], GENERATED, "0.1.0")
    assert report["comparison"]["before"] == "corp-before.jsonl"
    assert report["comparison"]["after"] == "corp-after.jsonl"
    assert "Before: corp-before.jsonl. After: corp-after.jsonl." in r.render_markdown(report)
    assert "corp-before.jsonl" in r.render_html(report)


# --- CSV -------------------------------------------------------------------------------------


def rows_of(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline="")))


def test_csv_has_one_row_per_difference_with_the_caveat_on_every_row(
    rich_report: dict[str, Any],
) -> None:
    text = r.render_csv(rich_report)
    assert "\r\n" in text
    assert not text.startswith("﻿")
    rows = rows_of(text)
    assert rows[0] == [
        "category",
        "kind",
        "gpo_guid",
        "gpo_name",
        "scope",
        "area",
        "subject",
        "before",
        "after",
        "note",
        "before_source",
        "after_source",
        "comparison_complete",
    ]
    assert len(rows) == 1 + len(rich_report["differences"])
    assert all(len(row) == 13 for row in rows)
    assert {row[-1] for row in rows[1:]} == {"false"}
    complete = make(empty_comparison(differences=[diff()]))
    assert {row[-1] for row in rows_of(r.render_csv(complete))[1:]} == {"true"}
    by_subject = {row[6]: row for row in rows[1:]}
    assert by_subject["Minimum password length"][7:9] == ["8", "14"]
    assert by_subject["Minimum password length"][10:12] == [
        "before.xml Computer/Registry/Policy[0]",
        "after.jsonl line 4",
    ]


def test_csv_serialises_values_and_picks_the_source_side(rich_report: dict[str, Any]) -> None:
    by_subject = {row[6]: row for row in rows_of(r.render_csv(rich_report))[1:]}
    assert by_subject["user half"][7:9] == ["true", "false"]
    assert by_subject["Account lockout"][7:9] == ["", "5"]
    assert by_subject["Legacy flag"][7:9] == ["on", ""]
    assert by_subject["Empty things"][7:9] == ["", "[]"]
    assert by_subject["Rights"][7] == json.dumps([SID_ADMINS, SID_STAFF], separators=(",", ":"))
    assert by_subject["Service"][8] == (
        '{"startup":"Automatic","sddl":null,"acl":{"ace":["a","b"],"n":2}}'
    )
    assert by_subject["Nothing"][7:9] == ["{}", "[[],{}]"]
    # Two sources: before first. One source: the side that holds the item.
    assert by_subject["Account lockout"][10:12] == [
        "before.xml Computer/Registry/Policy[0]",
        "after.jsonl line 4",
    ]
    assert by_subject["Legacy flag"][10:12] == ["before.xml Computer/Registry", ""]
    assert by_subject["Staff"][10:12] == ["", "after.jsonl Permissions[2]"]
    assert by_subject["query"][10:12] == ["", ""]
    # More than two: the rest follow the after source.
    assert by_subject["Orphan area"][10:12] == [
        "before.xml Computer/Registry/Policy[0]",
        "mid x; after.jsonl line 9",
    ]
    assert by_subject["corp.example/Servers"][2:4] == ["", ""]


def test_csv_neutralises_formulas_and_keeps_full_values() -> None:
    long = "z" * 1000
    comparison = empty_comparison(
        differences=[
            diff(
                gpo_name=FORMULA,
                subject="+cmd",
                before=FORMULA,
                after="@SUM(1)",
                note="\t=x",
                area="-cmd",
                sources=(Source(FULL_EQUALS + "bad", FULL_PLUS + "x"), Source("\n=y", "")),
            ),
            diff(subject="2", before=long, after=["=a", "b"]),
            diff(subject="3", before=PAYLOAD),
            diff(subject="4", before="-1", after=-5),
        ]
    )
    text = r.render_csv(build_report(comparison, [], GENERATED, "0.1.0"))
    rows = rows_of(text)
    assert rows[1][3] == "'" + FORMULA
    assert rows[1][6] == "'+cmd"
    assert rows[1][7] == "'" + FORMULA
    assert rows[1][8] == "'@SUM(1)"
    assert rows[1][9] == "'\t=x"
    assert rows[1][5] == "'-cmd"
    assert rows[4][7:9] == ["-1", "-5"]  # a plain negative number stays a number
    assert rows[1][10].startswith("'" + FULL_EQUALS + "bad")
    assert rows[1][11] == "'=y"  # the source text is stripped, then neutralised
    assert rows[2][7] == long  # never shortened
    assert rows[2][8] == '["=a","b"]'  # JSON starts with a bracket, so it is not a formula
    assert "\x1b" not in text
    assert RLO not in text
    assert "\\u202e" in text
    for row in rows[1:4]:
        for cell in row:
            assert not cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n"))


def test_csv_with_no_differences_is_the_header_alone() -> None:
    text = r.render_csv(build_report(empty_comparison(), [], GENERATED, "0.1.0"))
    assert len(rows_of(text)) == 1


# --- writing ---------------------------------------------------------------------------------


def test_write_reports_writes_every_format_and_a_manifest(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    written = write_reports(
        rich_report, tmp_path / "out", ["csv", "md", "html", "json"], force=False
    )
    assert [p.name for p in written] == [
        "mishpat-report.json",
        "mishpat-report.md",
        "mishpat-report.html",
        "mishpat-differences.csv",
        "mishpat-manifest.json",
    ]
    assert MANIFEST_NAME == "mishpat-manifest.json"
    assert list(FILE_NAMES.values()) == [p.name for p in written[:-1]]
    manifest = json.loads(written[-1].read_text(encoding="utf-8"))
    schema_check("manifest-v1.schema.json", manifest)
    assert manifest["tool"] == {"name": "mishpat", "version": "0.1.0"}
    assert manifest["generated_at"] == rich_report["generated_at"]
    assert [f["name"] for f in manifest["files"]] == [p.name for p in written[:-1]]
    for entry, path in zip(manifest["files"], written, strict=False):
        data = path.read_bytes()
        assert entry["size"] == len(data)
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert manifest["inputs"] == [
        {"name": "before.xml", "size": 4096, "sha256": SHA},
        {"name": "after.jsonl", "size": 8192, "sha256": "b" * 64},
    ]
    assert json.loads(written[0].read_text(encoding="utf-8")) == rich_report
    assert written[3].read_bytes().count(b"\r\n") > 3


def test_the_manifest_schema_rejects_a_foreign_file_name(tmp_path: Path) -> None:
    written = write_reports(make(), tmp_path, ["md"], force=False)
    manifest = json.loads(written[-1].read_text(encoding="utf-8"))
    manifest["files"][0]["name"] = "toledot-report.md"
    with pytest.raises(ValidationError):
        schema_check("manifest-v1.schema.json", manifest)


def test_write_reports_can_choose_one_format(tmp_path: Path, rich_report: dict[str, Any]) -> None:
    written = write_reports(rich_report, tmp_path, ["md"], force=False)
    assert [p.name for p in written] == ["mishpat-report.md", "mishpat-manifest.json"]


def test_two_runs_write_identical_bytes(tmp_path: Path) -> None:
    one = write_reports(make(), tmp_path / "one", list(FILE_NAMES), force=False)
    two = write_reports(make(), tmp_path / "two", list(FILE_NAMES), force=False)
    for a, b in zip(one, two, strict=True):
        assert a.name == b.name
        assert a.read_bytes() == b.read_bytes()


def test_the_json_report_decides_whether_markdown_and_html_shorten(tmp_path: Path) -> None:
    comparison, snapshot = crowded()
    report = build_report(comparison, [], GENERATED, "0.1.0", after=snapshot)
    with_json = write_reports(report, tmp_path / "a", ["json", "md", "html", "csv"], force=False)
    without = write_reports(report, tmp_path / "b", ["md", "html", "csv"], force=False)
    for path in with_json:
        if path.suffix in {".md", ".html"}:
            assert "in the JSON report" in path.read_text(encoding="utf-8")
    for path in without:
        if path.suffix in {".md", ".html"}:
            text = path.read_text(encoding="utf-8")
            assert "JSON report" not in text
            assert "L" * 400 in text
    csv_a = (tmp_path / "a" / "mishpat-differences.csv").read_bytes()
    assert csv_a == (tmp_path / "b" / "mishpat-differences.csv").read_bytes()
    assert b"L" * 400 in csv_a
    assert len(rows_of(csv_a.decode())) == 1 + len(report["differences"])


def test_write_reports_refuses_to_overwrite_without_force(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    write_reports(rich_report, tmp_path, ["json", "md"], force=False)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    other = make(empty_comparison())
    with pytest.raises(MishpatError, match="already exist"):
        write_reports(other, tmp_path, ["json", "md"], force=False)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    with pytest.raises(MishpatError, match="already exist"):
        write_reports(other, tmp_path, ["csv", "md"], force=False)  # one clash is enough
    assert not (tmp_path / "mishpat-differences.csv").exists()
    write_reports(other, tmp_path, ["json", "md"], force=True)
    assert json.loads((tmp_path / "mishpat-report.json").read_text(encoding="utf-8")) == other
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".mishpat-")]
    assert leftovers == []


def test_write_reports_is_all_or_nothing(tmp_path: Path, rich_report: dict[str, Any]) -> None:
    (tmp_path / "mishpat-report.md").mkdir()
    with pytest.raises(MishpatError, match="is a directory"):
        write_reports(rich_report, tmp_path, ["json", "md"], force=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["mishpat-report.md"]


def test_write_reports_rejects_unknown_or_no_formats(
    tmp_path: Path, rich_report: dict[str, Any]
) -> None:
    with pytest.raises(MishpatError, match="unknown report format 'pdf'"):
        write_reports(rich_report, tmp_path, ["json", "pdf"], force=False)
    with pytest.raises(MishpatError, match="no report format"):
        write_reports(rich_report, tmp_path, [], force=False)
    assert list(tmp_path.iterdir()) == []


def test_hostile_values_survive_a_round_trip_through_every_file(tmp_path: Path) -> None:
    report = build_report(hostile_comparison(FORMULA), INPUTS, GENERATED, "0.1.0", OPTIONS)
    written = write_reports(report, tmp_path, ["json", "md", "html", "csv"], force=False)
    for path in written:
        path.read_text(encoding="utf-8")
    again = json.loads(written[0].read_text(encoding="utf-8"))
    assert again == report
    assert "\x1b" in again["notices"][0]  # the JSON keeps exact values; the others escape them
