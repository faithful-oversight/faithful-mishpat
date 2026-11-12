# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the export bundle reader and the reference writer."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import bundle
from faithful_mishpat.formats.bundle import (
    BadLineError,
    check_end,
    check_header,
    check_path,
    decode_line,
    encode,
    is_bundle,
    parse_gplink,
    read_bundle,
    som_path,
    wql,
)
from faithful_mishpat.model import Link, Scope, Source, WmiFilter
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import (
    BACKUP_A,
    BACKUP_B,
    GUID_A,
    GUID_B,
    GUID_C,
    backup_files,
    bundle_bytes,
    gplink,
    gpo_xml,
    header,
    policy,
    registry_ext,
    report_bytes,
    scope_entry,
    structure,
)

SCHEMA = json.loads(
    (Path(bundle.__file__).parent.parent / "schema" / "export-v1.schema.json").read_text("utf-8")
)
VALIDATOR = Draft202012Validator(SCHEMA)


def two_gpos(**options: object) -> dict[str, bytes]:
    a = gpo_xml(
        GUID_A,
        "A",
        computer=registry_ext(policy("PA")),
        links=(("Servers", "corp.example/Servers", True, False),),
        wmi=("Win11 only", "d"),
        **options,  # type: ignore[arg-type]
    )
    b = gpo_xml(GUID_B, "B", links=(("Gone", "corp.example/Gone", True, False),))
    return {
        **backup_files(
            GUID_A, "A", prefix=BACKUP_A, report=report_bytes(a), wmi=("Win11 only", "")
        ),
        **backup_files(GUID_B, "B", backup_id=BACKUP_B, prefix=BACKUP_B, report=report_bytes(b)),
    }


def write(tmp_path: Path, data: bytes, name: str = "export.jsonl") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def read(tmp_path: Path, data: bytes) -> bundle.BundleRead:
    return read_bundle(write(tmp_path, data), "export.jsonl")


def lines(data: bytes) -> list[bytes]:
    return data.splitlines(keepends=True)


def rebuild(parts: list[bytes], *, files: int | None = None) -> bytes:
    """Join lines (all but the end line) and append a correct end line."""
    body = b"".join(parts)
    count = files if files is not None else sum(b'"path"' in part for part in parts)
    end = {"end": True, "files": count, "sha256": hashlib.sha256(body).hexdigest()}
    return body + json.dumps(end, separators=(",", ":")).encode() + b"\n"


def file_line(path: str, data: bytes = b"x", /, **changes: object) -> bytes:
    value: dict[str, object] = {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": base64.b64encode(data).decode(),
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def head() -> bytes:
    return lines(bundle_bytes({}))[0]


STRUCT = json.dumps({"structure": structure()}, separators=(",", ":")).encode() + b"\n"


def problems_of(result: bundle.BundleRead) -> list[str]:
    return [p.reason for p in result.problems]


# --- a good bundle ------------------------------------------------------------------------


def test_round_trip(tmp_path: Path) -> None:
    link = gplink((GUID_B, 0), (GUID_C, 2), (GUID_A, 1))
    scopes = [
        scope_entry("OU=Servers,DC=corp,DC=example", link=link, blocked=True),
        scope_entry("DC=corp,DC=example", "domain", gplink((GUID_A, 0))),
        scope_entry(
            "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example", "site"
        ),
    ]
    filters = [
        {
            "id": fx.braces(fx.WMI_ID),
            "name": "Win11 only",
            "description": "d",
            "query": "SELECT * FROM Win32_OperatingSystem",
        }
    ]
    result = read(tmp_path, bundle_bytes(two_gpos(), struct_=structure(scopes, filters)))
    assert result.problems == []
    assert result.domain_wide
    assert result.context == {
        "collector": "Export-MishpatGpo.ps1 0.1.0",
        "domain": "corp.example",
        "collected at": "2026-03-04T05:06:07Z",
        "scope": "all",
    }
    by_guid = {g.guid: g for g in result.gpos}
    assert sorted(by_guid) == [GUID_A, GUID_B]
    a = by_guid[GUID_A]
    assert a.context["read from"] == "export"
    assert a.context["registry.pol"] == "read"
    assert a.source == Source(f"export.jsonl:{BACKUP_A}/gpreport.xml")
    assert a.settings[0].source == Source(
        f"export.jsonl:{BACKUP_A}/gpreport.xml", "Computer/Registry/Policy[PA]"
    )
    # Link order 1 is the LAST entry of gPLink: A is last in Servers (order 1), B first (order 3).
    assert a.links == [
        Link("corp.example/Servers", enabled=False, enforced=False, order=1),
        Link("corp.example", enabled=True, enforced=False, order=1),
    ]
    assert a.wmi_filter == WmiFilter(
        "Win11 only", "d", fx.WMI_ID, "SELECT * FROM Win32_OperatingSystem"
    )
    # B: its report link (to Gone) is not in the structure, so it has no order.
    # Its Servers link is added from the structure.
    assert by_guid[GUID_B].links == [
        Link("corp.example/Gone", enabled=True, enforced=False, order=None),
        Link("corp.example/Servers", enabled=True, enforced=False, order=3),
    ]
    assert result.scopes is not None
    servers = result.scopes["ou=servers,dc=corp,dc=example"]
    assert servers == Scope(
        "OU=Servers,DC=corp,DC=example",
        "ou",
        blocked=True,
        links=((GUID_A, False, False), (GUID_C, True, True), (GUID_B, True, False)),
        source=Source("export.jsonl", "structure scope 1"),
    )
    assert set(result.scopes) == {
        "ou=servers,dc=corp,dc=example",
        "dc=corp,dc=example",
        "cn=default-first-site-name,cn=sites,cn=configuration,dc=corp,dc=example",
    }


def test_without_a_structure_line_scopes_are_none_and_links_stay_as_reported(
    tmp_path: Path,
) -> None:
    files = backup_files(report=report_bytes(gpo_xml(links=(("S", "corp.example/S", True, True),))))
    data = encode(header(), files, {})
    parts = lines(data)[:-1]
    parts = [p for p in parts if b'"structure"' not in p]
    result = read(tmp_path, rebuild(parts))
    assert result.problems == []
    assert result.scopes is None
    assert result.gpos[0].links == [Link("corp.example/S", enabled=True, enforced=True, order=None)]


def test_a_gpo_that_has_no_report_gets_links_from_the_structure(tmp_path: Path) -> None:
    files = backup_files(report=None)
    scopes = [scope_entry("OU=Servers,DC=corp,DC=example", link=gplink((GUID_A, 2)))]
    result = read(tmp_path, bundle_bytes(files, struct_=structure(scopes)))
    (gpo,) = result.gpos
    assert gpo.links == [Link("corp.example/Servers", enabled=True, enforced=True, order=1)]
    assert any("gpreport.xml missing" in r for r in problems_of(result))


def test_a_gpo_with_no_links_has_an_empty_list_when_the_structure_is_known(tmp_path: Path) -> None:
    result = read(tmp_path, bundle_bytes(backup_files(report=None)))
    assert result.gpos[0].links == []


def test_wmi_filter_query_is_matched_by_id_only(tmp_path: Path) -> None:
    filters = [{"id": WMI_OTHER, "name": "Win11 only", "description": "", "query": "SELECT 1"}]
    result = read(tmp_path, bundle_bytes(two_gpos(), struct_=structure(filters=filters)))
    a = next(g for g in result.gpos if g.guid == GUID_A)
    assert a.wmi_filter == WmiFilter("Win11 only", "d", fx.WMI_ID, None)


WMI_OTHER = "99999999-9999-4999-8999-999999999999"


def test_header_scope_list(tmp_path: Path) -> None:
    result = read(tmp_path, bundle_bytes(two_gpos(), scope=[fx.braces(GUID_A), GUID_B.upper()]))
    assert not result.domain_wide
    assert result.context["scope"] == "2 GPOs"
    assert result.problems == []


def test_a_listed_gpo_that_is_missing_is_a_problem(tmp_path: Path) -> None:
    result = read(tmp_path, bundle_bytes(two_gpos(), scope=[GUID_A, GUID_C]))
    assert problems_of(result) == [
        f"The header lists GPO {GUID_C}, but the bundle holds no backup of it"
    ]


def test_two_backups_of_one_gpo_are_an_input_error(tmp_path: Path) -> None:
    files = {**backup_files(prefix="a", report=None), **backup_files(prefix="b", report=None)}
    with pytest.raises(InputError, match="more than one backup of GPO"):
        read(tmp_path, bundle_bytes(files))


def test_every_line_of_a_bundle_matches_the_schema() -> None:
    data = bundle_bytes(
        two_gpos(),
        scope=[GUID_A],
        struct_=structure(
            [scope_entry("OU=A,DC=corp,DC=example", link=gplink((GUID_A, 0)))],
            [{"id": fx.braces(fx.WMI_ID), "name": "n", "description": "", "query": "q"}],
        ),
    )
    for line in lines(data):
        errors = list(VALIDATOR.iter_errors(json.loads(line)))
        assert errors == [], errors
    assert is_bundle(data)
    assert data.isascii()


@pytest.mark.parametrize(
    "line",
    [
        {"mishpat_export": 2, **{k: v for k, v in header().items() if k != "mishpat_export"}},
        {**header(), "extra": 1},
        {**header(), "scope": "some"},
        {**header(), "collected_at": "yesterday"},
        {"path": "../x", "size": 0, "sha256": "0" * 64, "data": ""},
        {"path": "a\\b", "size": 0, "sha256": "0" * 64, "data": ""},
        {"path": "a/./b", "size": 0, "sha256": "0" * 64, "data": ""},
        {"path": "/abs", "size": 0, "sha256": "0" * 64, "data": ""},
        {"path": "a", "size": -1, "sha256": "0" * 64, "data": ""},
        {"path": "a", "size": 0, "sha256": "ABC", "data": ""},
        {"structure": {"scopes": []}},
        {
            "structure": {
                "scopes": [{"path": "x", "kind": "forest", "blocked": False, "gplink": ""}],
                "wmi_filters": [],
            }
        },
        {"end": False, "files": 0, "sha256": "0" * 64},
        {"end": True, "files": 0},
    ],
)
def test_the_schema_rejects_what_the_reader_rejects(line: dict[str, Any]) -> None:
    assert list(VALIDATOR.iter_errors(line))


# --- header ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda h: h.update(mishpat_export=2), "mishpat_export is not 1"),
        (lambda h: h.update(mishpat_export=True), "mishpat_export is not 1"),
        (lambda h: h.pop("domain"), "no 'domain'"),
        (lambda h: h.update(extra=1), "unknown property 'extra'"),
        (lambda h: h.update(collector="x"), "collector is not an object"),
        (lambda h: h.update(collector={"name": "x"}), "no 'version'"),
        (lambda h: h.update(collector={"name": "", "version": "1"}), "collector.name"),
        (lambda h: h.update(domain=""), "domain is not text"),
        (lambda h: h.update(domain="x" * 300), "domain is not text"),
        (lambda h: h.update(collected_at="2026-03-04"), "collected_at is not a UTC time"),
        (lambda h: h.update(collected_at="2026-13-04T05:06:07Z"), "collected_at is not a UTC time"),
        (lambda h: h.update(collected_at=5), "collected_at is not text"),
        (lambda h: h.update(scope="some"), "scope is not"),
        (lambda h: h.update(scope=5), "scope is not"),
        (lambda h: h.update(scope=["nope"]), "not a GUID"),
        (lambda h: h.update(scope=[5]), "not text"),
    ],
)
def test_bad_headers_are_input_errors(tmp_path: Path, mutate: Any, reason: str) -> None:
    value = header()
    mutate(value)
    data = json.dumps(value).encode() + b"\n"
    with pytest.raises(
        InputError, match=f"^export.jsonl is not a mishpat export bundle: .*{reason}"
    ):
        read(tmp_path, data)


@pytest.mark.parametrize(
    "first",
    [
        b"",
        b"\n",
        b"not json\n",
        b"[1]\n",
        b"\xff\xfe\n",
        b'{"a":1,"a":2}\n',
        b"NaN\n",
        b'{"x":' + b"[" * 20 + b"]" * 20 + b"}\n",
    ],
)
def test_garbage_first_lines_are_input_errors(tmp_path: Path, first: bytes) -> None:
    with pytest.raises(InputError, match="is not a mishpat export bundle"):
        read(tmp_path, first)


def test_a_first_line_over_the_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle, "MAX_LINE", 50)
    with pytest.raises(InputError, match="first line is too long"):
        read(tmp_path, head())


def test_missing_file_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=r"^cannot read nope\.jsonl"):
        read_bundle(tmp_path / "nope.jsonl", "nope.jsonl")


def test_header_scope_accepts_the_fraction_form() -> None:
    value = header()
    value["collected_at"] = "2026-03-04T05:06:07.1234567Z"
    assert check_header(json.dumps(value).encode()).collected_at == "2026-03-04T05:06:07.1234567Z"


def test_marker_detection() -> None:
    assert is_bundle(bundle.MARKER + b"1}")
    assert not is_bundle(b'{"toledot_events":1}')
    assert not is_bundle(b"<GPO")


# --- trailer --------------------------------------------------------------------------------


def test_missing_trailer_is_a_problem_and_files_are_still_read(tmp_path: Path) -> None:
    full = bundle_bytes(backup_files(report=None))
    result = read(tmp_path, b"".join(lines(full)[:-1]))
    assert len(result.gpos) == 1
    (problem,) = [p for p in result.problems if "end line" in p.reason]
    assert "cut short" in problem.reason
    assert problem.source.detail.startswith("line ")


def test_trailer_count_and_hash_mismatches(tmp_path: Path) -> None:
    parts = lines(bundle_bytes(backup_files(report=None)))
    end = json.loads(parts[-1])
    wrong_count = [*parts[:-1], json.dumps({**end, "files": end["files"] + 1}).encode() + b"\n"]
    assert any("counts" in r for r in problems_of(read(tmp_path, b"".join(wrong_count))))
    wrong_hash = [*parts[:-1], json.dumps({**end, "sha256": "0" * 64}).encode() + b"\n"]
    assert any(
        "do not match the hash" in r for r in problems_of(read(tmp_path, b"".join(wrong_hash)))
    )


def test_altered_content_is_caught_by_the_hash(tmp_path: Path) -> None:
    data = bundle_bytes(backup_files(report=None))
    altered = data.replace(b'"collector"', b'"collecter"', 1)
    # The header is checked strictly, so alter a structure value instead.
    altered = data.replace(b'"wmi_filters":[]', b'"wmi_filters": []')
    assert any("do not match the hash" in r for r in problems_of(read(tmp_path, altered)))


@pytest.mark.parametrize(
    "end",
    [
        {"end": True, "files": 0},
        {"end": True, "files": 0, "sha256": "0" * 64, "x": 1},
        {"end": False, "files": 0, "sha256": "0" * 64},
        {"end": True, "files": -1, "sha256": "0" * 64},
        {"end": True, "files": 0, "sha256": "XYZ"},
        {"end": True, "files": 0, "sha256": 5},
    ],
)
def test_invalid_trailers_are_problems(tmp_path: Path, end: dict[str, Any]) -> None:
    data = head() + STRUCT + json.dumps(end).encode() + b"\n"
    result = read(tmp_path, data)
    assert any(r.startswith("The end line is not valid") for r in problems_of(result))


def test_nothing_may_follow_the_trailer(tmp_path: Path) -> None:
    data = bundle_bytes(backup_files(report=report_bytes(gpo_xml()))) + file_line("late.txt")
    result = read(tmp_path, data)
    assert problems_of(result) == ["The file continues after its end line."]
    assert len(result.gpos) == 1


def test_a_blank_line_after_the_trailer_is_also_refused(tmp_path: Path) -> None:
    result = read(tmp_path, bundle_bytes({}) + b"\n")
    assert problems_of(result) == ["The file continues after its end line."]


def test_a_final_line_without_newline_is_fine(tmp_path: Path) -> None:
    result = read(tmp_path, bundle_bytes({}).rstrip(b"\n"))
    assert result.problems == []


def test_check_end_direct() -> None:
    assert check_end({"end": True, "files": 3, "sha256": "a" * 64}) == (3, "a" * 64)
    with pytest.raises(BadLineError):
        check_end({"end": True, "files": True, "sha256": "a" * 64})


# --- line validation ----------------------------------------------------------------------


def test_bad_lines_are_problems_and_other_lines_are_used(tmp_path: Path) -> None:
    parts = [
        head(),
        b"this is not json\n",
        b"[1,2]\n",
        b'{"a":1,"a":2}\n',
        b"\xff\xfe\n",
        b'{"x":{"y":{"z":{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}}}}\n',
        b'{"x":"\\ud800"}\n',
        b"NaN\n",
        b'{"path":"a","size":0}\n',
        file_line("good/one.txt", b"1"),
        STRUCT,
    ]
    result = read(tmp_path, rebuild(parts, files=2))
    reasons = problems_of(result)
    assert reasons[0] == "The line is not valid: the line is not valid JSON."
    assert "the line is not a JSON object" in reasons[1]
    assert "repeated" in reasons[2]
    assert "not UTF-8" in reasons[3]
    assert "nested too deeply" in reasons[4]
    assert "unpaired surrogate" in reasons[5]
    assert "NaN is not JSON" in reasons[6]
    assert "The file was not read: the line has no 'data'" in reasons[7]
    # Bad lines are part of the hash and not of the count, so there are no other problems.
    assert len(reasons) == 8
    assert result.problems[0].source == Source("export.jsonl", "line 2")
    assert result.scopes == {}


def test_a_deeply_nested_line_that_overflows_the_json_parser_is_a_problem(tmp_path: Path) -> None:
    deep = b'{"x":' + b"[" * 100_000 + b"]" * 100_000 + b"}\n"
    result = read(tmp_path, rebuild([head(), deep, STRUCT]))
    assert any("nested too deeply" in r for r in problems_of(result))


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"path": "../evil.txt"}, "is not a relative path"),
        ({"path": "a/../../evil.txt"}, "is not a relative path"),
        ({"path": "/etc/passwd"}, "is not a relative path"),
        ({"path": "C:/Windows/x"}, "is not a relative path"),
        ({"path": "a\\b"}, "is not a relative path"),
        ({"path": "a//b"}, "is not a relative path"),
        ({"path": "a/"}, "is not a relative path"),
        ({"path": "./a"}, "is not a relative path"),
        ({"path": "a/\x01b"}, "is not a relative path"),
        ({"path": "a/\x7fb"}, "is not a relative path"),
        ({"path": ""}, "path is not text"),
        ({"path": "x" * 600}, "path is not text"),
        ({"path": 5}, "path is not text"),
        ({"size": 2}, "the file has 1 bytes, not the 2"),
        ({"size": -1}, "size is not a whole number"),
        ({"size": True}, "size is not a whole number"),
        ({"size": "1"}, "size is not a whole number"),
        ({"size": 10**12}, "size is not a whole number"),
        ({"sha256": "0" * 64}, "do not match its sha256"),
        ({"sha256": "A" * 64}, "64 lower-case hex digits"),
        ({"sha256": 7}, "64 lower-case hex digits"),
        ({"data": "!!!!"}, "data is not base64"),
        ({"data": 5}, "data is not base64"),
        ({"data": None}, "data is not base64"),
        ({"extra": 1}, "unknown property 'extra'"),
    ],
)
def test_bad_file_lines_are_problems_and_nothing_is_stored(
    tmp_path: Path, changes: dict[str, object], reason: str
) -> None:
    result = read(tmp_path, rebuild([head(), file_line("a.txt", **changes), STRUCT]))
    assert [r for r in problems_of(result) if reason in r], problems_of(result)
    assert result.gpos == []
    assert len(result.problems) == 1  # the count and hash still match


def test_path_traversal_never_reaches_the_tree_or_the_disk(tmp_path: Path) -> None:
    evil = backup_files(prefix="../escape", report=None)
    parts = [head()] + [file_line(path, data) for path, data in evil.items()] + [STRUCT]
    result = read(tmp_path, rebuild(parts))
    assert result.gpos == []
    assert len(result.problems) == len(evil)
    assert not (tmp_path.parent / "escape").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["export.jsonl"]


def test_paths_must_be_unique_without_regard_to_case(tmp_path: Path) -> None:
    files = {**backup_files(report=report_bytes(gpo_xml())), "bkupInfo.XML": b"other"}
    parts = [head()] + [file_line(path, data) for path, data in files.items()] + [STRUCT]
    result = read(tmp_path, rebuild(parts))
    assert len(result.gpos) == 1  # the first one wins
    (problem,) = result.problems
    assert "repeats an earlier path" in problem.reason
    assert problem.source == Source("export.jsonl", f"line {2 + len(files) - 1}")


def test_a_path_cannot_be_both_a_file_and_a_folder(tmp_path: Path) -> None:
    for first, second in (("a", "a/b"), ("a/b", "a"), ("A/b", "a")):
        parts = [head(), file_line(first), file_line(second), STRUCT]
        reasons = problems_of(read(tmp_path, rebuild(parts)))
        assert len(reasons) == 1
        assert "repeats an earlier path" in reasons[0] or "is inside a file" in reasons[0]


def test_limits_on_files_and_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parts = [head(), file_line("a", b"12"), file_line("b", b"34"), file_line("c", b"5"), STRUCT]
    monkeypatch.setattr(bundle, "MAX_TOTAL", 4)
    assert any("more files or bytes" in r for r in problems_of(read(tmp_path, rebuild(parts))))
    monkeypatch.setattr(bundle, "MAX_TOTAL", 100)
    monkeypatch.setattr(bundle, "MAX_FILES", 2)
    result = read(tmp_path, rebuild(parts, files=2))
    assert any("more files or bytes" in r for r in problems_of(result))


def test_a_line_over_the_limit_stops_the_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = file_line("big.txt", b"x" * 400)
    monkeypatch.setattr(bundle, "MAX_LINE", len(head()) + 10)
    data = head() + big + file_line("after.txt", b"y")
    result = read(tmp_path, data)
    assert problems_of(result) == [
        f"The line is longer than {len(head()) + 10} bytes; the rest is not read."
    ]
    assert result.gpos == []


def test_a_bad_line_is_part_of_the_hash_so_it_is_not_reported_twice(tmp_path: Path) -> None:
    result = read(tmp_path, rebuild([head(), b"garbage\n", STRUCT]))
    assert len(result.problems) == 1


# --- structure ----------------------------------------------------------------------------


def structure_line(value: object) -> bytes:
    return json.dumps({"structure": value}, separators=(",", ":")).encode() + b"\n"


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ([], "is not {"),
        ({"scopes": []}, "is not {"),
        ({"scopes": [], "wmi_filters": [], "x": 1}, "is not {"),
        ({"scopes": {}, "wmi_filters": []}, "must be lists"),
        ({"scopes": [], "wmi_filters": "x"}, "must be lists"),
    ],
)
def test_a_bad_structure_line_is_a_problem_and_scopes_stay_unknown(
    tmp_path: Path, value: object, reason: str
) -> None:
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert [r for r in problems_of(result) if reason in r]
    assert result.scopes is None
    assert len(result.problems) == 1


def test_an_oversized_structure_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle, "MAX_STRUCTURE", 1)
    value = structure([scope_entry("DC=a", "domain"), scope_entry("DC=b", "domain")])
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert "more than 1 entries" in problems_of(result)[0]
    assert result.scopes is None


def test_a_second_structure_line_is_not_used(tmp_path: Path) -> None:
    first = structure([scope_entry("DC=corp,DC=example", "domain")])
    second = structure([scope_entry("DC=other,DC=example", "domain")])
    result = read(
        tmp_path, rebuild([head(), structure_line(first), structure_line(second)], files=0)
    )
    assert problems_of(result) == ["A second structure line was not used"]
    assert result.scopes is not None
    assert list(result.scopes) == ["dc=corp,dc=example"]


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("x", "the entry is not an object"),
        ({"path": "a"}, "no 'blocked'"),
        (
            {"path": "a", "kind": "forest", "blocked": False, "gplink": ""},
            "kind is not domain, ou or site",
        ),
        (
            {"path": "a", "kind": "ou", "blocked": "no", "gplink": ""},
            "blocked is not true or false",
        ),
        ({"path": "", "kind": "ou", "blocked": False, "gplink": ""}, "path is not text"),
        ({"path": "a", "kind": "ou", "blocked": False, "gplink": 5}, "gplink is not text"),
    ],
)
def test_bad_scope_entries_are_skipped_with_a_problem(
    tmp_path: Path, entry: object, reason: str
) -> None:
    good = scope_entry("OU=Good,DC=corp,DC=example")
    value = {"scopes": [entry, good], "wmi_filters": []}
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert [
        p
        for p in result.problems
        if reason in p.reason and p.reason.startswith("A scope was skipped")
    ]
    assert result.problems[0].source == Source("export.jsonl", "structure scope 1")
    assert result.scopes is not None
    assert list(result.scopes) == ["ou=good,dc=corp,dc=example"]


def test_a_repeated_scope_is_skipped(tmp_path: Path) -> None:
    value = structure([scope_entry("OU=A,DC=x"), scope_entry("ou=a,dc=x")])
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert "appears twice" in problems_of(result)[0]
    assert result.scopes is not None
    assert len(result.scopes) == 1


def test_a_malformed_gplink_keeps_the_scope_without_links(tmp_path: Path) -> None:
    value = structure([scope_entry("OU=A,DC=corp,DC=example", link="[LDAP://cn=oops;0]")])
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert (
        "The links of 'OU=A,DC=corp,DC=example' were not read: malformed gPLink entry"
        in problems_of(result)[0]
    )
    assert result.scopes is not None
    assert result.scopes["ou=a,dc=corp,dc=example"].links == ()


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        (5, "the entry is not an object"),
        ({"id": GUID_A}, "no 'description'"),
        ({"id": "nope", "name": "n", "description": "", "query": ""}, "id is not a GUID"),
        ({"id": GUID_A, "name": "", "description": "", "query": ""}, "name is not text"),
        ({"id": GUID_A, "name": "n", "description": "", "query": 5}, "query is not text"),
    ],
)
def test_bad_wmi_filter_entries_are_skipped_with_a_problem(
    tmp_path: Path, entry: object, reason: str
) -> None:
    value = {"scopes": [], "wmi_filters": [entry]}
    result = read(tmp_path, rebuild([head(), structure_line(value)]))
    assert result.problems[0].reason.startswith("A WMI filter was skipped")
    assert reason in result.problems[0].reason
    assert result.problems[0].source == Source("export.jsonl", "structure wmi filter 1")


def test_a_structure_line_with_extra_keys_is_a_file_line_and_so_a_problem(tmp_path: Path) -> None:
    line = json.dumps({"structure": structure(), "x": 1}).encode() + b"\n"
    result = read(tmp_path, rebuild([head(), line], files=1))
    assert "The file was not read" in problems_of(result)[0]


# --- gPLink and DNs -----------------------------------------------------------------------


def test_parse_gplink_gives_listed_order_enforced_and_disabled() -> None:
    value = (
        f"[LDAP://cn={{{GUID_A.upper()}}},cn=policies,cn=system,DC=corp,DC=example;0]"
        f"[LDAP://cn={{{GUID_B}}},cn=policies,cn=system,DC=corp,DC=example;1]"
        f"[LDAP://cn={{{GUID_C}}},cn=policies,cn=system,DC=corp,DC=example;3]"
        f"[LDAP://cn={{{GUID_C}}},cn=policies,cn=system,DC=corp,DC=example;6] "
    )
    assert parse_gplink(value) == [
        (GUID_A, False, False),
        (GUID_B, False, True),
        (GUID_C, True, True),
        (GUID_C, True, False),
    ]
    assert parse_gplink("") == []
    assert parse_gplink("  ") == []


@pytest.mark.parametrize(
    "value",
    [
        "LDAP://cn={x};0",
        "[LDAP://cn={x}]",
        "[LDAP://cn=nothing;0]",
        "[LDAP://cn={not-a-guid};0]",
        f"[LDAP://cn={{{GUID_A}}};abc]",
        f"[LDAP://cn={{{GUID_A}}};-1]",
        f"[LDAP://cn=}}{GUID_A}{{;0]",
    ],
)
def test_parse_gplink_refuses_malformed_entries(value: str) -> None:
    with pytest.raises(ValueError, match="malformed gPLink entry"):
        parse_gplink(value)


@pytest.mark.parametrize(
    ("dn", "kind", "expected"),
    [
        ("DC=corp,DC=example", "domain", "corp.example"),
        ("OU=Servers,DC=corp,DC=example", "ou", "corp.example/Servers"),
        ("OU=Web,OU=Servers,DC=corp,DC=example", "ou", "corp.example/Servers/Web"),
        ("ou=web\\, east,dc=corp,dc=example", "ou", "corp.example/web, east"),
        (
            "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example",
            "site",
            "Default-First-Site-Name",
        ),
        ("OU=A\\2CB,DC=corp,DC=example", "ou", "corp.example/A,B"),
        ("OU=caf\\C3\\A9,DC=corp,DC=example", "ou", "corp.example/caf\u00e9"),
        ("OU=Trail\\ ,DC=corp,DC=example", "ou", "corp.example/Trail "),
        ("OU=  padded  ,DC=corp,DC=example", "ou", "corp.example/padded"),
        ("OU=x\\\\,OU=y,DC=corp,DC=example", "ou", "corp.example/y/x\\"),
        ("OU=a\\=b,DC=corp,DC=example", "ou", "corp.example/a=b"),
        ("not a dn", "ou", "not a dn"),
        ("OU=A,garbage", "ou", "OU=A,garbage"),
    ],
)
def test_som_path(dn: str, kind: str, expected: str) -> None:
    assert som_path(dn, kind) == expected


def parm2(*queries: tuple[str, str, str], count: int | None = None) -> str:
    """An ``msWMI-Parm2`` value: the count, then each query's three lengths and fields."""
    parts = [str(len(queries) if count is None else count)]
    for language, space, text in queries:
        parts += [str(len(language)), str(len(space)), str(len(text)), language, space, text]
    return ";".join([*parts, ""])


OS_QUERY = ("WQL", "root\\CIMv2", 'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%"')


def test_wql_writes_one_query_as_namespace_and_text() -> None:
    assert wql(parm2(OS_QUERY)) == ": ".join(OS_QUERY[1:])
    assert wql("1;3;10;35;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem;") == (
        "root\\CIMv2: SELECT * FROM Win32_OperatingSystem"
    )


def test_wql_writes_each_query_on_its_own_line() -> None:
    other = ("WQL", "root\\wmi", "SELECT * FROM Foo; SELECT 2")  # the text may hold a ";"
    assert wql(parm2(OS_QUERY, other)) == "\n".join(": ".join(q[1:]) for q in (OS_QUERY, other))


def test_wql_keeps_quotes_and_empty_fields() -> None:
    assert wql(parm2(("WQL", "root\\cimv2", "x"))) == "root\\cimv2: x"
    assert wql(parm2(("WQL", "", "SELECT 1"))) == ": SELECT 1"
    assert wql(parm2(("WQL", "root\\cimv2", ""))) == "root\\cimv2: "


def test_wql_ignores_white_space_after_the_last_query() -> None:
    assert wql(parm2(("WQL", "root\\cimv2", "x")) + "\r\n ") == "root\\cimv2: x"


@pytest.mark.parametrize(
    "malformed",
    [
        "",  # empty
        "   ",
        ";",
        "SELECT * FROM Win32_OperatingSystem",  # a plain query, not the attribute's layout
        "x;3;10;5;WQL;root\\CIMv2;SELECT 1;",  # non-numeric count
        "1.5;3;10;8;WQL;root\\CIMv2;SELECT 1;",
        "0;",  # a count of none holds no query
        "-1;",
        "2;" + parm2(("WQL", "root\\cimv2", "x"), count=1).split(";", 1)[1],  # count too high
        "1;3;10;8;WQL;root\\CIMv2;SELECT 1;WQL;root\\CIMv2;SELECT 2;",  # trailing query
        "1;3;10;8;WQL;root\\CIMv2;SELECT 1;junk",  # trailing junk
        "1;3;10;8;WQL;root\\CIMv2;SELECT 1",  # no closing separator
        "1;3;10;8;WQLroot\\CIMv2;SELECT 1;",  # no separator after the language
        "1;3;10;8;WQL;root\\CIMv2SELECT 1;",  # no separator after the namespace
        "1;3;10;9;WQL;root\\CIMv2;SELECT 1;",  # text length too long
        "1;3;10;7;WQL;root\\CIMv2;SELECT 1;",  # text length too short
        "1;3;9;8;WQL;root\\CIMv2;SELECT 1;",  # namespace length too short
        "1;3;11;8;WQL;root\\CIMv2;SELECT 1;",  # namespace length too long
        "1;2;10;8;WQL;root\\CIMv2;SELECT 1;",  # language length too short
        "1;4;10;8;WQL;root\\CIMv2;SELECT 1;",  # language length too long
        "1;3;10;-8;WQL;root\\CIMv2;SELECT 1;",  # negative length
        "1;-1;10;8;WQL;root\\CIMv2;SELECT 1;",
        "1;3;10;a;WQL;root\\CIMv2;SELECT 1;",  # non-numeric length
        "1;3;10;",  # lengths with no fields
        "1;3;10;8",
        "1;3;10",  # a missing length
        "1;",  # a count with no query
        "1",
    ],
)
def test_wql_returns_anything_that_is_not_the_layout_unchanged(malformed: str) -> None:
    assert wql(malformed) == malformed


def test_wql_returns_the_value_unchanged_when_a_later_query_is_malformed() -> None:
    good = parm2(OS_QUERY, ("WQL", "root\\wmi", "SELECT 1"))
    broken = good[:-3] + ";"  # the second query's text is now shorter than its length
    assert wql(broken) == broken


def test_a_bundle_writes_wmi_filter_queries_as_namespace_and_text(tmp_path: Path) -> None:
    filters = [
        {
            "id": fx.braces(fx.WMI_ID),
            "name": "Win11 only",
            "description": "d",
            "query": parm2(OS_QUERY),
        }
    ]
    result = read(tmp_path, bundle_bytes(two_gpos(), struct_=structure(filters=filters)))
    a = next(g for g in result.gpos if g.guid == GUID_A)
    assert a.wmi_filter == WmiFilter("Win11 only", "d", fx.WMI_ID, ": ".join(OS_QUERY[1:]))


# --- paths ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", ["a", "a/b.txt", "DomainSysvol/GPO/Machine/registry.pol", "with space/x y"]
)
def test_good_paths(path: str) -> None:
    assert check_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "..",
        "../a",
        "a/..",
        "a/../b",
        "/a",
        "a//b",
        ".",
        "a/.",
        "a\\b",
        "c:x",
        "a\x00b",
        "a\nb",
        5,
        None,
    ],
)
def test_bad_paths(path: object) -> None:
    with pytest.raises(BadLineError):
        check_path(path)


# --- writing ----------------------------------------------------------------------------------


def test_encode_writes_compact_ascii_json_lines_with_a_correct_trailer() -> None:
    data = encode(header(domain="caf\u00e9.example"), {"a/b.txt": b"\xff\x00"}, structure())
    assert data.isascii()
    assert data.startswith(bundle.MARKER)
    parts = lines(data)
    assert len(parts) == 4
    end = json.loads(parts[-1])
    assert end == {
        "end": True,
        "files": 1,
        "sha256": hashlib.sha256(b"".join(parts[:-1])).hexdigest(),
    }
    file = json.loads(parts[1])
    assert base64.b64decode(file["data"]) == b"\xff\x00"
    assert check_header(parts[0]).domain == "caf\u00e9.example"
    assert decode_line(parts[2]) == {"structure": structure()}


def test_encode_needs_the_marker_key_first() -> None:
    with pytest.raises(ValueError, match="first key must be mishpat_export"):
        encode({"domain": "x", "mishpat_export": 1}, {}, {})


# --- property tests -------------------------------------------------------------------------


@given(st.binary(max_size=400))
def test_arbitrary_bytes_after_a_valid_header_never_raise(tail: bytes) -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "b.jsonl"
        path.write_bytes(head() + tail)
        result = read_bundle(path, "b.jsonl")
    assert result.problems


@given(
    st.dictionaries(
        st.text(max_size=8),
        st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=12)),
        max_size=6,
    )
)
def test_arbitrary_objects_as_lines_never_raise(value: dict[str, object]) -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "b.jsonl"
        path.write_bytes(head() + json.dumps(value).encode() + b"\n")
        assert read_bundle(path, "b.jsonl").problems


# --- gaps in the structure -----------------------------------------------------------------


def test_gaps_become_problems_so_the_comparison_is_incomplete(tmp_path: Path) -> None:
    value = {
        **structure(),
        "gaps": [
            {"what": "Sites", "reason": "Access is denied"},
            {"what": "OU=Locked,DC=corp,DC=example", "reason": "no permission to read gPLink"},
        ],
    }
    result = read(tmp_path, rebuild([head(), structure_line(value)], files=0))
    assert [(p.source.detail, p.reason) for p in result.problems] == [
        ("structure gap 1", "Sites was not read: Access is denied"),
        (
            "structure gap 2",
            "OU=Locked,DC=corp,DC=example was not read: no permission to read gPLink",
        ),
    ]
    assert result.scopes == {}  # the structure itself is still used


def test_an_empty_gaps_list_is_fine(tmp_path: Path) -> None:
    result = read(tmp_path, rebuild([head(), structure_line({**structure(), "gaps": []})], files=0))
    assert result.problems == []


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("Sites", "the entry is not an object"),
        ({"what": "Sites"}, "no 'reason'"),
        ({"what": "Sites", "reason": "x", "more": 1}, "unknown property 'more'"),
        ({"what": 5, "reason": "x"}, "what is not text"),
        ({"what": "Sites", "reason": ""}, "reason is not text"),
        ({"what": "", "reason": "x"}, "what is not text"),
    ],
)
def test_malformed_gap_entries_are_problems(tmp_path: Path, entry: object, reason: str) -> None:
    value = {**structure(), "gaps": [entry]}
    result = read(tmp_path, rebuild([head(), structure_line(value)], files=0))
    (problem,) = result.problems
    assert problem.reason.startswith("A gap entry was skipped")
    assert reason in problem.reason


def test_gaps_that_is_not_a_list_rejects_the_structure(tmp_path: Path) -> None:
    result = read(tmp_path, rebuild([head(), structure_line({**structure(), "gaps": {}})], files=0))
    assert "must be lists" in problems_of(result)[0]
    assert result.scopes is None


def test_the_schema_knows_gaps() -> None:
    good = {"structure": {**structure(), "gaps": [{"what": "Sites", "reason": "denied"}]}}
    assert list(VALIDATOR.iter_errors(good)) == []
    for bad in (
        {"structure": {**structure(), "gaps": [{"what": "Sites"}]}},
        {"structure": {**structure(), "gaps": [{"what": "Sites", "reason": "x", "y": 1}]}},
        {"structure": {**structure(), "gaps": "none"}},
        {"structure": {**structure(), "other": []}},
    ):
        assert list(VALIDATOR.iter_errors(bad))
