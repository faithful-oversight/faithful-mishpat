# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The committed example in examples/ is exactly what the current code produces."""

from __future__ import annotations

import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from faithful_core.exitcodes import ExitCode
from jsonschema import FormatChecker
from jsonschema.validators import validator_for

from faithful_mishpat import example
from faithful_mishpat.cli import main
from faithful_mishpat.differences import CATEGORIES
from faithful_mishpat.formats import bundle
from faithful_mishpat.outputs import FILE_NAMES, MANIFEST_NAME

if TYPE_CHECKING:
    from collections.abc import Iterator

    import pytest

EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "corp-example"
SAMPLE_DIR = EXAMPLE_DIR / "sample-report"
INPUTS = [EXAMPLE_DIR / name for name in example.NAMES]
GENERATED = "1794225600"  # 2026-11-09T12:00:00Z, the SOURCE_DATE_EPOCH the sample used
REPORTS = [FILE_NAMES[key] for key in ("json", "md", "html", "csv")]
REGENERATE = (
    "is out of date. Regenerate it as examples/README.md shows, review the difference, "
    "and commit it"
)
# Every kind of difference the example must show, as (category, kind).
EXPECTED = {
    ("gpo", "added"),
    ("gpo", "removed"),
    ("gpo", "renamed"),
    ("status", "changed"),
    ("wmi-filter", "changed"),
    ("security-filtering", "added"),
    ("permissions", "removed"),
    ("link", "added"),
    ("link", "changed"),
    ("inheritance", "changed"),
    ("setting", "added"),
    ("setting", "removed"),
    ("setting", "changed"),
}
AREAS = {"Administrative Templates", "Security", "Advanced Audit", "Registry.pol"}


def stable(directory: Path, name: str) -> str:
    """Read an output with the tool version, which changes every release, replaced."""
    report = json.loads((directory / FILE_NAMES["json"]).read_text(encoding="utf-8"))
    version = re.escape(report["tool"]["version"])
    text = (directory / name).read_bytes().decode("utf-8")
    return re.sub(rf'(mishpat |"version": "){version}', r"\1<version>", text)


def committed() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (SAMPLE_DIR / FILE_NAMES["json"]).read_text(encoding="utf-8")
    )
    return document


def lines(path: Path) -> Iterator[dict[str, Any]]:
    for line in path.read_bytes().splitlines():
        found: dict[str, Any] = json.loads(line)
        yield found


def validator(name: str) -> Any:
    text = files("faithful_mishpat").joinpath("schema", name).read_text(encoding="utf-8")
    definition = json.loads(text)
    return validator_for(definition)(definition, format_checker=FormatChecker())


def test_the_example_command_writes_the_committed_inputs(tmp_path: Path) -> None:
    assert main(["example", str(tmp_path)]) == ExitCode.OK
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(p.name for p in INPUTS)
    for path in INPUTS:
        assert (tmp_path / path.name).read_bytes() == path.read_bytes(), f"{path.name} {REGENERATE}"


def test_the_sample_reports_are_what_the_code_produces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", GENERATED)
    assert main(["compare", *map(str, INPUTS), "-o", str(tmp_path)]) == ExitCode.FINDINGS
    for name in REPORTS:
        assert stable(tmp_path, name) == stable(SAMPLE_DIR, name), f"{name} {REGENERATE}"
    for directory in (tmp_path, SAMPLE_DIR):
        manifest = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            data = (directory / entry["name"]).read_bytes()
            assert (len(data), hashlib.sha256(data).hexdigest()) == (entry["size"], entry["sha256"])
        for entry, path in zip(manifest["inputs"], INPUTS, strict=True):
            assert entry["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        listed = {entry["name"] for entry in manifest["files"]} | {MANIFEST_NAME}
        assert {path.name for path in directory.iterdir()} == listed


def test_the_example_is_built_the_same_way_every_time() -> None:
    first, second = example.build(), example.build()
    assert first == second
    assert list(first) == list(example.NAMES)
    assert all(text.isascii() and text.endswith("\n") for text in first.values())


def test_every_line_of_each_example_follows_the_export_schema() -> None:
    check = validator("export-v1.schema.json")
    for path in INPUTS:
        found = list(lines(path))
        assert len(found) >= 8
        for line in found:
            check.validate(line)
        header = found[0]
        assert list(header) == ["mishpat_export", "collector", "domain", "collected_at", "scope"]
        assert header["domain"] == "corp.example"
        assert header["scope"] == "all"
        assert header["collected_at"].startswith("2026-")
        assert header["collector"] == {"name": "Export-MishpatGpo.ps1", "version": "0.1.0"}


def test_each_example_is_a_complete_export_of_one_domain() -> None:
    for path in INPUTS:
        result = bundle.read_bundle(path, path.name)
        assert result.problems == []
        assert result.domain_wide is True
        assert len(result.gpos) == 5
        assert {gpo.domain for gpo in result.gpos} == {"corp.example"}
        assert result.scopes is not None
        assert [scope.kind for scope in result.scopes.values()] == [
            "domain",
            "ou",
            "ou",
            "ou",
            "site",
        ]
        files_ = [line["path"] for line in lines(path) if "path" in line]
        assert all(p.count("/") >= 1 and p.startswith("{") for p in files_)
        assert sum(p.endswith("/gpreport.xml") for p in files_) == 5
        assert all(p == p.encode("ascii").decode() for p in files_)


def test_the_committed_report_follows_the_schema_and_is_complete() -> None:
    document = committed()
    validator("report-v1.schema.json").validate(document)
    assert document["summary"]["complete"] is True
    assert document["summary"]["differences"] == len(document["differences"]) == 27
    assert (document["summary"]["problems"], document["summary"]["gaps"]) == (0, 0)
    assert document["problems"] == document["gaps"] == document["notices"] == []
    assert [item["kind"] for item in document["inputs"]] == ["export", "export"]
    assert document["generated_at"] == "2026-11-09T12:00:00Z"


def test_the_example_shows_every_category_and_kind_of_difference() -> None:
    differences = committed()["differences"]
    seen = {(d["category"], d["kind"]) for d in differences}
    assert seen == EXPECTED
    assert {category for category, _ in seen} == set(CATEGORIES)
    assert {d["area"] for d in differences if d["category"] == "setting"} == AREAS
    assert {d["scope"] for d in differences if d["category"] == "setting"} == {"Computer"}


def test_the_example_shows_each_change_it_describes() -> None:
    differences = committed()["differences"]

    def one(category: str, **match: Any) -> dict[str, Any]:
        found: list[dict[str, Any]] = [
            d for d in differences if d["category"] == category and match.items() <= d.items()
        ]
        assert len(found) == 1, (category, match)
        return found[0]

    drop_down = one("setting", subject="Configure Automatic Updates")
    assert drop_down["kind"] == "changed"
    option = "Configure automatic updating"  # the closing colon is dropped
    assert drop_down["before"][option].startswith("3 - ")
    assert drop_down["after"][option].startswith("4 - ")
    assert drop_down["before"]["state"] == drop_down["after"]["state"] == "Enabled"
    assert {k for k in drop_down["before"] if drop_down["before"][k] != drop_down["after"][k]} == {
        option
    }  # one option changed; the rest of the policy is unchanged
    assert one("setting", area="Registry.pol", kind="changed")["after"]["data"] == 4
    directive = one(
        "setting",
        kind="added",
        subject=r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU\**del.UseWUServer",
    )
    assert directive["area"] == "Registry.pol"
    assert one("setting", subject="SeDenyNetworkLogonRight")["after"] == [
        "S-1-5-113",
        "S-1-5-32-546",
    ]
    assert one("gpo", kind="renamed")["before"] == "Workstation Baseline"
    assert one("status")["after"] == "disabled"
    assert one("wmi-filter")["before"]["query"] != one("wmi-filter")["after"]["query"]
    assert one("security-filtering")["subject"].startswith("CORP\\Pilot Workstations")
    assert one("permissions")["subject"].startswith("CORP\\Helpdesk Operators")
    assert one("inheritance")["after"] == "blocked"
    order = one("link", gpo="")
    assert order["before"] == ["Workstation Hardening", "Staff Desktop Settings"]
    assert order["after"] == ["Staff Desktop Settings", "Workstation Hardening"]
    links = [d for d in differences if d["category"] == "link" and d["gpo"]]
    assert [d["gpo_name"] for d in links if d["kind"] == "added"] == ["Baseline - Servers"]
    disabled = [d for d in links if d["after"] == {"enabled": False, "enforced": False}]
    enforced = [d for d in links if d["after"] == {"enabled": True, "enforced": True}]
    assert [d["gpo_name"] for d in disabled] == ["Staff Desktop Settings"]
    assert [d["gpo_name"] for d in enforced] == ["Workstation Hardening"]


def test_the_example_names_accounts_and_gives_security_options_their_words() -> None:
    differences = committed()["differences"]
    by_subject = {d["subject"]: d for d in differences if d["category"] == "setting"}
    assert by_subject["SeDenyNetworkLogonRight"]["labels"] == {
        "S-1-5-113": "NT AUTHORITY\\Local account",
        "S-1-5-32-546": "BUILTIN\\Guests",
    }
    level = by_subject["Network security: LAN Manager authentication level"]
    assert (level["before"], level["after"]) == (3, 5)
    assert level["labels"] == {
        "3": "Send NTLMv2 response only",
        "5": "Send NTLMv2 response only. Refuse LM & NTLM",
    }
    assert by_subject["Network access: Restrict anonymous access"]["labels"] == {"1": "Enabled"}
    assert by_subject["LockoutBadCount"]["labels"] == {}
    md = (SAMPLE_DIR / FILE_NAMES["md"]).read_text(encoding="utf-8")
    assert (
        "| 3 (Send NTLMv2 response only) | 5 (Send NTLMv2 response only. Refuse LM \\& NTLM) |"
        in md
    )
    assert "S-1-5-113 (NT AUTHORITY\\\\Local account), S-1-5-32-546 (BUILTIN\\\\Guests)" in md


def test_the_example_reads_as_a_review() -> None:
    document = committed()
    differences = document["differences"]
    assert document["comparison"]["before"] == "corp-before.jsonl"
    assert document["comparison"]["after"] == "corp-after.jsonl"
    # Scope-level subjects are written as paths, as GPO links are.
    scope_level = [d for d in differences if not d["gpo"]]
    assert sorted(d["subject"] for d in scope_level) == [
        "corp.example/Servers/Web",
        "corp.example/Workstations: link order",
    ]
    # A WMI filter query is readable, not the raw directory attribute.
    (wmi,) = (d for d in differences if d["category"] == "wmi-filter")
    for query in (wmi["before"]["query"], wmi["after"]["query"]):
        assert query.startswith("root\\CIMv2: SELECT ")
        assert ";WQL;" not in query
    # A GPO that was created or deleted carries its name on the side that has it.
    gpo_rows = {d["kind"]: d for d in differences if d["category"] == "gpo"}
    assert (gpo_rows["added"]["before"], gpo_rows["added"]["after"]) == (
        None,
        "Edge Browser Policy",
    )
    assert (gpo_rows["removed"]["before"], gpo_rows["removed"]["after"]) == (
        "Legacy Kiosk Lockdown", None,
    )  # fmt: skip
    md = (SAMPLE_DIR / FILE_NAMES["md"]).read_text(encoding="utf-8")
    assert "## Domain structure" in md
    assert "Scope inheritance" not in md
    assert "(not set) | (not set)" not in md
    assert "| Configure Automatic Updates | changed | Configure automatic updating: 3 - " in md
    assert "Scheduled install day" not in md  # unchanged options of the policy are left out
    assert '| type: REG_SZ; data: " " |' in md.replace("REG\\_SZ", "REG_SZ")


def test_a_reordered_user_right_and_an_unchanged_gpo_show_no_difference() -> None:
    document = committed()
    assert all(d["subject"] != "SeNetworkLogonRight" for d in document["differences"])
    (quiet,) = (g for g in document["gpos"] if g["status"] == "unchanged")
    assert quiet["name"] == "Default Domain Policy"
    assert quiet["differences"] == 0
    assert sorted(g["status"] for g in document["gpos"]) == [
        "added", "changed", "changed", "changed", "removed", "unchanged",
    ]  # fmt: skip


def test_the_readme_describes_the_example_it_sits_next_to() -> None:
    readme = (EXAMPLE_DIR.parent / "README.md").read_text(encoding="utf-8")
    summary = committed()["summary"]
    assert f"{summary['differences']} differences" in readme
    for name in (
        *example.NAMES,
        "SeNetworkLogonRight",
        "**del.UseWUServer",
        "Workstation Baseline",
    ):
        assert name in readme
    for gpo in committed()["gpos"]:
        assert f"`{gpo['name']}`" in readme
