# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Regressions from the independent review of 0.1.0.

Evidence that is missing, ambiguous or contradictory must never become a difference, a
silence, or a leak.

Each test runs the whole command and reads what it wrote, so the rule is checked where
an operator sees it, not only in the internal model.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import pytest

from faithful_mishpat.cli import ExitCode, main
from faithful_mishpat.formats import hidden, xmlsafe
from faithful_mishpat.formats.report import canonical
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import (
    backup_files,
    dword,
    extension,
    gpo_xml,
    policy,
    registry_ext,
    registry_pol,
    report_bytes,
    write_tree,
)

if TYPE_CHECKING:
    from pathlib import Path

PROBE = "SYNTHETIC-REDACTION-PROBE"
POL = [("Software\\Policies\\Example", "Level", 4, dword(2))]
SETTING = registry_ext(policy("Prevent example", "Enabled"))


def run(tmp_path: Path, before: Path, after: Path) -> tuple[int, dict[str, Any], str]:
    """Compare two inputs; return the exit code, the JSON report and every output's text."""
    out = tmp_path / "out"
    code = main(["compare", str(before), str(after), "-o", str(out), "--fail-on", "never"])
    texts = "\n".join(
        p.read_bytes().decode("utf-8", "replace") for p in sorted(out.iterdir()) if p.is_file()
    )
    return code, json.loads((out / "mishpat-report.json").read_text("utf-8")), texts


def kinds(report: dict[str, Any]) -> list[tuple[str, str]]:
    return [(d["category"], d["kind"]) for d in report["differences"]]


def backup(root: Path, **options: Any) -> Path:
    write_tree(root, backup_files(**options))
    return root


# --- F1: a stored password never leaks, whatever its shape -----------------------------


@pytest.mark.parametrize(
    "xml",
    [
        f'<cpassword encoding="opaque">{PROBE}</cpassword>',
        f"<cpassword><part>{PROBE}</part></cpassword>",
        f"<cpassword>start<b/>{PROBE}</cpassword>",
        f'<q:cPassword xmlns:q="urn:x">{PROBE}</q:cPassword>',
    ],
)
def test_a_stored_password_element_of_any_shape_is_hidden(xml: str) -> None:
    value = canonical(xmlsafe.parse(f"<Properties>{xml}</Properties>".encode()))
    assert PROBE not in json.dumps(value)
    assert hidden.conceal(value) == {
        "cpassword" if "cpassword" in xml else "cPassword": hidden.SHOWN
    }


def test_a_namespaced_cpassword_attribute_is_hidden() -> None:
    value = canonical(
        xmlsafe.parse(f'<Properties xmlns:q="urn:x" q:cpassword="{PROBE}"/>'.encode())
    )
    assert PROBE not in json.dumps(value)
    assert hidden.conceal(value) == {"@{urn:x}cpassword": hidden.SHOWN}


def test_an_attributed_password_element_never_reaches_any_output(tmp_path: Path) -> None:
    def item(secret: str) -> str:
        return extension(
            "Misc",
            '<q1:Things clsid="{C}"><q1:Thing clsid="{D}" name="t" uid="{U}">'
            f'<q1:Properties><q1:cpassword encoding="opaque">{secret}</q1:cpassword>'
            "</q1:Properties></q1:Thing></q1:Things>",
        )

    (tmp_path / "a.xml").write_bytes(report_bytes(gpo_xml(computer=item(PROBE + "-1"))))
    (tmp_path / "b.xml").write_bytes(report_bytes(gpo_xml(computer=item(PROBE + "-2"))))
    _, report, texts = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert PROBE not in texts
    assert "A stored password changed" in texts
    assert report["differences"]


# --- F2: missing or unreadable evidence is never "added" or "removed" ------------------


def test_a_backup_without_its_report_does_not_remove_its_settings(tmp_path: Path) -> None:
    full = backup(tmp_path / "full", report=fx.report_bytes(gpo_xml(computer=SETTING)))
    bare = backup(tmp_path / "bare", report=None)
    for before, after in ((full, bare), (bare, full)):
        _, report, _ = run(tmp_path / f"{before.name}-{after.name}", before, after)
        assert ("setting", "removed") not in kinds(report)
        assert ("setting", "added") not in kinds(report)
        assert any("in one input only" in g["subject"] for g in report["gaps"])
        assert report["problems"]


def test_a_report_without_its_computer_section_is_incomplete(tmp_path: Path) -> None:
    whole = gpo_xml(computer=SETTING)
    start, end = whole.index("<Computer>"), whole.index("</Computer>") + len("</Computer>")
    (tmp_path / "a.xml").write_bytes(report_bytes(whole))
    (tmp_path / "b.xml").write_bytes(report_bytes(whole[:start] + whole[end:]))
    code, report, _ = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert ("setting", "removed") not in kinds(report)
    assert report["comparison"]["complete"] is False
    assert any("no Computer section" in p["reason"] for p in report["problems"])
    assert code == ExitCode.OK  # --fail-on never


def test_a_genuinely_deleted_setting_is_still_removed(tmp_path: Path) -> None:
    (tmp_path / "a.xml").write_bytes(report_bytes(gpo_xml(computer=SETTING)))
    (tmp_path / "b.xml").write_bytes(report_bytes(gpo_xml()))
    _, report, _ = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert ("setting", "removed") in kinds(report)
    assert report["comparison"]["complete"] is True


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs symlinks")
def test_a_linked_registry_pol_does_not_remove_its_values(tmp_path: Path) -> None:
    before = backup(
        tmp_path / "before", report=report_bytes(gpo_xml()), machine_pol=registry_pol(POL)
    )
    after = backup(
        tmp_path / "after", report=report_bytes(gpo_xml()), machine_pol=registry_pol(POL)
    )
    real = next(p for p in after.rglob("*") if p.name.lower() == "registry.pol")
    outside = tmp_path / "outside.pol"
    outside.write_bytes(real.read_bytes())
    real.unlink()
    real.symlink_to(outside)
    _, report, _ = run(tmp_path, before, after)
    assert ("setting", "removed") not in kinds(report)
    assert report["comparison"]["complete"] is False
    assert any("Registry.pol" in g["subject"] for g in report["gaps"])


def test_a_deleted_registry_pol_is_still_removed(tmp_path: Path) -> None:
    before = backup(
        tmp_path / "before", report=report_bytes(gpo_xml()), machine_pol=registry_pol(POL)
    )
    after = backup(tmp_path / "after", report=report_bytes(gpo_xml(name="Servers baseline 2")))
    _, report, _ = run(tmp_path, before, after)
    assert ("setting", "removed") in kinds(report)


# --- F3: namespaced attributes count; prefixes do not ------------------------------------


def _widget(prefix: str, uri: str, mode: str) -> bytes:
    body = (
        f'<{prefix}:Widget xmlns:{prefix}="{uri}" {prefix}:mode="{mode}">'
        f"<{prefix}:Name>Mode</{prefix}:Name><{prefix}:Value>static</{prefix}:Value>"
        f"</{prefix}:Widget>"
    )
    return report_bytes(gpo_xml(computer=extension("Misc", body)))


@pytest.mark.parametrize(
    ("after", "changed"),
    [
        (("z", "urn:a", "allow"), False),  # only the prefix differs
        (("q", "urn:a", "deny"), True),  # same namespace, new value
        (("q", "urn:b", "allow"), True),  # same local name, other namespace
    ],
)
def test_namespaced_attributes_are_compared_by_namespace(
    tmp_path: Path, after: tuple[str, str, str], *, changed: bool
) -> None:
    (tmp_path / "a.xml").write_bytes(_widget("q", "urn:a", "allow"))
    (tmp_path / "b.xml").write_bytes(_widget(*after))
    if not changed:  # identical bytes would be refused as the same input
        (tmp_path / "b.xml").write_bytes(_widget(*after).replace(b"Servers", b"Servers"))
    _, report, _ = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert bool([d for d in report["differences"] if d["category"] == "setting"]) is changed


# --- F4: contradictory WMI filter records are not silently resolved ---------------------


@pytest.mark.parametrize("order", [("Changed", "Original"), ("Original", "Changed")])
def test_a_wmi_filter_recorded_twice_differently_is_a_problem(
    tmp_path: Path, order: tuple[str, str]
) -> None:
    def bundle(*queries: str) -> bytes:
        files = backup_files(
            report=report_bytes(gpo_xml(wmi=("Filter", fx.WMI_ID))), wmi=("Filter", fx.WMI_ID)
        )
        filters = [
            {
                "id": fx.WMI_ID,
                "name": "Filter",
                "description": "",
                "query": f"1;3;10;{len(q)};WQL;root\\CIMv2;{q};",
            }
            for q in queries
        ]
        return fx.bundle_bytes(files, struct_=fx.structure(filters=filters))

    (tmp_path / "a.jsonl").write_bytes(bundle("Original"))
    (tmp_path / "b.jsonl").write_bytes(bundle(*order))
    _, report, _ = run(tmp_path, tmp_path / "a.jsonl", tmp_path / "b.jsonl")
    assert report["comparison"]["complete"] is False
    assert any("appears twice with different queries" in p["reason"] for p in report["problems"])


def test_a_wmi_filter_recorded_twice_the_same_is_fine(tmp_path: Path) -> None:
    files = backup_files(report=report_bytes(gpo_xml()))
    one = {"id": fx.WMI_ID, "name": "F", "description": "", "query": "1;3;10;1;WQL;root\\CIMv2;x;"}
    upper = {**one, "id": fx.WMI_ID.upper()}
    (tmp_path / "a.jsonl").write_bytes(fx.bundle_bytes(files, struct_=fx.structure(filters=[one])))
    (tmp_path / "b.jsonl").write_bytes(
        fx.bundle_bytes(files, struct_=fx.structure(filters=[one, upper]))
    )
    _, report, _ = run(tmp_path, tmp_path / "a.jsonl", tmp_path / "b.jsonl")
    assert report["problems"] == []


# --- F5, F6: names Windows cannot tell apart are ambiguous, not a silent choice ----------


@pytest.mark.skipif(os.name == "nt", reason="needs a case-sensitive file system")
def test_two_reports_that_differ_only_in_case_are_ambiguous(tmp_path: Path) -> None:
    before = backup(tmp_path / "before", report=report_bytes(gpo_xml()))
    after = backup(tmp_path / "after", report=report_bytes(gpo_xml(computer=SETTING)))
    (after / "GPREPORT.XML").write_bytes(report_bytes(gpo_xml()))
    if len({p.name for p in after.iterdir()}) < 4:
        pytest.skip("the file system folds case")
    _, report, _ = run(tmp_path, before, after)
    assert report["comparison"]["complete"] is False
    assert any("differ only in case" in p["reason"] for p in report["problems"])


def test_a_case_variant_folder_in_a_bundle_cannot_hide_registry_pol(tmp_path: Path) -> None:
    files = backup_files(report=report_bytes(gpo_xml()), machine_pol=registry_pol(POL))
    lowered = {
        (k.lower() if k.lower().endswith("registry.pol") else k): v for k, v in files.items()
    }
    lowered["DomainSysvol/irrelevant.txt"] = b"x"
    empty = backup_files(report=report_bytes(gpo_xml(name="Servers baseline 2")))
    (tmp_path / "a.jsonl").write_bytes(fx.bundle_bytes(empty))
    (tmp_path / "b.jsonl").write_bytes(fx.bundle_bytes(lowered))
    _, report, _ = run(tmp_path, tmp_path / "a.jsonl", tmp_path / "b.jsonl")
    assert report["comparison"]["complete"] is False
    assert any("differ only in case" in p["reason"] for p in report["problems"])
    assert ("setting", "added") not in kinds(report)


# --- F7: malformed input is an input problem, never an internal error ---------------------


def test_non_ascii_base64_is_a_bad_line(tmp_path: Path) -> None:
    files = backup_files(report=report_bytes(gpo_xml()))
    good = fx.bundle_bytes(files)
    lines = good.split(b"\n")
    record = json.loads(lines[1])
    record["data"] = "é" + record["data"][1:]
    lines[1] = json.dumps(record).encode()
    body = b"\n".join(lines[:-2]) + b"\n"
    import hashlib  # noqa: PLC0415 - only this test rebuilds a trailer

    count = len(lines) - 3
    trailer = {"end": True, "files": count, "sha256": hashlib.sha256(body).hexdigest()}
    (tmp_path / "b.jsonl").write_bytes(body + json.dumps(trailer).encode() + b"\n")
    (tmp_path / "a.jsonl").write_bytes(good)
    code = main(
        ["compare", str(tmp_path / "a.jsonl"), str(tmp_path / "b.jsonl"), "-o", str(tmp_path / "o")]
    )
    assert code != ExitCode.INTERNAL_ERROR


@pytest.mark.parametrize("options", ["²", "9" * 4400])
def test_strange_option_numbers_are_ignored_not_fatal(tmp_path: Path, options: str) -> None:
    before = backup(tmp_path / "before", report=None)
    after = backup(tmp_path / "after", report=None, options=0)
    core = next(p for p in after.rglob("Backup.xml"))
    text = core.read_text("utf-8")
    core.write_text(
        text.replace(
            "<Options><![CDATA[0]]></Options>", f"<Options><![CDATA[{options}]]></Options>"
        ),
        "utf-8",
    )
    code = main(
        ["compare", str(before), str(after), "-o", str(tmp_path / "o"), "--fail-on", "never"]
    )
    assert code == ExitCode.OK


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_an_unreadable_folder_is_a_problem(tmp_path: Path) -> None:
    before = backup(tmp_path / "before", report=report_bytes(gpo_xml()))
    after = backup(
        tmp_path / "after",
        report=report_bytes(gpo_xml(name="Servers baseline 2")),
        machine_pol=registry_pol(POL),
    )
    locked = next(p for p in after.rglob("*") if p.is_dir() and p.name == "DomainSysvol")
    locked.chmod(0)
    try:
        code = main(
            ["compare", str(before), str(after), "-o", str(tmp_path / "o"), "--fail-on", "never"]
        )
    finally:
        locked.chmod(0o700)
    assert code == ExitCode.OK
    report = json.loads((tmp_path / "o" / "mishpat-report.json").read_text("utf-8"))
    assert report["comparison"]["complete"] is False


def test_a_folder_that_cannot_be_listed_is_a_problem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from faithful_mishpat.formats.backup import FolderTree, TreeError  # noqa: PLC0415

    before = backup(tmp_path / "before", report=report_bytes(gpo_xml()))
    after = backup(
        tmp_path / "after",
        report=report_bytes(gpo_xml(name="Servers baseline 2")),
        machine_pol=registry_pol(POL),
    )
    listing = FolderTree.entries

    def entries(self: FolderTree, path: str) -> list[tuple[str, bool]]:
        if self.root == after and path.casefold().startswith("domainsysvol"):
            msg = f"cannot list {path}: Permission denied"
            raise TreeError(msg)
        return listing(self, path)

    monkeypatch.setattr(FolderTree, "entries", entries)
    code = main(
        ["compare", str(before), str(after), "-o", str(tmp_path / "o"), "--fail-on", "never"]
    )
    assert code == ExitCode.OK
    report = json.loads((tmp_path / "o" / "mishpat-report.json").read_text("utf-8"))
    assert report["comparison"]["complete"] is False
    assert any("Permission denied" in p["reason"] for p in report["problems"])


# --- second recheck: R1 a password element dispatched as the root of a setting ---------


def _pair(tmp_path: Path, before: str, after: str) -> tuple[dict[str, Any], str]:
    (tmp_path / "a.xml").write_bytes(report_bytes(gpo_xml(computer=extension("Misc", before))))
    (tmp_path / "b.xml").write_bytes(report_bytes(gpo_xml(computer=extension("Misc", after))))
    _, report, texts = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    return report, texts


def test_a_password_element_that_is_a_setting_itself_never_leaks(tmp_path: Path) -> None:
    def body(secret: str) -> str:
        return f'<q1:cpassword encoding="opaque">{secret}</q1:cpassword>'

    report, texts = _pair(tmp_path, body(PROBE + "-A"), body(PROBE + "-B"))
    assert PROBE not in texts
    assert "mishpat-hidden" not in texts
    assert [(d["category"], d["kind"]) for d in report["differences"]] == [("setting", "changed")]
    assert "A stored password changed" in report["differences"][0]["note"]


# --- R3: every part of a mixed-content password counts ------------------------------------


def _mixed(secret: str, name: str = "Same") -> str:
    return (
        f"<q1:Widget><q1:Name>{name}</q1:Name><q1:Properties>"
        f"<q1:cpassword>start<q1:part/>{secret}</q1:cpassword>"
        "</q1:Properties></q1:Widget>"
    )


def test_a_change_in_the_text_after_a_child_of_a_password_is_found(tmp_path: Path) -> None:
    report, texts = _pair(tmp_path, _mixed(PROBE + "-A"), _mixed(PROBE + "-B"))
    assert PROBE not in texts
    assert [(d["category"], d["kind"]) for d in report["differences"]] == [("setting", "changed")]
    assert "A stored password changed" in report["differences"][0]["note"]


def test_the_same_mixed_content_password_is_no_change(tmp_path: Path) -> None:
    # Only the GPO name differs, so the inputs are distinct but the setting is equal.
    (tmp_path / "a.xml").write_bytes(
        report_bytes(gpo_xml(computer=extension("Misc", _mixed(PROBE))))
    )
    (tmp_path / "b.xml").write_bytes(
        report_bytes(gpo_xml(name="Servers baseline 2", computer=extension("Misc", _mixed(PROBE))))
    )
    _, report, texts = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert PROBE not in texts
    assert [d for d in report["differences"] if d["category"] == "setting"] == []


# --- R2: a setting skipped as malformed is not known to be absent ------------------------

VALID = policy("Critical setting")
DAMAGED = VALID.replace("<q1:Name>Critical setting</q1:Name>", "")


@pytest.mark.parametrize(("before", "after"), [(VALID, DAMAGED), (DAMAGED, VALID)])
def test_a_skipped_setting_is_neither_added_nor_removed(
    tmp_path: Path, before: str, after: str
) -> None:
    assert DAMAGED != VALID
    (tmp_path / "a.xml").write_bytes(report_bytes(gpo_xml(computer=registry_ext(before))))
    (tmp_path / "b.xml").write_bytes(report_bytes(gpo_xml(computer=registry_ext(after))))
    _, report, texts = run(tmp_path, tmp_path / "a.xml", tmp_path / "b.xml")
    assert [d for d in report["differences"] if d["category"] == "setting"] == []
    assert report["comparison"]["complete"] is False
    assert any("Computer settings in one input only" in g["subject"] for g in report["gaps"])
    assert "Critical setting" not in [d["subject"] for d in report["differences"]]
    assert "has no Name" in texts


def test_a_skip_in_one_half_leaves_the_other_half_and_registry_pol_compared(
    tmp_path: Path,
) -> None:
    other = registry_ext(policy("User setting"))
    before = backup(
        tmp_path / "before",
        report=report_bytes(gpo_xml(computer=registry_ext(VALID), user=other)),
        machine_pol=registry_pol(POL),
    )
    after = backup(
        tmp_path / "after",
        report=report_bytes(gpo_xml(computer=registry_ext(DAMAGED))),
    )
    _, report, _ = run(tmp_path, before, after)
    removed = [(d["scope"], d["subject"]) for d in report["differences"] if d["kind"] == "removed"]
    assert ("User", "User setting") in removed  # the undamaged half still compares
    assert any(
        d["area"] == "Registry.pol" and d["kind"] == "removed" for d in report["differences"]
    )
    assert not any(
        d["scope"] == "Computer" and d["area"] != "Registry.pol" and d["kind"] == "removed"
        for d in report["differences"]
    )
