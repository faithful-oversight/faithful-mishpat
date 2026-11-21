# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Backup-GPO reader and its two kinds of tree."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import backup
from faithful_mishpat.formats.backup import (
    FolderTree,
    MemoryTree,
    TreeError,
    find_backups,
    read_backups,
)
from faithful_mishpat.model import Gpo, Problem, Source, WmiFilter
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import (
    BACKUP_A,
    BACKUP_B,
    GUID_A,
    GUID_B,
    backup_files,
    dword,
    gpo_xml,
    policy,
    registry_ext,
    registry_pol,
    report_bytes,
    sz,
    write_tree,
)

if TYPE_CHECKING:
    from pathlib import Path

POL = [("Software\\Policies\\Example", "Level", 4, dword(2))]


def report(guid: str = GUID_A, name: str = "Servers baseline", **options: object) -> bytes:
    xml = gpo_xml(guid, name, computer=registry_ext(policy("Allow thing")), **options)  # type: ignore[arg-type]
    return report_bytes(xml)


def read_folder(tmp_path: Path, files: dict[str, bytes], name: str = "in") -> backup.BackupRead:
    write_tree(tmp_path, files)
    return read_backups(FolderTree(tmp_path), name)


def only(result: backup.BackupRead) -> Gpo:
    (gpo,) = result.gpos
    return gpo


# --- one backup folder -----------------------------------------------------------------


def test_one_folder_with_report_and_both_registry_pol_files(tmp_path: Path) -> None:
    files = backup_files(
        report=report(),
        machine_pol=registry_pol(POL),
        user_pol=registry_pol([("Software\\U", "v", 1, sz("x"))]),
    )
    result = read_folder(tmp_path, files, "baseline")
    assert result.problems == []
    gpo = only(result)
    assert gpo.guid == GUID_A
    assert gpo.links == []
    assert gpo.trustees is not None
    assert [(s.scope, s.area) for s in gpo.settings] == [
        ("Computer", "Administrative Templates"),
        ("Computer", "Registry.pol"),
        ("User", "Registry.pol"),
    ]
    assert gpo.context == {
        "created": "2026-01-02T03:04:05",
        "modified": "2026-02-03T04:05:06",
        "read from": "backup",
        "registry.pol": "read",
        "evidence:computer settings": "read",
        "evidence:user settings": "read",
        "evidence:computer registry.pol": "read",
        "evidence:user registry.pol": "read",
        "backup id": BACKUP_A,
        "backup time": "2026-03-04T05:06:07",
        "backup comment": "before the change",
    }
    assert gpo.settings[0].source == Source(
        "baseline", "gpreport.xml Computer/Registry/Policy[Allow thing]"
    )
    assert gpo.settings[1].source == Source(
        "baseline", "DomainSysvol/GPO/Machine/registry.pol entry 1"
    )


def test_no_registry_pol_files_means_no_values_not_unknown(tmp_path: Path) -> None:
    gpo = only(read_folder(tmp_path, backup_files(report=report())))
    assert gpo.context["registry.pol"] == "read"
    assert gpo.context["read from"] == "backup"
    assert [s.area for s in gpo.settings] == ["Administrative Templates"]


def test_unknown_extra_files_and_folders_are_ignored(tmp_path: Path) -> None:
    files = backup_files(
        report=report(),
        extra={
            "translation.xml": b"<x/>",
            "DomainSysvol/GPO/Machine/comment.cmtx": b"junk",
            "DomainSysvol/GPO/Machine/Preferences/Groups/Groups.xml": b"<Groups/>",
            "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf": b"[Unicode]",
        },
    )
    result = read_folder(tmp_path, files)
    assert result.problems == []
    assert len(only(result).settings) == 1


def test_lookup_ignores_case_in_every_name(tmp_path: Path) -> None:
    files = backup_files(
        report=report(),
        machine_pol=registry_pol(POL),
        names=("BKUPINFO.XML", "BACKUP.XML", "GPREPORT.XML", "Registry.POL"),
        sysvol=("domainsysvol", "gpo", "MACHINE", "user"),
    )
    gpo = only(read_folder(tmp_path, files))
    assert {s.area for s in gpo.settings} == {"Administrative Templates", "Registry.pol"}


def test_a_folder_named_like_a_file_is_not_that_file(tmp_path: Path) -> None:
    files = backup_files(report=None)
    files["gpreport.xml/inner.txt"] = b"x"
    result = read_folder(tmp_path, files)
    assert [p.reason for p in result.problems][:1] == ["gpreport.xml is a folder, not a file"]
    assert result.gpos[0].context["evidence:computer settings"] == "unreadable"


# --- a root with many ---------------------------------------------------------------------


def test_a_root_holds_many_backups_even_in_groups(tmp_path: Path) -> None:
    files = {
        **backup_files(GUID_A, "A", prefix=BACKUP_A, report=report(GUID_A, "A")),
        **backup_files(
            GUID_B, "B", backup_id=BACKUP_B, prefix=f"Group/{BACKUP_B}", report=report(GUID_B, "B")
        ),
        "manifest.xml": b"<Backups/>",
        "notes.txt": b"hi",
        "Empty/readme.txt": b"hi",
    }
    result = read_folder(tmp_path, files, "root")
    assert result.problems == []
    assert sorted(g.name for g in result.gpos) == ["A", "B"]
    by_name = {g.name: g for g in result.gpos}
    assert (
        by_name["B"].settings[0].source.detail
        == f"Group/{BACKUP_B}/gpreport.xml Computer/Registry/Policy[Allow thing]"
    )


def test_the_root_itself_is_a_backup_when_it_has_bkupinfo() -> None:
    files = {
        **backup_files(GUID_A, "Outer", report=report(GUID_A, "Outer")),
        **backup_files(GUID_B, "Inner", prefix="Sub", report=report(GUID_B, "Inner")),
    }
    tree = MemoryTree(files)
    assert find_backups(tree) == [""]
    assert [g.name for g in read_backups(tree, "t").gpos] == ["Outer"]


def test_search_reads_to_the_depth_limit() -> None:
    files = backup_files(prefix="/".join(["d"] * backup.MAX_SEARCH_DEPTH), report=report())
    assert len(find_backups(MemoryTree(files))) == 1
    result = read_backups(MemoryTree(files), "t")
    assert len(result.gpos) == 1
    assert result.problems == []


def test_a_backup_below_the_depth_limit_is_a_problem_not_silence() -> None:
    prefix = "/".join(["d"] * (backup.MAX_SEARCH_DEPTH + 1))
    deeper = backup_files(prefix=prefix, report=report())
    assert find_backups(MemoryTree(deeper)) == []
    result = read_backups(MemoryTree(deeper), "t")
    assert result.gpos == []
    (problem,) = result.problems
    assert problem.source.detail == prefix
    assert f"more than {backup.MAX_SEARCH_DEPTH} folders below the input" in problem.reason
    assert "was not read" in problem.reason


def test_a_deep_backup_beside_a_shallow_one_is_still_a_problem() -> None:
    files = {
        **backup_files(GUID_A, "Shallow", prefix=BACKUP_A, report=report(GUID_A, "Shallow")),
        **backup_files(
            GUID_B,
            "Deep",
            backup_id=BACKUP_B,
            prefix="a/b/c/d/e/" + BACKUP_B,
            report=report(GUID_B, "Deep"),
        ),
    }
    result = read_backups(MemoryTree(files), "t")
    assert [g.name for g in result.gpos] == ["Shallow"]
    (problem,) = result.problems
    assert problem.source.detail == f"a/b/c/d/e/{BACKUP_B}"


def test_a_backup_inside_the_backup_at_the_root_is_a_problem() -> None:
    files = {
        **backup_files(GUID_A, "Outer", report=report(GUID_A, "Outer")),
        **backup_files(GUID_B, "Inner", prefix="Sub", report=report(GUID_B, "Inner")),
    }
    result = read_backups(MemoryTree(files), "t")
    assert [g.name for g in result.gpos] == ["Outer"]
    (problem,) = result.problems
    assert "inside another backup folder" in problem.reason


def test_a_backup_inside_a_selected_child_backup_is_a_problem() -> None:
    """MIS-R1: a nested backup beneath a backup found below the root was never looked for."""
    files = {
        **backup_files(GUID_A, "Outer", prefix="Outer", report=report(GUID_A, "Outer")),
        **backup_files(GUID_B, "Inner", prefix="Outer/Sub", report=report(GUID_B, "Inner")),
    }
    result = read_backups(MemoryTree(files), "t")
    assert [g.name for g in result.gpos] == ["Outer"]
    (problem,) = result.problems
    assert problem.source.detail == "Outer/Sub"
    assert "inside another backup folder" in problem.reason


def test_every_selected_backup_in_a_group_is_searched_for_nested_ones() -> None:
    files = {
        **backup_files(GUID_A, "One", prefix="g/one", report=report(GUID_A, "One")),
        **backup_files(GUID_B, "Two", prefix="g/two", report=report(GUID_B, "Two")),
        **backup_files(fx.GUID_C, "Deep", prefix="g/two/x/y/z", report=report(fx.GUID_C, "Deep")),
    }
    result = read_backups(MemoryTree(files), "t")
    assert sorted(g.name for g in result.gpos) == ["One", "Two"]
    (problem,) = result.problems
    assert problem.source.detail == "g/two/x/y/z"
    assert "inside another backup folder" in problem.reason


def test_the_nested_search_shares_one_budget_across_selected_backups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(backup, "MAX_SCAN_FOLDERS", 4)
    files = {
        **backup_files(GUID_A, "One", prefix="one", report=report(GUID_A, "One")),
        **backup_files(GUID_B, "Two", prefix="two", report=report(GUID_B, "Two")),
        **{f"one/n{n}/file.txt": b"x" for n in range(5)},
        **{f"two/m{n}/file.txt": b"x" for n in range(5)},
    }
    result = read_backups(MemoryTree(files), "t")
    assert sorted(g.name for g in result.gpos) == ["One", "Two"]
    assert any("stopped after 4 folders" in p.reason for p in result.problems)


def test_the_search_below_the_depth_limit_gives_up_openly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup, "MAX_SCAN_FOLDERS", 3)
    files = {f"{'/'.join(['d'] * 4)}/x{n}/y/file.txt": b"x" for n in range(10)}
    result = read_backups(MemoryTree(files), "t")
    assert result.gpos == []
    assert any("stopped after 3 folders" in p.reason for p in result.problems)


def test_a_folder_below_the_limit_that_cannot_be_listed_is_a_problem() -> None:
    class Refusing(MemoryTree):
        def entries(self, path: str) -> list[tuple[str, bool]]:
            if path.endswith("x"):
                msg = "permission denied"
                raise TreeError(msg)
            return super().entries(path)

    files = {f"{'/'.join(['d'] * 4)}/x/file.txt": b"x"}
    result = read_backups(Refusing(files), "t")
    (problem,) = result.problems
    assert "could not be listed" in problem.reason
    assert "permission denied" in problem.reason


def test_two_backups_of_the_same_gpo_are_an_input_error_naming_both() -> None:
    files = {
        **backup_files(prefix=BACKUP_A, report=report()),
        **backup_files(backup_id=BACKUP_B, prefix=BACKUP_B, report=report()),
    }
    with pytest.raises(InputError) as caught:
        read_backups(MemoryTree(files), "root")
    message = str(caught.value)
    assert GUID_A in message
    assert BACKUP_A in message
    assert BACKUP_B in message
    assert "root holds more than one backup" in message


def test_duplicate_guid_naming_the_root_itself() -> None:
    # A backup at the root and another found below: the root wins, so no clash is possible,
    # but two siblings clash and a root-level backup is named "." in the message.
    files = {
        **backup_files(prefix="a", report=report()),
        **backup_files(prefix="b", report=report()),
    }
    with pytest.raises(InputError, match="'a' and 'b'"):
        read_backups(MemoryTree(files), "root")


def test_an_empty_tree_has_no_gpos() -> None:
    result = read_backups(MemoryTree({"readme.txt": b"x"}), "t")
    assert (result.gpos, result.problems) == ([], [])


# --- a backup without a usable report ---------------------------------------------------


@pytest.mark.parametrize(
    ("options", "computer", "user"),
    [(0, True, True), (1, True, False), (2, False, True), (3, False, False)],
)
def test_missing_report_builds_the_gpo_from_backup_xml(
    options: int, *, computer: bool, user: bool
) -> None:
    files = backup_files(
        options=options, machine_pol=registry_pol(POL), user_pol=registry_pol(POL), prefix=BACKUP_A
    )
    result = read_backups(MemoryTree(files), "b")
    gpo = only(result)
    assert (gpo.computer_enabled, gpo.user_enabled) == (computer, user)
    assert gpo.versions == {"computer directory": 66, "user directory": 1}
    assert (gpo.guid, gpo.name, gpo.domain) == (GUID_A, "Servers baseline", fx.DOMAIN)
    assert gpo.links is None
    assert gpo.trustees is None
    assert gpo.wmi_filter is None
    assert gpo.source == Source("b", BACKUP_A)
    assert gpo.context["registry.pol"] == "read"
    assert [s.area for s in gpo.settings] == ["Registry.pol", "Registry.pol"]
    (problem,) = result.problems
    assert problem == Problem(
        Source("b", BACKUP_A),
        "gpreport.xml missing: settings other than registry.pol were not compared",
    )


def test_fallback_gpo_knows_its_wmi_filter() -> None:
    files = backup_files(report=None, wmi=("Win11 only", ""))
    gpo = only(read_backups(MemoryTree(files), "b"))
    assert gpo.wmi_filter == WmiFilter("Win11 only", "", fx.WMI_ID)


def test_fallback_without_backup_xml_does_not_know_about_filters_or_enabled() -> None:
    gpo = only(read_backups(MemoryTree(backup_files(report=None, core=False)), "b"))
    assert gpo.wmi_filter == "unknown"
    assert (gpo.computer_enabled, gpo.user_enabled, gpo.versions) == (None, None, {})
    assert (gpo.name, gpo.domain) == ("Servers baseline", fx.DOMAIN)


def test_wmi_filter_with_unparseable_id_has_no_id() -> None:
    files = backup_files(report=None, wmi=("F", ""))
    files["Backup.xml"] = files["Backup.xml"].replace(fx.braces(fx.WMI_ID).encode(), b"{nope}")
    assert only(read_backups(MemoryTree(files), "b")).wmi_filter == WmiFilter("F", "", "")


def test_wmi_filter_without_an_id_attribute() -> None:
    files = backup_files(report=None, wmi=("F", ""))
    files["Backup.xml"] = files["Backup.xml"].replace(b"ID=", b"XX=")
    assert only(read_backups(MemoryTree(files), "b")).wmi_filter == WmiFilter("F")


def test_unusable_report_is_a_problem_and_the_fallback_is_used() -> None:
    for bad in (b"not xml", b"<html/>", report(GUID_B, "Other")):
        result = read_backups(MemoryTree(backup_files(report=bad)), "b")
        gpo = only(result)
        assert gpo.name == "Servers baseline"
        assert gpo.links is None
        reasons = [p.reason for p in result.problems]
        assert any("gpreport.xml could not be used" in r for r in reasons)


def test_report_for_another_gpo_is_named_in_the_problem() -> None:
    result = read_backups(MemoryTree(backup_files(report=report(GUID_B, "Other"))), "b")
    assert any(f"holds no GPO {GUID_A}" in p.reason for p in result.problems)


def test_report_problems_are_passed_on() -> None:
    xml = gpo_xml(computer=registry_ext("<q1:Policy/>"))
    result = read_backups(MemoryTree(backup_files(report=report_bytes(xml))), "b")
    assert only(result).links == []
    assert [p.source.detail for p in result.problems] == ["gpreport.xml Computer/Registry/Policy"]


def test_hostile_report_inside_a_backup_is_a_problem() -> None:
    bomb = b'<!DOCTYPE GPO [<!ENTITY a "aaaa">]><GPO>&a;</GPO>'
    result = read_backups(MemoryTree(backup_files(report=bomb)), "b")
    assert only(result).links is None
    assert any("DOCTYPE" in p.reason for p in result.problems)


# --- the WMI filter id from Backup.xml ---------------------------------------------------


def test_report_filter_gets_its_id_from_backup_xml_when_the_name_matches() -> None:
    files = backup_files(report=report(wmi=("Win11 Only", "d")), wmi=("win11 only", ""))
    assert only(read_backups(MemoryTree(files), "b")).wmi_filter == WmiFilter(
        "Win11 Only", "d", fx.WMI_ID
    )


def test_report_filter_keeps_no_id_when_backup_xml_names_another_filter_or_none() -> None:
    other = backup_files(report=report(wmi=("Win11 Only", "d")), wmi=("Other", ""))
    assert only(read_backups(MemoryTree(other), "b")).wmi_filter == WmiFilter("Win11 Only", "d", "")
    none = backup_files(report=report(wmi=("Win11 Only", "d")))
    assert only(read_backups(MemoryTree(none), "b")).wmi_filter == WmiFilter("Win11 Only", "d", "")
    no_core = backup_files(report=report(wmi=("Win11 Only", "d")), core=False)
    assert only(read_backups(MemoryTree(no_core), "b")).wmi_filter == WmiFilter(
        "Win11 Only", "d", ""
    )
    has_id = report_bytes(gpo_xml(wmi=("F", "")))
    files = backup_files(report=has_id, wmi=("F", ""))
    assert only(read_backups(MemoryTree(files), "b")).wmi_filter == WmiFilter("F", "", fx.WMI_ID)


def test_report_without_a_filter_is_not_given_one() -> None:
    files = backup_files(report=report(), wmi=("F", ""))
    assert only(read_backups(MemoryTree(files), "b")).wmi_filter is None


# --- damaged small files -----------------------------------------------------------------


def test_unreadable_registry_pol_marks_the_gpo_and_keeps_the_rest() -> None:
    files = backup_files(report=report(), machine_pol=b"garbage", user_pol=registry_pol(POL))
    result = read_backups(MemoryTree(files), "b")
    gpo = only(result)
    assert gpo.context["registry.pol"] == "unreadable"
    assert [s.scope for s in gpo.settings if s.area == "Registry.pol"] == ["User"]
    (problem,) = result.problems
    assert problem.source == Source("b", "DomainSysvol/GPO/Machine/registry.pol")


def test_a_truncated_registry_pol_is_unreadable_but_keeps_earlier_values() -> None:
    pol = registry_pol([*POL, ("Software\\Policies\\Example", "Two", 4, dword(1))])[:-5]
    gpo = only(read_backups(MemoryTree(backup_files(report=report(), machine_pol=pol)), "b"))
    assert gpo.context["registry.pol"] == "unreadable"
    assert [s.key[1] for s in gpo.settings if s.area == "Registry.pol"] == ["Level"]


def test_unreadable_bkupinfo_falls_back_to_backup_xml_for_the_guid() -> None:
    files = backup_files(report=report())
    files["bkupInfo.xml"] = b"<BackupInst"
    result = read_backups(MemoryTree(files), "b")
    assert only(result).guid == GUID_A
    assert "bkupInfo.xml cannot be read" in result.problems[0].reason
    assert "backup id" not in only(result).context


def test_unreadable_backup_xml_is_a_problem_but_the_report_is_used() -> None:
    files = backup_files(report=report())
    files["Backup.xml"] = b"<oops"
    result = read_backups(MemoryTree(files), "b")
    assert only(result).links == []
    assert "Backup.xml cannot be read" in result.problems[0].reason


def test_a_backup_that_does_not_say_which_gpo_is_skipped() -> None:
    files = backup_files(report=report())
    files["bkupInfo.xml"] = b"<BackupInst><GPOGuid>nope</GPOGuid></BackupInst>"
    del files["Backup.xml"]
    result = read_backups(MemoryTree(files), "b")
    assert result.gpos == []
    assert result.problems == [
        Problem(Source("b", "."), "The backup does not say which GPO it holds; it was not read")
    ]


def test_backup_xml_missing_is_not_a_problem_when_the_report_exists() -> None:
    result = read_backups(MemoryTree(backup_files(report=report(), core=False)), "b")
    assert result.problems == []


def test_non_numeric_options_and_versions_leave_them_unknown() -> None:
    files = backup_files(report=None)
    files["Backup.xml"] = files["Backup.xml"].replace(
        b"<![CDATA[0]]></Options>", b"<![CDATA[x]]></Options>"
    )
    gpo = only(read_backups(MemoryTree(files), "b"))
    assert (gpo.computer_enabled, gpo.user_enabled) == (None, None)


# --- bundle-style sources --------------------------------------------------------------------


def test_bundle_sources_are_written_as_name_colon_path() -> None:
    files = backup_files(prefix=BACKUP_A, report=report(), machine_pol=registry_pol(POL))
    result = read_backups(MemoryTree(files), "bundle.jsonl", origin="export", bundle=True)
    gpo = only(result)
    assert gpo.context["read from"] == "export"
    sources = [s.source for s in gpo.settings]
    assert sources[0] == Source(
        f"bundle.jsonl:{BACKUP_A}/gpreport.xml", "Computer/Registry/Policy[Allow thing]"
    )
    assert sources[1] == Source(
        f"bundle.jsonl:{BACKUP_A}/DomainSysvol/GPO/Machine/registry.pol", "entry 1"
    )


# --- trees ------------------------------------------------------------------------------------


def test_memory_tree_lists_and_reads() -> None:
    tree = MemoryTree({"a/b/c.txt": b"1", "a/d.txt": b"2", "e.txt": b"3"})
    assert tree.entries("") == [("a", True), ("e.txt", False)]
    assert tree.entries("a") == [("b", True), ("d.txt", False)]
    assert tree.entries("a/b") == [("c.txt", False)]
    assert tree.entries("nope") == []
    assert tree.read("a/d.txt") == b"2"
    with pytest.raises(TreeError, match="not in the tree"):
        tree.read("a/zzz")


def test_memory_tree_refuses_a_file_over_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup, "MAX_FILE", 3)
    tree = MemoryTree({"big": b"1234"})
    with pytest.raises(TreeError, match="larger than 3 bytes"):
        tree.read("big")


def test_folder_tree_lists_and_reads(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/b.txt": b"x", "c.txt": b"y"})
    tree = FolderTree(tmp_path)
    assert tree.entries("") == [("a", True), ("c.txt", False)]
    assert tree.entries("a") == [("b.txt", False)]
    assert tree.read("a/b.txt") == b"x"


def test_folder_tree_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = FolderTree(tmp_path)
    with pytest.raises(TreeError, match="cannot list zzz"):
        tree.entries("zzz")
    with pytest.raises(TreeError, match="cannot read zzz"):
        tree.read("zzz")
    FolderTree(tmp_path / "missing")
    with pytest.raises(TreeError, match=r"cannot list \."):
        FolderTree(tmp_path / "missing").entries("")
    (tmp_path / "big").write_bytes(b"1234")
    monkeypatch.setattr(backup, "MAX_FILE", 3)
    with pytest.raises(TreeError, match="big is larger than 3 bytes"):
        tree.read("big")


def test_folder_tree_does_not_follow_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(tmp_path, {"real.txt": b"x", "linked.txt": b"y"})
    monkeypatch.setattr(
        FolderTree, "_is_link", staticmethod(lambda entry: entry.name == "linked.txt")
    )
    tree = FolderTree(tmp_path)
    assert tree.entries("") == [("real.txt", False)]
    assert tree.skipped == ["linked.txt"]


def test_a_real_symlink_is_treated_as_absent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_bytes(b"s")
    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        (inside / "link").symlink_to(outside, target_is_directory=True)
    except OSError:  # no symlink privilege (Windows): the monkeypatched test above covers the code
        return
    tree = FolderTree(inside)
    assert tree.entries("") == []
    assert tree.skipped == ["link"]


def test_a_skipped_link_makes_the_read_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files = backup_files(report=report(), machine_pol=registry_pol(POL))
    linked = next(p for p in files if p.lower().endswith("machine/registry.pol"))
    monkeypatch.setattr(
        FolderTree, "_is_link", staticmethod(lambda entry: entry.name.lower() == "registry.pol")
    )
    result = read_folder(tmp_path, files)
    assert [(p.source.detail, p.reason) for p in result.problems] == [
        (".", f"{linked} is a link or a special file, which mishpat does not read")
    ]
    assert result.gpos[0].context["evidence:computer registry.pol"] == "unreadable"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_is_skipped_not_read(tmp_path: Path) -> None:
    files = backup_files(report=report(), machine_pol=registry_pol(POL))
    write_tree(tmp_path, files)
    pipe = next(p for p in tmp_path.rglob("*") if p.name.lower() == "registry.pol")
    pipe.unlink()
    os.mkfifo(pipe)
    result = read_backups(FolderTree(tmp_path), "in")
    assert any("is a link or a special file" in p.reason for p in result.problems)
    with pytest.raises(TreeError, match="is a link or a special file"):
        FolderTree(tmp_path).read(pipe.relative_to(tmp_path).as_posix())


def test_listing_error_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=r"^gone: cannot list"):
        read_backups(FolderTree(tmp_path / "gone"), "gone")


class FailingTree:
    """A tree that cannot read the files whose names it is given."""

    def __init__(self, files: dict[str, bytes], failing: set[str]) -> None:
        self.inner = MemoryTree(files)
        self.failing = failing

    def entries(self, path: str) -> list[tuple[str, bool]]:
        return self.inner.entries(path)

    def read(self, path: str) -> bytes:
        if path.rsplit("/", 1)[-1] in self.failing:
            msg = f"cannot read {path}: Permission denied"
            raise TreeError(msg)
        return self.inner.read(path)


def test_files_that_cannot_be_read_are_problems_not_crashes() -> None:
    files = backup_files(report=report(), machine_pol=registry_pol(POL))
    result = read_backups(
        FailingTree(files, {"bkupInfo.xml", "gpreport.xml", "registry.pol"}),
        "b",
    )
    gpo = only(result)
    assert gpo.links is None  # the report could not be read
    assert gpo.context["registry.pol"] == "unreadable"
    reasons = " | ".join(p.reason for p in result.problems)
    assert "cannot read bkupInfo.xml" in reasons
    assert "cannot read gpreport.xml" in reasons
    assert "cannot read DomainSysvol/GPO/Machine/registry.pol" in reasons
    assert "gpreport.xml could not be used" in reasons
