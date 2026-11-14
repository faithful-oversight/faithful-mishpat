# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for read_side: the input kind is detected from content."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from faithful_mishpat import inputs
from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import xmlsafe
from faithful_mishpat.inputs import display_name, read_side
from faithful_mishpat.model import Source
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import (
    BACKUP_A,
    BACKUP_B,
    GUID_A,
    GUID_B,
    backup_files,
    bundle_bytes,
    gpo_xml,
    policy,
    registry_ext,
    registry_pol,
    report_bytes,
    write_tree,
)

POL = [("Software\\Policies\\Example", "Level", 4, fx.dword(2))]


def gpo(guid: str, name: str) -> str:
    return gpo_xml(guid, name, computer=registry_ext(policy("P")))


# --- report files ------------------------------------------------------------------------


def test_a_single_gpo_report_is_not_domain_wide(tmp_path: Path) -> None:
    path = tmp_path / "gpo.xml"
    path.write_bytes(report_bytes(gpo(GUID_A, "A")))
    snapshot = read_side(path, "before")
    assert snapshot.label == "before"
    assert snapshot.inputs == ["gpo.xml"]
    assert list(snapshot.gpos) == [GUID_A]
    assert snapshot.gpos[GUID_A].source == Source("gpo.xml")
    assert snapshot.domain_wide is False
    assert snapshot.scopes is None
    assert snapshot.problems == []
    assert snapshot.context == {"kind": "report"}


@pytest.mark.parametrize("name", ["all.xml", "all.txt", "all", "all.dat"])
@pytest.mark.parametrize("how", ["utf8", "utf16", "utf16-be", "utf8-bom"])
def test_gpos_report_is_domain_wide_whatever_the_name_and_encoding(
    tmp_path: Path, name: str, how: str
) -> None:
    path = tmp_path / name
    path.write_bytes(report_bytes(gpo(GUID_A, "A"), gpo(GUID_B, "B"), wrapped=True, how=how))
    snapshot = read_side(path, "after")
    assert snapshot.domain_wide is True
    assert sorted(snapshot.gpos) == [GUID_A, GUID_B]
    assert snapshot.inputs == [name]


def test_report_problems_are_kept(tmp_path: Path) -> None:
    path = tmp_path / "r.xml"
    path.write_bytes(report_bytes(gpo(GUID_A, "A"), gpo_xml(ident="x"), wrapped=True))
    snapshot = read_side(path, "after")
    assert list(snapshot.gpos) == [GUID_A]
    assert [p.source for p in snapshot.problems] == [Source("r.xml", "GPO[2]")]


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"hello",
        b"\x00\x01\x02\xff\xfe",
        b"<html/>",
        b'<!DOCTYPE x [<!ENTITY a "b">]><x/>',
        b'{"toledot_events":1}\n',
    ],
)
def test_other_files_are_input_errors(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "x.xml"
    path.write_bytes(data)
    with pytest.raises(
        InputError, match=f"^{re.escape(str(path))} is not a Get-GPOReport XML file: "
    ):
        read_side(path, "before")


def test_a_report_over_the_size_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "big.xml"
    path.write_bytes(report_bytes(gpo(GUID_A, "A")))
    monkeypatch.setattr(xmlsafe, "MAX_BYTES", 200)
    with pytest.raises(InputError, match="larger than 200 bytes"):
        read_side(path, "before")


def test_an_unreadable_file_is_an_input_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "x.xml"
    path.write_bytes(b"<x/>")

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(InputError, match=f"^cannot read {re.escape(str(path))}: Permission denied"):
        read_side(path, "before")


def test_a_missing_path_is_an_input_error(tmp_path: Path) -> None:
    pattern = (
        f"^{re.escape(str(tmp_path / 'nope'))} does not exist or is neither a file nor a folder"
    )
    with pytest.raises(InputError, match=pattern):
        read_side(tmp_path / "nope", "before")


# --- backup folders ---------------------------------------------------------------------------


def test_a_backup_folder(tmp_path: Path) -> None:
    folder = tmp_path / BACKUP_A
    write_tree(
        folder, backup_files(report=report_bytes(gpo(GUID_A, "A")), machine_pol=registry_pol(POL))
    )
    snapshot = read_side(folder, "before")
    assert snapshot.inputs == [BACKUP_A]
    assert snapshot.domain_wide is False
    assert snapshot.context == {"kind": "backup"}
    assert snapshot.problems == []
    (found,) = snapshot.gpos.values()
    assert found.context["read from"] == "backup"
    assert found.context["registry.pol"] == "read"
    assert [s.area for s in found.settings] == ["Administrative Templates", "Registry.pol"]


def test_a_backup_root_with_many(tmp_path: Path) -> None:
    root = tmp_path / "Baseline"
    write_tree(
        root, backup_files(GUID_A, "A", prefix=BACKUP_A, report=report_bytes(gpo(GUID_A, "A")))
    )
    write_tree(root, backup_files(GUID_B, "B", backup_id=BACKUP_B, prefix=BACKUP_B, report=None))
    (root / "manifest.xml").write_bytes(b"<Backups/>")
    snapshot = read_side(root, "after")
    assert sorted(snapshot.gpos) == [GUID_A, GUID_B]
    assert snapshot.domain_wide is False
    assert len(snapshot.problems) == 1  # B has no gpreport.xml
    assert snapshot.problems[0].reason.startswith("gpreport.xml missing")


def test_current_directory_is_named_by_its_real_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Here"
    write_tree(root, backup_files(report=report_bytes(gpo(GUID_A, "A"))))
    monkeypatch.chdir(root)
    assert read_side(Path(), "before").inputs == ["Here"]


def test_a_folder_that_is_not_a_backup_is_an_input_error(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.txt").write_text("hi", "utf-8")
    with pytest.raises(
        InputError, match=f"^{re.escape(str(tmp_path / 'docs'))} is not a Backup-GPO folder"
    ):
        read_side(tmp_path / "docs", "before")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(InputError, match=f"^{re.escape(str(empty))} is not a Backup-GPO folder"):
        read_side(empty, "before")


def test_ambiguous_backups_are_an_input_error(tmp_path: Path) -> None:
    root = tmp_path / "root"
    write_tree(root, backup_files(prefix=BACKUP_A, report=None))
    write_tree(root, backup_files(backup_id=BACKUP_B, prefix=BACKUP_B, report=None))
    with pytest.raises(InputError, match="more than one backup of GPO"):
        read_side(root, "before")


def test_a_backup_folder_whose_only_backup_is_unreadable_reports_the_problem(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "b"
    files = backup_files(report=None)
    files["bkupInfo.xml"] = b"<x"
    del files["Backup.xml"]
    write_tree(folder, files)
    snapshot = read_side(folder, "before")
    assert snapshot.gpos == {}
    assert snapshot.problems


# --- export bundles ----------------------------------------------------------


def test_a_bundle_is_detected_from_its_content(tmp_path: Path) -> None:
    path = tmp_path / "export.dat"
    path.write_bytes(
        bundle_bytes(backup_files(prefix=BACKUP_A, report=report_bytes(gpo(GUID_A, "A"))))
    )
    snapshot = read_side(path, "before")
    assert snapshot.context["kind"] == "export"
    assert snapshot.context["domain"] == fx.DOMAIN
    assert snapshot.domain_wide is True
    assert snapshot.scopes == {}
    assert list(snapshot.gpos) == [GUID_A]
    assert snapshot.gpos[GUID_A].source == Source(f"export.dat:{BACKUP_A}/gpreport.xml")
    assert snapshot.inputs == ["export.dat"]
    assert snapshot.problems == []


def test_a_bundle_for_chosen_gpos_is_not_domain_wide(tmp_path: Path) -> None:
    path = tmp_path / "export.jsonl"
    path.write_bytes(
        bundle_bytes(backup_files(report=report_bytes(gpo(GUID_A, "A"))), scope=[GUID_A])
    )
    snapshot = read_side(path, "after")
    assert snapshot.domain_wide is False
    assert snapshot.context["scope"] == "1 GPOs"


def test_a_damaged_bundle_still_gives_what_it_can(tmp_path: Path) -> None:
    path = tmp_path / "export.jsonl"
    data = bundle_bytes(backup_files(report=report_bytes(gpo(GUID_A, "A"))))
    path.write_bytes(data[: data.rindex(b'{"end"')])
    snapshot = read_side(path, "after")
    assert list(snapshot.gpos) == [GUID_A]
    assert any("cut short" in p.reason for p in snapshot.problems)


def test_a_file_starting_like_a_bundle_but_with_a_bad_header_is_an_input_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "export.jsonl"
    path.write_bytes(b'{"mishpat_export":9}\n')
    with pytest.raises(InputError, match="is not a mishpat export bundle"):
        read_side(path, "before")


# --- names -------------------------------------------------------------------


def test_display_names_escape_bytes_that_are_not_text() -> None:
    assert display_name(Path("plain.xml")) == "plain.xml"
    assert display_name(Path("café.xml")) == "café.xml"
    if os.name == "posix":
        assert display_name(Path(os.fsdecode(b"bad\xffname.xml"))) == "bad\\xffname.xml"


def test_the_name_of_an_input_with_odd_bytes_is_what_sources_show(tmp_path: Path) -> None:
    if os.name != "posix":
        return
    path = tmp_path / os.fsdecode(b"r\xff.xml")
    try:
        path.write_bytes(report_bytes(gpo(GUID_A, "A")))
    except OSError as exc:  # macOS file systems refuse names that are not UTF-8
        pytest.skip(f"this file system refuses the name: {exc.strerror}")
    snapshot = read_side(path, "before")
    assert snapshot.inputs == ["r\\xff.xml"]
    assert snapshot.gpos[GUID_A].source == Source("r\\xff.xml")


def test_module_exports() -> None:
    assert inputs.__all__ == ["display_name", "read_side", "shown_path"]
