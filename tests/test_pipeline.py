# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the pipeline: fingerprints, and reading and comparing both sides."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from pathlib import Path

import pytest

from faithful_mishpat import example, pipeline
from faithful_mishpat.errors import InputError, UsageError
from faithful_mishpat.pipeline import InputFile, fingerprint
from tests import fixtures_gpo as fx

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating a link needs a privilege on Windows"
)


def gpo(guid: str = fx.GUID_A, name: str = "Servers baseline", state: str = "Enabled") -> str:
    return fx.gpo_xml(guid, name, computer=fx.registry_ext(fx.policy("Allow thing", state)))


def backup(root: Path, state: str = "Enabled", *, prefix: str = "") -> Path:
    files = fx.backup_files(report=fx.report_bytes(gpo(state=state)), prefix=prefix)
    fx.write_tree(root, files)
    return root


def digest_of(folder: Path) -> str:
    """The folder hash as ``InputFile`` documents it, worked out here on its own."""
    lines = b""
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        relative = path.relative_to(folder).as_posix().encode()
        lines += relative + b"\0" + hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n"
    return hashlib.sha256(lines).hexdigest()


# --- fingerprint ---------------------------------------------------------------------------


def test_a_files_fingerprint_is_its_size_and_sha256(tmp_path: Path) -> None:
    path = tmp_path / "gpo.xml"
    path.write_bytes(b"abc")
    assert fingerprint(path) == (3, hashlib.sha256(b"abc").hexdigest())


def test_an_empty_file_has_a_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "empty"
    path.write_bytes(b"")
    assert fingerprint(path) == (0, hashlib.sha256(b"").hexdigest())


def test_a_large_file_is_read_in_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline, "_BLOCK", 7)
    path = tmp_path / "big"
    path.write_bytes(bytes(range(256)) * 3)
    assert fingerprint(path) == (768, hashlib.sha256(bytes(range(256)) * 3).hexdigest())


def test_a_folders_fingerprint_is_the_hash_of_one_line_per_file(tmp_path: Path) -> None:
    folder = backup(tmp_path / "bk")
    size, digest = fingerprint(folder)
    assert digest == digest_of(folder)
    assert size == sum(p.stat().st_size for p in folder.rglob("*") if p.is_file())
    assert size > 0


def test_a_folders_fingerprint_is_the_same_wherever_it_is(tmp_path: Path) -> None:
    first = backup(tmp_path / "one" / "bk")
    second = tmp_path / "elsewhere" / "deeper" / "renamed"
    shutil.copytree(first, second)
    assert fingerprint(first) == fingerprint(second)


def test_a_folders_fingerprint_changes_with_a_name_or_a_byte(tmp_path: Path) -> None:
    folder = backup(tmp_path / "bk")
    before = fingerprint(folder)
    shutil.copytree(folder, tmp_path / "moved")
    (tmp_path / "moved" / "bkupInfo.xml").rename(tmp_path / "moved" / "BKUPINFO.xml")
    assert fingerprint(tmp_path / "moved") != before
    shutil.copytree(folder, tmp_path / "edited")
    target = tmp_path / "edited" / "Backup.xml"
    target.write_bytes(target.read_bytes() + b" ")
    assert fingerprint(tmp_path / "edited") != before


def test_the_order_files_were_made_in_does_not_matter(tmp_path: Path) -> None:
    files = {"b.txt": b"2", "a/z.txt": b"1", "a/y.txt": b"3"}
    fx.write_tree(tmp_path / "x", files)
    fx.write_tree(tmp_path / "y", dict(reversed(files.items())))
    assert fingerprint(tmp_path / "x") == fingerprint(tmp_path / "y")


def test_an_empty_folder_has_a_fingerprint(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    assert fingerprint(tmp_path / "empty") == (0, hashlib.sha256(b"").hexdigest())


@needs_symlinks
def test_links_in_a_folder_are_not_followed_or_counted(tmp_path: Path) -> None:
    folder = backup(tmp_path / "bk")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"secret outside the folder")
    before = fingerprint(folder)
    (folder / "to-file").symlink_to(outside)
    (folder / "to-folder").symlink_to(tmp_path, target_is_directory=True)
    assert fingerprint(folder) == before


def test_an_unreadable_file_in_a_folder_is_an_input_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = backup(tmp_path / "bk")
    real = Path.open

    def refuse(self: Path, *args: object, **kwargs: object) -> object:
        if self.name == "gpreport.xml":
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(InputError, match=r"cannot read gpreport\.xml: Permission denied"):
        fingerprint(folder)


def test_an_unreadable_folder_is_an_input_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = backup(tmp_path / "bk")

    def refuse(*_: object) -> object:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "rglob", refuse)
    with pytest.raises(InputError, match=r"cannot read bk: Permission denied"):
        fingerprint(folder)


def test_a_missing_path_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=r"cannot read nope\.xml: No such file"):
        fingerprint(tmp_path / "nope.xml")


# --- run -----------------------------------------------------------------------------------


def test_run_reads_both_sides_and_describes_the_inputs(tmp_path: Path) -> None:
    before = tmp_path / "before.xml"
    before.write_bytes(fx.report_bytes(gpo()))
    after = backup(tmp_path / "after-backup", state="Disabled")
    comparison, snapshot, inputs = pipeline.run(before, after)
    assert [(d.category, d.kind) for d in comparison.differences] == [("setting", "changed")]
    assert comparison.complete
    assert snapshot.label == "after"
    assert snapshot.inputs == ["after-backup"]
    assert inputs == [
        InputFile("before.xml", "report", *fingerprint(before)),
        InputFile("after-backup", "backup", *fingerprint(after)),
    ]


def test_run_names_the_comparison_sides_by_input_name(tmp_path: Path) -> None:
    before = tmp_path / "before.xml"
    before.write_bytes(fx.report_bytes(gpo()))
    after = backup(tmp_path / "after-backup", state="Disabled")
    comparison, _, inputs = pipeline.run(before, after)
    assert (comparison.before, comparison.after) == ("before.xml", "after-backup")
    assert [i.name for i in inputs] == [comparison.before, comparison.after]


def test_run_reports_the_kind_of_each_input(tmp_path: Path) -> None:
    fx.write_tree(tmp_path / "bk", fx.backup_files(report=fx.report_bytes(gpo())))
    (tmp_path / "all.xml").write_bytes(fx.report_bytes(gpo(), wrapped=True))
    for name, text in example.build().items():
        (tmp_path / name).write_text(text, encoding="ascii")
    kinds = {
        name: pipeline.run(tmp_path / "all.xml", tmp_path / name)[2][1].kind
        for name in ("bk", example.NAMES[0])
    }
    assert kinds == {"bk": "backup", example.NAMES[0]: "export"}


def test_run_pairs_by_name_when_asked(tmp_path: Path) -> None:
    (tmp_path / "a.xml").write_bytes(fx.report_bytes(gpo(fx.GUID_A, "Same name")))
    (tmp_path / "b.xml").write_bytes(fx.report_bytes(gpo(fx.GUID_B, "Same name", "Disabled")))
    by_guid, _, _ = pipeline.run(tmp_path / "a.xml", tmp_path / "b.xml")
    by_name, _, _ = pipeline.run(tmp_path / "a.xml", tmp_path / "b.xml", match="name")
    assert {p.status for p in by_guid.pairs} == {"only-before", "only-after"}
    assert [(p.status, p.before_guid) for p in by_name.pairs] == [("changed", fx.GUID_A)]


def test_the_same_contents_are_refused_whatever_the_name(tmp_path: Path) -> None:
    (tmp_path / "one.xml").write_bytes(fx.report_bytes(gpo()))
    shutil.copy(tmp_path / "one.xml", tmp_path / "two.xml")
    with pytest.raises(UsageError, match=r"one\.xml and two\.xml have the same contents"):
        pipeline.run(tmp_path / "one.xml", tmp_path / "two.xml")
    with pytest.raises(UsageError, match="same contents"):
        pipeline.run(tmp_path / "one.xml", tmp_path / "one.xml")


def test_the_same_folder_in_two_places_is_refused(tmp_path: Path) -> None:
    first = backup(tmp_path / "first")
    shutil.copytree(first, tmp_path / "second")
    with pytest.raises(UsageError, match="have the same contents"):
        pipeline.run(first, tmp_path / "second")


def test_a_file_and_a_folder_with_the_same_gpo_are_not_the_same_input(tmp_path: Path) -> None:
    (tmp_path / "gpo.xml").write_bytes(fx.report_bytes(gpo()))
    folder = backup(tmp_path / "bk")
    comparison, _, inputs = pipeline.run(tmp_path / "gpo.xml", folder)
    assert comparison.differences == []
    assert [item.kind for item in inputs] == ["report", "backup"]


def test_both_inputs_are_fingerprinted_before_either_is_read(tmp_path: Path) -> None:
    (tmp_path / "junk.txt").write_text("not xml", encoding="ascii")
    with pytest.raises(InputError, match=r"cannot read missing\.xml"):
        pipeline.run(tmp_path / "junk.txt", tmp_path / "missing.xml")


def test_an_input_that_is_not_group_policy_is_an_input_error(tmp_path: Path) -> None:
    (tmp_path / "good.xml").write_bytes(fx.report_bytes(gpo()))
    (tmp_path / "junk.txt").write_text("not xml", encoding="ascii")
    with pytest.raises(InputError, match=r"junk\.txt is not a Get-GPOReport XML file"):
        pipeline.run(tmp_path / "good.xml", tmp_path / "junk.txt")
    (tmp_path / "empty").mkdir()
    with pytest.raises(InputError, match="is not a Backup-GPO folder"):
        pipeline.run(tmp_path / "good.xml", tmp_path / "empty")


def test_names_that_cannot_be_encoded_are_shown_escaped(tmp_path: Path) -> None:
    if sys.platform in ("win32", "darwin"):
        pytest.skip("this file system rejects file names that are not valid UTF-8")
    odd = Path(os.fsdecode(os.fsencode(tmp_path) + b"/bad\xff.xml"))
    odd.write_bytes(fx.report_bytes(gpo()))
    (tmp_path / "after.xml").write_bytes(fx.report_bytes(gpo(state="Disabled")))
    _, _, inputs = pipeline.run(odd, tmp_path / "after.xml")
    assert inputs[0].name == "bad\\xff.xml"


def test_inputs_with_the_same_name_are_cited_with_their_side(tmp_path: Path) -> None:
    before = backup(tmp_path / "monday" / "Backups", "Enabled")
    after = backup(tmp_path / "friday" / "Backups", "Disabled")
    comparison, _after, inputs = pipeline.run(before, after)
    assert (comparison.before, comparison.after) == ("before/Backups", "after/Backups")
    assert [i.name for i in inputs] == ["before/Backups", "after/Backups"]
    files = {s.file for d in comparison.differences for s in d.sources}
    assert files
    assert all(f.startswith(("before/Backups", "after/Backups")) for f in files)


def test_names_that_differ_only_in_case_are_cited_with_their_side(tmp_path: Path) -> None:
    assert pipeline.input_names(tmp_path / "a" / "R.xml", tmp_path / "b" / "r.xml") == (
        "before/R.xml",
        "after/r.xml",
    )
    assert pipeline.input_names(tmp_path / "x.xml", tmp_path / "y.xml") == ("x.xml", "y.xml")
