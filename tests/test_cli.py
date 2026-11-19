# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the command-line entry point: every command, option and exit code."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import sys
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import FormatChecker
from jsonschema.validators import validator_for

from faithful_mishpat import __version__, cli, example, pipeline
from faithful_mishpat.cli import ExitCode, main
from faithful_mishpat.collect import secrets
from faithful_mishpat.formats import registrypol, xmlsafe
from faithful_mishpat.outputs import FILE_NAMES, MANIFEST_NAME
from tests import fixtures_gpo as fx

if TYPE_CHECKING:
    from collections.abc import Callable

ALL_FILES = [*FILE_NAMES.values(), MANIFEST_NAME]


def gpo(guid: str = fx.GUID_A, name: str = "Servers baseline", state: str = "Enabled") -> str:
    return fx.gpo_xml(guid, name, computer=fx.registry_ext(fx.policy("Allow thing", state)))


def write(path: Path, *gpos: str, wrapped: bool = False) -> Path:
    path.write_bytes(fx.report_bytes(*gpos, wrapped=wrapped))
    return path


def names(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def report(folder: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((folder / FILE_NAMES["json"]).read_text(encoding="utf-8"))
    return document


def schema_check(name: str, document: Any) -> None:
    text = files("faithful_mishpat").joinpath("schema", name).read_text(encoding="utf-8")
    definition = json.loads(text)
    validator_for(definition)(definition, format_checker=FormatChecker()).validate(document)


@pytest.fixture
def pair(tmp_path: Path) -> tuple[Path, Path]:
    """Two reports of one GPO, with one setting changed."""
    return write(tmp_path / "before.xml", gpo()), write(
        tmp_path / "after.xml", gpo(state="Disabled")
    )


def compare(before: Path, after: Path, out: Path, *extra: str) -> int:
    return main(["compare", str(before), str(after), "-o", str(out), *extra])


# --- the program ------------------------------------------------------------------------


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == ExitCode.OK
    assert f"mishpat {__version__}" in capsys.readouterr().out


def test_no_arguments_prints_help_on_standard_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == ExitCode.USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage: mishpat" in captured.err
    for command in ("compare", "schema", "example", "collect", "exporter"):
        assert command in captured.err


def test_unknown_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-such-option"]) == ExitCode.USAGE
    assert "unrecognized arguments" in capsys.readouterr().err


def test_unknown_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["frobnicate"]) == ExitCode.USAGE
    assert "invalid choice" in capsys.readouterr().err


def test_exit_codes_are_stable() -> None:
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3, 4]
    assert [code.name for code in ExitCode] == [
        "OK",
        "FINDINGS",
        "USAGE",
        "INPUT_ERROR",
        "INTERNAL_ERROR",
    ]


@given(st.lists(st.text().map(lambda s: "--x" + s), min_size=1))
def test_unknown_options_never_crash(argv: list[str]) -> None:
    assert main(argv) == ExitCode.USAGE


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["mishpat", "--version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("faithful_mishpat", run_name="__main__")
    assert exc.value.code == ExitCode.OK


@pytest.mark.parametrize("command", ["compare", "schema", "example", "collect", "exporter"])
def test_every_command_has_help(command: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([command, "--help"]) == ExitCode.OK
    assert f"usage: mishpat {command}" in capsys.readouterr().out


# --- compare: exit codes ----------------------------------------------------------------


def test_compare_with_differences_exits_1_and_writes_every_report(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "nested" / "reports"
    assert compare(*pair, out) == ExitCode.FINDINGS
    assert names(out) == sorted(ALL_FILES)
    printed = capsys.readouterr().out
    assert "1 difference across 1 GPO" in printed
    assert f"Reports written to {out}:" in printed
    for name in ALL_FILES:
        assert name in printed
    document = report(out)
    schema_check("report-v1.schema.json", document)
    assert document["summary"]["differences"] == 1
    assert [item["name"] for item in document["inputs"]] == ["before.xml", "after.xml"]
    assert document["options"] == {"match": "guid", "fail_on": "differences"}
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    schema_check("manifest-v1.schema.json", manifest)


def test_two_different_inputs_with_no_differences_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A report file and a backup of the same GPO are different inputs that say the same."""
    xml = gpo()
    one = write(tmp_path / "gpo.xml", xml)
    fx.write_tree(tmp_path / "bk", fx.backup_files(report=fx.report_bytes(xml)))
    out = tmp_path / "out"
    assert compare(one, tmp_path / "bk", out) == ExitCode.OK
    assert "No differences. Every input was read in full." in capsys.readouterr().out
    document = report(out)
    schema_check("report-v1.schema.json", document)
    assert document["differences"] == []
    assert [item["kind"] for item in document["inputs"]] == ["report", "backup"]
    assert names(out) == sorted(ALL_FILES)


def test_a_backup_nested_in_a_grouped_backup_is_never_a_clean_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MIS-R1: changing only the inner GPO of ``Outer/`` and ``Outer/Sub/`` must not exit 0."""

    def tree(root: Path, inner: str) -> Path:
        outer_files = fx.backup_files(fx.GUID_A, "Outer", prefix="Outer", report=fx.report_bytes(gpo()))
        inner_files = fx.backup_files(
            fx.GUID_B,
            "Inner",
            backup_id=fx.BACKUP_B,
            prefix="Outer/Sub",
            report=fx.report_bytes(gpo(fx.GUID_B, "Inner", inner)),
        )
        fx.write_tree(root, {**outer_files, **inner_files})
        return root

    before, after = tree(tmp_path / "before", "Enabled"), tree(tmp_path / "after", "Disabled")
    out = tmp_path / "out"
    assert compare(before, after, out) == ExitCode.FINDINGS
    printed = capsys.readouterr().out
    assert "Every input was read in full" not in printed
    document = report(out)
    assert document["summary"]["complete"] is False
    assert any("inside another backup folder" in p["reason"] for p in document["problems"])


def test_inputs_with_the_same_contents_are_a_usage_error(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    copy = shutil.copy(pair[0], tmp_path / "copy.xml")
    out = tmp_path / "out"
    assert compare(pair[0], Path(copy), out) == ExitCode.USAGE
    err = capsys.readouterr().err
    assert f"{pair[0]} and {copy} have the same contents; compare two different versions" in err
    assert not out.exists()


def test_the_same_folder_in_two_places_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fx.write_tree(tmp_path / "one", fx.backup_files(report=fx.report_bytes(gpo())))
    shutil.copytree(tmp_path / "one", tmp_path / "two")
    assert compare(tmp_path / "one", tmp_path / "two", tmp_path / "out") == ExitCode.USAGE
    assert "same contents" in capsys.readouterr().err


def test_inputs_that_cannot_be_read_are_input_errors(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    assert compare(pair[0], tmp_path / "gone.xml", out) == ExitCode.INPUT_ERROR
    assert f"cannot read {tmp_path / 'gone.xml'}: " in capsys.readouterr().err
    junk = tmp_path / "notes.txt"
    junk.write_text("hello", encoding="utf-8")
    assert compare(pair[0], junk, out) == ExitCode.INPUT_ERROR
    assert f"{junk} is not a Get-GPOReport XML file" in capsys.readouterr().err
    (tmp_path / "empty").mkdir()
    assert compare(pair[0], tmp_path / "empty", out) == ExitCode.INPUT_ERROR
    assert f"{tmp_path / 'empty'} is not a Backup-GPO folder" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_named_pipe_input_is_refused_not_read(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pipe = tmp_path / "pipe.xml"
    os.mkfifo(pipe)
    assert compare(pair[0], pipe, tmp_path / "out") == ExitCode.INPUT_ERROR
    assert "neither a regular file nor a folder" in capsys.readouterr().err


def test_an_error_message_cannot_print_control_characters(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if sys.platform == "win32":
        pytest.skip("Windows file names cannot hold control characters")
    hostile = tmp_path / "a\x1b[31mred\x07.xml"
    assert compare(pair[0], hostile, tmp_path / "out") == ExitCode.INPUT_ERROR
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\x07" not in err
    assert "\\u001b[31mred\\u0007.xml" in err


def test_a_missing_option_or_argument_is_a_usage_error(
    pair: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["compare", str(pair[0]), str(pair[1])]) == ExitCode.USAGE
    assert "-o/--output" in capsys.readouterr().err
    assert main(["compare", str(pair[0]), "-o", "out"]) == ExitCode.USAGE
    assert main(["compare"]) == ExitCode.USAGE


def test_an_output_path_that_is_a_file_is_an_input_error(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "taken").write_text("a file", encoding="utf-8")
    assert compare(*pair, tmp_path / "taken") == ExitCode.INPUT_ERROR
    assert "cannot create" in capsys.readouterr().err


# --- compare: --fail-on -----------------------------------------------------------------


def scenario(tmp_path: Path, name: str) -> tuple[Path, Path]:
    """Inputs that are complete or incomplete, with or without differences."""
    broken = [fx.gpo_xml(fx.GUID_B, ""), fx.gpo_xml(fx.GUID_C, "")]  # no Name: not readable
    same, other = gpo(), gpo(state="Disabled")
    sides = {
        "differences": ((same,), (other,)),
        "incomplete-and-differences": ((same, broken[0]), (other, broken[1])),
        "incomplete-only": ((same, broken[0]), (same, broken[1])),
    }[name]
    wrapped = name != "differences"
    return (
        write(tmp_path / "a.xml", *sides[0], wrapped=wrapped),
        write(tmp_path / "b.xml", *sides[1], wrapped=wrapped),
    )


@pytest.mark.parametrize(
    ("name", "fail_on", "code"),
    [
        ("differences", None, ExitCode.FINDINGS),
        ("differences", "differences", ExitCode.FINDINGS),
        ("differences", "incomplete", ExitCode.OK),
        ("differences", "never", ExitCode.OK),
        ("incomplete-and-differences", "differences", ExitCode.FINDINGS),
        ("incomplete-and-differences", "incomplete", ExitCode.FINDINGS),
        ("incomplete-and-differences", "never", ExitCode.OK),
        ("incomplete-only", None, ExitCode.FINDINGS),
        ("incomplete-only", "incomplete", ExitCode.FINDINGS),
        ("incomplete-only", "never", ExitCode.OK),
    ],
)
def test_fail_on_decides_the_exit_code(
    tmp_path: Path, name: str, fail_on: str | None, code: ExitCode
) -> None:
    before, after = scenario(tmp_path, name)
    extra = [] if fail_on is None else ["--fail-on", fail_on]
    out = tmp_path / "out"
    assert compare(before, after, out, *extra) == code
    document = report(out)
    assert document["options"]["fail_on"] == (fail_on or "differences")
    assert document["summary"]["complete"] is (name == "differences")


def test_no_difference_and_complete_exits_0_under_every_fail_on(tmp_path: Path) -> None:
    xml = gpo()
    one = write(tmp_path / "gpo.xml", xml)
    fx.write_tree(tmp_path / "bk", fx.backup_files(report=fx.report_bytes(xml)))
    for index, fail_on in enumerate(("differences", "incomplete", "never")):
        out = tmp_path / f"out{index}"
        assert compare(one, tmp_path / "bk", out, "--fail-on", fail_on) == ExitCode.OK


def test_an_incomplete_comparison_says_so_in_the_report(tmp_path: Path) -> None:
    before, after = scenario(tmp_path, "incomplete-only")
    out = tmp_path / "out"
    compare(before, after, out, "--fail-on", "never")
    document = report(out)
    assert document["summary"]["complete"] is False
    assert document["summary"]["problems"] == 2
    assert document["differences"] == []


def test_an_unknown_fail_on_is_a_usage_error(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert compare(*pair, tmp_path / "out", "--fail-on", "sometimes") == ExitCode.USAGE
    assert "invalid choice" in capsys.readouterr().err


# --- compare: --match -------------------------------------------------------------------


def test_match_name_pairs_gpos_that_were_re_created(tmp_path: Path) -> None:
    before = write(tmp_path / "before.xml", gpo(fx.GUID_A, "Servers baseline"))
    after = write(tmp_path / "after.xml", gpo(fx.GUID_B, "Servers baseline", "Disabled"))
    by_guid, by_name = tmp_path / "guid", tmp_path / "name"
    assert compare(before, after, by_guid) == ExitCode.FINDINGS
    assert compare(before, after, by_name, "--match", "name") == ExitCode.FINDINGS
    guid_report, name_report = report(by_guid), report(by_name)
    assert {g["status"] for g in guid_report["gpos"]} == {"only-before", "only-after"}
    assert any("--match name" in notice for notice in guid_report["notices"])
    assert name_report["options"]["match"] == "name"
    assert name_report["comparison"]["match"] == "name"
    assert [(g["status"], g["before_guid"]) for g in name_report["gpos"]] == [
        ("changed", fx.GUID_A)
    ]
    assert [d["kind"] for d in name_report["differences"]] == ["changed"]


def test_match_name_with_a_duplicate_name_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    twice = write(
        tmp_path / "twice.xml",
        gpo(fx.GUID_A, "Same name"),
        gpo(fx.GUID_B, "same NAME"),
        wrapped=True,
    )
    other = write(tmp_path / "other.xml", gpo(fx.GUID_C, "Same name"), wrapped=True)
    out = tmp_path / "out"
    assert compare(twice, other, out, "--match", "name") == ExitCode.USAGE
    err = capsys.readouterr().err
    assert "the before input has more than one GPO named 'same name'" in err
    assert "pair them by GUID instead" in err
    assert not out.exists()
    assert compare(twice, other, out) == ExitCode.FINDINGS  # by GUID it is fine


def test_an_unknown_match_is_a_usage_error(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert compare(*pair, tmp_path / "out", "--match", "path") == ExitCode.USAGE
    assert "invalid choice" in capsys.readouterr().err


# --- compare: --format ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("json", ["json"]),
        ("md", ["md"]),
        ("html", ["html"]),
        ("csv", ["csv"]),
        ("json, md", ["json", "md"]),
        (" html ,csv ", ["html", "csv"]),
        ("md,md,json,md", ["md", "json"]),
        ("csv,html,md,json", ["json", "md", "html", "csv"]),
    ],
)
def test_format_chooses_the_files_written(
    pair: tuple[Path, Path], tmp_path: Path, value: str, expected: list[str]
) -> None:
    out = tmp_path / "out"
    assert compare(*pair, out, "-f", value) == ExitCode.FINDINGS
    assert names(out) == sorted([*(FILE_NAMES[key] for key in expected), MANIFEST_NAME])
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert sorted(entry["name"] for entry in manifest["files"]) == sorted(
        FILE_NAMES[key] for key in expected
    )


def test_the_long_format_option_works(pair: tuple[Path, Path], tmp_path: Path) -> None:
    assert compare(*pair, tmp_path / "out", "--format", "json") == ExitCode.FINDINGS
    assert names(tmp_path / "out") == sorted([FILE_NAMES["json"], MANIFEST_NAME])


@pytest.mark.parametrize("value", ["pdf", ",", "", "  ", "json,pdf", "JSON", "json;md"])
def test_a_bad_format_is_a_usage_error(
    pair: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    out = tmp_path / "out"
    assert compare(*pair, out, "-f", value) == ExitCode.USAGE
    assert "choose formats from json, md, html, csv" in capsys.readouterr().err
    assert not out.exists()


# --- compare: --force -------------------------------------------------------------------


def test_existing_reports_are_kept_unless_forced(
    pair: tuple[Path, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = tmp_path / "out"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1794225600")
    assert compare(*pair, out) == ExitCode.FINDINGS
    first = (out / FILE_NAMES["json"]).read_bytes()
    capsys.readouterr()
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1794229200")
    assert compare(*pair, out) == ExitCode.INPUT_ERROR
    assert "use --force to replace" in capsys.readouterr().err
    assert (out / FILE_NAMES["json"]).read_bytes() == first
    assert compare(*pair, out, "--force") == ExitCode.FINDINGS
    assert report(out)["generated_at"] == "2026-11-09T13:00:00Z"
    assert names(out) == sorted(ALL_FILES)


def test_force_replaces_only_the_formats_asked_for(pair: tuple[Path, Path], tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert compare(*pair, out) == ExitCode.FINDINGS
    assert compare(*pair, out, "-f", "md", "--force") == ExitCode.FINDINGS
    assert names(out) == sorted(ALL_FILES)  # the manifest now lists one file, the rest stay
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert [entry["name"] for entry in manifest["files"]] == [FILE_NAMES["md"]]


# --- compare: names and time ------------------------------------------------------------


def test_a_file_name_that_is_not_utf8_is_shown_escaped(
    pair: tuple[Path, Path], tmp_path: Path
) -> None:
    if sys.platform in ("win32", "darwin"):
        pytest.skip("this file system rejects file names that are not valid UTF-8")
    bad = os.fsdecode(os.fsencode(tmp_path) + b"/bad\xff.xml")
    shutil.copy(pair[0], bad)
    out = tmp_path / "out"
    assert compare(Path(bad), pair[1], out) == ExitCode.FINDINGS
    assert [item["name"] for item in report(out)["inputs"]] == ["bad\\xff.xml", "after.xml"]
    assert "bad\\\\xff.xml" in (out / FILE_NAMES["md"]).read_text(
        encoding="utf-8"
    )  # Markdown escape


def test_source_date_epoch_sets_the_report_time(
    pair: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1762905600")
    out = tmp_path / "out"
    compare(*pair, out, "-f", "json")
    assert report(out)["generated_at"] == "2025-11-12T00:00:00Z"
    assert (out / MANIFEST_NAME).read_text(encoding="utf-8").count("2025-11-12T00:00:00Z") == 1


@pytest.mark.parametrize("value", ["", "abc", "-5", "1.5", "99999999999999999999", "٣"])
def test_a_bad_source_date_epoch_falls_back_to_the_clock(
    pair: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", value)
    out = tmp_path / "out"
    compare(*pair, out, "-f", "json")
    assert report(out)["generated_at"].startswith("20")
    assert report(out)["generated_at"] != "1970-01-01T00:00:00Z"


def test_the_same_inputs_give_the_same_bytes(
    pair: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1794225600")
    compare(*pair, tmp_path / "one")
    compare(*pair, tmp_path / "two")
    for name in ALL_FILES:
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


# --- schema ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "file", "title"),
    [
        ("report", "report-v1", "report"),
        ("export", "export-v1", "export"),
        ("manifest", "manifest-v1", "manifest"),
    ],
)
def test_schema_prints_valid_json(
    name: str, file: str, title: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["schema", name]) == ExitCode.OK
    printed = capsys.readouterr().out
    document = json.loads(printed)
    assert document["$schema"].startswith("https://json-schema.org/")
    assert document["$id"].endswith(f"/{file}.schema.json")
    assert title in document["title"]
    validator_for(document).check_schema(document)
    packaged = files("faithful_mishpat").joinpath(f"schema/{file}.schema.json")
    assert printed == packaged.read_text(encoding="utf-8")


def test_an_unknown_schema_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema", "changes"]) == ExitCode.USAGE
    assert "invalid choice" in capsys.readouterr().err
    assert main(["schema"]) == ExitCode.USAGE


def test_the_schema_command_covers_every_schema_file() -> None:
    shipped = {p.name for p in files("faithful_mishpat").joinpath("schema").iterdir()}
    assert shipped == {f"{value}.schema.json" for value in cli.SCHEMAS.values()}


# --- example -----------------------------------------------------------------------------


@pytest.fixture
def sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    folder = tmp_path / "my sample"
    assert main(["example", str(folder)]) == ExitCode.OK
    printed = capsys.readouterr().out
    assert "mishpat compare" in printed
    assert "'" in printed or '"' in printed  # the folder name with a space is quoted
    assert example.NAMES[0] in printed
    assert example.NAMES[1] in printed
    return folder


def test_the_example_writes_two_exports_and_compares(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert names(sample) == sorted(example.NAMES)
    out = sample / "report"
    before, after = (sample / name for name in example.NAMES)
    assert compare(before, after, out) == ExitCode.FINDINGS
    assert "27 differences" in capsys.readouterr().out
    document = report(out)
    schema_check("report-v1.schema.json", document)
    assert [item["kind"] for item in document["inputs"]] == ["export", "export"]


def test_the_example_does_not_replace_files_unless_forced(
    sample: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (sample / example.NAMES[0]).write_text("mine", encoding="utf-8")
    assert main(["example", str(sample)]) == ExitCode.INPUT_ERROR
    assert "use --force to replace" in capsys.readouterr().err
    assert (sample / example.NAMES[0]).read_text(encoding="utf-8") == "mine"
    assert main(["example", str(sample), "--force"]) == ExitCode.OK
    assert (sample / example.NAMES[0]).read_bytes() == example.build()[example.NAMES[0]].encode()


def test_the_example_needs_a_folder(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["example"]) == ExitCode.USAGE
    assert "DIR" in capsys.readouterr().err


# --- internal errors ---------------------------------------------------------------------


def broken(message: str) -> Callable[..., Any]:
    def boom(*_: object, **__: object) -> Any:
        raise RuntimeError(message)

    return boom


def test_an_internal_error_is_a_short_message_not_a_traceback(
    pair: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(pipeline, "run", broken("unexpected"))
    out = tmp_path / "out"
    assert compare(*pair, out) == ExitCode.INTERNAL_ERROR
    captured = capsys.readouterr()
    assert captured.err.splitlines() == [
        "mishpat: internal error: RuntimeError: unexpected",
        "This is a bug in mishpat. Please report it.",
    ]
    assert captured.out == ""
    assert not out.exists()


def test_an_internal_error_message_is_cut_short_and_made_safe(
    pair: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(pipeline, "run", broken("\x1b[31m" + "x" * 5000))
    assert compare(*pair, tmp_path / "out") == ExitCode.INTERNAL_ERROR
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert len(err) < 400


def test_an_internal_error_in_another_command_is_also_exit_4(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(example, "build", broken("no example"))
    assert main(["example", "somewhere"]) == ExitCode.INTERNAL_ERROR
    assert "internal error: RuntimeError: no example" in capsys.readouterr().err


def test_errors_never_print_a_secret_the_process_resolved(
    pair: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(secrets, "_resolved", set())
    secrets.remember("hunter2-not-a-real-secret")
    odd = tmp_path / "hunter2-not-a-real-secret.xml"
    assert compare(pair[0], odd, tmp_path / "out") == ExitCode.INPUT_ERROR
    err = capsys.readouterr().err
    assert "hunter2" not in err
    assert f"cannot read {tmp_path}" in err
    assert "[redacted].xml" in err


def test_an_output_folder_that_cannot_be_made_leaves_nothing_behind(
    pair: tuple[Path, Path], tmp_path: Path
) -> None:
    blocked = tmp_path / "taken"
    blocked.write_text("a file", encoding="utf-8")
    assert compare(*pair, blocked / "inside") == ExitCode.INPUT_ERROR
    assert blocked.read_text(encoding="utf-8") == "a file"


# --- owner and custom permissions are compared, never passed over (MISHPAT-C01) ---------------


def test_a_changed_owner_and_a_custom_permission_are_not_a_clean_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    custom = fx.trustee("S-1-5-21-1000-2000-3000-1500", "CORP\\evil", "", mask=131072)
    before = write(tmp_path / "before.xml", gpo())
    after = write(
        tmp_path / "after.xml",
        fx.gpo_xml(
            computer=fx.registry_ext(fx.policy("Allow thing", "Enabled")),
            sddl="O:S-1-5-21-1000-2000-3000-1999G:DAD:PAI",
            trustees=fx.DEFAULT_TRUSTEES + custom,
        ),
    )
    out = tmp_path / "out"
    assert compare(before, after, out) == ExitCode.FINDINGS
    said = capsys.readouterr().out
    assert "No differences" not in said
    subjects = {(d["category"], d["subject"]) for d in report(out)["differences"]}
    assert ("permissions", "owner") in subjects
    assert ("permissions", "evil (S-1-5-21-1000-2000-3000-1500)") not in subjects
    assert ("permissions", "CORP\\evil (S-1-5-21-1000-2000-3000-1500)") in subjects


def test_a_permission_the_reader_cannot_interpret_makes_the_run_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    odd = fx.trustee("S-1-5-21-1000-2000-3000-1500", "CORP\\x", "", mask="not a number")
    before = write(tmp_path / "before.xml", gpo())
    after = write(
        tmp_path / "after.xml",
        fx.gpo_xml(
            computer=fx.registry_ext(fx.policy("Allow thing", "Disabled")),
            trustees=fx.DEFAULT_TRUSTEES + odd,
        ),
    )
    out = tmp_path / "out"
    compare(before, after, out)
    said = capsys.readouterr().out
    assert "Every input was read in full" not in said
    document = report(out)
    assert document["summary"]["complete"] is False
    assert any("TrusteePermissions" in p["detail"] for p in document["problems"])


def test_a_backup_too_deep_to_be_read_is_a_problem_not_a_clean_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    shallow = fx.backup_files(prefix=fx.BACKUP_A, report=fx.report_bytes(gpo()))
    deep = fx.backup_files(
        fx.GUID_B,
        "Deep",
        backup_id=fx.BACKUP_B,
        prefix="a/b/c/d/e/" + fx.BACKUP_B,
        report=fx.report_bytes(gpo(fx.GUID_B, "Deep")),
    )
    fx.write_tree(tmp_path / "before", shallow)
    fx.write_tree(tmp_path / "after", {**shallow, **deep})
    out = tmp_path / "out"
    assert compare(tmp_path / "before", tmp_path / "after", out) == ExitCode.FINDINGS
    said = capsys.readouterr().out
    assert "Every input was read in full" not in said
    document = report(out)
    assert document["summary"]["complete"] is False
    assert any("was not read" in p["reason"] for p in document["problems"])


# --- limits are overridable and never silent (owner decision) ---------------------------------


def pol_backup(root: Path, entries: int) -> Path:
    pol = fx.registry_pol([("Software\\X", f"V{n}", 4, fx.dword(n)) for n in range(entries)])
    files = fx.backup_files(report=fx.report_bytes(gpo()), machine_pol=pol)
    fx.write_tree(root, files)
    return root


def test_the_registry_pol_limit_fails_the_run_and_can_be_raised(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before, after = pol_backup(tmp_path / "b", 5), pol_backup(tmp_path / "a", 6)
    out = tmp_path / "out"
    code = compare(before, after, out, "--max-pol-entries", "3", "--fail-on", "incomplete")
    assert code == ExitCode.FINDINGS
    document = report(out)
    assert document["summary"]["complete"] is False
    assert any("more than 3 entries" in p["reason"] for p in document["problems"])
    assert "Every input was read in full" not in capsys.readouterr().out
    assert (
        compare(
            before, after, tmp_path / "out2", "--max-pol-entries", "10", "--fail-on", "incomplete"
        )
        == ExitCode.OK
    )
    assert registrypol.MAX_ENTRIES == 1_000_000  # the option never leaks past the run


def test_the_scan_limit_fails_the_run_and_can_be_raised(tmp_path: Path) -> None:
    deep = "/".join(["d"] * 4)
    files = {f"{deep}/x{n}/y/file.txt": b"x" for n in range(5)}
    fx.write_tree(
        tmp_path / "b", {**fx.backup_files(prefix=fx.BACKUP_A, report=fx.report_bytes(gpo()))}
    )
    changed = fx.backup_files(prefix=fx.BACKUP_A, report=fx.report_bytes(gpo(state="Disabled")))
    fx.write_tree(tmp_path / "a", {**changed, **files})
    out = tmp_path / "out"
    code = compare(
        tmp_path / "b", tmp_path / "a", out, "--max-scan-folders", "2", "--fail-on", "incomplete"
    )
    assert code == ExitCode.FINDINGS
    assert any("stopped after 2 folders" in p["reason"] for p in report(out)["problems"])
    code = compare(
        tmp_path / "b",
        tmp_path / "a",
        tmp_path / "out2",
        "--max-scan-folders",
        "100",
        "--fail-on",
        "incomplete",
    )
    assert code == ExitCode.OK


@pytest.mark.parametrize("option", ["--max-pol-entries", "--max-scan-folders"])
@pytest.mark.parametrize("value", ["0", "-1", "many"])
def test_the_limit_options_refuse_nonsense(
    pair: tuple[Path, Path], tmp_path: Path, option: str, value: str
) -> None:
    assert compare(*pair, tmp_path / "o", option, value) == ExitCode.USAGE


def test_the_xml_element_limit_is_refused_and_can_be_raised(
    pair: tuple[Path, Path], tmp_path: Path
) -> None:
    assert compare(*pair, tmp_path / "o", "--max-xml-elements", "10") == ExitCode.INPUT_ERROR
    assert not (tmp_path / "o").exists()
    assert compare(*pair, tmp_path / "o2", "--max-xml-elements", "100000") == ExitCode.FINDINGS
    assert xmlsafe.MAX_ELEMENTS == 1_000_000
