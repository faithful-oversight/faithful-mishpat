# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A summary that cannot be printed never changes the exit code of a finished run."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from faithful_core.exitcodes import ExitCode

from faithful_mishpat.cli import main
from faithful_mishpat.outputs import FILE_NAMES, MANIFEST_NAME
from tests import fixtures_gpo as fx

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

ALL_FILES = sorted([*FILE_NAMES.values(), MANIFEST_NAME])


def gpo(state: str = "Enabled") -> str:
    return fx.gpo_xml(computer=fx.registry_ext(fx.policy("Allow thing", state)))


@pytest.fixture
def pair(tmp_path: Path) -> tuple[Path, Path]:
    before, after = tmp_path / "before.xml", tmp_path / "after.xml"
    before.write_bytes(fx.report_bytes(gpo()))
    after.write_bytes(fx.report_bytes(gpo("Disabled")))
    return before, after


def run(args: Sequence[str | Path], **env: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - this interpreter, arguments the test built
        [sys.executable, "-m", "faithful_mishpat", *map(str, args)],
        capture_output=True,
        check=False,
        env={**os.environ, **env},
        timeout=120,
    )


def non_ascii_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "démo-é"
    try:
        folder.mkdir()
    except OSError:
        pytest.skip("this file system refuses a non-ASCII name")
    return folder


def complete(folder: Path) -> None:
    assert sorted(p.name for p in folder.iterdir()) == ALL_FILES
    assert json.loads((folder / FILE_NAMES["json"]).read_text(encoding="utf-8"))["differences"]
    assert all((folder / name).stat().st_size for name in ALL_FILES)


class Closed(io.TextIOBase):
    """A standard output whose reader has gone away."""

    def __init__(self, *, fail_on: str = "write") -> None:
        self.fail_on = fail_on

    def write(self, text: str) -> int:
        if self.fail_on == "write":
            raise BrokenPipeError(32, "Broken pipe")
        return len(text)

    def flush(self) -> None:
        if self.fail_on == "flush":
            raise BrokenPipeError(32, "Broken pipe")

    def close(self) -> None:
        """Do nothing, so that collecting the object does not flush it again."""


def test_ascii_only_output_and_a_non_ascii_path_keep_the_real_exit_code(
    pair: tuple[Path, Path], tmp_path: Path
) -> None:
    out = non_ascii_folder(tmp_path) / "report"
    done = run(["compare", *pair, "-o", out], PYTHONIOENCODING="ascii")
    assert done.returncode == ExitCode.FINDINGS
    assert b"internal error" not in done.stderr
    assert b"\\xe9" in done.stdout  # shown as an escape, not lost
    complete(out)


def test_ascii_only_output_does_not_fail_the_example_command(tmp_path: Path) -> None:
    target = non_ascii_folder(tmp_path) / "x"
    done = run(["example", target], PYTHONIOENCODING="ascii")
    assert done.returncode == ExitCode.OK
    assert b"internal error" not in done.stderr
    assert (target / "corp-before.jsonl").is_file()


def test_an_ascii_stream_in_this_process_does_not_fail(
    pair: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", write_through=True)
    monkeypatch.setattr(sys, "stdout", stream)
    out = non_ascii_folder(tmp_path) / "report"
    assert main(["compare", *map(str, pair), "-o", str(out)]) == ExitCode.FINDINGS
    assert b"\\xe9" in raw.getvalue()
    complete(out)


def test_a_closed_pipe_is_not_an_error_for_a_clean_run(
    pair: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "stdout", Closed())
    out = tmp_path / "report"
    code = main(["compare", *map(str, pair), "-o", str(out), "--fail-on", "never"])
    assert code == ExitCode.OK


def test_a_closed_pipe_does_not_fail_help_or_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", Closed())
    assert main(["--help"]) == ExitCode.OK
    monkeypatch.setattr(sys, "stdout", Closed())
    assert main(["schema", "report"]) == ExitCode.OK


def test_a_real_closed_pipe_keeps_the_exit_code_and_stays_quiet(
    pair: tuple[Path, Path], tmp_path: Path
) -> None:
    out = tmp_path / "report"
    command = [sys.executable, "-m", "faithful_mishpat", "compare", *map(str, pair), "-o", str(out)]
    with subprocess.Popen(  # noqa: S603 - this interpreter, arguments the test built
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as child:
        assert child.stdout is not None
        child.stdout.close()  # the reader goes away before the child prints
        assert child.stderr is not None
        stderr = child.stderr.read()
        assert child.wait(timeout=120) == ExitCode.FINDINGS
    assert b"Traceback" not in stderr
    assert b"BrokenPipe" not in stderr
    assert b"internal error" not in stderr
    complete(out)
