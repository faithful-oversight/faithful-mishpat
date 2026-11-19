# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0

"""Remote collection over PowerShell remoting, and the collect and exporter commands.

Set ``MISHPAT_REQUIRE_LIVE=1`` to fail instead of skipping when the ``live`` extra
(pypsrp) is missing.

The bundle rules (header, end line) live in ``faithful_mishpat.formats.bundle``, which
these tests use as it is. The streams are built here with the plain ``json`` and
``hashlib`` modules, apart from one test that uses the reference ``encode()``.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import importlib
import json
import os
import re
import sys
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from faithful_mishpat.collect import cli, names, remote, script, secrets
from faithful_mishpat.collect.remote import Target, collect, parameters, settings
from faithful_mishpat.errors import CollectionError, MishpatError, UsageError

if os.environ.get("MISHPAT_REQUIRE_LIVE") == "1":  # pragma: no cover - set in CI
    # Fail at collection, not skip, when the live extra is missing. Imported by name so
    # type checking does not need the extra installed.
    importlib.import_module("pypsrp")

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

SECRET = 'p@ss w/rd%"\\ü'  # noqa: S105 - synthetic
SERVER = "dc01.corp.example"
TARGET = Target(SERVER, "kerberos", "CORP\\auditor", SECRET)
RUNNING, COMPLETED, FAILED = 1, 4, 5
GUID = "11111111-1111-4111-8111-111111111111"


# --- the bundle rules --------------------------------------------------------------------


@pytest.fixture(name="bundle_module")
def bundle_fixture() -> Any:
    """The real bundle module, whose rules the stream is checked against."""
    return importlib.import_module("faithful_mishpat.formats.bundle")


def line(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def file_line(path: str, data: bytes) -> str:
    return line(
        {
            "path": path,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": base64.b64encode(data).decode("ascii"),
        }
    )


def build(*, gaps: Sequence[dict[str, str]] = ()) -> list[str]:
    """A good export as the exporter writes it: header, files, structure, end line."""
    lines = [
        line(
            {
                "mishpat_export": 1,
                "collector": {"name": "Export-MishpatGpo.ps1", "version": "0.1.0"},
                "domain": "corp.example",
                "collected_at": "2026-11-03T14:00:00Z",
                "scope": [GUID],
            }
        ),
        file_line("{AAAA}/bkupInfo.xml", b"<info/>"),
        file_line("{AAAA}/gpreport.xml", b"\xff\xfe<\x00G\x00P\x00O\x00/\x00>\x00"),
        line(
            {
                "structure": {
                    "scopes": [
                        {
                            "path": "DC=corp,DC=example",
                            "kind": "domain",
                            "blocked": False,
                            "gplink": "",
                        }
                    ],
                    "wmi_filters": [],
                    **({"gaps": list(gaps)} if gaps else {}),
                }
            }
        ),
    ]
    digest = hashlib.sha256("".join(f"{item}\n" for item in lines).encode("ascii")).hexdigest()
    lines.append(line({"end": True, "files": 2, "sha256": digest}))
    return lines


LINES = build()
GOOD = "".join(f"{item}\n" for item in LINES).encode("ascii")
HEADER, FILE_1, FILE_2, STRUCTURE, END = LINES


def restamped(lines: list[str], **changes: object) -> list[str]:
    """``lines`` (ending in an end line) with a correct hash and ``changes`` to the end line."""
    body = lines[:-1]
    trailer = {
        "end": True,
        "files": sum(1 for item in body if item.startswith('{"path":')),
        "sha256": hashlib.sha256("".join(f"{item}\n" for item in body).encode("ascii")).hexdigest(),
    }
    return [*body, line({**trailer, **changes})]


# --- names ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "problem"),
    [
        ("10.0.0.5", "is an IP address"),
        ("[fe80::1]", "is an IP address"),
        ("dc01", "not a fully qualified DNS name"),
        ("dc01.corp.example/x", "not a fully qualified DNS name"),
        ("u:p@dc01.corp.example", "not a fully qualified DNS name"),
        ("-dc.corp.example", "not a fully qualified DNS name"),
        ("dc01.10", "not a fully qualified DNS name"),
        ("a" * 64 + ".corp.example", "not a fully qualified DNS name"),
        ("a." * 127 + "example", "not a fully qualified DNS name"),
    ],
)
def test_server_must_be_a_dns_name(server: str, problem: str) -> None:
    with pytest.raises(CollectionError, match=problem):
        names.server_name(server)


def test_server_names_and_usernames_that_are_accepted() -> None:
    assert names.server_name("DC01.Corp.Example.") == "DC01.Corp.Example"
    assert names.account_name("CORP\\auditor") == "CORP\\auditor"
    assert names.account_name("auditor@corp.example") == "corp.example\\auditor"
    assert names.account_name(None) is None


@pytest.mark.parametrize(
    "username", ["auditor", "\\auditor", "CORP\\", "@corp.example", "C\\a:b", "C\\u\n"]
)
def test_a_username_needs_a_domain(username: str) -> None:
    with pytest.raises(CollectionError, match="must be DOMAIN"):
        names.account_name(username)


# --- transport settings -----------------------------------------------------------------


def test_https_always_verifies_the_certificate(tmp_path: Path) -> None:
    values = settings(TARGET)
    assert (values["ssl"], values["port"], values["cert_validation"], values["encryption"]) == (
        True, 5986, True, "auto",
    )  # fmt: skip
    ca = tmp_path / "corp-ca.pem"
    with_ca = settings(replace(TARGET, ca_file=ca, port=443))
    assert (with_ca["cert_validation"], with_ca["port"]) == (str(ca), 443)


@pytest.mark.parametrize("auth", remote.AUTHS)
def test_http_is_used_only_with_message_encryption(auth: str) -> None:
    values = settings(replace(TARGET, auth=auth, transport="http"))
    assert (values["ssl"], values["port"], values["encryption"]) == (False, 5985, "always")


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"auth": "basic"}, "--auth must be one of"),
        ({"auth": "credssp"}, "--auth must be one of"),
        ({"transport": "ftp"}, "--auth must be one of"),
        ({"transport": "http", "ca_file": "x.pem"}, "--ca-file applies to https only"),
    ],
)
def test_insecure_combinations_are_refused(changes: dict[str, Any], problem: str) -> None:
    with pytest.raises(CollectionError, match=problem):
        settings(replace(TARGET, **changes))


@pytest.mark.parametrize(("transport", "wrapped"), [("https", False), ("http", True)])
def test_the_settings_reach_the_real_transport(transport: str, *, wrapped: bool) -> None:
    """The real pypsrp transport keeps verification on and wraps plain HTTP."""
    wsman_module = pytest.importorskip("pypsrp.wsman")
    wsman = wsman_module.WSMan(**settings(replace(TARGET, transport=transport, auth="ntlm")))
    transport_object = wsman.transport
    assert transport_object.cert_validation is True
    assert transport_object.ssl is (transport == "https")
    assert transport_object.wrap_required is wrapped
    assert transport_object.endpoint.startswith(f"{transport}://{SERVER}:")


def test_script_parameters() -> None:
    assert parameters(every_gpo=True) == {"ToPipeline": True, "All": True}
    assert parameters(names=["A B", "C"], server=SERVER) == {
        "ToPipeline": True, "Name": ["A B", "C"], "Server": SERVER,
    }  # fmt: skip
    assert parameters(guids=[GUID]) == {"ToPipeline": True, "Guid": [GUID]}


@pytest.mark.parametrize(
    "choice",
    [
        {},
        {"every_gpo": True, "guids": [GUID]},
        {"names": ["a"], "guids": [GUID]},
        {"names": [], "guids": []},
    ],
)
def test_exactly_one_selection_is_needed(choice: dict[str, Any]) -> None:
    with pytest.raises(CollectionError, match="exactly one of --all, --name and --guid"):
        parameters(**choice)


# --- a stand-in for pypsrp --------------------------------------------------------------


class Remote:
    """The parts of pypsrp mishpat uses, replaying chosen output in chosen batches."""

    def __init__(self, batches: Sequence[Sequence[object]], *, end: int = COMPLETED) -> None:
        self.batches: list[Sequence[object]] = list(batches)
        self.end = end
        self.settings: dict[str, Any] = {}
        self.script = ""
        self.parameters: dict[str, Any] = {}
        self.error: Exception | None = None
        self.errors: list[str] = []
        self.stopped = False

    def classes(self) -> tuple[Any, Any, Any, int]:  # noqa: C901 - one small class per pypsrp part
        remote_side = self

        class WSMan:
            def __init__(self, **values: Any) -> None:
                remote_side.settings = values
                if remote_side.error is not None:
                    raise remote_side.error

            def __enter__(self) -> WSMan:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Pool:
            def __init__(self, _: object) -> None:
                pass

            def __enter__(self) -> Pool:
                return self

            def __exit__(self, *_: object) -> None:
                return None

        class Streams:
            error = remote_side.errors

        class Shell:
            def __init__(self, _: object) -> None:
                self.state = RUNNING
                self.output: list[object] = []
                self.had_errors = False
                self.streams = Streams()

            def add_script(self, text: str) -> None:
                remote_side.script = text

            def add_parameters(self, values: dict[str, Any]) -> None:
                remote_side.parameters = values

            def begin_invoke(self) -> None:
                pass

            def poll_invoke(self, timeout: int) -> None:
                assert timeout == remote.POLL_SECONDS
                if remote_side.batches:
                    self.output.extend(remote_side.batches.pop(0))
                if not remote_side.batches:
                    self.state = remote_side.end
                    self.had_errors = remote_side.end == FAILED

            def stop(self) -> None:
                remote_side.stopped = True
                msg = "stop is best effort"
                raise RuntimeError(msg)

        return WSMan, Pool, Shell, RUNNING


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Remote:
    side = Remote([LINES[:2], [], LINES[2:]])
    monkeypatch.setattr(remote, "_client", side.classes)
    return side


def run(destination: Path, **options: Any) -> remote.Result:
    return collect(
        TARGET,
        "script text",
        {"ToPipeline": True},
        destination,
        force=options.pop("force", False),
        **options,
    )


def leftovers(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.name.endswith(".part"))


def test_a_collection_streams_into_a_checked_file(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "gpos.jsonl"
    result = run(out)
    assert (result.path, result.files, result.gaps) == (out, 2, ())
    assert out.read_bytes() == GOOD
    assert fake.settings["password"] == SECRET
    assert (fake.script, fake.parameters) == ("script text", {"ToPipeline": True})
    assert leftovers(tmp_path) == []


def test_gaps_the_exporter_recorded_are_returned(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [build(gaps=[{"what": "the sites", "reason": "Access is denied."}])]
    assert run(tmp_path / "e.jsonl").gaps == ("the sites: Access is denied.",)


def damaged(lines: list[str]) -> list[Sequence[object]]:
    return [list(lines)]


@pytest.mark.parametrize(
    ("batches", "problem"),
    [
        (damaged(LINES[:-1]), "ended without its end line"),
        (damaged([HEADER, FILE_2, STRUCTURE, END]), "does not match what arrived"),
        (
            damaged([HEADER, FILE_1, FILE_2.replace("sha256", "sha257"), STRUCTURE, END]),
            "does not match",
        ),
        (
            damaged([HEADER, FILE_1, FILE_2, STRUCTURE.replace("domain", "forest"), END]),
            "does not match",
        ),
        (damaged(restamped(LINES, files=3)), "does not match what arrived"),
        (damaged([*LINES, FILE_1]), "output after its end line"),
        ([[HEADER, 42]], "not one line of text"),
        ([[HEADER, "a\nb"]], "not one line of text"),
        ([[HEADER, "a\rb"]], "not one line of text"),
        ([[HEADER, "ü"]], "not one line of text"),
        ([[FILE_1]], "first line is not a mishpat export header"),
        ([[HEADER, '{"x":1}']], "line of an unknown kind (line 2)"),
        ([[HEADER, FILE_1, FILE_2, STRUCTURE, STRUCTURE]], "more than one structure line"),
        (damaged(restamped([HEADER, FILE_1, FILE_2, END])), "no structure line"),
    ],
)
def test_a_damaged_export_leaves_no_file(
    tmp_path: Path, fake: Remote, batches: list[Sequence[object]], problem: str
) -> None:
    fake.batches = batches
    out = tmp_path / "e.jsonl"
    with pytest.raises(CollectionError, match=re.escape(problem)):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


def with_trailer(**changes: object) -> list[Sequence[object]]:
    """The good stream with its end line changed; ``None`` removes a key."""
    trailer = json.loads(END)
    for key, value in changes.items():
        if value is None:
            del trailer[key]
        else:
            trailer[key] = value
    return [[*LINES[:-1], line(trailer)]]


@pytest.mark.parametrize(
    ("batches", "problem"),
    [
        (with_trailer(end=False), "end line is not valid"),
        (with_trailer(end=1), "end line is not valid"),
        (with_trailer(files="2"), "end line is not valid"),
        (with_trailer(files=True), "end line is not valid"),
        (with_trailer(sha256="ABC"), "end line is not valid"),
        (with_trailer(files=None), "end line is not valid"),
        (with_trailer(extra=1), "end line is not valid"),
        ([[HEADER.replace('"domain"', '"machine"'), *LINES[1:]]], "header is not valid"),
        (
            [[HEADER.replace(',"scope":["' + GUID + '"]', ',"scope":"some"'), *LINES[1:]]],
            "header is not valid",
        ),
        ([['{"mishpat_export":1,', *LINES[1:]]], "header is not valid"),
        ([['{"end":true', *LINES[1:]]], "first line is not a mishpat export header"),
        ([[*LINES[:3], '{"end":true', LINES[-1]]], "end line is not valid"),
    ],
)
def test_a_stream_the_reader_would_refuse_is_never_published(
    tmp_path: Path, fake: Remote, batches: list[Sequence[object]], problem: str
) -> None:
    fake.batches = batches
    out = tmp_path / "e.jsonl"
    out.write_bytes(b"existing evidence\n")
    with pytest.raises(CollectionError, match=problem):
        run(out, force=True)
    assert out.read_bytes() == b"existing evidence\n"
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "bad",
    [
        '{"structure":[]}',
        '{"structure":{"gaps":{"what":"x","reason":"y"}}}',
        '{"structure":3}',
        '{"structure":{"gaps":[{"what":"x"}]}}',
        '{"structure":{"gaps":[3]}}',
        '{"structure":{"gaps":',
    ],
)
def test_an_unreadable_structure_line_is_refused(tmp_path: Path, fake: Remote, bad: str) -> None:
    fake.batches = [[HEADER, FILE_1, bad]]
    with pytest.raises(CollectionError, match="structure line is not valid"):
        run(tmp_path / "e.jsonl")
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_an_invalid_stream_with_no_existing_file_leaves_nothing(
    tmp_path: Path, fake: Remote
) -> None:
    fake.batches = with_trailer(end=False)
    with pytest.raises(CollectionError, match="end line is not valid"):
        run(tmp_path / "e.jsonl")
    assert sorted(path.name for path in tmp_path.iterdir()) == []


def test_the_reference_writer_output_is_accepted(
    tmp_path: Path, fake: Remote, bundle_module: Any
) -> None:
    structure: dict[str, Any] = {"scopes": [], "wmi_filters": []}
    header = {
        "mishpat_export": 1,
        "collector": {"name": "c", "version": "0.1.0"},
        "domain": "corp.example",
        "collected_at": "2026-11-03T14:00:00Z",
        "scope": "all",
    }
    data = bundle_module.encode(header, {"{A}/bkupInfo.xml": b"x", "{A}/b": b""}, structure)
    fake.batches = [data.decode("ascii").splitlines()]
    out = tmp_path / "e.jsonl"
    assert run(out).files == 2
    assert out.read_bytes() == data


def test_a_file_whose_text_mentions_an_end_line_is_still_a_file(
    tmp_path: Path, fake: Remote
) -> None:
    # Lines are told apart by how they start, so a file line (even one whose base64
    # or path spells an end line) can never be taken for the end line.
    tricky = file_line('{"end":true,"files":0}', b'{"end":true}')
    lines = restamped([HEADER, tricky, STRUCTURE, END])
    fake.batches = [lines]
    assert run(tmp_path / "e.jsonl").files == 1


@pytest.mark.usefixtures("fake")
def test_an_overlong_line_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bundle_module: Any
) -> None:
    monkeypatch.setattr(bundle_module, "MAX_LINE", 50)
    with pytest.raises(CollectionError, match="line 1 from the exporter is too long"):
        run(tmp_path / "e.jsonl")


def test_a_script_that_fails_reports_its_own_error(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:2]]
    fake.end = FAILED
    fake.errors.append(f"Access is denied for {SECRET}")
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "e.jsonl")
    assert "the exporter failed on dc01.corp.example: Access is denied for [redacted]" in str(
        exc.value
    )
    fake.errors.clear()
    fake.batches = [LINES[:2]]
    with pytest.raises(CollectionError, match="the script stopped with an error"):
        run(tmp_path / "e.jsonl")


def test_a_stalled_collection_is_stopped(tmp_path: Path, fake: Remote) -> None:
    fake.batches = [LINES[:1], [], [], [], LINES[1:]]
    ticks = iter(range(0, 10_000, 400))
    with pytest.raises(CollectionError, match="sent nothing for 600 seconds and was stopped"):
        collect(TARGET, "s", {}, tmp_path / "e.jsonl", force=False, clock=lambda: next(ticks))
    assert fake.stopped
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize(
    "error", [OSError(f"connection refused, password={SECRET}"), ValueError("")]
)
def test_library_errors_never_show_the_secret(
    tmp_path: Path, fake: Remote, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(secrets, "_resolved", {SECRET})
    fake.error = error
    with pytest.raises(CollectionError) as exc:
        run(tmp_path / "e.jsonl")
    assert SECRET not in str(exc.value)
    assert str(exc.value).startswith("remote collection from dc01.corp.example failed: ")
    assert leftovers(tmp_path) == []


def test_an_existing_file_is_kept_unless_forced(tmp_path: Path, fake: Remote) -> None:
    out = tmp_path / "e.jsonl"
    out.write_text("keep", encoding="utf-8")
    with pytest.raises(CollectionError, match="already exists; pass --force"):
        run(out)
    assert fake.settings == {}  # refused before connecting
    run(out, force=True)
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_during_collection_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001 - the moment between check and publish

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


def no_hard_links(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Make ``os.link`` fail as on FAT; the count says how often it was tried."""
    calls = {"link": 0}

    def refuse(*_: object, **__: object) -> None:
        calls["link"] += 1
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "link", refuse)
    return calls


@pytest.mark.usefixtures("fake")
def test_a_file_system_without_hard_links_still_gets_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    result = run(out)
    assert calls["link"] == 1
    assert (result.path, result.files) == (out, 2)
    assert out.read_bytes() == GOOD
    assert sorted(path.name for path in tmp_path.iterdir()) == ["e.jsonl"]


@pytest.mark.usefixtures("fake")
def test_a_failed_copy_removes_the_partly_written_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    real = os.fsync
    out = tmp_path / "e.jsonl"

    def full(fd: int) -> None:
        if out.exists():  # only the copy into the destination fails
            raise OSError(errno.ENOSPC, "No space left on device")
        real(fd)

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(CollectionError, match=r"cannot write .*e\.jsonl: No space left"):
        run(out)
    assert not out.exists()
    assert leftovers(tmp_path) == []


@pytest.mark.usefixtures("fake")
def test_a_file_that_appears_when_links_are_unavailable_is_not_clobbered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    no_hard_links(monkeypatch)
    out = tmp_path / "e.jsonl"
    real = remote._Sink.finish  # noqa: SLF001 - the moment between check and publish

    def appear(sink: Any) -> Any:
        out.write_text("arrived", encoding="utf-8")
        return real(sink)

    monkeypatch.setattr(remote._Sink, "finish", appear)  # noqa: SLF001
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    assert out.read_text(encoding="utf-8") == "arrived"
    assert leftovers(tmp_path) == []


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges on Windows")
def test_a_link_at_the_destination_is_never_followed(tmp_path: Path, fake: Remote) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("precious", encoding="utf-8")
    out = tmp_path / "e.jsonl"
    out.symlink_to(outside)
    with pytest.raises(CollectionError, match="already exists"):
        run(out)
    fake.batches = [LINES]
    run(out, force=True)
    assert outside.read_text(encoding="utf-8") == "precious"
    assert not out.is_symlink()
    assert out.read_bytes() == GOOD


@pytest.mark.usefixtures("fake")
def test_an_unwritable_folder_is_reported(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match="cannot write to"):
        run(tmp_path / "missing" / "e.jsonl")


def test_the_part_file_is_private(tmp_path: Path, fake: Remote) -> None:
    seen: list[int] = []
    real = remote._Sink.finish  # noqa: SLF001

    def look(sink: Any) -> Any:
        seen.append(sink.temp.stat().st_mode & 0o777)
        return real(sink)

    fake.batches = [LINES]
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(remote._Sink, "finish", look)  # noqa: SLF001
        run(tmp_path / "e.jsonl")
    assert seen == [0o600] or os.name == "nt"


@pytest.mark.usefixtures("fake")
def test_a_collection_without_a_secret_still_publishes(tmp_path: Path) -> None:
    out = tmp_path / "e.jsonl"
    result = collect(replace(TARGET, secret=None), "s", {}, out, force=False)
    assert result.path == out
    assert out.read_bytes() == GOOD


def test_pypsrp_missing_says_how_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pypsrp.wsman", None)
    with pytest.raises(CollectionError, match=r'pip install "faithful-mishpat\[live\]"'):
        remote._client()  # noqa: SLF001 - the import boundary itself


def test_the_real_client_classes_load() -> None:
    pytest.importorskip("pypsrp")
    wsman, pool, shell, running = remote._client()  # noqa: SLF001
    assert (wsman.__name__, pool.__name__, shell.__name__, running) == (
        "WSMan", "RunspacePool", "PowerShell", RUNNING,
    )  # fmt: skip


def test_the_bundle_module_is_loaded_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    sentinel = object()

    def record(name: str) -> object:
        seen.append(name)
        return sentinel

    monkeypatch.setattr(importlib, "import_module", record)
    assert remote._bundle() is sentinel  # noqa: SLF001
    assert seen == ["faithful_mishpat.formats.bundle"]


# --- the commands -----------------------------------------------------------------------


def invoke(*argv: str) -> int:
    """Run a subcommand the way the main parser will: parse, then call ``run``."""
    parser = argparse.ArgumentParser(prog="mishpat")
    commands = parser.add_subparsers(dest="command", required=True)
    cli.add_arguments(commands)
    args = parser.parse_args(argv)
    code: int = args.run(args)
    return code


def collect_args(out: Path, *extra: str) -> list[str]:
    return ["collect", "--server", SERVER, "-o", str(out), *extra]


@pytest.fixture
def fetched(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def resolve(reference: str) -> str:
        calls.append(reference)
        return SECRET

    monkeypatch.setattr(secrets, "resolve", resolve)
    return calls


@pytest.mark.parametrize(
    ("extra", "error", "problem"),
    [
        (["--all", "--server", "10.0.0.5"], CollectionError, "is an IP address"),
        (
            ["--all", "--username", "auditor", "--secret", "env:X"],
            CollectionError,
            "must be DOMAIN",
        ),
        (["--all", "--secret", "env:X"], UsageError, "--secret needs --username"),
        (["--all", "--username", "CORP\\auditor"], UsageError, "--username needs --secret"),
        (["--all", "--auth", "ntlm"], UsageError, "--auth ntlm needs --username and --secret"),
        (
            [
                "--all",
                "--transport",
                "http",
                "--ca-file",
                "ca.pem",
                "--username",
                "CORP\\a",
                "--secret",
                "env:X",
            ],
            CollectionError,
            "https only",
        ),
    ],
)
def test_collect_checks_everything_before_reading_the_secret(
    tmp_path: Path, fetched: list[str], extra: list[str], error: type[Exception], problem: str
) -> None:
    with pytest.raises(error, match=re.escape(problem)):
        invoke(*collect_args(tmp_path / "e.jsonl", *extra))
    assert fetched == []


@pytest.mark.parametrize("used", ["ca", "secret"])
def test_collect_never_replaces_the_file_it_was_told_to_use(
    used: str, tmp_path: Path, fetched: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The MER-1 / PAK-1 class: ``-o`` equal to the CA file or the secret file, with --force."""
    called: list[object] = []

    def record(*args: object, **_: object) -> None:
        called.append(args)

    monkeypatch.setattr(remote, "collect", record)
    file = tmp_path / "input.txt"
    file.write_bytes(b"line one\nline two\n")
    original = file.read_bytes()
    outputs = [file]
    if sys.platform != "win32":  # creating a link needs a privilege on Windows
        (tmp_path / "alias.txt").symlink_to(file)
        outputs.append(tmp_path / "alias.txt")
    use = (
        ["--ca-file", str(file)]
        if used == "ca"
        else ["--username", "auditor@corp.example", "--secret", f"file:{file}"]
    )
    for out in outputs:
        with pytest.raises(MishpatError, match="would be overwritten"):
            invoke(*collect_args(out, "--all", "--force", *use))
    assert file.read_bytes() == original
    assert (called, fetched) == ([], [])  # nothing was read, nothing was collected


def test_collect_runs_and_says_what_to_do_next(
    tmp_path: Path,
    fetched: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: dict[str, Any] = {}

    def fake_collect(
        target: Target, text: str, values: dict[str, Any], out: Path, *, force: bool
    ) -> remote.Result:
        seen.update(target=target, text=text, values=values, force=force)
        return remote.Result(out, 12, ("the sites: Access is denied.",))

    monkeypatch.setattr(remote, "collect", fake_collect)
    out = tmp_path / "my gpos.jsonl"
    args = collect_args(
        out, "--username", "auditor@corp.example", "--secret", "env:PW",
        "--name", "Workstation Baseline", "Dup", "--name", "More",
        "--timeout", "90", "--port", "443", "--force",
    )  # fmt: skip
    assert invoke(*args) == 0
    assert fetched == ["env:PW"]
    target = seen["target"]
    assert (target.username, target.secret, target.idle_timeout, target.port) == (
        "corp.example\\auditor", SECRET, 90, 443,
    )  # fmt: skip
    assert seen["text"] == script.text()
    assert seen["force"] is True
    assert seen["values"] == {
        "ToPipeline": True,
        "Name": ["Workstation Baseline", "Dup", "More"],
        "Server": SERVER,
    }
    printed = capsys.readouterr().out
    assert f"Exported 12 files from {SERVER}" in printed
    assert "not read: the sites: Access is denied." in printed
    assert "mishpat compare" in printed
    assert "'" in printed or '"' in printed  # the path with a space is quoted


@pytest.mark.usefixtures("fetched")
def test_a_gap_or_path_with_a_line_break_cannot_add_a_terminal_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    forged = "Exported 0 files from nowhere."
    gap = f"the sites: Access is denied.\n{forged}"

    def fake_collect(
        _target: Target, _text: str, _values: dict[str, Any], out: Path, **_options: Any
    ) -> remote.Result:
        return remote.Result(out, 1, (gap,))

    monkeypatch.setattr(remote, "collect", fake_collect)
    args = collect_args(
        tmp_path / "e.jsonl", "--username", "auditor@corp.example", "--secret", "env:PW", "--all"
    )
    assert invoke(*args) == 0
    lines = capsys.readouterr().out.splitlines()
    assert forged not in lines
    assert not any(line.strip().startswith(forged) for line in lines)
    assert f"  not read: the sites: Access is denied.\\n{forged}" in lines
    assert len(lines) == 3


def test_collect_with_the_current_kerberos_ticket_and_every_gpo(
    tmp_path: Path, fetched: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Target, dict[str, Any]]] = []

    def record(
        target: Target, _: str, values: dict[str, Any], *__: object, **___: object
    ) -> remote.Result:
        calls.append((target, values))
        return remote.Result(tmp_path, 0, ())

    monkeypatch.setattr(remote, "collect", record)
    assert invoke(*collect_args(tmp_path / "e.jsonl", "--all")) == 0
    target, values = calls[0]
    assert (target.username, target.secret, fetched) == (None, None, [])
    assert values == {"ToPipeline": True, "All": True, "Server": SERVER}


def test_collect_by_guid_normalises_guids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def record(
        _: Target, __: str, values: dict[str, Any], *___: object, **____: object
    ) -> remote.Result:
        calls.append(values)
        return remote.Result(tmp_path, 0, ())

    monkeypatch.setattr(remote, "collect", record)
    invoke(*collect_args(tmp_path / "e.jsonl", "--guid", "{" + GUID.upper() + "}", GUID))
    assert calls[0]["Guid"] == [GUID, GUID]


@pytest.mark.parametrize(
    "extra",
    [
        [],  # one of --all, --name, --guid is required
        ["--all", "--name", "x"],
        ["--all", "--guid", GUID],
        ["--name", "x", "--guid", GUID],
        ["--guid", "not-a-guid"],
        ["--guid", GUID[:-1]],
        ["--name", ""],
        ["--name", "bad\nname"],
        ["--all", "--timeout", "0"],
        ["--all", "--timeout", "x"],
        ["--all", "--port", "70000"],
        ["--all", "--auth", "basic"],
        ["--all", "--transport", "ftp"],
    ],
)
def test_collect_option_values_are_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        invoke(*collect_args(tmp_path / "e.jsonl", *extra))
    assert exc.value.code == 2
    assert capsys.readouterr().err


def test_exporter_writes_the_script(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / script.NAME
    assert invoke("exporter", "-o", str(out)) == 0
    assert out.read_text(encoding="ascii") == script.text()
    assert "-All -OutFile corp-gpos.jsonl" in capsys.readouterr().out
    with pytest.raises(MishpatError, match="exist"):
        invoke("exporter", "-o", str(out))
    assert invoke("exporter", "-o", str(out), "--force") == 0
