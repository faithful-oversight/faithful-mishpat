# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Run the exporter on a domain controller over PowerShell remoting.

The packaged script is sent to the controller and run there with ``-ToPipeline``.
Its lines stream back and are written to a file next to the destination, and the
file is published only after its end line checks out: the file count and the
SHA-256 the script computed over everything it sent before the end line must match
what arrived. A partial file is never left behind.

faithful-core runs the connection, the transport rules, the secret handling, and the
rule that every failure discards the private file; see ``faithful_core.collect.winrm``.
This module holds what is mishpat's own: the checks on each line, the end line, the
script's parameters, and the result.

Rights: the account must be allowed to open a PowerShell remoting session on the
controller (by default, members of Administrators or Remote Management Users) and
to read the GPOs it exports (Backup-GPO needs Read on each GPO). Microsoft documents
both; whether a just-enough-administration endpoint can be narrowed further for this
script has not been tested.

The bundle's own rules (header, line decoding, end line) belong to
``faithful_mishpat.formats.bundle``, which this module loads when it is first needed.
Lines are told apart by how they start: ``{"path":`` is a file, ``{"structure":`` is
the structure, and ``{"end":`` is the end line. The end line's file count and hash are
checked against what arrived; the structure's ``gaps`` (present only when the exporter
could not read a part) are returned to the caller.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import importlib
import os
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from faithful_core.collect import names, winrm

from faithful_mishpat.errors import CollectionError, InputError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

install_hint = functools.partial(names.install_hint, "faithful-mishpat")
"""Say how to install mishpat with extras, for the messages faithful-core writes."""
_END = b'{"end":'
_FILE = b'{"path":'
_STRUCTURE = b'{"structure":'
_BAD_LINE = (ValueError, InputError)
"""What the bundle functions raise for a line that breaks the schema."""


def _bundle() -> Any:
    """Return the bundle module, imported when first needed."""
    return importlib.import_module("faithful_mishpat.formats.bundle")


@dataclass(frozen=True)
class Result:
    """What a collection wrote.

    Attributes:
        path: The published file.
        files: How many backup files it holds.
        gaps: What the exporter could not read, as ``what: reason`` sentences.
    """

    path: Path
    files: int
    gaps: tuple[str, ...]


def parameters(
    *,
    names: list[str] | None = None,
    guids: list[str] | None = None,
    every_gpo: bool = False,
    server: str | None = None,
) -> dict[str, Any]:
    """Return the script's parameters for a remote run.

    Exactly one of ``names``, ``guids`` and ``every_gpo`` selects the GPOs. The
    script reads from ``server`` (the controller the session is on) so that its
    directory reads are not a second hop.

    Raises:
        CollectionError: Not exactly one selection was given.
    """
    chosen = [bool(names), bool(guids), every_gpo]
    if sum(chosen) != 1:
        msg = "give exactly one of --all, --name and --guid"
        raise CollectionError(msg)
    values: dict[str, Any] = {"ToPipeline": True}
    if names:
        values["Name"] = list(names)
    elif guids:
        values["Guid"] = list(guids)
    else:
        values["All"] = True
    if server:
        values["Server"] = server
    return values


class _Sink:
    """Write streamed lines to a private file and check them as they come."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.temp = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.part"
        descriptor = os.open(self.temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.handle = os.fdopen(descriptor, "wb")
        self.digest = hashlib.sha256()
        self.files = 0
        self.structures = 0
        self.trailer: Any = None
        self.gaps: tuple[str, ...] = ()
        self.lines = 0

    @property
    def ended(self) -> bool:
        return self.trailer is not None

    def take(self, item: object) -> None:
        if self.trailer is not None:
            msg = "the exporter sent output after its end line"
            raise CollectionError(msg)
        if not isinstance(item, str) or not item.isascii() or "\n" in item or "\r" in item:
            msg = (
                f"the exporter sent something that is not one line of text (line {self.lines + 1})"
            )
            raise CollectionError(msg)
        raw = item.encode("ascii") + b"\n"
        bundle = _bundle()
        if len(raw) > bundle.MAX_LINE:
            msg = f"line {self.lines + 1} from the exporter is too long"
            raise CollectionError(msg)
        if self.lines == 0:
            self._header(raw, bundle)
        elif raw.startswith(_END):
            self.trailer = self._end_line(raw, bundle)
        elif raw.startswith(_FILE):
            self.files += 1
        elif raw.startswith(_STRUCTURE):
            self._structure(raw, bundle)
        else:
            msg = f"the exporter sent a line of an unknown kind (line {self.lines + 1})"
            raise CollectionError(msg)
        self.lines += 1
        self.handle.write(raw)
        if self.trailer is None:
            self.digest.update(raw)

    @staticmethod
    def _header(raw: bytes, bundle: Any) -> None:
        # The header must pass the rules the reader applies, or the file would be
        # published and then refused by the reader.
        if not raw.startswith(bundle.MARKER):
            msg = "the exporter's first line is not a mishpat export header"
            raise CollectionError(msg)
        try:
            bundle.check_header(raw)
        except _BAD_LINE as exc:
            msg = f"the exporter's header is not valid: {exc}"
            raise CollectionError(msg) from None

    @staticmethod
    def _end_line(raw: bytes, bundle: Any) -> Any:
        try:
            return bundle.check_end(bundle.decode_line(raw))
        except _BAD_LINE as exc:
            msg = f"the exporter's end line is not valid: {exc}"
            raise CollectionError(msg) from None

    def _structure(self, raw: bytes, bundle: Any) -> None:
        self.structures += 1
        if self.structures > 1:
            msg = "the exporter sent more than one structure line"
            raise CollectionError(msg)
        try:
            body = bundle.decode_line(raw)["structure"]
            # "gaps" is present only when the exporter could not read a part.
            gaps = body.get("gaps", [])
            self.gaps = tuple(f"{gap['what']}: {gap['reason']}" for gap in gaps)
        except (*_BAD_LINE, KeyError, TypeError, AttributeError) as exc:
            msg = f"the exporter's structure line is not valid: {type(exc).__name__}"
            raise CollectionError(msg) from None

    def finish(self) -> Result:
        """Check the end line against what arrived."""
        self.handle.close()
        trailer = self.trailer
        if trailer is None:
            msg = "the export ended without its end line, so it did not finish"
            raise CollectionError(msg)
        if self.structures != 1:
            msg = "the export has no structure line, so it did not finish"
            raise CollectionError(msg)
        if trailer.files != self.files or trailer.sha256 != self.digest.hexdigest():
            msg = (
                f"the export's end line does not match what arrived ({self.files} files "
                "received); the transfer was damaged"
            )
            raise CollectionError(msg)
        return Result(self.destination, self.files, self.gaps)

    def publish(self, *, force: bool) -> None:
        """Put the checked file in place without following a link or clobbering."""
        winrm.publish_file(self.temp, self.destination, force=force)

    def discard(self) -> None:
        with contextlib.suppress(OSError):
            self.handle.close()
        with contextlib.suppress(OSError):
            self.temp.unlink()


def collect(  # noqa: PLR0913 - one argument per collection choice
    target: winrm.Target,
    script: str,
    script_parameters: dict[str, Any],
    destination: Path,
    *,
    force: bool,
    clock: Callable[[], float] = time.monotonic,
) -> Result:
    """Run the exporter on the target and write its file to ``destination``.

    Raises:
        CollectionError: The connection, authentication, or export failed, or
            what arrived does not match the exporter's end line. Every message has
            the secret removed, and no partial file is left.
    """
    try:
        sink = _Sink(destination)
    except OSError as exc:
        msg = f"cannot write to {destination.parent}: {exc.strerror or exc}"
        raise CollectionError(msg) from None
    return winrm.collect(
        target,
        script,
        script_parameters,
        destination,
        sink=sink,
        noun="exporter",
        hint=install_hint("live"),
        force=force,
        clock=clock,
    )
