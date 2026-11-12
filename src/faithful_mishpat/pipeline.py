# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read both sides, record exactly what was read, and compare them."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from faithful_mishpat.compare import compare
from faithful_mishpat.errors import InputError, UsageError
from faithful_mishpat.inputs import display_name, read_side

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_mishpat.differences import Comparison
    from faithful_mishpat.model import Snapshot

_BLOCK = 1 << 20


@dataclass(frozen=True)
class InputFile:
    r"""One input as it was when mishpat read it.

    Attributes:
        name: The name as given, made safe to show.
        kind: ``report``, ``backup`` or ``export``.
        size: Its size in bytes; for a folder, the total of its files.
        sha256: The SHA-256 of a file's bytes. For a folder, the SHA-256 of one line
            per file, ``<relative path>\0<sha256 of the file>\n``, in path order, so
            the same files give the same value wherever the folder is.
    """

    name: str
    kind: str
    size: int
    sha256: str


def fingerprint(path: Path) -> tuple[int, str]:
    """Return a file's or folder's size and SHA-256 as :class:`InputFile` describes.

    Links inside a folder are not followed, as the backup reader does not follow them.

    Raises:
        InputError: Something cannot be read.
    """
    if not path.is_dir():
        return _file(path)
    lines = hashlib.sha256()
    total = 0
    try:
        members = sorted(
            (p for p in path.rglob("*") if p.is_file() and not p.is_symlink()),
            key=lambda p: p.relative_to(path).as_posix(),
        )
    except OSError as exc:
        msg = f"cannot read {display_name(path)}: {exc.strerror or exc}"
        raise InputError(msg) from exc
    for member in members:
        size, digest = _file(member)
        total += size
        relative = member.relative_to(path).as_posix().encode("utf-8", "surrogateescape")
        lines.update(relative + b"\0" + digest.encode("ascii") + b"\n")
    return total, lines.hexdigest()


def _file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while block := handle.read(_BLOCK):
                digest.update(block)
                size += len(block)
    except OSError as exc:
        msg = f"cannot read {display_name(path)}: {exc.strerror or exc}"
        raise InputError(msg) from exc
    return size, digest.hexdigest()


def input_names(before: Path, after: Path) -> tuple[str, str]:
    """Return how reports cite each input.

    Each input is cited by its file or folder name. When both have the same name (two
    backups of one GPO in different folders, say), the names are prefixed with
    ``before/`` and ``after/`` so every citation still says which side it came from.
    """
    names = display_name(before), display_name(after)
    if names[0].casefold() != names[1].casefold():
        return names
    return f"before/{names[0]}", f"after/{names[1]}"


def run(
    before: Path, after: Path, *, match: str = "guid"
) -> tuple[Comparison, Snapshot, list[InputFile]]:
    """Read both sides and compare them.

    Both inputs are fingerprinted before either is parsed, so the report records
    the inputs exactly as they were read.

    Raises:
        UsageError: Both sides are the same input.
        InputError: An input cannot be read or is not Group Policy.
    """
    prints = [fingerprint(before), fingerprint(after)]
    if prints[0] == prints[1]:
        msg = (
            f"{display_name(before)} and {display_name(after)} have the same contents; "
            "compare two different versions"
        )
        raise UsageError(msg)
    names = input_names(before, after)
    sides = [read_side(before, "before", names[0]), read_side(after, "after", names[1])]
    result = compare(sides[0], sides[1], match=match)
    result.before, result.after = names
    inputs = [
        InputFile(name, str(side.context.get("kind", "")), size, digest)
        for name, side, (size, digest) in zip(names, sides, prints, strict=True)
    ]
    return result, sides[1], inputs
