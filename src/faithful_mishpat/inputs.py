# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read one side of a comparison, detecting what the input is from its content.

* A folder is a ``Backup-GPO`` folder, or a root holding many backup folders.
* A file that starts with the bundle marker is a mishpat export bundle.
* Any other file is read as ``Get-GPOReport -ReportType Xml`` output, whatever its
  extension, and is an error if it is not one.

``Snapshot.domain_wide`` is ``True`` for a ``<GPOS>`` report (``Get-GPOReport -All``) and
for a bundle whose header says ``scope: "all"``, and ``False`` for a single ``<GPO>``
report and for backups (a backup set is a selection). ``Snapshot.context["kind"]`` is
``report``, ``backup`` or ``export``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import backup, bundle, report, xmlsafe
from faithful_mishpat.model import Snapshot, Source

if TYPE_CHECKING:
    from pathlib import Path

_SNIFF = 64


def display_name(path: Path) -> str:
    """Return the input's name made safe to print: bytes that are not UTF-8 are escaped."""
    name = path.name or path.resolve().name or str(path)
    return os.fsencode(name).decode("utf-8", "backslashreplace")


def _read_file(path: Path, name: str) -> Snapshot:
    try:
        with path.open("rb") as handle:
            start = handle.read(_SNIFF)
            is_bundle = bundle.is_bundle(start)
            data = b"" if is_bundle else start + handle.read(xmlsafe.MAX_BYTES)
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    if is_bundle:
        return _bundle(path, name)
    result = report.read_report(data, Source(name))
    return Snapshot(
        label="",
        inputs=[name],
        gpos={gpo.guid: gpo for gpo in result.gpos},
        domain_wide=result.wrapped,
        problems=list(result.problems),
        context={"kind": "report"},
    )


def _bundle(path: Path, name: str) -> Snapshot:
    result = bundle.read_bundle(path, name)
    return Snapshot(
        label="",
        inputs=[name],
        gpos={gpo.guid: gpo for gpo in result.gpos},
        scopes=result.scopes,
        domain_wide=result.domain_wide,
        problems=list(result.problems),
        context={"kind": "export", **result.context},
    )


def _read_folder(path: Path, name: str) -> Snapshot:
    result = backup.read_backups(backup.FolderTree(path), name)
    if not result.gpos and not result.problems:
        msg = f"{name} is not a Backup-GPO folder: no bkupInfo.xml was found in it or below it"
        raise InputError(msg)
    return Snapshot(
        label="",
        inputs=[name],
        gpos={gpo.guid: gpo for gpo in result.gpos},
        problems=list(result.problems),
        context={"kind": "backup"},
    )


def read_side(path: Path, label: str) -> Snapshot:
    """Read one input into a snapshot.

    Args:
        path: A Get-GPOReport XML file, an export bundle, or a Backup-GPO folder or root.
        label: How reports name this side (``before`` or ``after``).

    Returns:
        The snapshot, with every problem found while reading.

    Raises:
        InputError: The path is missing, unreadable, or none of the three kinds, or it is
            ambiguous (two backups of one GPO).
    """
    name = display_name(path)
    if path.is_dir():
        snapshot = _read_folder(path, name)
    elif path.is_file():
        snapshot = _read_file(path, name)
    else:
        msg = f"{name} does not exist or is neither a file nor a folder"
        raise InputError(msg)
    snapshot.label = label
    return snapshot


__all__ = ["display_name", "read_side"]
