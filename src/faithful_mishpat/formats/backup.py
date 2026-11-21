# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read ``Backup-GPO`` output: one backup folder, or a root holding many.

A backup folder holds ``bkupInfo.xml`` (which GPO and when), ``Backup.xml`` (the GPO's
core settings), ``gpreport.xml`` (the ``Get-GPOReport`` XML, the primary source) and
``DomainSysvol/GPO/{Machine,User}/registry.pol``. Everything else is ignored. File and
folder names are looked up without regard to case.

Input is the abstract :class:`Tree`, so the same reader serves a real folder
(:class:`FolderTree`) and the files of an export bundle (:class:`MemoryTree`).

A root is any folder that is not itself a backup folder: every folder below it (up to
:data:`MAX_SEARCH_DEPTH` levels, so grouped layouts work) that holds ``bkupInfo.xml`` is
one GPO. Two backups of the same GPO GUID under one root are ambiguous, which raises
:class:`~faithful_mishpat.errors.InputError` naming both folders. A ``bkupInfo.xml`` that
the search does not read, because it is deeper than that or inside another backup folder,
is a problem, so the input is never reported as read in full (see :func:`search_backups`).

Per backup the GPO is the one in ``gpreport.xml``, plus the ``Registry.pol`` values (the
report has no registry key for Administrative Templates). Without a usable
``gpreport.xml`` the GPO is built from ``Backup.xml`` and ``bkupInfo.xml``: name, domain,
which half is enabled (``Options``: 1 turns the user half off, 2 the computer half off),
version numbers (``& 0xFFFF``), the WMI filter, ``registry.pol``, links ``None``, and a
problem saying the rest was not compared.

Every GPO read here has ``context["registry.pol"]``: ``"read"`` when both halves were
looked for (a missing file means no values), or ``"unreadable"`` when a file exists but
cannot be read. ``context["read from"]`` is ``backup`` or ``export``. A GPO that comes
only from a report has neither key, which is how a comparison knows a report cannot hold
``Registry.pol`` values.

The small files (``bkupInfo.xml``, ``Backup.xml``) are matched by element local name:
their namespaces (``.../GPOOperations`` and ``.../GPOOperations/Manifest``) differ and
carry no meaning here.
"""

from __future__ import annotations

import os
import re
import stat
import uuid
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

from faithful_core import xmlsafe

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats.registrypol import read_registry_pol
from faithful_mishpat.formats.report import read_report
from faithful_mishpat.model import Gpo, Problem, Source, WmiFilter, evidence_key

if TYPE_CHECKING:
    from pathlib import Path
    from xml.etree import ElementTree as ET

MAX_FILE = 64 * 1024 * 1024
"""Largest single file read from a backup, in bytes."""
MAX_SEARCH_DEPTH = 4
"""How many folder levels below a root are searched for backups."""
MAX_SCAN_FOLDERS = 200_000
"""How many folders beyond that depth are listed, only to find a backup that would not be read.

``mishpat compare --max-scan-folders`` changes it. Reaching it is a problem, so the run is
incomplete and fails."""

_WMI_ID = re.compile(r'ID\s*=\s*"(\{[^"]*\})"', re.IGNORECASE)
_USER_OFF = 1
_COMPUTER_OFF = 2
_VERSION_MASK = 0xFFFF


class TreeError(Exception):
    """A file or folder in a tree could not be read."""


class Tree(Protocol):
    """A read-only tree of files, with ``/``-separated paths relative to its root."""

    def entries(self, path: str) -> list[tuple[str, bool]]:
        """List a folder as ``(name, is_folder)``; ``""`` is the root.

        Raises:
            TreeError: The folder cannot be listed.
        """
        ...

    def read(self, path: str) -> bytes:
        """Return a file's bytes.

        Raises:
            TreeError: The file cannot be read or is larger than :data:`MAX_FILE`.
        """
        ...


class FolderTree:
    """A real folder. Links and special files are not followed or read.

    Each one that a listing meets is recorded in :attr:`skipped`, so the reader can say
    the input was not read in full.
    """

    def __init__(self, root: Path) -> None:
        """Read the folder at ``root``."""
        self.root = root
        self.skipped: list[str] = []
        self._skipped: set[str] = set()

    @staticmethod
    def _is_link(entry: os.DirEntry[str]) -> bool:
        return entry.is_symlink()

    def _skip(self, path: str) -> None:
        """Record a skipped entry once, however many times its folder is listed."""
        if path not in self._skipped:
            self._skipped.add(path)
            self.skipped.append(path)

    def entries(self, path: str) -> list[tuple[str, bool]]:
        """List a folder, leaving out links and anything that is not a file or folder."""
        folder = self.root.joinpath(*path.split("/")) if path else self.root
        try:
            with os.scandir(folder) as scan:
                kept = []
                for entry in scan:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if self._is_link(entry) or not (is_dir or entry.is_file(follow_symlinks=False)):
                        self._skip(f"{path}/{entry.name}" if path else entry.name)
                        continue
                    kept.append((entry.name, is_dir))
                return sorted(kept)
        except OSError as exc:
            msg = f"cannot list {path or '.'}: {exc.strerror or exc}"
            raise TreeError(msg) from None

    def read(self, path: str) -> bytes:
        """Return a file's bytes."""
        target = self.root.joinpath(*path.split("/"))
        try:
            facts = target.lstat()
            if not stat.S_ISREG(facts.st_mode):
                msg = f"{path} is a link or a special file, which mishpat does not read"
                raise TreeError(msg)
            if facts.st_size > MAX_FILE:
                msg = f"{path} is larger than {MAX_FILE} bytes"
                raise TreeError(msg)
            return target.read_bytes()
        except OSError as exc:
            msg = f"cannot read {path}: {exc.strerror or exc}"
            raise TreeError(msg) from None


class MemoryTree:
    """Files held in memory, keyed by relative path."""

    def __init__(self, files: dict[str, bytes]) -> None:
        """Hold ``files``, which must have unique paths."""
        self.files = files
        self._folders: dict[str, dict[str, bool]] = {"": {}}
        for path in files:
            parts = path.split("/")
            for depth, name in enumerate(parts):
                parent = "/".join(parts[:depth])
                is_folder = depth < len(parts) - 1
                self._folders.setdefault(parent, {}).setdefault(name, is_folder)
                if is_folder:
                    self._folders.setdefault("/".join(parts[: depth + 1]), {})

    def entries(self, path: str) -> list[tuple[str, bool]]:
        """List a folder."""
        return sorted(self._folders.get(path, {}).items())

    def read(self, path: str) -> bytes:
        """Return a file's bytes."""
        try:
            data = self.files[path]
        except KeyError:
            msg = f"{path} is not in the tree"
            raise TreeError(msg) from None
        if len(data) > MAX_FILE:
            msg = f"{path} is larger than {MAX_FILE} bytes"
            raise TreeError(msg)
        return data


def _join(*parts: str) -> str:
    return "/".join(part for part in parts if part)


def _lookup(tree: Tree, folder: str, name: str, *, want_folder: bool) -> str | None:
    """Find ``name`` in ``folder`` as Windows would, without regard to case.

    Returns its path, or ``None`` when nothing has that name.

    Raises:
        TreeError: Windows could not tell the candidates apart (two names that differ
            only in case, or a file and a folder of one name), the one found is a file
            where a folder is wanted or the reverse, or it is a link or special file
            that a folder listing skipped. Choosing one would hide the other.
    """
    wanted = name.casefold()
    found = [
        (entry, is_folder)
        for entry, is_folder in tree.entries(folder)
        if entry.casefold() == wanted
    ]
    skipped = [
        path
        for path in getattr(tree, "skipped", ())
        if path.rpartition("/")[0] == folder and path.rpartition("/")[2].casefold() == wanted
    ]
    where = _join(folder, name)
    if len(found) + len(skipped) > 1:
        msg = f"{where}: names that differ only in case are ambiguous on Windows"
        raise TreeError(msg)
    if skipped:
        msg = f"{skipped[0]} is a link or a special file, which mishpat does not read"
        raise TreeError(msg)
    if not found:
        return None
    entry, is_folder = found[0]
    if is_folder != want_folder:
        kinds = ("file", "folder")
        msg = f"{_join(folder, entry)} is a {kinds[is_folder]}, not a {kinds[want_folder]}"
        raise TreeError(msg)
    return _join(folder, entry)


def _resolve(tree: Tree, folder: str, *names: str) -> str | None:
    """Follow folder names (and a file name last) case-insensitively."""
    current = folder
    for index, name in enumerate(names):
        last = index == len(names) - 1
        found = _lookup(tree, current, name, want_folder=not last)
        if found is None:
            return None
        current = found
    return current


@dataclass
class BackupSearch:
    """Where the search for backups looked, and what it saw but did not read.

    Attributes:
        folders: The folders (relative paths, ``""`` for the root) that hold ``bkupInfo.xml``
            within the search depth. These are read.
        unread: ``(folder, reason)`` for every place the search met something it did not
            read: a folder with ``bkupInfo.xml`` below the search depth, or one inside another
            backup, a folder that could not be listed, or the point where the search gave
            up. Each becomes a problem, so the input is never reported as read in full.
    """

    folders: list[str] = field(default_factory=list)
    unread: list[tuple[str, str]] = field(default_factory=list)


def _deeper(tree: Tree, start: str, found: BackupSearch, budget: list[int], *, why: str) -> None:
    """Look below ``start`` only for ``bkupInfo.xml``, which is recorded but not read.

    At most ``budget[0]`` folders are listed in all; the search then says it gave up.
    """
    pending = [start]
    while pending:
        folder = pending.pop()
        if budget[0] <= 0:
            reason = (
                f"the search for backups below this folder stopped after {MAX_SCAN_FOLDERS} "
                f"folders; a backup {why} would not have been found"
            )
            found.unread.append((folder, reason))
            return
        budget[0] -= 1
        entries = tree.entries(folder)
        for name, is_folder in entries:
            if not is_folder:
                continue
            path = _join(folder, name)
            try:
                holds_backup = _lookup(tree, path, "bkupInfo.xml", want_folder=False) is not None
            except TreeError as exc:
                found.unread.append(
                    (path, f"it could not be listed, so backups in it were not looked for: {exc}")
                )
                continue
            if holds_backup:
                found.unread.append((path, f"a backup {why} was not read"))
            else:
                pending.append(path)


def search_backups(tree: Tree) -> BackupSearch:
    """Find the backups to read, and say what the search saw below them and did not read."""
    found = BackupSearch()
    budget = [MAX_SCAN_FOLDERS]
    if _lookup(tree, "", "bkupInfo.xml", want_folder=False) is not None:
        found.folders.append("")
        _deeper(tree, "", found, budget, why="inside another backup folder")
        return found
    deep = f"more than {MAX_SEARCH_DEPTH} folders below the input"

    def search(folder: str, depth: int) -> None:
        for name, is_folder in tree.entries(folder):
            if not is_folder:
                continue
            path = _join(folder, name)
            if _lookup(tree, path, "bkupInfo.xml", want_folder=False) is not None:
                found.folders.append(path)
            elif depth < MAX_SEARCH_DEPTH:
                search(path, depth + 1)
            else:
                _deeper(tree, path, found, budget, why=deep)

    search("", 1)
    for selected in list(found.folders):  # a backup below the root can hold another one too
        _deeper(tree, selected, found, budget, why="inside another backup folder")
    return found


def find_backups(tree: Tree) -> list[str]:
    """Return the folders (relative paths, ``""`` for the root) that hold ``bkupInfo.xml``."""
    return search_backups(tree).folders


@dataclass
class BackupRead:
    """What a backup folder or root held.

    Attributes:
        gpos: One GPO per backup, in folder order.
        problems: What could not be read.
    """

    gpos: list[Gpo] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)


@dataclass
class _Reader:
    tree: Tree
    name: str
    origin: str
    bundle: bool
    problems: list[Problem] = field(default_factory=list)

    def source(self, path: str, detail: str = "") -> Source:
        path = path or "."
        if self.bundle:
            return Source(f"{self.name}:{path}", detail)
        return Source(self.name, f"{path} {detail}".strip())

    def problem(self, path: str, reason: str) -> None:
        self.problems.append(Problem(self.source(path), reason))

    def xml(self, path: str) -> ET.Element | None:
        """Read and parse a small XML file; a failure is recorded and gives ``None``."""
        try:
            return xmlsafe.parse(self.tree.read(path), max_elements=xmlsafe.MAX_ELEMENTS)
        except TreeError as exc:
            self.problem(path, str(exc))
        except xmlsafe.XmlError as exc:
            self.problem(path, f"{path.rsplit('/', 1)[-1]} cannot be read: {exc}")
        return None


def _fields(root: ET.Element | None, *names: str) -> dict[str, str]:
    """Return the text of the children of the element reached by following ``names``."""
    current = root
    for name in names:
        if current is None:
            break
        current = next((c for c in current if xmlsafe.split(c.tag)[1] == name), None)
    if current is None:
        return {}
    return {xmlsafe.split(c.tag)[1]: (c.text or "").strip() for c in current}


def _guid(text: str) -> str | None:
    try:
        return str(uuid.UUID(text.strip().strip("{}")))
    except ValueError:
        return None


_DECIMAL = re.compile(r"[0-9]{1,10}")


def _int(text: str | None) -> int | None:
    """Read a small decimal number; anything else, such as ``²`` or 400 digits, is ``None``."""
    return int(text) if text and _DECIMAL.fullmatch(text) else None


def _wmi(core: dict[str, str], *, known: bool) -> WmiFilter | str | None:
    if not known:
        return "unknown"
    name = core.get("WMIFilterName", "")
    if not name:
        return None
    match = _WMI_ID.search(core.get("WMIFilter", ""))
    return WmiFilter(name=name, identifier=(_guid(match.group(1)) or "") if match else "")


def _from_core(
    guid: str, info: dict[str, str], core: dict[str, str], *, known: bool, source: Source
) -> Gpo:
    options = _int(core.get("Options"))
    versions = {}
    for key, label in (("MachineVersionNumber", "computer"), ("UserVersionNumber", "user")):
        number = _int(core.get(key))
        if number is not None:
            versions[f"{label} directory"] = number & _VERSION_MASK
    return Gpo(
        guid=guid,
        domain=info.get("GPODomain") or core.get("Domain", ""),
        name=info.get("GPODisplayName") or core.get("DisplayName") or guid,
        source=source,
        computer_enabled=None if options is None else not options & _COMPUTER_OFF,
        user_enabled=None if options is None else not options & _USER_OFF,
        versions=versions,
        wmi_filter=_wmi(core, known=known),
        links=None,
    )


def _with_filter_id(gpo: Gpo, core: dict[str, str]) -> None:
    """Fill the report's WMI filter id from ``Backup.xml`` when it is the same filter."""
    current = gpo.wmi_filter
    wanted = _wmi(core, known=bool(core))
    if (
        isinstance(current, WmiFilter)
        and isinstance(wanted, WmiFilter)
        and not current.identifier
        and wanted.name.casefold() == current.name.casefold()
    ):
        gpo.wmi_filter = replace(current, identifier=wanted.identifier)


def _report_gpo(reader: _Reader, folder: str, guid: str) -> Gpo | None:
    try:
        path = _resolve(reader.tree, folder, "gpreport.xml")
    except TreeError as exc:
        reader.problem(folder, str(exc))
        path = None
    where = "gpreport.xml missing"
    if path is not None:
        where = "gpreport.xml could not be used"
        try:
            data = reader.tree.read(path)
            result = read_report(data, reader.source(path))
        except (TreeError, InputError) as exc:
            reader.problem(path, str(exc))
        else:
            reader.problems.extend(result.problems)
            for gpo in result.gpos:
                if gpo.guid == guid:
                    return gpo
            reader.problem(path, f"gpreport.xml holds no GPO {guid}")
    reader.problem(folder, f"{where}: settings other than registry.pol were not compared")
    return None


def _registry_pol(reader: _Reader, folder: str, gpo: Gpo) -> None:
    for scope, half in (("Computer", "Machine"), ("User", "User")):
        gpo.context[evidence_key(scope, raw=True)] = _registry_half(
            reader, folder, gpo, scope, half
        )
    halves = (gpo.context[evidence_key(s, raw=True)] for s in ("Computer", "User"))
    gpo.context["registry.pol"] = "read" if all(h == "read" for h in halves) else "unreadable"


def _registry_half(reader: _Reader, folder: str, gpo: Gpo, scope: str, half: str) -> str:
    """Read one half's registry.pol; say ``read`` (in full, or absent) or ``unreadable``."""
    try:
        path = _resolve(reader.tree, folder, "DomainSysvol", "GPO", half, "registry.pol")
        if path is None:
            return "read"  # no file: this half sets no values
        data = reader.tree.read(path)
    except TreeError as exc:
        reader.problem(folder, str(exc))
        return "unreadable"
    result = read_registry_pol(data, scope, reader.source(path))
    gpo.settings.extend(result.settings)
    reader.problems.extend(result.problems)
    return "read" if result.ok else "unreadable"


def _read_one(reader: _Reader, folder: str) -> Gpo | None:
    tree = reader.tree
    info_path = _resolve(tree, folder, "bkupInfo.xml")
    info = _fields(reader.xml(info_path) if info_path else None)
    core_path = _resolve(tree, folder, "Backup.xml")
    core_root = reader.xml(core_path) if core_path else None
    core = _fields(core_root, "GroupPolicyObject", "GroupPolicyCoreSettings")
    guid = _guid(info.get("GPOGuid", "")) or _guid(core.get("ID", ""))
    if guid is None:
        reader.problem(folder, "The backup does not say which GPO it holds; it was not read")
        return None
    gpo = _report_gpo(reader, folder, guid)
    if gpo is None:
        gpo = _from_core(guid, info, core, known=bool(core), source=reader.source(folder))
        for scope in ("Computer", "User"):
            gpo.context[evidence_key(scope)] = "unreadable"
    else:
        _with_filter_id(gpo, core)
    gpo.context["read from"] = reader.origin
    for key, label in (
        ("ID", "backup id"),
        ("BackupTime", "backup time"),
        ("Comment", "backup comment"),
    ):
        if info.get(key):
            gpo.context[label] = info[key]
    _registry_pol(reader, folder, gpo)
    return gpo


def read_backups(
    tree: Tree, name: str, *, origin: str = "backup", bundle: bool = False
) -> BackupRead:
    """Read every backup in a tree.

    Args:
        tree: A folder or the files of a bundle.
        name: The input's display name, used in sources.
        origin: ``backup`` for a folder or ``export`` for a bundle; recorded in each GPO's
            ``context["read from"]``.
        bundle: Whether paths are inside a bundle, which changes how sources are written
            (``name:path`` rather than ``name`` and ``path``).

    Returns:
        The GPOs and problems. A tree with no ``bkupInfo.xml`` anywhere gives no GPOs.

    Raises:
        InputError: Two backups hold the same GPO GUID, or the tree cannot be listed.
    """
    reader = _Reader(tree, name, origin, bundle)
    try:
        search = search_backups(tree)
    except TreeError as exc:
        msg = f"{name}: {exc}"
        raise InputError(msg) from None
    for where, reason in search.unread:
        reader.problem(where, reason)
    result = BackupRead()
    seen: dict[str, str] = {}
    for folder in search.folders:
        try:
            gpo = _read_one(reader, folder)
        except TreeError as exc:  # a folder that cannot be listed, or an ambiguous name
            reader.problem(folder, f"the backup was not read: {exc}")
            continue
        if gpo is None:
            continue
        if gpo.guid in seen:
            first, second = seen[gpo.guid] or ".", folder or "."
            msg = f"{name} holds more than one backup of GPO {gpo.guid}: {first!r} and {second!r}"
            raise InputError(msg)
        seen[gpo.guid] = folder
        result.gpos.append(gpo)
    said = " ".join(p.reason for p in reader.problems)
    for path in sorted(set(getattr(tree, "skipped", ()))):
        if path not in said:  # not already named by the lookup that met it
            reader.problem(path, "is a link or a special file; mishpat does not follow or read it")
    result.problems = reader.problems
    return result
