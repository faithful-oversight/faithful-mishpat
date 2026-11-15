# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read ``Registry.pol`` files ([MS-GPREG] 2.2.1, "PReg" version 1).

A file is the signature ``PReg``, the version 1, and then entries
``[key;value;type;size;data]`` whose text parts are UTF-16LE and whose numbers are
little-endian 32-bit. Parsing is adapted from merilo's reader (Apache-2.0, same company).

Each entry becomes one :class:`~faithful_mishpat.model.Setting` in the area
``Registry.pol``. The scope is the folder the file came from (``Computer`` for
``Machine``, ``User`` for ``User``), the key is ``(key path, value name)`` and the value is
``{"type": <name>, "data": <canonical data>}``. The kind is ``Value``, or ``Directive`` for
an entry whose value name starts with ``**``.

mishpat compares definitions, not the effect of applying them, so the directives
(``**del.``, ``**delvals.``, ``**DeleteValues``, ``**DeleteKeys``, ``**SecureKey``,
``**soft.``) are kept as settings of their own and are never resolved against the values.

Data by type: ``REG_SZ`` and ``REG_EXPAND_SZ`` are text without the terminator,
``REG_MULTI_SZ`` is a list of text, ``REG_DWORD``, ``REG_DWORD_BIG_ENDIAN`` and
``REG_QWORD`` are integers, and ``REG_BINARY``, ``REG_NONE`` and every other type are lower
case hex. Data that does not fit its type (a DWORD that is not four bytes, text that is not
UTF-16) is kept as hex and noted as a problem.

Repeated entries: the same key path and value name (compared without regard to case, as
the registry does) can appear more than once. Windows applies entries in order, so the
later entry wins: the setting holds the last entry's value and source, keeps the position
of the first, and records ``occurrences`` in its context when there was more than one.

A file that cannot be read produces a problem, never an exception. A wrong signature or
version gives no settings; a damaged entry stops the read and keeps the entries before it, as
does the entry after the first :data:`MAX_ENTRIES`. Either way ``ok`` is false.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from faithful_mishpat.model import Problem, Setting, Source, ValueData

SIGNATURE = b"PReg"
VERSION = 1
AREA = "Registry.pol"
TYPE_NAMES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}
MAX_ENTRIES = 100_000
"""Most entries read from one file. A real ``Registry.pol`` holds at most a few thousand.

Each entry becomes a setting, and a changed one a difference and a report record: about 5 KB
of memory and 760 bytes of JSON for a 41-byte entry, so the limit keeps a crafted file of
64 MiB (over a million entries) from needing gigabytes."""
_HEADER = 8
_SZ = (1, 2)
_MULTI_SZ = 7
_NUMBERS = (4, 5, 11)
_DWORD_BE = 5
_QWORD_TYPE = 11
_DWORD = 4
_QWORD = 8


@dataclass
class PolRead:
    """What one ``Registry.pol`` file held.

    Attributes:
        settings: One setting per distinct key path and value name.
        problems: What could not be read.
        ok: ``False`` when the file could not be read completely.
    """

    settings: list[Setting] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    ok: bool = True


class _DamagedError(ValueError):
    """An entry that cannot be read."""


@dataclass
class _Entry:
    key: str
    name: str
    kind: int
    data: bytes


def _expect(data: bytes, position: int, char: str) -> int:
    if data[position : position + 2] != char.encode("utf-16-le"):
        msg = f"expected {char!r} at byte {position}"
        raise _DamagedError(msg)
    return position + 2


def _text(data: bytes, position: int) -> tuple[str, int]:
    """Read NUL-terminated UTF-16LE text."""
    end = position
    while end + 1 < len(data):
        if data[end : end + 2] == b"\x00\x00":
            try:
                return data[position:end].decode("utf-16-le"), end + 2
            except UnicodeDecodeError:
                msg = f"the text at byte {position} is not valid UTF-16"
                raise _DamagedError(msg) from None
        end += 2
    msg = "the entry is cut short"
    raise _DamagedError(msg)


def _number(data: bytes, position: int) -> tuple[int, int]:
    if position + _DWORD > len(data):
        msg = "the entry is cut short"
        raise _DamagedError(msg)
    return struct.unpack_from("<I", data, position)[0], position + _DWORD


def _entry(data: bytes, position: int) -> tuple[_Entry, int]:
    position = _expect(data, position, "[")
    key, position = _text(data, position)
    position = _expect(data, position, ";")
    name, position = _text(data, position)
    position = _expect(data, position, ";")
    kind, position = _number(data, position)
    position = _expect(data, position, ";")
    size, position = _number(data, position)
    position = _expect(data, position, ";")
    if position + size > len(data):
        msg = "the entry is cut short"
        raise _DamagedError(msg)
    value = data[position : position + size]
    position = _expect(data, position + size, "]")
    return _Entry(key, name, kind, value), position


def _decode_text(data: bytes) -> str:
    return data.decode("utf-16-le")


def _canonical(entry: _Entry) -> tuple[ValueData, str | None]:
    """Return the canonical data and a note when the data does not fit its type."""
    data, kind = entry.data, entry.kind
    try:
        if kind in _SZ:
            return _decode_text(data).rstrip("\x00"), None
        if kind == _MULTI_SZ:
            return [part for part in _decode_text(data).split("\x00") if part], None
    except UnicodeDecodeError:
        return data.hex(), "its text is not valid UTF-16, so it is shown as hex"
    if kind in _NUMBERS:
        width = _QWORD if kind == _QWORD_TYPE else _DWORD
        if len(data) != width:
            return data.hex(), f"its data is {len(data)} bytes, not {width}, so it is shown as hex"
        return int.from_bytes(data, "big" if kind == _DWORD_BE else "little"), None
    return data.hex(), None


def read_registry_pol(data: bytes, scope: str, base: Source) -> PolRead:
    """Read a ``Registry.pol`` file into settings.

    Args:
        data: The file's bytes.
        scope: ``Computer`` or ``User``.
        base: Where the file is; each setting's detail adds its entry number.

    Returns:
        The settings and problems. See the module documentation for the rules.
    """
    result = PolRead()

    def problem(reason: str) -> None:
        result.ok = False
        result.problems.append(Problem(base, reason))

    if len(data) < _HEADER or data[:4] != SIGNATURE:
        problem("Registry.pol does not start with the PReg signature; its values were not read")
        return result
    if struct.unpack_from("<I", data, 4)[0] != VERSION:
        problem("Registry.pol has a version other than 1; its values were not read")
        return result
    settings: dict[tuple[str, str], Setting] = {}
    order: list[tuple[str, str]] = []
    counts: dict[tuple[str, str], int] = {}
    position = _HEADER
    number = 0
    while position < len(data):
        number += 1
        if number > MAX_ENTRIES:
            problem(
                f"Registry.pol holds more than {MAX_ENTRIES} entries; "
                f"the entries after the first {MAX_ENTRIES} were not read"
            )
            break
        try:
            entry, position = _entry(data, position)
        except _DamagedError as exc:
            problem(
                f"Registry.pol entry {number} is damaged ({exc}); "
                "it and the entries after it were not read"
            )
            break
        value, note = _canonical(entry)
        where = Source(base.file, f"{base.detail} entry {number}".strip())
        if note:
            result.problems.append(Problem(where, f"The value {entry.name!r} is kept, but {note}"))
        identity = (entry.key.casefold(), entry.name.casefold())
        counts[identity] = counts.get(identity, 0) + 1
        if identity not in settings:
            order.append(identity)
        kind = "Directive" if entry.name.startswith("**") else "Value"
        title = f"{entry.key}\\{entry.name}" if entry.name else entry.key
        settings[identity] = Setting(
            scope=scope,
            area=AREA,
            kind=kind,
            key=(entry.key, entry.name),
            title=title,
            value={"type": TYPE_NAMES.get(entry.kind, f"REG_TYPE_{entry.kind}"), "data": value},
            source=where,
            context={"occurrences": str(counts[identity])} if counts[identity] > 1 else {},
        )
    result.settings = [settings[identity] for identity in order]
    return result
