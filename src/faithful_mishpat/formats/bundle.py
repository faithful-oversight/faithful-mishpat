# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read and write the mishpat export bundle.

The bundle is JSON Lines, laid out like toledot's collection file (and checked as
strictly). See ``schema/export-v1.schema.json`` for the exact shape of each line:

1. The header ``{"mishpat_export":1,"collector":{"name","version"},"domain",
   "collected_at","scope"}``. ``scope`` is ``"all"`` or a list of GPO GUIDs. A bundle starts
   with the bytes :data:`MARKER` (compact JSON, ``mishpat_export`` first).
2. Zero or more file lines ``{"path","size","sha256","data"}``: a file of a ``Backup-GPO``
   folder, its bytes in base64.
3. One ``{"structure": {...}}`` line: ``scopes`` (domain, OUs and sites, each with its raw
   ``gPLink``), ``wmi_filters`` (with the WQL query) and, only when the exporter could not
   read part of the directory, ``gaps`` (``{"what", "reason"}`` objects). Each gap becomes
   a problem ``"<what> was not read: <reason>"``, so the comparison is incomplete.
4. The trailer ``{"end":true,"files":N,"sha256":"<hex>"}``: the number of file lines and
   the SHA-256 of every byte before the trailer line. Nothing may follow it.

A bundle that fails any check is not hidden and does not stop the reading: a line that
breaks the schema, a file whose size or hash is wrong, a path that is not relative or
repeats another (compared without regard to case), a missing, wrong or unexpected trailer
are all :class:`~faithful_mishpat.model.Problem` objects, and every line that is fine is
still used. Only a bad first line raises :class:`~faithful_mishpat.errors.InputError`.

The files are placed in an in-memory tree and read with the backup reader, so a bundle
and a ``Backup-GPO`` folder give the same GPOs. ``structure`` becomes
:attr:`~faithful_mishpat.model.Snapshot.scopes`. The ``gPLink`` attribute lists links with
link order 1 last ([MS-GPOL]; merilo's ``parse_gplink`` and its link chain do the same).
Each GPO's links get their order from it, with the enabled and enforced flags the directory
states directly, and links the GPO's report does not list are
added, so with a structure :attr:`~faithful_mishpat.model.Gpo.links` is never ``None``.
Link targets are written as report ``SOMPath`` values (``corp.example/Servers``) so
that a bundle and a report file compare.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, NamedTuple

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import backup
from faithful_mishpat.model import Gpo, Link, Problem, Scope, Source, WmiFilter

if TYPE_CHECKING:
    from pathlib import Path

MARKER = b'{"mishpat_export":'
"""How every bundle starts, byte for byte."""
VERSION = 1
MAX_FILE = backup.MAX_FILE
"""Largest file a bundle may hold, in bytes."""
MAX_LINE = (MAX_FILE // 3 + 1) * 4 + 4096
"""The longest line accepted, in bytes: a largest file in base64 and its keys."""
MAX_FILES = 100_000
MAX_TOTAL = 1024 * 1024 * 1024
"""Most file bytes a bundle may hold in all."""
MAX_DEPTH = 8
MAX_NAME = 255
MAX_PATH = 512
MAX_STRUCTURE = 100_000

_SHA256 = re.compile(r"[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z")
_HEADER_KEYS = frozenset({"mishpat_export", "collector", "domain", "collected_at", "scope"})
_FILE_KEYS = frozenset({"path", "size", "sha256", "data"})
_TRAILER_KEYS = frozenset({"end", "files", "sha256"})
_SCOPE_KEYS = frozenset({"path", "kind", "blocked", "gplink"})
_FILTER_KEYS = frozenset({"id", "name", "description", "query"})
_GAP_KEYS = frozenset({"what", "reason"})
_KINDS = frozenset({"domain", "ou", "site"})
_GPLINK_OPTIONS_DISABLED = 1
_GPLINK_OPTIONS_ENFORCED = 2


class BadLineError(ValueError):
    """A line that is not what the schema says."""


class Header(NamedTuple):
    """The checked header.

    Attributes:
        collector: The collector's name and version, as ``"name version"``.
        domain: The domain the bundle was collected from.
        collected_at: When, as the header wrote it (UTC).
        scope: ``"all"``, or the GUIDs the collector was asked for (lower case).
    """

    collector: str
    domain: str
    collected_at: str
    scope: str | tuple[str, ...]


class Trailer(NamedTuple):
    """The checked end line: the file count and hash it states."""

    files: int
    sha256: str


# --- strict JSON ---------------------------------------------------------------------


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        if name in out:
            msg = f"the property {name!r} is repeated"
            raise BadLineError(msg)
        out[name] = value
    return out


def _constant(text: str) -> Any:
    msg = f"{text} is not JSON"
    raise BadLineError(msg)


def decode_line(line: bytes) -> dict[str, Any]:
    """Parse one line strictly: UTF-8, one object, no repeated names, valid Unicode.

    Raises:
        BadLineError: The line is not that.
    """
    try:
        value = json.loads(line.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
    except UnicodeDecodeError:
        msg = "the line is not UTF-8"
        raise BadLineError(msg) from None
    except RecursionError:
        msg = "the line is nested too deeply"
        raise BadLineError(msg) from None
    except ValueError as exc:
        msg = str(exc) if isinstance(exc, BadLineError) else "the line is not valid JSON"
        raise BadLineError(msg) from None
    if not isinstance(value, dict):
        msg = "the line is not a JSON object"
        raise BadLineError(msg)
    _check(value, 0)
    return value


def _check(value: object, depth: int) -> None:
    """Refuse deep nesting and text that is not valid Unicode."""
    if depth > MAX_DEPTH:
        msg = "the line is nested too deeply"
        raise BadLineError(msg)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            msg = "the line holds an unpaired surrogate"
            raise BadLineError(msg) from None
    elif isinstance(value, dict):
        for name, item in value.items():
            _check(name, depth + 1)
            _check(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check(item, depth + 1)


def _keys(value: dict[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    if unknown or missing:
        problem = f"unknown property {unknown[0]!r}" if unknown else f"no {missing[0]!r}"
        msg = f"the line has {problem}"
        raise BadLineError(msg)


def _string(value: object, what: str, *, limit: int = MAX_NAME, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        msg = f"{what} is not text of at most {limit} characters"
        raise BadLineError(msg)
    return value


def _integer(value: object, what: str, *, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= high:
        msg = f"{what} is not a whole number from 0 to {high}"
        raise BadLineError(msg)
    return value


def _guid(value: object, what: str) -> str:
    text = _string(value, what).strip("{}")
    try:
        return str(uuid.UUID(text))
    except ValueError:
        msg = f"{what} is not a GUID"
        raise BadLineError(msg) from None


def _hash(value: object, what: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        msg = f"{what} is not 64 lower-case hex digits"
        raise BadLineError(msg)
    return value


# --- header and trailer -------------------------------------------------------------


def check_header(line: bytes) -> Header:
    """Check the first line against the schema.

    Both the bundle reader and the remote collector call this, so a stream is published
    only if the reader will accept its first line.

    Raises:
        BadLineError: The line is too long or is not a header the schema allows.
    """
    if len(line) > MAX_LINE:
        msg = "the first line is too long"
        raise BadLineError(msg)
    value = decode_line(line)
    _keys(value, _HEADER_KEYS)
    if value["mishpat_export"] != VERSION or isinstance(value["mishpat_export"], bool):
        msg = f"mishpat_export is not {VERSION}, the only version this reader knows"
        raise BadLineError(msg)
    collector = value["collector"]
    if not isinstance(collector, dict):
        msg = "collector is not an object"
        raise BadLineError(msg)
    _keys(collector, frozenset({"name", "version"}))
    when = _string(value["collected_at"], "collected_at")
    try:
        if _TIME.fullmatch(when) is None:
            raise ValueError  # noqa: TRY301 - one message for both ways a time can be wrong
        datetime.strptime(when[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        msg = "collected_at is not a UTC time such as 2026-11-03T14:00:00Z"
        raise BadLineError(msg) from None
    scope = value["scope"]
    if scope != "all":
        if not isinstance(scope, list) or len(scope) > MAX_FILES:
            msg = 'scope is not "all" or a list of GPO GUIDs'
            raise BadLineError(msg)
        scope = tuple(_guid(item, "a GUID in scope") for item in scope)
    return Header(
        f"{_string(collector['name'], 'collector.name')} "
        f"{_string(collector['version'], 'collector.version')}",
        _string(value["domain"], "domain"),
        when,
        scope,
    )


def check_end(value: dict[str, Any]) -> Trailer:
    """Check a decoded end line against the schema.

    Whether the count and hash match the file is for the caller.

    Raises:
        BadLineError: The line breaks the schema.
    """
    _keys(value, _TRAILER_KEYS)
    if value["end"] is not True:
        msg = "the end line is not what the schema says"
        raise BadLineError(msg)
    return Trailer(
        _integer(value["files"], "files", high=MAX_FILES), _hash(value["sha256"], "sha256")
    )


def is_bundle(start: bytes) -> bool:
    """Whether a file's first bytes are those of a mishpat export bundle."""
    return start.startswith(MARKER)


# --- file lines ----------------------------------------------------------------------


def check_path(path: object) -> str:
    """Check a path inside a bundle: relative, ``/``-separated, no ``..``, no control characters.

    Raises:
        BadLineError: The path is none of those.
    """
    text = _string(path, "path", limit=MAX_PATH)
    parts = text.split("/")
    bad = (
        "\\" in text
        or ":" in text
        or any(ord(char) < 32 or ord(char) == 127 for char in text)  # noqa: PLR2004 - DEL
        or any(part in {"", ".", ".."} for part in parts)
    )
    if bad:
        msg = (
            f"the path {text[:80]!r} is not a relative path of non-empty names "
            "separated by '/', with no '.', '..', ':', '\\' or control characters"
        )
        raise BadLineError(msg)
    return text


def _file(value: dict[str, Any]) -> tuple[str, bytes]:
    _keys(value, _FILE_KEYS)
    path = check_path(value["path"])
    size = _integer(value["size"], "size", high=MAX_FILE)
    digest = _hash(value["sha256"], "sha256")
    encoded = value["data"]
    if not isinstance(encoded, str):
        msg = "data is not base64"
        raise BadLineError(msg)
    try:
        data = base64.b64decode(encoded, validate=True)
    except binascii.Error:
        msg = "data is not base64"
        raise BadLineError(msg) from None
    if len(data) != size:
        msg = f"the file has {len(data)} bytes, not the {size} the line says"
        raise BadLineError(msg)
    if hashlib.sha256(data).hexdigest() != digest:
        msg = "the file's contents do not match its sha256"
        raise BadLineError(msg)
    return path, data


# --- structure ------------------------------------------------------------------------


def parse_gplink(value: str) -> list[tuple[str, bool, bool]]:
    """Parse a ``gPLink`` value into ``(guid, enforced, disabled)`` in listed order.

    Each link is ``[LDAP://cn={GUID},cn=policies,...;options]`` ([MS-GPOL] 2.2.2).
    Option bit 1 disables the link; bit 2 enforces it. Link order 1 is the LAST entry.
    Ported from merilo's reader (Apache-2.0, same company).

    Raises:
        ValueError: A link is malformed.
    """
    links: list[tuple[str, bool, bool]] = []
    for raw in value.split("]"):
        part = raw.strip()
        if not part:
            continue
        if not part.startswith("[") or ";" not in part:
            msg = f"malformed gPLink entry {part[:80]!r}"
            raise ValueError(msg)
        path, _sep, options = part[1:].rpartition(";")
        start, end = path.find("{"), path.find("}")
        try:
            guid = str(uuid.UUID(path[start + 1 : end])) if 0 <= start < end else ""
            flags = int(options)
        except ValueError:
            guid, flags = "", -1
        if not guid or flags < 0:
            msg = f"malformed gPLink entry {part[:80]!r}"
            raise ValueError(msg)
        links.append(
            (guid, bool(flags & _GPLINK_OPTIONS_ENFORCED), bool(flags & _GPLINK_OPTIONS_DISABLED))
        )
    return links


def wql(parm2: str) -> str:
    r"""Write a WMI filter's ``msWMI-Parm2`` as its queries, one per line.

    The attribute holds a count, then for each query the lengths of its language,
    namespace and text followed by those three fields, all ``;``-separated, such as
    ``1;3;10;45;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE ...;``.
    Each query is written as ``<namespace>: <query>``. Text that does not follow the
    layout is returned unchanged, so nothing is lost.
    """
    try:
        count, _, rest = parm2.partition(";")
        queries = []
        for _ in range(int(count)):
            sizes = rest.split(";", 3)
            lang, space, text = (int(part) for part in sizes[:3])
            body = sizes[3]
            fields = [body[:lang], body[lang + 1 : lang + 1 + space]]
            start = lang + space + 2
            fields.append(body[start : start + text])
            if body[lang : lang + 1] != ";" or body[start - 1 : start] != ";":
                return parm2
            if body[start + text : start + text + 1] != ";" or min(lang, space, text) < 0:
                return parm2
            queries.append(f"{fields[1]}: {fields[2]}")
            rest = body[start + text + 1 :]
    except (ValueError, IndexError):
        return parm2
    return "\n".join(queries) if queries and not rest.strip() else parm2


_HEX = frozenset("0123456789abcdefABCDEF")


def _rdns(dn: str) -> list[tuple[str, str]] | None:
    r"""Split a distinguished name into (type, value) pairs as RFC 4514 writes them.

    A backslash keeps the next character (``\,``), or with two hex digits gives one
    byte of UTF-8 (``\2C``). Unescaped spaces around a type or value are dropped, but
    an escaped space is kept. Returns ``None`` when ``dn`` is not a distinguished name.
    """
    out: list[tuple[str, str]] = []
    # Each part is (bytes, escaped); a part's bytes are one character or one hex byte.
    name: list[tuple[bytes, bool]] | None = None
    value: list[tuple[bytes, bool]] = []
    i = 0
    while i < len(dn) + 1:
        char = dn[i] if i < len(dn) else ","
        if char == "\\" and i + 1 < len(dn):
            pair = dn[i + 1 : i + 3]
            if len(pair) == 2 and set(pair) <= _HEX:  # noqa: PLR2004 - two hex digits
                value.append((bytes.fromhex(pair), True))
                i += 3
            else:
                value.append((dn[i + 1].encode("utf-8"), True))
                i += 2
            continue
        if char == "=" and name is None:
            name, value = value, []
        elif char == ",":
            if name is None:
                return None
            out.append((_join(name).upper(), _join(value)))
            name, value = None, []
        else:
            value.append((char.encode("utf-8"), False))
        i += 1
    return out


def _join(parts: list[tuple[bytes, bool]]) -> str:
    """Join parts, dropping unescaped spaces at both ends."""
    start, end = 0, len(parts)
    while start < end and parts[start] == (b" ", False):
        start += 1
    while end > start and parts[end - 1] == (b" ", False):
        end -= 1
    return b"".join(p for p, _ in parts[start:end]).decode("utf-8", "replace")


def som_path(dn: str, kind: str) -> str:
    """Write a scope's distinguished name as a report ``SOMPath``.

    ``DC=corp,DC=example`` is ``corp.example``; ``OU=B,OU=A,DC=corp,DC=example`` is
    ``corp.example/A/B``; a site is its name. A name that is not a distinguished name is
    returned unchanged.
    """
    rdns = _rdns(dn)
    if rdns is None:
        return dn
    if kind == "site":
        return rdns[0][1]
    domain = ".".join(value for name, value in rdns if name == "DC")
    folders = [value for name, value in reversed(rdns) if name != "DC"]
    return "/".join([domain, *folders])


@dataclass
class _Structure:
    scopes: dict[str, Scope] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)
    filters: dict[str, str] = field(default_factory=dict)


def _read_structure(value: object, name: str, problems: list[Problem]) -> _Structure | None:
    where = Source(name, "structure")
    if (
        not isinstance(value, dict)
        or not {"scopes", "wmi_filters"} <= set(value)
        or set(value) - {"scopes", "wmi_filters", "gaps"}
    ):
        text = (
            'The structure is not {"scopes": [...], "wmi_filters": [...]} with an optional "gaps"'
        )
        problems.append(Problem(where, text))
        return None
    scopes, filters, gaps = value["scopes"], value["wmi_filters"], value.get("gaps", [])
    if not isinstance(scopes, list) or not isinstance(filters, list) or not isinstance(gaps, list):
        problems.append(Problem(where, "scopes, wmi_filters and gaps must be lists"))
        return None
    if max(len(scopes), len(filters), len(gaps)) > MAX_STRUCTURE:
        problems.append(Problem(where, f"The structure holds more than {MAX_STRUCTURE} entries"))
        return None
    result = _Structure()
    for number, entry in enumerate(scopes, 1):
        _scope(entry, Source(name, f"structure scope {number}"), result, problems)
    for number, entry in enumerate(filters, 1):
        _filter(entry, Source(name, f"structure wmi filter {number}"), result, problems)
    for number, entry in enumerate(gaps, 1):
        _gap(entry, Source(name, f"structure gap {number}"), problems)
    return result


def _gap(entry: object, where: Source, problems: list[Problem]) -> None:
    """Turn something the exporter could not read into a problem, so the run is incomplete."""
    try:
        if not isinstance(entry, dict):
            msg = "the entry is not an object"
            raise BadLineError(msg)  # noqa: TRY301 - reported with the other bad entries
        _keys(entry, _GAP_KEYS)
        what = _string(entry["what"], "what", limit=1024)
        reason = _string(entry["reason"], "reason", limit=4096)
    except BadLineError as exc:
        problems.append(Problem(where, f"A gap entry was skipped: {exc}"))
        return
    problems.append(Problem(where, f"{what} was not read: {reason}"))


def _scope(entry: object, where: Source, result: _Structure, problems: list[Problem]) -> None:
    try:
        if not isinstance(entry, dict):
            msg = "the entry is not an object"
            raise BadLineError(msg)  # noqa: TRY301 - reported with the other bad entries
        _keys(entry, _SCOPE_KEYS)
        path = _string(entry["path"], "path", limit=1024)
        kind = _string(entry["kind"], "kind")
        if kind not in _KINDS:
            msg = "kind is not domain, ou or site"
            raise BadLineError(msg)  # noqa: TRY301
        if not isinstance(entry["blocked"], bool):
            msg = "blocked is not true or false"
            raise BadLineError(msg)  # noqa: TRY301
        gplink = _string(entry["gplink"], "gplink", limit=1 << 20, empty=True)
        if path.casefold() in result.scopes:
            msg = f"the scope {path[:80]!r} appears twice"
            raise BadLineError(msg)  # noqa: TRY301
    except BadLineError as exc:
        problems.append(Problem(where, f"A scope was skipped: {exc}"))
        return
    try:
        links = tuple(
            (guid, not disabled, enforced)
            for guid, enforced, disabled in reversed(parse_gplink(gplink))
        )
    except ValueError as exc:
        problems.append(Problem(where, f"The links of {path[:80]!r} were not read: {exc}"))
        links = ()
    result.scopes[path.casefold()] = Scope(path, kind, entry["blocked"], links, where)
    result.paths[path.casefold()] = som_path(path, kind)


def _filter(entry: object, where: Source, result: _Structure, problems: list[Problem]) -> None:
    try:
        if not isinstance(entry, dict):
            msg = "the entry is not an object"
            raise BadLineError(msg)  # noqa: TRY301 - reported with the other bad entries
        _keys(entry, _FILTER_KEYS)
        identifier = _guid(entry["id"], "id")
        _string(entry["name"], "name")
        _string(entry["description"], "description", limit=1 << 16, empty=True)
        query = _string(entry["query"], "query", limit=1 << 20, empty=True)
    except BadLineError as exc:
        problems.append(Problem(where, f"A WMI filter was skipped: {exc}"))
        return
    result.filters[identifier] = wql(query)


def _apply_structure(gpos: list[Gpo], structure: _Structure) -> None:
    by_gpo: dict[str, list[Link]] = {}
    for key, scope in structure.scopes.items():
        for order, (guid, enabled, enforced) in enumerate(scope.links, 1):
            by_gpo.setdefault(guid, []).append(Link(structure.paths[key], enabled, enforced, order))
    for gpo in gpos:
        known = {link.target.casefold(): link for link in by_gpo.get(gpo.guid, [])}
        merged = [
            replace(
                link,
                enabled=known[link.target.casefold()].enabled,
                enforced=known[link.target.casefold()].enforced,
                order=known[link.target.casefold()].order,
            )
            if link.target.casefold() in known
            else link
            for link in gpo.links or []
        ]
        listed = {link.target.casefold() for link in merged}
        merged.extend(link for target, link in known.items() if target not in listed)
        gpo.links = merged
        current = gpo.wmi_filter
        if isinstance(current, WmiFilter) and current.identifier in structure.filters:
            gpo.wmi_filter = replace(current, query=structure.filters[current.identifier])


# --- reading --------------------------------------------------------------------------


@dataclass
class BundleRead:
    """What a bundle held.

    Attributes:
        gpos: The GPOs.
        problems: What could not be read.
        scopes: The domain structure, by casefolded path, or ``None`` when the bundle has
            no ``structure`` line.
        domain_wide: Whether the header says ``scope: "all"``.
        context: Facts from the header: collector, domain, when, scope.
    """

    gpos: list[Gpo] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    scopes: dict[str, Scope] | None = None
    domain_wide: bool = False
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class _State:
    name: str
    files: dict[str, bytes] = field(default_factory=dict)
    seen: set[str] = field(default_factory=set)
    folders: set[str] = field(default_factory=set)
    total: int = 0
    count: int = 0
    structure: _Structure | None = None
    structure_seen: bool = False
    problems: list[Problem] = field(default_factory=list)

    def add_file(self, value: dict[str, Any], where: Source) -> None:
        self.count += 1
        try:
            path, data = _file(value)
        except BadLineError as exc:
            self.problems.append(Problem(where, f"The file was not read: {exc}"))
            return
        folded = path.casefold()
        parts = folded.split("/")
        parents = {"/".join(parts[:n]) for n in range(1, len(parts))}
        reason = None
        if folded in self.seen or folded in self.folders:
            reason = f"the path {path!r} repeats an earlier path (compared without regard to case)"
        elif parents & self.seen:
            reason = f"the path {path!r} is inside a file"
        elif len(self.seen) >= MAX_FILES or self.total + len(data) > MAX_TOTAL:
            reason = "the bundle holds more files or bytes than mishpat reads"
        if reason:
            self.problems.append(Problem(where, f"The file was not used: {reason}"))
            return
        self.seen.add(folded)
        self.folders |= parents
        self.files[path] = data
        self.total += len(data)

    def add_structure(self, value: dict[str, Any], where: Source) -> None:
        if self.structure_seen:
            self.problems.append(Problem(where, "A second structure line was not used"))
            return
        self.structure_seen = True
        self.structure = _read_structure(value["structure"], self.name, self.problems)


def _lines(handle: Any, first: bytes, state: _State) -> None:
    digest = hashlib.sha256(first)
    number = 1
    ended = False
    while True:
        line = handle.readline(MAX_LINE + 1)
        if not line:
            break
        number += 1
        where = Source(state.name, f"line {number}")
        if ended:
            state.problems.append(Problem(where, "The file continues after its end line."))
            return
        if len(line) > MAX_LINE:
            text = f"The line is longer than {MAX_LINE} bytes; the rest is not read."
            state.problems.append(Problem(where, text))
            return
        try:
            value = decode_line(line)
        except BadLineError as exc:
            digest.update(line)
            state.problems.append(Problem(where, f"The line is not valid: {exc}."))
            continue
        if "end" in value:
            ended = True
            _trailer(value, where, state, digest.hexdigest())
            continue
        digest.update(line)
        if "structure" in value and len(value) == 1:
            state.add_structure(value, where)
        else:
            state.add_file(value, where)
    if not ended:
        text = (
            "The file ends without its end line, so it was cut short or the collection "
            "did not finish. Files may be missing."
        )
        state.problems.append(Problem(Source(state.name, f"line {number}"), text))


def _trailer(value: dict[str, Any], where: Source, state: _State, digest: str) -> None:
    try:
        trailer = check_end(value)
    except BadLineError as exc:
        state.problems.append(Problem(where, f"The end line is not valid: {exc}."))
        return
    if trailer.files != state.count:
        text = (
            f"The end line counts {trailer.files} files but {state.count} were read. "
            "Files are missing or the file was altered."
        )
        state.problems.append(Problem(where, text))
    if trailer.sha256 != digest:
        state.problems.append(
            Problem(where, "The file's contents do not match the hash in its end line.")
        )


def read_bundle(path: Path, name: str) -> BundleRead:
    """Read an export bundle.

    Args:
        path: The file.
        name: The display name used in sources.

    Returns:
        The GPOs, structure and problems. See the module documentation.

    Raises:
        InputError: The file cannot be opened, its first line is not a header, or two
            backups in it hold the same GPO GUID.
    """
    try:
        handle = path.open("rb")
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror or exc}"
        raise InputError(msg) from None
    state = _State(name)
    with handle:
        first = handle.readline(MAX_LINE + 1)
        try:
            header = check_header(first)
        except BadLineError as exc:
            msg = f"{name} is not a mishpat export bundle: {exc}"
            raise InputError(msg) from None
        _lines(handle, first, state)
    result = BundleRead(
        problems=state.problems,
        domain_wide=header.scope == "all",
        context={
            "collector": header.collector,
            "domain": header.domain,
            "collected at": header.collected_at,
            "scope": "all" if header.scope == "all" else f"{len(header.scope)} GPOs",
        },
    )
    read = backup.read_backups(backup.MemoryTree(state.files), name, origin="export", bundle=True)
    result.gpos = read.gpos
    result.problems.extend(read.problems)
    if isinstance(header.scope, tuple):
        present = {gpo.guid for gpo in result.gpos}
        for guid in header.scope:
            if guid not in present:
                text = f"The header lists GPO {guid}, but the bundle holds no backup of it"
                result.problems.append(Problem(Source(name, "line 1"), text))
    if state.structure is not None:
        result.scopes = state.structure.scopes
        _apply_structure(result.gpos, state.structure)
    return result


# --- writing --------------------------------------------------------------------------


def encode(header: dict[str, Any], files: dict[str, bytes], structure: dict[str, Any]) -> bytes:
    """Build a bundle's bytes. This is the reference writer the tests use.

    Args:
        header: The header line's object; its first key must be ``mishpat_export``.
        files: File bytes by path inside the bundle, in the order to write them.
        structure: The ``structure`` object (``scopes`` and ``wmi_filters``).

    Raises:
        ValueError: The header does not start with ``mishpat_export``.
    """
    if next(iter(header), None) != "mishpat_export":
        msg = "the header's first key must be mishpat_export"
        raise ValueError(msg)

    def dump(value: object) -> bytes:
        return json.dumps(value, separators=(",", ":")).encode("ascii") + b"\n"

    body = dump(header)
    for path, data in files.items():
        body += dump(
            {
                "path": path,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    body += dump({"structure": structure})
    trailer = {"end": True, "files": len(files), "sha256": hashlib.sha256(body).hexdigest()}
    return body + dump(trailer)
