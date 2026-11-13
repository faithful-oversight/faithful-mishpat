# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""What mishpat knows about one version of Group Policy.

Readers turn exports into a :class:`Snapshot`; :mod:`faithful_mishpat.compare`
compares two snapshots. Everything here is plain data with no behaviour beyond
small conveniences, so readers and the comparison can be tested apart.

A snapshot says what it does not know. Context that an export does not hold, such
as link order in a Get-GPOReport file, is ``None`` (not captured) rather than empty
(captured and empty), and the comparison reports "not compared" for it instead of
inventing a difference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCOPES = ("Computer", "User")
"""The two halves of a GPO; settings outside either use the empty scope."""

ValueData = str | int | bool | None | list["ValueData"] | dict[str, "ValueData"]
"""A setting's compared value: JSON-shaped, already canonical (sets sorted)."""


@dataclass(frozen=True)
class Source:
    """Where a fact came from, so every difference can be checked by hand.

    Attributes:
        file: The input name as the user gave it (a file, a folder, or a file
            inside an export bundle, as ``bundle.jsonl:path/inside``).
        detail: Where inside it, such as ``LinksTo[2]`` or ``line 14``, or empty.
    """

    file: str
    detail: str = ""

    def __str__(self) -> str:
        """Return the file and detail, as reports cite them."""
        return f"{self.file} {self.detail}".strip()


@dataclass(frozen=True)
class Setting:
    """One configured item in a GPO.

    Attributes:
        scope: ``Computer``, ``User`` or empty.
        area: The extension, as a short stable name: ``Administrative Templates``,
            ``Registry``, ``Security``, ``Advanced Audit``, ``Scripts``,
            ``Preferences: Registry``, ``Registry.pol`` and so on. Unknown
            extensions use their namespace URI.
        kind: The item type within the area, such as ``Policy``, ``User Rights
            Assignment`` or ``Account``.
        key: The identity within ``(scope, area, kind)``, as text parts compared
            casefolded. Two settings with the same identity are the same setting.
        title: What a person calls it, for reports (often the same as ``key``).
        value: The compared value. Sets (members of a user right, trustees) are
            sorted lists so order alone never shows as a change.
        context: Shown with the setting but never compared, such as a policy's
            explanation text or a preference item's ``changed`` time.
        source: Where it was read.
    """

    scope: str
    area: str
    kind: str
    key: tuple[str, ...]
    title: str
    value: ValueData
    source: Source
    context: dict[str, str] = field(default_factory=dict)

    @property
    def identity(self) -> tuple[str, ...]:
        """The casefolded identity used to pair settings across versions."""
        named = (self.scope, self.area, self.kind, *self.key)
        return tuple(part.casefold() for part in named)


@dataclass(frozen=True)
class Trustee:
    """One permission entry on a GPO, as security filtering and delegation use it.

    Attributes:
        sid: Upper-case SID, or the name when no SID was recorded.
        name: The account name as recorded, for reports only.
        allow: Allow (``True``) or Deny.
        rights: The GPMC permission names, sorted, such as ``Apply Group Policy``.
    """

    sid: str
    name: str
    allow: bool
    rights: tuple[str, ...]

    @property
    def applies(self) -> bool:
        """Whether this entry is security filtering: an allow of Apply Group Policy."""
        return self.allow and "Apply Group Policy" in self.rights


@dataclass(frozen=True)
class Link:
    """A GPO linked to a scope of management (domain, OU or site).

    Attributes:
        target: The scope's path as the export gives it: ``SOMPath`` from a report
            (``corp.example/Servers``) or a distinguished name from the exporter.
            Compared casefolded.
        enabled: Whether the link is enabled.
        enforced: Whether the link is enforced (No Override).
        order: Link order on the target, 1 first, or ``None`` when the export does
            not record it (Get-GPOReport files and backups do not).
    """

    target: str
    enabled: bool
    enforced: bool
    order: int | None = None


@dataclass(frozen=True)
class WmiFilter:
    """The WMI filter a GPO uses.

    Attributes:
        name: The filter's name.
        description: Its description, or empty.
        identifier: Its id (a GUID), or empty when the export does not record it.
        query: The WQL text, or ``None`` when the export does not record it (only
            the mishpat exporter reads it from the directory).
    """

    name: str
    description: str = ""
    identifier: str = ""
    query: str | None = None


@dataclass
class Gpo:
    """One Group Policy object as exported.

    Attributes:
        guid: Lower-case GUID without braces. GPOs are paired by this.
        domain: The DNS domain name.
        name: The display name.
        computer_enabled: Whether the computer half is enabled, or ``None``.
        user_enabled: Whether the user half is enabled, or ``None``.
        versions: Version numbers by name (``computer directory``, ``computer
            sysvol``, ``user directory``, ``user sysvol``), for context only.
        trustees: Permission entries, or ``None`` when not exported.
        wmi_filter: The WMI filter, ``None`` when there is none, or the string
            ``"unknown"`` when the export cannot say.
        links: Links to scopes, or ``None`` when the export holds no links (a
            backup without its report).
        settings: Every configured item.
        source: Where the GPO was read.
        context: Facts shown but never compared, such as created and modified times.
    """

    guid: str
    domain: str
    name: str
    source: Source
    computer_enabled: bool | None = None
    user_enabled: bool | None = None
    versions: dict[str, int] = field(default_factory=dict)
    trustees: list[Trustee] | None = None
    wmi_filter: WmiFilter | str | None = "unknown"
    links: list[Link] | None = None
    settings: list[Setting] = field(default_factory=list)
    context: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Scope:
    """A scope of management (domain, OU or site) as the exporter read it.

    Attributes:
        path: Distinguished name.
        kind: ``domain``, ``ou`` or ``site``.
        blocked: Whether it blocks inheritance.
        links: Its links in order, as ``(gpo guid, enabled, enforced)``, order 1 first.
        source: Where it was read.
    """

    path: str
    kind: str
    blocked: bool
    links: tuple[tuple[str, bool, bool], ...]
    source: Source


@dataclass(frozen=True)
class Problem:
    """Something in an input that could not be read. Problems make a comparison incomplete.

    Attributes:
        source: Where.
        reason: What went wrong, in plain words.
    """

    source: Source
    reason: str


@dataclass
class Snapshot:
    """One side of a comparison: every GPO an input holds, and what it could not read.

    Attributes:
        label: How reports name this side (``before`` / ``after`` or the input name).
        inputs: The input names this side was read from.
        gpos: GPOs by GUID.
        scopes: Scopes of management by casefolded path, or ``None`` when the input
            holds no domain structure (only the mishpat exporter records it). With
            it, link order and blocked inheritance can be compared.
        domain_wide: Whether the input is a whole domain, so a GPO missing from it
            was deleted rather than simply not exported.
        problems: What could not be read.
        context: Facts about the export shown in reports, such as when it was taken.
    """

    label: str
    inputs: list[str]
    gpos: dict[str, Gpo] = field(default_factory=dict)
    scopes: dict[str, Scope] | None = None
    domain_wide: bool = False
    problems: list[Problem] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


def evidence_key(scope: str, *, raw: bool = False) -> str:
    """Return the :attr:`Gpo.context` key that says whether one source of settings was read.

    Readers set ``evidence:computer settings`` and ``evidence:user settings`` for the
    settings in a report, and ``evidence:computer registry.pol`` and ``evidence:user
    registry.pol`` for Registry.pol values, to ``read``, ``partial`` (read, but something in
    it was skipped) or ``unreadable``. A setting in
    one input only is a difference only when its source was read on both sides; a GPO
    with no such key (one built by hand) counts as read.
    """
    return f"evidence:{scope.casefold()} {'registry.pol' if raw else 'settings'}"
