# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The result of comparing two snapshots: differences, gaps and problems.

:mod:`faithful_mishpat.compare` produces a :class:`Comparison`; the outputs render it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from faithful_mishpat.model import Problem, Source, ValueData

CATEGORIES = (
    "gpo",  # added, removed, renamed
    "status",  # computer or user half enabled or disabled
    "wmi-filter",
    "security-filtering",  # allow entries for Apply Group Policy
    "permissions",  # every other permission entry (delegation)
    "link",  # added, removed, enabled, enforced, order
    "inheritance",  # a scope blocks or stops blocking inheritance
    "setting",
)
"""What a difference is about, in the order reports list them."""

KINDS = ("added", "removed", "changed", "renamed", "only-before", "only-after")
"""``only-before``/``only-after``: a GPO in one input but not the other when the inputs
are not whole domains, so it cannot be said to have been added or removed."""


@dataclass(frozen=True)
class Difference:
    """One difference between the two sides.

    Attributes:
        category: One of :data:`CATEGORIES`.
        kind: One of :data:`KINDS`.
        gpo: The GPO's GUID, or empty for a scope-level difference (inheritance).
        gpo_name: The GPO's name on the after side (before side when removed).
        subject: What changed, in a few words: a setting's title, a link's
            target, a trustee's name, or a field such as ``computer half``.
        scope: ``Computer``, ``User`` or empty.
        area: The setting area, for setting differences; empty otherwise.
        before: The value before, or ``None`` when added.
        after: The value after, or ``None`` when removed.
        sources: Where each side was read, before first.
        note: Extra words a reader needs, such as why an order changed.
        labels: Words to show beside values, as ``(value, words)`` pairs: an
            account name beside a SID, or a security option's meaning beside its
            number. Never compared.
    """

    category: str
    kind: str
    gpo: str
    gpo_name: str
    subject: str
    before: ValueData = None
    after: ValueData = None
    scope: str = ""
    area: str = ""
    sources: tuple[Source, ...] = ()
    note: str = ""
    labels: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Gap:
    """Something that was not compared, and why.

    Gaps do not make a comparison incomplete: they are limits of the exports, stated
    so a reader does not assume a check was made.

    Attributes:
        subject: What was not compared, such as ``link order``.
        reason: Why, such as ``the before input is a Get-GPOReport file, which does
            not record link order``.
        gpo: The GPO it concerns, or empty when it concerns the whole comparison.
    """

    subject: str
    reason: str
    gpo: str = ""


@dataclass(frozen=True)
class Pair:
    """A GPO as compared: its identity on each side, for the report's table of contents.

    Attributes:
        guid: The after-side GUID (before-side when only before has it).
        before_guid: The before-side GUID when pairing by name paired different GUIDs.
        name: The after-side name (before-side when removed).
        status: ``changed``, ``unchanged``, ``added``, ``removed``, ``only-before``
            or ``only-after``.
        differences: How many differences concern it.
    """

    guid: str
    name: str
    status: str
    differences: int
    before_guid: str = ""


@dataclass
class Comparison:
    """Everything a report says.

    Attributes:
        before: Label of the before side.
        after: Label of the after side.
        match: How GPOs were paired: ``guid`` or ``name``.
        pairs: Every GPO compared, in name order.
        differences: Every difference, in report order.
        gaps: What was not compared, and why.
        problems: What could not be read, on either side. Any problem makes the
            comparison incomplete.
        notices: Plain sentences a reader should see first, such as a hint that the
            two inputs share no GPO.
    """

    before: str
    after: str
    match: str
    pairs: list[Pair] = field(default_factory=list)
    differences: list[Difference] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """Whether every input was read in full."""
        return not self.problems
