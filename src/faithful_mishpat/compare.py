# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Compare two snapshots of Group Policy.

Rules that decide what a reader sees:

- GPOs are paired by GUID, or by display name with ``match="name"`` for GPOs that
  were re-created or come from different baseline generations.
- A GPO in only one input is ``added`` or ``removed`` only when both inputs are whole
  domains. Otherwise it is ``only-before`` or ``only-after``: a selection of GPOs
  cannot show that one was deleted.
- Context an input does not hold is never compared. It becomes a :class:`Gap` that
  says what was not compared and why, instead of a difference invented from absence.
- Sets compare as sets, so members listed in a new order are not a change.
- Link order is compared per scope among the GPOs linked there on both sides, so one
  link added or removed does not make every later link look moved.
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from faithful_mishpat.differences import Comparison, Difference, Gap, Pair
from faithful_mishpat.errors import UsageError
from faithful_mishpat.formats.bundle import som_path
from faithful_mishpat.model import evidence_key

if TYPE_CHECKING:
    from faithful_mishpat.model import (
        Gpo,
        Link,
        Scope,
        Setting,
        Snapshot,
        Source,
        Trustee,
        ValueData,
        WmiFilter,
    )

MATCHES = ("guid", "name")
_ORDER = {"gpo": 0, "status": 1, "wmi-filter": 2, "security-filtering": 3, "permissions": 4}
_ORDER |= {"link": 5, "inheritance": 6, "setting": 7}


def compare(before: Snapshot, after: Snapshot, *, match: str = "guid") -> Comparison:
    """Compare two snapshots and say every difference, gap and problem.

    Raises:
        UsageError: ``match`` is not one of :data:`MATCHES`, or matching by name
            meets two GPOs with the same name on one side.
    """
    if match not in MATCHES:
        msg = f"match must be one of {', '.join(MATCHES)}"
        raise UsageError(msg)
    result = Comparison(before.label, after.label, match)
    result.problems = [*before.problems, *after.problems]
    left, right = _keyed(before, match), _keyed(after, match)
    # A GPO that could not be read is missing from its side, so only two whole domains
    # read without a problem can say a GPO was created or deleted.
    whole = _whole(before) and _whole(after)
    for key in sorted(left.keys() | right.keys(), key=lambda k: _name_of(left, right, k)):
        old, new = left.get(key), right.get(key)
        if old is not None and new is not None:
            found = _compare_gpo(old, new, result)
            guid = new.guid
            status = "changed" if found else "unchanged"
            other = old.guid if old.guid != new.guid else ""
            result.pairs.append(Pair(guid, new.name, status, found, other))
            continue
        gpo = old if old is not None else new
        assert gpo is not None  # noqa: S101 - one side always has it
        if old is not None:
            kind = "removed" if whole else "only-before"
        else:
            kind = "added" if whole else "only-after"
        result.differences.append(
            Difference(
                "gpo",
                kind,
                gpo.guid,
                gpo.name,
                gpo.name,
                gpo.name if old is not None else None,
                gpo.name if new is not None else None,
                sources=(gpo.source,),
            )
        )
        result.pairs.append(Pair(gpo.guid, gpo.name, kind, 1))
    _compare_scopes(before, after, result)
    _explain(before, after, left, right, result)
    result.differences.sort(key=lambda d: (_name_of_pair(d), _ORDER[d.category]))
    return result


def _keyed(side: Snapshot, match: str) -> dict[str, Gpo]:
    if match == "guid":
        return dict(side.gpos)
    names = Counter(gpo.name.casefold() for gpo in side.gpos.values())
    twice = sorted(name for name, count in names.items() if count > 1)
    if twice:
        msg = (
            f"the {side.label} input has more than one GPO named {twice[0]!r}, so GPOs "
            "cannot be paired by name; pair them by GUID instead"
        )
        raise UsageError(msg)
    return {gpo.name.casefold(): gpo for gpo in side.gpos.values()}


def _name_of(left: dict[str, Gpo], right: dict[str, Gpo], key: str) -> tuple[str, str]:
    gpo = right.get(key) or left[key]
    return (gpo.name.casefold(), gpo.guid)


def _name_of_pair(difference: Difference) -> tuple[str, str]:
    if not difference.gpo:
        return ("￿", difference.subject.casefold())  # scope-level differences go last
    return (difference.gpo_name.casefold(), difference.gpo)


def _compare_gpo(old: Gpo, new: Gpo, result: Comparison) -> int:
    """Add the differences between two versions of one GPO; return how many."""
    start = len(result.differences)
    both = (old.source, new.source)
    add = result.differences.append
    if old.name != new.name:
        add(
            Difference(
                "gpo", "renamed", new.guid, new.name, "name", old.name, new.name, sources=both
            )
        )
    for half, was, now in (
        ("computer half", old.computer_enabled, new.computer_enabled),
        ("user half", old.user_enabled, new.user_enabled),
    ):
        if was is None or now is None:
            result.gaps.append(Gap(f"{half} status", _unknown(was, "status"), new.guid))
        elif was != now:
            add(
                Difference(
                    "status", "changed", new.guid, new.name, half, _on(was), _on(now), sources=both
                )
            )
    _compare_filter(old, new, result)
    _compare_trustees(old, new, result)
    _compare_links(old, new, result)
    _compare_settings(old, new, result)
    return len(result.differences) - start


def _on(enabled: bool) -> str:  # noqa: FBT001 - a plain mapping
    return "enabled" if enabled else "disabled"


def _unknown(before: object, what: str) -> str:
    side = "before" if before is None else "after"
    return f"the {side} input does not record the {what}"


def _compare_filter(old: Gpo, new: Gpo, result: Comparison) -> None:
    was, now = old.wmi_filter, new.wmi_filter
    if was == "unknown" or now == "unknown":
        side = "before" if was == "unknown" else "after"
        result.gaps.append(Gap("WMI filter", f"the {side} input does not record it", new.guid))
        return
    assert not isinstance(was, str)  # noqa: S101 - "unknown" is the only text value
    assert not isinstance(now, str)  # noqa: S101
    if was is None and now is None:
        return
    query_known = was is None or now is None or (was.query is not None and now.query is not None)
    if not query_known:
        result.gaps.append(
            Gap("WMI filter query", "only the mishpat exporter records the query text", new.guid)
        )
    before, after = _filter_value(was, query=query_known), _filter_value(now, query=query_known)
    if before == after:
        return
    kind = "added" if was is None else "removed" if now is None else "changed"
    result.differences.append(
        Difference(
            "wmi-filter",
            kind,
            new.guid,
            new.name,
            "WMI filter",
            before,
            after,
            sources=(old.source, new.source),
        )
    )


def _filter_value(wmi: WmiFilter | None, *, query: bool) -> ValueData:
    if wmi is None:
        return None
    value: dict[str, ValueData] = {"name": wmi.name, "description": wmi.description}
    if query and wmi.query is not None:
        value["query"] = wmi.query
    return value


def _compare_trustees(old: Gpo, new: Gpo, result: Comparison) -> None:
    if old.trustees is None or new.trustees is None:
        reason = _unknown(old.trustees, "permissions")
        result.gaps.append(Gap("security filtering and permissions", reason, new.guid))
        return
    both = (old.source, new.source)
    filtering = (
        {t.sid.casefold(): t for t in old.trustees if t.applies},
        {t.sid.casefold(): t for t in new.trustees if t.applies},
    )
    for sid in sorted(filtering[0].keys() | filtering[1].keys()):
        was, now = filtering[0].get(sid), filtering[1].get(sid)
        if (was is None) != (now is None):
            trustee = now or was
            assert trustee is not None  # noqa: S101 - one side has it
            kind = "added" if was is None else "removed"
            result.differences.append(
                Difference(
                    "security-filtering",
                    kind,
                    new.guid,
                    new.name,
                    _who(trustee),
                    None if was is None else "applies",
                    None if now is None else "applies",
                    sources=both,
                )
            )
    rest = (_permissions(old.trustees), _permissions(new.trustees))
    for key in sorted(rest[0].keys() | rest[1].keys()):
        was_rights, now_rights = rest[0].get(key), rest[1].get(key)
        if _rights(was_rights) == _rights(now_rights):
            continue
        trustee = (now_rights or was_rights)[0]  # type: ignore[index]
        kind = "added" if was_rights is None else "removed" if now_rights is None else "changed"
        result.differences.append(
            Difference(
                "permissions",
                kind,
                new.guid,
                new.name,
                _who(trustee),
                _rights(was_rights),
                _rights(now_rights),
                sources=both,
                note="deny" if not trustee.allow else "",
            )
        )


def _permissions(
    trustees: list[Trustee],
) -> dict[tuple[str, bool], tuple[Trustee, tuple[str, ...]]]:
    """Permission entries other than the filtering right, by (SID, allow)."""
    found: dict[tuple[str, bool], tuple[Trustee, tuple[str, ...]]] = {}
    for trustee in trustees:
        rights = tuple(
            r for r in trustee.rights if not (trustee.allow and r == "Apply Group Policy")
        )
        if not rights:
            continue
        key = (trustee.sid.casefold(), trustee.allow)
        merged = tuple(sorted({*found.get(key, (trustee, ()))[1], *rights}))
        found[key] = (trustee, merged)
    return found


def _rights(entry: tuple[Trustee, tuple[str, ...]] | None) -> ValueData:
    return None if entry is None else list(entry[1])


def _who(trustee: Trustee) -> str:
    return (
        f"{trustee.name} ({trustee.sid})"
        if trustee.name and trustee.name != trustee.sid
        else trustee.sid
    )


def _compare_links(old: Gpo, new: Gpo, result: Comparison) -> None:
    if old.links is None or new.links is None:
        result.gaps.append(Gap("links", _unknown(old.links, "links"), new.guid))
        return
    was = {link.target.casefold(): link for link in old.links}
    now = {link.target.casefold(): link for link in new.links}
    for target in sorted(was.keys() | now.keys()):
        before, after = was.get(target), now.get(target)
        if _link_value(before) == _link_value(after):
            continue
        link = after or before
        assert link is not None  # noqa: S101 - one side has it
        kind = "added" if before is None else "removed" if after is None else "changed"
        result.differences.append(
            Difference(
                "link",
                kind,
                new.guid,
                new.name,
                link.target,
                _link_value(before),
                _link_value(after),
                sources=(old.source, new.source),
            )
        )


def _link_value(link: Link | None) -> ValueData:
    """A link's state. Order is compared per scope, in :func:`_compare_scopes`."""
    if link is None:
        return None
    return {"enabled": link.enabled, "enforced": link.enforced}


def _compare_settings(old: Gpo, new: Gpo, result: Comparison) -> None:
    was, now = _by_identity(old, result), _by_identity(new, result)
    raw = {"Registry.pol".casefold()}
    raw_read = (old.context.get("registry.pol"), new.context.get("registry.pol"))
    compare_raw = raw_read[0] == raw_read[1] == "read"
    if not compare_raw and (raw_read[0] or raw_read[1]):
        reason = "Registry.pol values are compared only when both inputs are backups read in full"
        result.gaps.append(Gap("Registry.pol values", reason, new.guid))
    unknown: set[str] = set()
    for identity in sorted(was.keys() | now.keys()):
        if identity[1] in raw and not compare_raw:
            continue
        before, after = was.get(identity), now.get(identity)
        if before is not None and after is not None and before.value == after.value:
            continue
        setting = after or before
        assert setting is not None  # noqa: S101 - one side has it
        if before is None or after is None:
            key = evidence_key(setting.scope, raw=identity[1] in raw)
            if not (_known(old, key) and _known(new, key)):
                unknown.add(key)  # absent from a side whose source was not read
                continue
        kind = "added" if before is None else "removed" if after is None else "changed"
        sources = tuple(s.source for s in (before, after) if s is not None)
        result.differences.append(
            Difference(
                "setting",
                kind,
                new.guid,
                new.name,
                setting.title,
                None if before is None else before.value,
                None if after is None else after.value,
                scope=setting.scope,
                area=setting.area,
                sources=sources,
                labels=_labels(before, after),
            )
        )
    _unknown_gaps(unknown, new, result)


def _known(gpo: Gpo, key: str) -> bool:
    return gpo.context.get(key, "read") == "read"


def _unknown_gaps(keys: set[str], gpo: Gpo, result: Comparison) -> None:
    for key in sorted(keys):
        half, _, source = key.removeprefix("evidence:").partition(" ")
        what = "Registry.pol values" if source == "registry.pol" else "settings"
        result.gaps.append(
            Gap(
                f"{half.capitalize()} {what} in one input only",
                "they were not read in full on the other side, so they are not listed as added "
                "or removed",
                gpo.guid,
            )
        )


def _labels(*settings: Setting | None) -> tuple[tuple[str, str], ...]:
    """Words readers recorded to show beside values (``label:<value>`` context)."""
    found: dict[str, str] = {}
    for setting in settings:
        if setting is not None:
            for key, words in setting.context.items():
                if key.startswith("label:") and words:
                    found.setdefault(key[len("label:") :], words)
    return tuple(sorted(found.items()))


def _by_identity(gpo: Gpo, result: Comparison) -> dict[tuple[str, ...], Setting]:
    found: dict[tuple[str, ...], Setting] = {}
    for setting in gpo.settings:
        if setting.identity in found and found[setting.identity].value != setting.value:
            reason = (
                f"{setting.title} is defined more than once in {setting.source.file}; "
                "the last definition is compared"
            )
            result.gaps.append(Gap(f"{setting.area}: {setting.title}", reason, gpo.guid))
        found[setting.identity] = setting
    return found


def _compare_scopes(before: Snapshot, after: Snapshot, result: Comparison) -> None:
    if before.scopes is None or after.scopes is None:
        side = "before" if before.scopes is None else "after"
        reason = (
            f"the {side} input does not record the domain's structure; only the mishpat "
            "exporter does"
        )
        result.gaps.append(Gap("link order and blocked inheritance", reason))
        return
    names = {
        **{g.guid: g.name for g in before.gpos.values()},
        **{g.guid: g.name for g in after.gpos.values()},
    }
    _one_sided_scopes(before.scopes, after.scopes, result, whole=_whole(before) and _whole(after))
    for path in sorted(before.scopes.keys() & after.scopes.keys()):
        was, now = before.scopes[path], after.scopes[path]
        sources: tuple[Source, ...] = (was.source, now.source)
        shown = som_path(now.path, now.kind)
        if was.blocked != now.blocked:
            value = ("blocked", "not blocked")
            result.differences.append(
                Difference(
                    "inheritance",
                    "changed",
                    "",
                    "",
                    shown,
                    value[not was.blocked],
                    value[not now.blocked],
                    sources=sources,
                )
            )
        common = {guid for guid, _, _ in was.links} & {guid for guid, _, _ in now.links}
        old_order = [guid for guid, _, _ in was.links if guid in common]
        new_order = [guid for guid, _, _ in now.links if guid in common]
        if old_order != new_order:
            note = (
                "Order among the GPOs linked here on both sides; added or removed links "
                "are listed under each GPO."
            )
            result.differences.append(
                Difference(
                    "link",
                    "changed",
                    "",
                    "",
                    f"{shown}: link order",
                    [names.get(g, g) for g in old_order],
                    [names.get(g, g) for g in new_order],
                    sources=sources,
                    note=note,
                )
            )


def _whole(snapshot: Snapshot) -> bool:
    return snapshot.domain_wide and not snapshot.problems


def _one_sided_scopes(
    before: dict[str, Scope],
    after: dict[str, Scope],
    result: Comparison,
    *,
    whole: bool,
) -> None:
    """Report a container on one side only when it blocks inheritance.

    Its links are already listed under each GPO, so blocked inheritance is the only fact
    that would otherwise go unreported.
    """
    sides = (
        (before, after, "removed" if whole else "only-before", "before"),
        (after, before, "added" if whole else "only-after", "after"),
    )
    for scopes, other, kind, side in sides:
        for path in sorted(scopes.keys() - other.keys()):
            scope = scopes[path]
            if not scope.blocked:
                continue
            values = ("blocked", None) if side == "before" else (None, "blocked")
            result.differences.append(
                Difference(
                    "inheritance",
                    kind,
                    "",
                    "",
                    som_path(scope.path, scope.kind),
                    values[0],
                    values[1],
                    sources=(scope.source,),
                    note=f"This container is in the {side} input only, and blocks inheritance.",
                )
            )


def _explain(
    before: Snapshot,
    after: Snapshot,
    left: dict[str, Gpo],
    right: dict[str, Gpo],
    result: Comparison,
) -> None:
    """Add notices a reader needs before the differences."""
    if left and right and not (left.keys() & right.keys()):
        if result.match == "guid":
            result.notices.append(
                "The two inputs share no GPO by GUID. If they hold the same policies under "
                "different GUIDs, such as two generations of a security baseline, compare "
                "them by name with --match name."
            )
        else:
            result.notices.append("The two inputs share no GPO by name.")
    if left.keys() ^ right.keys():
        if not (before.domain_wide and after.domain_wide):
            result.notices.append(
                "At least one input is a selection of GPOs rather than a whole domain, so a "
                "GPO in only one input is listed as only before or only after, not as added "
                "or removed."
            )
        elif not (_whole(before) and _whole(after)):
            result.notices.append(
                "Something in the inputs could not be read, so a GPO in only one input is "
                "listed as only before or only after: it may be the one that could not be read."
            )
    if not result.problems:
        return
    result.notices.append(
        f"{len(result.problems)} part(s) of the inputs could not be read, so this comparison "
        "is incomplete; see Problems."
    )
