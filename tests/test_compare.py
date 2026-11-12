# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The comparison says every real difference, invents none, and states what it could not compare."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from faithful_mishpat.compare import compare
from faithful_mishpat.errors import UsageError
from faithful_mishpat.model import (
    Gpo,
    Link,
    Problem,
    Scope,
    Setting,
    Snapshot,
    Source,
    Trustee,
    WmiFilter,
)

GUID = "6f8a2d10-0000-4000-8000-000000000001"
OTHER = "6f8a2d10-0000-4000-8000-000000000002"
USERS = "S-1-5-11"
ADMINS = "S-1-5-21-1000-2000-3000-512"
HERE = Source("before.xml")
THERE = Source("after.xml")


def setting(title: str, value: Any, *, scope: str = "Computer", area: str = "Security",
            kind: str = "Account") -> Setting:  # fmt: skip
    return Setting(scope, area, kind, (title,), title, value, HERE)


def gpo(guid: str = GUID, name: str = "Baseline - Servers", **changes: Any) -> Gpo:
    base = Gpo(
        guid=guid,
        domain="corp.example",
        name=name,
        source=HERE,
        computer_enabled=True,
        user_enabled=False,
        trustees=[
            Trustee(USERS, "Authenticated Users", allow=True, rights=("Apply Group Policy", "Read"))
        ],
        wmi_filter=None,
        links=[Link("corp.example/Servers", enabled=True, enforced=False)],
        settings=[setting("MinimumPasswordLength", 14)],
    )
    return replace(base, **changes)


def side(*gpos: Gpo, label: str = "before", whole: bool = False, **changes: Any) -> Snapshot:
    snap = Snapshot(label, [f"{label}.xml"], {g.guid: g for g in gpos}, domain_wide=whole)
    return replace(snap, **changes)


def kinds(result: Any) -> list[tuple[str, str, str]]:
    return [(d.category, d.kind, d.subject) for d in result.differences]


def test_identical_gpos_have_no_differences() -> None:
    result = compare(side(gpo()), side(gpo(), label="after"))
    assert result.differences == []
    assert [(p.status, p.differences) for p in result.pairs] == [("unchanged", 0)]
    assert result.complete


def test_a_changed_setting_names_before_and_after_with_sources() -> None:
    after = gpo(settings=[replace(setting("MinimumPasswordLength", 15), source=THERE)])
    (difference,) = compare(side(gpo()), side(after, label="after")).differences
    assert (difference.kind, difference.before, difference.after) == ("changed", 14, 15)
    assert (difference.scope, difference.area) == ("Computer", "Security")
    assert difference.sources == (HERE, THERE)


def test_settings_added_and_removed() -> None:
    after = gpo(settings=[setting("LockoutBadCount", 5)])
    result = compare(side(gpo()), side(after, label="after"))
    assert sorted(kinds(result)) == [
        ("setting", "added", "LockoutBadCount"),
        ("setting", "removed", "MinimumPasswordLength"),
    ]


def test_setting_identity_ignores_case_and_scope_matters() -> None:
    upper = gpo(settings=[setting("MINIMUMPASSWORDLENGTH", 14)])
    assert compare(side(gpo()), side(upper, label="after")).differences == []
    user = gpo(settings=[setting("MinimumPasswordLength", 14, scope="User")])
    assert len(compare(side(gpo()), side(user, label="after")).differences) == 2


def test_a_gpo_renamed_and_its_halves_switched() -> None:
    after = gpo(name="Baseline - All servers", computer_enabled=False, user_enabled=True)
    result = compare(side(gpo()), side(after, label="after"))
    assert kinds(result) == [
        ("gpo", "renamed", "name"),
        ("status", "changed", "computer half"),
        ("status", "changed", "user half"),
    ]
    assert result.differences[1].before == "enabled"
    assert result.pairs[0].name == "Baseline - All servers"


@pytest.mark.parametrize(
    ("whole", "kinds_seen"),
    [(True, {"added", "removed"}), (False, {"only-before", "only-after"})],
)
def test_a_gpo_on_one_side_is_added_only_when_both_are_whole_domains(
    *, whole: bool, kinds_seen: set[str]
) -> None:
    result = compare(side(gpo(), whole=whole),
                     side(gpo(OTHER, "New"), label="after", whole=whole))  # fmt: skip
    assert {d.kind for d in result.differences} == kinds_seen
    assert any("share no GPO by GUID" in n for n in result.notices)
    assert any("selection of GPOs" in n for n in result.notices) is not whole


def test_matching_by_name_pairs_regenerated_gpos() -> None:
    old = gpo(settings=[setting("MinimumPasswordLength", 14)])
    new = gpo(OTHER, settings=[setting("MinimumPasswordLength", 15)])
    result = compare(side(old), side(new, label="after"), match="name")
    (pair,) = result.pairs
    assert (pair.guid, pair.before_guid, pair.status) == (OTHER, GUID, "changed")
    assert kinds(result) == [("setting", "changed", "MinimumPasswordLength")]


def test_matching_by_name_refuses_duplicate_names() -> None:
    twice = side(gpo(), gpo(OTHER))
    with pytest.raises(UsageError, match="more than one GPO named"):
        compare(twice, side(gpo(), label="after"), match="name")
    with pytest.raises(UsageError, match="match must be one of"):
        compare(side(gpo()), side(gpo(), label="after"), match="title")


def test_security_filtering_and_delegation_are_separate_and_set_based() -> None:
    admins = Trustee(ADMINS, "CORP\\Domain Admins", allow=True, rights=("Edit settings", "Read"))
    reordered = Trustee(
        USERS, "Authenticated Users", allow=True, rights=("Read", "Apply Group Policy")
    )
    after = gpo(trustees=[admins, reordered])
    result = compare(side(gpo()), side(after, label="after"))
    (difference,) = result.differences
    assert (difference.category, difference.kind, difference.after) == (
        "permissions", "added", ["Edit settings", "Read"],
    )  # fmt: skip
    removed = gpo(trustees=[Trustee(USERS, "Authenticated Users", allow=True, rights=("Read",))])
    (filtering,) = compare(side(gpo()), side(removed, label="after")).differences
    assert (filtering.category, filtering.kind, filtering.before) == (
        "security-filtering", "removed", "applies",
    )  # fmt: skip


def test_a_deny_entry_is_reported_with_a_note() -> None:
    deny = Trustee(ADMINS, "", allow=False, rights=("Apply Group Policy",))
    after = gpo(trustees=[*(gpo().trustees or []), deny])
    (difference,) = compare(side(gpo()), side(after, label="after")).differences
    assert (difference.category, difference.note, difference.subject) == (
        "permissions",
        "deny",
        ADMINS,
    )


def test_wmi_filters() -> None:
    servers = WmiFilter("Servers only", "Server OS", "{a}", None)
    added = compare(side(gpo()), side(gpo(wmi_filter=servers), label="after"))
    assert kinds(added) == [("wmi-filter", "added", "WMI filter")]
    renamed = replace(servers, name="Servers 2025")
    changed = compare(side(gpo(wmi_filter=servers)), side(gpo(wmi_filter=renamed), label="after"))
    assert changed.differences[0].after == {"name": "Servers 2025", "description": "Server OS"}
    assert next(g.subject for g in changed.gaps) == "WMI filter query"
    queried = replace(servers, query="SELECT * FROM Win32_OperatingSystem WHERE ProductType=3")
    retyped = replace(queried, query="SELECT * FROM Win32_OperatingSystem WHERE ProductType<>1")
    by_query = compare(side(gpo(wmi_filter=queried)), side(gpo(wmi_filter=retyped), label="after"))
    assert kinds(by_query) == [("wmi-filter", "changed", "WMI filter")]
    unknown = compare(side(gpo(wmi_filter="unknown")), side(gpo(wmi_filter=servers), label="after"))
    assert (unknown.differences, next(g.subject for g in unknown.gaps)) == ([], "WMI filter")


def test_links_compare_state_but_not_order() -> None:
    moved = Link("corp.example/Servers", enabled=True, enforced=False, order=3)
    assert compare(side(gpo()), side(gpo(links=[moved]), label="after")).differences == []
    enforced = Link("corp.example/servers", enabled=True, enforced=True)
    extra = Link("corp.example/Domain Controllers", enabled=False, enforced=False)
    result = compare(side(gpo()), side(gpo(links=[enforced, extra]), label="after"))
    assert sorted(kinds(result)) == [
        ("link", "added", "corp.example/Domain Controllers"),
        ("link", "changed", "corp.example/servers"),
    ]


@pytest.mark.parametrize(
    "missing",
    [{"links": None}, {"trustees": None}, {"computer_enabled": None}, {"user_enabled": None}],
)
def test_unrecorded_context_is_a_gap_not_a_difference(missing: dict[str, Any]) -> None:
    result = compare(side(gpo(**missing)), side(gpo(), label="after"))
    assert result.differences == []
    assert len(result.gaps) == 2  # that context, and link order with no structure
    assert "before input does not record" in result.gaps[0].reason


def scope(path: str, *links: str, blocked: bool = False) -> Scope:
    return Scope(path, "ou", blocked, tuple((g, True, False) for g in links), HERE)


def test_link_order_is_compared_among_links_on_both_sides() -> None:
    third = "6f8a2d10-0000-4000-8000-000000000003"
    names = (gpo(), gpo(OTHER, "Second"), gpo(third, "Third"))
    path = "ou=servers,dc=corp,dc=example"
    before = side(*names, scopes={path: scope(path, GUID, OTHER)})
    inserted = side(*names, label="after", scopes={path: scope(path, third, GUID, OTHER)})
    assert compare(before, inserted).differences == []  # a new link moves nothing else
    swapped = side(*names, label="after", scopes={path: scope(path, OTHER, GUID)})
    (difference,) = compare(before, swapped).differences
    assert (difference.subject, difference.before, difference.after) == (
        "corp.example/servers: link order",
        ["Baseline - Servers", "Second"],
        ["Second", "Baseline - Servers"],
    )
    assert difference.gpo == ""


def test_blocked_inheritance() -> None:
    path = "ou=servers,dc=corp,dc=example"
    before = side(gpo(), scopes={path: scope(path)})
    after = side(gpo(), label="after", scopes={path: scope(path, blocked=True)})
    (difference,) = compare(before, after).differences
    assert (difference.category, difference.before, difference.after) == (
        "inheritance", "not blocked", "blocked",
    )  # fmt: skip
    assert difference.subject == "corp.example/servers"  # a SOMPath, as GPO links are written


@pytest.mark.parametrize(
    ("whole", "kinds_seen"), [(True, ("removed", "added")), (False, ("only-before", "only-after"))]
)
def test_a_container_on_one_side_is_reported_when_it_blocks_inheritance(
    *, whole: bool, kinds_seen: tuple[str, str]
) -> None:
    gone, new, quiet = (
        "ou=old,dc=corp,dc=example",
        "ou=new,dc=corp,dc=example",
        "ou=plain,dc=corp,dc=example",
    )
    before = side(
        gpo(),
        whole=whole,
        scopes={gone: scope(gone, blocked=True), quiet: scope(quiet)},
    )
    after = side(gpo(), label="after", whole=whole, scopes={new: scope(new, blocked=True)})
    found = [
        (d.category, d.kind, d.subject, d.before, d.after)
        for d in compare(before, after).differences
    ]
    assert sorted(found, key=str) == sorted(
        [
            ("inheritance", kinds_seen[0], "corp.example/old", "blocked", None),
            ("inheritance", kinds_seen[1], "corp.example/new", None, "blocked"),
        ],
        key=str,
    )


def test_scope_differences_use_the_path_form_for_each_kind_of_scope() -> None:
    domain, site = (
        "dc=corp,dc=example",
        "cn=default-site,cn=sites,cn=configuration,dc=corp,dc=example",
    )
    nested = "ou=web,ou=servers,dc=corp,dc=example"
    scopes = {
        path: Scope(
            path,
            kind,
            blocked=False,
            links=((GUID, True, False), (OTHER, True, False)),
            source=HERE,
        )
        for path, kind in ((domain, "domain"), (site, "site"), (nested, "ou"))
    }
    flipped = {
        path: Scope(
            path,
            item.kind,
            blocked=True,
            links=((OTHER, True, False), (GUID, True, False)),
            source=THERE,
        )
        for path, item in scopes.items()
    }
    names = (gpo(), gpo(OTHER, "Second"))
    result = compare(side(*names, scopes=scopes), side(*names, label="after", scopes=flipped))
    assert sorted(d.subject for d in result.differences) == [
        "corp.example",
        "corp.example/servers/web",
        "corp.example/servers/web: link order",
        "corp.example: link order",
        "default-site",
        "default-site: link order",
    ]


def test_gpo_added_and_removed_carry_the_name_as_the_side_that_has_it() -> None:
    result = compare(
        side(gpo(), whole=True), side(gpo(OTHER, "New one"), label="after", whole=True)
    )
    by_kind = {d.kind: d for d in result.differences}
    removed, added = by_kind["removed"], by_kind["added"]
    assert (removed.before, removed.after) == ("Baseline - Servers", None)
    assert (added.before, added.after) == (None, "New one")
    partial = compare(side(gpo()), side(gpo(OTHER, "New one"), label="after"))
    alone = {d.kind: d for d in partial.differences}
    assert (alone["only-before"].before, alone["only-before"].after) == ("Baseline - Servers", None)
    assert (alone["only-after"].before, alone["only-after"].after) == (None, "New one")


def test_a_renamed_gpo_still_shows_both_names() -> None:
    after = gpo(name="Baseline - All servers")
    (difference,) = compare(side(gpo()), side(after, label="after")).differences
    assert (difference.before, difference.after) == ("Baseline - Servers", "Baseline - All servers")


def labelled(title: str, value: Any, **context: str) -> Setting:
    return replace(setting(title, value), context=context)


def test_setting_differences_carry_the_words_recorded_beside_values() -> None:
    before = gpo(settings=[labelled("Level", 3, **{"label:3": "Send LM & NTLM", "members": "x"})])
    after = gpo(settings=[labelled("Level", 5, **{"label:5": "NTLMv2 only", "label:9": ""})])
    (difference,) = compare(side(before), side(after, label="after")).differences
    assert difference.labels == (
        ("3", "Send LM & NTLM"),
        ("5", "NTLMv2 only"),
    )  # sorted; no empty words


def test_labels_come_from_whichever_side_has_the_item_and_the_before_side_wins() -> None:
    old = gpo(settings=[labelled("Rights", [ADMINS], **{f"label:{ADMINS}": "Domain Admins"})])
    new = gpo(
        settings=[
            labelled(
                "Rights",
                [ADMINS, USERS],
                **{f"label:{ADMINS}": "Renamed", f"label:{USERS}": "Users"},
            )
        ]
    )
    (changed,) = compare(side(old), side(new, label="after")).differences
    assert changed.labels == ((USERS, "Users"), (ADMINS, "Domain Admins"))  # sorted by value
    (added,) = compare(side(gpo(settings=[])), side(old, label="after")).differences
    assert (added.kind, added.labels) == ("added", ((ADMINS, "Domain Admins"),))
    (removed,) = compare(side(old), side(gpo(settings=[]), label="after")).differences
    assert (removed.kind, removed.labels) == ("removed", ((ADMINS, "Domain Admins"),))


def test_differences_without_recorded_words_have_no_labels() -> None:
    after = gpo(settings=[setting("MinimumPasswordLength", 15)])
    (difference,) = compare(side(gpo()), side(after, label="after")).differences
    assert difference.labels == ()
    assert all(d.labels == () for d in compare(side(gpo(), whole=True),
               side(gpo(OTHER), label="after", whole=True)).differences)  # fmt: skip


def test_registry_pol_values_need_backups_on_both_sides() -> None:
    raw = setting("HKLM\\Software\\Policies\\Example", {"type": "REG_DWORD", "data": 1},
                  area="Registry.pol", kind="Value")  # fmt: skip
    backup = gpo(settings=[raw], context={"registry.pol": "read"})
    report = gpo()
    result = compare(side(report), side(backup, label="after"))
    assert result.differences == [] or kinds(result) == [
        ("setting", "removed", "MinimumPasswordLength")
    ]
    assert "Registry.pol values" in [g.subject for g in result.gaps]
    both = compare(side(gpo(settings=[], context={"registry.pol": "read"})),
                   side(backup, label="after"))  # fmt: skip
    assert kinds(both) == [("setting", "added", "HKLM\\Software\\Policies\\Example")]


def test_a_setting_defined_twice_is_a_gap() -> None:
    twice = gpo(
        settings=[setting("MinimumPasswordLength", 12), setting("MinimumPasswordLength", 14)]
    )
    result = compare(side(twice), side(gpo(), label="after"))
    assert result.differences == []
    assert "defined more than once" in result.gaps[0].reason


def test_problems_make_the_comparison_incomplete() -> None:
    broken = side(gpo(), problems=[Problem(HERE, "registry.pol is truncated")])
    result = compare(broken, side(gpo(), label="after"))
    assert not result.complete
    assert any("could not be read" in n for n in result.notices)


def test_differences_are_ordered_by_gpo_then_category() -> None:
    zed = gpo(OTHER, "Zed", settings=[])
    changed = replace(zed, settings=[setting("A", 1)])
    after = side(gpo(user_enabled=True), changed, label="after", whole=True)
    result = compare(side(gpo(), zed, whole=True), after)
    assert [(d.gpo_name, d.category) for d in result.differences] == [
        ("Baseline - Servers", "status"),
        ("Zed", "setting"),
    ]


def test_an_unchanged_filter_and_a_trustee_with_only_the_filtering_right() -> None:
    same = WmiFilter("Servers only", "Server OS")
    assert (
        compare(side(gpo(wmi_filter=same)), side(gpo(wmi_filter=same), label="after")).differences
        == []
    )
    only_apply = gpo(
        trustees=[Trustee(USERS, "Authenticated Users", allow=True, rights=("Apply Group Policy",))]
    )
    (difference,) = compare(side(gpo()), side(only_apply, label="after")).differences
    assert (difference.category, difference.kind) == ("permissions", "removed")


def test_inputs_sharing_no_gpo_by_name() -> None:
    result = compare(side(gpo()), side(gpo(OTHER, "Other"), label="after"), match="name")
    assert "share no GPO by name" in result.notices[0]
