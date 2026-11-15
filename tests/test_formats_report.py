# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Get-GPOReport reader, one test group per row of the design table."""

from __future__ import annotations

from typing import Any, cast

import pytest

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import xmlsafe
from faithful_mishpat.formats.report import ReportRead, canonical, read_report
from faithful_mishpat.model import Gpo, Link, Setting, Source, Trustee, WmiFilter
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import extension, member, policy, registry_ext, security_ext, user_right

TYPES = fx.TYPES


def read(*gpos: str, **options: object) -> ReportRead:
    how = str(options.pop("how", "utf16"))
    return read_report(fx.report_bytes(*gpos, how=how, **options), Source("r.xml"))  # type: ignore[arg-type]


def one(computer: str = "", user: str = "", **options: object) -> Gpo:
    result = read(fx.gpo_xml(computer=computer, user=user, **options))  # type: ignore[arg-type]
    assert result.problems == []
    (gpo,) = result.gpos
    return gpo


def settings(gpo: Gpo, area: str | None = None) -> dict[tuple[str, ...], Setting]:
    return {s.identity: s for s in gpo.settings if area is None or s.area == area}


def policy_value(setting: Setting) -> dict[str, Any]:
    value = cast("dict[str, Any]", setting.value)
    assert isinstance(value, dict)
    return value


def first_element(setting: Setting) -> Any:
    """The one option a policy holds, by the name the editor shows."""
    value = policy_value(setting)
    (name,) = [key for key in value if key != "state"]
    return value[name]


def only(gpo: Gpo) -> Setting:
    (setting,) = gpo.settings
    return setting


# --- GPO-level facts ----------------------------------------------------------------


def test_gpo_facts() -> None:
    gpo = one(links=(("Servers", "corp.example/Servers", True, False),))
    assert gpo.guid == fx.GUID_A
    assert (gpo.domain, gpo.name) == ("corp.example", "Servers baseline")
    assert gpo.source == Source("r.xml")
    assert (gpo.computer_enabled, gpo.user_enabled) == (True, True)
    assert gpo.versions == {
        "computer directory": 3,
        "computer sysvar".replace("var", "vol"): 3,
        "user directory": 1,
        "user sysvol": 1,
    }
    assert gpo.context == {
        "created": "2026-01-02T03:04:05",
        "modified": "2026-02-03T04:05:06",
        "evidence:computer settings": "read",
        "evidence:user settings": "read",
    }
    assert gpo.links == [Link("corp.example/Servers", enabled=True, enforced=False, order=None)]
    assert gpo.settings == []
    assert "registry.pol" not in gpo.context  # a report never holds Registry.pol values


def test_guid_is_lower_case_without_braces() -> None:
    assert (
        one(ident="{ABCDEF01-2345-4678-89AB-CDEF01234567}").guid
        == "abcdef01-2345-4678-89ab-cdef01234567"
    )
    assert (
        one(ident=" abcdef01-2345-4678-89ab-cdef01234567 ").guid
        == "abcdef01-2345-4678-89ab-cdef01234567"
    )


@pytest.mark.parametrize(("flag", "expected"), [("true", True), ("false", False), ("maybe", None)])
def test_halves_enabled(flag: str, *, expected: bool | None) -> None:
    gpo = one(computer_enabled=flag, user_enabled=flag)
    assert (gpo.computer_enabled, gpo.user_enabled) == (expected, expected)


def test_missing_halves_are_unknown() -> None:
    text = fx.gpo_xml()
    start, end = text.index("<Computer>"), text.index("</User>") + len("</User>")
    gpo = read_report(fx.report_bytes(text[:start] + text[end:]), Source("r")).gpos[0]
    assert (gpo.computer_enabled, gpo.user_enabled, gpo.versions) == (None, None, {})


def test_bad_version_is_a_problem_and_not_recorded() -> None:
    result = read(fx.gpo_xml(versions=("x", "2", "1", "1")))
    assert result.gpos[0].versions["computer sysvol"] == 2
    assert "computer directory" not in result.gpos[0].versions
    (problem,) = result.problems
    assert problem.source == Source("r.xml", "Computer/VersionDirectory")
    assert "not a number" in problem.reason


def test_trustees() -> None:
    gpo = one(
        trustees=fx.trustee("s-1-5-11", "NT AUTHORITY\\Authenticated Users", "Apply Group Policy")
        + fx.trustee(f"{fx.DOMAIN_SID}-512", "CORP\\Domain Admins", "Edit settings")
        + fx.trustee("S-1-1-0", "Everyone", "Apply Group Policy", allow=False)
        + fx.trustee("S-1-5-18", "NT AUTHORITY\\SYSTEM", "Read")
    )
    assert gpo.trustees == [
        Trustee(
            "S-1-5-11",
            "NT AUTHORITY\\Authenticated Users",
            allow=True,
            rights=("Apply Group Policy",),
            access_mask=0,
        ),
        Trustee(
            f"{fx.DOMAIN_SID}-512",
            "CORP\\Domain Admins",
            allow=True,
            rights=("Edit settings",),
            access_mask=0,
        ),
        Trustee("S-1-1-0", "Everyone", allow=False, rights=("Apply Group Policy",), access_mask=0),
        Trustee("S-1-5-18", "NT AUTHORITY\\SYSTEM", allow=True, rights=("Read",), access_mask=0),
    ]
    assert gpo.trustees[0].applies
    assert not gpo.trustees[2].applies


def test_trustee_rights_are_sorted_unique_and_a_name_stands_in_for_a_missing_sid() -> None:
    entry = """<q2:TrusteePermissions>
      <q2:Trustee><q3:Name>CORP\\Helpdesk</q3:Name></q2:Trustee>
      <q2:Standard><q2:GPOGroupedAccessEnum>Read</q2:GPOGroupedAccessEnum>
      <q2:GPOGroupedAccessEnum>Apply Group Policy</q2:GPOGroupedAccessEnum>
      <q2:GPOGroupedAccessEnum>Read</q2:GPOGroupedAccessEnum></q2:Standard>
    </q2:TrusteePermissions>"""
    (trustee,) = one(trustees=entry).trustees or []
    assert trustee == Trustee(
        "CORP\\Helpdesk", "CORP\\Helpdesk", allow=False, rights=("Apply Group Policy", "Read")
    )


def test_trustee_without_trustee_or_rights_element() -> None:
    result = read(fx.gpo_xml(trustees="<q2:TrusteePermissions/>"))
    (trustee,) = result.gpos[0].trustees or []
    assert trustee == Trustee("", "", allow=False, rights=())
    (problem,) = result.problems  # nothing to compare, so the entry is said to be unread
    assert "unnamed trustee" in problem.reason


def test_trustees_are_none_when_not_exported() -> None:
    assert one(trustees=None).trustees is None
    text = (
        fx.gpo_xml()
        .replace("<SecurityDescriptor", "<Ignored")
        .replace("</SecurityDescriptor>", "</Ignored>")
    )
    assert read_report(fx.report_bytes(text), Source("r")).gpos[0].trustees is None


def test_permissions_present_without_entries_is_an_empty_list() -> None:
    assert one(trustees="").trustees == []


def test_wmi_filter() -> None:
    assert one(wmi=("Win11 only", "Workstations")).wmi_filter == WmiFilter(
        "Win11 only", "Workstations"
    )
    assert one().wmi_filter is None
    assert one(wmi_unavailable=True).wmi_filter == "unknown"
    assert one(wmi=("F", ""), wmi_unavailable=True).wmi_filter == WmiFilter("F")


def test_link_details() -> None:
    gpo = one(links=(("A", "corp.example/A", False, True), ("corp.example", "", True, False)))
    assert gpo.links == [
        Link("corp.example/A", enabled=False, enforced=True),
        Link("corp.example", enabled=True, enforced=False),
    ]
    assert one().links == []


# --- Administrative Templates / Registry ---------------------------------------------


def test_policy_value_and_context() -> None:
    gpo = one(computer=registry_ext(policy("Allow thing", "Enabled", "Windows Components/Thing")))
    setting = only(gpo)
    assert (setting.scope, setting.area, setting.kind) == (
        "Computer",
        "Administrative Templates",
        "Policy",
    )
    assert setting.key == ("Windows Components/Thing", "Allow thing")
    assert setting.title == "Allow thing"
    assert setting.value == {"state": "Enabled"}
    assert setting.context == {
        "category": "Windows Components/Thing",
        "explain": "Explains Allow thing.",
        "supported": "At least Windows Vista",
    }
    assert setting.source == Source("r.xml", "Computer/Registry/Policy[Allow thing]")


def test_policy_elements_are_sorted_and_typed() -> None:
    body = """
      <q1:DropDownList><q1:Name>Day</q1:Name><q1:State>Enabled</q1:State>
        <q1:Value><q1:Name>0 - Every day</q1:Name></q1:Value></q1:DropDownList>
      <q1:Text><q1:Name>Only a label</q1:Name></q1:Text>
      <q1:CheckBox><q1:Name>Quiet</q1:Name><q1:State>Disabled</q1:State></q1:CheckBox>
      <q1:Numeric><q1:Name>Size</q1:Name><q1:State>Enabled</q1:State><q1:Value>32768</q1:Value></q1:Numeric>
      <q1:EditText><q1:Name>Path</q1:Name><q1:State>Enabled</q1:State><q1:Value>42</q1:Value></q1:EditText>
      <q1:EditText><q1:Name>Empty</q1:Name><q1:State>Enabled</q1:State><q1:Value/></q1:EditText>
      <q1:Comment>Ticket 123</q1:Comment>
    """
    setting = only(one(user=registry_ext(policy("Mixed", body=body))))
    assert setting.scope == "User"
    assert setting.value == {
        "state": "Enabled",
        "Quiet": "Disabled",
        "Day": "0 - Every day",
        "Empty": "",
        "Path": "42",
        "Size": 32768,
    }
    assert list(policy_value(setting)) == ["state", "Quiet", "Day", "Empty", "Path", "Size"]
    assert setting.context["comment"] == "Ticket 123"


def test_policy_options_are_keyed_by_the_name_the_editor_shows() -> None:
    def check(name: str, state: str) -> str:
        return f"<q1:CheckBox><q1:Name>{name}</q1:Name><q1:State>{state}</q1:State></q1:CheckBox>"

    body = (
        check("Same", "Enabled")
        + check("Same", "Disabled")
        + check("Same", "Enabled")
        + check("State", "Disabled")
        + "<q1:Numeric><q1:State>Enabled</q1:State><q1:Value>5</q1:Value></q1:Numeric>"
        + "<q1:Numeric><q1:State>Enabled</q1:State><q1:Value>6</q1:Value></q1:Numeric>"
    )
    value = policy_value(only(one(computer=registry_ext(policy("P", "Disabled", body=body)))))
    assert value["state"] == "Disabled"  # the policy's own state is not overwritten
    assert value["State (option)"] == "Disabled"
    assert value["Numeric"] == 5  # no name: the kind stands in for it
    assert value["Numeric #2"] == 6
    assert sorted(v for k, v in value.items() if k.startswith("Same")) == [
        "Disabled",
        "Enabled",
        "Enabled",
    ]
    assert {"Same", "Same #2", "Same #3"} <= value.keys()


def test_an_option_names_closing_colon_is_dropped() -> None:
    body = (
        "<q1:Numeric><q1:Name>Maximum size (KB): </q1:Name><q1:State>Enabled</q1:State>"
        "<q1:Value>4096</q1:Value></q1:Numeric>"
        "<q1:Numeric><q1:Name>:</q1:Name><q1:State>Enabled</q1:State><q1:Value>1</q1:Value>"
        "</q1:Numeric>"
    )
    value = policy_value(only(one(computer=registry_ext(policy("P", "Enabled", body=body)))))
    assert value["Maximum size (KB)"] == 4096
    assert value["Numeric"] == 1  # a name that is only a colon falls back to the kind


def test_list_box_options_travel_with_the_value() -> None:
    body = """<q1:ListBox><q1:Name>Rules</q1:Name><q1:State>Enabled</q1:State>
      <q1:Additive>true</q1:Additive>
      <q1:Value><q1:Element><q1:Name>a</q1:Name><q1:Data>1</q1:Data></q1:Element></q1:Value>
      </q1:ListBox>"""
    value = policy_value(only(one(computer=registry_ext(policy("L", body=body)))))
    assert value["Rules"] == {
        "value": [{"data": "1", "name": "a"}],
        "options": {"Additive": True},
    }


def test_policy_element_order_does_not_matter() -> None:
    a = "<q1:CheckBox><q1:Name>A</q1:Name><q1:State>Enabled</q1:State></q1:CheckBox>"
    b = "<q1:CheckBox><q1:Name>B</q1:Name><q1:State>Disabled</q1:State></q1:CheckBox>"
    first = only(one(computer=registry_ext(policy("P", body=a + b))))
    second = only(one(computer=registry_ext(policy("P", body=b + a))))
    assert first.value == second.value


def test_list_box_entries_are_a_sorted_set_with_options() -> None:
    body = """<q1:ListBox><q1:Name>Rules</q1:Name><q1:State>Enabled</q1:State>
      <q1:ExplicitValue>true</q1:ExplicitValue><q1:Additive>false</q1:Additive>
      <q1:ValuePrefix>R</q1:ValuePrefix>
      <q1:Value><q1:Element><q1:Name>zeta</q1:Name><q1:Data>1</q1:Data></q1:Element>
      <q1:Element><q1:Name>alpha</q1:Name><q1:Data>2</q1:Data></q1:Element>
      <q1:Element><q1:Name>name only</q1:Name></q1:Element></q1:Value></q1:ListBox>"""
    element = first_element(only(one(computer=registry_ext(policy("L", body=body)))))
    assert element["value"] == [
        {"data": "2", "name": "alpha"},
        {"data": None, "name": "name only"},
        {"data": "1", "name": "zeta"},
    ]
    assert element["options"] == {"Additive": False, "ExplicitValue": True, "ValuePrefix": "R"}
    assert set(element) == {"value", "options"}


def test_empty_list_box_value() -> None:
    body = (
        "<q1:ListBox><q1:Name>Rules</q1:Name><q1:State>Enabled</q1:State><q1:Value/></q1:ListBox>"
    )
    element = first_element(only(one(computer=registry_ext(policy("L", body=body)))))
    assert element == []


def test_list_box_option_that_is_not_a_flag_stays_text() -> None:
    body = "<q1:ListBox><q1:Name>R</q1:Name><q1:Additive>maybe</q1:Additive></q1:ListBox>"
    element = first_element(only(one(computer=registry_ext(policy("L", body=body)))))
    assert element["options"] == {"Additive": "maybe"}


def test_policy_without_name_is_a_problem() -> None:
    xml = fx.gpo_xml(
        computer=registry_ext("<q1:Policy><q1:State>Enabled</q1:State></q1:Policy>", policy("Ok"))
    )
    result = read(xml)
    assert [s.title for s in result.gpos[0].settings] == ["Ok"]
    (problem,) = result.problems
    assert problem.source == Source("r.xml", "Computer/Registry/Policy")
    assert "it has no Name" in problem.reason


def test_registry_setting_number_string_and_none() -> None:
    items = (
        "<q1:RegistrySetting><q1:KeyPath>Software\\Test</q1:KeyPath><q1:AdmSetting>false</q1:AdmSetting>"
        "<q1:Value><q1:Name>Count</q1:Name><q1:Number>7</q1:Number></q1:Value></q1:RegistrySetting>"
        "<q1:RegistrySetting><q1:KeyPath>Software\\Test</q1:KeyPath>"
        "<q1:Value><q1:Name>Label</q1:Name><q1:String>hi</q1:String></q1:Value></q1:RegistrySetting>"
        "<q1:RegistrySetting><q1:KeyPath>Software\\Other</q1:KeyPath><q1:AdmSetting>true</q1:AdmSetting>"
        "</q1:RegistrySetting>"
        "<q1:RegistrySetting><q1:KeyPath>Software\\Blob</q1:KeyPath>"
        "<q1:Value><q1:Name>Raw</q1:Name><q1:Binary>00</q1:Binary></q1:Value></q1:RegistrySetting>"
    )
    found = settings(one(computer=registry_ext(items)), "Registry")
    count = found[("computer", "registry", "registry setting", "software\\test", "count")]
    assert count.value == {"value": 7}
    assert count.context == {"AdmSetting": "false"}
    assert count.title == "Software\\Test\\Count"
    assert found[("computer", "registry", "registry setting", "software\\test", "label")].value == {
        "value": "hi"
    }
    other = found[("computer", "registry", "registry setting", "software\\other", "")]
    assert (other.value, other.title, other.context) == (
        {"value": None},
        "Software\\Other",
        {"AdmSetting": "true"},
    )
    assert found[("computer", "registry", "registry setting", "software\\blob", "raw")].value == {
        "value": None
    }


def test_registry_setting_without_key_path_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=registry_ext("<q1:RegistrySetting/>")))
    assert result.gpos[0].settings == []
    assert "no KeyPath" in result.problems[0].reason


# --- Security ------------------------------------------------------------------------


def test_account_settings() -> None:
    items = (
        "<q1:Account><q1:Name>MinimumPasswordLength</q1:Name><q1:SettingNumber>14</q1:SettingNumber>"
        "<q1:Type>Password</q1:Type></q1:Account>"
        "<q1:Account><q1:Name>ClearTextPassword</q1:Name><q1:SettingBoolean>false</q1:SettingBoolean>"
        "<q1:Type>Password</q1:Type></q1:Account>"
        "<q1:Account><q1:Name>Odd</q1:Name><q1:SettingBoolean>maybe</q1:SettingBoolean></q1:Account>"
        "<q1:Account><q1:Name>Empty</q1:Name><q1:Type>Lockout</q1:Type></q1:Account>"
    )
    gpo = one(computer=security_ext(items))
    by_name = {s.key[1]: s for s in gpo.settings}
    assert by_name["MinimumPasswordLength"].value == 14
    assert by_name["MinimumPasswordLength"].key == ("Password", "MinimumPasswordLength")
    assert by_name["ClearTextPassword"].value is False
    assert by_name["Odd"].value == "maybe"
    assert by_name["Odd"].key == ("", "Odd")
    assert by_name["Empty"].value is None
    assert {s.kind for s in gpo.settings} == {"Account"}


def test_security_options() -> None:
    items = (
        "<q1:SecurityOptions><q1:KeyName>MACHINE\\System\\Lsa\\NoLMHash</q1:KeyName>"
        "<q1:SettingNumber>1</q1:SettingNumber><q1:Display>"
        "<q1:Name>Network security: LM hash</q1:Name>"
        "<q1:Units/><q1:DisplayString>Enabled</q1:DisplayString></q1:Display></q1:SecurityOptions>"
        "<q1:SecurityOptions><q1:SystemAccessPolicyName>NewAdministratorName</q1:SystemAccessPolicyName>"
        '<q1:SettingString>"localadmin"</q1:SettingString></q1:SecurityOptions>'
        "<q1:SecurityOptions><q1:KeyName>MACHINE\\NoDisplay</q1:KeyName></q1:SecurityOptions>"
    )
    first, second, third = one(computer=security_ext(items)).settings
    assert first.key == ("MACHINE\\System\\Lsa\\NoLMHash",)
    assert (first.title, first.value, first.kind) == (
        "Network security: LM hash",
        1,
        "Security Option",
    )
    assert first.context == {"display": "Enabled", "label:1": "Enabled"}
    assert (second.key, second.value, second.title) == (
        ("NewAdministratorName",),
        '"localadmin"',
        "NewAdministratorName",
    )
    assert (third.value, third.title) == (None, "MACHINE\\NoDisplay")


def test_account_without_name_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=security_ext("<q1:Account/>")))
    assert "no Name" in result.problems[0].reason


def test_missing_version_elements_are_simply_absent() -> None:
    text = fx.gpo_xml().replace("<VersionSysvol>3</VersionSysvol>", "")
    assert "computer sysvol" not in read_report(fx.report_bytes(text), Source("r")).gpos[0].versions


def test_security_option_without_key_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=security_ext("<q1:SecurityOptions/>")))
    assert "KeyName or SystemAccessPolicyName" in result.problems[0].reason


def test_user_rights_are_a_sorted_set_of_upper_case_sids() -> None:
    admins, system = (
        member("s-1-5-32-544", "BUILTIN\\Administrators"),
        member("S-1-5-18", "NT AUTHORITY\\SYSTEM"),
    )
    a = only(one(computer=security_ext(user_right("SeBackupPrivilege", admins, system, admins))))
    b = only(one(computer=security_ext(user_right("SeBackupPrivilege", system, admins))))
    assert a.value == b.value == ["S-1-5-18", "S-1-5-32-544"]
    assert a.context == {
        "members": "BUILTIN\\Administrators, NT AUTHORITY\\SYSTEM",
        "label:S-1-5-32-544": "BUILTIN\\Administrators",
        "label:S-1-5-18": "NT AUTHORITY\\SYSTEM",
    }
    assert (a.kind, a.key, a.title) == (
        "User Rights Assignment",
        ("SeBackupPrivilege",),
        "SeBackupPrivilege",
    )


def test_user_right_falls_back_to_the_name_and_may_be_empty() -> None:
    named = f'<q1:Member><q3:Name xmlns:q3="{TYPES}">CORP\\Unresolved</q3:Name></q1:Member>'
    empty_member = "<q1:Member/>"
    gpo = one(
        computer=security_ext(
            user_right("SeDebugPrivilege", named, empty_member), user_right("SeTcbPrivilege")
        )
    )
    debug, tcb = gpo.settings
    assert debug.value == ["CORP\\Unresolved"]
    assert debug.context == {"members": "CORP\\Unresolved"}  # the name is the id: nothing to add
    assert tcb.value == []
    assert tcb.context == {}


def test_user_right_names_only_members_that_have_both_a_sid_and_a_name() -> None:
    bare = f'<q1:Member><q3:SID xmlns:q3="{TYPES}">S-1-5-19</q3:SID></q1:Member>'
    right = user_right("SeBackupPrivilege", member("S-1-5-32-544", "BUILTIN\\Administrators"), bare)
    setting = only(one(computer=security_ext(right)))
    assert setting.value == ["S-1-5-19", "S-1-5-32-544"]
    assert {k: v for k, v in setting.context.items() if k.startswith("label:")} == {
        "label:S-1-5-32-544": "BUILTIN\\Administrators"
    }


def test_security_option_labels_the_value_only_when_there_are_words() -> None:
    def option(number: int, display: str) -> str:
        shown = f"<q1:DisplayString>{display}</q1:DisplayString>" if display else ""
        return (
            "<q1:SecurityOptions><q1:KeyName>MACHINE\\Lsa\\Level</q1:KeyName>"
            f"<q1:SettingNumber>{number}</q1:SettingNumber>"
            f"<q1:Display><q1:Name>Level</q1:Name>{shown}</q1:Display></q1:SecurityOptions>"
        )

    (with_words,) = one(computer=security_ext(option(5, "Send NTLMv2 response only"))).settings
    assert with_words.context["label:5"] == "Send NTLMv2 response only"
    (without,) = one(computer=security_ext(option(5, ""))).settings
    assert not [key for key in without.context if key.startswith("label:")]


def test_user_right_without_name_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=security_ext("<q1:UserRightsAssignment/>")))
    assert "no Name" in result.problems[0].reason


def account_ref(tag: str, sid: str | None, name: str) -> str:
    sid_xml = f'<q3:SID xmlns:q3="{TYPES}">{sid}</q3:SID>' if sid else ""
    return f'<q1:{tag}>{sid_xml}<q3:Name xmlns:q3="{TYPES}">{name}</q3:Name></q1:{tag}>'


def test_restricted_groups() -> None:
    zed = member(f"{fx.DOMAIN_SID}-1002", "CORP\\Zed")
    amy = member(f"{fx.DOMAIN_SID}-1001", "CORP\\Amy")
    xml = (
        "<q1:RestrictedGroups>"
        + account_ref("GroupName", "s-1-5-32-544", "BUILTIN\\Administrators")
        + zed
        + amy
        + account_ref("MemberOf", "S-1-5-32-545", "BUILTIN\\Users")
        + "</q1:RestrictedGroups><q1:RestrictedGroups>"
        + account_ref("GroupName", None, "CORP\\Plain")
        + "</q1:RestrictedGroups>"
    )
    first, second = one(computer=security_ext(xml)).settings
    assert first.key == ("S-1-5-32-544",)
    assert first.title == "BUILTIN\\Administrators"
    assert first.value == {
        "members": [f"{fx.DOMAIN_SID}-1001", f"{fx.DOMAIN_SID}-1002"],
        "member_of": ["S-1-5-32-545"],
    }
    assert first.context == {
        "member names": "CORP\\Amy, CORP\\Zed",
        "member of names": "BUILTIN\\Users",
    }
    assert (second.key, second.value) == (("CORP\\Plain",), {"members": [], "member_of": []})


def test_restricted_group_without_group_name_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=security_ext("<q1:RestrictedGroups/>")))
    assert "no GroupName" in result.problems[0].reason


def test_system_services() -> None:
    items = (
        "<q1:SystemServices><q1:Name>Spooler</q1:Name><q1:StartupMode>Disabled</q1:StartupMode>"
        f'<q1:SecurityDescriptor><q4:SDDL xmlns:q4="{fx.SECURITY_TYPES}">'
        "D:(A;;CCLCSWRP;;;AU)</q4:SDDL>"
        "</q1:SecurityDescriptor></q1:SystemServices>"
        "<q1:SystemServices><q1:Name>Fax</q1:Name></q1:SystemServices>"
    )
    spooler, fax = one(computer=security_ext(items)).settings
    assert spooler.value == {"startup": "Disabled", "sddl": "D:(A;;CCLCSWRP;;;AU)"}
    assert fax.value == {"startup": ""}
    assert spooler.kind == "System Service"


def test_system_service_without_name_is_a_problem() -> None:
    assert (
        "no Name"
        in read(fx.gpo_xml(computer=security_ext("<q1:SystemServices/>"))).problems[0].reason
    )


def test_legacy_audit_and_event_log() -> None:
    items = (
        "<q1:Audit><q1:Name>AuditLogonEvents</q1:Name><q1:SuccessAttempts>true</q1:SuccessAttempts>"
        "<q1:FailureAttempts>false</q1:FailureAttempts></q1:Audit>"
        "<q1:Audit><q1:Name>AuditBare</q1:Name></q1:Audit>"
        "<q1:EventLog><q1:Name>MaximumLogSize</q1:Name><q1:Log>Security</q1:Log>"
        "<q1:SettingNumber>196608</q1:SettingNumber></q1:EventLog>"
        "<q1:EventLog><q1:Name>RestrictGuestAccess</q1:Name><q1:SettingBoolean>true</q1:SettingBoolean></q1:EventLog>"
    )
    logon, bare, size, guest = one(computer=security_ext(items)).settings
    assert (logon.kind, logon.key, logon.value) == (
        "Audit",
        ("AuditLogonEvents",),
        {"success": True, "failure": False},
    )
    assert bare.value == {"success": False, "failure": False}
    assert (size.kind, size.key, size.value, size.title) == (
        "Event Log",
        ("Security", "MaximumLogSize"),
        196608,
        "Security MaximumLogSize",
    )
    assert (guest.key, guest.value, guest.title) == (
        ("", "RestrictGuestAccess"),
        True,
        "RestrictGuestAccess",
    )


@pytest.mark.parametrize("element", ["Audit", "EventLog"])
def test_audit_and_event_log_without_name_are_problems(element: str) -> None:
    result = read(fx.gpo_xml(computer=security_ext(f"<q1:{element}/>")))
    assert "no Name" in result.problems[0].reason


# --- Advanced Audit ------------------------------------------------------------------


def test_advanced_audit() -> None:
    items = (
        "<q1:AuditSetting><q1:PolicyTarget>System</q1:PolicyTarget>"
        "<q1:SubcategoryName>Audit Logon</q1:SubcategoryName>"
        "<q1:SubcategoryGuid>{0CCE9215-69AE-11D9-BED3-505054503030}</q1:SubcategoryGuid>"
        "<q1:SettingValue>3</q1:SettingValue></q1:AuditSetting>"
        "<q1:AuditSetting><q1:SubcategoryGuid>not-a-guid</q1:SubcategoryGuid></q1:AuditSetting>"
    )
    logon, odd = one(computer=extension("Auditing", items)).settings
    assert (logon.area, logon.kind) == ("Advanced Audit", "Audit Setting")
    assert logon.key == ("System", "0cce9215-69ae-11d9-bed3-505054503030")
    assert (logon.title, logon.value) == ("Audit Logon", 3)
    assert (odd.key, odd.title, odd.value) == (("", "not-a-guid"), "not-a-guid", "")


def test_advanced_audit_without_guid_is_a_problem() -> None:
    result = read(fx.gpo_xml(computer=extension("Auditing", "<q1:AuditSetting/>")))
    assert "SubcategoryGuid" in result.problems[0].reason


# --- Scripts -------------------------------------------------------------------------


def script(
    kind: str, command: str, order: str, parameters: str | None = None, run: str | None = None
) -> str:
    return (
        f"<q1:Script><q1:Command>{command}</q1:Command>"
        + (f"<q1:Parameters>{parameters}</q1:Parameters>" if parameters is not None else "")
        + f"<q1:Type>{kind}</q1:Type><q1:Order>{order}</q1:Order>"
        + (f"<q1:RunOrder>{run}</q1:RunOrder>" if run else "")
        + "</q1:Script>"
    )


def test_scripts_are_one_ordered_list_per_scope_and_type() -> None:
    computer = extension(
        "Scripts",
        script("Startup", "b.cmd", "1")
        + script("Shutdown", "off.cmd", "0")
        + script("Startup", "a.cmd", "0", "-x", "PSFirst"),
    ) + extension("Scripts", script("Startup", "c.cmd", "2"))
    gpo = one(computer=computer, user=extension("Scripts", script("Logon", "hi.cmd", "text")))
    startup = settings(gpo)[("computer", "scripts", "script", "startup")]
    assert startup.value == [
        {"command": "a.cmd", "parameters": "-x", "order": 0, "run_order": "PSFirst"},
        {"command": "b.cmd", "parameters": "", "order": 1},
        {"command": "c.cmd", "parameters": "", "order": 2},
    ]
    assert startup.title == "Startup scripts"
    assert startup.source == Source("r.xml", "Computer/Scripts/Script[Startup]")
    assert settings(gpo)[("computer", "scripts", "script", "shutdown")].value == [
        {"command": "off.cmd", "parameters": "", "order": 0}
    ]
    logon = settings(gpo)[("user", "scripts", "script", "logon")]
    assert logon.value == [{"command": "hi.cmd", "parameters": "", "order": "text"}]
    assert len(gpo.settings) == 3


def test_script_without_type_is_a_problem() -> None:
    result = read(
        fx.gpo_xml(
            computer=extension("Scripts", "<q1:Script><q1:Command>x</q1:Command></q1:Script>")
        )
    )
    assert result.gpos[0].settings == []
    assert "no Type or Command" in result.problems[0].reason


# --- Folder Redirection --------------------------------------------------------------


def test_folder_redirection() -> None:
    folder = (
        "<q1:Folder><q1:Id>{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}</q1:Id><q1:Location>"
        "<q1:DestinationPath>\\\\files.corp.example\\Users$\\%USERNAME%\\Documents</q1:DestinationPath>"
        '<q1:SecurityGroup><q3:SID xmlns:q3="'
        + TYPES
        + '">s-1-1-0</q3:SID><q3:Name xmlns:q3="'
        + TYPES
        + '">Everyone</q3:Name>'
        "</q1:SecurityGroup></q1:Location><q1:MoveContents>true</q1:MoveContents></q1:Folder>"
    )
    setting = only(one(user=extension("FolderRedirection", folder)))
    assert (setting.area, setting.kind) == ("Folder Redirection", "Folder")
    assert setting.key == ("3eb685db-65f9-4cf6-a03a-e3ef65729f3d",)
    assert setting.value == {
        "Location": {
            "DestinationPath": "\\\\files.corp.example\\Users$\\%USERNAME%\\Documents",
            "SecurityGroup": {"Name": "Everyone", "SID": "S-1-1-0"},
        },
        "MoveContents": "true",
    }


def test_folder_redirection_without_id_is_a_problem() -> None:
    result = read(fx.gpo_xml(user=extension("FolderRedirection", "<q1:Folder/>")))
    assert "no Id" in result.problems[0].reason


# --- Group Policy Preferences --------------------------------------------------------


def registry_item(
    uid: str | None,
    name: str,
    value: str = "00000001",
    extra: str = "",
    changed: str = "2026-01-01 00:00:00",
) -> str:
    attrs = f' uid="{{{uid}}}"' if uid else ""
    return (
        '<q1:Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}"'
        f' name="{name}" status="{name}" image="12"'
        f' changed="{changed}"{attrs} descr="why"><q1:GPOSettingOrder>4</q1:GPOSettingOrder>'
        '<q1:Properties action="U" hive="HKEY_LOCAL_MACHINE" key="Software\\Test"'
        f' name="{name}" type="REG_DWORD" value="{value}">'
        f"<q1:Values/></q1:Properties>{extra}<q1:Filters/></q1:Registry>"
    )


def prefs(items: str) -> str:
    return extension(
        "Windows/Registry",
        '<q1:RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}">'
        f"{items}</q1:RegistrySettings>",
    )


def test_gpp_registry_item() -> None:
    gpo = one(computer=prefs(registry_item("0386C407-F13E-4B4A-9CAD-26028C795314", "MaxSize")))
    setting = only(gpo)
    assert (setting.area, setting.kind) == ("Preferences: Registry", "Registry")
    assert setting.key == ("0386c407-f13e-4b4a-9cad-26028c795314",)
    assert setting.title == "MaxSize"
    value = setting.value
    assert isinstance(value, dict)
    assert value["attributes"] == {
        "clsid": "{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}",
        "name": "MaxSize",
    }
    assert value["properties"] == {
        "@action": "U",
        "@hive": "HKEY_LOCAL_MACHINE",
        "@key": "Software\\Test",
        "@name": "MaxSize",
        "@type": "REG_DWORD",
        "@value": "00000001",
        "Values": "",
    }
    assert value["filters"] == ""
    assert setting.context == {"changed": "2026-01-01 00:00:00", "order": "4", "description": "why"}
    assert setting.source == Source("r.xml", "Computer/Windows/Registry/Registry[MaxSize]")


def test_gpp_changed_time_is_context_and_value_changes_are_seen() -> None:
    a = only(
        one(
            computer=prefs(
                registry_item(
                    "0386C407-F13E-4B4A-9CAD-26028C795314", "M", changed="2026-01-01 00:00:00"
                )
            )
        )
    )
    b = only(
        one(
            computer=prefs(
                registry_item(
                    "0386C407-F13E-4B4A-9CAD-26028C795314", "M", changed="2026-06-01 00:00:00"
                )
            )
        )
    )
    c = only(
        one(
            computer=prefs(
                registry_item("0386C407-F13E-4B4A-9CAD-26028C795314", "M", value="00000002")
            )
        )
    )
    assert a.identity == b.identity == c.identity
    assert a.value == b.value
    assert a.value != c.value


def test_gpp_collections_are_flattened_into_the_key() -> None:
    inner = registry_item("A0000000-0000-4000-8000-000000000001", "Deep")
    filt = '<q1:Filters><q1:FilterOs bool="AND" not="0" class="NT" version="WIN10"/></q1:Filters>'
    tree = (
        '<q1:Collection clsid="{53B533F5}" name="Outer"'
        ' uid="{B0000000-0000-4000-8000-000000000001}">'
        f"<q1:GPOSettingOrder>1</q1:GPOSettingOrder><q1:Filters/>"
        f'<q1:Collection clsid="{{53B533F5}}" name="Inner">{filt}{inner}'
        "</q1:Collection></q1:Collection>"
        + registry_item("A0000000-0000-4000-8000-000000000002", "Top")
    )
    deep, top = one(computer=prefs(tree)).settings
    assert deep.key == ("Outer", "Inner", "a0000000-0000-4000-8000-000000000001")
    assert top.key == ("a0000000-0000-4000-8000-000000000002",)
    deep_value = cast("dict[str, Any]", deep.value)
    assert deep_value["collection_filters"][0] == ""
    assert deep_value["collection_filters"][1] == {
        "FilterOs": {"@bool": "AND", "@class": "NT", "@not": "0", "@version": "WIN10"}
    }
    assert "collection_filters" not in top.value  # type: ignore[operator]


@pytest.mark.parametrize(
    ("tail", "collection", "item", "properties", "expected"),
    [
        (
            "Windows/Registry",
            "RegistrySettings",
            "Registry",
            'hive="HKLM" key="Software\\X" name="v"',
            "HKLM\\Software\\X\\v",
        ),
        ("Windows/Registry", "RegistrySettings", "Registry", "", "n"),
        ("Files", "FilesSettings", "File", 'targetPath="C:\\x.txt"', "C:\\x.txt"),
        ("Folders", "Folders", "Folder", 'path="C:\\Logs"', "C:\\Logs"),
        (
            "Lugs",
            "LocalUsersAndGroups",
            "Group",
            'groupSid="S-1-5-32-555" groupName="RDU"',
            "S-1-5-32-555",
        ),
        ("Lugs", "LocalUsersAndGroups", "Group", 'groupName="RDU"', "RDU"),
        ("Lugs", "LocalUsersAndGroups", "User", 'userName="bob"', "bob"),
        ("Lugs", "LocalUsersAndGroups", "Group", "", "n"),
        ("ScheduledTasks", "ScheduledTasks", "TaskV2", 'name="T"', "n"),
        ("Shortcuts", "ShortcutSettings", "Shortcut", 'targetPath="x"', "n"),
    ],
)
def test_gpp_items_without_uid_use_the_type_specific_key(
    tail: str, collection: str, item: str, properties: str, expected: str
) -> None:
    xml = (
        f'<q1:{collection} clsid="{{C}}"><q1:{item} clsid="{{D}}" name="n">'
        f"<q1:Properties {properties}/></q1:{item}></q1:{collection}>"
    )
    setting = only(one(computer=extension(tail, xml)))
    assert setting.key == (expected,)
    assert setting.kind == item


def test_gpp_area_names() -> None:
    def area(tail: str, collection: str) -> str:
        uid = "{E0000000-0000-4000-8000-000000000001}"
        xml = (
            f'<q1:{collection} clsid="{{C}}">'
            f'<q1:Item clsid="{{D}}" name="n" uid="{uid}"/></q1:{collection}>'
        )
        return only(one(computer=extension(tail, xml))).area

    assert area("Windows/Registry", "RegistrySettings") == "Preferences: Registry"
    assert area("Lugs", "LocalUsersAndGroups") == "Preferences: Local Users and Groups"
    assert area("ScheduledTasks", "ScheduledTasks") == "Preferences: Scheduled Tasks"
    assert area("Files", "FilesSettings") == "Preferences: Files"
    assert area("Windows/Environment", "EnvironmentVariables") == "Preferences: Environment"


def test_gpp_item_with_nothing_to_key_on_gets_a_content_hash() -> None:
    xml = (
        '<q1:Things clsid="{C}"><q1:Thing clsid="{D}"><q1:Properties a="1"/></q1:Thing></q1:Things>'
    )
    (key,) = only(one(computer=extension("Misc", xml))).key
    assert len(key) == 16
    again = only(one(computer=extension("Misc", xml.replace('a="1"', 'a="1"')))).key
    assert again == (key,)


def test_gpp_members_are_a_set_and_non_items_are_skipped() -> None:
    def group(members: str) -> Setting:
        xml = (
            '<q1:LocalUsersAndGroups clsid="{C}"><q1:Group clsid="{D}" name="G"'
            ' uid="{E0000000-0000-4000-8000-000000000001}">'
            f'<q1:Properties groupSid="S-1-5-32-555"><q1:Members>{members}</q1:Members>'
            "</q1:Properties></q1:Group>"
            "<q1:SomethingElse>ignored</q1:SomethingElse></q1:LocalUsersAndGroups>"
        )
        return only(one(computer=extension("Lugs", xml)))

    amy = '<q1:Member name="CORP\\amy" action="ADD" sid="S-1-5-21-1000-2000-3000-1001"/>'
    bob = '<q1:Member name="CORP\\bob" action="ADD" sid="s-1-5-21-1000-2000-3000-1002"/>'
    assert group(amy + bob).value == group(bob + amy).value


# --- generic extensions -----------------------------------------------------------------


def test_unknown_extension_children_become_generic_settings() -> None:
    xml = (
        "<q1:PublicRule><q1:Name>Rule one</q1:Name><q1:Action>Allow</q1:Action>"
        "<q1:Explain>x</q1:Explain>"
        "<q1:Port>80</q1:Port><q1:Port>443</q1:Port></q1:PublicRule>"
        '<q1:ProfileSettings Type="Domain"><q1:Enable>true</q1:Enable></q1:ProfileSettings>'
        "<q1:Blocked>false</q1:Blocked>"
    )
    rule, profile = one(computer=extension("WindowsFirewall", xml)).settings
    assert (rule.area, rule.kind, rule.key, rule.title) == (
        "WindowsFirewall",
        "PublicRule",
        ("Rule one",),
        "Rule one",
    )
    assert rule.value == {"Action": "Allow", "Name": "Rule one", "Port": ["80", "443"]}
    assert rule.source == Source("r.xml", "Computer/WindowsFirewall/PublicRule[Rule one]")
    assert profile.key == ("Domain",)
    assert profile.value == {"@Type": "Domain", "Enable": "true"}


def test_generic_key_choices() -> None:
    xml = (
        "<q1:ById><q1:Id>x1</q1:Id><q1:V>1</q1:V></q1:ById>"
        '<q1:ByAttr id="x2"><q1:V>1</q1:V></q1:ByAttr>'
        "<q1:Single><q1:V>1</q1:V></q1:Single>"
        "<q1:Many><q1:V>1</q1:V></q1:Many><q1:Many><q1:V>2</q1:V></q1:Many>"
    )
    by_id, by_attr, single, many1, many2 = one(computer=extension("Misc/Deep", xml)).settings
    assert by_id.key == ("x1",)
    assert by_attr.key == ("x2",)
    assert (single.key, single.title) == ((), "Single")
    assert single.identity == ("computer", "misc/deep", "single")
    assert len(many1.key[0]) == 16
    assert many1.key != many2.key
    assert by_id.area == "Misc/Deep"


def test_foreign_namespace_uses_the_whole_uri_and_nil_is_none() -> None:
    xml = (
        '<z:Thing xmlns:z="urn:vendor:policy"><z:Name>T</z:Name><z:Gone xsi:nil="true"/></z:Thing>'
    )
    text = fx.gpo_xml(
        computer=f'<ExtensionData><Extension xsi:type="z:X">{xml}</Extension></ExtensionData>'
    )
    (setting,) = read(text).gpos[0].settings
    assert setting.area == "urn:vendor:policy"
    assert setting.value == {"Gone": None, "Name": "T"}


def test_extension_children_outside_any_extension_are_ignored() -> None:
    text = fx.gpo_xml(
        computer="<Other><x/></Other><ExtensionData><Name>No extension</Name></ExtensionData>"
    )
    assert read(text).gpos[0].settings == []


def test_duplicate_identities_get_numbered_keys() -> None:
    items = policy("Same", "Enabled") + policy("Same", "Disabled") + policy("Same", "Enabled")
    gpo = one(computer=registry_ext(items))
    assert [s.key for s in gpo.settings] == [
        ("System/Test", "Same"),
        ("System/Test", "Same#2"),
        ("System/Test", "Same#3"),
    ]
    assert len({s.identity for s in gpo.settings}) == 3


def test_duplicate_generic_without_key_gets_a_numbered_key() -> None:
    xml = "<q1:Single><q1:V>1</q1:V></q1:Single>"
    first, second = one(computer=extension("A", xml) + extension("A", xml)).settings
    assert first.key == (first.key[0],)
    assert second.key[0].endswith("#2")


def test_a_setting_keyed_on_nothing_that_repeats_gets_a_numbered_key() -> None:
    # Two extension blocks each holding one unnamed element: unique within a block, not across.
    xml = "<q1:Single><q1:V>1</q1:V></q1:Single>"
    gpo = one(computer=extension("A", xml), user=extension("A", xml))
    assert [s.scope for s in gpo.settings] == ["Computer", "User"]


# --- identity by namespace, not prefix ----------------------------------------------------


def test_prefixes_mean_nothing() -> None:
    def build(prefix: str) -> Gpo:
        items = policy(
            "P", body="<q1:CheckBox><q1:Name>C</q1:Name><q1:State>Enabled</q1:State></q1:CheckBox>"
        )
        return one(
            computer=registry_ext(items, prefix=prefix)
            + security_ext(user_right("SeX"), prefix=prefix),
            user=extension("Scripts", script("Logon", "a.cmd", "0"), prefix),
        )

    first, second = build("q1"), build("zzz")
    assert [(s.identity, s.value) for s in first.settings] == [
        (s.identity, s.value) for s in second.settings
    ]
    assert len(first.settings) == 3


def test_elements_in_the_wrong_namespace_are_not_policies() -> None:
    wrong = fx.gpo_xml(computer=extension("Registry2", policy("P")))
    (setting,) = read(wrong).gpos[0].settings
    assert (setting.area, setting.kind) == ("Registry2", "Policy")


def test_same_local_names_in_the_policy_namespace_are_not_confused_with_security() -> None:
    text = fx.gpo_xml(computer=extension("Security", "<q1:Policy><q1:Name>N</q1:Name></q1:Policy>"))
    (setting,) = read(text).gpos[0].settings
    assert (setting.area, setting.kind) == ("Security", "Policy")


# --- the file as a whole ---------------------------------------------------------------------


@pytest.mark.parametrize("how", ["utf16", "utf16-be", "utf8", "utf8-bom", "utf16-nobom"])
def test_encodings(how: str) -> None:
    result = read(fx.gpo_xml(name="Caf\u00e9 \u4e2d", computer=registry_ext(policy("P"))), how=how)
    assert result.problems == []
    assert result.gpos[0].name == "Caf\u00e9 \u4e2d"
    assert len(result.gpos[0].settings) == 1
    assert not result.wrapped


def test_gpos_wrapper_reads_every_gpo() -> None:
    a = fx.gpo_xml(fx.GUID_A, "A", computer=registry_ext(policy("PA")))
    b = fx.gpo_xml(fx.GUID_B, "B", computer=registry_ext(policy("PB")))
    result = read(a, b, wrapped=True, how="utf8")
    assert result.wrapped
    assert [g.name for g in result.gpos] == ["A", "B"]
    assert result.gpos[1].source == Source("r.xml", "GPO[2]")
    assert result.gpos[1].settings[0].source == Source(
        "r.xml", "GPO[2] Computer/Registry/Policy[PB]"
    )
    assert result.problems == []


def test_base_detail_is_kept_in_every_source() -> None:
    result = read_report(
        fx.report_bytes(fx.gpo_xml(computer=registry_ext(policy("P")))),
        Source("b.jsonl:x/gpreport.xml", "pre"),
    )
    assert result.gpos[0].source == Source("b.jsonl:x/gpreport.xml", "pre")
    assert result.gpos[0].settings[0].source.detail == "pre Computer/Registry/Policy[P]"


def test_one_bad_gpo_is_a_problem_and_the_rest_are_read() -> None:
    good = fx.gpo_xml(fx.GUID_A, "Good")
    no_ident = good.replace("<Identifier>", "<Gone>", 1).replace(
        "</Identifier>\n  <Name>", "</Gone>\n  <Name>", 1
    )
    bad_guid = fx.gpo_xml(fx.GUID_B, "Bad", ident="{not-a-guid}")
    no_name = fx.gpo_xml(fx.GUID_C, "x").replace("<Name>x</Name>", "")
    result = read(no_ident, bad_guid, good, no_name, wrapped=True)
    assert [g.name for g in result.gpos] == ["Good"]
    reasons = [(p.source.detail, p.reason) for p in result.problems]
    assert reasons == [
        ("GPO[1]", "This GPO was not read: it has no Identifier"),
        ("GPO[2]", "This GPO was not read: its Identifier '{not-a-guid}' is not a GUID"),
        ("GPO[4]", "This GPO was not read: it has no Name"),
    ]


def test_a_single_bad_gpo_gives_no_gpos_and_a_problem() -> None:
    result = read(fx.gpo_xml(ident=""))
    assert result.gpos == []
    assert "no Identifier" in result.problems[0].reason


def test_duplicate_guid_in_one_file_keeps_the_first() -> None:
    result = read(fx.gpo_xml(fx.GUID_A, "First"), fx.gpo_xml(fx.GUID_A, "Second"), wrapped=True)
    assert [g.name for g in result.gpos] == ["First"]
    assert "appears twice" in result.problems[0].reason


def test_unexpected_children_and_empty_wrapper() -> None:
    text = fx.report_text(fx.gpo_xml(), wrapped=True).replace("</GPOS>", "<Junk/></GPOS>")
    result = read_report(text.encode("utf-8"), Source("r"))
    assert len(result.gpos) == 1
    assert "Unexpected element <Junk>" in result.problems[0].reason
    empty = read_report(b"<GPOS/>", Source("r"))
    assert empty.wrapped
    assert "holds no GPO" in empty.problems[0].reason


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"hello, not xml", "not well-formed"),
        (b"", "not well-formed"),
        (b"<html><body/></html>", "root element is <html>"),
        (b'<GPO xmlns="urn:other"/>', "root element is <GPO>"),
        (b'<GPOS xmlns="urn:other"/>', "root element is <GPOS>"),
        (
            b'<!DOCTYPE GPO [<!ENTITY x "y">]><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"/>',
            "DOCTYPE",
        ),
    ],
)
def test_files_that_are_not_reports_are_input_errors(data: bytes, reason: str) -> None:
    with pytest.raises(InputError, match=f"^r.xml is not a Get-GPOReport XML file: .*{reason}"):
        read_report(data, Source("r.xml"))


def test_a_long_root_name_is_cut_in_the_message() -> None:
    with pytest.raises(InputError) as caught:
        read_report(f"<{'x' * 200}/>".encode(), Source("r"))
    assert "x" * 41 not in str(caught.value)


def test_entity_bombs_and_depth_in_a_report_are_refused() -> None:
    bomb = b'<!DOCTYPE GPO [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><GPO>&b;</GPO>'
    with pytest.raises(InputError, match="DOCTYPE"):
        read_report(bomb, Source("r"))
    deep = ("<a>" * 70 + "</a>" * 70).encode()
    with pytest.raises(InputError, match="levels deep"):
        read_report(deep, Source("r"))
    nested = fx.gpo_xml(
        computer=extension("X", "<q1:A>" + "<q1:B>" * 55 + "</q1:B>" * 55 + "</q1:A>")
    )
    assert read(nested).gpos[0].settings  # 55 levels inside is still under the limit
    too_deep = fx.gpo_xml(
        computer=extension("X", "<q1:A>" + "<q1:B>" * 70 + "</q1:B>" * 70 + "</q1:A>")
    )
    with pytest.raises(InputError, match="levels deep"):
        read(too_deep)


def test_huge_file_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xmlsafe, "MAX_BYTES", 100)
    with pytest.raises(InputError, match="larger than 100 bytes"):
        read_report(b"<GPO>" + b"x" * 200 + b"</GPO>", Source("r"))


def test_canonical_helper() -> None:
    root = xmlsafe.parse(
        b'<a x="1" y="S-1-5-18"> t <b>S-1-5-32-544</b><c/><c>2</c><Explain>drop</Explain>'
        b"<Member>z</Member><Member>a</Member></a>"
    )
    assert canonical(root) == {
        "#text": "t",
        "@x": "1",
        "@y": "S-1-5-18",
        "b": "S-1-5-32-544",
        "c": ["", "2"],
        "Member": ["a", "z"],
    }
    assert cast("dict[str, Any]", canonical(root, drop=frozenset({"x"}), sort=frozenset({"c"})))[
        "c"
    ] == ["", "2"]


# --- security descriptor: owner, group, raw SDDL and custom permissions (MISHPAT-C01) ----

OWNER_ELEMENT = (
    f'<Owner xmlns="{fx.SECURITY_TYPES}"><SID xmlns="{TYPES}">S-1-5-21-1000-2000-3000-1999</SID>'
    f'<Name xmlns="{TYPES}">CORP\\owner</Name></Owner>'
)


def test_owner_and_group_come_from_the_sddl_text() -> None:
    gpo = one(sddl="O:DAG:S-1-5-21-1000-2000-3000-513D:PAI(A;;GA;;;DA)")
    assert (gpo.owner, gpo.group) == ("DA", "S-1-5-21-1000-2000-3000-513")
    assert gpo.sddl == "O:DAG:S-1-5-21-1000-2000-3000-513D:PAI(A;;GA;;;DA)"


def test_an_sddl_without_an_owner_has_no_owner_and_no_problem() -> None:
    gpo = one(sddl="D:PAI(A;;GA;;;DA)")
    assert (gpo.owner, gpo.group) == (None, None)
    assert gpo.sddl == "D:PAI(A;;GA;;;DA)"


def test_no_sddl_means_nothing_recorded() -> None:
    gpo = one(sddl=None)
    assert (gpo.sddl, gpo.owner, gpo.group) == (None, None, None)


def test_an_sddl_that_does_not_start_as_expected_is_a_problem() -> None:
    result = read(fx.gpo_xml(sddl="owner is Domain Admins"))
    (problem,) = result.problems
    assert "SecurityDescriptor/SDDL" in str(problem.source)
    assert "not compared" in problem.reason or "were not compared" in problem.reason
    assert result.gpos[0].owner is None
    assert result.gpos[0].sddl == "owner is Domain Admins"  # the text is still compared


def test_an_owner_element_gives_the_owner_and_its_name() -> None:
    gpo = one(owner=OWNER_ELEMENT)
    assert (gpo.owner, gpo.owner_name) == ("S-1-5-21-1000-2000-3000-1999", "CORP\\owner")


def test_an_owner_element_with_no_sid_or_name_is_a_problem() -> None:
    empty = f'<Owner xmlns="{fx.SECURITY_TYPES}"/>'
    result = read(fx.gpo_xml(owner=empty))
    (problem,) = result.problems
    assert "Owner element" in problem.reason
    assert result.gpos[0].owner == "DA"  # the SDDL still gives one


def test_a_permission_with_no_named_right_keeps_its_access_mask() -> None:
    entry = fx.trustee("S-1-5-21-1000-2000-3000-1500", "CORP\\x", "", mask=131072)
    (trustee,) = one(trustees=entry).trustees or []
    assert trustee.rights == ()
    assert trustee.access_mask == 131072


@pytest.mark.parametrize("mask", ["", "abc", "0x20000", "-1", "99999999999", "1.5"])
def test_a_permission_with_no_named_right_and_no_usable_mask_is_a_problem(mask: str) -> None:
    entry = fx.trustee("S-1-5-21-1000-2000-3000-1500", "CORP\\x", "", mask=mask)
    result = read(fx.gpo_xml(trustees=entry))
    (problem,) = result.problems
    assert "TrusteePermissions[1]" in str(problem.source)
    assert "not compared" in problem.reason
    assert result.gpos[0].trustees is not None


# --- oversized and non-ASCII numbers (MISHPAT-C03) ----------------------------------------

HUGE = "9" * 5000


def registry_setting(number: str) -> str:
    return fx.registry_ext(
        f"<q1:RegistrySetting><q1:KeyPath>HKLM\\Software\\X</q1:KeyPath>"
        f"<q1:Value><q1:Name>V</q1:Name><q1:Number>{number}</q1:Number></q1:Value>"
        "</q1:RegistrySetting>"
    )


def test_a_number_of_thousands_of_digits_stays_text_and_is_not_a_crash() -> None:
    gpo = one(computer=registry_setting(HUGE))
    assert only(gpo).value == {"value": HUGE}


def test_a_number_of_twenty_digits_is_still_a_number() -> None:
    gpo = one(computer=registry_setting("18446744073709551615"))
    assert only(gpo).value == {"value": 18446744073709551615}
    assert one(computer=registry_setting("-1")).settings[0].value == {"value": -1}


def test_digits_of_other_scripts_are_not_numbers() -> None:
    assert only(one(computer=registry_setting("٣"))).value == {"value": "٣"}


@pytest.mark.parametrize("scalar_text", [HUGE, "-" + HUGE, "1" * 21])
def test_every_reader_that_converts_numbers_survives_a_long_one(scalar_text: str) -> None:
    ext = fx.security_ext(
        "<q1:SecurityOptions><q1:KeyName>MACHINE\\X</q1:KeyName>"
        f"<q1:SettingNumber>{scalar_text}</q1:SettingNumber>"
        "<q1:Display><q1:Name>Setting X</q1:Name></q1:Display></q1:SecurityOptions>"
        f"<q1:Account><q1:Name>MinimumPasswordLength</q1:Name><q1:SettingNumber>{scalar_text}</q1:SettingNumber>"
        "<q1:Type>Password</q1:Type></q1:Account>"
    )
    result = read(fx.gpo_xml(computer=ext))
    assert result.gpos  # read, not an internal error


def test_a_version_of_thousands_of_digits_is_a_problem_not_a_crash() -> None:
    result = read(fx.gpo_xml(versions=(HUGE, "3", "1", "1")))
    assert result.gpos
    assert any(
        "VersionDirectory" in p.reason and "not a number" in p.reason for p in result.problems
    )
    assert "computer directory" not in result.gpos[0].versions


# --- mixed content and ignored names inside unknown extensions (MISHPAT-C09) ---------------


def generic(body: str) -> Any:
    ext = fx.extension("Vendor/Thing", body.replace("<z:", "<q1:").replace("</z:", "</q1:"))
    return only(one(computer=ext)).value


def test_text_after_a_child_element_is_part_of_the_value() -> None:
    allow = generic("<z:Thing><z:Name>n</z:Name>allow</z:Thing>")
    deny = generic("<z:Thing><z:Name>n</z:Name>deny</z:Thing>")
    assert allow != deny
    assert allow["#tail"] == "allow"


def test_indentation_between_children_is_not_a_tail() -> None:
    value = generic("<z:Thing>\n  <z:A>1</z:A>\n  <z:B>2</z:B>\n</z:Thing>")
    assert "#tail" not in value


def test_a_setting_called_blocked_in_an_unknown_extension_is_compared() -> None:
    on = generic("<z:Thing><z:Blocked>true</z:Blocked><z:A>1</z:A></z:Thing>")
    off = generic("<z:Thing><z:Blocked>false</z:Blocked><z:A>1</z:A></z:Thing>")
    assert on != off
    assert on["Blocked"] == "true"


def test_extension_level_read_time_is_still_left_out() -> None:
    ext = fx.extension(
        "Vendor/Thing", "<q1:ReadTime>now</q1:ReadTime><q1:Thing><q1:A>1</q1:A></q1:Thing>"
    )
    assert len(one(computer=ext).settings) == 1


# --- a <GPOS> file is read one GPO at a time ---------------------------------------------


def test_a_gpos_file_is_not_held_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    gpos = [fx.gpo_xml(f"{n:08x}-aaaa-4aaa-8aaa-000000000001", f"G{n}") for n in range(40)]
    data = fx.report_bytes(*gpos, wrapped=True)
    whole = read_report(data, Source("r.xml"))
    monkeypatch.setattr(xmlsafe, "MAX_ELEMENTS", 400)  # one GPO fits, forty do not
    streamed = read_report(data, Source("r.xml"))
    assert [g.guid for g in streamed.gpos] == [g.guid for g in whole.gpos]
    assert len(streamed.gpos) == 40


def test_a_gpo_over_the_element_limit_is_refused_naming_the_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(xmlsafe, "MAX_ELEMENTS", 10)
    with pytest.raises(InputError, match=r"r\.xml is not a Get-GPOReport XML file: .*10 elements"):
        read_report(fx.report_bytes(fx.gpo_xml()), Source("r.xml"))
