# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Stored passwords never reach a report, but a change to one is still reported."""

from __future__ import annotations

from typing import TYPE_CHECKING

from faithful_core.exitcodes import ExitCode

from faithful_mishpat.cli import main
from faithful_mishpat.formats import hidden
from faithful_mishpat.formats.report import read_report
from faithful_mishpat.model import Source
from tests import fixtures_gpo as fx
from tests.fixtures_gpo import extension

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_mishpat.model import Gpo
# Synthetic stand-ins for a GPP cpassword value.
STORED_A = "synthetic-stored-password-one"
STORED_B = "synthetic-stored-password-two"
UID = "{E0000000-0000-4000-8000-000000000001}"


def _user(cpassword: str, *, uid: bool = True, user: str = "svc") -> str:
    uid_attr = f' uid="{UID}"' if uid else ""
    return extension(
        "Lugs",
        '<q1:LocalUsersAndGroups clsid="{C}">'
        f'<q1:User clsid="{{D}}" name="svc"{uid_attr}>'
        f'<q1:Properties action="U" userName="{user}" cpassword="{cpassword}"/>'
        "</q1:User></q1:LocalUsersAndGroups>",
    )


def _bytes(
    cpassword: str, *, uid: bool = True, name: str = "Servers baseline", user: str = "svc"
) -> bytes:
    return fx.report_bytes(fx.gpo_xml(name=name, computer=_user(cpassword, uid=uid, user=user)))


def _gpo(cpassword: str, *, uid: bool = True) -> Gpo:
    result = read_report(_bytes(cpassword, uid=uid), Source("r.xml"))
    assert result.problems == []
    (gpo,) = result.gpos
    return gpo


def test_hide_is_stable_within_a_run_and_empty_stays_empty() -> None:
    assert hidden.hide(STORED_A) == hidden.hide(STORED_A)
    assert hidden.hide(STORED_A) != hidden.hide(STORED_B)
    assert STORED_A not in hidden.hide(STORED_A)
    assert hidden.hide("") == ""


def test_conceal_walks_nested_values() -> None:
    value = {"a": [hidden.hide("x"), ("y", hidden.hide("z"))], "b": 1}
    assert hidden.conceal(value) == {"a": [hidden.SHOWN, ["y", hidden.SHOWN]], "b": 1}


def test_reader_never_keeps_the_stored_value() -> None:
    (setting,) = _gpo(STORED_A).settings
    assert STORED_A not in repr(setting)
    assert hidden.conceal(setting.value)["properties"]["@cpassword"] == hidden.SHOWN


def test_keys_without_uid_do_not_depend_on_the_hidden_value() -> None:
    (a,) = _gpo(STORED_A, uid=False).settings
    (b,) = _gpo(STORED_A, uid=False).settings
    assert a.key == b.key


def _run(tmp_path: Path, before: str, after: str, user: str = "svc") -> str:
    (tmp_path / "before.xml").write_bytes(_bytes(before))
    # A different name keeps the two inputs distinct when the passwords match.
    (tmp_path / "after.xml").write_bytes(_bytes(after, name="Servers baseline v2", user=user))
    out = tmp_path / "out"
    code = main(
        ["compare", str(tmp_path / "before.xml"), str(tmp_path / "after.xml"), "-o", str(out)]
    )
    assert code in {ExitCode.OK, ExitCode.FINDINGS}
    texts = []
    for path in sorted(out.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            texts.append(data.decode("utf-8", "replace"))
            assert STORED_A.encode() not in data
            assert STORED_B.encode() not in data
    return "\n".join(texts)


def test_changed_password_is_reported_without_either_value(tmp_path: Path) -> None:
    text = _run(tmp_path, STORED_A, STORED_B)
    assert "A stored password changed" in text
    assert hidden.SHOWN in text
    assert "mishpat-hidden" not in text


def test_unchanged_password_is_not_a_difference(tmp_path: Path) -> None:
    text = _run(tmp_path, STORED_A, STORED_A)
    assert "A stored password changed" not in text
    assert hidden.SHOWN not in text


def test_password_change_is_noted_beside_another_change(tmp_path: Path) -> None:
    text = _run(tmp_path, STORED_A, STORED_B, user="svc2")
    assert "A stored password changed" in text
    assert "svc2" in text


def test_password_added_with_an_item_is_not_called_a_change() -> None:
    assert hidden.password_changed({"p": hidden.hide("x")}, {"p": hidden.hide("y")})
    assert hidden.password_changed({"p": ""}, {"p": hidden.hide("y")})
    assert not hidden.password_changed({"p": hidden.hide("x"), "u": 1}, {"p": hidden.hide("x")})


def test_a_cpassword_child_element_is_hidden_too() -> None:
    xml = (
        '<q1:Things clsid="{C}"><q1:Thing clsid="{D}" name="t">'
        f"<q1:Properties><q1:cPassword>{STORED_A}</q1:cPassword></q1:Properties>"
        "</q1:Thing></q1:Things>"
    )
    result = read_report(
        fx.report_bytes(fx.gpo_xml(computer=extension("Misc", xml))), Source("r.xml")
    )
    (setting,) = result.gpos[0].settings
    assert STORED_A not in repr(setting)
    assert hidden.conceal(setting.value)["properties"]["cPassword"] == hidden.SHOWN


def test_a_value_that_starts_like_a_stand_in_is_not_one() -> None:
    forged = hidden.PREFIX + "aaa"
    assert hidden.conceal(forged) == forged
    assert hidden.conceal({"data": forged}) == {"data": forged}
    assert hidden.password_changed(forged, hidden.PREFIX + "bbb") is False  # plain text


def test_a_real_stand_in_is_still_concealed() -> None:
    assert hidden.conceal(hidden.hide("secret")) == hidden.SHOWN
