# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Registry.pol reader."""

from __future__ import annotations

import struct
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_mishpat.formats import registrypol
from faithful_mishpat.formats.registrypol import PolRead, read_registry_pol
from faithful_mishpat.model import Source
from tests.fixtures_gpo import Entry, dword, multi_sz, qword, registry_pol, sz

BASE = Source("x", "DomainSysvol/GPO/Machine/registry.pol")
KEY = "Software\\Policies\\Example"


def read(entries: list[Entry], scope: str = "Computer") -> PolRead:
    return read_registry_pol(registry_pol(entries), scope, BASE)


@pytest.mark.parametrize(
    ("kind", "data", "type_name", "canonical"),
    [
        (0, b"", "REG_NONE", ""),
        (0, b"\x01\x02", "REG_NONE", "0102"),
        (1, sz("text"), "REG_SZ", "text"),
        (2, sz("%TEMP%\\x"), "REG_EXPAND_SZ", "%TEMP%\\x"),
        (3, b"\x00\xab\xff", "REG_BINARY", "00abff"),
        (4, dword(0xFFFFFFFF), "REG_DWORD", 4294967295),
        (5, b"\x00\x00\x01\x00", "REG_DWORD_BIG_ENDIAN", 256),
        (6, b"\x01", "REG_LINK", "01"),
        (7, multi_sz("one", "two"), "REG_MULTI_SZ", ["one", "two"]),
        (7, multi_sz(), "REG_MULTI_SZ", []),
        (8, b"\x09", "REG_RESOURCE_LIST", "09"),
        (11, qword(2**40), "REG_QWORD", 2**40),
        (99, b"\x63", "REG_TYPE_99", "63"),
    ],
)
def test_every_type_is_carried(kind: int, data: bytes, type_name: str, canonical: object) -> None:
    result = read([(KEY, "Value1", kind, data)])
    assert result.ok
    assert result.problems == []
    (setting,) = result.settings
    assert setting.value == {"type": type_name, "data": canonical}
    assert (setting.scope, setting.area, setting.kind) == ("Computer", "Registry.pol", "Value")
    assert setting.key == (KEY, "Value1")
    assert setting.title == f"{KEY}\\Value1"
    assert setting.source == Source("x", "DomainSysvol/GPO/Machine/registry.pol entry 1")


def test_scope_comes_from_the_caller() -> None:
    assert read([(KEY, "v", 4, dword(1))], "User").settings[0].scope == "User"


@pytest.mark.parametrize(
    "name",
    ["**del.Foo", "**delvals.", "**DeleteValues", "**DeleteKeys", "**SecureKey", "**soft.Foo"],
)
def test_directives_are_kept_as_distinct_settings(name: str) -> None:
    result = read([(KEY, "Foo", 4, dword(1)), (KEY, name, 1, sz(" "))])
    values, directives = result.settings
    assert (values.kind, directives.kind) == ("Value", "Directive")
    assert directives.key == (KEY, name)
    assert len(result.settings) == 2  # not resolved against each other


def test_empty_value_name_titles_the_key_alone() -> None:
    (setting,) = read([(KEY, "", 3, b"")]).settings
    assert setting.title == KEY


def test_later_entries_win_and_occurrences_are_counted() -> None:
    result = read(
        [
            (KEY, "A", 4, dword(1)),
            (KEY, "B", 4, dword(5)),
            (KEY.upper(), "a", 4, dword(2)),
            (KEY, "A", 4, dword(3)),
        ]
    )
    first, second = result.settings
    assert first.value == {"type": "REG_DWORD", "data": 3}
    assert first.context == {"occurrences": "3"}
    assert first.source.detail.endswith("entry 4")
    assert second.context == {}
    assert (first.key[1], second.key[1]) == ("A", "B")  # first-seen order is kept


def test_header_only_file_has_no_settings() -> None:
    result = read([])
    assert result.ok
    assert result.settings == []


@pytest.mark.parametrize(
    "data",
    [b"", b"PReg", b"XXXX\x01\x00\x00\x00", b"PReg\x02\x00\x00\x00"],
)
def test_wrong_signature_or_version_gives_a_problem_and_no_settings(data: bytes) -> None:
    result = read_registry_pol(data, "Computer", BASE)
    assert not result.ok
    assert result.settings == []
    (problem,) = result.problems
    assert "values were not read" in problem.reason
    assert problem.source == BASE


def test_a_truncated_entry_keeps_the_entries_before_it() -> None:
    good = registry_pol([(KEY, "A", 4, dword(1)), (KEY, "B", 4, dword(2))])
    for cut in (1, 7, 40, 60):
        result = read_registry_pol(good[:-cut], "Computer", BASE)
        assert not result.ok
        assert [s.key[1] for s in result.settings] == ["A"]
        assert "entry 2 is damaged" in result.problems[0].reason


def test_a_file_with_more_entries_than_the_limit_is_read_up_to_it_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(registrypol, "MAX_ENTRIES", 3)
    result = read([(KEY, f"V{n}", 4, dword(n)) for n in range(5)])
    assert not result.ok
    assert [s.key[1] for s in result.settings] == ["V0", "V1", "V2"]
    (problem,) = result.problems
    assert "more than 3 entries" in problem.reason
    assert "after the first 3 were not read" in problem.reason


def test_a_file_with_exactly_the_limit_is_read_in_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(registrypol, "MAX_ENTRIES", 3)
    result = read([(KEY, f"V{n}", 4, dword(n)) for n in range(3)])
    assert result.ok
    assert len(result.settings) == 3


def test_every_truncation_point_is_a_problem_not_a_crash() -> None:
    good = registry_pol([(KEY, "A", 1, sz("hello")), (KEY, "B", 7, multi_sz("x"))])
    for cut in range(len(good)):
        result = read_registry_pol(good[:cut], "Computer", BASE)
        assert result.ok or result.problems


def test_odd_trailing_byte_is_damage() -> None:
    result = read_registry_pol(registry_pol([(KEY, "A", 4, dword(1))]) + b"\x5b", "Computer", BASE)
    assert not result.ok
    assert [s.key[1] for s in result.settings] == ["A"]


def test_a_missing_separator_is_damage() -> None:
    good = bytearray(registry_pol([(KEY, "A", 4, dword(1))]))
    good[8:10] = b"\x28\x00"  # '(' instead of '['
    result = read_registry_pol(bytes(good), "Computer", BASE)
    assert not result.ok
    assert "expected '['" in result.problems[0].reason


def test_invalid_utf16_in_a_name_is_damage() -> None:
    raw = bytearray(registry_pol([(KEY, "A", 4, dword(1))]))
    raw[10:12] = b"\x00\xd8"  # a lone high surrogate where the key starts
    result = read_registry_pol(bytes(raw), "Computer", BASE)
    assert not result.ok
    assert "not valid UTF-16" in result.problems[0].reason


@pytest.mark.parametrize(
    ("kind", "data", "fragment"),
    [
        (4, b"\x01\x02", "2 bytes, not 4"),
        (5, b"\x01", "1 bytes, not 4"),
        (11, dword(1), "4 bytes, not 8"),
        (1, b"\x00\xd8\x00\x00", "not valid UTF-16"),
        (7, b"\x01", "not valid UTF-16"),
    ],
)
def test_data_that_does_not_fit_its_type_is_kept_as_hex_with_a_note(
    kind: int, data: bytes, fragment: str
) -> None:
    result = read([(KEY, "Odd", kind, data)])
    assert result.ok
    (setting,) = result.settings
    assert setting.value == {
        "type": cast("dict[str, Any]", setting.value)["type"],
        "data": data.hex(),
    }
    (problem,) = result.problems
    assert fragment in problem.reason
    assert problem.source.detail.endswith("entry 1")


def test_data_may_contain_the_bracket_character() -> None:
    tricky = "]".encode("utf-16-le") + b";\x00"
    (setting,) = read([(KEY, "B", 3, tricky)]).settings
    assert setting.value == {"type": "REG_BINARY", "data": tricky.hex()}


@given(st.binary(max_size=200))
def test_arbitrary_bytes_never_raise(data: bytes) -> None:
    result = read_registry_pol(b"PReg" + struct.pack("<I", 1) + data, "User", BASE)
    assert isinstance(result, PolRead)


@given(
    st.lists(
        st.tuples(
            st.text(
                st.characters(codec="utf-8", exclude_characters="\x00"),
                max_size=20,
            ),
            st.text(
                st.characters(codec="utf-8", exclude_characters="\x00"),
                max_size=20,
            ),
            st.integers(0, 12),
            st.binary(max_size=24),
        ),
        max_size=6,
    )
)
def test_written_entries_are_read_back(entries: list[Entry]) -> None:
    result = read(entries)
    distinct = {(k.casefold(), n.casefold()) for k, n, _, _ in entries}
    assert len(result.settings) == len(distinct)
