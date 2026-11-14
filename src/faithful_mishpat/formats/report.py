# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Read ``Get-GPOReport -ReportType Xml`` files.

Accepted shapes: one ``<GPO>`` (namespace ``http://www.microsoft.com/GroupPolicy/Settings``)
or an unnamespaced ``<GPOS>`` wrapping many (``Get-GPOReport -All``). Every element is
identified by its namespace URI; the ``q1``/``q2`` prefixes in a file mean nothing.
Parsing is done by :mod:`faithful_mishpat.formats.xmlsafe`.

One GPO element that cannot be read becomes a :class:`~faithful_mishpat.model.Problem` and
the rest are still read. A file that is not a GPO report at all raises
:class:`~faithful_mishpat.errors.InputError`.

Mapping (``DESIGN.md``, "Report XML to Settings"):

* ``Registry``: ``Policy`` is an ``Administrative Templates`` setting keyed by
  ``(Category, Name)``; ``RegistrySetting`` is a ``Registry`` setting keyed by
  ``(KeyPath, value name)``.
* ``Security``: ``Account``, ``SecurityOptions``, ``UserRightsAssignment``,
  ``RestrictedGroups``, ``SystemServices``, ``Audit`` and ``EventLog``. Members are sorted
  SIDs (the name when there is no SID), so a reordered list is not a change.
* ``Auditing``: ``AuditSetting`` is an ``Advanced Audit`` setting keyed by
  ``(PolicyTarget, SubcategoryGuid)``.
* ``Scripts``: one setting per scope and script type, holding the ordered list.
* Group Policy Preferences (an extension element with a ``clsid``): one ``Preferences:
  <Type>`` setting per item, keyed by the collection path and the item ``uid`` (or, with
  no ``uid``, the target the type is about). Collections are flattened.
* ``FolderRedirection``: ``Folder`` keyed by ``Id``.
* Anything else is generic: one setting per child element of ``Extension``, with the
  area taken from the namespace (the part after ``.../GroupPolicy/Settings/``, or the
  whole URI for a foreign namespace), the kind the element's local name, the key the
  ``Name`` child (else an ``Id`` child, else a ``Name``/``Id``/``Type`` attribute, else
  nothing when the element is the only one of its name in the scope, else a hash of its
  canonical content) and the value the element's canonical content.

Two settings with the same identity in one GPO get ``#2``, ``#3`` on the last key part, in
document order, so that none is lost. ``Blocked``, ``ReadTime``, ``Explain``,
``Supported`` and the version numbers never take part in a value.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from faithful_mishpat.errors import InputError
from faithful_mishpat.formats import hidden, xmlsafe
from faithful_mishpat.model import (
    Gpo,
    Link,
    Problem,
    Setting,
    Source,
    Trustee,
    ValueData,
    WmiFilter,
    evidence_key,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from xml.etree import ElementTree as ET

BASE = "http://www.microsoft.com/GroupPolicy/"
SETTINGS = BASE + "Settings"
TYPES = BASE + "Types"
SECURITY_TYPES = BASE + "Types/Security"
_XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
_IGNORED = frozenset(
    {
        "ReadTime",
        "Blocked",
        "VersionDirectory",
        "VersionSysvol",
        "Explain",
        "Supported",
        "GPOSettingOrder",
    }
)
_SID = re.compile(r"[sS]-1-\d+(?:-\d+)+")
_NUMBER = re.compile(r"-?[0-9]{1,20}")
"""A whole number mishpat reads as a number: ASCII digits, at most 20 (a 64-bit value).

Anything longer, or in other digits, stays text. Python refuses to convert thousands of digits,
and such a number is not a registry value or a version."""
_POLICY_NON_ELEMENTS = frozenset(
    {"Name", "State", "Explain", "Supported", "Category", "Comment", "Text"}
)
_GPP_LABELS = {
    "Windows/Registry": "Registry",
    "Lugs": "Local Users and Groups",
    "ScheduledTasks": "Scheduled Tasks",
}
_GPP_DROPPED = frozenset({"changed", "image", "status", "uid", "descr"})
_GPP_SKIPPED = frozenset({"GPOSettingOrder", "Filters", "Properties"})
_EFFECTIVE = ("computer", "user")


@dataclass
class ReportRead:
    """What a report file held.

    Attributes:
        gpos: The GPOs that could be read, in file order.
        problems: What could not be read.
        wrapped: Whether the root was ``<GPOS>`` (a ``-All`` capture).
    """

    gpos: list[Gpo] = field(default_factory=list)
    problems: list[Problem] = field(default_factory=list)
    wrapped: bool = False


class _BadGpoError(ValueError):
    """A GPO element that cannot be read."""


# --- small helpers ----------------------------------------------------------------


def _ns(element: ET.Element) -> str:
    return xmlsafe.split(element.tag)[0]


def _local(element: ET.Element) -> str:
    return xmlsafe.split(element.tag)[1]


def _clean(text: str | None) -> str:
    value = (text or "").strip()
    return value.upper() if _SID.fullmatch(value) else value


def _find(element: ET.Element, local: str, ns: str | None = None) -> ET.Element | None:
    return element.find(f"{{{_ns(element) if ns is None else ns}}}{local}")


def _all(element: ET.Element, local: str, ns: str | None = None) -> list[ET.Element]:
    return element.findall(f"{{{_ns(element) if ns is None else ns}}}{local}")


def _text(element: ET.Element, local: str, ns: str | None = None) -> str | None:
    """Return a child's text (stripped), or ``None`` when there is no such child."""
    child = _find(element, local, ns)
    return None if child is None else (child.text or "").strip()


def _scalar(text: str) -> ValueData:
    return int(text) if _NUMBER.fullmatch(text) else text


def _flag(text: str) -> ValueData:
    lowered = text.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    return text


def _guid(text: str) -> str:
    """Normalize a GUID to lower case without braces; raise ``ValueError`` if it is not one."""
    return str(uuid.UUID(text.strip().strip("{}")))


def _guid_or_text(text: str) -> str:
    try:
        return _guid(text)
    except ValueError:
        return text.strip()


def _sid_or_name(element: ET.Element) -> str:
    sid = _text(element, "SID", TYPES)
    return sid.upper() if sid else (_text(element, "Name", TYPES) or "")


_XSI_PREFIX = "{http://www.w3.org/2001/XMLSchema-instance}"


def _attribute_name(key: str) -> str:
    """Return an attribute's local name, without its ``{uri}``."""
    return key.rpartition("}")[2]


def _json(value: ValueData) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _whole_content(element: ET.Element) -> list[object]:
    """Everything an element holds: names, attributes, text, children and the text after each."""
    return [
        element.tag,
        sorted((k, v) for k, v in element.attrib.items() if not k.startswith(_XSI_PREFIX)),
        _clean(element.text),
        [[_whole_content(child), _clean(child.tail)] for child in element],
    ]


def _hidden_element(element: ET.Element) -> str:
    """Stand in for a stored-password element, of any shape, by a fingerprint of all of it.

    The fingerprint covers attributes, children and mixed text, so any change to what is
    stored is found. An element that holds nothing is ``""``, an empty password.
    """
    if not element.attrib and not len(element) and not _clean(element.text):
        return ""
    return hidden.hide(json.dumps(_whole_content(element), ensure_ascii=False))


def canonical(
    element: ET.Element,
    *,
    drop: frozenset[str] = frozenset(),
    sort: frozenset[str] = frozenset({"Member"}),
) -> ValueData:
    """Return an element's content as plain data: attributes, text and children.

    Namespaces are dropped from element names. Attributes are ``@name``, or
    ``@{uri}name`` for an attribute in a namespace, so a prefix never matters and two
    namespaces never collide; only XML Schema instance attributes are left out. Text
    beside children is ``#text``, repeated children are lists (sorted for the names in
    ``sort``), and ``xsi:nil`` is ``None``. The ignored names (see the module
    documentation) and the attribute names in ``drop`` are left out. SIDs are upper
    case. A stored password (``cpassword``), as an attribute or as a whole element of
    any shape, is replaced by :func:`faithful_mishpat.formats.hidden.hide`.
    """
    if element.get(_XSI_NIL) == "true":
        return None
    if hidden.is_hidden_name(_local(element)):
        return _hidden_element(element)
    text = _clean(element.text)
    attributes = {
        k: v for k, v in element.attrib.items() if not k.startswith(_XSI_PREFIX) and k not in drop
    }
    children: dict[str, list[ValueData]] = {}
    for child in element:
        name = _local(child)
        if name not in _IGNORED:
            item = canonical(child, drop=drop, sort=sort)
            children.setdefault(name, []).append(item)
    if not attributes and not children:
        return text
    out: dict[str, ValueData] = {
        f"@{k}": hidden.hide(v) if hidden.is_hidden_name(_attribute_name(k)) else _clean(v)
        for k, v in sorted(attributes.items())
    }
    if text:
        out["#text"] = text
    for name in sorted(children):
        items = children[name]
        if name in sort:
            items = sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
        out[name] = items[0] if len(items) == 1 else items
    return out


def _hash(value: ValueData) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def _tail(uri: str) -> str:
    prefix = SETTINGS + "/"
    return uri.removeprefix(prefix)


# --- per-scope context ---------------------------------------------------------------


@dataclass
class _Scope:
    """What the mappers share while reading one half of a GPO."""

    name: str
    base: Source
    problems: list[Problem]
    settings: list[Setting] = field(default_factory=list)
    scripts: dict[str, list[dict[str, ValueData]]] = field(default_factory=dict)
    # Stored-password elements met where a setting would start, by (area, kind, key).
    hidden: dict[tuple[str, str, tuple[str, ...]], list[ET.Element]] = field(default_factory=dict)

    def keep_hidden(self, element: ET.Element, area: str, key: tuple[str, ...] = ()) -> None:
        """Set aside a stored-password element; nothing inside it may name a setting."""
        self.hidden.setdefault((area, _local(element), key), []).append(element)

    def finish_hidden(self) -> None:
        """Add one setting per group of stored-password elements.

        Its identity uses only the area, the element name and a path of collection names,
        never anything inside the elements. Its value is the sorted fingerprints of all of
        them, so a change to any is found and an order change is not.
        """
        for (area, kind, key), elements in sorted(self.hidden.items(), key=lambda i: i[0]):
            fingerprints: list[ValueData] = []
            fingerprints.extend(sorted(_hidden_element(e) for e in elements))
            self.add(
                elements[0],
                area=area,
                kind=kind,
                key=key,
                title=kind,
                value=fingerprints,
            )
        self.hidden.clear()

    def source(self, tail: str, local: str, title: str) -> Source:
        detail = f"{self.name}/{tail}/{local}[{title}]"
        return Source(self.base.file, f"{self.base.detail} {detail}".strip())

    def problem(self, tail: str, local: str, reason: str) -> None:
        where = Source(self.base.file, f"{self.base.detail} {self.name}/{tail}/{local}".strip())
        self.problems.append(Problem(where, f"A {local} element was skipped: {reason}"))

    def add(  # noqa: PLR0913 - the fields of a Setting
        self,
        element: ET.Element,
        *,
        area: str,
        kind: str,
        key: tuple[str, ...],
        title: str,
        value: ValueData,
        context: dict[str, str] | None = None,
    ) -> None:
        tail, local = _tail(_ns(element)), _local(element)
        self.settings.append(
            Setting(
                scope=self.name,
                area=area,
                kind=kind,
                key=key,
                title=title,
                value=value,
                source=self.source(tail, local, title),
                context={k: v for k, v in (context or {}).items() if v},
            )
        )


# --- Registry -------------------------------------------------------------------------


def _policy_element(element: ET.Element) -> dict[str, ValueData]:
    kind = _local(element)
    value: ValueData = None
    holder = _find(element, "Value")
    if holder is not None:
        value = _policy_value(holder, kind)
    out: dict[str, ValueData] = {
        "kind": kind,
        "name": _text(element, "Name") or "",
        "state": _text(element, "State"),
        "value": value,
    }
    if kind == "ListBox":
        options = {
            name: _flag(text)
            for name in ("Additive", "ExplicitValue", "ValuePrefix")
            if (text := _text(element, name)) is not None
        }
        if options:
            out["options"] = options
    return out


def _policy_value(holder: ET.Element, kind: str) -> ValueData:
    name = _find(holder, "Name")
    if name is not None:
        return (name.text or "").strip()
    entries = _all(holder, "Element")
    if entries or kind == "ListBox":
        listed = sorted(
            ((_text(entry, "Name") or "", _text(entry, "Data")) for entry in entries),
            key=lambda entry: (entry[0], entry[1] or ""),
        )
        return [{"name": name, "data": data} for name, data in listed]
    text = (holder.text or "").strip()
    return _scalar(text) if kind == "Numeric" else text


def _policy_state(state: str, parts: list[dict[str, ValueData]]) -> dict[str, ValueData]:
    """A policy's value: its state, then each option by the name the editor shows.

    Options are keyed by name so a change to one option shows as that option alone.
    An unnamed option uses its kind; a repeated name gets ``#2``, ``#3``.
    """
    value: dict[str, ValueData] = {"state": state}
    for part in parts:
        # The editor writes many option names with a closing colon ("Size (KB):").
        label = str(part["name"] or "").rstrip().rstrip(":").rstrip() or str(part["kind"])
        if label.casefold() == "state":
            label = f"{label} (option)"
        base, count = label, 1
        while label in value:
            count += 1
            label = f"{base} #{count}"
        shown: ValueData = part["value"] if part["value"] is not None else part["state"]
        if "options" in part:
            shown = {"value": shown, "options": part["options"]}
        value[label] = shown
    return value


def _policy(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Registry", "Policy", "it has no Name")
        return
    category = _text(element, "Category") or ""
    parts = [
        _policy_element(child) for child in element if _local(child) not in _POLICY_NON_ELEMENTS
    ]
    parts.sort(key=lambda part: (str(part["kind"]), str(part["name"])))
    scope.add(
        element,
        area="Administrative Templates",
        kind="Policy",
        key=(category, name),
        title=name,
        value=_policy_state(_text(element, "State") or "", parts),
        context={
            "category": category,
            "explain": _text(element, "Explain") or "",
            "supported": _text(element, "Supported") or "",
            "comment": _text(element, "Comment") or "",
        },
    )


def _registry_setting(scope: _Scope, element: ET.Element) -> None:
    path = _text(element, "KeyPath")
    if not path:
        scope.problem("Registry", "RegistrySetting", "it has no KeyPath")
        return
    holder = _find(element, "Value")
    name = "" if holder is None else (_text(holder, "Name") or "")
    value: ValueData = None
    if holder is not None:
        number, string = _text(holder, "Number"), _text(holder, "String")
        if number is not None:
            value = _scalar(number)
        elif string is not None:
            value = string
    scope.add(
        element,
        area="Registry",
        kind="Registry Setting",
        key=(path, name),
        title=f"{path}\\{name}" if name else path,
        value={"value": value},
        context={"AdmSetting": _text(element, "AdmSetting") or ""},
    )


# --- Security -------------------------------------------------------------------------


def _number_or_text(element: ET.Element, *names: str) -> ValueData:
    for name in names:
        text = _text(element, name)
        if text is not None:
            return _flag(text) if name == "SettingBoolean" else _scalar(text)
    return None


def _account(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Security", "Account", "it has no Name")
        return
    kind = _text(element, "Type") or ""
    scope.add(
        element,
        area="Security",
        kind="Account",
        key=(kind, name),
        title=name,
        value=_number_or_text(element, "SettingNumber", "SettingBoolean"),
    )


def _security_option(scope: _Scope, element: ET.Element) -> None:
    key = _text(element, "KeyName") or _text(element, "SystemAccessPolicyName")
    if not key:
        scope.problem("Security", "SecurityOptions", "it has no KeyName or SystemAccessPolicyName")
        return
    display = _find(element, "Display")
    title = (_text(display, "Name") if display is not None else None) or key
    context = {}
    if display is not None:
        context = {
            "display": _text(display, "DisplayString") or "",
            "units": _text(display, "Units") or "",
        }
    value = _number_or_text(element, "SettingNumber", "SettingString")
    if context.get("display"):
        context[f"label:{value}"] = context["display"]
    scope.add(
        element,
        area="Security",
        kind="Security Option",
        key=(key,),
        title=title,
        value=value,
        context=context,
    )


def _members(element: ET.Element, local: str) -> tuple[list[str], list[str]]:
    """Return sorted unique member ids and the sorted names, for ``local`` children."""
    found = _all(element, local)
    ids = sorted({_sid_or_name(member) for member in found} - {""})
    names = sorted({_text(member, "Name", TYPES) or "" for member in found} - {""})
    return ids, names


def _names_of(members: list[ET.Element]) -> dict[str, str]:
    """``label:<sid>`` context entries naming each member, for reports to show."""
    labels: dict[str, str] = {}
    for member in members:
        sid, name = _sid_or_name(member), _text(member, "Name", TYPES) or ""
        if sid and name and name != sid:
            labels[f"label:{sid}"] = name
    return labels


def _user_right(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Security", "UserRightsAssignment", "it has no Name")
        return
    ids, names = _members(element, "Member")
    scope.add(
        element,
        area="Security",
        kind="User Rights Assignment",
        key=(name,),
        title=name,
        value=list(ids),
        context={"members": ", ".join(names), **_names_of(_all(element, "Member"))},
    )


def _restricted_group(scope: _Scope, element: ET.Element) -> None:
    group = _find(element, "GroupName")
    key = _sid_or_name(group) if group is not None else ""
    if not key:
        scope.problem("Security", "RestrictedGroups", "it has no GroupName")
        return
    members, member_names = _members(element, "Member")
    member_of, member_of_names = _members(element, "MemberOf")
    scope.add(
        element,
        area="Security",
        kind="Restricted Group",
        key=(key,),
        title=(_text(group, "Name", TYPES) if group is not None else None) or key,
        value={"members": list(members), "member_of": list(member_of)},
        context={
            "member names": ", ".join(member_names),
            "member of names": ", ".join(member_of_names),
        },
    )


def _system_service(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Security", "SystemServices", "it has no Name")
        return
    value: dict[str, ValueData] = {"startup": _text(element, "StartupMode") or ""}
    descriptor = _find(element, "SecurityDescriptor")
    sddl = _text(descriptor, "SDDL", SECURITY_TYPES) if descriptor is not None else None
    if sddl:
        value["sddl"] = sddl
    scope.add(element, area="Security", kind="System Service", key=(name,), title=name, value=value)


def _legacy_audit(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Security", "Audit", "it has no Name")
        return
    scope.add(
        element,
        area="Security",
        kind="Audit",
        key=(name,),
        title=name,
        value={
            "success": _flag(_text(element, "SuccessAttempts") or "false"),
            "failure": _flag(_text(element, "FailureAttempts") or "false"),
        },
    )


def _event_log(scope: _Scope, element: ET.Element) -> None:
    name = _text(element, "Name")
    if not name:
        scope.problem("Security", "EventLog", "it has no Name")
        return
    log = _text(element, "Log") or ""
    scope.add(
        element,
        area="Security",
        kind="Event Log",
        key=(log, name),
        title=f"{log} {name}".strip(),
        value=_number_or_text(element, "SettingNumber", "SettingBoolean"),
    )


# --- Advanced Audit, Scripts, Folder Redirection --------------------------------------


def _audit_setting(scope: _Scope, element: ET.Element) -> None:
    target = _text(element, "PolicyTarget") or ""
    guid = _text(element, "SubcategoryGuid")
    if not guid:
        scope.problem("Auditing", "AuditSetting", "it has no SubcategoryGuid")
        return
    name = _text(element, "SubcategoryName") or guid
    scope.add(
        element,
        area="Advanced Audit",
        kind="Audit Setting",
        key=(target, _guid_or_text(guid)),
        title=name,
        value=_scalar(_text(element, "SettingValue") or ""),
    )


def _script(scope: _Scope, element: ET.Element) -> None:
    kind = _text(element, "Type")
    command = _text(element, "Command")
    if not kind or command is None:
        scope.problem("Scripts", "Script", "it has no Type or Command")
        return
    entry: dict[str, ValueData] = {
        "command": command,
        "parameters": _text(element, "Parameters") or "",
        "order": _scalar(_text(element, "Order") or "0"),
    }
    run_order = _text(element, "RunOrder")
    if run_order:
        entry["run_order"] = run_order
    scope.scripts.setdefault(kind, []).append(entry)


def _finish_scripts(scope: _Scope) -> None:
    for kind, entries in scope.scripts.items():
        ordered = sorted(
            entries,
            key=lambda e: (e["order"] if isinstance(e["order"], int) else 0, str(e["command"])),
        )
        scope.settings.append(
            Setting(
                scope=scope.name,
                area="Scripts",
                kind="Script",
                key=(kind,),
                title=f"{kind} scripts",
                value=list(ordered),
                source=scope.source("Scripts", "Script", kind),
            )
        )


def _folder(scope: _Scope, element: ET.Element) -> None:
    identifier = _text(element, "Id")
    if not identifier:
        scope.problem("FolderRedirection", "Folder", "it has no Id")
        return
    value = canonical(element)
    assert isinstance(value, dict)  # noqa: S101 - an element with an Id child is a mapping
    value.pop("Id", None)
    scope.add(
        element,
        area="Folder Redirection",
        kind="Folder",
        key=(_guid_or_text(identifier),),
        title=identifier,
        value=value,
    )


# --- Preferences ----------------------------------------------------------------------


def _gpp_fallback(tail: str, attributes: dict[str, str], properties: dict[str, str]) -> str:
    if tail == "Windows/Registry":
        parts = [properties.get(n, "") for n in ("hive", "key", "name")]
        return "\\".join(parts) if any(parts) else attributes.get("name", "")
    names = {
        "Files": ("targetPath",),
        "Folders": ("path",),
        "Lugs": ("groupSid", "groupName", "userName"),
    }.get(tail, ())
    for name in names:
        if properties.get(name):
            return properties[name]
    return attributes.get("name", "")


@dataclass
class _Preferences:
    """The extension a Group Policy Preferences walk is reading."""

    scope: _Scope
    tail: str
    area: str


def _gpp_item(
    prefs: _Preferences, item: ET.Element, path: tuple[str, ...], filters: list[ValueData]
) -> None:
    attributes = {k: v for k, v in item.attrib.items() if not k.startswith("{")}
    holder = _find(item, "Properties")
    properties = (
        {k: v for k, v in holder.attrib.items() if not k.startswith("{")}
        if holder is not None
        else {}
    )
    value: dict[str, ValueData] = {
        "attributes": {
            k: hidden.hide(v) if hidden.is_hidden_name(k) else _clean(v)
            for k, v in sorted(attributes.items())
            if k not in _GPP_DROPPED
        },
        "properties": canonical(holder) if holder is not None else None,
        "filters": canonical(f) if (f := _find(item, "Filters")) is not None else "",
    }
    if any(filters):
        value["collection_filters"] = list(filters)
    uid = attributes.get("uid", "")
    identifier = (
        _guid_or_text(uid)
        if uid
        else _gpp_fallback(prefs.tail, attributes, properties) or _hash(hidden.conceal(value))
    )
    title = attributes.get("name") or identifier
    order = _text(item, "GPOSettingOrder") or ""
    prefs.scope.add(
        item,
        area=prefs.area,
        kind=_local(item),
        key=(*path, identifier),
        title=title,
        value=value,
        context={
            "changed": attributes.get("changed", ""),
            "order": order,
            "description": attributes.get("descr", ""),
        },
    )


def _gpp_walk(
    prefs: _Preferences, parent: ET.Element, path: tuple[str, ...], filters: list[ValueData]
) -> None:
    for child in parent:
        local = _local(child)
        if local in _GPP_SKIPPED:
            continue
        if hidden.is_hidden_name(local):
            prefs.scope.keep_hidden(child, prefs.area, path)
        elif local == "Collection":
            holder = _find(child, "Filters")
            inner = [*filters, canonical(holder) if holder is not None else ""]
            _gpp_walk(prefs, child, (*path, child.get("name", "")), inner)
        elif child.get("clsid") is not None:
            _gpp_item(prefs, child, path, filters)


def _preferences(scope: _Scope, element: ET.Element) -> None:
    tail = _tail(_ns(element))
    label = _GPP_LABELS.get(tail, tail.rsplit("/", 1)[-1])
    _gpp_walk(_Preferences(scope, tail, f"Preferences: {label}"), element, (), [])


# --- generic --------------------------------------------------------------------------


def _generic_key(element: ET.Element, *, unique: bool, value: ValueData) -> tuple[str, ...]:
    for name in ("Name", "Id"):
        text = _text(element, name)
        if text:
            return (text,)
    for name in ("Name", "name", "Id", "id", "Type", "type"):
        if element.get(name):
            return (element.get(name, ""),)
    return () if unique else (_hash(hidden.conceal(value)),)


def _generic(scope: _Scope, element: ET.Element, *, unique: bool) -> None:
    value = canonical(element)
    key = _generic_key(element, unique=unique, value=value)
    scope.add(
        element,
        area=_tail(_ns(element)),
        kind=_local(element),
        key=key,
        title=key[0] if key else _local(element),
        value=value,
    )


_HANDLERS: dict[tuple[str, str], Callable[[_Scope, ET.Element], None]] = {
    (f"{SETTINGS}/Registry", "Policy"): _policy,
    (f"{SETTINGS}/Registry", "RegistrySetting"): _registry_setting,
    (f"{SETTINGS}/Security", "Account"): _account,
    (f"{SETTINGS}/Security", "SecurityOptions"): _security_option,
    (f"{SETTINGS}/Security", "UserRightsAssignment"): _user_right,
    (f"{SETTINGS}/Security", "RestrictedGroups"): _restricted_group,
    (f"{SETTINGS}/Security", "SystemServices"): _system_service,
    (f"{SETTINGS}/Security", "Audit"): _legacy_audit,
    (f"{SETTINGS}/Security", "EventLog"): _event_log,
    (f"{SETTINGS}/Auditing", "AuditSetting"): _audit_setting,
    (f"{SETTINGS}/Scripts", "Script"): _script,
    (f"{SETTINGS}/FolderRedirection", "Folder"): _folder,
}


def _extension_children(half: ET.Element) -> list[ET.Element]:
    found: list[ET.Element] = []
    for data in _all(half, "ExtensionData", SETTINGS):
        for extension in _all(data, "Extension", SETTINGS):
            found.extend(child for child in extension if _local(child) not in _IGNORED)
    return found


def _read_half(scope: _Scope, half: ET.Element) -> None:
    children = _extension_children(half)
    totals: dict[tuple[str, str], int] = {}
    for child in children:
        totals[(_ns(child), _local(child))] = totals.get((_ns(child), _local(child)), 0) + 1
    for child in children:
        if hidden.is_hidden_name(_local(child)):
            scope.keep_hidden(child, _tail(_ns(child)))
            continue
        handler = _HANDLERS.get((_ns(child), _local(child)))
        if handler is not None:
            handler(scope, child)
        elif child.get("clsid") is not None:
            _preferences(scope, child)
        else:
            _generic(scope, child, unique=totals[(_ns(child), _local(child))] == 1)
    _finish_scripts(scope)
    scope.finish_hidden()


def _dedupe(settings: list[Setting]) -> list[Setting]:
    """Give later settings with an identity already seen a ``#n`` suffix on the key."""
    seen: dict[tuple[str, ...], int] = {}
    out: list[Setting] = []
    for setting in settings:
        count = seen.get(setting.identity, 0) + 1
        seen[setting.identity] = count
        if count > 1:
            key = (*setting.key[:-1], f"{setting.key[-1] if setting.key else ''}#{count}")
            setting = Setting(  # noqa: PLW2901 - replaced by a copy with a distinct key
                setting.scope,
                setting.area,
                setting.kind,
                key,
                setting.title,
                setting.value,
                setting.source,
                setting.context,
            )
        out.append(setting)
    return out


# --- GPO level ------------------------------------------------------------------------


_SDDL_HEAD = re.compile(
    r"(?:O:(?P<owner>S-1(?:-\d+)+|[A-Z]{2}))?(?:G:(?P<group>S-1(?:-\d+)+|[A-Z]{2}))?(?=[DS]:|$)"
)
_MASK = re.compile(r"[0-9]{1,10}")


@dataclass
class _Descriptor:
    """What a GPO's ``SecurityDescriptor`` element held, as far as mishpat can read it."""

    trustees: list[Trustee] | None = None
    sddl: str | None = None
    owner: str | None = None
    owner_name: str = ""
    group: str | None = None
    group_name: str = ""


def _principal(descriptor: ET.Element, local: str) -> tuple[str, str] | None:
    """Return ``(id, name)`` of a child ``Owner`` or ``Group``; ``None`` when there is none.

    The element is found by its local name in any namespace, because mishpat has not seen
    real ``Get-GPOReport`` output that holds one (see docs/limitations.md). An element that
    holds neither a SID nor a name returns ``("", "")``.
    """
    for child in descriptor:
        if _local(child) != local:
            continue
        sid = name = ""
        for part in child:
            if _local(part) == "SID":
                sid = (part.text or "").strip().upper()
            elif _local(part) == "Name":
                name = (part.text or "").strip()
        return sid or name, name
    return None


def _descriptor(
    descriptor: ET.Element | None, base: Source, problems: list[Problem]
) -> _Descriptor:
    """Read the owner, group, SDDL text and permission entries of a GPO."""
    if descriptor is None:
        return _Descriptor()
    found = _Descriptor(trustees=_trustees(descriptor, base, problems))
    sddl = _text(descriptor, "SDDL", SECURITY_TYPES)
    found.sddl = sddl or None
    if sddl:
        head = _SDDL_HEAD.match(sddl)
        if head is None:
            where = Source(base.file, f"{base.detail} SecurityDescriptor/SDDL".strip())
            problems.append(
                Problem(
                    where,
                    "the SDDL text does not start with an owner and group in the form mishpat "
                    "reads, so the owner and group were not compared from it",
                )
            )
        else:
            found.owner = head["owner"].upper() if head["owner"] else None
            found.group = head["group"].upper() if head["group"] else None
    for local, attribute in (("Owner", "owner"), ("Group", "group")):
        principal = _principal(descriptor, local)
        if principal is None:
            continue
        if not principal[0]:
            where = Source(base.file, f"{base.detail} SecurityDescriptor/{local}".strip())
            problems.append(
                Problem(where, f"the {local} element holds no SID or name; it was not compared")
            )
            continue
        setattr(found, attribute, principal[0])
        setattr(found, f"{attribute}_name", principal[1])
    return found


def _mask(entry: ET.Element) -> int | None:
    text = _text(entry, "AccessMask", SECURITY_TYPES)
    return int(text) if text is not None and _MASK.fullmatch(text) else None


def _trustees(
    descriptor: ET.Element | None, base: Source, problems: list[Problem]
) -> list[Trustee] | None:
    if (
        descriptor is None
        or (_text(descriptor, "PermissionsPresent", SECURITY_TYPES) or "") != "true"
    ):
        return None
    permissions = _find(descriptor, "Permissions", SECURITY_TYPES)
    found: list[Trustee] = []
    entries = (
        _all(permissions, "TrusteePermissions", SECURITY_TYPES) if permissions is not None else []
    )
    for number, entry in enumerate(entries, 1):
        trustee = _find(entry, "Trustee", SECURITY_TYPES)
        kind = _find(entry, "Type", SECURITY_TYPES)
        standard = _find(entry, "Standard", SECURITY_TYPES)
        rights = {
            (right.text or "").strip()
            for right in (
                _all(standard, "GPOGroupedAccessEnum", SECURITY_TYPES)
                if standard is not None
                else []
            )
        } - {""}
        sid = _sid_or_name(trustee) if trustee is not None else ""
        mask = _mask(entry)
        if not rights and mask is None:
            # A custom permission is written as an access mask. Without one there is nothing
            # to compare, and silence would read as "this entry grants nothing".
            where = Source(
                base.file, f"{base.detail} SecurityDescriptor/TrusteePermissions[{number}]".strip()
            )
            problems.append(
                Problem(
                    where,
                    f"the permission entry for {sid or 'an unnamed trustee'} has no named "
                    "permission and no access mask that mishpat can read, so it was not compared",
                )
            )
        found.append(
            Trustee(
                sid=sid,
                name=(_text(trustee, "Name", TYPES) if trustee is not None else None) or sid,
                allow=(_text(kind, "PermissionType", SECURITY_TYPES) if kind is not None else None)
                == "Allow",
                rights=tuple(sorted(rights)),
                access_mask=mask,
            )
        )
    return found


def _links(element: ET.Element, base: Source, problems: list[Problem]) -> list[Link] | None:
    """Read a GPO's links; ``None`` when one target is listed twice with different flags."""
    links: list[Link] = []
    for entry in _all(element, "LinksTo", SETTINGS):
        target = _text(entry, "SOMPath", SETTINGS) or _text(entry, "SOMName", SETTINGS) or ""
        links.append(
            Link(
                target=target,
                enabled=_text(entry, "Enabled", SETTINGS) == "true",
                enforced=_text(entry, "NoOverride", SETTINGS) == "true",
            )
        )
    seen: dict[str, Link] = {}
    for link in links:
        other = seen.setdefault(link.target.casefold(), link)
        if (other.enabled, other.enforced) != (link.enabled, link.enforced):
            where = Source(base.file, f"{base.detail} LinksTo[{link.target}]".strip())
            problems.append(
                Problem(
                    where,
                    "this link is listed twice with different settings; links were not compared",
                )
            )
            return None
    return links


def _wmi(element: ET.Element) -> WmiFilter | str | None:
    name = _text(element, "FilterName", SETTINGS)
    if name:
        return WmiFilter(name=name, description=_text(element, "FilterDescription", SETTINGS) or "")
    if _text(element, "FilterDataAvailable", SETTINGS) == "false":
        return "unknown"
    return None


def _versions(
    half: ET.Element | None, name: str, base: Source, problems: list[Problem]
) -> dict[str, int]:
    found: dict[str, int] = {}
    if half is None:
        return found
    for tag, label in (("VersionDirectory", "directory"), ("VersionSysvol", "sysvol")):
        text = _text(half, tag, SETTINGS)
        if text is None:
            continue
        if _NUMBER.fullmatch(text):
            found[f"{name.lower()} {label}"] = int(text)
        else:
            where = Source(base.file, f"{base.detail} {name}/{tag}".strip())
            problems.append(Problem(where, f"{tag} {text!r} is not a number; it was not recorded"))
    return found


def _enabled(half: ET.Element | None) -> bool | None:
    flag = _text(half, "Enabled", SETTINGS) if half is not None else None
    return {"true": True, "false": False}.get(flag or "")


def _conflicts(element: ET.Element, names: tuple[str, ...]) -> list[str]:
    """Return the names, of those that should appear once, found more than once and differing.

    Copies that are the same in every respect are harmless and read as one; copies that
    differ cannot be told apart, so mishpat does not choose one by position.
    """
    out = []
    for local in names:
        copies = _all(element, local, SETTINGS)
        if len({json.dumps(_whole_content(c), ensure_ascii=False) for c in copies}) > 1:
            out.append(local)
    return out


_GPO_SINGLES = (
    "Identifier",
    "Name",
    "SecurityDescriptor",
    "FilterName",
    "FilterDescription",
    "FilterDataAvailable",
    "Computer",
    "User",
)
_HALF_SINGLES = ("Enabled", "VersionDirectory", "VersionSysvol")


def _conflict_problems(base: Source, where: str, names: list[str], what: str) -> list[Problem]:
    return [
        Problem(
            Source(base.file, f"{base.detail} {where}{local}".strip()),
            f"{local} appears more than once with different contents; mishpat did not choose "
            f"one, so {what} was not compared",
        )
        for local in names
    ]


def _halves(
    element: ET.Element, conflicts: list[str], base: Source, problems: list[Problem]
) -> dict[str, ET.Element | None]:
    """Find the Computer and User halves; a half that is contradictory is ``None``.

    A conflicting half's name is added to ``conflicts``, with a problem.
    """
    halves: dict[str, ET.Element | None] = {}
    for name in ("Computer", "User"):
        half = None if name in conflicts else _find(element, name, SETTINGS)
        inner = [] if half is None else _conflicts(half, _HALF_SINGLES)
        problems.extend(_conflict_problems(base, f"{name}/", inner, f"the {name} half"))
        if inner:
            conflicts.append(name)
            half = None
        halves[name] = half
    return halves


def _gpo(element: ET.Element, base: Source, problems: list[Problem]) -> Gpo:
    conflicts = _conflicts(element, _GPO_SINGLES)
    if "Identifier" in conflicts or "Name" in conflicts:
        msg = "it has two different Identifier or Name elements"
        raise _BadGpoError(msg)
    problems.extend(_conflict_problems(base, "", conflicts, "it"))
    identity = _find(element, "Identifier", SETTINGS)
    raw = _text(identity, "Identifier", TYPES) if identity is not None else None
    if not raw:
        msg = "it has no Identifier"
        raise _BadGpoError(msg)
    try:
        guid = _guid(raw)
    except ValueError:
        msg = f"its Identifier {raw[:60]!r} is not a GUID"
        raise _BadGpoError(msg) from None
    name = _text(element, "Name", SETTINGS)
    if not name:
        msg = "it has no Name"
        raise _BadGpoError(msg)
    descriptor = (
        _Descriptor()
        if "SecurityDescriptor" in conflicts
        else _descriptor(_find(element, "SecurityDescriptor", SETTINGS), base, problems)
    )
    gpo = Gpo(
        guid=guid,
        domain=(_text(identity, "Domain", TYPES) if identity is not None else None) or "",
        name=name,
        source=base,
        trustees=descriptor.trustees,
        sddl=descriptor.sddl,
        owner=descriptor.owner,
        owner_name=descriptor.owner_name,
        group=descriptor.group,
        group_name=descriptor.group_name,
        wmi_filter="unknown"
        if {"FilterName", "FilterDescription", "FilterDataAvailable"} & set(conflicts)
        else _wmi(element),
        links=_links(element, base, problems),
        context={
            "created": _text(element, "CreatedTime", SETTINGS) or "",
            "modified": _text(element, "ModifiedTime", SETTINGS) or "",
        },
    )
    gpo.context = {k: v for k, v in gpo.context.items() if v}
    halves = _halves(element, conflicts, base, problems)
    gpo.computer_enabled = _enabled(halves["Computer"])
    gpo.user_enabled = _enabled(halves["User"])
    for scope_name, half in halves.items():
        gpo.versions.update(_versions(half, scope_name, base, problems))
        if half is None:
            # Get-GPOReport always writes both halves; without one, its settings are unknown.
            gpo.context[evidence_key(scope_name)] = "unreadable"
            if scope_name in conflicts:
                continue  # already a problem
            where = Source(base.file, f"{base.detail} {scope_name}".strip())
            problems.append(
                Problem(
                    where, f"the report has no {scope_name} section; its settings were not compared"
                )
            )
            continue
        scope = _Scope(scope_name, base, problems)
        before = len(problems)
        _read_half(scope, half)
        # A setting skipped as malformed is not known to be absent, so a half with any
        # skip is "partial": its one-sided settings are not called added or removed.
        gpo.context[evidence_key(scope_name)] = "read" if len(problems) == before else "partial"
        gpo.settings.extend(scope.settings)
    gpo.settings = _dedupe(gpo.settings)
    return gpo


def read_report(data: bytes, base: Source) -> ReportRead:
    """Read a ``Get-GPOReport`` XML file.

    Args:
        data: The file's bytes.
        base: Where the file is. Every source gets this file and a detail that starts with
            ``base.detail``; GPOs inside ``<GPOS>`` add ``GPO[n]``.

    Returns:
        The GPOs and problems.

    Raises:
        InputError: The bytes are not a Get-GPOReport XML file (not XML, hostile XML, or a
            root other than ``<GPO>`` and ``<GPOS>``).
    """
    prefix = f"{base.file} is not a Get-GPOReport XML file: "
    try:
        root = xmlsafe.parse(data)
    except xmlsafe.XmlError as exc:
        raise InputError(prefix + str(exc)) from None
    uri, local = xmlsafe.split(root.tag)
    result = ReportRead()
    if (uri, local) == (SETTINGS, "GPO"):
        entries = [(root, base)]
    elif (uri, local) == ("", "GPOS"):
        result.wrapped = True
        entries = []
        for number, child in enumerate(root, 1):
            where = Source(base.file, f"{base.detail} GPO[{number}]".strip())
            if xmlsafe.split(child.tag) == (SETTINGS, "GPO"):
                entries.append((child, where))
            else:
                result.problems.append(
                    Problem(
                        where, f"Unexpected element <{_local(child)[:40]}> in <GPOS> was skipped"
                    )
                )
        if not len(root):
            result.problems.append(Problem(base, "The <GPOS> element holds no GPO"))
    else:
        raise InputError(prefix + f"the root element is <{local[:40]}>, not <GPO> or <GPOS>")
    seen: dict[str, Source] = {}
    for element, where in entries:
        try:
            gpo = _gpo(element, where, result.problems)
        except _BadGpoError as exc:
            result.problems.append(Problem(where, f"This GPO was not read: {exc}"))
            continue
        if gpo.guid in seen:
            result.problems.append(
                Problem(where, f"The GPO {gpo.guid} appears twice; the later one was not read")
            )
            continue
        seen[gpo.guid] = where
        result.gpos.append(gpo)
    return result


__all__: list[Any] = ["ReportRead", "canonical", "read_report"]
