# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Synthetic Group Policy inputs for the reader tests.

Everything here is invented: the domain is ``corp.example``, addresses come from RFC 5737,
and GUIDs and SIDs are made up (``S-1-5-21-1000-2000-3000-xxxx``). Nothing is copied from a
real organization. The builders mirror the shapes real tools write, so the readers meet
the same structure (namespace-qualified elements, per-extension ``qN`` prefixes, UTF-16
backup files) without any real data.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from faithful_mishpat.formats import bundle

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

DOMAIN = "corp.example"
DOMAIN_SID = "S-1-5-21-1000-2000-3000"
GUID_A = "11111111-aaaa-4aaa-8aaa-000000000001"
GUID_B = "22222222-bbbb-4bbb-8bbb-000000000002"
GUID_C = "33333333-cccc-4ccc-8ccc-000000000003"
BACKUP_A = "{AAAAAAAA-0000-4000-8000-00000000000A}"
BACKUP_B = "{BBBBBBBB-0000-4000-8000-00000000000B}"
WMI_ID = "44444444-dddd-4ddd-8ddd-000000000004"

SETTINGS = "http://www.microsoft.com/GroupPolicy/Settings"
TYPES = "http://www.microsoft.com/GroupPolicy/Types"
SECURITY_TYPES = "http://www.microsoft.com/GroupPolicy/Types/Security"


def braces(guid: str) -> str:
    """Write a GUID the way Windows does: upper case in braces."""
    return "{" + guid.upper() + "}"


# --- report XML ---------------------------------------------------------------------


def trustee(sid: str, name: str, right: str, *, allow: bool = True) -> str:
    """One ``TrusteePermissions`` entry."""
    kind = "Allow" if allow else "Deny"
    return f"""
      <q2:TrusteePermissions>
        <q2:Trustee><q3:SID>{sid}</q3:SID><q3:Name>{escape(name)}</q3:Name></q2:Trustee>
        <q2:Type xsi:type="q2:PermissionType">
          <q2:PermissionType>{kind}</q2:PermissionType>
        </q2:Type>
        <q2:Inherited>false</q2:Inherited>
        <q2:Standard><q2:GPOGroupedAccessEnum>{escape(right)}</q2:GPOGroupedAccessEnum></q2:Standard>
        <q2:AccessMask>0</q2:AccessMask>
      </q2:TrusteePermissions>"""


DEFAULT_TRUSTEES = trustee(
    f"{DOMAIN_SID}-512", "CORP\\Domain Admins", "Edit, delete, modify security"
) + trustee("S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Apply Group Policy")


def extension(tail: str, body: str, prefix: str = "q1") -> str:
    """Wrap ``body`` (written with ``q1:`` prefixes) in an ``ExtensionData`` for ``tail``.

    ``tail`` is the part of the namespace after ``.../GroupPolicy/Settings/``. The prefix is
    renamed to ``prefix`` so tests can show that the prefix means nothing.
    """
    uri = f"{SETTINGS}/{tail}"
    text = body.replace("<q1:", f"<{prefix}:").replace("</q1:", f"</{prefix}:")
    return (
        f'<ExtensionData><Extension xmlns:{prefix}="{uri}" xsi:type="{prefix}:Test">{text}'
        "</Extension><Name>Test</Name></ExtensionData>"
    )


def gpo_xml(  # noqa: PLR0913 - a GPO has this many independent parts
    guid: str = GUID_A,
    name: str = "Servers baseline",
    *,
    computer: str = "",
    user: str = "",
    links: tuple[tuple[str, str, bool, bool], ...] = (),
    wmi: tuple[str, str] | None = None,
    trustees: str | None = DEFAULT_TRUSTEES,
    computer_enabled: str = "true",
    user_enabled: str = "true",
    versions: tuple[str, str, str, str] = ("3", "3", "1", "1"),
    domain: str = DOMAIN,
    wmi_unavailable: bool = False,
    ident: str | None = None,
) -> str:
    """Build one ``<GPO>`` element as ``Get-GPOReport`` writes it.

    ``links`` are ``(SOMName, SOMPath, enabled, enforced)``. ``computer`` and ``user`` are
    the ``ExtensionData`` blocks (see :func:`extension`).
    """
    descriptor = ""
    if trustees is not None:
        unprefixed = trustees.replace("<q2:", "<").replace("</q2:", "</")
        descriptor = f"""
  <SecurityDescriptor>
    <SDDL xmlns="{SECURITY_TYPES}">O:DAG:DAD:PAI</SDDL>
    <PermissionsPresent xmlns="{SECURITY_TYPES}">true</PermissionsPresent>
    <Permissions xmlns="{SECURITY_TYPES}" xmlns:q3="{TYPES}">
      <InheritsFromParent>false</InheritsFromParent>{unprefixed}
    </Permissions>
  </SecurityDescriptor>"""
    else:
        descriptor = f"""
  <SecurityDescriptor>
    <PermissionsPresent xmlns="{SECURITY_TYPES}">false</PermissionsPresent>
  </SecurityDescriptor>"""
    filt = ""
    if wmi is not None:
        filt = (
            f"\n  <FilterName>{escape(wmi[0])}</FilterName>"
            f"\n  <FilterDescription>{escape(wmi[1])}</FilterDescription>"
        )
    link_xml = "".join(
        f"""
  <LinksTo>
    <SOMName>{escape(som_name)}</SOMName>
    <SOMPath>{escape(som_path)}</SOMPath>
    <Enabled>{str(enabled).lower()}</Enabled>
    <NoOverride>{str(enforced).lower()}</NoOverride>
  </LinksTo>"""
        for som_name, som_path, enabled, enforced in links
    )
    v = versions
    identifier = ident if ident is not None else braces(guid)
    return f"""<GPO xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="{SETTINGS}">
  <Identifier>
    <Identifier xmlns="{TYPES}">{identifier}</Identifier>
    <Domain xmlns="{TYPES}">{domain}</Domain>
  </Identifier>
  <Name>{escape(name)}</Name>
  <IncludeComments>true</IncludeComments>
  <CreatedTime>2026-01-02T03:04:05</CreatedTime>
  <ModifiedTime>2026-02-03T04:05:06</ModifiedTime>
  <ReadTime>2026-03-04T05:06:07.0000000Z</ReadTime>{descriptor}
  <FilterDataAvailable>{"false" if wmi_unavailable else "true"}</FilterDataAvailable>{filt}
  <Computer>
    <VersionDirectory>{v[0]}</VersionDirectory>
    <VersionSysvol>{v[1]}</VersionSysvol>
    <Enabled>{computer_enabled}</Enabled>
    {computer}
  </Computer>
  <User>
    <VersionDirectory>{v[2]}</VersionDirectory>
    <VersionSysvol>{v[3]}</VersionSysvol>
    <Enabled>{user_enabled}</Enabled>
    {user}
  </User>{link_xml}
</GPO>"""


def report_text(*gpos: str, wrapped: bool = False, declaration: str = "utf-16") -> str:
    """Join GPO elements into a report document (``<GPOS>`` when ``wrapped``)."""
    head = f'<?xml version="1.0" encoding="{declaration}"?>\n'
    if wrapped:
        return head + "<GPOS>\n\n" + "\n\n".join(gpos) + "\n</GPOS>"
    return head + gpos[0]


def utf16(text: str) -> bytes:
    """UTF-16LE with a byte order mark, as ``gpreport.xml`` is written."""
    return b"\xff\xfe" + text.encode("utf-16-le")


def report_bytes(*gpos: str, wrapped: bool = False, how: str = "utf16") -> bytes:
    """A report file in one of the encodings seen in practice.

    ``how`` is ``utf16`` (BOM), ``utf16-be``, ``utf8`` (declares utf-16, as ``-All``
    captures do), ``utf8-bom`` or ``utf16-nobom``.
    """
    text = report_text(*gpos, wrapped=wrapped)
    if how == "utf16":
        return utf16(text)
    if how == "utf16-be":
        return b"\xfe\xff" + text.encode("utf-16-be")
    if how == "utf8":
        return text.encode("utf-8")
    if how == "utf8-bom":
        return b"\xef\xbb\xbf" + text.encode("utf-8")
    if how == "utf16-nobom":
        return text.encode("utf-16-le")
    raise ValueError(how)


# --- extension snippets ---------------------------------------------------------------


def policy(name: str, state: str = "Enabled", category: str = "System/Test", body: str = "") -> str:
    """An Administrative Templates ``Policy`` (written with ``q1:`` for the Registry namespace)."""
    return f"""<q1:Policy><q1:Name>{escape(name)}</q1:Name><q1:State>{state}</q1:State>
<q1:Explain>Explains {escape(name)}.</q1:Explain><q1:Supported>At least Windows Vista</q1:Supported>
<q1:Category>{escape(category)}</q1:Category>{body}</q1:Policy>"""


def registry_ext(*items: str, prefix: str = "q1") -> str:
    """An extension block in the Registry namespace."""
    return extension("Registry", "".join(items), prefix)


def security_ext(*items: str, prefix: str = "q1") -> str:
    """An extension block in the Security namespace."""
    return extension("Security", "".join(items), prefix)


def member(sid: str, name: str) -> str:
    """A ``Member`` of a user right, written for the Security namespace."""
    return (
        f'<q1:Member><q3:SID xmlns:q3="{TYPES}">{sid}</q3:SID>'
        f'<q3:Name xmlns:q3="{TYPES}">{escape(name)}</q3:Name></q1:Member>'
    )


def user_right(name: str, *members: str) -> str:
    """A ``UserRightsAssignment``."""
    joined = "".join(members)
    return f"<q1:UserRightsAssignment><q1:Name>{name}</q1:Name>{joined}</q1:UserRightsAssignment>"


# --- Registry.pol ---------------------------------------------------------------------

Entry = tuple[str, str, int, bytes]


def sz(text: str) -> bytes:
    """``REG_SZ`` data."""
    return (text + "\0").encode("utf-16-le")


def multi_sz(*parts: str) -> bytes:
    """``REG_MULTI_SZ`` data."""
    return ("\0".join(parts) + "\0\0").encode("utf-16-le")


def dword(number: int) -> bytes:
    """``REG_DWORD`` data."""
    return struct.pack("<I", number)


def qword(number: int) -> bytes:
    """``REG_QWORD`` data."""
    return struct.pack("<Q", number)


def registry_pol(entries: list[Entry], *, signature: bytes = b"PReg", version: int = 1) -> bytes:
    """Build a ``Registry.pol`` file."""
    out = bytearray(signature + struct.pack("<I", version))
    for key, name, kind, data in entries:
        out += "[".encode("utf-16-le") + (key + "\0").encode("utf-16-le") + ";".encode("utf-16-le")
        out += (name + "\0").encode("utf-16-le") + ";".encode("utf-16-le")
        out += struct.pack("<I", kind) + ";".encode("utf-16-le")
        out += (
            struct.pack("<I", len(data)) + ";".encode("utf-16-le") + data + "]".encode("utf-16-le")
        )
    return bytes(out)


# --- Backup-GPO folders ---------------------------------------------------------------


def backup_files(  # noqa: PLR0913 - a backup has this many independent parts
    guid: str = GUID_A,
    name: str = "Servers baseline",
    *,
    backup_id: str = BACKUP_A,
    prefix: str = "",
    report: bytes | None = None,
    machine_pol: bytes | None = None,
    user_pol: bytes | None = None,
    options: int = 0,
    wmi: tuple[str, str] | None = None,
    machine_version: int = 4325442,
    user_version: int = 65537,
    extra: dict[str, bytes] | None = None,
    core: bool = True,
    names: tuple[str, str, str, str] = (
        "bkupInfo.xml",
        "Backup.xml",
        "gpreport.xml",
        "registry.pol",
    ),
    sysvol: tuple[str, str, str, str] = ("DomainSysvol", "GPO", "Machine", "User"),
) -> dict[str, bytes]:
    """The files of one ``Backup-GPO`` folder, by path under ``prefix``.

    ``report`` is the bytes of ``gpreport.xml``; ``None`` leaves it out. ``names`` lets a
    test change the case of the file names.
    """
    files: dict[str, bytes] = {}
    info_name, core_name, report_name, pol_name = names
    prefix = prefix.rstrip("/") + "/" if prefix else ""
    files[f"{prefix}{info_name}"] = (
        '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">'
        f"<GPOGuid><![CDATA[{braces(guid)}]]></GPOGuid><GPODomain><![CDATA[{DOMAIN}]]></GPODomain>"
        f"<BackupTime><![CDATA[2026-03-04T05:06:07]]></BackupTime><ID><![CDATA[{backup_id}]]></ID>"
        f"<Comment><![CDATA[before the change]]></Comment>"
        f"<GPODisplayName><![CDATA[{name}]]></GPODisplayName></BackupInst>"
    ).encode("ascii")
    if core:
        filt = "<WMIFilter/>"
        if wmi is not None:
            filt = (
                f'<WMIFilter><![CDATA[MSFT_SomFilter.ID="{braces(WMI_ID)}",Domain="{DOMAIN}"]]>'
                f"</WMIFilter><WMIFilterName><![CDATA[{wmi[0]}]]></WMIFilterName>"
            )
        files[f"{prefix}{core_name}"] = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<GroupPolicyBackupScheme xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">'
            "<GroupPolicyObject><SecurityGroups/><FilePaths/><GroupPolicyCoreSettings>"
            f"<ID><![CDATA[{braces(guid)}]]></ID><Domain><![CDATA[{DOMAIN}]]></Domain>"
            f"<DisplayName><![CDATA[{name}]]></DisplayName><Options><![CDATA[{options}]]></Options>"
            f"<UserVersionNumber><![CDATA[{user_version}]]></UserVersionNumber>"
            f"<MachineVersionNumber><![CDATA[{machine_version}]]></MachineVersionNumber>"
            f"{filt}</GroupPolicyCoreSettings></GroupPolicyObject></GroupPolicyBackupScheme>"
        ).encode("ascii")
    if report is not None:
        files[f"{prefix}{report_name}"] = report
    if machine_pol is not None:
        files[f"{prefix}{sysvol[0]}/{sysvol[1]}/{sysvol[2]}/{pol_name}"] = machine_pol
    if user_pol is not None:
        files[f"{prefix}{sysvol[0]}/{sysvol[1]}/{sysvol[3]}/{pol_name}"] = user_pol
    files.update({f"{prefix}{path}": data for path, data in (extra or {}).items()})
    return files


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    """Write ``files`` under ``root``, making folders as needed."""
    for path, data in files.items():
        target = root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


# --- export bundles -------------------------------------------------------------------


def header(scope: object = "all", domain: str = DOMAIN) -> dict[str, object]:
    """A valid bundle header."""
    return {
        "mishpat_export": 1,
        "collector": {"name": "Export-MishpatGpo.ps1", "version": "0.1.0"},
        "domain": domain,
        "collected_at": "2026-03-04T05:06:07Z",
        "scope": scope,
    }


def gplink(*entries: tuple[str, int]) -> str:
    """A raw ``gPLink`` value; ``entries`` are ``(guid, options)`` in the order written."""
    return "".join(
        f"[LDAP://cn={braces(guid)},cn=policies,cn=system,DC=corp,DC=example;{options}]"
        for guid, options in entries
    )


def structure(
    scopes: Sequence[Mapping[str, object]] | None = None,
    filters: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """A ``structure`` object."""
    return {"scopes": scopes or [], "wmi_filters": filters or []}


def scope_entry(
    path: str, kind: str = "ou", link: str = "", *, blocked: bool = False
) -> dict[str, object]:
    """One entry of ``structure.scopes``."""
    return {"path": path, "kind": kind, "blocked": blocked, "gplink": link}


def bundle_bytes(
    files: dict[str, bytes],
    *,
    scope: object = "all",
    struct_: dict[str, object] | None = None,
) -> bytes:
    """A complete, valid bundle."""
    return bundle.encode(header(scope), files, struct_ or structure())
