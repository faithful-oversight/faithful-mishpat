# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A synthetic before and after of one domain, for trying mishpat without one.

Everything here is invented: the domain ``corp.example``, its GPOs, groups and SIDs
(``S-1-5-21-1000-2000-3000-*``), and every GUID. :func:`build` returns two export bundles
written the way ``Export-MishpatGpo.ps1`` writes them (see
:mod:`faithful_mishpat.formats.bundle`): one ``Backup-GPO`` folder per GPO, then the
domain's scopes of management and WMI filters.

The story is one change window on six GPOs. It is built so that the report shows every
category of difference at least once:

* ``Default Domain Policy`` does not change.
* ``Baseline - Servers`` gets a changed drop-down in an Administrative Templates policy,
  one policy added and one removed, the matching ``Registry.pol`` changes (a value
  changed, one added, one removed, and a ``**del.`` directive added), Advanced Audit
  changes, a new WMI filter query, and a link to the ``Web`` OU.
* ``Workstation Baseline`` is renamed ``Workstation Hardening``. Its Security settings
  change (an account policy, security options, one user right whose members change and
  one whose members are only listed in another order), a group is added to security
  filtering, and its link becomes enforced.
* ``Staff Desktop Settings`` has its computer half disabled, loses a delegation entry,
  and has its link disabled. Its link also moves from second to first on the
  ``Workstations`` OU, ahead of ``Workstation Hardening``.
* ``Legacy Kiosk Lockdown`` is deleted and ``Edge Browser Policy`` is created.
* The ``Web`` OU starts to block inheritance.

Every number and time is fixed, so :func:`build` returns the same bytes on every run. The
Group Policy files are built here by hand, because the package must not depend on its
tests.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from xml.sax.saxutils import escape

from faithful_mishpat.collect import script
from faithful_mishpat.formats import bundle

NAMES = ("corp-before.jsonl", "corp-after.jsonl")
"""The files :func:`build` returns, before first."""

DOMAIN = "corp.example"
DOMAIN_DN = "DC=corp,DC=example"
DOMAIN_SID = "S-1-5-21-1000-2000-3000"

DEFAULT_DOMAIN = "4e0b7d1a-93c2-4f68-a1d5-2c7e9b3f6a10"
SERVERS = "9c3e51b7-2d84-4a6f-8e10-b5f7a2c4d963"
WORKSTATIONS = "c71a0e5f-68b3-4d29-9a47-3e8d1f5b0c72"
STAFF = "2f6d8b94-1e57-4c03-b8a6-d9c0e7a31f45"
KIOSK = "e5b94a20-7c16-43d8-85f1-0a6c3d2e9b87"
EDGE = "73d0c6e8-b2a9-4f15-96c4-8e1b5a7d3f29"
"""The GUIDs of the six GPOs (default domain policy, servers, workstations, staff, kiosk, edge)."""

_SETTINGS = "http://www.microsoft.com/GroupPolicy/Settings"
_TYPES = "http://www.microsoft.com/GroupPolicy/Types"
_SECURITY_TYPES = "http://www.microsoft.com/GroupPolicy/Types/Security"
_CONTROLLER = "DC01.corp.example"
_DOMAIN_GUID = "6b2f9c40-35d1-4e7a-8c0b-1f4d7a92e350"
_ENABLED, _DISABLED, _ENFORCED = 0, 1, 2  # gPLink option bits: 1 disables, 2 enforces

Entry = tuple[str, str, int, bytes]
"""A ``Registry.pol`` entry: key, value name, type number and data."""


# --- Registry.pol ---------------------------------------------------------------------


def _registry_pol(entries: tuple[Entry, ...]) -> bytes:
    """Build a ``Registry.pol`` file ([MS-GPREG] "PReg", version 1)."""

    def text(value: str) -> bytes:
        return value.encode("utf-16-le")

    out = bytearray(b"PReg" + struct.pack("<I", 1))
    for key, name, kind, data in entries:
        out += text("[") + text(key + "\0") + text(";") + text(name + "\0") + text(";")
        out += struct.pack("<I", kind) + text(";") + struct.pack("<I", len(data)) + text(";")
        out += data + text("]")
    return bytes(out)


def _dword(key: str, name: str, number: int) -> Entry:
    return (key, name, 4, struct.pack("<I", number))


def _delete(key: str, name: str) -> Entry:
    """The ``**del.`` directive: clients delete ``name``. Its data is one space."""
    return (key, f"**del.{name}", 1, " \0".encode("utf-16-le"))


# --- Report XML pieces -----------------------------------------------------------------


@dataclass(frozen=True)
class _Extension:
    """One ``ExtensionData`` block; ``body`` is written with ``q:`` for the extension prefix."""

    tail: str
    kind: str
    title: str
    body: str


def _policy(name: str, category: str, explain: str, elements: str = "") -> str:
    return (
        f"<q:Policy><q:Name>{escape(name)}</q:Name><q:State>Enabled</q:State>"
        f"<q:Explain>{escape(explain)}</q:Explain>"
        "<q:Supported>At least Windows Server 2016</q:Supported>"
        f"<q:Category>{escape(category)}</q:Category>{elements}</q:Policy>"
    )


def _dropdown(name: str, choice: str) -> str:
    return (
        f"<q:DropDownList><q:Name>{escape(name)}</q:Name><q:State>Enabled</q:State>"
        f"<q:Value><q:Name>{escape(choice)}</q:Name></q:Value></q:DropDownList>"
    )


def _numeric(name: str, number: int) -> str:
    return (
        f"<q:Numeric><q:Name>{escape(name)}</q:Name><q:State>Enabled</q:State>"
        f"<q:Value>{number}</q:Value></q:Numeric>"
    )


def _checkbox(name: str, state: str) -> str:
    return f"<q:CheckBox><q:Name>{escape(name)}</q:Name><q:State>{state}</q:State></q:CheckBox>"


def _number_account(name: str, kind: str, number: int) -> str:
    return (
        f"<q:Account><q:Name>{name}</q:Name><q:SettingNumber>{number}</q:SettingNumber>"
        f"<q:Type>{kind}</q:Type></q:Account>"
    )


def _flag_account(name: str, kind: str, *, on: bool) -> str:
    return (
        f"<q:Account><q:Name>{name}</q:Name><q:SettingBoolean>{str(on).lower()}</q:SettingBoolean>"
        f"<q:Type>{kind}</q:Type></q:Account>"
    )


def _option(key: str, title: str, number: int, shown: str) -> str:
    return (
        f"<q:SecurityOptions><q:KeyName>{escape(key)}</q:KeyName>"
        f"<q:SettingNumber>{number}</q:SettingNumber><q:Display>"
        f"<q:Name>{escape(title)}</q:Name><q:Units/><q:DisplayString>{escape(shown)}"
        "</q:DisplayString></q:Display></q:SecurityOptions>"
    )


def _right(name: str, *members: tuple[str, str]) -> str:
    listed = "".join(
        f'<q:Member><SID xmlns="{_TYPES}">{sid}</SID><Name xmlns="{_TYPES}">{escape(who)}</Name>'
        "</q:Member>"
        for sid, who in members
    )
    return f"<q:UserRightsAssignment><q:Name>{name}</q:Name>{listed}</q:UserRightsAssignment>"


def _audit(guid: str, name: str, value: int) -> str:
    return (
        "<q:AuditSetting><q:PolicyTarget>System</q:PolicyTarget>"
        f"<q:SubcategoryName>{escape(name)}</q:SubcategoryName>"
        f"<q:SubcategoryGuid>{{{guid}}}</q:SubcategoryGuid>"
        f"<q:SettingValue>{value}</q:SettingValue></q:AuditSetting>"
    )


def _registry(*items: str) -> _Extension:
    return _Extension("Registry", "RegistrySettings", "Registry", "".join(items))


def _security(*items: str) -> _Extension:
    return _Extension("Security", "SecuritySettings", "Security", "".join(items))


def _auditing(*items: str) -> _Extension:
    return _Extension("Auditing", "AuditSettings", "Advanced Audit Configuration", "".join(items))


# --- The domain ------------------------------------------------------------------------


@dataclass(frozen=True)
class _Trustee:
    sid: str
    name: str
    right: str


_ADMINS = _Trustee(f"{DOMAIN_SID}-512", "CORP\\Domain Admins", "Edit, delete, modify security")
_ENTERPRISE = _Trustee(
    f"{DOMAIN_SID}-519", "CORP\\Enterprise Admins", "Edit, delete, modify security"
)
_CONTROLLERS = _Trustee("S-1-5-9", "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS", "Read")
_SYSTEM = _Trustee("S-1-5-18", "NT AUTHORITY\\SYSTEM", "Edit, delete, modify security")
_EVERYONE = _Trustee("S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Apply Group Policy")
_PILOT = _Trustee(f"{DOMAIN_SID}-1301", "CORP\\Pilot Workstations", "Apply Group Policy")
_HELPDESK = _Trustee(f"{DOMAIN_SID}-1204", "CORP\\Helpdesk Operators", "Read")
_DEFAULT = (_ADMINS, _ENTERPRISE, _CONTROLLERS, _SYSTEM, _EVERYONE)


@dataclass(frozen=True)
class _Filter:
    identifier: str
    name: str
    description: str
    query: str

    @property
    def parm2(self) -> str:
        """The directory's ``msWMI-Parm2``: language, namespace and query, with a length."""
        return f"1;3;10;{len(self.query)};WQL;root\\CIMv2;{self.query};"


@dataclass(frozen=True)
class _Gpo:
    guid: str
    name: str
    modified: str
    versions: tuple[int, int]  # computer, user
    computer: tuple[_Extension, ...] = ()
    user: tuple[_Extension, ...] = ()
    machine_pol: tuple[Entry, ...] = ()
    user_pol: tuple[Entry, ...] = ()
    trustees: tuple[_Trustee, ...] = _DEFAULT
    wmi: str = ""
    computer_enabled: bool = True
    created: str = "2026-01-12T08:30:00"


@dataclass(frozen=True)
class _Scope:
    """A scope of management. ``links`` are ``(GPO GUID, gPLink options)``, link order 1 first."""

    dn: str
    kind: str
    name: str
    blocked: bool = False
    links: tuple[tuple[str, int], ...] = ()

    @property
    def path(self) -> str:
        return bundle.som_path(self.dn, self.kind)


@dataclass(frozen=True)
class _Export:
    collected_at: str
    gpos: tuple[_Gpo, ...]
    scopes: tuple[_Scope, ...]
    filters: tuple[_Filter, ...]
    backups: dict[str, str]


_SERVER_FILTER = "{B6F2A1D4-5C37-4E80-9D12-7A4E3C8B0F56}"
_CLIENT_FILTER = "{1D9E4B7A-8F25-4C63-A0B1-6E2D5F379C48}"
_WUAU = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
_WER = "Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting"
_AUTOPLAY = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
_LOGGING = "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
_LSA = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa"
_SYSTEM_POLICY = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
_POLICIES_SYSTEM = "MACHINE\\" + _SYSTEM_POLICY
_ADMINISTRATORS = ("S-1-5-32-544", "BUILTIN\\Administrators")
_USERS = ("S-1-5-32-545", "BUILTIN\\Users")
_BACKUP_OPERATORS = ("S-1-5-32-551", "BUILTIN\\Backup Operators")
_GUESTS = ("S-1-5-32-546", "BUILTIN\\Guests")
_LOCAL_ACCOUNT = ("S-1-5-113", "NT AUTHORITY\\Local account")


def _default_domain() -> _Gpo:
    accounts = _security(
        _number_account("MinimumPasswordAge", "Password", 1),
        _number_account("MaximumPasswordAge", "Password", 90),
        _number_account("MinimumPasswordLength", "Password", 12),
        _number_account("PasswordHistorySize", "Password", 24),
        _flag_account("PasswordComplexity", "Password", on=True),
    )
    return _Gpo(DEFAULT_DOMAIN, "Default Domain Policy", "2026-03-18T09:12:44", (7, 0), (accounts,))


def _servers(*, after: bool) -> _Gpo:
    choice = "4 - Auto download and schedule the install"
    if not after:
        choice = "3 - Auto download and notify for install"
    policies = [
        _policy(
            "Configure Automatic Updates",
            "Windows Components/Windows Update",
            "Sets how this computer downloads and installs updates.",
            _dropdown("Configure automatic updating:", choice)
            + _dropdown("Scheduled install day:", "0 - Every day")
            + _numeric("Scheduled install time:", 3),
        ),
        _policy(
            "Turn on PowerShell Script Block Logging",
            "Windows Components/Windows PowerShell",
            "Writes the text of scripts that run to the event log.",
            _checkbox("Log script block invocation start / stop events:", "Disabled"),
        ),
    ]
    pol: list[Entry] = [
        _dword(_WUAU, "NoAutoUpdate", 0),
        _dword(_WUAU, "AUOptions", 4 if after else 3),
        _dword(_WUAU, "ScheduledInstallDay", 0),
        _dword(_WUAU, "ScheduledInstallTime", 3),
        _dword(_LOGGING, "EnableScriptBlockLogging", 1),
    ]
    audits = [
        _audit("0cce923f-69ae-11d9-bed3-505054503030", "Audit Credential Validation", 3),
        _audit("0cce9215-69ae-11d9-bed3-505054503030", "Audit Logon", 3 if after else 1),
    ]
    if after:
        policies.append(
            _policy(
                "Disable Windows Error Reporting",
                "Windows Components/Windows Error Reporting",
                "Stops this computer from sending error reports.",
            )
        )
        pol += [_dword(_WER, "Disabled", 1), _delete(_WUAU, "UseWUServer")]
        audits.append(_audit("0cce922b-69ae-11d9-bed3-505054503030", "Audit Process Creation", 1))
    else:
        policies.append(
            _policy(
                "Turn off Autoplay",
                "Windows Components/AutoPlay Policies",
                "Stops removable media from starting programs.",
                _dropdown("Turn off Autoplay on:", "All drives"),
            )
        )
        pol.append(_dword(_AUTOPLAY, "NoDriveTypeAutoRun", 255))
        audits.append(_audit("0cce9224-69ae-11d9-bed3-505054503030", "Audit File Share", 3))
    return _Gpo(
        SERVERS,
        "Baseline - Servers",
        "2026-11-03T16:41:09" if after else "2026-08-21T10:05:33",
        (15, 0) if after else (12, 0),
        (_registry(*policies), _auditing(*audits)),
        machine_pol=tuple(pol),
        wmi=_SERVER_FILTER,
    )


def _workstations(*, after: bool) -> _Gpo:
    accounts = [_number_account("LockoutBadCount", "Account Lockout", 5 if after else 10)]
    options = [
        _option(
            f"{_LSA}\\LmCompatibilityLevel",
            "Network security: LAN Manager authentication level",
            5 if after else 3,
            "Send NTLMv2 response only. Refuse LM & NTLM" if after else "Send NTLMv2 response only",
        ),
        _option(
            f"{_LSA}\\RestrictAnonymousSAM",
            "Network access: Do not allow anonymous enumeration of SAM accounts",
            1,
            "Enabled",
        ),
    ]
    if after:
        options.append(
            _option(
                f"{_POLICIES_SYSTEM}\\InactivityTimeoutSecs",
                "Interactive logon: Machine inactivity limit",
                900,
                "900 seconds",
            )
        )
    else:
        options.append(
            _option(
                f"{_LSA}\\RestrictAnonymous",
                "Network access: Restrict anonymous access",
                1,
                "Enabled",
            )
        )
    deny = (_GUESTS, _LOCAL_ACCOUNT) if after else (_GUESTS,)
    # Same three members; only the order they are listed in changes.
    network = (_BACKUP_OPERATORS, _ADMINISTRATORS, _USERS)
    if not after:
        network = (_ADMINISTRATORS, _USERS, _BACKUP_OPERATORS)
    rights = (
        _right("SeDenyNetworkLogonRight", *deny),
        _right("SeNetworkLogonRight", *network),
    )
    trustees = (*_DEFAULT, _PILOT) if after else _DEFAULT
    return _Gpo(
        WORKSTATIONS,
        "Workstation Hardening" if after else "Workstation Baseline",
        "2026-11-04T08:17:52" if after else "2026-09-02T13:48:20",
        (9, 0) if after else (8, 0),
        (_security(*accounts, *options, *rights),),
        trustees=trustees,
        wmi=_CLIENT_FILTER,
    )


def _staff(*, after: bool) -> _Gpo:
    policies = (
        _policy(
            "Prevent access to the command prompt",
            "System",
            "Stops people from running the command prompt.",
            _checkbox("Disable the command prompt script processing also?", "Disabled"),
        ),
        _policy(
            "Remove Run menu from Start Menu",
            "Start Menu and Taskbar",
            "Removes the Run command from the Start menu.",
        ),
    )
    pol = (
        _dword("Software\\Policies\\Microsoft\\Windows\\System", "DisableCMD", 1),
        _dword(_AUTOPLAY, "NoRun", 1),
    )
    return _Gpo(
        STAFF,
        "Staff Desktop Settings",
        "2026-11-04T08:20:15" if after else "2026-07-14T15:22:01",
        (4, 5) if after else (3, 5),
        user=(_registry(*policies),),
        user_pol=pol,
        trustees=_DEFAULT if after else (*_DEFAULT, _HELPDESK),
        computer_enabled=not after,
    )


def _kiosk() -> _Gpo:
    policy = _policy(
        "Remove Task Manager",
        "System/Ctrl+Alt+Del Options",
        "Stops people from starting Task Manager.",
    )
    return _Gpo(
        KIOSK,
        "Legacy Kiosk Lockdown",
        "2026-02-09T11:30:48",
        (0, 4),
        user=(_registry(policy),),
        user_pol=(_dword(_SYSTEM_POLICY, "DisableTaskMgr", 1),),
    )


def _edge() -> _Gpo:
    policy = _policy(
        "Configure Microsoft Defender SmartScreen",
        "Microsoft Edge/SmartScreen settings",
        "Turns SmartScreen on for the browser.",
    )
    return _Gpo(
        EDGE,
        "Edge Browser Policy",
        "2026-11-04T09:02:37",
        (2, 0),
        (_registry(policy),),
        machine_pol=(_dword("Software\\Policies\\Microsoft\\Edge", "SmartScreenEnabled", 1),),
        created="2026-11-04T08:55:10",
    )


def _filters(*, after: bool) -> tuple[_Filter, ...]:
    servers = 'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%" AND ProductType = "3"'
    if after:
        servers = (
            'SELECT * FROM Win32_OperatingSystem WHERE BuildNumber >= "20348" AND ProductType = "3"'
        )
    return (
        _Filter(
            _CLIENT_FILTER,
            "Windows clients",
            "Windows 10 and Windows 11 computers",
            'SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%" AND ProductType = "1"',
        ),
        _Filter(_SERVER_FILTER, "Member servers", "Windows Server member servers", servers),
    )


def _scopes(*, after: bool) -> tuple[_Scope, ...]:
    web_links = ((SERVERS, _ENABLED),) if after else ()
    if after:
        workstations = ((STAFF, _DISABLED), (WORKSTATIONS, _ENFORCED), (EDGE, _ENABLED))
    else:
        workstations = ((WORKSTATIONS, _ENABLED), (STAFF, _ENABLED), (KIOSK, _ENABLED))
    return (
        _Scope(DOMAIN_DN, "domain", DOMAIN, links=((DEFAULT_DOMAIN, _ENABLED),)),
        _Scope(f"OU=Servers,{DOMAIN_DN}", "ou", "Servers", links=((SERVERS, _ENABLED),)),
        _Scope(f"OU=Web,OU=Servers,{DOMAIN_DN}", "ou", "Web", blocked=after, links=web_links),
        _Scope(f"OU=Workstations,{DOMAIN_DN}", "ou", "Workstations", links=workstations),
        _Scope(
            f"CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{DOMAIN_DN}",
            "site",
            "Default-First-Site-Name",
        ),
    )


def _before() -> _Export:
    gpos = (
        _default_domain(),
        _servers(after=False),
        _workstations(after=False),
        _staff(after=False),
        _kiosk(),
    )
    backups = {
        DEFAULT_DOMAIN: "a3f1c9d2-5b7e-4a08-9c64-e12d8f0b7a35",
        SERVERS: "0d84b6e1-c2a7-4f39-b5d0-7e9a1c3f8b26",
        WORKSTATIONS: "f92e7a05-3d18-4b6c-8a41-c5b0e6d9273f",
        STAFF: "58c0d3b7-e4a1-4296-b7f8-2a9e5d1c6403",
        KIOSK: "1b7f4e90-a6d3-4c58-9e02-d8c3b5f7a164",
    }
    return _Export(
        "2026-10-05T14:30:00Z", gpos, _scopes(after=False), _filters(after=False), backups
    )


def _after() -> _Export:
    gpos = (
        _default_domain(),
        _servers(after=True),
        _workstations(after=True),
        _staff(after=True),
        _edge(),
    )
    backups = {
        DEFAULT_DOMAIN: "c60a2f8e-91b4-4d73-a5e6-3f7d0b9c1e82",
        SERVERS: "7e3d95a1-0f6c-48b2-8d17-a4c2e9b60f53",
        WORKSTATIONS: "2a8c1d64-b7e0-4f95-9a3b-6d5e8c0f1b47",
        STAFF: "d41b7e03-6a92-4c8f-b150-9e3a2d7c5f08",
        EDGE: "9f05e6c2-d3a8-4b71-8e24-1c7b4a0d6e93",
    }
    return _Export("2026-11-09T09:15:00Z", gpos, _scopes(after=True), _filters(after=True), backups)


# --- Writing the files -----------------------------------------------------------------


def _extensions(blocks: tuple[_Extension, ...], first: int) -> str:
    """Write ``ExtensionData`` blocks, numbering their prefixes from ``first`` as Windows does."""
    out = []
    for number, block in enumerate(blocks, first):
        prefix = f"q{number}"
        body = block.body.replace("<q:", f"<{prefix}:").replace("</q:", f"</{prefix}:")
        out.append(
            f'<ExtensionData><Extension xmlns:{prefix}="{_SETTINGS}/{block.tail}" '
            f'xsi:type="{prefix}:{block.kind}">{body}</Extension><Name>{escape(block.title)}</Name>'
            "</ExtensionData>"
        )
    return "".join(out)


def _trustee_xml(trustee: _Trustee) -> str:
    return (
        f'<TrusteePermissions><Trustee><SID xmlns="{_TYPES}">{trustee.sid}</SID>'
        f'<Name xmlns="{_TYPES}">{escape(trustee.name)}</Name></Trustee>'
        '<Type xsi:type="PermissionType"><PermissionType>Allow</PermissionType></Type>'
        "<Inherited>false</Inherited><Standard>"
        f"<GPOGroupedAccessEnum>{trustee.right}</GPOGroupedAccessEnum></Standard>"
        "<AccessMask>0</AccessMask></TrusteePermissions>"
    )


def _links_xml(gpo: _Gpo, side: _Export) -> str:
    out = []
    for scope in side.scopes:
        for guid, options in scope.links:
            if guid != gpo.guid:
                continue
            out.append(
                f"<LinksTo><SOMName>{escape(scope.name)}</SOMName><SOMPath>{escape(scope.path)}"
                f"</SOMPath><Enabled>{str(not options & _DISABLED).lower()}</Enabled>"
                f"<NoOverride>{str(bool(options & _ENFORCED)).lower()}</NoOverride></LinksTo>"
            )
    return "".join(out)


def _filter_xml(gpo: _Gpo, side: _Export) -> str:
    chosen = next((f for f in side.filters if f.identifier == gpo.wmi), None)
    if chosen is None:
        return "<FilterDataAvailable>true</FilterDataAvailable>"
    return (
        "<FilterDataAvailable>true</FilterDataAvailable>"
        f"<FilterName>{escape(chosen.name)}</FilterName>"
        f"<FilterDescription>{escape(chosen.description)}</FilterDescription>"
    )


def _report(gpo: _Gpo, side: _Export) -> bytes:
    """``gpreport.xml`` as ``Get-GPOReport`` writes it: UTF-16LE with a byte order mark."""
    name = escape(gpo.name)
    read_at = side.collected_at.removesuffix("Z") + ".0000000Z"
    first = len(gpo.computer) + 1
    text = (
        '<?xml version="1.0" encoding="utf-16"?>\n'
        '<GPO xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="{_SETTINGS}">'
        f'<Identifier><Identifier xmlns="{_TYPES}">{{{gpo.guid}}}</Identifier>'
        f'<Domain xmlns="{_TYPES}">{DOMAIN}</Domain></Identifier>'
        f"<Name>{name}</Name><IncludeComments>true</IncludeComments>"
        f"<CreatedTime>{gpo.created}</CreatedTime><ModifiedTime>{gpo.modified}</ModifiedTime>"
        f"<ReadTime>{read_at}</ReadTime>"
        "<SecurityDescriptor>"
        f'<SDDL xmlns="{_SECURITY_TYPES}">O:DAG:DAD:PAI</SDDL>'
        f'<PermissionsPresent xmlns="{_SECURITY_TYPES}">true</PermissionsPresent>'
        f'<Permissions xmlns="{_SECURITY_TYPES}"><InheritsFromParent>false</InheritsFromParent>'
        f"{''.join(_trustee_xml(t) for t in gpo.trustees)}</Permissions></SecurityDescriptor>"
        f"{_filter_xml(gpo, side)}"
        f"<Computer><VersionDirectory>{gpo.versions[0]}</VersionDirectory>"
        f"<VersionSysvol>{gpo.versions[0]}</VersionSysvol>"
        f"<Enabled>{str(gpo.computer_enabled).lower()}</Enabled>{_extensions(gpo.computer, 1)}"
        "</Computer>"
        f"<User><VersionDirectory>{gpo.versions[1]}</VersionDirectory>"
        f"<VersionSysvol>{gpo.versions[1]}</VersionSysvol><Enabled>true</Enabled>"
        f"{_extensions(gpo.user, first)}</User>"
        f"{_links_xml(gpo, side)}</GPO>"
    )
    return b"\xff\xfe" + text.encode("utf-16-le")


def _backup(gpo: _Gpo, side: _Export, backup_id: str) -> dict[str, bytes]:
    """The files of one ``Backup-GPO`` folder, by path inside it."""
    guid, taken = f"{{{gpo.guid.upper()}}}", side.collected_at.removesuffix("Z")
    info = (
        '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">'
        f"<GPOGuid><![CDATA[{guid}]]></GPOGuid><GPODomain><![CDATA[{DOMAIN}]]></GPODomain>"
        f"<GPODomainGuid><![CDATA[{{{_DOMAIN_GUID}}}]]></GPODomainGuid>"
        f"<GPODomainController><![CDATA[{_CONTROLLER}]]></GPODomainController>"
        f"<BackupTime><![CDATA[{taken}]]></BackupTime>"
        f"<ID><![CDATA[{{{backup_id.upper()}}}]]></ID><Comment><![CDATA[]]></Comment>"
        f"<GPODisplayName><![CDATA[{gpo.name}]]></GPODisplayName></BackupInst>"
    )
    chosen = next((f for f in side.filters if f.identifier == gpo.wmi), None)
    wmi = "<WMIFilter/>"
    if chosen is not None:
        wmi = (
            f'<WMIFilter><![CDATA[MSFT_SomFilter.ID="{chosen.identifier}",Domain="{DOMAIN}"]]>'
            f"</WMIFilter><WMIFilterName><![CDATA[{chosen.name}]]></WMIFilterName>"
        )
    machine, user = gpo.versions
    options = 0 if gpo.computer_enabled else 2  # Options: 1 turns the user half off, 2 the computer
    core = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" '
        'xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" '
        'xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations">'
        "<GroupPolicyObject><SecurityGroups/><FilePaths/><GroupPolicyCoreSettings>"
        f"<ID><![CDATA[{guid}]]></ID><Domain><![CDATA[{DOMAIN}]]></Domain>"
        f"<DisplayName><![CDATA[{gpo.name}]]></DisplayName>"
        f"<Options><![CDATA[{options}]]></Options>"
        f"<UserVersionNumber><![CDATA[{user << 16 | user}]]></UserVersionNumber>"
        f"<MachineVersionNumber><![CDATA[{machine << 16 | machine}]]></MachineVersionNumber>"
        f"{wmi}</GroupPolicyCoreSettings></GroupPolicyObject>"
        "</GroupPolicyBackupScheme>"
    )
    files = {
        "bkupInfo.xml": info.encode("ascii"),
        "Backup.xml": core.encode("ascii"),
        "gpreport.xml": _report(gpo, side),
    }
    if gpo.machine_pol:
        files["DomainSysvol/GPO/Machine/registry.pol"] = _registry_pol(gpo.machine_pol)
    if gpo.user_pol:
        files["DomainSysvol/GPO/User/registry.pol"] = _registry_pol(gpo.user_pol)
    return files


def _gplink(links: tuple[tuple[str, int], ...]) -> str:
    """A raw ``gPLink``: link order 1 is the last entry."""
    return "".join(
        f"[LDAP://cn={{{guid.upper()}}},cn=policies,cn=system,{DOMAIN_DN};{options}]"
        for guid, options in reversed(links)
    )


def _encode(side: _Export) -> str:
    files: dict[str, bytes] = {}
    for gpo in sorted(side.gpos, key=lambda g: g.guid):
        backup_id = side.backups[gpo.guid]
        folder = f"{{{backup_id.upper()}}}"
        parts = _backup(gpo, side, backup_id)
        files.update({f"{folder}/{path}": parts[path] for path in sorted(parts)})
    header = {
        "mishpat_export": 1,
        "collector": {"name": script.NAME, "version": script.version()},
        "domain": DOMAIN,
        "collected_at": side.collected_at,
        "scope": "all",
    }
    structure = {
        "scopes": [
            {"path": s.dn, "kind": s.kind, "blocked": s.blocked, "gplink": _gplink(s.links)}
            for s in side.scopes
        ],
        "wmi_filters": [
            {"id": f.identifier, "name": f.name, "description": f.description, "query": f.parm2}
            for f in sorted(side.filters, key=lambda f: f.identifier)
        ],
    }
    return bundle.encode(header, files, structure).decode("ascii")


def build() -> dict[str, str]:
    """Return the two example export bundles by name (:data:`NAMES`), as ASCII text."""
    return {NAMES[0]: _encode(_before()), NAMES[1]: _encode(_after())}
