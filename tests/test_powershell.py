# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded PowerShell keeps its own line layout
"""The PowerShell exporter.

The text checks run everywhere. Where PowerShell is installed, the script's own
functions also run, with only Active Directory, the GroupPolicy module, and the
computer's name replaced by synthetic stand-ins; its output is checked here by an
independent reader written in Python (it does not use mishpat's bundle reader).
Set ``MISHPAT_REQUIRE_PWSH=1`` to fail instead of skipping when PowerShell is missing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING, Any

import pytest

from faithful_mishpat.collect import script

if TYPE_CHECKING:
    from pathlib import Path

TEXT = script.text()

# Commands the script may call. Anything else, such as Set-, New-Item, Remove-,
# Clear-, Invoke-Expression, or Start-Process, would make the test fail.
ALLOWED = {
    "Set-StrictMode", "New-Object", "Write-Output", "Write-Warning", "Get-Date", "Sort-Object",
    "ForEach-Object", "Where-Object", "Get-Command", "Import-Module", "Get-GPO", "Backup-GPO",
}  # fmt: skip
_FUNCTION = re.compile(r"^function ([A-Za-z]+-[A-Za-z]+)", re.MULTILINE)
_COMMAND = re.compile(r"(?<![\w$.-])([A-Z][a-z]+-[A-Z][A-Za-z]+)\b")


def code() -> str:
    """The script without comments, so help text cannot hide or fake a command."""
    without_blocks = re.sub(r"<#.*?#>", "", TEXT, flags=re.DOTALL)
    without_blocks = re.sub(r"'[^'\n]*'", "''", without_blocks)
    return "\n".join(
        line.split(" #")[0]
        for line in without_blocks.splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_script_is_pure_ascii_for_windows_powershell() -> None:
    """Windows PowerShell 5.1 reads a file without a BOM in the system code page."""
    assert TEXT.isascii()
    assert "\r" not in TEXT


def test_the_script_states_the_version_it_writes() -> None:
    assert script.version() == "0.1.0"
    assert "$CollectorVersion = '0.1.0'" in TEXT
    assert "$CollectorName = 'Export-MishpatGpo.ps1'" in TEXT
    assert script.NAME == "Export-MishpatGpo.ps1"


def test_the_script_only_reads() -> None:
    body = code()
    defined = set(_FUNCTION.findall(body))
    called = set(_COMMAND.findall(body)) - defined
    assert called <= ALLOWED, called - ALLOWED
    forbidden_commands = (
        "Invoke-Expression", "Start-Process", "Remove-Item", "Set-Content", "Out-File",
        "Set-GPO", "New-GPO", "Remove-GPO", "Import-GPO", "Restore-GPO", "Copy-GPO",
        "Set-GPLink", "New-GPLink", "Remove-GPLink", "Set-ADObject", "Get-ADObject",
    )  # fmt: skip
    for forbidden in forbidden_commands:
        assert forbidden not in body
    assert "Set-StrictMode -Version 3.0" in TEXT
    assert "\n$ErrorActionPreference = 'Stop'\n" in TEXT
    # Active Directory is read through ADSI only: no ActiveDirectory module.
    assert "ActiveDirectory" not in code()
    assert "[adsisearcher]" in TEXT
    assert "[adsi]" in TEXT


def test_no_function_sends_a_whole_array_as_one_object() -> None:
    """A leading comma before ``ToArray()`` hides every row inside one ``Object[]`` (MIS-R2)."""
    assert not re.search(r"^\s*,\s*\$\w+\.ToArray\(\)", code(), re.MULTILINE)


def test_the_output_file_is_never_overwritten_without_force() -> None:
    assert "[System.IO.FileMode]::CreateNew" in TEXT
    assert "[System.IO.FileMode]::Create " not in TEXT  # the file is never opened in place
    assert "[System.IO.File]::Move($Writer.TempPath, $Path)" in TEXT


def test_backups_go_to_a_new_random_folder_that_is_removed_in_a_finally_block() -> None:
    assert "'mishpat-' + [guid]::NewGuid().ToString('N')" in TEXT
    assert "$env:TEMP" in TEXT
    write = TEXT[TEXT.index("function Write-GpoBackup") : TEXT.index("# --- Structure")]
    assert "} finally {\n        Remove-TempFolder $temp" in write
    assert "changes\n    # nothing in Active Directory or in SYSVOL" in write


# --- running the script's functions -----------------------------------------------------

# MISHPAT_PWSH names the PowerShell to test with, such as "powershell" for Windows
# PowerShell 5.1. Without it the tests use pwsh, then powershell.
_PWSH_NAME = os.environ.get("MISHPAT_PWSH")
_PWSH = (
    shutil.which(_PWSH_NAME) if _PWSH_NAME else shutil.which("pwsh") or shutil.which("powershell")
)
if _PWSH is None and os.environ.get("MISHPAT_REQUIRE_PWSH") == "1":  # pragma: no cover
    msg = f"MISHPAT_REQUIRE_PWSH is set but {_PWSH_NAME or 'PowerShell'} is not installed"
    raise RuntimeError(msg)
needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="PowerShell is not installed")

PARAMETERS = """
$Name = $null; $Guid = $null; $All = $false; $Domain = $null; $Server = $null
$OutFile = $null; $ToPipeline = $false; $Force = $false
"""


def functions() -> str:
    """The script's definitions, without its parameter block or its call to run."""
    start = TEXT.index("Set-StrictMode")
    end = TEXT.index("if ($MyInvocation.InvocationName")
    return PARAMETERS + TEXT[start:end]


class Place:
    """A scratch area: a script folder, an output folder, and the TEMP the script uses."""

    def __init__(self, root: Path) -> None:
        self.scripts = root / "script"
        self.out = root / "out"
        self.temp = root / "temp"
        for folder in (self.scripts, self.out, self.temp):
            folder.mkdir()

    def leftovers(self) -> list[str]:
        """Everything left in TEMP and next to the output."""
        return sorted(p.name for p in self.temp.iterdir()) + sorted(
            p.name for p in self.out.iterdir() if p.name.endswith(".part")
        )


@pytest.fixture
def place(tmp_path: Path) -> Place:
    return Place(tmp_path)


def run_pwsh(
    where: Place, body: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    path = where.scripts / "run.ps1"
    path.write_text(functions() + "\n" + body, encoding="utf-8")
    environment = {**os.environ, "TEMP": str(where.temp), **(env or {})}
    return subprocess.run(  # noqa: S603 - a fixed interpreter and a script built here
        [_PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        check=False,
        env=environment,
    )


def encoded(value: str) -> str:
    """Pass any text into PowerShell untouched, as base64 of UTF-16."""
    raw = value.encode("utf-16-le", "surrogatepass")
    return f"[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{base64.b64encode(raw).decode()}'))"


HOSTILE = [
    "",
    "plain",
    'quote " and backslash \\',
    "controls \x00\x01\x08\t\n\r\x1f\x7f",
    "line separators \u2028\u2029",
    "accents é ü and CJK 漢字",
    "astral 😀 𝄞",
    "(&(objectClass=msWMI-Som)(msWMI-Name=*))",
    "SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.%' AND ProductType='1'",
    "root\\CIMv2",
]


@needs_pwsh
def test_the_json_writer_agrees_with_python(place: Place) -> None:
    lines = "\n".join(f"ConvertTo-JsonText ({encoded(value)})" for value in HOSTILE)
    result = run_pwsh(place, lines + "\nConvertTo-JsonText $null")
    assert result.returncode == 0, result.stderr
    out = result.stdout.splitlines()
    assert all(line.isascii() for line in out)
    assert [json.loads(line) for line in out] == [*HOSTILE, None]


@needs_pwsh
def test_an_unpaired_surrogate_stays_visible(place: Place) -> None:
    result = run_pwsh(place, "ConvertTo-JsonText ('a' + [char] 0xD800 + 'b')")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '"a\\ud800b"'


@needs_pwsh
def test_small_helpers(place: Place) -> None:
    body = r"""
Format-UtcTime ([datetime]::new(2026, 11, 3, 14, 0, 5, [System.DateTimeKind]::Utc).AddTicks(1234567))
Format-UtcTime ([datetime]::new(2026, 11, 3, 8, 0, 0, [System.DateTimeKind]::Utc).ToLocalTime())
ConvertTo-GuidText '{ABCDEF01-2345-6789-ABCD-EF0123456789}'
ConvertTo-GuidText ' abcdef01-2345-6789-abcd-ef0123456789 '
ConvertTo-DnsName 'DC=corp,DC=example'
ConvertTo-DnsName 'dc=Sub,dc=corp,DC=example'
ConvertTo-JsonBool $true
ConvertTo-JsonBool $false
'[' + (Get-Text $null) + ']'
Get-Text 7
(Sort-Ordinal @(@{ k = 'b' }, @{ k = 'B' }, @{ k = 'a' }, @{ k = [string][char]0xE9 }) 'k' | ForEach-Object { $_.k }) -join ''
Get-LdapPath 'OU=A/B,DC=corp,DC=example'
$Server = 'dc01.corp.example'
Get-LdapPath 'DC=corp,DC=example'
$Server = $null; $Domain = 'corp.example'
Get-LdapPath 'DC=corp,DC=example'
"""
    result = run_pwsh(place, body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "2026-11-03T14:00:05Z",
        "2026-11-03T08:00:00Z",
        "abcdef01-2345-6789-abcd-ef0123456789",
        "abcdef01-2345-6789-abcd-ef0123456789",
        "corp.example",
        "Sub.corp.example",
        "true",
        "false",
        "[]",
        "7",
        "Babé",
        "LDAP://OU=A\\/B,DC=corp,DC=example",
        "LDAP://dc01.corp.example/DC=corp,DC=example",
        "LDAP://corp.example/DC=corp,DC=example",
    ]


@needs_pwsh
def test_sort_ordinal_gives_callers_items_not_a_wrapped_array(place: Place) -> None:
    """The sibling of MIS-R2: ``@(Sort-Ordinal ...)`` must count items for none, one, many."""
    body = r"""
$none = @(Sort-Ordinal @() 'k')
$one = @(Sort-Ordinal @(@{ k = 'a' }) 'k')
$many = @(Sort-Ordinal @(@{ k = 'b' }, @{ k = 'a' }) 'k')
$objects = @(Sort-Ordinal @([pscustomobject] @{ k = 'z' }) 'k')
"$($none.Count) $($one.Count) $($one[0].GetType().Name) $($many.Count) $($many[0].k) $($objects.Count) $($objects[0].k)"
"""
    result = run_pwsh(place, body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["0", "1", "Hashtable", "2", "a", "1", "z"]


# --- a stand-in for Active Directory and the GroupPolicy module -------------------------

GUID_A = "11111111-1111-4111-8111-111111111111"
GUID_B = "bbbbbbbb-2222-4222-8222-222222222222"
GUID_C = "33333333-3333-4333-8333-333333333333"
GUID_D = "44444444-4444-4444-8444-444444444444"
GUID_E = "55555555-5555-4555-8555-555555555555"
ALL_GUIDS = sorted([GUID_A, GUID_B, GUID_C, GUID_D, GUID_E])
CAFE = 'Caf\u00e9 "Servers"'

# Only reading AD, the GroupPolicy module and the computer name is replaced. The
# script's own selection, backup reading, hashing, writing and publishing run.
STUB = r"""
function Assert-GroupPolicyModule { }
function Get-DomainFacts {
    [ordered] @{ DomainDn = 'DC=corp,DC=example'; ConfigDn = 'CN=Configuration,DC=corp,DC=example' }
}
function Get-GpoCandidates {
    @(
        [pscustomobject] @{ Guid = '55555555-5555-4555-8555-555555555555'; Name = 'Dup' }
        [pscustomobject] @{ Guid = '11111111-1111-4111-8111-111111111111'; Name = 'Default Domain Policy' }
        [pscustomobject] @{ Guid = '33333333-3333-4333-8333-333333333333'; Name = ('Caf' + [char] 0xE9 + ' "Servers"') }
        [pscustomobject] @{ Guid = 'bbbbbbbb-2222-4222-8222-222222222222'; Name = 'Workstation Baseline' }
        [pscustomobject] @{ Guid = '44444444-4444-4444-8444-444444444444'; Name = 'DUP' }
    )
}
function Backup-GPO {
    param([guid] $Guid, [string] $Path, [string] $Domain = '', [string] $Server = '')
    if (-not $Path.StartsWith($env:TEMP)) { throw 'Backup-GPO was given a folder outside TEMP' }
    if (@([System.IO.Directory]::GetFileSystemEntries($Path)).Count -ne 0) { throw 'Backup-GPO was given a folder that is not empty' }
    $id = '{' + $Guid.ToString('N').ToUpperInvariant().Substring(0, 8) + '-0000-4000-8000-000000000000}'
    $folder = [System.IO.Path]::Combine($Path, $id)
    [void] [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($folder, 'DomainSysvol', 'GPO', 'Machine'))
    [void] [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($folder, 'DomainSysvol', 'GPO', 'User'))
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($Path, 'manifest.xml'), '<Backups/>')
    if ($Guid.ToString() -eq $env:MISHPAT_FAIL_GUID) {
        [System.IO.File]::WriteAllText([System.IO.Path]::Combine($folder, 'bkupInfo.xml'), 'half')
        throw 'Access is denied.'
    }
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($folder, 'bkupInfo.xml'), "guid=$Guid;domain=$Domain;server=$Server")
    $report = [System.Text.Encoding]::Unicode.GetPreamble() + [System.Text.Encoding]::Unicode.GetBytes('<GPO>caf' + [char] 0xE9 + ' ' + [char] 0x6F22 + '</GPO>')
    [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($folder, 'gpreport.xml'), $report)
    [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($folder, 'DomainSysvol', 'GPO', 'Machine', 'registry.pol'), [byte[]] (0..255))
    [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($folder, 'DomainSysvol', 'GPO', 'User', 'empty.pol'), [byte[]] @())
    if ($Guid.ToString().StartsWith('1')) {
        $big = New-Object byte[] 1048576
        (New-Object System.Random -ArgumentList 42).NextBytes($big)
        [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($folder, 'Big.bin'), $big)
    }
    if ($env:MISHPAT_TWO_FOLDERS) { [void] [System.IO.Directory]::CreateDirectory([System.IO.Path]::Combine($Path, '{second}')) }
}
# Active Directory itself is replaced one level lower than the script's own search: only
# the directory object and the searcher are stand-ins, so Search-Directory, with its row
# building and what it returns to its callers, is the script's own code.
$FakeRows = @{
    '(objectClass=domain)' = @(
        @{ distinguishedname = 'DC=corp,DC=example'; gplink = '[LDAP://cn={11111111-1111-4111-8111-111111111111},cn=policies,cn=system,DC=corp,DC=example;2]'; gpoptions = 0 }
    )
    '(objectClass=organizationalUnit)' = @(
        @{ distinguishedname = 'OU=Servers,DC=corp,DC=example'; gplink = $null; gpoptions = 1 }
        @{ distinguishedname = 'OU=Caf' + [char] 0xE9 + ',OU=Servers,DC=corp,DC=example'; gplink = ''; gpoptions = $null }
        @{ distinguishedname = 'OU=Admins,DC=corp,DC=example'; gplink = '[LDAP://cn={bbbbbbbb-2222-4222-8222-222222222222},cn=policies,cn=system,DC=corp,DC=example;0]'; gpoptions = '0' }
    )
    '(objectClass=site)' = @(
        @{ distinguishedname = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example'; gplink = '[LDAP://cn={33333333-3333-4333-8333-333333333333},cn=policies,cn=system,DC=corp,DC=example;1]'; gpoptions = 1 }
    )
    '(objectClass=msWMI-Som)' = @(
        @{ 'mswmi-id' = '{ABCDEF01-0000-4000-8000-00000000000F}'; 'mswmi-name' = 'Win10'; 'mswmi-parm1' = $null; 'mswmi-parm2' = '1;3;10;5;WQL;root\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%";' }
        @{ 'mswmi-id' = '{0A0A0A0A-0000-4000-8000-000000000001}'; 'mswmi-name' = 'Laptops'; 'mswmi-parm1' = 'Only laptops'; 'mswmi-parm2' = 'q' }
    )
}
function New-DirectoryEntry([string] $DistinguishedName) {
    $entry = [pscustomobject] @{ DistinguishedName = $DistinguishedName }
    Add-Member -InputObject $entry -MemberType ScriptMethod -Name Dispose -Value { }
    $entry
}
function New-DirectorySearcher([string] $Filter) {
    $searcher = [pscustomobject] @{
        Filter = $Filter; SearchRoot = $null; PageSize = 0; SearchScope = $null
        PropertiesToLoad = (New-Object System.Collections.ArrayList)
    }
    Add-Member -InputObject $searcher -MemberType ScriptMethod -Name Dispose -Value { }
    Add-Member -InputObject $searcher -MemberType ScriptMethod -Name FindAll -Value {
        # FINDALL-HOOK
        if (-not $FakeRows.ContainsKey($this.Filter)) { throw "unexpected search $($this.Filter)" }
        $found = New-Object System.Collections.ArrayList
        foreach ($row in $FakeRows[$this.Filter]) {
            $properties = @{}
            foreach ($name in $this.PropertiesToLoad) {
                $key = ([string] $name).ToLowerInvariant()
                $properties[$key] = if ($null -ne $row[$key]) { , @($row[$key]) } else { , @() }
            }
            [void] $found.Add([pscustomobject] @{ Properties = $properties })
        }
        Add-Member -InputObject $found -MemberType ScriptMethod -Name Dispose -Value { }
        , $found
    }
    $searcher
}
"""

EXPECTED_STRUCTURE: dict[str, Any] = {
    "scopes": [
        {
            "path": "DC=corp,DC=example",
            "kind": "domain",
            "blocked": False,
            "gplink": "[LDAP://cn={11111111-1111-4111-8111-111111111111},cn=policies,cn=system,DC=corp,DC=example;2]",
        },
        {
            "path": "OU=Admins,DC=corp,DC=example",
            "kind": "ou",
            "blocked": False,
            "gplink": "[LDAP://cn={bbbbbbbb-2222-4222-8222-222222222222},cn=policies,cn=system,DC=corp,DC=example;0]",
        },
        {
            "path": "OU=Caf\u00e9,OU=Servers,DC=corp,DC=example",
            "kind": "ou",
            "blocked": False,
            "gplink": "",
        },
        {"path": "OU=Servers,DC=corp,DC=example", "kind": "ou", "blocked": True, "gplink": ""},
        {
            "path": "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example",
            "kind": "site",
            "blocked": True,
            "gplink": "[LDAP://cn={33333333-3333-4333-8333-333333333333},cn=policies,cn=system,DC=corp,DC=example;1]",
        },
    ],
    "wmi_filters": [
        {
            "id": "{0A0A0A0A-0000-4000-8000-000000000001}",
            "name": "Laptops",
            "description": "Only laptops",
            "query": "q",
        },
        {
            "id": "{ABCDEF01-0000-4000-8000-00000000000F}",
            "name": "Win10",
            "description": "",
            "query": '1;3;10;5;WQL;root\\CIMv2;SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%";',
        },
    ],
}


# --- an independent reader of the bundle ------------------------------------------------


def backup_id(guid: str) -> str:
    return "{" + guid.replace("-", "").upper()[:8] + "-0000-4000-8000-000000000000}"


def expected_files(guid: str) -> dict[str, bytes | None]:
    """The files the stub backs up for a GPO, by path; ``None`` where only the size is known."""
    prefix = backup_id(guid) + "/"
    files: dict[str, bytes | None] = {
        prefix + "bkupInfo.xml": f"guid={guid};domain=;server=".encode(),
        prefix + "gpreport.xml": b"\xff\xfe" + "<GPO>caf\u00e9 \u6f22</GPO>".encode("utf-16-le"),
        prefix + "DomainSysvol/GPO/Machine/registry.pol": bytes(range(256)),
        prefix + "DomainSysvol/GPO/User/empty.pol": b"",
    }
    if guid.startswith("1"):
        files[prefix + "Big.bin"] = None
    return files


class Bundle:
    """A bundle read line by line with nothing but ``json`` and ``hashlib``."""

    def __init__(self, raw: bytes) -> None:
        assert raw.isascii(), "the bundle is not pure ASCII"
        assert raw.endswith(b"\n")
        assert b"\r" not in raw
        lines = raw.split(b"\n")[:-1]
        assert len(lines) >= 3
        self.header: dict[str, Any] = json.loads(lines[0])
        assert lines[0].startswith(b'{"mishpat_export":1,')
        self.trailer: dict[str, Any] = json.loads(lines[-1])
        assert lines[-1].startswith(b'{"end":true,"files":')
        # The trailer hashes every byte before itself.
        before = raw[: len(raw) - len(lines[-1]) - 1]
        assert self.trailer["sha256"] == hashlib.sha256(before).hexdigest()
        assert list(self.trailer) == ["end", "files", "sha256"]
        assert self.trailer["end"] is True
        structure = json.loads(lines[-2])
        assert list(structure) == ["structure"]
        self.structure: dict[str, Any] = structure["structure"]
        self.files: dict[str, bytes] = {}
        self.order: list[str] = []
        for line in lines[1:-2]:
            assert line.startswith(b'{"path":')
            entry = json.loads(line)
            assert list(entry) == ["path", "size", "sha256", "data"]
            data = base64.b64decode(entry["data"], validate=True)
            assert entry["size"] == len(data)
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()
            assert entry["path"] not in self.files
            self.files[entry["path"]] = data
            self.order.append(entry["path"])
        assert self.trailer["files"] == len(self.files)


def check_files(bundle: Bundle, guids: list[str]) -> None:
    expected: dict[str, bytes | None] = {}
    for guid in guids:
        expected.update(expected_files(guid))
    assert sorted(bundle.files) == sorted(expected)
    for path, content in expected.items():
        if content is None:
            assert len(bundle.files[path]) == 1048576
        else:
            assert bundle.files[path] == content, path
    assert not any(path.endswith("manifest.xml") for path in bundle.files)
    assert all(not path.startswith(("/", ".")) and "\\" not in path for path in bundle.files)


def export(  # noqa: PLR0913 - one argument per export choice
    place: Place,
    settings: str = "",
    *,
    stub: str = STUB,
    pipeline: bool = False,
    env: dict[str, str] | None = None,
    out_name: str = "gpos.jsonl",
) -> subprocess.CompletedProcess[str]:
    out = place.out / out_name
    target = "$ToPipeline = $true" if pipeline else f"$OutFile = '{out}'"
    return run_pwsh(place, f"{stub}\n{target}\n{settings}\nInvoke-Export", env)


def read_out(place: Place, name: str = "gpos.jsonl") -> Bundle:
    return Bundle((place.out / name).read_bytes())


@needs_pwsh
def test_an_export_of_every_gpo_is_a_valid_bundle(place: Place) -> None:
    result = export(place, "$All = $true")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    bundle = read_out(place)
    assert list(bundle.header) == ["mishpat_export", "collector", "domain", "collected_at", "scope"]
    assert bundle.header["mishpat_export"] == 1
    assert bundle.header["collector"] == {"name": "Export-MishpatGpo.ps1", "version": "0.1.0"}
    assert bundle.header["domain"] == "corp.example"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", bundle.header["collected_at"])
    assert bundle.header["scope"] == "all"
    check_files(bundle, ALL_GUIDS)
    assert bundle.structure == EXPECTED_STRUCTURE
    assert (
        bundle.trailer["files"] == 5 * 4 + 1
    )  # four files each, and Big.bin for the GUID starting 1
    assert place.leftovers() == []


@needs_pwsh
def test_files_are_in_ordinal_path_order_and_gpos_in_guid_order(place: Place) -> None:
    assert export(place, "$All = $true").returncode == 0
    order = read_out(place).order
    assert order == sorted(order, key=lambda path: (path.split("/")[0], path))
    assert list(dict.fromkeys(path.split("/")[0] for path in order)) == [
        backup_id(g) for g in ALL_GUIDS
    ]
    one = [p for p in order if p.startswith(backup_id(GUID_A))]
    assert one == sorted(one)  # uppercase "Big.bin" sorts before lower-case names


@needs_pwsh
def test_the_pipeline_output_is_the_same_bundle(place: Place) -> None:
    result = export(place, "$All = $true", pipeline=True)
    assert result.returncode == 0, result.stderr
    assert not any(p.suffix == ".jsonl" for p in place.out.iterdir())
    bundle = Bundle(result.stdout.encode("ascii"))
    check_files(bundle, ALL_GUIDS)
    assert bundle.structure == EXPECTED_STRUCTURE
    assert place.leftovers() == []


@needs_pwsh
def test_names_and_guids_select_only_those_gpos_and_still_record_every_scope(place: Place) -> None:
    result = export(
        place,
        f"$Name = @('workstation baseline', ({encoded(CAFE)}), 'Workstation Baseline')",
    )
    assert result.returncode == 0, result.stderr
    bundle = read_out(place)
    assert bundle.header["scope"] == sorted([GUID_B, GUID_C])
    check_files(bundle, [GUID_B, GUID_C])
    assert bundle.structure == EXPECTED_STRUCTURE
    out = place.out / "by-guid.jsonl"
    result = export(
        place,
        f"$Guid = @('{{{GUID_E.upper()}}}', '{GUID_A}')",
        out_name=out.name,
    )
    assert result.returncode == 0, result.stderr
    by_guid = read_out(place, out.name)
    assert by_guid.header["scope"] == sorted([GUID_A, GUID_E])
    check_files(by_guid, [GUID_A, GUID_E])
    assert place.leftovers() == []


@needs_pwsh
def test_domain_and_server_reach_backup_gpo(place: Place) -> None:
    result = export(
        place,
        "$Name = 'Workstation Baseline'; $Domain = 'corp.example'; $Server = 'dc01.corp.example'",
    )
    assert result.returncode == 0, result.stderr
    info = read_out(place).files[backup_id(GUID_B) + "/bkupInfo.xml"]
    assert info == f"guid={GUID_B};domain=corp.example;server=dc01.corp.example".encode()


@needs_pwsh
@pytest.mark.parametrize(
    ("settings", "problem"),
    [
        ("$Name = 'No such GPO'", "No GPO is named 'No such GPO'"),
        ("$Name = 'dup'", "More than one GPO is named 'dup'"),
        ("$Name = @('Workstation Baseline', 'Dup')", "More than one GPO is named 'Dup'"),
        (
            "$Guid = '66666666-6666-4666-8666-666666666666'",
            "No GPO has the GUID 66666666-6666-4666-8666-666666666666",
        ),
        ("", "Give exactly one of -Name, -Guid and -All"),
        ("$All = $true; $Name = 'x'", "Give exactly one of"),
        (f"$Guid = '{GUID_A}'; $Name = 'x'", "Give exactly one of"),
        (f"$Guid = '{GUID_A}'; $All = $true", "Give exactly one of"),
    ],
)
def test_a_selection_error_stops_before_anything_is_written(
    place: Place, settings: str, problem: str
) -> None:
    for pipeline in (False, True):
        result = export(place, settings, pipeline=pipeline)
        assert result.returncode != 0
        assert problem in result.stderr
        assert result.stdout == ""
        assert list(place.out.iterdir()) == []
        assert place.leftovers() == []


@needs_pwsh
def test_an_ambiguous_name_lists_the_guids(place: Place) -> None:
    result = export(place, "$Name = 'dup'")
    assert GUID_D in result.stderr
    assert GUID_E in result.stderr
    assert "Use -Guid" in result.stderr


@needs_pwsh
def test_a_missing_group_policy_module_is_explained(place: Place) -> None:
    stub = STUB.replace("function Assert-GroupPolicyModule { }", "")
    stub += "\nfunction Get-Command { $null }\nfunction Import-Module { throw 'not found' }\n"
    result = export(place, "$All = $true", stub=stub)
    assert result.returncode != 0
    assert "The GroupPolicy module is not available" in result.stderr
    assert list(place.out.iterdir()) == []


# --- parts of the structure that cannot be read ----------------------------------------


REASON = 'Access is denied. "quoted" \u00e9'


def failing(filter_text: str, message: str) -> str:
    return STUB.replace(
        "# FINDALL-HOOK",
        f"if ($this.Filter -eq '{filter_text}') {{ throw '{message}' }}",
    )


@needs_pwsh
@pytest.mark.parametrize(
    ("filter_text", "what", "key"),
    [
        ("(objectClass=domain)", "the domain object (its links and inheritance)", "domain"),
        (
            "(objectClass=organizationalUnit)",
            "the organizational units (their links and inheritance)",
            "ou",
        ),
        ("(objectClass=site)", "the sites (their links and inheritance)", "site"),
        ("(objectClass=msWMI-Som)", "the WMI filters (their queries)", None),
    ],
)
def test_a_part_that_cannot_be_read_becomes_a_gap(
    place: Place, filter_text: str, what: str, key: str | None
) -> None:
    result = export(place, "$All = $true", stub=failing(filter_text, REASON))
    assert result.returncode == 0, result.stderr
    bundle = read_out(place)
    (gap,) = bundle.structure["gaps"]
    assert gap["what"] == what
    # PowerShell wraps an exception raised inside a method call; the cause stays in the text.
    assert gap["reason"].endswith(f'"{REASON}"')
    assert REASON in gap["reason"]
    assert list(bundle.structure)[:2] == ["scopes", "wmi_filters"]
    if key is None:
        assert bundle.structure["wmi_filters"] == []
        assert bundle.structure["scopes"] == EXPECTED_STRUCTURE["scopes"]
    else:
        assert {s["kind"] for s in bundle.structure["scopes"]} == {"domain", "ou", "site"} - {key}
        assert bundle.structure["wmi_filters"] == EXPECTED_STRUCTURE["wmi_filters"]
    check_files(bundle, ALL_GUIDS)  # the GPOs are still all there


@needs_pwsh
def test_search_directory_hands_its_callers_one_hashtable_per_object(place: Place) -> None:
    """MIS-R2: the rows must reach ``@(...)`` as rows, for none, one and several objects."""
    body = r"""
$props = @('distinguishedName', 'gPLink', 'gPOptions')
$FakeRows['(objectClass=none)'] = @()
$FakeRows['(objectClass=one)'] = @(@{ distinguishedname = 'OU=Only'; gplink = 'x'; gpoptions = 3 })
foreach ($filter in '(objectClass=none)', '(objectClass=one)', '(objectClass=organizationalUnit)') {
    $rows = @(Search-Directory 'DC=corp,DC=example' $filter $props 'Subtree')
    $kinds = (@($rows | ForEach-Object { $_.GetType().Name }) | Sort-Object -Unique) -join ','
    "$filter|$($rows.Count)|$kinds|" + ((@($rows | ForEach-Object { $_['distinguishedname'] })) -join ';')
}
$one = @(Search-Directory 'DC=corp,DC=example' '(objectClass=one)' $props 'Subtree')[0]
"$($one['gplink'])|$($one['gpoptions'])|" + (($one.Keys | Sort-Object) -join ',')
"""
    result = run_pwsh(place, STUB + body)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "(objectClass=none)|0||",
        "(objectClass=one)|1|Hashtable|OU=Only",
        (
            "(objectClass=organizationalUnit)|3|Hashtable|OU=Servers,DC=corp,DC=example;"
            "OU=Café,OU=Servers,DC=corp,DC=example;OU=Admins,DC=corp,DC=example"
        ),
        "x|3|distinguishedname,gplink,gpoptions",
    ]


@needs_pwsh
def test_the_structure_is_complete_for_every_kind_of_scope_and_has_no_gap(place: Place) -> None:
    body = r"""
$line = Get-StructureLine (Get-DomainFacts)
$line
"""
    result = run_pwsh(place, STUB + body)
    assert result.returncode == 0, result.stderr
    structure = json.loads(result.stdout)["structure"]
    assert "gaps" not in structure
    assert structure == EXPECTED_STRUCTURE


@needs_pwsh
def test_a_search_base_that_does_not_exist_is_empty_and_not_a_gap(place: Place) -> None:
    # A real method's COMException is what the script catches, so the stand-in must be
    # compiled code: an exception thrown from a PowerShell script method arrives wrapped.
    missing = r"""
Add-Type -TypeDefinition @'
public class MissingBaseSearcher {
    public object SearchRoot; public int PageSize; public object SearchScope;
    public System.Collections.ArrayList PropertiesToLoad = new System.Collections.ArrayList();
    public System.Collections.ArrayList FindAll() {
        throw new System.Runtime.InteropServices.COMException("No such object", -2147016656);
    }
    public void Dispose() { }
}
'@
$realSearcher = ${function:New-DirectorySearcher}
function New-DirectorySearcher([string] $Filter) {
    if ($Filter -eq '(objectClass=site)') { New-Object MissingBaseSearcher } else { & $realSearcher $Filter }
}
"""
    result = export(place, "$All = $true", stub=STUB + missing)
    assert result.returncode == 0, result.stderr
    structure = read_out(place).structure
    assert "gaps" not in structure
    assert {s["kind"] for s in structure["scopes"]} == {"domain", "ou"}


# --- the temporary folder and the output file ------------------------------------------


@needs_pwsh
@pytest.mark.parametrize("pipeline", [False, True])
def test_a_failed_backup_removes_every_temporary_folder_and_publishes_nothing(
    place: Place, *, pipeline: bool
) -> None:
    result = export(place, "$All = $true", pipeline=pipeline, env={"MISHPAT_FAIL_GUID": GUID_C})
    assert result.returncode != 0
    assert "Access is denied." in result.stderr
    assert place.leftovers() == []
    assert list(place.out.iterdir()) == []
    if pipeline:
        # What was streamed before the failure has no end line, so a reader refuses it.
        assert '{"end":true' not in result.stdout


@needs_pwsh
def test_a_backup_that_makes_two_folders_is_refused_and_cleaned_up(place: Place) -> None:
    result = export(place, f"$Guid = '{GUID_A}'", env={"MISHPAT_TWO_FOLDERS": "1"})
    assert result.returncode != 0
    assert "did not make exactly one backup folder" in result.stderr
    assert place.leftovers() == []
    assert list(place.out.iterdir()) == []


@needs_pwsh
def test_the_temporary_folder_is_removed_after_each_gpo_not_at_the_end(place: Place) -> None:
    stub = (
        STUB
        + "\nfunction Remove-TempFolder([string] $Path) { Write-Output ('removing ' + [System.IO.Path]::GetFileName($Path)); [System.IO.Directory]::Delete($Path, $true) }\n"
    )
    result = export(place, f"$Guid = @('{GUID_A}', '{GUID_B}')", stub=stub)
    assert result.returncode == 0, result.stderr
    removed = [line for line in result.stdout.splitlines() if line.startswith("removing mishpat-")]
    assert len(removed) == 2
    assert len(set(removed)) == 2  # a new random name each time
    assert all(re.fullmatch(r"removing mishpat-[0-9a-f]{32}", line) for line in removed)


@needs_pwsh
def test_a_temporary_folder_that_cannot_be_removed_warns_without_hiding_the_error(
    place: Place,
) -> None:
    stub = STUB + "\nfunction Remove-TempFolder([string] $Path) { Write-Warning 'kept' }\n"
    result = export(place, "$All = $true", stub=stub, env={"MISHPAT_FAIL_GUID": GUID_C})
    assert result.returncode != 0
    assert "Access is denied." in result.stderr


@needs_pwsh
def test_remove_temp_folder_clears_read_only_files_and_never_throws(place: Place) -> None:
    folder = place.temp / "victim"
    (folder / "sub").mkdir(parents=True)
    locked = folder / "sub" / "ro.txt"
    locked.write_text("x", encoding="utf-8")
    locked.chmod(0o444)
    body = f"Remove-TempFolder '{folder}'\nRemove-TempFolder '{folder}'\nRemove-TempFolder $null"
    result = run_pwsh(place, body)
    assert result.returncode == 0, result.stderr
    assert not folder.exists()


@needs_pwsh
def test_an_existing_file_is_not_overwritten(place: Place) -> None:
    out = place.out / "gpos.jsonl"
    out.write_text("keep", encoding="utf-8")
    result = export(place, "$All = $true")
    assert result.returncode != 0
    assert "already exists" in result.stderr
    assert out.read_text(encoding="utf-8") == "keep"
    assert [p.name for p in place.out.iterdir()] == ["gpos.jsonl"]
    assert place.leftovers() == []


@needs_pwsh
@pytest.mark.parametrize("force", [False, True])
def test_a_failed_run_keeps_the_existing_file_and_leaves_nothing(
    place: Place, *, force: bool
) -> None:
    out = place.out / "gpos.jsonl"
    out.write_text("keep", encoding="utf-8")
    settings = "$All = $true" + ("; $Force = $true" if force else "")
    result = export(place, settings, env={"MISHPAT_FAIL_GUID": GUID_B})
    assert result.returncode != 0
    assert out.read_text(encoding="utf-8") == "keep"
    assert [p.name for p in place.out.iterdir()] == ["gpos.jsonl"]
    assert place.leftovers() == []


@needs_pwsh
def test_a_failed_run_with_nothing_before_it_leaves_no_file(place: Place) -> None:
    assert export(place, "$All = $true", env={"MISHPAT_FAIL_GUID": GUID_B}).returncode != 0
    assert list(place.out.iterdir()) == []


@needs_pwsh
def test_a_successful_run_with_force_replaces_the_existing_file(place: Place) -> None:
    out = place.out / "gpos.jsonl"
    out.write_text("old", encoding="utf-8")
    result = export(place, f"$Guid = '{GUID_A}'; $Force = $true")
    assert result.returncode == 0, result.stderr
    assert [p.name for p in place.out.iterdir()] == ["gpos.jsonl"]
    check_files(read_out(place), [GUID_A])


@needs_pwsh
def test_a_successful_run_without_force_creates_the_file_and_leaves_nothing_else(
    place: Place,
) -> None:
    result = export(place, f"$Guid = '{GUID_A}'")
    assert result.returncode == 0, result.stderr
    assert [p.name for p in place.out.iterdir()] == ["gpos.jsonl"]


@needs_pwsh
def test_a_file_that_appears_during_the_run_is_not_replaced_without_force(place: Place) -> None:
    out = place.out / "gpos.jsonl"
    stub = (
        STUB
        + f"\nfunction Get-StructureLine($Facts) {{ [System.IO.File]::WriteAllText('{out}', 'arrived'); '{{\"structure\":{{}}}}' }}\n"
    )
    result = export(place, f"$Guid = '{GUID_A}'", stub=stub)
    assert result.returncode != 0
    assert out.read_text(encoding="utf-8") == "arrived"
    assert [p.name for p in place.out.iterdir()] == ["gpos.jsonl"]


@needs_pwsh
def test_a_relative_out_file_is_relative_to_the_powershell_location(place: Place) -> None:
    here = place.out / "here"
    here.mkdir()
    # The process directory stays elsewhere; only PowerShell's location moves.
    body = f"{STUB}\nSet-Location -LiteralPath '{here}'\n$OutFile = 'rel.jsonl'\n$Guid = '{GUID_A}'\nInvoke-Export"
    result = run_pwsh(place, body)
    assert result.returncode == 0, result.stderr
    assert [p.name for p in here.iterdir()] == ["rel.jsonl"]
    check_files(Bundle((here / "rel.jsonl").read_bytes()), [GUID_A])


# --- the real script's parameters -------------------------------------------------------


def run_script(place: Place, *arguments: str) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    path = place.scripts / script.NAME
    path.write_text(TEXT, encoding="ascii")
    return subprocess.run(  # noqa: S603 - a fixed interpreter and the packaged script
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(path),
            *arguments,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        check=False,
        env={**os.environ, "TEMP": str(place.temp)},
    )


@needs_pwsh
@pytest.mark.parametrize(
    ("arguments", "problem"),
    [
        (["-OutFile", "x.jsonl"], "Give exactly one of -Name, -Guid and -All"),
        (["-All", "-Name", "x", "-OutFile", "x.jsonl"], "Give exactly one of"),
        (["-ToPipeline"], "Give exactly one of"),
        (["-Guid", "not-a-guid", "-OutFile", "x.jsonl"], "does not match"),
        (["-Name", "", "-OutFile", "x.jsonl"], "empty"),
        (["-All", "-ToPipeline", "-OutFile", "x.jsonl"], "Parameter set cannot be resolved"),
        (["-All", "-ToPipeline", "-Force"], "Parameter set cannot be resolved"),
        (["-All"], "OutFile"),
    ],
)
def test_the_real_script_refuses_bad_parameters_before_touching_anything(
    place: Place, arguments: list[str], problem: str
) -> None:
    result = run_script(place, *arguments)
    assert result.returncode != 0
    assert problem in result.stderr or problem in result.stdout, result.stderr
    assert not any(p.name.endswith((".jsonl", ".part")) for p in place.scripts.iterdir())
    assert place.leftovers() == []


@pytest.mark.skipif(
    sys.platform != "win32" or _PWSH is None or os.environ.get("MISHPAT_LAB_DOMAIN") != "1",
    reason="run by hand on a domain-joined computer with RSAT: set MISHPAT_LAB_DOMAIN=1",
)
def test_the_real_script_exports_a_real_gpo(place: Place) -> None:  # pragma: no cover
    """Run by hand on a domain-joined computer: ``-All`` against a lab domain.

    It needs RSAT and a domain, which CI runners do not have, so it runs only when
    ``MISHPAT_LAB_DOMAIN=1`` says the computer is ready. Never point it at production.
    """
    result = run_script(place, "-All", "-OutFile", str(place.out / "real.jsonl"))
    assert result.returncode == 0, result.stderr
    bundle = Bundle((place.out / "real.jsonl").read_bytes())
    assert bundle.header["scope"] == "all"


# --- the export agrees with mishpat's own bundle reader ----------------------------------


@needs_pwsh
def test_the_exporters_output_passes_the_bundle_readers_checks(place: Place) -> None:
    from faithful_mishpat.formats import bundle  # noqa: PLC0415 - the reader is used by this test only

    assert export(place, "$All = $true").returncode == 0
    path = place.out / "gpos.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    header = bundle.check_header(lines[0])
    assert (header.scope, header.domain, header.collector) == (
        "all",
        "corp.example",
        "Export-MishpatGpo.ps1 0.1.0",
    )
    assert bundle.check_end(bundle.decode_line(lines[-1])).files == 21
    for entry in lines[1:-2]:
        decoded = bundle.decode_line(entry)
        assert bundle.check_path(decoded["path"]) == decoded["path"]
        assert len(entry) <= bundle.MAX_LINE
    read = bundle.read_bundle(path, "gpos.jsonl")
    # The backups here are not real backups, so the reader has things to say about them;
    # it must have nothing to say about the lines, the hash, or the structure.
    for problem in read.problems:
        assert "structure" not in problem.source.detail
        assert "end line" not in problem.reason
        assert "hash" not in problem.reason
        assert not problem.reason.startswith("The file was not read")
    assert read.scopes is not None
    assert set(read.scopes) == {s["path"].casefold() for s in EXPECTED_STRUCTURE["scopes"]}
    assert read.domain_wide is True
