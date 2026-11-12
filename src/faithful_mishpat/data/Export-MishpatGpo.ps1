# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Export Group Policy objects and their domain context for mishpat. Read-only.

.DESCRIPTION
    Backs up the chosen GPOs and reads where they are linked, and writes everything to
    one file in the mishpat export format (JSON Lines, pure ASCII):

      1. a header line: {"mishpat_export":1, collector, domain, collected_at, scope}
      2. one line per backup file: {"path", "size", "sha256", "data"} with the file's
         bytes in base64 and its path inside the backup, like <backup-id>/gpreport.xml
      3. one {"structure":{...}} line with the domain's scopes of management (the domain,
         every organizational unit, and every site: distinguishedName, gPLink and whether
         inheritance is blocked), the WMI filters with their queries, and, only when a part
         could not be read, "gaps": a list of {"what", "reason"}
      4. an end line {"end":true,"files":N,"sha256":"<hex>"}, where N counts the file
         lines and the hash covers every byte before the end line

    The script changes nothing in Active Directory or in SYSVOL. Backup-GPO reads a GPO
    and writes only into the folder it is given; this script gives it a new folder with a
    random name under $env:TEMP and removes that folder, with every file in it, when the
    GPO has been read, even if something fails. Scopes and WMI filters are read with
    ADSI (no ActiveDirectory module). The script's only other write is the output file,
    which it never overwrites unless -Force is given.

    A GPO that cannot be selected or backed up stops the export: nothing is written for a
    selection error, and no output file is published after a failure. A part of the
    structure that cannot be read (for example the sites container) is not fatal; it is
    named in "gaps" so the comparison can say what it did not compare.

    Rights needed: read access to the GPOs you select (Backup-GPO needs Read on each
    GPO and on its files in SYSVOL; Domain Admins and Group Policy Creator Owners have
    it), and read access to the domain, the Sites container and the WMIPolicy container
    (Authenticated Users have it by default). Needs the GroupPolicy module, which comes
    with the Group Policy Management Tools of RSAT and is present on domain controllers.

    Runs on Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Name
    The display names of the GPOs to export. A name that matches no GPO, or more than
    one, stops the export; use -Guid for the second case. Give exactly one of -Name,
    -Guid and -All.

.PARAMETER Guid
    The GUIDs of the GPOs to export, with or without braces.

.PARAMETER All
    Export every GPO in the domain. The file then says its scope is "all", so a GPO
    missing from a later export counts as deleted.

.PARAMETER Domain
    The domain to read, as a DNS name. Default: the domain of this computer.

.PARAMETER Server
    The domain controller to read from. Default: any controller. When the script runs
    over PowerShell remoting, name the controller the session is on to avoid a second hop.

.PARAMETER OutFile
    The file to write, for example gpos.jsonl.

.PARAMETER Force
    Replace -OutFile if it exists.

.PARAMETER ToPipeline
    Write the lines to the output stream instead of a file. mishpat's remote collection
    uses this.

.EXAMPLE
    .\Export-MishpatGpo.ps1 -All -OutFile corp-gpos.jsonl

.EXAMPLE
    .\Export-MishpatGpo.ps1 -Name 'Workstation Baseline' -OutFile baseline.jsonl
#>
[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [ValidateCount(1, 10000)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Name,
    [ValidateCount(1, 10000)]
    [ValidatePattern('^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$')]
    [string[]] $Guid,
    [switch] $All,
    [string] $Domain,
    [string] $Server,
    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [string] $OutFile,
    [Parameter(ParameterSetName = 'Pipeline')]
    [switch] $ToPipeline,
    [Parameter(ParameterSetName = 'File')]
    [switch] $Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$CollectorName = 'Export-MishpatGpo.ps1'
$CollectorVersion = '0.1.0'
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture

# --- Text and JSON ------------------------------------------------------------------

$JsonPattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '[\x00-\x1f"\\\u007f-\uffff]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$JsonEscape = [System.Text.RegularExpressions.MatchEvaluator] {
    param($Match)
    $c = $Match.Value[0]
    switch ([int] $c) {
        0x22 { return '\"' }
        0x5C { return '\\' }
        0x0A { return '\n' }
        0x0D { return '\r' }
        0x09 { return '\t' }
        default { return '\u' + ([int] $c).ToString('x4', $Invariant) }
    }
}

function ConvertTo-JsonText($Value) {
    # Every character outside printable ASCII is written as \uXXXX, so each line is
    # plain ASCII whatever a name or a filter query holds. An unpaired surrogate stays
    # visible as its own escape.
    if ($null -eq $Value) { return 'null' }
    '"' + $JsonPattern.Replace([string] $Value, $JsonEscape) + '"'
}

function ConvertTo-JsonBool([bool] $Value) {
    if ($Value) { 'true' } else { 'false' }
}

function Get-Text($Value) {
    # A directory attribute that is missing is empty text, never null.
    if ($null -eq $Value) { '' } else { [string] $Value }
}

function Format-UtcTime([datetime] $Time) {
    $Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
}

function Sort-Ordinal($Items, [string] $Property) {
    # Sort objects or hashtables by one text property, by code point, so the file does
    # not depend on the culture of the computer that wrote it. Wrap the call in @().
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Items) { $list.Add($item) }
    $list.Sort([System.Comparison[object]] {
            param($a, $b)
            [string]::CompareOrdinal([string] $a.$Property, [string] $b.$Property)
        })
    $list.ToArray()
}

function ConvertTo-GuidText([string] $Text) {
    # Lower case, no braces: the form mishpat uses everywhere.
    [guid]::Parse($Text.Trim().Trim('{', '}')).ToString('D', $Invariant)
}

function ConvertTo-DnsName([string] $DistinguishedName) {
    # DC=corp,DC=example becomes corp.example.
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($part in ($DistinguishedName -split ',')) {
        if ($part.Trim() -match '^(?i)DC=(.+)$') { $labels.Add($Matches[1]) }
    }
    $labels -join '.'
}

# --- Output -------------------------------------------------------------------------

function New-LineWriter([string] $Path, [bool] $Pipeline) {
    # Writes lines as ASCII with "\n" endings and keeps a running SHA-256 of them.
    # A file is never written under its final name: lines go to a new temporary file
    # next to it, created with CreateNew so it cannot be a file that already exists,
    # and Publish-Output moves it into place only once the end line is written.
    $writer = [pscustomobject] @{
        Stream = $null; Hash = [System.Security.Cryptography.SHA256]::Create()
        Pipeline = $Pipeline; Count = 0; TempPath = $null
    }
    if (-not $Pipeline) {
        $writer.TempPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.part'
        $writer.Stream = New-Object System.IO.FileStream -ArgumentList @(
            $writer.TempPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
    }
    $writer
}

function Write-Line($Writer, [string] $Line, [switch] $Last) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Line + "`n")
    if (-not $Last) { [void] $Writer.Hash.TransformBlock($bytes, 0, $bytes.Length, $null, 0) }
    if ($Writer.Pipeline) { Write-Output $Line } else { $Writer.Stream.Write($bytes, 0, $bytes.Length) }
}

function Get-HashText($Writer) {
    [void] $Writer.Hash.TransformFinalBlock([byte[]] @(), 0, 0)
    -join ($Writer.Hash.Hash | ForEach-Object { $_.ToString('x2', $Invariant) })
}

function Close-LineWriter($Writer) {
    # Safe to call twice: the stream is released the first time.
    if ($null -ne $Writer.Stream) { $Writer.Stream.Flush(); $Writer.Stream.Dispose(); $Writer.Stream = $null }
    $Writer.Hash.Dispose()
}

function Publish-Output($Writer, [string] $Path, [bool] $Replace) {
    # Called after the stream is closed. Without -Force the move fails if the name is
    # taken, even by a file that appeared after the start. With -Force the old file is
    # replaced in one step where the file system allows. File.Move with overwrite is
    # .NET Core 3.0 and later only, and this script must also run on Windows PowerShell
    # 5.1 (.NET Framework), so File.Replace is used when the target exists and a plain
    # move when it does not. Delete-then-move would leave no file at all if it failed
    # in between.
    if ($Replace -and [System.IO.File]::Exists($Path)) {
        # [NullString]::Value, because PowerShell turns a plain $null into "" for a
        # string argument, and "" is refused as the backup name.
        [System.IO.File]::Replace($Writer.TempPath, $Path, [NullString]::Value)
    } else {
        [System.IO.File]::Move($Writer.TempPath, $Path)
    }
}

# --- Directory access ---------------------------------------------------------------
# Everything that talks to Active Directory or to the GroupPolicy module is in the
# small functions of this section, so the tests can replace them. All reads are
# searches and gets; nothing here writes.

function Assert-GroupPolicyModule {
    if (Get-Command -Name Backup-GPO -ErrorAction SilentlyContinue) { return }
    try {
        Import-Module -Name GroupPolicy -ErrorAction Stop
    } catch {
        throw 'The GroupPolicy module is not available. Install the Group Policy Management Tools (RSAT), or run this on a domain controller.'
    }
}

function Get-LdapPath([string] $DistinguishedName) {
    # An ADsPath. A "/" in a distinguished name must be escaped in an ADsPath.
    $where = ''
    if ($Server) { $where = $Server + '/' } elseif ($Domain) { $where = $Domain + '/' }
    'LDAP://' + $where + $DistinguishedName.Replace('/', '\/')
}

function Get-DomainFacts {
    # Returns the domain's and the configuration partition's distinguished names.
    $where = ''
    if ($Server) { $where = $Server + '/' } elseif ($Domain) { $where = $Domain + '/' }
    $root = [adsi] ('LDAP://' + $where + 'RootDSE')
    try {
        [ordered] @{
            DomainDn = [string] $root.Properties['defaultNamingContext'][0]
            ConfigDn = [string] $root.Properties['configurationNamingContext'][0]
        }
    } finally {
        $root.Dispose()
    }
}

function Search-Directory([string] $BaseDn, [string] $Filter, [string[]] $Properties, [string] $Scope) {
    # Returns one hashtable per object found, with every requested property under its
    # lower-case name (the first value as text or number, or $null when absent). A base
    # that does not exist returns nothing. $Scope is Base, OneLevel or Subtree.
    $entry = [adsi] (Get-LdapPath $BaseDn)
    $searcher = [adsisearcher] $Filter
    $found = $null
    try {
        $searcher.SearchRoot = $entry
        $searcher.PageSize = 500
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$Scope
        [void] $searcher.PropertiesToLoad.AddRange($Properties)
        try {
            $found = $searcher.FindAll()
        } catch [System.Runtime.InteropServices.COMException] {
            if ($_.Exception.ErrorCode -eq -2147016656) { return @() }  # no such object
            throw
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($result in $found) {
            $row = @{}
            foreach ($property in $Properties) {
                $values = $result.Properties[$property.ToLowerInvariant()]
                $row[$property.ToLowerInvariant()] = if ($values.Count -gt 0) { $values[0] } else { $null }
            }
            $rows.Add($row)
        }
        , $rows.ToArray()
    } finally {
        if ($null -ne $found) { $found.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Get-GpoCandidates {
    # Every GPO in the domain, as objects with Guid (lower case, no braces) and Name.
    $arguments = @{ All = $true }
    if ($Domain) { $arguments['Domain'] = $Domain }
    if ($Server) { $arguments['Server'] = $Server }
    @(Get-GPO @arguments | ForEach-Object {
            [pscustomobject] @{ Guid = (ConvertTo-GuidText ([string] $_.Id)); Name = [string] $_.DisplayName }
        })
}

# --- Selection ----------------------------------------------------------------------

function Assert-Selection {
    $chosen = 0
    if ($null -ne $Name -and @($Name).Count -gt 0) { $chosen++ }
    if ($null -ne $Guid -and @($Guid).Count -gt 0) { $chosen++ }
    if ($All) { $chosen++ }
    if ($chosen -ne 1) { throw 'Give exactly one of -Name, -Guid and -All.' }
}

function Select-Gpo {
    # Returns the chosen GPOs sorted by GUID. Any name or GUID that does not select
    # exactly one GPO stops the export before anything is written.
    $candidates = @(Get-GpoCandidates)
    $chosen = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    if ($All) {
        if ($candidates.Count -eq 0) { throw 'No GPOs were found in the domain.' }
        foreach ($candidate in $candidates) { $chosen[$candidate.Guid] = $candidate }
    } elseif ($null -ne $Guid -and @($Guid).Count -gt 0) {
        foreach ($text in $Guid) {
            $wanted = ConvertTo-GuidText $text
            $match = @($candidates | Where-Object { $_.Guid -eq $wanted })
            if ($match.Count -eq 0) { throw "No GPO has the GUID $wanted." }
            $chosen[$wanted] = $match[0]
        }
    } else {
        foreach ($text in $Name) {
            $match = @($candidates | Where-Object { [string]::Equals($_.Name, $text, [System.StringComparison]::OrdinalIgnoreCase) })
            if ($match.Count -eq 0) { throw "No GPO is named '$text'." }
            if ($match.Count -gt 1) {
                $guids = @($match | ForEach-Object { $_.Guid }) -join ', '
                throw "More than one GPO is named '$text' ($guids). Use -Guid."
            }
            $chosen[$match[0].Guid] = $match[0]
        }
    }
    Sort-Ordinal $chosen.Values 'Guid'
}

# --- GPO backups --------------------------------------------------------------------

function New-TempFolder {
    $base = $env:TEMP
    if (-not $base) { $base = [System.IO.Path]::GetTempPath() }
    $path = [System.IO.Path]::Combine($base, 'mishpat-' + [guid]::NewGuid().ToString('N'))
    [void] [System.IO.Directory]::CreateDirectory($path)
    $path
}

function Remove-TempFolder([string] $Path) {
    # Never throws: it runs in a finally block and must not hide the error that got
    # us there. A folder that cannot be removed is reported as a warning.
    try {
        if ([System.IO.Directory]::Exists($Path)) {
            foreach ($file in [System.IO.Directory]::GetFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)) {
                [System.IO.File]::SetAttributes($file, [System.IO.FileAttributes]::Normal)
            }
            [System.IO.Directory]::Delete($Path, $true)
        }
    } catch {
        Write-Warning "The temporary folder $Path could not be removed: $($_.Exception.Message)"
    }
}

function Write-BackupFiles($Writer, [string] $Folder) {
    # One bundle line per file under the backup folder, in ordinal order of the
    # relative path written with "/" (so the order is the same on every computer).
    $root = $Folder.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $prefix = [System.IO.Path]::GetFileName($Folder.TrimEnd('\', '/'))
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($path in [System.IO.Directory]::GetFiles($Folder, '*', [System.IO.SearchOption]::AllDirectories)) {
        $relative = $prefix + '/' + $path.Substring($root.Length).Replace('\', '/')
        $entries.Add([pscustomobject] @{ Relative = $relative; Path = $path })
    }
    foreach ($entry in @(Sort-Ordinal $entries 'Relative')) {
        $bytes = [System.IO.File]::ReadAllBytes($entry.Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2', $Invariant) })
        } finally {
            $sha.Dispose()
        }
        Write-Line $Writer ('{"path":' + (ConvertTo-JsonText $entry.Relative) +
            ',"size":' + $bytes.Length.ToString($Invariant) +
            ',"sha256":"' + $digest + '"' +
            ',"data":"' + [System.Convert]::ToBase64String($bytes) + '"}')
        $Writer.Count++
    }
}

function Write-GpoBackup($Writer, [string] $GpoGuid) {
    # Backup-GPO reads the GPO and writes only into the folder it is given. It changes
    # nothing in Active Directory or in SYSVOL. The folder is new, has a random name,
    # and is removed in the finally block. Backup-GPO also writes a manifest.xml next to
    # the backup folder; it is not part of a backup, so it is not exported.
    $temp = New-TempFolder
    try {
        $arguments = @{ Guid = [guid] $GpoGuid; Path = $temp }
        if ($Domain) { $arguments['Domain'] = $Domain }
        if ($Server) { $arguments['Server'] = $Server }
        [void] (Backup-GPO @arguments)
        $folders = @([System.IO.Directory]::GetDirectories($temp))
        if ($folders.Count -ne 1) {
            throw "Backup-GPO did not make exactly one backup folder for the GPO $GpoGuid."
        }
        Write-BackupFiles $Writer $folders[0]
    } finally {
        Remove-TempFolder $temp
    }
}

# --- Structure ----------------------------------------------------------------------

function Add-ScopeRows($Scopes, $Rows, [string] $Kind) {
    foreach ($row in @(Sort-Ordinal $Rows 'distinguishedname')) {
        $options = 0
        if ($null -ne $row['gpoptions']) { $options = [int] $row['gpoptions'] }
        $Scopes.Add('{"path":' + (ConvertTo-JsonText (Get-Text $row['distinguishedname'])) +
            ',"kind":"' + $Kind + '"' +
            ',"blocked":' + (ConvertTo-JsonBool (($options -band 1) -eq 1)) +
            ',"gplink":' + (ConvertTo-JsonText (Get-Text $row['gplink'])) + '}')
    }
}

function Add-Gap($Gaps, [string] $What, $ErrorRecord) {
    $Gaps.Add('{"what":' + (ConvertTo-JsonText $What) +
        ',"reason":' + (ConvertTo-JsonText $ErrorRecord.Exception.Message) + '}')
}

function Get-StructureLine($Facts) {
    # The scopes of management and WMI filters, as one JSON line. A part that cannot
    # be read becomes an entry in "gaps" (a key that is present only then); the rest is
    # still written.
    $props = @('distinguishedName', 'gPLink', 'gPOptions')
    $scopes = New-Object System.Collections.Generic.List[string]
    $filters = New-Object System.Collections.Generic.List[string]
    $gaps = New-Object System.Collections.Generic.List[string]
    $domainDn = $Facts.DomainDn
    try {
        Add-ScopeRows $scopes @(Search-Directory $domainDn '(objectClass=domain)' $props 'Base') 'domain'
    } catch { Add-Gap $gaps 'the domain object (its links and inheritance)' $_ }
    try {
        Add-ScopeRows $scopes @(Search-Directory $domainDn '(objectClass=organizationalUnit)' $props 'Subtree') 'ou'
    } catch { Add-Gap $gaps 'the organizational units (their links and inheritance)' $_ }
    try {
        Add-ScopeRows $scopes @(Search-Directory ('CN=Sites,' + $Facts.ConfigDn) '(objectClass=site)' $props 'OneLevel') 'site'
    } catch { Add-Gap $gaps 'the sites (their links and inheritance)' $_ }
    try {
        $wmi = @('msWMI-ID', 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2')
        $rows = @(Search-Directory ('CN=SOM,CN=WMIPolicy,CN=System,' + $domainDn) '(objectClass=msWMI-Som)' $wmi 'OneLevel')
        foreach ($row in @(Sort-Ordinal $rows 'mswmi-id')) {
            $filters.Add('{"id":' + (ConvertTo-JsonText (Get-Text $row['mswmi-id'])) +
                ',"name":' + (ConvertTo-JsonText (Get-Text $row['mswmi-name'])) +
                ',"description":' + (ConvertTo-JsonText (Get-Text $row['mswmi-parm1'])) +
                ',"query":' + (ConvertTo-JsonText (Get-Text $row['mswmi-parm2'])) + '}')
        }
    } catch { Add-Gap $gaps 'the WMI filters (their queries)' $_ }
    $gapText = ''
    if ($gaps.Count -gt 0) { $gapText = ',"gaps":[' + ($gaps -join ',') + ']' }
    '{"structure":{"scopes":[' + ($scopes -join ',') + '],"wmi_filters":[' + ($filters -join ',') + ']' +
    $gapText + '}}'
}

# --- Export -------------------------------------------------------------------------

function Invoke-Export {
    Assert-Selection
    if (-not $ToPipeline) {
        # .NET resolves a relative path against the process directory, which is not
        # PowerShell's current location; resolve it the way the user sees it.
        $script:OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        if (-not $Force -and [System.IO.File]::Exists($OutFile)) {
            throw "$OutFile already exists. Use -Force to replace it."
        }
    }
    Assert-GroupPolicyModule
    # Everything that can fail on the choice of GPOs happens before a file is made.
    $facts = Get-DomainFacts
    $selected = @(Select-Gpo)
    $writer = New-LineWriter $OutFile ([bool] $ToPipeline)
    $published = $false
    try {
        if ($All) { $scope = '"all"' } else {
            $scope = '[' + ((@($selected | ForEach-Object { '"' + $_.Guid + '"' })) -join ',') + ']'
        }
        $header = '{"mishpat_export":1' +
        ',"collector":{"name":"' + $CollectorName + '","version":"' + $CollectorVersion + '"}' +
        ',"domain":' + (ConvertTo-JsonText (ConvertTo-DnsName $facts.DomainDn)) +
        ',"collected_at":"' + (Format-UtcTime (Get-Date)) + '"' +
        ',"scope":' + $scope + '}'
        Write-Line $writer $header
        foreach ($gpo in $selected) {
            Write-GpoBackup $writer $gpo.Guid
        }
        Write-Line $writer (Get-StructureLine $facts)
        $hash = Get-HashText $writer
        Write-Line $writer ('{"end":true,"files":' + $writer.Count + ',"sha256":"' + $hash + '"}') -Last
        Close-LineWriter $writer
        if (-not $ToPipeline) {
            Publish-Output $writer $OutFile ([bool] $Force)
            $published = $true
        }
    } finally {
        Close-LineWriter $writer
        # Whatever went wrong, OutFile is untouched and no partial file is left.
        if (-not $ToPipeline -and -not $published) { [System.IO.File]::Delete($writer.TempPath) }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Export
}
