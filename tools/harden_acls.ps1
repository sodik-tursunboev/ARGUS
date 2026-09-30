<#
.SYNOPSIS
    Make ARGUS's security layer unwritable by the account ARGUS runs as.

.DESCRIPTION
    Everything in integrity.py is detection: it tells you a file changed, after
    it changed. This script is the only PREVENTION against a local attacker,
    and it works because of how Windows integrity levels and UAC interact.

    ARGUS runs unelevated. If these files grant Write only to Administrators,
    then even when you are an administrator, the unelevated token ARGUS runs
    with does not have the Administrators group enabled -- so the write fails.
    Elevating to change them is a deliberate, visible act with a UAC prompt,
    which is exactly the property wanted: changing the security layer should
    require more authority than talking to the assistant.

    THE DACL ALONE IS NOT ENOUGH, which earlier versions of this script got
    wrong. Windows gives the OWNER of a file implicit READ_CONTROL and
    WRITE_DAC rights that no DACL -- not even an explicit Deny -- overrides.
    As long as the interactive user still owns these files, a completely
    UNELEVATED process running as that user (the user's own typo, or someone
    else's code that got execution as them -- neither needs to be ARGUS)
    can undo everything above with one command and no UAC prompt:

        icacls auth.py /grant "you:(M)"

    That is not a hypothetical; it was verified against a file this script had
    just hardened. So hardening now also moves OWNERSHIP to Administrators.
    That single change is what makes reclaiming write access require the same
    elevation this script itself requires -- an icacls /grant from an
    unelevated shell fails outright once the invoking user is no longer the
    owner, rather than quietly succeeding because they always were.

    This does NOT stop malware that can elevate. Nothing running as an
    unprivileged user can stop that, and a script claiming to would be lying.

    THE FILE LIST IS NOT WRITTEN HERE. It is read from integrity.py at run
    time. The previous version kept its own copy of the eight critical files
    and fell five behind as the security layer grew -- settings.py (which
    decides what the settings panel may change), plugins.py, netpolicy.py,
    voiceauth.py and manage_secrets.py were all left writable while this
    script reported success. A hardening tool that silently protects less
    than it claims is worse than none, because it stops anyone looking.

.PARAMETER Revert
    Restore inherited permissions (undo). Do this before applying an update.

.PARAMETER App
    Harden a BUILT app folder (dist\ARGUS) instead of the source tree. The
    packaged app is the thing most installs actually run, and its _internal
    folder holds the HUD, intent.py and every skill as plain editable text.

.EXAMPLE
    # From an ELEVATED PowerShell:
    .\harden_acls.ps1                      # the source tree
    .\harden_acls.ps1 -App ..\dist\ARGUS   # a built app
    .\harden_acls.ps1 -Revert
#>

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

[CmdletBinding()]
param(
    [switch]$Revert,
    [string]$App = ''
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Elevated)) {
    Write-Error "This must run from an ELEVATED PowerShell (Run as Administrator)."
    exit 1
}

# ---- work out what to protect -----------------------------------------
if ($App) {
    # A built app: the exe plus everything in _internal that is plain text or
    # is the interpreter itself. Derived by walking the folder, because the
    # payload layout is PyInstaller's to decide, not ours.
    $Target = (Resolve-Path $App).Path
    if (-not (Test-Path (Join-Path $Target '_internal'))) {
        Write-Error "$Target does not look like a built ARGUS app (no _internal)."
        exit 1
    }
    $Files = @()
    $Files += Get-ChildItem -Path $Target -Filter '*.exe' -File |
              ForEach-Object { $_.FullName }
    $inner = Join-Path $Target '_internal'
    $Files += Get-ChildItem -Path $inner -File |
              Where-Object { $_.Name -like 'python*.dll' -or
                             $_.Name -eq 'base_library.zip' } |
              ForEach-Object { $_.FullName }
    foreach ($rel in @('intent.py', 'hud\index.html')) {
        $p = Join-Path $inner $rel
        if (Test-Path $p) { $Files += $p }
    }
    $skills = Join-Path $inner 'skills'
    if (Test-Path $skills) {
        $Files += Get-ChildItem -Path $skills -Filter '*.py' -File |
                  ForEach-Object { $_.FullName }
    }
}
else {
    # The source tree. Ask integrity.py which files are CRITICAL rather than
    # keeping a second copy of the list here -- see the note above.
    $Target = $Root
    $py = Join-Path $Root 'venv\Scripts\python.exe'
    if (-not (Test-Path $py)) { $py = 'python' }

    $listing = & $py -c "import sys; sys.path.insert(0, r'$Root'); import integrity; print('\n'.join(integrity.CRITICAL))" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $listing) {
        Write-Error "Could not read integrity.CRITICAL. Is the venv intact? Refusing to guess the file list."
        exit 1
    }
    $Files = @()
    foreach ($name in ($listing -split "`r?`n" | Where-Object { $_.Trim() })) {
        $p = Join-Path $Root $name.Trim()
        if (Test-Path $p) { $Files += $p }
        else { Write-Warning "skip (missing): $($name.Trim())" }
    }
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Target     : $Target"
Write-Host "Running as : $me (elevated)"
Write-Host "Files      : $($Files.Count)"
Write-Host ""

if ($Files.Count -eq 0) {
    Write-Error "Nothing to process."
    exit 1
}

$done = 0
$failed = @()
foreach ($path in $Files) {
    $name = Split-Path -Leaf $path
    try {
        if ($Revert) {
            # Ownership back to the interactive user FIRST. /reset alone would
            # leave Administrators as the owner even after inheritance is
            # restored -- not the pre-hardening state, and it would leave a
            # future -Revert (or a plain edit) needing elevation for a reason
            # the operator never asked for. Can only be done elevated, which
            # -Revert already requires exactly like hardening does.
            & icacls $path /setowner $me 2>$null | Out-Null
            # Re-enable inheritance and drop the explicit entries this added.
            & icacls $path /reset | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls /reset returned $LASTEXITCODE" }
            Write-Host "  reverted  $name"
        }
        else {
            # /inheritance:r  drop inherited ACEs (the user's Modify right comes
            #                 from the parent folder -- without this, everything
            #                 below is decorative)
            # Administrators + SYSTEM keep full control so the app can be updated
            # and repaired; the interactive user is granted Read+Execute only.
            & icacls $path /inheritance:r | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls /inheritance:r returned $LASTEXITCODE" }
            & icacls $path /grant:r '*S-1-5-32-544:(F)' | Out-Null   # Administrators
            & icacls $path /grant:r '*S-1-5-18:(F)'     | Out-Null   # SYSTEM
            & icacls $path /grant:r "${me}:(RX)"        | Out-Null   # this user: read+execute
            if ($LASTEXITCODE -ne 0) { throw "icacls /grant returned $LASTEXITCODE" }
            # OWNERSHIP, not just the DACL -- see the script header. Last, so a
            # failure here still leaves the DACL step's protection in place
            # rather than an all-or-nothing ordering that risks neither landing.
            # SeRestorePrivilege is live in THIS elevated session, which is
            # exactly what lets it succeed here and nowhere else.
            & icacls $path /setowner '*S-1-5-32-544' | Out-Null   # BUILTIN\Administrators
            if ($LASTEXITCODE -ne 0) { throw "icacls /setowner returned $LASTEXITCODE" }
            Write-Host "  hardened  $name"
        }
        $done++
    }
    catch {
        # Report per file rather than aborting: a partial result the operator
        # can see beats a stack trace halfway through with no summary of what
        # did and did not get applied.
        Write-Warning "  FAILED    $name -- $_"
        $failed += $name
    }
}

Write-Host ""
Write-Host "$done file(s) processed."
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) FAILED: $($failed -join ', ')" -ForegroundColor Red
}
if (-not $Revert -and -not $App) {
    Write-Host ""
    Write-Host "Verify from an UNELEVATED shell:" -ForegroundColor Cyan
    Write-Host "    venv\Scripts\python.exe -c `"import integrity; print(integrity.acls_hardened())`""
    Write-Host "Expected: (True, 'security files are read-only to this account')"
    Write-Host ""
    Write-Host "NOTE: editing these files now requires an elevated editor." -ForegroundColor Yellow
    Write-Host "      Re-run with -Revert before applying an update."
}
if ($failed.Count -gt 0) { exit 1 }
