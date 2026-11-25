<#
T3 Code lockdown for Windows.
  -Mode Apply|Verify|Rollback   (default Apply)
  -Backend Wsl|Windows          Wsl = desktop on Windows, server in WSL2 (recommended): NO Windows policy file.
                                Windows = server runs natively on Windows: write Windows policy.
  -Organization NAME            policy organization label (default "Local")
Idempotent. Backs up / renames before changing. Never touches firewall, hosts or processes.
Writing or renaming a Windows policy file needs an elevated (Administrator) PowerShell.
Env vars, and a Wsl apply when no Windows policy file is present, do not.
#>
param(
  [ValidateSet('Apply','Verify','Rollback')][string]$Mode = 'Apply',
  [ValidateSet('Wsl','Windows')][string]$Backend = 'Wsl',
  [string]$Organization = 'Local'
)
$ErrorActionPreference = 'Stop'
$PolicyDir  = 'C:\Program Files\T3Code'
$PolicyPath = Join-Path $PolicyDir 'policy.json'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$EnvWanted = [ordered]@{ T3CODE_TELEMETRY_ENABLED = 'false'; T3CODE_OTEL_SDK_DISABLED = 'true' }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$RegKey = 'HKLM:\SOFTWARE\Policies\T3Tools\T3Code'
$script:ExitCode = 0

function New-PolicyJson {
  $obj = [ordered]@{
    schemaVersion = 1
    organization  = $Organization
    limits        = [ordered]@{
      telemetry = $false
      connect   = $false
      updates   = [ordered]@{ mode = 'off' }
    }
  }
  return (($obj | ConvertTo-Json -Depth 8) + "`n")
}

$PolicyJson = New-PolicyJson

function Read-Utf8Text {
  param([string]$Path)
  $text = [IO.File]::ReadAllText($Path)
  if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
  return $text
}

function Test-SamePolicy {
  param([string]$Path, [string]$ExpectedJson)
  if (-not (Test-Path $Path)) { return $false }
  try {
    $a = (Read-Utf8Text $Path) | ConvertFrom-Json
    $b = $ExpectedJson | ConvertFrom-Json
    return ($a.schemaVersion -eq $b.schemaVersion) -and
           ($a.organization -eq $b.organization) -and
           ($a.limits.telemetry -eq $b.limits.telemetry) -and
           ($a.limits.connect -eq $b.limits.connect) -and
           ($a.limits.updates.mode -eq $b.limits.updates.mode)
  } catch { return $false }
}

function Set-UserEnv {
  foreach ($k in $EnvWanted.Keys) {
    $cur = [Environment]::GetEnvironmentVariable($k, 'User')
    if ($cur -eq $EnvWanted[$k]) { Write-Host "[env] $k already $cur (unchanged)" }
    else { [Environment]::SetEnvironmentVariable($k, $EnvWanted[$k], 'User'); Write-Host "[env] $k : '$cur' -> '$($EnvWanted[$k])'" }
  }
}

function Test-NativePolicyConflict {
  # T3 Code refuses to start if a registry/GPO policy AND a policy file both exist (docs/user/managed-policy.md). We never edit the registry.
  if (Test-Path $RegKey) { Write-Warning "[policy] registry/GPO policy exists at $RegKey. Do not add a file policy next to it; do not edit the registry without asking the user." ; return $true }
  return $false
}

function Invoke-T3 {
  param([Parameter(Mandatory = $true)][string[]]$T3Args)
  # Windows PowerShell 5.1 treats native stderr as a terminating NativeCommandError when $ErrorActionPreference is Stop.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & t3 @T3Args 2>&1 | Out-Host
    return $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prev
  }
}

function Set-WindowsPolicy {
  if ($Backend -eq 'Wsl') {
    [void](Test-NativePolicyConflict)
    if (-not (Test-Path $PolicyPath)) {
      Write-Host '[policy] Wsl backend: no Windows policy present (good)'
      return
    }
    # A file is present and must be renamed so the desktop keeps its server in WSL.
    if (-not $IsAdmin) { Write-Warning '[policy] not elevated; re-run in Administrator PowerShell to rename the Windows policy file'; return }
    $dest = "$PolicyPath.disabled-$Stamp"
    Rename-Item -Path $PolicyPath -NewName (Split-Path $dest -Leaf)
    Write-Host "[policy] Wsl backend: renamed Windows policy -> $dest"
    return
  }

  if (Test-NativePolicyConflict) { Write-Warning '[policy] skipped: registry policy already present'; return }
  if (-not $IsAdmin) { Write-Warning '[policy] not elevated; re-run in Administrator PowerShell'; return }
  New-Item -ItemType Directory -Force -Path $PolicyDir | Out-Null
  if (Test-SamePolicy -Path $PolicyPath -ExpectedJson $PolicyJson) { Write-Host "[policy] $PolicyPath already up to date (unchanged)"; return }
  if (Test-Path $PolicyPath) { Copy-Item $PolicyPath "$PolicyPath.bak-$Stamp"; Write-Host "[policy] backup: $PolicyPath.bak-$Stamp" }
  [IO.File]::WriteAllText($PolicyPath, $PolicyJson)   # UTF-8 without BOM
  Write-Host "[policy] wrote $PolicyPath"
}

function Test-Lockdown {
  $bad = 0
  foreach ($k in $EnvWanted.Keys) {
    $cur = [Environment]::GetEnvironmentVariable($k, 'User')
    if ($cur -eq $EnvWanted[$k]) { Write-Host "[ok]   user env $k=$cur" } else { Write-Host "[FAIL] user env $k='$cur'"; $bad = 1 }
  }
  $hasReg = Test-Path $RegKey
  if ($hasReg) { Write-Host "[WARN] registry/GPO policy present at $RegKey (a Windows policy of any kind makes the desktop run its server on Windows, not WSL)" }
  if ($Backend -eq 'Wsl') {
    if ($hasReg) { Write-Host "[FAIL] registry/GPO policy would make the desktop run its server on Windows instead of WSL"; $bad = 1 }
    if (Test-Path $PolicyPath) { Write-Host "[FAIL] Windows policy exists ($PolicyPath): desktop would run server on Windows instead of WSL"; $bad = 1 }
    elseif (-not $hasReg) { Write-Host '[ok]   no Windows policy (server stays in WSL)' }
    Write-Host '[next] run scripts/lockdown.sh inside WSL (apply) to create /etc/t3code/policy.json'
  } else {
    if (Test-Path $PolicyPath) {
      try {
        $p = (Read-Utf8Text $PolicyPath) | ConvertFrom-Json
        if ($p.schemaVersion -eq 1 -and $p.limits.telemetry -eq $false -and $p.limits.connect -eq $false -and $p.limits.updates.mode -eq 'off') { Write-Host "[ok]   policy valid: $PolicyPath" } else { Write-Host '[FAIL] policy content wrong'; $bad = 1 }
      } catch { Write-Host "[FAIL] policy is not valid JSON"; $bad = 1 }
    } else { Write-Host "[FAIL] policy missing: $PolicyPath"; $bad = 1 }
    if (Get-Command t3 -ErrorAction SilentlyContinue) {
      if (Test-Path $PolicyPath) {
        $code = Invoke-T3 -T3Args @('policy', 'check', $PolicyPath)
        if ($code -ne 0) { Write-Host '[FAIL] t3 policy check failed'; $bad = 1 }
      }
      [void](Invoke-T3 -T3Args @('policy', 'show'))
    }
  }
  Write-Host '[note] env vars apply after Windows logoff/login (or new shells) and a T3 Code restart. Ask the user to restart; do not kill processes yourself.'
  $script:ExitCode = $bad
}

function Undo-Lockdown {
  foreach ($k in $EnvWanted.Keys) {
    if ($null -ne [Environment]::GetEnvironmentVariable($k, 'User')) { [Environment]::SetEnvironmentVariable($k, $null, 'User'); Write-Host "[env] removed user env $k" }
  }
  if ($Backend -eq 'Windows') {
    if (-not $IsAdmin) { Write-Warning '[policy] not elevated; policy rollback skipped'; return }
    if (Test-Path $PolicyPath) { Rename-Item $PolicyPath "policy.json.removed-$Stamp"; Write-Host '[policy] moved current policy to policy.json.removed-*' }
    $bak = Get-ChildItem $PolicyDir -Filter 'policy.json.bak-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    # Move (do not copy) so a later rollback can step further back, including to no policy file.
    if ($bak) { Move-Item $bak.FullName $PolicyPath; Write-Host "[policy] restored $($bak.Name)" }
  } else {
    $dis = Get-ChildItem $PolicyDir -Filter 'policy.json.disabled-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($dis -and -not (Test-Path $PolicyPath)) {
      if (-not $IsAdmin) { Write-Warning '[policy] not elevated; policy rollback skipped'; return }
      Move-Item $dis.FullName $PolicyPath; Write-Host "[policy] restored Windows policy from $($dis.Name) (NOTE: server will run on Windows again)"
    }
  }
}

switch ($Mode) {
  'Apply'    { Set-UserEnv; Set-WindowsPolicy; Test-Lockdown; exit $script:ExitCode }
  'Verify'   { Test-Lockdown; exit $script:ExitCode }
  'Rollback' { Undo-Lockdown }
}
