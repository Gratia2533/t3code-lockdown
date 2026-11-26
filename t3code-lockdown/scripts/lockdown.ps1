<#
T3 Code lockdown for Windows (PowerShell 5.1+ / 7+).
  -Mode Apply|Verify|Rollback|Snapshot  (default Apply)
  -Backend Wsl|Windows                  Wsl = desktop on Windows, server in WSL2 (recommended): NO Windows policy file.
                                        Windows = server runs natively on Windows: write Windows policy.
  -Profile Standard|Strict              Lockdown profile from references/baseline.json (default Standard).
  -Organization NAME                    Policy organization label (default "Local").
  -T3Bin PATH                           Optional explicit path to t3 executable.
  -CheckWsl                             For -Backend Wsl, also run lockdown.sh verify inside WSL for a full verdict.
  -Json                                 Emit machine-readable JSON report to stdout.

Exit codes (Apply / Verify):
  0  = VERIFIED        (all static, runtime, process, and drift checks passed)
  1  = FAIL            (missing/wrong config, conflict, or forbidden process)
  10 = PENDING_RESTART (disk config valid, but T3 Code not running or needs restart/re-login)
  20 = DRIFT_DETECTED  (unaudited T3 Code version or policy schema/CLI drift detected)
  30 = INCOMPLETE      (required verifier/t3 binary unavailable, or WSL side not checked yet)

Idempotent. Backs up / renames before changing. Never touches firewall, hosts, or processes.
#>
[CmdletBinding()]
param(
  [ValidateSet('Apply','Verify','Rollback','Snapshot')][string]$Mode = 'Apply',
  [ValidateSet('Wsl','Windows')][string]$Backend = 'Wsl',
  [ValidateSet('Standard','Strict')][string]$Profile = 'Standard',
  [string]$Organization = 'Local',
  [string]$T3Bin = '',
  [string]$BaselinePath = '',
  [string]$PolicyPath = 'C:\Program Files\T3Code\policy.json',
  [string]$T3Home = '',
  [switch]$AllowUnvalidatedPolicy,
  [switch]$CheckWsl,
  [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SkillRoot = Split-Path -Parent $ScriptDir
. (Join-Path $ScriptDir 'audit_windows.ps1')

if ([string]::IsNullOrWhiteSpace($BaselinePath)) { $BaselinePath = Join-Path $SkillRoot 'references\baseline.json' }
if ([string]::IsNullOrWhiteSpace($T3Home)) { $T3Home = if ($env:T3CODE_HOME) { $env:T3CODE_HOME } else { Join-Path $HOME '.t3' } }

$PolicyDir = Split-Path -Parent $PolicyPath
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RegKey = 'HKLM:\SOFTWARE\Policies\T3Tools\T3Code'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ProfileKey = $Profile.ToLowerInvariant()
$AppliedActions = New-Object System.Collections.Generic.List[string]
$script:ExitCode = 0

$VerdictPriority = @{ 'VERIFIED' = 0; 'PENDING_RESTART' = 1; 'INCOMPLETE' = 2; 'DRIFT_DETECTED' = 3; 'FAIL' = 4 }
$ManualChecks = @(
  'iOS app: Settings -> About T3 Code -> Diagnostics -> disable Send crash reports & Send connection traces.',
  'Host app: Settings -> Sharing & access -> confirm Publish agent activity is OFF.',
  'Browser: avoid app.t3.codes hosted web client (use local desktop or Tailscale directly).'
)

if (-not (Test-Path -LiteralPath $BaselinePath)) { Write-Error "Missing baseline reference file: $BaselinePath"; exit 1 }
$Baseline = (Read-Utf8Text $BaselinePath) | ConvertFrom-Json
$EnvWanted = ConvertTo-Hashtable $Baseline.requiredEnv
$ProfileSpec = ConvertTo-Hashtable ($Baseline.profiles.$ProfileKey)
if ($null -eq $ProfileSpec) { Write-Error "Profile '$ProfileKey' not found in baseline: $BaselinePath"; exit 2 }

function Log-Action {
  param([string]$Message)
  $AppliedActions.Add($Message)
  if (-not $Json) { Write-Host $Message }
}

function Set-UserEnv {
  foreach ($k in $EnvWanted.Keys) {
    $cur = [Environment]::GetEnvironmentVariable($k, 'User')
    if ($cur -eq $EnvWanted[$k]) { Log-Action "[env] $k already $cur (unchanged)" }
    else { [Environment]::SetEnvironmentVariable($k, $EnvWanted[$k], 'User'); Log-Action "[env] $k : '$cur' -> '$($EnvWanted[$k])'" }
  }
}

function Set-WindowsPolicy {
  if ($Backend -eq 'Wsl') {
    if (Test-Path $RegKey) { Log-Action "[policy] WARNING: registry/GPO policy exists at $RegKey (not modified; server will run on Windows instead of WSL)" }
    if (-not (Test-Path -LiteralPath $PolicyPath)) { Log-Action '[policy] Wsl backend: no Windows policy present (good)'; return }
    if (-not $IsAdmin) { Log-Action '[policy] WARNING: not elevated; re-run in Administrator PowerShell to rename Windows policy file'; return }
    $dest = "$PolicyPath.disabled-$Stamp"
    Rename-Item -LiteralPath $PolicyPath -NewName (Split-Path $dest -Leaf)
    Log-Action "[policy] Wsl backend: renamed Windows policy -> $dest"
    return
  }

  if (Test-Path $RegKey) { Log-Action "[policy] SKIPPED: registry/GPO policy already exists at $RegKey (coexistence breaks T3 Code startup)"; return }
  if (-not $IsAdmin) { Log-Action '[policy] WARNING: not elevated; re-run in Administrator PowerShell to write Windows policy'; return }

  $expectedJson = New-PolicyJson -BaselineObj $Baseline -ProfileSpecObj $ProfileSpec -OrgName $Organization
  $tmpFile = Join-Path ([IO.Path]::GetTempPath()) ("t3-policy-" + [Guid]::NewGuid().ToString('N') + '.json')
  Write-Utf8NoBom -Path $tmpFile -Content $expectedJson
  try {
    $exe = Find-T3Binary -ExplicitBin $T3Bin -HomeDir $T3Home
    if ($exe) {
      $chk = Invoke-NativeCapture -Exe $exe -Arguments @('policy', 'check', $tmpFile)
      if ($chk.exitCode -ne 0) { Log-Action "[policy] ABORTED: 't3 policy check' rejected generated '$ProfileKey' policy (not written)"; return }
    } elseif (-not $AllowUnvalidatedPolicy) {
      Log-Action '[policy] ABORTED: t3 binary not found; refusing to write unvalidated policy (pass -T3Bin PATH or -AllowUnvalidatedPolicy to override)'
      return
    } else {
      Log-Action "[policy] WARNING: t3 binary not found; writing policy without 't3 policy check' (-AllowUnvalidatedPolicy)"
    }
    New-Item -ItemType Directory -Force -Path $PolicyDir | Out-Null
    if (Test-Path -LiteralPath $PolicyPath) {
      if ((Read-Utf8Text $PolicyPath).Trim() -eq $expectedJson.Trim()) { Log-Action "[policy] $PolicyPath already up to date for '$ProfileKey' profile (unchanged)"; return }
      Copy-Item -LiteralPath $PolicyPath -Destination "$PolicyPath.bak-$Stamp"
      Log-Action "[policy] backup: $PolicyPath.bak-$Stamp"
    }
    Write-Utf8NoBom -Path $PolicyPath -Content $expectedJson
    Log-Action "[policy] wrote $PolicyPath (profile: $ProfileKey, org: $Organization)"
  } finally {
    Remove-Item -LiteralPath $tmpFile -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-LockdownVerify {
  $checks = New-Object System.Collections.Generic.List[object]
  function Add-Check {
    param([string]$Id, [string]$Category, [string]$Status, [string]$Message, $Details = $null)
    $item = [ordered]@{ id = $Id; category = $Category; status = $Status; message = $Message }
    if ($null -ne $Details) { $item['details'] = $Details }
    $checks.Add($item)
  }

  # --- 1. STATIC CHECKS ---
  foreach ($k in $EnvWanted.Keys) {
    $want = $EnvWanted[$k]
    $userVal = [Environment]::GetEnvironmentVariable($k, 'User')
    $procVal = [Environment]::GetEnvironmentVariable($k, 'Process')
    $machVal = [Environment]::GetEnvironmentVariable($k, 'Machine')
    if ($userVal -eq $want) {
      Add-Check "env.user:$k" 'static' 'PASS' "User env $k=$userVal"
      if (-not [string]::IsNullOrEmpty($procVal) -and $procVal -ne $want) {
        Add-Check "env.process:$k" 'static' 'FAIL' "Current process env overrides $k='$procVal' (expected '$want')."
      } elseif ([string]::IsNullOrEmpty($procVal)) {
        Add-Check "env.process:$k" 'static' 'PENDING_RESTART' "Current session has not picked up $k yet (re-login / restart T3 Code)."
      }
    } else {
      Add-Check "env.user:$k" 'static' 'FAIL' "User env $k='$userVal' (expected '$want')."
    }
    if (-not [string]::IsNullOrEmpty($machVal) -and $machVal -ne $want) {
      Add-Check "env.machine:$k" 'static' 'INFO' "Machine env $k='$machVal' differs (User env overrides for interactive sessions, but Windows services read Machine env)."
    }
  }

  $hasReg = Test-Path $RegKey
  $hasFile = Test-Path -LiteralPath $PolicyPath

  if ($Backend -eq 'Wsl') {
    if ($hasReg) { Add-Check 'conflict.windows_reg' 'static' 'FAIL' "Registry/GPO policy exists at $RegKey; desktop will run server on Windows instead of WSL." }
    else { Add-Check 'conflict.windows_reg' 'static' 'PASS' 'No Windows registry/GPO policy present.' }
    if ($hasFile) { Add-Check 'conflict.windows_file' 'static' 'FAIL' "Windows policy file exists ($PolicyPath); desktop will run server on Windows instead of WSL." }
    else { Add-Check 'conflict.windows_file' 'static' 'PASS' 'No Windows policy file (server stays in WSL).' }
  } else {
    if ($hasReg -and $hasFile) { Add-Check 'conflict.windows_reg' 'static' 'FAIL' "Registry/GPO ($RegKey) AND file policy ($PolicyPath) both exist; T3 Code refuses to start." }
    elseif ($hasReg) { Add-Check 'conflict.windows_reg' 'static' 'INFO' "Registry/GPO policy present at $RegKey (managed externally)." }
    else { Add-Check 'conflict.windows_reg' 'static' 'PASS' 'No conflicting Windows registry/GPO policy.' }

    if (-not $hasFile) {
      Add-Check 'policy.file' 'static' 'FAIL' "Policy file missing: $PolicyPath"
    } else {
      try {
        $pObj = (Read-Utf8Text $PolicyPath) | ConvertFrom-Json
        $mismatches = New-Object System.Collections.Generic.List[string]
        if ([int]$pObj.schemaVersion -ne [int]$Baseline.policySchemaVersion) { $mismatches.Add("schemaVersion: expected $($Baseline.policySchemaVersion), got $($pObj.schemaVersion)") }
        if ([string]::IsNullOrWhiteSpace([string]$pObj.organization)) { $mismatches.Add('organization: must be non-empty') }
        foreach ($m in (Compare-DeepSubset -Actual $pObj.limits -Expected $ProfileSpec['limits'] -Prefix 'limits')) { $mismatches.Add($m) }
        if ($ProfileSpec.Contains('settings') -and $ProfileSpec['settings'] -and $ProfileSpec['settings'].Count -gt 0) {
          $actSettings = if ($pObj.PSObject.Properties['settings']) { $pObj.settings } else { $null }
          foreach ($m in (Compare-DeepSubset -Actual $actSettings -Expected $ProfileSpec['settings'] -Prefix 'settings')) { $mismatches.Add($m) }
        }
        if ($mismatches.Count -gt 0) { Add-Check 'policy.file' 'static' 'FAIL' "Policy content does not satisfy '$ProfileKey' profile: $PolicyPath" @{ mismatches = @($mismatches.ToArray()) } }
        else { Add-Check 'policy.file' 'static' 'PASS' "Policy content satisfies '$ProfileKey' profile: $PolicyPath" }
      } catch {
        Add-Check 'policy.file' 'static' 'FAIL' "Policy file is not valid JSON: $($_.Exception.Message)"
      }
    }

    $settingsPath = Join-Path $T3Home 'userdata\settings.json'
    if (Test-Path -LiteralPath $settingsPath) {
      try {
        $uSet = ConvertTo-Hashtable ((Read-Utf8Text $settingsPath) | ConvertFrom-Json)
        $badAlways = @($Baseline.forbiddenUserSettings.always | Where-Object { $uSet.Contains($_) -and $uSet[$_] -eq $true })
        $badStrict = @($Baseline.forbiddenUserSettings.strictOnly | Where-Object { $uSet.Contains($_) -and $uSet[$_] -eq $true })
        if ($badAlways.Count -gt 0) { Add-Check 'settings.user_file' 'static' 'FAIL' "Privacy-sensitive setting enabled in $($settingsPath): $($badAlways -join ', ')" }
        elseif ($ProfileKey -eq 'strict' -and $badStrict.Count -gt 0) { Add-Check 'settings.user_file' 'static' 'FAIL' "Strict-profile forbidden setting enabled in $($settingsPath): $($badStrict -join ', ')" }
        else { Add-Check 'settings.user_file' 'static' 'PASS' "User settings clean: $settingsPath" }
      } catch {
        Add-Check 'settings.user_file' 'static' 'INCOMPLETE' "Unable to parse $($settingsPath): $($_.Exception.Message)"
      }
    } else {
      Add-Check 'settings.user_file' 'static' 'INFO' "No user settings file yet at $settingsPath."
    }
  }

  # --- 2. NETWORK / PROCESS AUDIT (READ-ONLY) ---
  $cfProcs = @(Get-Process -Name 'cloudflared' -ErrorAction SilentlyContinue)
  if ($cfProcs.Count -gt 0) {
    $ids = ($cfProcs | ForEach-Object { "pid=$($_.Id)" }) -join ', '
    Add-Check 'network.forbidden_processes' 'network' 'FAIL' "Forbidden tunnel process 'cloudflared' detected on Windows ($ids); not killed."
  } else {
    Add-Check 'network.forbidden_processes' 'network' 'PASS' 'No cloudflared tunnel process running on Windows.'
  }

  # --- 3. RUNTIME & DRIFT CHECKS ---
  $t3Exe = $null
  $runningVersion = $null
  $drift = [ordered]@{ auditedVersions = @($Baseline.auditedVersions); installedVersion = $null; runningVersion = $null; versionDrift = @(); schemaChanged = $false; cliChanged = $false; detected = $false }

  if ($Backend -eq 'Wsl') {
    if ($CheckWsl) {
      $wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
      if (-not $wslCmd) {
        Add-Check 'runtime.wsl_audit' 'runtime' 'INCOMPLETE' 'wsl.exe not found; cannot audit WSL backend from Windows.'
      } else {
        $unixScript = (Join-Path $ScriptDir 'lockdown.sh') -replace '\\', '/'
        $wslPathRes = Invoke-NativeCapture -Exe $wslCmd.Source -Arguments @('wslpath', '-a', $unixScript)
        if ($wslPathRes.exitCode -ne 0) {
          Add-Check 'runtime.wsl_audit' 'runtime' 'INCOMPLETE' "Failed to translate script path for WSL: $($wslPathRes.output.Trim())"
        } else {
          $wslRes = Invoke-NativeCapture -Exe $wslCmd.Source -Arguments @('bash', $wslPathRes.output.Trim(), 'verify', '--profile', $ProfileKey, '--json')
          try {
            $wslReport = $wslRes.output | ConvertFrom-Json
            $wslVerdict = [string]$wslReport.verdict
            $drift = ConvertTo-Hashtable $wslReport.drift
            $runningVersion = $wslReport.runningVersion
            Add-Check 'runtime.wsl_audit' 'runtime' $wslVerdict "WSL backend audit verdict: $wslVerdict (exit $($wslReport.exitCode))" @{ wslChecks = $wslReport.checks }
          } catch {
            Add-Check 'runtime.wsl_audit' 'runtime' 'INCOMPLETE' "Could not parse WSL audit JSON output (exit $($wslRes.exitCode))."
          }
        }
      }
    } else {
      Add-Check 'runtime.wsl_audit' 'runtime' 'INCOMPLETE' 'Windows host side checked, but WSL backend policy/runtime/drift NOT audited yet. Run lockdown.sh verify inside WSL (or pass -CheckWsl).'
    }
  } else {
    $t3Exe = Find-T3Binary -ExplicitBin $T3Bin -HomeDir $T3Home
    $installedFp = $null
    if (-not $t3Exe) {
      Add-Check 'cli.discovery' 'runtime' 'INCOMPLETE' 't3 CLI binary not found (pass -T3Bin). Cannot run policy check, status, or drift detection.'
    } else {
      Add-Check 'cli.discovery' 'runtime' 'PASS' "Found t3 CLI: $t3Exe"

      if ($hasFile) {
        $chk = Invoke-NativeCapture -Exe $t3Exe -Arguments @('policy', 'check', $PolicyPath)
        if ($chk.exitCode -ne 0) { Add-Check 'policy.cli_check' 'runtime' 'FAIL' "t3 policy check failed for $PolicyPath" @{ output = $chk.output.Trim() } }
        else {
          if ($chk.output -match 'fingerprint\s+([0-9A-Za-z_-]+)') { $installedFp = $Matches[1] }
          Add-Check 'policy.cli_check' 'runtime' 'PASS' "t3 policy check passed (fingerprint: $(if ($installedFp) { $installedFp } else { 'unknown' }))."
        }
      }

      $show = Invoke-NativeCapture -Exe $t3Exe -Arguments @('policy', 'show', '--base-dir', $T3Home)
      if ($show.exitCode -ne 0) { Add-Check 'runtime.policy_show' 'runtime' 'INCOMPLETE' "t3 policy show exited $($show.exitCode)." }
      elseif ($show.output -match '(?i)Restart T3 Code to apply') { Add-Check 'runtime.policy_show' 'runtime' 'PENDING_RESTART' 'Running server has NOT loaded the latest installed policy yet (restart required).' }
      elseif ($show.output -match '(?i)loaded this policy') {
        $showFp = if ($show.output -match 'fingerprint\s+([0-9A-Za-z_-]+)') { $Matches[1] } else { $null }
        if ($installedFp -and $showFp -and $installedFp -ne $showFp) { Add-Check 'runtime.policy_show' 'runtime' 'PENDING_RESTART' "Policy fingerprint mismatch (installed=$installedFp, show=$showFp)." }
        else { Add-Check 'runtime.policy_show' 'runtime' 'PASS' "Running server loaded the installed policy (fingerprint: $(if ($showFp) { $showFp } else { 'verified' }))." }
      } else { Add-Check 'runtime.policy_show' 'runtime' 'PENDING_RESTART' 'No running T3 Code server detected by t3 policy show (start/restart T3 Code and re-verify).' }

      $st = Invoke-NativeCapture -Exe $t3Exe -Arguments @('status', '--base-dir', $T3Home)
      if ($st.exitCode -ne 0) { Add-Check 'runtime.t3_status' 'runtime' 'INCOMPLETE' "t3 status exited $($st.exitCode)." }
      elseif ($st.output -match '(?i)T3 Connect\s+(\S+)') {
        $connVal = $Matches[1].Trim()
        if ($connVal.ToLowerInvariant() -eq 'off') { Add-Check 'runtime.t3_status' 'runtime' 'PASS' 't3 status confirms T3 Connect is off.' }
        else { Add-Check 'runtime.t3_status' 'runtime' 'FAIL' "t3 status reports T3 Connect is NOT off: $connVal" }
      } else { Add-Check 'runtime.t3_status' 'runtime' 'INCOMPLETE' "Could not parse 'T3 Connect' from t3 status." }

      $rtPath = Join-Path $T3Home 'userdata\server-runtime.json'
      if (-not (Test-Path -LiteralPath $rtPath)) {
        Add-Check 'runtime.server_json' 'runtime' 'PENDING_RESTART' "No active server metadata at $rtPath."
      } else {
        try {
          $rt = (Read-Utf8Text $rtPath) | ConvertFrom-Json
          $runningVersion = [string]$rt.serverVersion
          $alive = $null -ne (Get-Process -Id ([int]$rt.pid) -ErrorAction SilentlyContinue)
          if (-not $alive) { Add-Check 'runtime.server_json' 'runtime' 'PENDING_RESTART' "Server PID $($rt.pid) in server-runtime.json is not running." }
          else {
            $mpFp = if ($rt.PSObject.Properties['managedPolicy'] -and $rt.managedPolicy) { [string]$rt.managedPolicy.fingerprint } else { '' }
            if ([string]::IsNullOrWhiteSpace($mpFp)) { Add-Check 'runtime.server_json' 'runtime' 'PENDING_RESTART' "Running server (pid $($rt.pid)) has no managedPolicy loaded." }
            elseif ($installedFp -and $mpFp -ne $installedFp) { Add-Check 'runtime.server_json' 'runtime' 'PENDING_RESTART' "Running server fingerprint $mpFp != installed $installedFp." }
            else { Add-Check 'runtime.server_json' 'runtime' 'PASS' "Running server (pid $($rt.pid), v$runningVersion) loaded policy fingerprint $mpFp." }
          }
        } catch { Add-Check 'runtime.server_json' 'runtime' 'INCOMPLETE' "Failed to parse $($rtPath): $($_.Exception.Message)" }
      }

      $snap = Get-T3Snapshot -ExePath $t3Exe
      $drift = Compute-Drift -BaselineObj $Baseline -Snap $snap -RunningVersion $runningVersion
      if ([string]::IsNullOrWhiteSpace($snap.version)) { Add-Check 'drift.version' 'drift' 'INCOMPLETE' "Could not parse version from t3 --version: '$($snap.rawVersion)'" }
      elseif (@($drift.versionDrift).Count -gt 0) { Add-Check 'drift.version' 'drift' 'DRIFT_DETECTED' "Unaudited T3 Code version detected ($($drift.versionDrift -join ', '); audited: $($drift.auditedVersions -join ', '))." $drift }
      else { Add-Check 'drift.version' 'drift' 'PASS' "T3 Code version $($snap.version) matches audited baseline." }

      if ($null -eq $snap.admxPolicies) { Add-Check 'drift.policy_schema' 'drift' 'INCOMPLETE' "Unable to inspect ADMX policy schema: $($snap.admxError)" }
      elseif ($drift.schemaChanged) { Add-Check 'drift.policy_schema' 'drift' 'DRIFT_DETECTED' 'Live T3 Code policy schema differs from audited baseline!' $drift }
      else { Add-Check 'drift.policy_schema' 'drift' 'PASS' 'Live ADMX policy schema matches audited baseline.' }

      if ($null -eq $snap.cliSubcommands -or $null -eq $snap.policySubcommands) { Add-Check 'drift.cli_surface' 'drift' 'INCOMPLETE' 'Could not parse t3 --help / policy --help subcommands.' }
      elseif ($drift.cliChanged) { Add-Check 'drift.cli_surface' 'drift' 'DRIFT_DETECTED' 'New T3 CLI subcommands detected outside audited baseline.' $drift }
      else { Add-Check 'drift.cli_surface' 'drift' 'PASS' 'T3 CLI subcommands match audited baseline.' }
    }
  }

  # --- AGGREGATE VERDICT ---
  $verdict = 'VERIFIED'
  foreach ($c in $checks) {
    $s = [string]$c.status
    if ($VerdictPriority.ContainsKey($s) -and $VerdictPriority[$s] -gt $VerdictPriority[$verdict]) { $verdict = $s }
  }
  $script:ExitCode = [int]($Baseline.exitCodes.$verdict)

  $reportPolicyPath = if ($Backend -eq 'Windows') { $PolicyPath } else { $null }
  $report = [ordered]@{
    verdict              = $verdict
    exitCode             = $script:ExitCode
    safeToClaimLocked    = ($verdict -eq 'VERIFIED')
    backend              = $Backend
    profile              = $ProfileKey
    platform             = 'Windows'
    policyPath           = $reportPolicyPath
    t3Binary             = $t3Exe
    installedVersion     = $drift.installedVersion
    runningVersion       = $runningVersion
    auditedVersions      = @($Baseline.auditedVersions)
    drift                = $drift
    appliedActions       = @($AppliedActions.ToArray())
    checks               = @($checks.ToArray())
    manualChecksRequired = $ManualChecks
  }

  if ($Json) {
    Write-Output ($report | ConvertTo-Json -Depth 12)
  } else {
    $tagMap = @{ 'PASS' = '[PASS]      '; 'FAIL' = '[FAIL]      '; 'PENDING_RESTART' = '[PENDING]   '; 'DRIFT_DETECTED' = '[DRIFT]     '; 'INCOMPLETE' = '[INCOMPLETE]'; 'INFO' = '[INFO]      ' }
    foreach ($sec in @(@('static','STATIC CONFIG'), @('runtime','LIVE RUNTIME'), @('network','NETWORK / PROCESS (READ-ONLY)'), @('drift','UPDATE DRIFT DETECTION'))) {
      $items = @($checks | Where-Object { $_.category -eq $sec[0] })
      if ($items.Count -eq 0) { continue }
      Write-Host "=== $($sec[1]) ==="
      foreach ($it in $items) { Write-Host "  $($tagMap[$it.status]) $($it.message)" }
      Write-Host ''
    }
    Write-Host '=== VERDICT ==='
    Write-Host "  Verdict:           $verdict (exit $($script:ExitCode))"
    Write-Host "  Safe to claim ok:  $(if ($verdict -eq 'VERIFIED') { 'YES' } else { 'NO' })"
    Write-Host "  Backend / Profile: $Backend / $ProfileKey"
    Write-Host '  Manual-only reminders (not enforced by host scripts):'
    foreach ($m in $ManualChecks) { Write-Host "    - $m" }
  }
}

function Invoke-Snapshot {
  $exe = Find-T3Binary -ExplicitBin $T3Bin -HomeDir $T3Home
  if (-not $exe) {
    $script:ExitCode = [int]$Baseline.exitCodes.INCOMPLETE
    Write-Output ([ordered]@{ error = 't3 CLI binary not found'; verdict = 'INCOMPLETE' } | ConvertTo-Json -Depth 6)
    return
  }
  $snap = Get-T3Snapshot -ExePath $exe
  $snap['diffAgainstBaseline'] = Compute-Drift -BaselineObj $Baseline -Snap $snap -RunningVersion $null
  $script:ExitCode = 0
  Write-Output ($snap | ConvertTo-Json -Depth 10)
}

function Undo-Lockdown {
  foreach ($k in $EnvWanted.Keys) {
    if ($null -ne [Environment]::GetEnvironmentVariable($k, 'User')) {
      [Environment]::SetEnvironmentVariable($k, $null, 'User')
      Write-Host "[env] removed user env $k"
    }
  }
  if ($Backend -eq 'Windows') {
    if (-not $IsAdmin) { Write-Warning '[policy] not elevated; policy rollback skipped'; return }
    if (Test-Path -LiteralPath $PolicyPath) { Rename-Item -LiteralPath $PolicyPath -NewName "policy.json.removed-$Stamp"; Write-Host "[policy] moved current policy to policy.json.removed-$Stamp" }
    $bak = Get-ChildItem $PolicyDir -Filter 'policy.json.bak-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($bak) { Move-Item -LiteralPath $bak.FullName -Destination $PolicyPath; Write-Host "[policy] restored $($bak.Name)" }
  } else {
    $dis = Get-ChildItem $PolicyDir -Filter 'policy.json.disabled-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
    if ($dis -and -not (Test-Path -LiteralPath $PolicyPath)) {
      if (-not $IsAdmin) { Write-Warning '[policy] not elevated; policy rollback skipped'; return }
      Move-Item -LiteralPath $dis.FullName -Destination $PolicyPath; Write-Host "[policy] restored Windows policy from $($dis.Name) (NOTE: server will run on Windows again)"
    }
  }
}

switch ($Mode) {
  'Apply'    { Set-UserEnv; Set-WindowsPolicy; Invoke-LockdownVerify; exit $script:ExitCode }
  'Verify'   { Invoke-LockdownVerify; exit $script:ExitCode }
  'Snapshot' { Invoke-Snapshot; exit $script:ExitCode }
  'Rollback' { Undo-Lockdown; exit 0 }
}
