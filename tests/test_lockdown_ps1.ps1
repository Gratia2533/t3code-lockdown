<#
Read-only syntax, AST, and behavior tests for t3code-lockdown/scripts/lockdown.ps1.
Never modifies Windows User/Machine environment variables or C:\Program Files\T3Code.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Ps1Path = Join-Path $RepoRoot 't3code-lockdown\scripts\lockdown.ps1'
$BaselinePath = Join-Path $RepoRoot 't3code-lockdown\references\baseline.json'

function Assert-True {
  param([bool]$Condition, [string]$Message)
  if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

Write-Host '[1/5] PowerShell AST syntax check...'
foreach ($f in @($Ps1Path, (Join-Path $RepoRoot 't3code-lockdown\scripts\audit_windows.ps1'))) {
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$errors)
  Assert-True ($errors.Count -eq 0) "Syntax errors in $($f): $($errors | Out-String)"
}
Write-Host '      PASS'

$TmpDir = Join-Path ([IO.Path]::GetTempPath()) ("t3lock-ps1-test-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
$OrigLoc = Get-Location
Set-Location $TmpDir

try {
  Write-Host '[2/5] Verify -Backend Wsl without -CheckWsl fails closed (never claims safe)...'
  $outWsl = & powershell -NoProfile -ExecutionPolicy Bypass -File $Ps1Path -Mode Verify -Backend Wsl -PolicyPath (Join-Path $TmpDir 'nonexistent.json') -Json | Out-String
  $codeWsl = $LASTEXITCODE
  $jsonWsl = $outWsl | ConvertFrom-Json
  Assert-True ($codeWsl -ne 0) "Expected non-zero exit code without -CheckWsl, got $codeWsl"
  Assert-True ($jsonWsl.safeToClaimLocked -eq $false) 'Expected safeToClaimLocked=false without -CheckWsl'
  Write-Host "      PASS (verdict=$($jsonWsl.verdict), exit=$codeWsl)"

  Write-Host '[3/5] Verify -Backend Windows rejects missing policy...'
  $missingPol = Join-Path $TmpDir 'missing-policy.json'
  $outMiss = & powershell -NoProfile -ExecutionPolicy Bypass -File $Ps1Path -Mode Verify -Backend Windows -PolicyPath $missingPol -T3Home (Join-Path $TmpDir 't3home') -Json | Out-String
  $codeMiss = $LASTEXITCODE
  $jsonMiss = $outMiss | ConvertFrom-Json
  Assert-True ($codeMiss -eq 1) "Expected exit 1 for missing policy, got $codeMiss"
  Assert-True ($jsonMiss.verdict -eq 'FAIL') "Expected FAIL verdict, got $($jsonMiss.verdict)"
  Write-Host '      PASS'

  Write-Host '[4/5] Verify -Backend Windows detects drift on mock t3.cmd (version 0.1.99)...'
  $t3Home = Join-Path $TmpDir 't3home-drift'
  New-Item -ItemType Directory -Force -Path (Join-Path $t3Home 'userdata') | Out-Null
  $strictPol = Join-Path $TmpDir 'strict-policy.json'
  $strictObj = [ordered]@{
    schemaVersion = 1
    organization  = 'TestOrg'
    limits        = [ordered]@{
      telemetry           = $false
      connect             = $false
      webhookTasks        = $false
      browserCookieImport = $false
      previewTunnel       = $false
      updates             = [ordered]@{ mode = 'off'; allowNightly = $false }
    }
    settings      = [ordered]@{
      enableProviderUpdateChecks = [ordered]@{ value = $false; locked = $true }
    }
  }
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($strictPol, ($strictObj | ConvertTo-Json -Depth 10), $utf8NoBom)

  $fixtureAdmx = Join-Path $TmpDir 'fixture.admx'
  [IO.File]::WriteAllText($fixtureAdmx, '<?xml version="1.0" encoding="utf-8"?><policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"><policies><policy name="NewTelemetry" class="Machine"/></policies></policyDefinitions>', $utf8NoBom)

  $mockCmd = Join-Path $TmpDir 'mock-t3.cmd'
  $mockBody = @'
@echo off
if "%~1"=="--version" goto ver
if "%~1"=="--help" goto mainhelp
if "%~1"=="status" goto status
if "%~1"=="policy" goto policy
exit /b 1

:ver
echo t3 v0.1.99
exit /b 0

:mainhelp
echo SUBCOMMANDS
echo   status   desc
echo   policy   desc
echo   brandnew desc
exit /b 0

:status
echo   T3 Connect     off
exit /b 0

:policy
if "%~2"=="--help" goto polhelp
if "%~2"=="check" goto polcheck
if "%~2"=="show" goto polshow
if "%~2"=="templates" goto poltpl
exit /b 1

:polhelp
echo SUBCOMMANDS
echo   check   desc
echo   show    desc
echo   templates desc
exit /b 0

:polcheck
echo Managed by TestOrg (%~3, fingerprint deadbeef1234).
exit /b 0

:polshow
echo Managed by TestOrg (fingerprint deadbeef1234).
echo No running server.
exit /b 0

:poltpl
mkdir "%~3\windows" 2>nul
copy /y "%~dp0fixture.admx" "%~3\windows\t3code.admx" >nul
exit /b 0
'@
  [IO.File]::WriteAllText($mockCmd, ($mockBody -replace "`r?`n", "`r`n"), [Text.Encoding]::ASCII)

  # Snapshot mode test with mock t3.cmd
  $snapOut = & powershell -NoProfile -ExecutionPolicy Bypass -File $Ps1Path -Mode Snapshot -T3Bin $mockCmd | Out-String
  $snapCode = $LASTEXITCODE
  $snapJson = $snapOut | ConvertFrom-Json
  Assert-True ($snapCode -eq 0) "Expected Snapshot exit 0, got $snapCode"
  Assert-True ($snapJson.version -eq '0.1.99') "Expected snapshot version 0.1.99, got $($snapJson.version)"
  Assert-True ($null -eq $snapJson.admxError) "Unexpected snapshot admxError: $($snapJson.admxError)"
  Assert-True ($snapJson.diffAgainstBaseline.detected -eq $true) 'Expected snapshot drift detected=true'
  Write-Host '      PASS (Snapshot drift detected)'

  Write-Host '[5/5] Verify -Backend Windows -Profile Strict validates policy content and surfaces drift...'
  $outDrift = & powershell -NoProfile -ExecutionPolicy Bypass -File $Ps1Path -Mode Verify -Backend Windows -Profile Strict -PolicyPath $strictPol -T3Home $t3Home -T3Bin $mockCmd -Json | Out-String
  $jsonDrift = $outDrift | ConvertFrom-Json
  $polCheck = @($jsonDrift.checks | Where-Object { $_.id -eq 'policy.file' })[0]
  $driftCheck = @($jsonDrift.checks | Where-Object { $_.id -eq 'drift.version' })[0]
  $schemaCheck = @($jsonDrift.checks | Where-Object { $_.id -eq 'drift.policy_schema' })[0]
  Assert-True ($polCheck.status -eq 'PASS') "Expected policy.file PASS, got $($polCheck.status) ($($polCheck.message))"
  Assert-True ($driftCheck.status -eq 'DRIFT_DETECTED') "Expected drift.version DRIFT_DETECTED, got $($driftCheck.status) ($($driftCheck.message))"
  Assert-True ($schemaCheck.status -eq 'DRIFT_DETECTED') "Expected drift.policy_schema DRIFT_DETECTED, got $($schemaCheck.status) ($($schemaCheck.message))"
  Assert-True ($jsonDrift.safeToClaimLocked -eq $false) 'Expected safeToClaimLocked=false when drifted'
  Write-Host '      PASS'

  Write-Host 'ALL POWERSHELL TESTS PASSED.'
} finally {
  Set-Location $OrigLoc
  Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}
