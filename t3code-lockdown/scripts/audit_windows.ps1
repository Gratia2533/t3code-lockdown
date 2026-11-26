<#
Reusable read-only inspection, policy builder, and drift helpers for lockdown.ps1.
Dot-sourced by lockdown.ps1. Compatible with Windows PowerShell 5.1+ and PowerShell 7+.
#>

function Read-Utf8Text {
  param([Parameter(Mandatory = $true)][string]$Path)
  $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
  if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
  return $text
}

function Write-Utf8NoBom {
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Content)
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function ConvertTo-Hashtable {
  param([Parameter(ValueFromPipeline = $true)]$InputObject)
  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [System.Collections.IDictionary]) {
    $ht = [ordered]@{}
    foreach ($k in $InputObject.Keys) { $ht[$k] = ConvertTo-Hashtable $InputObject[$k] }
    return $ht
  }
  if ($InputObject -is [pscustomobject]) {
    $ht = [ordered]@{}
    foreach ($prop in $InputObject.PSObject.Properties) {
      $ht[$prop.Name] = ConvertTo-Hashtable $prop.Value
    }
    return $ht
  }
  if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
    $arr = @()
    foreach ($item in $InputObject) { $arr += ,(ConvertTo-Hashtable $item) }
    return ,$arr
  }
  return $InputObject
}

function New-PolicyJson {
  param($BaselineObj, $ProfileSpecObj, [string]$OrgName)
  $obj = [ordered]@{
    schemaVersion = [int]$BaselineObj.policySchemaVersion
    organization  = $OrgName
    limits        = $ProfileSpecObj['limits']
  }
  if ($ProfileSpecObj.Contains('settings') -and $ProfileSpecObj['settings'] -and $ProfileSpecObj['settings'].Count -gt 0) {
    $obj['settings'] = $ProfileSpecObj['settings']
  }
  return (($obj | ConvertTo-Json -Depth 10) + "`n")
}

function Compare-DeepSubset {
  param($Actual, $Expected, [string]$Prefix = '')
  $mismatches = New-Object System.Collections.Generic.List[string]
  if ($Expected -is [System.Collections.IDictionary]) {
    $actDict = ConvertTo-Hashtable $Actual
    if (-not ($actDict -is [System.Collections.IDictionary])) {
      $mismatches.Add("$($Prefix): expected object")
      return ,$mismatches.ToArray()
    }
    foreach ($k in $Expected.Keys) {
      $p = if ($Prefix) { "$Prefix.$k" } else { "$k" }
      if (-not $actDict.Contains($k)) {
        $mismatches.Add("$($p): missing")
      } else {
        foreach ($m in (Compare-DeepSubset -Actual $actDict[$k] -Expected $Expected[$k] -Prefix $p)) {
          $mismatches.Add($m)
        }
      }
    }
    return ,$mismatches.ToArray()
  }
  if ($null -eq $Actual -or $Actual.GetType().FullName -ne $Expected.GetType().FullName -or $Actual -ne $Expected) {
    $mismatches.Add("$($Prefix): expected '$Expected', got '$Actual'")
  }
  return ,$mismatches.ToArray()
}

function Invoke-NativeCapture {
  param([Parameter(Mandatory = $true)][string]$Exe, [string[]]$Arguments = @())
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & $Exe @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    return [ordered]@{ exitCode = $code; output = $output }
  } catch {
    return [ordered]@{ exitCode = 127; output = $_.Exception.Message }
  } finally {
    $ErrorActionPreference = $prev
  }
}

function Find-T3Binary {
  param([string]$ExplicitBin, [string]$HomeDir)
  $candidates = New-Object System.Collections.Generic.List[string]
  if (-not [string]::IsNullOrWhiteSpace($ExplicitBin)) { $candidates.Add($ExplicitBin) }
  if (-not [string]::IsNullOrWhiteSpace($env:T3_BIN)) { $candidates.Add($env:T3_BIN) }
  $cmd = Get-Command t3 -ErrorAction SilentlyContinue
  if ($cmd) { $candidates.Add($cmd.Source) }
  if ($env:LOCALAPPDATA) {
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\T3 Code\resources\bin\t3.exe'))
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'T3Code\bin\t3.exe'))
  }
  $toolsDir = Join-Path $HomeDir 'tools'
  if (Test-Path $toolsDir) {
    Get-ChildItem -Path $toolsDir -Filter 't3*.exe' -Recurse -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      ForEach-Object { $candidates.Add($_.FullName) }
  }
  foreach ($c in $candidates) {
    if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
  }
  return $null
}

function Parse-VersionString {
  param([string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
  if ($Raw -match '\bv?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)\b') { return $Matches[1] }
  return $null
}

function Parse-Subcommands {
  param([string]$HelpText)
  $subs = New-Object System.Collections.Generic.HashSet[string]
  $inSec = $false
  foreach ($line in ($HelpText -split "`r?`n")) {
    if ($line.Trim() -eq 'SUBCOMMANDS') { $inSec = $true; continue }
    if ($inSec) {
      if ([string]::IsNullOrWhiteSpace($line)) { continue }
      if (-not $line.StartsWith(' ')) { break }
      if ($line -match '^\s+([a-zA-Z0-9_-]+)\s{2,}') { [void]$subs.Add($Matches[1]) }
    }
  }
  return @($subs | Sort-Object)
}

function Get-LiveAdmxPolicies {
  param([Parameter(Mandatory = $true)][string]$ExePath)
  $tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("t3-lockdown-tpl-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  try {
    $res = Invoke-NativeCapture -Exe $ExePath -Arguments @('policy', 'templates', $tmpDir)
    if ($res.exitCode -ne 0) { return [ordered]@{ policies = $null; error = $res.output.Trim() } }
    $admxPath = Join-Path $tmpDir 'windows\t3code.admx'
    if (-not (Test-Path -LiteralPath $admxPath)) { return [ordered]@{ policies = $null; error = "missing $admxPath" } }
    [xml]$xml = Read-Utf8Text $admxPath
    $nsMgr = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $nsMgr.AddNamespace('p', 'http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions')
    $map = [ordered]@{}
    $names = @()
    foreach ($n in $xml.SelectNodes('//p:policy', $nsMgr)) {
      $pn = $n.GetAttribute('name')
      if (-not [string]::IsNullOrEmpty($pn)) { $names += $pn }
    }
    foreach ($name in ($names | Sort-Object -Unique)) {
      $node = $xml.SelectSingleNode("//p:policy[@name='$name']", $nsMgr)
      $elems = @()
      foreach ($e in $node.SelectNodes('./p:elements/*', $nsMgr)) {
        $eid = $e.GetAttribute('id')
        if (-not [string]::IsNullOrEmpty($eid)) { $elems += $eid }
      }
      $map[$name] = @($elems | Sort-Object)
    }
    return [ordered]@{ policies = $map; error = $null }
  } catch {
    return [ordered]@{ policies = $null; error = $_.Exception.Message }
  } finally {
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Get-T3Snapshot {
  param([Parameter(Mandatory = $true)][string]$ExePath)
  $vRes = Invoke-NativeCapture -Exe $ExePath -Arguments @('--version')
  $rawVer = if ($vRes.exitCode -eq 0) { $vRes.output.Trim() } else { '' }
  $hRes = Invoke-NativeCapture -Exe $ExePath -Arguments @('--help')
  $phRes = Invoke-NativeCapture -Exe $ExePath -Arguments @('policy', '--help')
  $admx = Get-LiveAdmxPolicies -ExePath $ExePath
  return [ordered]@{
    t3Binary          = $ExePath
    rawVersion        = $rawVer
    version           = Parse-VersionString $rawVer
    admxPolicies      = $admx.policies
    admxError         = $admx.error
    cliSubcommands    = if ($hRes.exitCode -eq 0) { Parse-Subcommands $hRes.output } else { $null }
    policySubcommands = if ($phRes.exitCode -eq 0) { Parse-Subcommands $phRes.output } else { $null }
  }
}

function Compute-Drift {
  param($BaselineObj, $Snap, [string]$RunningVersion)
  $audited = @($BaselineObj.auditedVersions)
  $verDrift = New-Object System.Collections.Generic.List[string]
  if ($Snap.version -and ($audited -notcontains $Snap.version)) { $verDrift.Add("installed=$($Snap.version)") }
  if ($RunningVersion -and ($audited -notcontains $RunningVersion)) { $verDrift.Add("running=$RunningVersion") }

  $baseAdmx = ConvertTo-Hashtable $BaselineObj.admxPolicies
  $liveAdmx = $Snap.admxPolicies
  $addedPol = [ordered]@{}
  $removedPol = [ordered]@{}
  $addedElem = [ordered]@{}
  $removedElem = [ordered]@{}

  if ($null -ne $liveAdmx) {
    foreach ($k in $liveAdmx.Keys) {
      if (-not $baseAdmx.Contains($k)) {
        $addedPol[$k] = $liveAdmx[$k]
      } else {
        $ae = @($liveAdmx[$k] | Where-Object { $baseAdmx[$k] -notcontains $_ } | Sort-Object)
        $re = @($baseAdmx[$k] | Where-Object { $liveAdmx[$k] -notcontains $_ } | Sort-Object)
        if ($ae.Count -gt 0) { $addedElem[$k] = $ae }
        if ($re.Count -gt 0) { $removedElem[$k] = $re }
      }
    }
    foreach ($k in $baseAdmx.Keys) {
      if (-not $liveAdmx.Contains($k)) { $removedPol[$k] = $baseAdmx[$k] }
    }
  }

  $baseCli = @($BaselineObj.cliSubcommands)
  $cliAdded = @(if ($null -ne $Snap.cliSubcommands) { $Snap.cliSubcommands | Where-Object { $baseCli -notcontains $_ } | Sort-Object })
  $basePolCli = @($BaselineObj.policySubcommands)
  $polCliAdded = @(if ($null -ne $Snap.policySubcommands) { $Snap.policySubcommands | Where-Object { $basePolCli -notcontains $_ } | Sort-Object })

  $schemaChanged = ($addedPol.Count -gt 0) -or ($removedPol.Count -gt 0) -or ($addedElem.Count -gt 0) -or ($removedElem.Count -gt 0)
  $cliChanged = (@($cliAdded).Count -gt 0) -or (@($polCliAdded).Count -gt 0)
  $detected = ($verDrift.Count -gt 0) -or $schemaChanged -or $cliChanged

  return [ordered]@{
    auditedVersions        = $audited
    installedVersion       = $Snap.version
    runningVersion         = $RunningVersion
    versionDrift           = @($verDrift.ToArray())
    schemaChanged          = $schemaChanged
    cliChanged             = $cliChanged
    addedPolicies          = $addedPol
    removedPolicies        = $removedPol
    addedElements          = $addedElem
    removedElements        = $removedElem
    addedCliSubcommands    = $cliAdded
    addedPolicySubcommands = $polCliAdded
    detected               = $detected
  }
}
