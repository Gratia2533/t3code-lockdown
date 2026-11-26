#!/usr/bin/env bash
# T3 Code lockdown for Linux / WSL2 / macOS.
# Usage:
#   lockdown.sh [apply|verify|rollback|snapshot]
#               [--profile standard|strict] [--org NAME]
#               [--policy-path PATH] [--no-policy]
#               [--t3-bin PATH] [--allow-unvalidated-policy] [--json]
#
# Exit codes (verify / apply):
#   0  = VERIFIED        (all static, runtime, network, and drift checks passed)
#   1  = FAIL            (missing/wrong/overridden config, conflict, or forbidden process)
#   10 = PENDING_RESTART (disk config valid, but T3 Code not running or needs restart)
#   20 = DRIFT_DETECTED  (unaudited T3 Code version or schema/CLI changes detected)
#   30 = INCOMPLETE      (required verification dependency or t3 binary unavailable)
#
# Idempotent. Backs up every file before modifying it. Never touches firewall/hosts/processes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASELINE_PATH="${T3CODE_LOCKDOWN_BASELINE:-$SKILL_ROOT/references/baseline.json}"
AUDIT_HELPER="$SCRIPT_DIR/audit_unix.py"

MODE="apply"
if [ $# -gt 0 ]; then
  case "$1" in
    apply|verify|rollback|snapshot) MODE="$1"; shift ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
  esac
fi

PROFILE="standard"
ORG="Local"
POLICY_PATH=""
NO_POLICY=0
ALLOW_UNVALIDATED_POLICY=0
T3_BIN_ARG=""
AS_JSON=0

need_arg() {
  if [ $# -lt 2 ] || [ -z "$2" ]; then
    echo "missing value for $1" >&2
    exit 2
  fi
}

while [ $# -gt 0 ]; do
  case "$1" in
    --profile)                  need_arg "$@"; PROFILE="$2"; shift 2 ;;
    --org)                      need_arg "$@"; ORG="$2"; shift 2 ;;
    --policy-path)              need_arg "$@"; POLICY_PATH="$2"; shift 2 ;;
    --no-policy)                NO_POLICY=1; shift ;;
    --allow-unvalidated-policy) ALLOW_UNVALIDATED_POLICY=1; shift ;;
    --t3-bin)                   need_arg "$@"; T3_BIN_ARG="$2"; shift 2 ;;
    --json)                     AS_JSON=1; shift ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

case "$PROFILE" in
  standard|strict) ;;
  *) echo "invalid --profile '$PROFILE' (expected standard or strict)" >&2; exit 2 ;;
esac

TEST_MODE="${T3CODE_LOCKDOWN_TEST_MODE:-0}"
if [ "$TEST_MODE" = "1" ] && [ -n "${T3CODE_OS_OVERRIDE:-}" ]; then
  OS="$T3CODE_OS_OVERRIDE"
else
  OS="$(uname -s)"
fi
if [ -z "$POLICY_PATH" ]; then
  case "$OS" in
    Linux)  POLICY_PATH="/etc/t3code/policy.json" ;;
    Darwin) POLICY_PATH="/Library/Application Support/T3Code/policy.json" ;;
  esac
fi

T3_HOME="${T3CODE_HOME:-$HOME/.t3}"
SERVICE_ENV="${T3CODE_SERVICE_ENV:-$T3_HOME/service.env}"
TS="$(date +%Y%m%d-%H%M%S)"
BEGIN="# >>> t3code-lockdown >>>"
END="# <<< t3code-lockdown <<<"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if [ "$TEST_MODE" = "1" ] && [ "${T3CODE_NO_SUDO:-0}" = "1" ]; then
    SUDO=""
  else
    SUDO="sudo"
  fi
fi

ACTIONS_FILE=""
cleanup() {
  [ -n "$ACTIONS_FILE" ] && rm -f "$ACTIONS_FILE" || true
}
trap cleanup EXIT

log_action() {
  if [ -n "$ACTIONS_FILE" ]; then
    printf '%s\n' "$1" >> "$ACTIONS_FILE"
  elif [ "$AS_JSON" = "1" ]; then
    printf '%s\n' "$1" >&2
  else
    printf '%s\n' "$1"
  fi
}

require_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    if [ "$AS_JSON" = "1" ]; then
      printf '{"verdict":"INCOMPLETE","exitCode":30,"safeToClaimLocked":false,"error":"python3 is required for audit and policy generation"}\n'
    else
      echo "[INCOMPLETE] python3 not found; cannot complete strict verification (exit 30)" >&2
    fi
    exit 30
  fi
  if [ ! -f "$BASELINE_PATH" ] || [ ! -f "$AUDIT_HELPER" ]; then
    echo "[FAIL] missing skill reference or helper ($BASELINE_PATH / $AUDIT_HELPER)" >&2
    exit 1
  fi
}

rc_files() {
  local f found=0
  for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$f" ] || { [ "$OS" = "Darwin" ] && [ "$f" = "$HOME/.zshrc" ]; }; then
      printf '%s\n' "$f"
      found=1
    fi
  done
  # Linux with neither rc file: still create ~/.bashrc so apply writes flags and verify can fail closed.
  if [ "$found" = 0 ] && [ "$OS" = "Linux" ]; then
    printf '%s\n' "$HOME/.bashrc"
  fi
}

rc_files_csv() {
  local list="" f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ -z "$list" ]; then list="$f"; else list="$list,$f"; fi
  done < <(rc_files)
  printf '%s' "$list"
}

strip_block() {
  awk -v b="$BEGIN" -v e="$END" '$0==b{s=1;next} $0==e{s=0;next} !s' "$1"
}

# Overwrite $1 in place so mode, ownership and symlink target are kept.
rewrite_in_place() {
  local f=$1 tmp
  tmp="$(mktemp)"
  strip_block "$f" > "$tmp"
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

env_file_state() {
  # Prints: OK | CONFLICT | NEEDS_WRITE
  local f=$1 kind=$2
  python3 - "$AUDIT_HELPER" "$BASELINE_PATH" "$f" "$kind" <<'PY'
import json, subprocess, sys
helper, baseline, fpath, kind = sys.argv[1:5]
p = subprocess.run([sys.executable, helper, "check-env-file", "--baseline", baseline, "--file", fpath, "--kind", kind], capture_output=True, text=True)
data = json.loads(p.stdout)
if data["ok"]:
    print("OK")
elif data["conflicts"]:
    print("CONFLICT")
else:
    print("NEEDS_WRITE")
PY
}

apply_env() {
  local f state
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -f "$f" ] || : > "$f"
    state="$(env_file_state "$f" rc)"
    if [ "$state" = "OK" ]; then
      if grep -qF "$BEGIN" "$f"; then
        log_action "[env] $f: already has effective lockdown flags (unchanged)"
      else
        log_action "[env] $f: already sets required flags manually (unchanged)"
      fi
      continue
    fi
    if [ "$state" = "CONFLICT" ]; then
      log_action "[env] $f: CONFLICTING manual/trailing override detected (not modified; fix file manually)"
      continue
    fi
    if grep -qF "$BEGIN" "$f"; then
      cp -p "$f" "$f.bak-$TS"
      rewrite_in_place "$f"
      printf '\n%s\nexport T3CODE_TELEMETRY_ENABLED=false\nexport T3CODE_OTEL_SDK_DISABLED=true\n%s\n' "$BEGIN" "$END" >> "$f"
      log_action "[env] $f: refreshed lockdown block (backup: $f.bak-$TS)"
    else
      cp -p "$f" "$f.bak-$TS"
      printf '\n%s\nexport T3CODE_TELEMETRY_ENABLED=false\nexport T3CODE_OTEL_SDK_DISABLED=true\n%s\n' "$BEGIN" "$END" >> "$f"
      log_action "[env] $f: added lockdown block (backup: $f.bak-$TS)"
    fi
  done < <(rc_files)
}

apply_service_env() {
  local f="$SERVICE_ENV" state
  if [ ! -f "$f" ]; then
    log_action "[service.env] $f not found (skipped; if you use 't3 service', add the two flags there and run 't3 service restart')"
    return
  fi
  state="$(env_file_state "$f" service)"
  if [ "$state" = "OK" ]; then
    log_action "[service.env] $f: already has effective lockdown flags (unchanged)"
    return
  fi
  if [ "$state" = "CONFLICT" ]; then
    log_action "[service.env] $f: CONFLICTING value detected (not modified; fix file manually)"
    return
  fi
  cp -p "$f" "$f.bak-$TS"
  if grep -qF "$BEGIN" "$f"; then
    rewrite_in_place "$f"
  fi
  printf '\n%s\nT3CODE_TELEMETRY_ENABLED=false\nT3CODE_OTEL_SDK_DISABLED=true\n%s\n' "$BEGIN" "$END" >> "$f"
  log_action "[service.env] updated lockdown block (backup: $f.bak-$TS); run 't3 service restart' (ask the user)"
}

apply_launchctl() {
  [ "$OS" = "Darwin" ] || return 0
  if [ "$TEST_MODE" = "1" ] && [ "${T3CODE_SKIP_LAUNCHCTL:-0}" = "1" ]; then return 0; fi
  if launchctl setenv T3CODE_TELEMETRY_ENABLED false && launchctl setenv T3CODE_OTEL_SDK_DISABLED true; then
    log_action "[launchctl] set for current macOS login session"
  else
    log_action "[launchctl] failed to set current session env (re-login required)"
  fi
}

discover_t3_for_apply() {
  if [ -n "$T3_BIN_ARG" ] && [ -x "$T3_BIN_ARG" ]; then printf '%s' "$T3_BIN_ARG"; return; fi
  if [ -n "${T3_BIN:-}" ] && [ -x "${T3_BIN}" ]; then printf '%s' "$T3_BIN"; return; fi
  if command -v t3 >/dev/null 2>&1; then command -v t3; return; fi
  if [ -x "$T3_HOME/bin/t3" ]; then printf '%s' "$T3_HOME/bin/t3"; return; fi
  local candidate
  candidate="$(ls -t "$T3_HOME"/wsl-runtime/sha256-*/t3 2>/dev/null | head -n1 || true)"
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then printf '%s' "$candidate"; return; fi
}

apply_policy() {
  if [ "$NO_POLICY" = 1 ] || [ -z "$POLICY_PATH" ]; then
    log_action "[policy] skipped (--no-policy or no policy path for $OS)"
    return 0
  fi
  # Guard against macOS MDM profile conflict (T3 Code refuses to start if both exist).
  if [ "$OS" = "Darwin" ]; then
    local mdm_plist="/Library/Managed Preferences/com.t3tools.t3code.plist"
    if [ "$TEST_MODE" = "1" ] && [ -n "${T3CODE_MACOS_MDM_PLIST:-}" ]; then
      mdm_plist="$T3CODE_MACOS_MDM_PLIST"
    fi
    if [ -e "$mdm_plist" ]; then
      log_action "[policy] SKIPPED: macOS MDM profile exists at $mdm_plist (coexistence breaks T3 Code startup; use --no-policy or coordinate with MDM)"
      return 0
    fi
  fi

  local tmp t3_bin
  tmp="$(mktemp)"
  python3 "$AUDIT_HELPER" generate-policy --baseline "$BASELINE_PATH" --profile "$PROFILE" --org "$ORG" > "$tmp"

  # Pre-validate policy with t3 CLI before deploying so we never write a startup-breaking policy.
  t3_bin="$(discover_t3_for_apply || true)"
  if [ -n "$t3_bin" ]; then
    if ! "$t3_bin" policy check "$tmp" >/dev/null 2>&1; then
      log_action "[policy] ABORTED: 't3 policy check' rejected generated '$PROFILE' policy (not written)"
      rm -f "$tmp"
      return 1
    fi
  elif [ "$ALLOW_UNVALIDATED_POLICY" != "1" ]; then
    log_action "[policy] ABORTED: t3 binary not found; refusing to write unvalidated policy (pass --t3-bin PATH or --allow-unvalidated-policy to override)"
    rm -f "$tmp"
    return 1
  else
    log_action "[policy] WARNING: t3 binary not found; writing policy without 't3 policy check' (--allow-unvalidated-policy)"
  fi

  if [ -f "$POLICY_PATH" ] && cmp -s "$tmp" "$POLICY_PATH"; then
    log_action "[policy] $POLICY_PATH already up to date for '$PROFILE' profile (unchanged)"
    rm -f "$tmp"
    return 0
  fi

  $SUDO mkdir -p "$(dirname "$POLICY_PATH")"
  if [ -f "$POLICY_PATH" ]; then
    $SUDO cp -p "$POLICY_PATH" "$POLICY_PATH.bak-$TS"
    log_action "[policy] backup: $POLICY_PATH.bak-$TS"
  fi
  $SUDO install -m 0644 "$tmp" "$POLICY_PATH"
  rm -f "$tmp"
  log_action "[policy] wrote $POLICY_PATH (profile: $PROFILE, org: $ORG)"
}

run_verify() {
  local -a cmd=(
    python3 "$AUDIT_HELPER" verify
    --baseline "$BASELINE_PATH"
    --profile "$PROFILE"
    --policy-path "$POLICY_PATH"
    --rc-files "$(rc_files_csv)"
    --service-env "$SERVICE_ENV"
    --os-name "$OS"
    --t3-home "$T3_HOME"
  )
  [ "$NO_POLICY" = 1 ] && cmd+=(--no-policy)
  [ -n "$T3_BIN_ARG" ] && cmd+=(--t3-bin "$T3_BIN_ARG")
  [ -n "$ACTIONS_FILE" ] && cmd+=(--actions-file "$ACTIONS_FILE")
  [ "$AS_JSON" = 1 ] && cmd+=(--json)
  "${cmd[@]}"
}

run_snapshot() {
  local -a cmd=(
    python3 "$AUDIT_HELPER" snapshot
    --baseline "$BASELINE_PATH"
    --os-name "$OS"
    --t3-home "$T3_HOME"
  )
  [ -n "$T3_BIN_ARG" ] && cmd+=(--t3-bin "$T3_BIN_ARG")
  "${cmd[@]}"
}

rollback() {
  local f latest bak
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    if [ -f "$f" ] && grep -qF "$BEGIN" "$f"; then
      cp -p "$f" "$f.bak-$TS"
      rewrite_in_place "$f"
      echo "[env] $f: removed lockdown block (backup: $f.bak-$TS)"
    fi
  done < <(rc_files)

  if [ -f "$SERVICE_ENV" ] && grep -qF "$BEGIN" "$SERVICE_ENV"; then
    cp -p "$SERVICE_ENV" "$SERVICE_ENV.bak-$TS"
    rewrite_in_place "$SERVICE_ENV"
    echo "[service.env] removed lockdown block (backup: $SERVICE_ENV.bak-$TS)"
  fi

  if [ "$OS" = "Darwin" ] && { [ "$TEST_MODE" != "1" ] || [ "${T3CODE_SKIP_LAUNCHCTL:-0}" != "1" ]; }; then
    launchctl unsetenv T3CODE_TELEMETRY_ENABLED 2>/dev/null || true
    launchctl unsetenv T3CODE_OTEL_SDK_DISABLED 2>/dev/null || true
  fi

  if [ "$NO_POLICY" = 0 ] && [ -n "$POLICY_PATH" ] && [ -f "$POLICY_PATH" ]; then
    latest=""
    for bak in "$POLICY_PATH".bak-*; do
      [ -e "$bak" ] || continue
      latest="$bak"
    done
    $SUDO mv "$POLICY_PATH" "$POLICY_PATH.removed-$TS"
    echo "[policy] moved current policy to $POLICY_PATH.removed-$TS"
    if [ -n "$latest" ]; then
      $SUDO mv "$latest" "$POLICY_PATH"
      echo "[policy] restored $latest"
    fi
  fi
}

case "$MODE" in
  apply)
    require_python3
    ACTIONS_FILE="$(mktemp)"
    apply_env
    apply_service_env
    apply_launchctl
    apply_policy || true
    run_verify
    ;;
  verify)
    require_python3
    run_verify
    ;;
  snapshot)
    require_python3
    run_snapshot
    ;;
  rollback)
    rollback
    ;;
  *)
    echo "usage: $0 [apply|verify|rollback|snapshot] [--profile standard|strict] [--org NAME] [--policy-path PATH] [--no-policy] [--t3-bin PATH] [--json]" >&2
    exit 2
    ;;
esac
