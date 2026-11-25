#!/usr/bin/env bash
# T3 Code lockdown for Linux / WSL2 / macOS.
# Usage: lockdown.sh [apply|verify|rollback] [--org NAME] [--policy-path PATH] [--no-policy]
# Idempotent. Backs up every file before modifying it. Never touches firewall/hosts/processes.
set -euo pipefail

MODE="${1:-apply}"; [ $# -gt 0 ] && shift || true
ORG="Local"
POLICY_PATH=""
NO_POLICY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --org) ORG="$2"; shift 2 ;;
    --policy-path) POLICY_PATH="$2"; shift 2 ;;
    --no-policy) NO_POLICY=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
# Paths from T3 Code docs/user/managed-policy.md ("Where the policy goes").
if [ -z "$POLICY_PATH" ]; then
  case "$OS" in
    Linux)  POLICY_PATH="/etc/t3code/policy.json" ;;
    Darwin) POLICY_PATH="/Library/Application Support/T3Code/policy.json" ;;
  esac
fi
SERVICE_ENV="${T3CODE_SERVICE_ENV:-$HOME/.t3/service.env}"  # background service (t3 service) env file
TS="$(date +%Y%m%d-%H%M%S)"
BEGIN="# >>> t3code-lockdown >>>"
END="# <<< t3code-lockdown <<<"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

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

json_escape() {
  # Escape backslash and double quote for a JSON string value.
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

policy_json() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$ORG" <<'PY'
import json, sys
print(json.dumps({
    "schemaVersion": 1,
    "organization": sys.argv[1],
    "limits": {
        "telemetry": False,
        "connect": False,
        "updates": {"mode": "off"},
    },
}, indent=2, ensure_ascii=False) + "\n")
PY
  else
    cat <<JSON
{
  "schemaVersion": 1,
  "organization": "$(json_escape "$ORG")",
  "limits": {
    "telemetry": false,
    "connect": false,
    "updates": { "mode": "off" }
  }
}
JSON
  fi
}

assert_json_file() {
  local f=$1
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$f"
  fi
}

strip_block() { # file -> stdout without our marker block
  awk -v b="$BEGIN" -v e="$END" '$0==b{s=1;next} $0==e{s=0;next} !s' "$1"
}

# Overwrite $1 in place so mode, ownership and symlink target are kept (do not mv a new file over it).
rewrite_in_place() {
  local f=$1 tmp
  tmp="$(mktemp)"
  strip_block "$f" > "$tmp"
  cat "$tmp" > "$f"
  rm -f "$tmp"
}

apply_service_env() {
  # `t3 service` does not read shell rc files; it reads ~/.t3/service.env (KEY=VALUE). Only touched if it exists.
  local f="$SERVICE_ENV"
  if [ ! -f "$f" ]; then echo "[service.env] $f not found (skipped; if you use 't3 service', add the two flags there and run 't3 service restart')"; return; fi
  if grep -qF "$BEGIN" "$f"; then echo "[service.env] already has lockdown block (unchanged)"; return; fi
  cp -p "$f" "$f.bak-$TS"
  printf '\n%s\nT3CODE_TELEMETRY_ENABLED=false\nT3CODE_OTEL_SDK_DISABLED=true\n%s\n' "$BEGIN" "$END" >> "$f"
  echo "[service.env] added lockdown block (backup: $f.bak-$TS); run 't3 service restart' (ask the user)"
}

apply_launchctl() {
  # macOS GUI apps launched from Dock/Finder: set for the current login session too (does not survive reboot; rc file covers the desktop app per T3 docs).
  [ "$OS" = "Darwin" ] || return 0
  launchctl setenv T3CODE_TELEMETRY_ENABLED false && launchctl setenv T3CODE_OTEL_SDK_DISABLED true && echo "[launchctl] set for current session"
}

apply_env() {
  local f
  while IFS= read -r f; do
    [ -f "$f" ] || : > "$f"
    if grep -qF "$BEGIN" "$f"; then echo "[env] $f: already has lockdown block (unchanged)"; continue; fi
    if grep -q 'T3CODE_TELEMETRY_ENABLED' "$f"; then echo "[env] $f: T3CODE_TELEMETRY_ENABLED already set manually (unchanged, check value)"; continue; fi
    cp -p "$f" "$f.bak-$TS"
    printf '\n%s\nexport T3CODE_TELEMETRY_ENABLED=false\nexport T3CODE_OTEL_SDK_DISABLED=true\n%s\n' "$BEGIN" "$END" >> "$f"
    echo "[env] $f: added lockdown block (backup: $f.bak-$TS)"
  done < <(rc_files)
}

apply_policy() {
  if [ "$NO_POLICY" = 1 ] || [ -z "$POLICY_PATH" ]; then echo "[policy] skipped (no policy path for $OS; use --policy-path)"; return; fi
  local tmp; tmp="$(mktemp)"; policy_json > "$tmp"
  if ! assert_json_file "$tmp"; then
    echo "[FAIL] generated policy is not valid JSON (check --org for quotes/backslashes)" >&2
    rm -f "$tmp"
    return 1
  fi
  if [ -f "$POLICY_PATH" ] && cmp -s "$tmp" "$POLICY_PATH"; then
    echo "[policy] $POLICY_PATH already up to date (unchanged)"; rm -f "$tmp"; return
  fi
  $SUDO mkdir -p "$(dirname "$POLICY_PATH")"
  if [ -f "$POLICY_PATH" ]; then $SUDO cp -p "$POLICY_PATH" "$POLICY_PATH.bak-$TS"; echo "[policy] backup: $POLICY_PATH.bak-$TS"; fi
  $SUDO install -m 0644 "$tmp" "$POLICY_PATH"; rm -f "$tmp"
  echo "[policy] wrote $POLICY_PATH"
}

check_flags() {
  local f=$1 label=$2
  if grep -q 'T3CODE_TELEMETRY_ENABLED=false' "$f" && grep -q 'T3CODE_OTEL_SDK_DISABLED=true' "$f"; then
    echo "[ok]   $label flags in $f"
    return 0
  fi
  echo "[FAIL] $label flags missing in $f"
  return 1
}

verify() {
  local rc=0 f
  while IFS= read -r f; do
    if [ -f "$f" ]; then
      check_flags "$f" "env" || rc=1
    else
      echo "[FAIL] env file missing: $f"; rc=1
    fi
  done < <(rc_files)
  if [ -f "$SERVICE_ENV" ]; then
    check_flags "$SERVICE_ENV" "service.env" || rc=1
  fi
  if [ -n "$POLICY_PATH" ] && [ "$NO_POLICY" = 0 ]; then
    if [ -f "$POLICY_PATH" ]; then
      if ! command -v python3 >/dev/null 2>&1; then echo "[info] python3 missing; rely on 't3 policy check' below"
      elif python3 - "$POLICY_PATH" <<'PY'
import json,sys
p=json.load(open(sys.argv[1], encoding="utf-8")); l=p.get("limits",{})
ok = p.get("schemaVersion")==1 and l.get("telemetry") is False and l.get("connect") is False and l.get("updates",{}).get("mode")=="off"
sys.exit(0 if ok else 1)
PY
      then echo "[ok]   policy content valid: $POLICY_PATH"; else echo "[FAIL] policy content wrong: $POLICY_PATH"; rc=1; fi
    else echo "[FAIL] policy missing: $POLICY_PATH"; rc=1; fi
  fi
  if command -v t3 >/dev/null 2>&1; then
    if [ "$NO_POLICY" = 0 ] && [ -n "$POLICY_PATH" ] && [ -f "$POLICY_PATH" ]; then
      if t3 policy check "$POLICY_PATH"; then
        echo "[ok]   t3 policy check: $POLICY_PATH"
      else
        echo "[FAIL] t3 policy check failed: $POLICY_PATH"
        rc=1
      fi
    fi
    t3 policy show || true
  else echo "[info] t3 CLI not on PATH; after restarting T3 Code run: t3 policy show (desktop app installs the t3 command)"; fi
  echo "[note] env flags apply to NEW shells and a restarted T3 Code server. Restart T3 Code (ask the user; do not kill it yourself)."
  return $rc
}

rollback() {
  local f latest bak
  while IFS= read -r f; do
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
  if [ "$OS" = "Darwin" ]; then launchctl unsetenv T3CODE_TELEMETRY_ENABLED 2>/dev/null || true; launchctl unsetenv T3CODE_OTEL_SDK_DISABLED 2>/dev/null || true; fi
  if [ "$NO_POLICY" = 0 ] && [ -n "$POLICY_PATH" ] && [ -f "$POLICY_PATH" ]; then
    latest=""
    for bak in "$POLICY_PATH".bak-*; do
      [ -e "$bak" ] || continue
      latest="$bak"
    done
    $SUDO mv "$POLICY_PATH" "$POLICY_PATH.removed-$TS"; echo "[policy] moved current policy to $POLICY_PATH.removed-$TS"
    # Move (do not copy) the newest backup so a later rollback can step further back,
    # including to a machine that originally had no policy file.
    if [ -n "$latest" ]; then $SUDO mv "$latest" "$POLICY_PATH"; echo "[policy] restored $latest"; fi
  fi
}

case "$MODE" in
  apply) apply_env; apply_service_env; apply_launchctl; apply_policy; verify ;;
  verify) verify ;;
  rollback) rollback ;;
  *) echo "usage: $0 [apply|verify|rollback] [--org NAME] [--policy-path PATH] [--no-policy]" >&2; exit 2 ;;
esac
