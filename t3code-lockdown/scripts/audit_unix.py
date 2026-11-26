#!/usr/bin/env python3
"""CLI orchestration and report renderer for t3code-lockdown (Unix).

Delegates reusable inspection & drift logic to audit_lib.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from audit_lib import (  # noqa: E402
    active_test_overrides,
    build_policy_document,
    capture_snapshot,
    compute_drift,
    deep_subset_check,
    discover_t3_binary,
    inspect_forbidden_processes,
    inspect_server_sockets,
    is_test_mode,
    is_wsl,
    load_baseline,
    parse_env_assignments,
    pid_is_alive,
    read_proc_env_selected,
    run_cmd,
    test_env,
)

VERDICT_PRIORITY = {
    "VERIFIED": 0,
    "PENDING_RESTART": 1,
    "INCOMPLETE": 2,
    "DRIFT_DETECTED": 3,
    "FAIL": 4,
}

MANUAL_CHECKS = [
    "iOS app: Settings -> About T3 Code -> Diagnostics -> disable Send crash reports & Send connection traces.",
    "Host app: Settings -> Sharing & access -> confirm Publish agent activity is OFF.",
    "Browser: avoid app.t3.codes hosted web client (use local desktop or Tailscale directly).",
]


def _add_check(
    checks: list[dict[str, Any]],
    cid: str,
    cat: str,
    status: str,
    msg: str,
    details: dict[str, Any] | None = None,
) -> None:
    item: dict[str, Any] = {"id": cid, "category": cat, "status": status, "message": msg}
    if details is not None:
        item["details"] = details
    checks.append(item)


def _audit_static(
    checks: list[dict[str, Any]],
    baseline: dict[str, Any],
    args: argparse.Namespace,
    userdata_dir: str,
) -> bool:
    req_env: dict[str, str] = baseline["requiredEnv"]
    env_keys = list(req_env.keys())
    profile = args.profile
    os_name = args.os_name

    rc_list = [p for p in args.rc_files.split(",") if p] if args.rc_files else []
    static_env_ok = True
    if not rc_list:
        static_env_ok = False
        _add_check(checks, "env.rc", "static", "FAIL", "No shell rc files resolved for verification.")

    for rc_path in rc_list:
        parsed = parse_env_assignments(rc_path, env_keys, kind="rc")
        if not parsed["exists"]:
            static_env_ok = False
            _add_check(checks, f"env.rc:{rc_path}", "static", "FAIL", f"Shell rc file missing: {rc_path}")
            continue
        mismatches = {
            k: {"expected": req_env[k], "actual": parsed["effective"][k]}
            for k in env_keys
            if parsed["effective"][k] != req_env[k]
        }
        if mismatches:
            static_env_ok = False
            _add_check(checks, f"env.rc:{rc_path}", "static", "FAIL", f"Effective env flags missing or overridden in {rc_path}", {"mismatches": mismatches})
        else:
            _add_check(checks, f"env.rc:{rc_path}", "static", "PASS", f"Effective env flags valid in {rc_path}")

    if args.service_env and os.path.isfile(args.service_env):
        parsed_svc = parse_env_assignments(args.service_env, env_keys, kind="service")
        mismatches = {
            k: {"expected": req_env[k], "actual": parsed_svc["effective"][k]}
            for k in env_keys
            if parsed_svc["effective"][k] != req_env[k]
        }
        if mismatches:
            static_env_ok = False
            _add_check(checks, "env.service_env", "static", "FAIL", f"service.env missing or conflicting flags: {args.service_env}", {"mismatches": mismatches})
        else:
            _add_check(checks, "env.service_env", "static", "PASS", f"service.env flags valid: {args.service_env}")
    else:
        _add_check(checks, "env.service_env", "static", "INFO", f"No service.env at {args.service_env} (ok if not using 't3 service').")

    # Check extra shell startup files (read-only) for conflicting overrides.
    home_dir = os.path.expanduser("~")
    extra_profiles = [
        os.path.join(home_dir, name)
        for name in (".profile", ".bash_profile", ".zprofile", ".zshenv")
        if os.path.join(home_dir, name) not in rc_list and os.path.isfile(os.path.join(home_dir, name))
    ]
    for prof_path in extra_profiles:
        parsed_extra = parse_env_assignments(prof_path, env_keys, kind="rc")
        conflicts = {
            k: {"expected": req_env[k], "actual": parsed_extra["effective"][k]}
            for k in env_keys
            if parsed_extra["effective"][k] is not None and parsed_extra["effective"][k] != req_env[k]
        }
        if conflicts:
            static_env_ok = False
            _add_check(
                checks,
                f"env.profile:{prof_path}",
                "static",
                "FAIL",
                f"Conflicting env override found in {prof_path}",
                {"mismatches": conflicts},
            )

    if os_name == "Darwin" and test_env("T3CODE_SKIP_LAUNCHCTL") != "1":
        lc_bad = {}
        for k, want in req_env.items():
            code, out, _ = run_cmd(["launchctl", "getenv", k])
            got = out.strip() if code == 0 else ""
            if got != want:
                lc_bad[k] = {"expected": want, "actual": got or None}
        if lc_bad:
            _add_check(checks, "env.macos_launchctl", "static", "PENDING_RESTART", "macOS launchctl current-session env not set (run apply or re-login).", {"mismatches": lc_bad})
        else:
            _add_check(checks, "env.macos_launchctl", "static", "PASS", "macOS launchctl session env flags valid.")

    if os_name == "Darwin":
        mdm_paths = [
            test_env("T3CODE_MACOS_MDM_PLIST", "/Library/Managed Preferences/com.t3tools.t3code.plist"),
            os.path.expanduser("~/Library/Managed Preferences/com.t3tools.t3code.plist"),
        ]
        found_mdm = [p for p in mdm_paths if p and os.path.exists(p)]
        if found_mdm and not args.no_policy and args.policy_path and os.path.exists(args.policy_path):
            _add_check(checks, "conflict.macos_mdm", "static", "FAIL", f"macOS MDM profile ({found_mdm[0]}) coexists with file policy ({args.policy_path}); T3 Code refuses to start.", {"mdmPaths": found_mdm})
        elif found_mdm:
            _add_check(checks, "conflict.macos_mdm", "static", "INFO", f"macOS MDM profile detected at {found_mdm[0]} (file policy skipped).")

    if os_name == "Linux" and is_wsl():
        win_policy = test_env("T3CODE_WSL_WIN_POLICY", "/mnt/c/Program Files/T3Code/policy.json") or "/mnt/c/Program Files/T3Code/policy.json"
        if os.path.exists(win_policy):
            _add_check(checks, "conflict.wsl_windows_policy", "static", "FAIL", f"Windows policy exists at {win_policy}; T3 Code desktop will run server on Windows and bypass WSL policy.")
        else:
            _add_check(checks, "conflict.wsl_windows_policy", "static", "PASS", f"WSL check: no Windows policy file at {win_policy}.")

    if args.no_policy:
        _add_check(checks, "policy.file", "static", "INFO", "Policy file check skipped (--no-policy).")
    elif not args.policy_path:
        _add_check(checks, "policy.file", "static", "FAIL", "No policy path configured for this OS.")
    elif not os.path.exists(args.policy_path):
        _add_check(checks, "policy.file", "static", "FAIL", f"Policy file missing: {args.policy_path}")
    else:
        if os.path.islink(args.policy_path):
            _add_check(checks, "policy.permissions", "static", "FAIL", f"Policy path is a symlink (tamper risk): {args.policy_path}")
        else:
            mode = stat.S_IMODE(os.stat(args.policy_path).st_mode)
            if mode & 0o022:
                _add_check(checks, "policy.permissions", "static", "FAIL", f"Policy file permissions too permissive ({oct(mode)}): {args.policy_path} (must not be group/world writable).")
            else:
                _add_check(checks, "policy.permissions", "static", "PASS", f"Policy file permissions safe ({oct(mode)}).")
        try:
            with open(args.policy_path, encoding="utf-8") as fh:
                policy_doc = json.load(fh)
        except Exception as exc:
            _add_check(checks, "policy.file", "static", "FAIL", f"Policy file is not valid JSON: {exc}")
        else:
            spec = baseline["profiles"][profile]
            mismatches_p: list[str] = []
            if policy_doc.get("schemaVersion") != baseline["policySchemaVersion"]:
                mismatches_p.append(f"schemaVersion: expected {baseline['policySchemaVersion']}, got {policy_doc.get('schemaVersion')}")
            org_val = policy_doc.get("organization")
            if not isinstance(org_val, str) or not org_val.strip():
                mismatches_p.append("organization: must be a non-empty string")
            mismatches_p.extend(deep_subset_check(policy_doc.get("limits"), spec["limits"], "limits"))
            if spec.get("settings"):
                mismatches_p.extend(deep_subset_check(policy_doc.get("settings"), spec["settings"], "settings"))
            if mismatches_p:
                _add_check(checks, "policy.file", "static", "FAIL", f"Policy content does not satisfy '{profile}' profile: {args.policy_path}", {"mismatches": mismatches_p})
            else:
                _add_check(checks, "policy.file", "static", "PASS", f"Policy content satisfies '{profile}' profile: {args.policy_path}")

    settings_path = os.path.join(userdata_dir, "settings.json")
    if os.path.isfile(settings_path):
        try:
            with open(settings_path, encoding="utf-8") as fh:
                user_settings = json.load(fh)
        except Exception as exc:
            _add_check(checks, "settings.user_file", "static", "INCOMPLETE", f"Unable to parse {settings_path}: {exc}")
        else:
            bad_always = [k for k in baseline["forbiddenUserSettings"]["always"] if user_settings.get(k) is True]
            bad_strict = [k for k in baseline["forbiddenUserSettings"]["strictOnly"] if user_settings.get(k) is True]
            if bad_always:
                _add_check(checks, "settings.user_file", "static", "FAIL", f"Privacy-sensitive setting enabled in {settings_path}: {', '.join(bad_always)}", {"enabled": bad_always})
            elif profile == "strict" and bad_strict:
                _add_check(checks, "settings.user_file", "static", "FAIL", f"Strict-profile forbidden setting enabled in {settings_path}: {', '.join(bad_strict)}", {"enabled": bad_strict})
            else:
                msg = f"User settings clean: {settings_path}"
                if bad_strict:
                    msg += f" (note: {', '.join(bad_strict)} enabled; locked off in --profile strict)"
                _add_check(checks, "settings.user_file", "static", "PASS", msg)
    else:
        _add_check(checks, "settings.user_file", "static", "INFO", f"No user settings file yet at {settings_path}.")

    return static_env_ok


def _audit_runtime(
    checks: list[dict[str, Any]],
    baseline: dict[str, Any],
    args: argparse.Namespace,
    t3_home: str,
    userdata_dir: str,
    static_env_ok: bool,
) -> tuple[str | None, int | None, bool, str | None]:
    req_env: dict[str, str] = baseline["requiredEnv"]
    env_keys = list(req_env.keys())
    t3_bin = discover_t3_binary(args.t3_bin, t3_home, args.os_name)
    installed_fp: str | None = None
    running_pid: int | None = None
    running_version: str | None = None

    if not t3_bin:
        _add_check(checks, "cli.discovery", "runtime", "INCOMPLETE", "t3 CLI binary not found (checked --t3-bin, PATH, ~/.t3/wsl-runtime, tools). Cannot run policy check, status, or drift detection.")
    else:
        _add_check(checks, "cli.discovery", "runtime", "PASS", f"Found t3 CLI: {t3_bin}")

        if not args.no_policy and args.policy_path and os.path.isfile(args.policy_path):
            code, out, err = run_cmd([t3_bin, "policy", "check", args.policy_path])
            combined = (out + "\n" + err).strip()
            if code != 0:
                _add_check(checks, "policy.cli_check", "runtime", "FAIL", f"t3 policy check failed for {args.policy_path}", {"output": combined[:500]})
            else:
                m_fp = re.search(r"fingerprint\s+([0-9A-Za-z_-]+)", combined)
                installed_fp = m_fp.group(1) if m_fp else None
                _add_check(checks, "policy.cli_check", "runtime", "PASS", f"t3 policy check passed (fingerprint: {installed_fp or 'unknown'}).")

        code, out, err = run_cmd([t3_bin, "policy", "show", "--base-dir", t3_home])
        if code != 0 and "unknown" in (out + err).lower() and "--base-dir" in (out + err):
            code, out, err = run_cmd([t3_bin, "policy", "show"])
        show_text = (out + "\n" + err).strip()
        if code != 0:
            _add_check(checks, "runtime.policy_show", "runtime", "INCOMPLETE", f"t3 policy show returned exit {code}.", {"output": show_text[:500]})
        else:
            low = show_text.lower()
            m_pid = re.search(r"running server\s*\(pid\s+(\d+)", show_text, re.IGNORECASE)
            if m_pid:
                running_pid = int(m_pid.group(1))
            if "restart t3 code to apply" in low:
                _add_check(checks, "runtime.policy_show", "runtime", "PENDING_RESTART", "Running T3 Code server has NOT loaded the latest installed policy yet (restart required).")
            elif "loaded this policy" in low:
                m_show_fp = re.search(r"fingerprint\s+([0-9A-Za-z_-]+)", show_text)
                show_fp = m_show_fp.group(1) if m_show_fp else None
                if installed_fp and show_fp and installed_fp != show_fp:
                    _add_check(checks, "runtime.policy_show", "runtime", "PENDING_RESTART", f"Policy fingerprint mismatch (installed={installed_fp}, show={show_fp}).")
                else:
                    _add_check(checks, "runtime.policy_show", "runtime", "PASS", f"Running server loaded the installed policy (fingerprint: {show_fp or 'verified'}).")
            elif "no running server" in low or not m_pid:
                _add_check(checks, "runtime.policy_show", "runtime", "PENDING_RESTART", "No running T3 Code server detected by 't3 policy show' (start/restart T3 Code and re-verify).")
            else:
                _add_check(checks, "runtime.policy_show", "runtime", "INCOMPLETE", "Unrecognized 't3 policy show' output; cannot confirm server loaded policy.", {"output": show_text[:500]})

        code, out, err = run_cmd([t3_bin, "status", "--base-dir", t3_home])
        if code != 0 and "--base-dir" in (out + err):
            code, out, err = run_cmd([t3_bin, "status"])
        status_text = (out + "\n" + err).strip()
        if code != 0:
            _add_check(checks, "runtime.t3_status", "runtime", "INCOMPLETE", f"t3 status returned exit {code}.")
        else:
            m_conn = re.search(r"T3 Connect\s+(\S+)", status_text, re.IGNORECASE)
            m_lan = re.search(r"Local network\s+(.+)", status_text, re.IGNORECASE)
            if not m_conn:
                _add_check(checks, "runtime.t3_status", "runtime", "INCOMPLETE", "Could not find 'T3 Connect' field in 't3 status' output.")
            elif m_conn.group(1).strip().lower() == "off":
                lan_info = m_lan.group(1).strip() if m_lan else "unknown"
                _add_check(checks, "runtime.t3_status", "runtime", "PASS", f"t3 status confirms T3 Connect is off (Local network: {lan_info}).")
            else:
                _add_check(checks, "runtime.t3_status", "runtime", "FAIL", f"t3 status reports T3 Connect is NOT off: {m_conn.group(1).strip()}")

    runtime_json_path = os.path.join(userdata_dir, "server-runtime.json")
    runtime_pid_alive = False
    if not os.path.isfile(runtime_json_path):
        _add_check(checks, "runtime.server_json", "runtime", "PENDING_RESTART", f"No active server metadata at {runtime_json_path} (start/restart T3 Code and re-verify).")
    else:
        try:
            with open(runtime_json_path, encoding="utf-8") as fh:
                rt = json.load(fh)
        except Exception as exc:
            _add_check(checks, "runtime.server_json", "runtime", "INCOMPLETE", f"Failed to parse {runtime_json_path}: {exc}")
        else:
            rt_pid = rt.get("pid")
            running_version = rt.get("serverVersion")
            if isinstance(rt_pid, int) and pid_is_alive(rt_pid):
                running_pid = rt_pid
                runtime_pid_alive = True
                mp = rt.get("managedPolicy") or {}
                mp_fp, mp_src = mp.get("fingerprint"), mp.get("source")
                if not args.no_policy:
                    if not mp_fp:
                        _add_check(checks, "runtime.server_json", "runtime", "PENDING_RESTART", f"Running server (pid {rt_pid}) has no managedPolicy loaded (restart required).")
                    elif installed_fp and mp_fp != installed_fp:
                        _add_check(checks, "runtime.server_json", "runtime", "PENDING_RESTART", f"Running server (pid {rt_pid}) loaded stale policy fingerprint {mp_fp} != installed {installed_fp}.")
                    else:
                        _add_check(checks, "runtime.server_json", "runtime", "PASS", f"Running server (pid {rt_pid}, v{running_version or '?'}) loaded policy {mp_src} (fingerprint {mp_fp}).")
                else:
                    _add_check(checks, "runtime.server_json", "runtime", "PASS", f"Running server active (pid {rt_pid}, v{running_version or '?'}).")
            else:
                _add_check(checks, "runtime.server_json", "runtime", "PENDING_RESTART", f"Server PID {rt_pid} in server-runtime.json is not running (start/restart T3 Code).")

    if runtime_pid_alive and running_pid and args.os_name == "Linux":
        proc_env, env_err = read_proc_env_selected(running_pid, env_keys)
        if env_err or proc_env is None:
            _add_check(checks, "runtime.proc_environ", "runtime", "INCOMPLETE", f"Cannot inspect running server environment for pid {running_pid}: {env_err}")
        else:
            bad = {k: {"expected": req_env[k], "actual": proc_env[k]} for k in env_keys if proc_env[k] != req_env[k]}
            if bad:
                status = "PENDING_RESTART" if static_env_ok else "FAIL"
                _add_check(checks, "runtime.proc_environ", "runtime", status, f"Running server (pid {running_pid}) does NOT have lockdown env vars active yet.", {"mismatches": bad})
            else:
                _add_check(checks, "runtime.proc_environ", "runtime", "PASS", f"Running server (pid {running_pid}) process environment has both lockdown env vars active.")
    elif runtime_pid_alive and running_pid and args.os_name == "Darwin":
        _add_check(checks, "runtime.proc_environ", "runtime", "INFO", "macOS restricts reading another process's environ without root; verified via rc + launchctl.")

    return t3_bin, running_pid, runtime_pid_alive, running_version


def _audit_drift(
    checks: list[dict[str, Any]],
    baseline: dict[str, Any],
    t3_bin: str | None,
    running_version: str | None,
) -> dict[str, Any]:
    drift: dict[str, Any] = {
        "auditedVersions": baseline.get("auditedVersions", []),
        "installedVersion": None,
        "runningVersion": running_version,
        "versionDrift": [],
        "schemaChanged": False,
        "cliChanged": False,
        "addedPolicies": {},
        "removedPolicies": {},
        "addedElements": {},
        "removedElements": {},
        "addedCliSubcommands": [],
        "addedPolicySubcommands": [],
        "detected": False,
    }
    if not t3_bin:
        return drift

    snap = capture_snapshot(t3_bin)
    drift = compute_drift(baseline, snap, running_version)

    if not snap["version"]:
        _add_check(checks, "drift.version", "drift", "INCOMPLETE", f"Could not parse version from 't3 --version': {snap['rawVersion']!r}")
    elif drift["versionDrift"]:
        _add_check(checks, "drift.version", "drift", "DRIFT_DETECTED", f"Unaudited T3 Code version detected ({', '.join(drift['versionDrift'])}; audited: {', '.join(drift['auditedVersions'])}). Do NOT claim safe until audited.", {"versionDrift": drift["versionDrift"], "auditedVersions": drift["auditedVersions"]})
    else:
        _add_check(checks, "drift.version", "drift", "PASS", f"T3 Code version {snap['version']} matches audited baseline.")

    if snap["version"] and running_version and snap["version"] != running_version:
        _add_check(checks, "drift.running_version_mismatch", "runtime", "PENDING_RESTART", f"Installed t3 ({snap['version']}) differs from running server ({running_version}); restart required.")

    if snap["admxPolicies"] is None:
        _add_check(checks, "drift.policy_schema", "drift", "INCOMPLETE", f"Unable to inspect live policy schema via 't3 policy templates': {snap['admxError']}")
    elif drift["schemaChanged"]:
        _add_check(checks, "drift.policy_schema", "drift", "DRIFT_DETECTED", "Live T3 Code policy schema differs from audited baseline! Audit new/changed fields before claiming safe.", {"addedPolicies": drift["addedPolicies"], "removedPolicies": drift["removedPolicies"], "addedElements": drift["addedElements"], "removedElements": drift["removedElements"]})
    else:
        _add_check(checks, "drift.policy_schema", "drift", "PASS", "Live ADMX policy schema matches audited baseline.")

    if snap["cliSubcommands"] is None or snap["policySubcommands"] is None:
        _add_check(checks, "drift.cli_surface", "drift", "INCOMPLETE", "Could not parse 't3 --help' or 't3 policy --help' subcommands.")
    elif drift["cliChanged"]:
        _add_check(checks, "drift.cli_surface", "drift", "DRIFT_DETECTED", "New T3 CLI subcommands detected outside audited baseline.", {"addedCliSubcommands": drift["addedCliSubcommands"], "addedPolicySubcommands": drift["addedPolicySubcommands"]})
    else:
        _add_check(checks, "drift.cli_surface", "drift", "PASS", "T3 CLI subcommands match audited baseline.")

    return drift


def run_verify(args: argparse.Namespace) -> dict[str, Any]:
    baseline = load_baseline(args.baseline)
    if args.profile not in baseline["profiles"]:
        raise SystemExit(f"unknown profile: {args.profile}")

    t3_home = args.t3_home or os.environ.get("T3CODE_HOME") or os.path.expanduser("~/.t3")
    userdata_dir = os.path.join(t3_home, "userdata")
    checks: list[dict[str, Any]] = []

    overrides = active_test_overrides()
    if is_test_mode():
        _add_check(
            checks,
            "audit.test_mode",
            "static",
            "INFO",
            f"Running in explicit test mode (T3CODE_LOCKDOWN_TEST_MODE=1); active overrides: {', '.join(overrides) or 'none'}.",
            {"activeTestOverrides": overrides},
        )
    elif overrides:
        _add_check(
            checks,
            "audit.unexpected_test_env",
            "static",
            "INCOMPLETE",
            f"Test-only override env vars detected outside test mode (ignored, refusing VERIFIED): {', '.join(overrides)}. Unset them and re-run verify.",
            {"ignoredOverrides": overrides},
        )

    static_env_ok = _audit_static(checks, baseline, args, userdata_dir)
    t3_bin, running_pid, runtime_pid_alive, running_version = _audit_runtime(
        checks, baseline, args, t3_home, userdata_dir, static_env_ok
    )

    forbidden_hits, ps_err = inspect_forbidden_processes(baseline.get("forbiddenProcesses", ["cloudflared"]))
    if ps_err is not None or forbidden_hits is None:
        _add_check(checks, "network.forbidden_processes", "network", "INCOMPLETE", f"Process audit failed: {ps_err}")
    elif forbidden_hits:
        _add_check(checks, "network.forbidden_processes", "network", "FAIL", f"Forbidden tunnel process detected (read-only check; not killed): {', '.join(forbidden_hits)}", {"processes": forbidden_hits})
    else:
        _add_check(checks, "network.forbidden_processes", "network", "PASS", "No cloudflared tunnel process running.")

    if runtime_pid_alive and running_pid:
        sock_info = inspect_server_sockets(running_pid)
        _add_check(checks, "network.server_sockets", "network", "INFO", f"Server pid {running_pid} sockets ({sock_info['tool']}, zero-DNS): {len(sock_info['listen'])} listening, {len(sock_info['established'])} established.", sock_info)

    drift = _audit_drift(checks, baseline, t3_bin, running_version)

    verdict = "VERIFIED"
    for item in checks:
        st = item["status"]
        if st in VERDICT_PRIORITY and VERDICT_PRIORITY[st] > VERDICT_PRIORITY[verdict]:
            verdict = st

    exit_code = int(baseline["exitCodes"][verdict])
    applied_actions: list[str] = []
    if args.actions_file and os.path.isfile(args.actions_file):
        with open(args.actions_file, encoding="utf-8", errors="replace") as fh:
            applied_actions = [line.rstrip("\n") for line in fh if line.strip()]

    return {
        "verdict": verdict,
        "exitCode": exit_code,
        "safeToClaimLocked": verdict == "VERIFIED" and not is_test_mode(),
        "testMode": is_test_mode(),
        "activeTestOverrides": overrides if is_test_mode() else [],
        "profile": args.profile,
        "platform": args.os_name,
        "isWsl": is_wsl() if args.os_name == "Linux" else False,
        "policyPath": None if args.no_policy else args.policy_path,
        "t3Binary": t3_bin,
        "installedVersion": drift["installedVersion"],
        "runningVersion": drift["runningVersion"],
        "auditedVersions": drift["auditedVersions"],
        "drift": drift,
        "appliedActions": applied_actions,
        "checks": checks,
        "manualChecksRequired": MANUAL_CHECKS,
        "nextSteps": build_next_steps(verdict),
    }


def build_next_steps(verdict: str) -> list[str]:
    if verdict == "VERIFIED":
        return [
            "All automated lockdown, runtime, and drift checks passed.",
            "Confirm the manual-only items (iOS Diagnostics, Publish agent activity, avoid app.t3.codes).",
        ]
    steps = {
        "FAIL": "Fix all [FAIL] items above before claiming lockdown is active, then re-run verify.",
        "DRIFT_DETECTED": "T3 Code version/schema drift detected: run 'lockdown.sh snapshot' and follow the Drift Triage Protocol in SKILL.md before trusting lockdown.",
        "INCOMPLETE": "Resolve [INCOMPLETE] checks (e.g. pass --t3-bin /path/to/t3) so every required check actually executes.",
        "PENDING_RESTART": "Ask the user to restart T3 Code (and re-login / open a fresh shell for env vars), then re-run verify until VERIFIED (exit 0).",
    }
    return [steps[verdict]]


def print_human_report(report: dict[str, Any]) -> None:
    if report.get("appliedActions"):
        print("=== APPLIED ACTIONS ===")
        for line in report["appliedActions"]:
            print(f"  {line}")
        print()

    tag_map = {
        "PASS": "[PASS]      ",
        "FAIL": "[FAIL]      ",
        "PENDING_RESTART": "[PENDING]   ",
        "DRIFT_DETECTED": "[DRIFT]     ",
        "INCOMPLETE": "[INCOMPLETE]",
        "INFO": "[INFO]      ",
    }
    for cat, title in [
        ("static", "STATIC CONFIG"),
        ("runtime", "LIVE RUNTIME"),
        ("network", "NETWORK / PROCESS (READ-ONLY)"),
        ("drift", "UPDATE DRIFT DETECTION"),
    ]:
        items = [c for c in report["checks"] if c["category"] == cat]
        if not items:
            continue
        print(f"=== {title} ===")
        for item in items:
            print(f"  {tag_map.get(item['status'], '[?]')} {item['message']}")
            details = item.get("details")
            if details and item["status"] in ("FAIL", "DRIFT_DETECTED", "PENDING_RESTART"):
                print(f"               details: {json.dumps(details, ensure_ascii=False)}")
        print()

    print("=== VERDICT ===")
    print(f"  Verdict:           {report['verdict']} (exit {report['exitCode']})")
    print(f"  Safe to claim ok:  {'YES' if report['safeToClaimLocked'] else 'NO'}")
    print(f"  Profile:           {report['profile']}")
    print(f"  Installed t3:      {report['installedVersion'] or 'unknown'} (audited: {', '.join(report['auditedVersions'])})")
    print(f"  Running server:    {report['runningVersion'] or 'not detected'}")
    print("  Next steps:")
    for step in report["nextSteps"]:
        print(f"    - {step}")
    print("  Manual-only reminders (not enforced by host scripts):")
    for m in report["manualChecksRequired"]:
        print(f"    - {m}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="t3code-lockdown Unix audit helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate-policy")
    p_gen.add_argument("--baseline", required=True)
    p_gen.add_argument("--profile", default="standard")
    p_gen.add_argument("--org", default="Local")

    p_env = sub.add_parser("check-env-file")
    p_env.add_argument("--baseline", required=True)
    p_env.add_argument("--file", required=True)
    p_env.add_argument("--kind", choices=["rc", "service"], default="rc")

    p_snap = sub.add_parser("snapshot")
    p_snap.add_argument("--baseline", required=True)
    p_snap.add_argument("--t3-bin", default="")
    p_snap.add_argument("--t3-home", default="")
    p_snap.add_argument("--os-name", default="Linux")

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("--baseline", required=True)
    p_ver.add_argument("--profile", default="standard")
    p_ver.add_argument("--policy-path", default="")
    p_ver.add_argument("--no-policy", action="store_true")
    p_ver.add_argument("--rc-files", default="")
    p_ver.add_argument("--service-env", default="")
    p_ver.add_argument("--os-name", default="Linux")
    p_ver.add_argument("--t3-bin", default="")
    p_ver.add_argument("--t3-home", default="")
    p_ver.add_argument("--actions-file", default="")
    p_ver.add_argument("--json", action="store_true", dest="as_json")

    args = parser.parse_args(argv)

    if args.cmd == "generate-policy":
        doc = build_policy_document(load_baseline(args.baseline), args.profile, args.org)
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "check-env-file":
        baseline = load_baseline(args.baseline)
        req_env = baseline["requiredEnv"]
        parsed = parse_env_assignments(args.file, list(req_env.keys()), kind=args.kind)
        mismatches, conflicts, missing = {}, {}, []
        for k, want in req_env.items():
            actual = parsed["effective"][k]
            if actual is None:
                missing.append(k)
                mismatches[k] = {"expected": want, "actual": None}
            elif actual != want:
                conflicts[k] = {"expected": want, "actual": actual}
                mismatches[k] = {"expected": want, "actual": actual}
        out = {"exists": parsed["exists"], "ok": parsed["exists"] and not mismatches, "missing": missing, "conflicts": conflicts, "effective": parsed["effective"]}
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out["ok"] else 1

    if args.cmd == "snapshot":
        baseline = load_baseline(args.baseline)
        t3_home = args.t3_home or os.environ.get("T3CODE_HOME") or os.path.expanduser("~/.t3")
        t3_bin = discover_t3_binary(args.t3_bin or None, t3_home, args.os_name)
        if not t3_bin:
            print(json.dumps({"error": "t3 CLI binary not found", "verdict": "INCOMPLETE"}, indent=2))
            return int(baseline["exitCodes"]["INCOMPLETE"])
        snap = capture_snapshot(t3_bin)
        snap["diffAgainstBaseline"] = compute_drift(baseline, snap, None)
        print(json.dumps(snap, indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    if args.cmd == "verify":
        report = run_verify(args)
        if args.as_json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print_human_report(report)
        return int(report["exitCode"])

    return 2


if __name__ == "__main__":
    sys.exit(main())
