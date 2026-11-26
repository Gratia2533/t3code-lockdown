"""Reusable inspection, policy generation, and drift primitives for t3code-lockdown (Unix).

Stdlib-only (Python 3.8+). Read-only inspection; never modifies files, firewall,
hosts, or running processes, and never issues outbound DNS or network requests.
"""

from __future__ import annotations

import copy
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any

ADMX_NS = {"p": "http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"}


def load_baseline(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_policy_document(baseline: dict[str, Any], profile: str, org: str) -> dict[str, Any]:
    profiles = baseline["profiles"]
    if profile not in profiles:
        raise ValueError(f"unknown profile: {profile}")
    spec = profiles[profile]
    doc: dict[str, Any] = {
        "schemaVersion": baseline["policySchemaVersion"],
        "organization": org,
        "limits": copy.deepcopy(spec["limits"]),
    }
    if spec.get("settings"):
        doc["settings"] = copy.deepcopy(spec["settings"])
    return doc


def _strip_shell_comment(raw: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    out = []
    for ch in raw:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\" and not in_single:
            out.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            out.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            out.append(ch)
            continue
        if ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).strip()


def _unquote_value(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and ((val[0] == val[-1] == "'") or (val[0] == val[-1] == '"')):
        return val[1:-1]
    return val


def _split_semicolons(line: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in line:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and not in_single:
            buf.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            continue
        if ch == ";" and not in_single and not in_double:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def parse_env_assignments(path: str, keys: list[str], kind: str = "rc") -> dict[str, Any]:
    """Parse effective final values for target env keys in a shell rc or KEY=VALUE file."""
    effective: dict[str, str | None] = {k: None for k in keys}
    occurrences: dict[str, list[dict[str, Any]]] = {k: [] for k in keys}
    key_set = set(keys)

    if not os.path.isfile(path):
        return {"exists": False, "effective": effective, "occurrences": occurrences}

    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw_line in enumerate(fh, start=1):
            cleaned = _strip_shell_comment(raw_line)
            if not cleaned:
                continue
            parts = [cleaned] if kind == "service" else _split_semicolons(cleaned)
            for stmt in parts:
                stmt = stmt.strip()
                if not stmt:
                    continue
                if kind == "rc":
                    m_unset = re.match(r"^unset\s+(.+)$", stmt)
                    if m_unset:
                        for tok in m_unset.group(1).split():
                            if tok in key_set:
                                effective[tok] = None
                                occurrences[tok].append({"line": lineno, "op": "unset", "value": None})
                        continue
                    m_assign = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", stmt)
                else:
                    m_assign = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", stmt)
                if not m_assign:
                    continue
                k, raw_v = m_assign.group(1), m_assign.group(2)
                if k in key_set:
                    v = _unquote_value(raw_v)
                    effective[k] = v
                    occurrences[k].append({"line": lineno, "op": "set", "value": v})

    return {"exists": True, "effective": effective, "occurrences": occurrences}


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out after {timeout}s"


def discover_t3_binary(explicit: str | None, t3_home: str, os_name: str) -> str | None:
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("T3_BIN"):
        candidates.append(os.environ["T3_BIN"])
    on_path = shutil.which("t3")
    if on_path:
        candidates.append(on_path)

    for pattern in (
        os.path.join(t3_home, "wsl-runtime", "sha256-*", "t3"),
        os.path.join(t3_home, "tools", "*", "t3"),
    ):
        matches = glob.glob(pattern)
        matches.sort(key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0, reverse=True)
        candidates.extend(matches)

    if os_name == "Darwin":
        candidates.extend([
            "/Applications/T3 Code.app/Contents/Resources/bin/t3",
            os.path.expanduser("~/Applications/T3 Code.app/Contents/Resources/bin/t3"),
        ])

    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def parse_version(raw: str) -> str | None:
    m = re.search(r"\bv?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)\b", raw)
    return m.group(1) if m else None


def parse_subcommands(help_text: str) -> list[str]:
    subs: list[str] = []
    in_section = False
    for line in help_text.splitlines():
        if re.match(r"^SUBCOMMANDS\s*$", line.strip()):
            in_section = True
            continue
        if in_section:
            if not line.strip():
                continue
            if not line.startswith(" "):
                break
            m = re.match(r"^\s+([a-zA-Z0-9_-]+)\s{2,}", line)
            if m:
                subs.append(m.group(1))
    return sorted(set(subs))


def extract_admx_policies(t3_bin: str) -> tuple[dict[str, list[str]] | None, str | None]:
    with tempfile.TemporaryDirectory(prefix="t3-lockdown-tpl-") as tmpd:
        code, out, err = run_cmd([t3_bin, "policy", "templates", tmpd])
        if code != 0:
            return None, (err or out or f"exit {code}").strip()
        admx_path = os.path.join(tmpd, "windows", "t3code.admx")
        if not os.path.isfile(admx_path):
            return None, f"missing expected template file: {admx_path}"
        try:
            root = ET.parse(admx_path).getroot()
        except ET.ParseError as exc:
            return None, f"failed to parse ADMX XML: {exc}"
        policies: dict[str, list[str]] = {}
        for pol in root.findall(".//p:policy", ADMX_NS):
            name = pol.attrib.get("name")
            if not name:
                continue
            elems = sorted(
                e.attrib["id"]
                for e in pol.findall("./p:elements/*", ADMX_NS)
                if e.attrib.get("id")
            )
            policies[name] = elems
        return dict(sorted(policies.items())), None


def capture_snapshot(t3_bin: str) -> dict[str, Any]:
    ver_code, ver_out, ver_err = run_cmd([t3_bin, "--version"])
    raw_ver = (ver_out or ver_err).strip() if ver_code == 0 else ""
    help_code, help_out, help_err = run_cmd([t3_bin, "--help"])
    phelp_code, phelp_out, phelp_err = run_cmd([t3_bin, "policy", "--help"])
    admx_policies, admx_err = extract_admx_policies(t3_bin)

    return {
        "t3Binary": t3_bin,
        "rawVersion": raw_ver,
        "version": parse_version(raw_ver),
        "admxPolicies": admx_policies,
        "admxError": admx_err,
        "cliSubcommands": parse_subcommands(help_out + "\n" + help_err) if help_code == 0 else None,
        "policySubcommands": parse_subcommands(phelp_out + "\n" + phelp_err) if phelp_code == 0 else None,
    }


def deep_subset_check(actual: Any, expected: Any, prefix: str = "") -> list[str]:
    mismatches: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{prefix or 'root'}: expected object, got {type(actual).__name__}"]
        for k, v in expected.items():
            path = f"{prefix}.{k}" if prefix else k
            if k not in actual:
                mismatches.append(f"{path}: missing (expected {json.dumps(v)})")
            else:
                mismatches.extend(deep_subset_check(actual[k], v, path))
    elif actual != expected or type(actual) is not type(expected):
        mismatches.append(f"{prefix}: expected {json.dumps(expected)}, got {json.dumps(actual)}")
    return mismatches


def is_wsl() -> bool:
    if os.environ.get("T3CODE_ASSUME_WSL") == "1":
        return True
    if os.environ.get("T3CODE_ASSUME_WSL") == "0":
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def read_proc_env_selected(pid: int, keys: list[str]) -> tuple[dict[str, str | None] | None, str | None]:
    """Read ONLY the requested env keys from /proc/<pid>/environ (never touches secrets)."""
    proc_root = os.environ.get("T3CODE_PROC_ROOT", "/proc")
    env_path = os.path.join(proc_root, str(pid), "environ")
    try:
        with open(env_path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, str(exc)

    result: dict[str, str | None] = {k: None for k in keys}
    key_set = set(keys)
    for entry in raw.split(b"\x00"):
        if b"=" not in entry:
            continue
        k_b, v_b = entry.split(b"=", 1)
        k = k_b.decode("utf-8", errors="replace")
        if k in key_set:
            result[k] = v_b.decode("utf-8", errors="replace")
    return result, None


def inspect_forbidden_processes(forbidden: list[str]) -> tuple[list[str] | None, str | None]:
    override = os.environ.get("T3CODE_PS_OUTPUT_FILE")
    if override:
        try:
            with open(override, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            return None, str(exc)
    else:
        code, out, err = run_cmd(["ps", "-eo", "pid=,comm=,args="])
        if code != 0:
            return None, (err or out or f"ps exited {code}").strip()
        lines = out.splitlines()

    hits: list[str] = []
    my_pid = str(os.getpid())
    for line in lines:
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        pid_s, comm = parts[0], parts[1]
        args_s = parts[2] if len(parts) > 2 else ""
        if pid_s == my_pid:
            continue
        comm_base = os.path.basename(comm)
        for name in forbidden:
            if comm_base == name or re.search(rf"(?:^|/){re.escape(name)}(?:\s|$)", args_s):
                hits.append(f"pid={pid_s} comm={comm_base}")
                break
    return hits, None


def inspect_server_sockets(pid: int) -> dict[str, Any]:
    """Read-only, zero-DNS numeric socket visibility for the live t3 server PID."""
    if shutil.which("ss"):
        code, out, _ = run_cmd(["ss", "-H", "-atnp"])
        if code == 0:
            estab, listen = [], []
            for line in out.splitlines():
                if f"pid={pid}," not in line and f"pid={pid})" not in line:
                    continue
                cols = line.split()
                if len(cols) >= 5:
                    state, local_addr, peer_addr = cols[0], cols[3], cols[4]
                    if state == "LISTEN":
                        listen.append(local_addr)
                    elif state == "ESTAB":
                        estab.append(f"{local_addr} -> {peer_addr}")
            return {"tool": "ss", "listen": listen, "established": estab}
    return {"tool": "none", "listen": [], "established": []}


def compute_drift(baseline: dict[str, Any], snap: dict[str, Any], running_ver: str | None) -> dict[str, Any]:
    audited_versions = list(baseline.get("auditedVersions", []))
    installed_ver = snap.get("version")

    version_drift: list[str] = []
    if installed_ver and installed_ver not in audited_versions:
        version_drift.append(f"installed={installed_ver}")
    if running_ver and running_ver not in audited_versions:
        version_drift.append(f"running={running_ver}")

    base_admx: dict[str, list[str]] = baseline.get("admxPolicies", {})
    live_admx = snap.get("admxPolicies")
    schema_added: dict[str, list[str]] = {}
    schema_removed: dict[str, list[str]] = {}
    elements_added: dict[str, list[str]] = {}
    elements_removed: dict[str, list[str]] = {}
    if isinstance(live_admx, dict):
        for pol, elems in live_admx.items():
            if pol not in base_admx:
                schema_added[pol] = elems
            else:
                add_e = sorted(set(elems) - set(base_admx[pol]))
                rem_e = sorted(set(base_admx[pol]) - set(elems))
                if add_e:
                    elements_added[pol] = add_e
                if rem_e:
                    elements_removed[pol] = rem_e
        for pol, elems in base_admx.items():
            if pol not in live_admx:
                schema_removed[pol] = elems

    cli_added = (
        sorted(set(snap["cliSubcommands"]) - set(baseline.get("cliSubcommands", [])))
        if isinstance(snap.get("cliSubcommands"), list)
        else []
    )
    pol_cli_added = (
        sorted(set(snap["policySubcommands"]) - set(baseline.get("policySubcommands", [])))
        if isinstance(snap.get("policySubcommands"), list)
        else []
    )

    has_schema_drift = bool(schema_added or schema_removed or elements_added or elements_removed)
    has_cli_drift = bool(cli_added or pol_cli_added)
    return {
        "auditedVersions": audited_versions,
        "installedVersion": installed_ver,
        "runningVersion": running_ver,
        "versionDrift": version_drift,
        "schemaChanged": has_schema_drift,
        "cliChanged": has_cli_drift,
        "addedPolicies": schema_added,
        "removedPolicies": schema_removed,
        "addedElements": elements_added,
        "removedElements": elements_removed,
        "addedCliSubcommands": cli_added,
        "addedPolicySubcommands": pol_cli_added,
        "detected": bool(version_drift) or has_schema_drift or has_cli_drift,
    }
