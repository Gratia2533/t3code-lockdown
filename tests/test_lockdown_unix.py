#!/usr/bin/env python3
"""Automated unit & integration tests for t3code-lockdown Unix scripts.

Runs completely isolated in temporary directories with mock t3 binaries and
fixture /proc and ps inputs; never modifies the real host environment.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCKDOWN_SH = REPO_ROOT / "t3code-lockdown" / "scripts" / "lockdown.sh"
BASELINE_JSON = REPO_ROOT / "t3code-lockdown" / "references" / "baseline.json"


def load_baseline() -> dict:
    return json.loads(BASELINE_JSON.read_text(encoding="utf-8"))


def build_admx(policies: dict[str, list[str]]) -> str:
    blocks = []
    for name, elems in sorted(policies.items()):
        el_xml = "".join(
            f'<boolean id="{eid}" valueName="{eid}" />' for eid in sorted(elems)
        )
        elements_block = f"<elements>{el_xml}</elements>" if elems else ""
        blocks.append(f'<policy name="{name}" class="Machine">{elements_block}</policy>')
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">'
        "<policies>"
        + "".join(blocks)
        + "</policies></policyDefinitions>"
    )


def create_mock_t3(
    dest: Path,
    *,
    version: str = "0.1.11",
    fingerprint: str = "aabbcc112233",
    show_state: str = "loaded",
    connect_state: str = "off",
    running_pid: int | None = None,
    admx_policies: dict[str, list[str]] | None = None,
    cli_subcommands: list[str] | None = None,
    policy_subcommands: list[str] | None = None,
    reject_policy: bool = False,
) -> Path:
    baseline = load_baseline()
    admx_xml = build_admx(admx_policies if admx_policies is not None else baseline["admxPolicies"])
    cli_subs = cli_subcommands if cli_subcommands is not None else baseline["cliSubcommands"]
    pol_subs = policy_subcommands if policy_subcommands is not None else baseline["policySubcommands"]
    pid = running_pid if running_pid is not None else os.getpid()

    main_help = "USAGE\n  t3 <subcommand>\n\nSUBCOMMANDS\n" + "".join(
        f"  {s}   desc\n" for s in cli_subs
    )
    policy_help = "USAGE\n  t3 policy <subcommand>\n\nSUBCOMMANDS\n" + "".join(
        f"  {s}   desc\n" for s in pol_subs
    )

    cfg = {
        "version": version,
        "fingerprint": fingerprint,
        "show_state": show_state,
        "connect_state": connect_state,
        "pid": pid,
        "admx_xml": admx_xml,
        "main_help": main_help,
        "policy_help": policy_help,
        "reject_policy": reject_policy,
    }
    cfg_path = dest.parent / f"{dest.name}.cfg.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    script = textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import json, os, sys
        cfg = json.load(open({str(cfg_path)!r}, encoding="utf-8"))
        args = sys.argv[1:]
        if args == ["--version"]:
            print(f"t3 v{{cfg['version']}}")
            sys.exit(0)
        if args == ["--help"]:
            print(cfg["main_help"])
            sys.exit(0)
        if args[:2] == ["policy", "--help"]:
            print(cfg["policy_help"])
            sys.exit(0)
        if args[:2] == ["policy", "check"]:
            if cfg["reject_policy"]:
                print("ERROR: ManagedPolicyFileError: rejected", file=sys.stderr)
                sys.exit(1)
            print(f"Managed by Test ({{args[2]}}, fingerprint {{cfg['fingerprint']}}).")
            sys.exit(0)
        if args[:2] == ["policy", "show"]:
            print(f"Managed by Test (/tmp/policy.json, fingerprint {{cfg['fingerprint']}}).")
            if cfg["show_state"] == "loaded":
                print(f"The running server (pid {{cfg['pid']}}, started 2026-11-26T00:00:00Z) loaded this policy.")
            elif cfg["show_state"] == "restart":
                print("Restart T3 Code to apply the installed policy.")
            else:
                print("No running server.")
            sys.exit(0)
        if args[:2] == ["policy", "templates"]:
            out_dir = args[2]
            os.makedirs(os.path.join(out_dir, "windows"), exist_ok=True)
            with open(os.path.join(out_dir, "windows", "t3code.admx"), "w", encoding="utf-8") as fh:
                fh.write(cfg["admx_xml"])
            sys.exit(0)
        if args[:1] == ["status"]:
            print("This machine")
            print("  Service        not installed")
            print(f"  T3 Connect     {{cfg['connect_state']}}")
            print("  Local network  off")
            sys.exit(0)
        print(f"unexpected args: {{args}}", file=sys.stderr)
        sys.exit(2)
        """
    )
    dest.write_text(script, encoding="utf-8")
    dest.chmod(0o755)
    return dest


class LockdownUnixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="t3lock-test-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        (self.home / ".bashrc").write_text("# user bashrc\nexport FOO=bar\n", encoding="utf-8")
        self.t3_home = self.home / ".t3"
        self.userdata = self.t3_home / "userdata"
        self.userdata.mkdir(parents=True)
        self.policy_path = self.root / "etc" / "t3code" / "policy.json"
        self.proc_root = self.root / "proc"
        self.ps_file = self.root / "ps.txt"
        self.ps_file.write_text("1 init /sbin/init\n42 bash /bin/bash\n", encoding="utf-8")
        self.win_policy = self.root / "win" / "policy.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _base_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(self.home),
                "T3CODE_HOME": str(self.t3_home),
                "T3CODE_LOCKDOWN_TEST_MODE": "1",
                "T3CODE_NO_SUDO": "1",
                "T3CODE_OS_OVERRIDE": "Linux",
                "T3CODE_ASSUME_WSL": "0",
                "T3CODE_WSL_WIN_POLICY": str(self.win_policy),
                "T3CODE_PROC_ROOT": str(self.proc_root),
                "T3CODE_PS_OUTPUT_FILE": str(self.ps_file),
                "T3CODE_SKIP_LAUNCHCTL": "1",
            }
        )
        env.pop("T3_BIN", None)
        if extra:
            env.update(extra)
        return env

    def _write_live_runtime(
        self,
        *,
        version: str = "0.1.11",
        fingerprint: str = "aabbcc112233",
        proc_env: dict[str, str] | None = None,
    ) -> int:
        pid = os.getpid()
        rt = {
            "version": 1,
            "pid": pid,
            "serverVersion": version,
            "managedPolicy": {
                "source": str(self.policy_path),
                "organization": "TestOrg",
                "fingerprint": fingerprint,
            },
        }
        (self.userdata / "server-runtime.json").write_text(json.dumps(rt), encoding="utf-8")
        pid_dir = self.proc_root / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)
        env_map = (
            proc_env
            if proc_env is not None
            else {
                "T3CODE_TELEMETRY_ENABLED": "false",
                "T3CODE_OTEL_SDK_DISABLED": "true",
            }
        )
        raw = b"".join(f"{k}={v}\x00".encode("utf-8") for k, v in env_map.items())
        (pid_dir / "environ").write_bytes(raw)
        return pid

    def _run(self, *args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(LOCKDOWN_SH), *args],
            env=self._base_env(env_extra),
            capture_output=True,
            text=True,
        )

    def test_standard_apply_pending_then_verified_and_idempotent(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="none")
        # 1. Fresh apply with no running server -> PENDING_RESTART (10)
        res = self._run(
            "apply",
            "--org",
            "TestOrg",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res.returncode, 10, res.stdout + res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["verdict"], "PENDING_RESTART")
        self.assertFalse(data["safeToClaimLocked"])
        pol = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.assertEqual(pol["limits"]["updates"], {"mode": "off", "allowNightly": False})
        self.assertNotIn("settings", pol)

        # 2. Server restarts and loads policy + env -> VERIFIED (0)
        create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        res2 = self._run(
            "verify",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
        data2 = json.loads(res2.stdout)
        self.assertEqual(data2["verdict"], "VERIFIED")
        self.assertTrue(data2["testMode"])
        # In explicit test mode, safeToClaimLocked stays False so test mocks cannot masquerade as live host verification.
        self.assertFalse(data2["safeToClaimLocked"])

        # 3. Re-running apply is idempotent and returns VERIFIED (0)
        res3 = self._run(
            "apply",
            "--org",
            "TestOrg",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res3.returncode, 0, res3.stdout + res3.stderr)
        data3 = json.loads(res3.stdout)
        self.assertTrue(any("unchanged" in a for a in data3["appliedActions"]))

    def test_strict_profile_locks_extra_controls(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        res = self._run(
            "apply",
            "--profile",
            "strict",
            "--org",
            "TestOrg",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        pol = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.assertIs(pol["limits"]["webhookTasks"], False)
        self.assertIs(pol["limits"]["browserCookieImport"], False)
        self.assertIs(pol["limits"]["previewTunnel"], False)
        self.assertEqual(
            pol["settings"]["enableProviderUpdateChecks"], {"value": False, "locked": True}
        )

        # Standard policy fails strict verification
        self._run(
            "apply",
            "--profile",
            "standard",
            "--org",
            "TestOrg",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
        )
        res_fail = self._run(
            "verify",
            "--profile",
            "strict",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res_fail.returncode, 1)
        self.assertEqual(json.loads(res_fail.stdout)["verdict"], "FAIL")

    def test_env_comment_and_trailing_override_caught(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        # Only commented flags -> must FAIL
        (self.home / ".bashrc").write_text(
            "# export T3CODE_TELEMETRY_ENABLED=false\n# export T3CODE_OTEL_SDK_DISABLED=true\n",
            encoding="utf-8",
        )
        self._run(
            "apply",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
        )
        # Now append a trailing override that re-enables telemetry -> must FAIL!
        with open(self.home / ".bashrc", "a", encoding="utf-8") as fh:
            fh.write("\nexport T3CODE_TELEMETRY_ENABLED=true\n")
        res = self._run(
            "verify",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
        )
        self.assertEqual(res.returncode, 1)
        report = json.loads(res.stdout)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertFalse(report["safeToClaimLocked"])

    def test_policy_world_writable_and_symlink_fail(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        os.chmod(self.policy_path, 0o666)
        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 1)
        self.assertEqual(json.loads(res.stdout)["verdict"], "FAIL")

        # Symlink check
        real_copy = self.root / "real_policy.json"
        real_copy.write_text(self.policy_path.read_text(encoding="utf-8"), encoding="utf-8")
        self.policy_path.unlink()
        self.policy_path.symlink_to(real_copy)
        res2 = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res2.returncode, 1)
        self.assertEqual(json.loads(res2.stdout)["verdict"], "FAIL")

    def test_wsl_windows_policy_conflict_fails(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        self.win_policy.parent.mkdir(parents=True, exist_ok=True)
        self.win_policy.write_text("{}", encoding="utf-8")
        res = self._run(
            "verify",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
            env_extra={"T3CODE_ASSUME_WSL": "1"},
        )
        self.assertEqual(res.returncode, 1)
        report = json.loads(res.stdout)
        self.assertTrue(any(c["id"] == "conflict.wsl_windows_policy" and c["status"] == "FAIL" for c in report["checks"]))

    def test_macos_mdm_conflict_skips_apply_and_fails_coexistence(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        mdm_plist = self.root / "com.t3tools.t3code.plist"
        mdm_plist.write_text("<plist/>", encoding="utf-8")
        env_extra = {
            "T3CODE_OS_OVERRIDE": "Darwin",
            "T3CODE_MACOS_MDM_PLIST": str(mdm_plist),
        }
        # apply skips writing policy file when MDM exists
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), env_extra=env_extra)
        self.assertFalse(self.policy_path.exists())

        # If a file somehow coexists with MDM -> FAIL
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_path.write_text(
            json.dumps({"schemaVersion": 1, "organization": "Local", "limits": {"telemetry": False, "connect": False, "updates": {"mode": "off", "allowNightly": False}}}),
            encoding="utf-8",
        )
        res = self._run(
            "verify",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
            env_extra=env_extra,
        )
        self.assertEqual(res.returncode, 1)
        report = json.loads(res.stdout)
        self.assertTrue(any(c["id"] == "conflict.macos_mdm" and c["status"] == "FAIL" for c in report["checks"]))

    def test_drift_version_bump_triggers_exit_20(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", version="0.1.12", show_state="loaded")
        self._write_live_runtime(version="0.1.12")
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 20, res.stdout)
        report = json.loads(res.stdout)
        self.assertEqual(report["verdict"], "DRIFT_DETECTED")
        self.assertFalse(report["safeToClaimLocked"])
        self.assertFalse(report["drift"]["schemaChanged"])
        self.assertIn("installed=0.1.12", report["drift"]["versionDrift"])

    def test_drift_new_admx_policy_and_cli_subcommand(self) -> None:
        baseline = load_baseline()
        new_admx = dict(baseline["admxPolicies"])
        new_admx["CloudTelemetry"] = ["CloudTelemetry_enabled"]
        new_cli = list(baseline["cliSubcommands"]) + ["cloud-sync"]
        t3_bin = create_mock_t3(
            self.root / "t3",
            version="0.2.0",
            admx_policies=new_admx,
            cli_subcommands=new_cli,
            show_state="loaded",
        )
        self._write_live_runtime(version="0.2.0")
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 20)
        report = json.loads(res.stdout)
        self.assertEqual(report["verdict"], "DRIFT_DETECTED")
        self.assertTrue(report["drift"]["schemaChanged"])
        self.assertIn("CloudTelemetry", report["drift"]["addedPolicies"])
        self.assertIn("cloud-sync", report["drift"]["addedCliSubcommands"])

    def test_incomplete_when_t3_binary_missing(self) -> None:
        # Without t3 binary, apply refuses to write an unvalidated policy by default.
        res_refused = self._run("apply", "--policy-path", str(self.policy_path), "--json")
        self.assertFalse(self.policy_path.exists())
        self.assertEqual(res_refused.returncode, 1)  # FAIL because policy file was not written
        self.assertTrue(any("ABORTED: t3 binary not found" in a for a in json.loads(res_refused.stdout)["appliedActions"]))

        # With explicit --allow-unvalidated-policy, policy is written, but verify still fails closed as INCOMPLETE (30).
        self._run("apply", "--policy-path", str(self.policy_path), "--allow-unvalidated-policy")
        self.assertTrue(self.policy_path.exists())
        res = self._run("verify", "--policy-path", str(self.policy_path), "--json")
        self.assertEqual(res.returncode, 30, res.stdout)
        report = json.loads(res.stdout)
        self.assertEqual(report["verdict"], "INCOMPLETE")
        self.assertFalse(report["safeToClaimLocked"])

    def test_test_overrides_ignored_and_refuse_verified_outside_test_mode(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        # Disable T3CODE_LOCKDOWN_TEST_MODE while leaving test override env vars set -> must NOT return VERIFIED!
        res = self._run(
            "verify",
            "--policy-path",
            str(self.policy_path),
            "--t3-bin",
            str(t3_bin),
            "--json",
            env_extra={"T3CODE_LOCKDOWN_TEST_MODE": "0"},
        )
        self.assertNotEqual(res.returncode, 0, res.stdout)
        report = json.loads(res.stdout)
        self.assertFalse(report["safeToClaimLocked"])
        self.assertFalse(report["testMode"])
        self.assertTrue(
            any(c["id"] == "audit.unexpected_test_env" and c["status"] == "INCOMPLETE" for c in report["checks"])
        )

    def test_grep_cloudflared_does_not_false_positive(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        # A grep or editor mentioning cloudflared in its arguments should NOT trigger FAIL.
        self.ps_file.write_text(
            "101 grep grep cloudflared /var/log/syslog\n102 vim vim cloudflared.md\n",
            encoding="utf-8",
        )
        res_ok = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res_ok.returncode, 0, res_ok.stdout)

        # Wrapper invoking cloudflared binary itself MUST still trigger FAIL.
        self.ps_file.write_text("202 sudo sudo -u root /usr/bin/cloudflared tunnel run\n", encoding="utf-8")
        res_fail = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res_fail.returncode, 1, res_fail.stdout)
        report = json.loads(res_fail.stdout)
        self.assertTrue(any(c["id"] == "network.forbidden_processes" and c["status"] == "FAIL" for c in report["checks"]))

    def test_extra_startup_profile_override_caught(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        (self.home / ".zprofile").write_text("export T3CODE_TELEMETRY_ENABLED=true\n", encoding="utf-8")
        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 1, res.stdout)
        report = json.loads(res.stdout)
        self.assertTrue(any(c["id"].startswith("env.profile:") and c["status"] == "FAIL" for c in report["checks"]))

    def test_fail_on_cloudflared_t3_connect_and_publish_activity(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded", connect_state="on")
        self._write_live_runtime()
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        self.ps_file.write_text("999 cloudflared /usr/bin/cloudflared tunnel run\n", encoding="utf-8")
        (self.userdata / "settings.json").write_text(json.dumps({"publishAgentActivity": True}), encoding="utf-8")

        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 1)
        report = json.loads(res.stdout)
        failed_ids = {c["id"] for c in report["checks"] if c["status"] == "FAIL"}
        self.assertIn("runtime.t3_status", failed_ids)
        self.assertIn("network.forbidden_processes", failed_ids)
        self.assertIn("settings.user_file", failed_ids)

    def test_pending_restart_when_live_proc_missing_env_or_stale_fingerprint(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", fingerprint="newfp111", show_state="loaded")
        self._write_live_runtime(fingerprint="oldfp000", proc_env={})
        self._run("apply", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        res = self._run("verify", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin), "--json")
        self.assertEqual(res.returncode, 10, res.stdout)
        report = json.loads(res.stdout)
        self.assertEqual(report["verdict"], "PENDING_RESTART")
        pending_ids = {c["id"] for c in report["checks"] if c["status"] == "PENDING_RESTART"}
        self.assertIn("runtime.server_json", pending_ids)
        self.assertIn("runtime.proc_environ", pending_ids)

    def test_snapshot_mode_returns_valid_json(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", version="0.1.11")
        res = self._run("snapshot", "--t3-bin", str(t3_bin))
        self.assertEqual(res.returncode, 0, res.stderr)
        snap = json.loads(res.stdout)
        self.assertEqual(snap["version"], "0.1.11")
        self.assertFalse(snap["diffAgainstBaseline"]["detected"])

    def test_rollback_steps_back_and_preserves_user_rc(self) -> None:
        t3_bin = create_mock_t3(self.root / "t3", show_state="loaded")
        self._run("apply", "--org", "OrgOne", "--policy-path", str(self.policy_path), "--t3-bin", str(t3_bin))
        # Ensure distinct timestamp for second backup
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        (self.policy_path.parent / "policy.json.bak-20260101-000001").write_text(
            self.policy_path.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.policy_path.write_text(
            json.dumps({"schemaVersion": 1, "organization": "OrgTwo", "limits": {"telemetry": False, "connect": False, "updates": {"mode": "off", "allowNightly": False}}}),
            encoding="utf-8",
        )
        res = self._run("rollback", "--policy-path", str(self.policy_path))
        self.assertEqual(res.returncode, 0, res.stderr)
        restored = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.assertEqual(restored["organization"], "OrgOne")
        rc_text = (self.home / ".bashrc").read_text(encoding="utf-8")
        self.assertIn("export FOO=bar", rc_text)
        self.assertNotIn("t3code-lockdown", rc_text)

        # Second rollback removes policy completely
        res2 = self._run("rollback", "--policy-path", str(self.policy_path))
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertFalse(self.policy_path.exists())


if __name__ == "__main__":
    unittest.main()
