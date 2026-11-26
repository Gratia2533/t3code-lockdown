<p align="center">
  <img src="assets/logo.png" width="200" alt="t3code-lockdown">
</p>

<p align="center">
  <a href="t3code-lockdown"><img src="https://img.shields.io/badge/skill-t3code--lockdown-24292f?style=flat-square&labelColor=555" alt="skill: t3code-lockdown"></a>
  &nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-24292f?style=flat-square&labelColor=555&logo=github&logoColor=white" alt="license: MIT"></a>
</p>

<p align="center">
  <a href="README.md">English</a> | <strong>繁體中文</strong>
</p>

# t3code-lockdown

把 T3 Code 鎖到「不送遙測、不能用 T3 Connect、不自動更新」的 Agent Skill，並內建**三層唯讀實況稽核與版本／Schema 漂移偵測**——只要還沒重啟、有檢查被略過、或 T3 Code 升級到未審計版本，一律**拒絕誤報安全**。

適用任何支援標準 Agent Skills 格式（`SKILL.md` 搭配 `references/` 與 `scripts/`）的代理，零額外相依、不綁定特定產品。

## 核心特色

- **雙層 Profile（Standard / Strict）**：
  - `standard`（預設）：鎖定 `limits.telemetry=false`、`limits.connect=false`、`limits.updates={mode:"off", allowNightly:false}` 與兩個環境變數（`T3CODE_TELEMETRY_ENABLED=false`、`T3CODE_OTEL_SDK_DISABLED=true`），保留手機經 Tailscale 連線。
  - `strict`（`--profile strict` / `-Profile Strict`）：再加鎖 `limits.webhookTasks=false`、`limits.browserCookieImport=false`、`limits.previewTunnel=false` 與 `settings.enableProviderUpdateChecks={value:false, locked:true}`。
- **5 態 Fail-Closed 判定模型**（支援 `--json` / `-Json` 機器可讀報告）：
  - `0` = `VERIFIED`（唯一允許宣告「已生效／安全」的狀態）
  - `10` = `PENDING_RESTART`（磁碟設定正確，但 T3 Code 尚未啟動或尚未重啟載入新設定）
  - `20` = `DRIFT_DETECTED`（偵測到未審計的 T3 Code 版本、新 ADMX policy 欄位或新 CLI 子命令）
  - `30` = `INCOMPLETE`（找不到 `t3` 執行檔、無法讀取執行期資訊、或 WSL 模式只驗了 Windows 端）
  - `1` = `FAIL`（設定缺失／遭註解或後方覆寫、MDM/GPO/WSL 衝突、`t3 policy check` 失敗、`T3 Connect` 未關閉、發現 `cloudflared` 或敏感設定開啟）
- **實況稽核與更新漂移防線**：
  - 自動探索 `t3`（含 WSL2 的 `~/.t3/wsl-runtime/sha256-*/t3`），寫入 policy 前先用 `t3 policy check` 預檢；驗證 running server 指紋與 Linux/WSL `/proc/<pid>/environ`、`t3 status` 與 `cloudflared`（純唯讀、零 DNS 查詢）。
  - 自動比對本機 `t3 --version`、`t3 policy templates` ADMX schema 與 `t3 --help` 子命令是否偏離 [`t3code-lockdown/references/baseline.json`](t3code-lockdown/references/baseline.json)，並提供 `snapshot` 子命令協助審計新版。

完整步驟、Drift Triage Protocol、驗證與 rollback 見 [`t3code-lockdown/SKILL.md`](t3code-lockdown/SKILL.md)。

## 安裝

把 `t3code-lockdown` 資料夾複製到你使用的代理會讀取的 skills 目錄。常見位置例如：

- 通用／多代理：`~/.agents/skills/t3code-lockdown`
- Claude Code：`~/.claude/skills/t3code-lockdown`
- Codex：`~/.codex/skills/t3code-lockdown`
- Cursor：專案或使用者的 skills 資料夾（實際路徑依 Cursor 版本與設定為準）

複製後請開新 session，或依該代理的方式重新載入 skills。

```bash
git clone git@github.com:Gratia2533/t3code-lockdown.git
cp -R t3code-lockdown/t3code-lockdown ~/.agents/skills/t3code-lockdown
```

HTTPS 的話把 clone 網址改成 `https://github.com/Gratia2533/t3code-lockdown.git`。這是私有倉庫，需要有權限的 GitHub 帳號。

## 內容

- `t3code-lockdown/SKILL.md`：skill 說明、5 態判定契約、操作步驟與 Drift Triage Protocol
- `t3code-lockdown/references/baseline.json`：已審計版本、profile 定義、ADMX schema 與 CLI 子命令基準
- `t3code-lockdown/scripts/lockdown.sh`：Linux／WSL2／macOS（`apply`／`verify`／`rollback`／`snapshot`）
- `t3code-lockdown/scripts/audit_unix.py` 與 `audit_lib.py`：零外部相依的 Python 3 稽核、policy 產生與漂移偵測模組
- `t3code-lockdown/scripts/lockdown.ps1` 與 `audit_windows.ps1`：Windows PowerShell 5.1+／7+（`Apply`／`Verify`／`Rollback`／`Snapshot`、`-CheckWsl`、`-Json`）
- `tests/`：Unix 與 PowerShell 自動化測試（複製安裝 `t3code-lockdown/` 時不需要）

兩個腳本皆為冪等、修改前自動備份，且絕不動防火牆、hosts 或執行中程序。

## 執行測試

```bash
python3 -m unittest discover -s tests -v
```

在 Windows（或 WSL 具備 `powershell.exe` 時）：

```powershell
powershell -ExecutionPolicy Bypass -File tests\test_lockdown_ps1.ps1
```

## 授權

以 [MIT License](LICENSE) 釋出。Copyright (c) 2026 Gratia2533。
