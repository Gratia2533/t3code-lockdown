---
name: t3code-lockdown
description: Lock down T3 Code on a machine so it stops sending usage telemetry, cannot use T3 Connect, and does not auto-update, with Standard/Strict profiles, live runtime and read-only network/process auditing, T3 Code update drift detection, machine-readable JSON output, and rollback. Supports WSL2-backend (recommended) and native Linux/macOS/Windows. Use when asked to set up, harden, audit, verify, triage version drift, or roll back T3 Code privacy/telemetry settings.
---

# T3 Code Lockdown

在新機器上把 T3 Code 鎖到「不送遙測、不能用 T3 Connect、不自動更新」，並透過三層唯讀稽核與版本／Schema 漂移偵測，避免鎖完沒生效或 T3 Code 更新後出現漏網之魚仍誤報安全。

所有已審計版本、policy profile、必要環境變數與 CLI／ADMX 基準都集中在 [`references/baseline.json`](references/baseline.json)（單一真相來源）。

## 兩層防護與 Profile 分級

- **為什麼要兩層**：使用分析送到 PostHog（`ingest.t3.codes`），relay tracing 送到 Axiom。環境變數只管伺服器端遙測；Managed Policy（`schemaVersion: 1`）強制擋 T3 Connect（Cloudflare Tunnel）、自動更新與進階外連。
- **環境變數**（兩組 profile 皆啟用）：`T3CODE_TELEMETRY_ENABLED=false`、`T3CODE_OTEL_SDK_DISABLED=true`。
- **Standard profile（預設，`--profile standard` / `-Profile Standard`）**：
  - `limits.telemetry = false`
  - `limits.connect = false`
  - `limits.updates = { mode: "off", allowNightly: false }`
  - 不設定 `limits.clients`，保留手機經由 Tailscale 連線的能力。
- **Strict profile（`--profile strict` / `-Profile Strict`）**：在 Standard 基礎上再加鎖 4 項（不影響 Tailscale 手機操作）：
  - `limits.webhookTasks = false`（停用 webhook 排程觸發）
  - `limits.browserCookieImport = false`（禁止匯入其他瀏覽器 cookie）
  - `limits.previewTunnel = false`（禁止透過 T3 Code 轉發本機 dev server 給遠端裝置）
  - `settings.enableProviderUpdateChecks = { value: false, locked: true }`（鎖死背景 provider CLI 更新檢查）
- **兩者都涵蓋不到的項目**（例如 `publishAgentActivity` 在 v0.1.11 無法寫入 managed policy，強行寫入會導致 T3 Code 拒絕啟動）：見「手動項目總整理」。

## Agent 鐵則

- **絕不誤報安全（Fail-Closed）**：只有 `verify` 回傳 `VERIFIED`（exit `0`）時，才能宣告自動化範圍已生效；任何非 `0` 狀態（`PENDING_RESTART`、`DRIFT_DETECTED`、`INCOMPLETE`、`FAIL`）都必須如實回報 verdict、exit code 與每一條未通過／未驗證項目，**禁止只因檔案寫入成功或腳本略過檢查就說「安全」**。
- 不改防火牆、hosts；未經詢問不 kill／重啟任何程序（需要重啟 T3 Code 時請使用者手動執行）。
- 需要 sudo／系統管理員時先告知並請使用者提供，不自行繞過。
- 公司機器先確認使用者同意；所有修改前皆自動備份，腳本不含任何機密或個人資訊。
- 不要在輸出中貼出 token、auth 檔內容或非必要環境變數。

## 5 態 Verdict 與 Exit Code 契約

優先序：`FAIL (1) > DRIFT_DETECTED (20) > INCOMPLETE (30) > PENDING_RESTART (10) > VERIFIED (0)`。建議 Agent 呼叫腳本時加上 `--json` / `-Json` 精準判讀 `verdict` 與 `safeToClaimLocked`。

| Verdict | Exit Code | 意義 | Agent 應該怎麼回應 |
| --- | --- | --- | --- |
| `VERIFIED` | `0` | 靜態設定、權限/衝突、`t3 policy check`、執行中 server 指紋與程序 env、`t3 status`、`cloudflared` 檢查、版本與 schema 漂移檢查**全部通過** | 可宣告自動化防線已生效，並附上「手動項目總整理」提醒 |
| `PENDING_RESTART` | `10` | 磁碟設定有效且無漂移，但 T3 Code 尚未啟動或執行中 server 還沒重啟載入最新 policy／env（剛 `apply` 完的正常狀態） | 告知「設定已寫入但**尚未生效**」，請使用者重啟 T3 Code／重新登入後再執行 `verify` |
| `DRIFT_DETECTED` | `20` | 本機 `t3` 版本超出 `references/baseline.json` 已審計版本，或 `t3 policy templates`／`t3 --help` 出現新欄位或子命令 | **禁止稱安全**；立即執行下方「Drift Triage Protocol」 |
| `INCOMPLETE` | `30` | 缺少必要驗證依賴（如找不到 `t3` binary、缺 `python3`、無法讀 `/proc/<pid>/environ`、或 WSL 模式只驗了 Windows 端未驗 WSL 端） | 如實指出哪些檢查沒跑到、原因與補測方式（例如 `--t3-bin` 或 `-CheckWsl`） |
| `FAIL` | `1` | 任一明確違規（設定缺失／遭註解或後方覆寫、policy 權限過寬或為 symlink、MDM/GPO 衝突、WSL 端存在 Windows policy、`t3 policy check` 失敗、`T3 Connect` 非 `off`、發現 `cloudflared`、`publishAgentActivity` 開啟） | 逐項列出 `[FAIL]` 原因與修復動作，修復後重驗 |

## 各平台 policy 位置（出自 T3 Code `docs/user/managed-policy.md`）

| OS | Policy 檔 | 備註 |
| --- | --- | --- |
| Linux | `/etc/t3code/policy.json` | 需 sudo；權限不可對 group/others 可寫 |
| macOS | `/Library/Application Support/T3Code/policy.json` | 需 sudo；若已裝 MDM configuration profile（`com.t3tools.t3code`），**檔案與 profile 並存會讓 T3 Code 拒絕啟動** |
| Windows | `C:\Program Files\T3Code\policy.json` | 需系統管理員；若存在 GPO／`HKLM\SOFTWARE\Policies\T3Tools\T3Code`，同樣不可並存 |
| WSL2 內 | `/etc/t3code/policy.json`（該 distro 內） | Windows 端絕不可有 policy 檔或 registry policy（見下方陷阱） |

- 環境變數：Linux／macOS 桌面 app 讀 shell profile（`~/.bashrc`／`~/.zshrc`）；Windows 用「使用者環境變數」。`t3 service` 不讀 shell rc，改讀 `~/.t3/service.env`（存在時腳本會一併寫入與檢查）。macOS 另外以 `launchctl setenv` 補當前登入工作階段。
- `apply` 在寫入 policy 前會先用 `t3 policy check` 預檢暫存檔，避免寫入無法啟動的壞 policy；**若找不到 `t3` 執行檔，預設會中止寫入 policy**（除非明確加上 `--allow-unvalidated-policy` / `-AllowUnvalidatedPolicy`，且驗證仍會回傳 `INCOMPLETE (30)`）。
- **不要在 policy 加 `limits.clients` 卻漏掉 `"remote"`**：少了 `remote` 會讓 server 只聽 loopback 並停用 Tailscale Serve，導致手機連不上。

## Agent 操作步驟

先確認執行模式（不確定預設 A）與 profile（預設 `standard`；高敏環境可問使用者是否改用 `strict`）。Organization 名稱可用 `--org` / `-Organization` 自訂（預設 `Local`）。路徑皆以本 skill 目錄為基準。

### A. Windows desktop + WSL2 backend（推薦）

1. **Windows 端**（環境變數用一般權限；僅需改名既有 `C:\Program Files\T3Code\policy.json` 時才要系統管理員 PowerShell）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Apply -Backend Wsl -Profile Standard -Organization "<name>"
   ```
   - 設定使用者環境變數。
   - **重要陷阱**：只要 Windows 端有任何 policy（檔案或 GPO／registry），desktop 就**不會用 WSL backend**，server 會改跑在 Windows。腳本會把既有檔案改名為 `policy.json.disabled-<時間>`；若偵測到 registry policy 會報 `FAIL` 交由使用者處理。
2. **WSL 內**（需 sudo）：
   ```bash
   bash scripts/lockdown.sh apply --profile standard --org "<name>"
   ```
   - 寫入 rc 區塊與 `/etc/t3code/policy.json`（先備份並先跑 `t3 policy check` 預檢），並自動偵測 `/mnt/c/Program Files/T3Code/policy.json` 是否誤存。
   - 剛寫完還沒重啟時，腳本會誠實回傳 `PENDING_RESTART (10)`，這是預期過渡態。
3. 請使用者**登出 Windows 再登入**（或開新 shell），並**重啟 T3 Code**。
4. **重啟後執行完整驗證**（必須同時確認 Windows 端與 WSL 端）：
   - 在 Windows 端帶 `-CheckWsl` 一次串查兩端：
     ```powershell
     powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Verify -Backend Wsl -Profile Standard -CheckWsl -Json
     ```
   - 或分別在 Windows 端跑 `-Mode Verify -Backend Wsl` 並於 WSL 內跑 `bash scripts/lockdown.sh verify --profile standard --json`。
   - 只有兩端皆通過且最終達 `VERIFIED (0)` 才能回報已生效。

### B. Linux

```bash
bash scripts/lockdown.sh apply --profile standard --org "<name>"
```
重啟 T3 Code（若用 `t3 service`，另請使用者跑 `t3 service restart`），再執行：
```bash
bash scripts/lockdown.sh verify --profile standard --json
```

### C. macOS

```bash
bash scripts/lockdown.sh apply --profile standard --org "<name>"
```
若機器已由 MDM 安裝 `com.t3tools.t3code` profile，腳本會自動略過寫入檔案（避免啟動失敗），請改用 `--no-policy` 並與使用者確認 MDM 內容。重啟 T3 Code 後跑 `verify --json`。Intel Mac 若無 `t3` CLI，腳本會誠實回報 `INCOMPLETE (30)`，此時須向使用者說明無法執行 CLI/漂移驗證，請搭配 App 內 Settings 人工核對。

### D. Windows 原生（server 跑在 Windows）

系統管理員 PowerShell：
```powershell
powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Apply -Backend Windows -Profile Standard -Organization "<name>"
```
重啟 T3 Code 後再跑：
```powershell
powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Verify -Backend Windows -Profile Standard -Json
```

## Lock 後驗證涵蓋項目（三層唯讀稽核）

1. **靜態層**：忽略註解並解析 `~/.bashrc`／`~/.zshrc` 與 `service.env` 的**最後生效值**（防後方覆寫或 `unset`），並唯讀掃描既有的 `~/.profile`、`~/.bash_profile`、`~/.zprofile`、`~/.zshenv` 是否存在衝突覆寫；Windows 檢查 User/Process/Machine env 覆蓋；驗證 policy JSON 符合所選 profile 與權限安全（非 symlink、非 group/world writable）；偵測 macOS MDM、Windows GPO/Registry、以及 WSL 端誤存 Windows policy；檢查 `~/.t3/userdata/settings.json` 的敏感開關。
   - **靜態解析範圍限制**：僅解析頂層賦值與 `unset`，不實際執行 shell 腳本，也不追蹤 `source` 或動態 `if` 分支（Linux/WSL 端由執行期 `/proc/<pid>/environ` 補位實證）。
2. **執行期層**：自動尋找 `t3`（`--t3-bin` → `T3_BIN` → `PATH` → `~/.t3/bin/t3(.cmd)` → `~/.t3/wsl-runtime/sha256-*/t3` → `tools/`／macOS `.app`）；執行 `t3 policy check` 取得指紋；解析 `t3 policy show` 與 `server-runtime.json` 確認 running server PID 存活且載入同一指紋；Linux/WSL 讀取 `/proc/<pid>/environ`（僅比對兩個目標鍵，絕不讀取或輸出機密）確認程序已吃到 env；檢查 `t3 status` 確認 `T3 Connect` 為 `off`。
   - **macOS 範圍說明**：macOS 未提權時無法直接讀取其他程序的 `environ`，因此 macOS 的 `VERIFIED` 代表「shell rc + `launchctl getenv`（登入工作階段代理環境）+ `t3 policy show`/`server-runtime.json`（實時 policy 指紋）」皆通過，而非直接讀取 server 程序記憶體環境。
3. **連線與程序層（純唯讀、零 DNS 查詢）**：檢查系統程序表是否有實際執行 `cloudflared`（比對命令本身而非任意參數，避免 `grep cloudflared` 誤報；發現則 `FAIL`，絕不 kill）；以純數字模式（`ss -H -atnp`）回報 server PID 的監聽／連線數量供透明檢視。
   - **零 DNS 範圍說明**：為避免稽核本身向 `ingest.t3.codes` 等端點送出 DNS 查詢，本層不做反解或主機名稱封包比對；防外連主要依賴已驗證載入的 policy、環境變數、`t3 status` 與 `cloudflared` 檢查。
4. **版本與 Schema 漂移層**：比對 `t3 --version`、`server-runtime.json` 的 `serverVersion`、`t3 policy templates` 吐出的最新 ADMX 欄位、以及 `t3 --help`／`t3 policy --help` 子命令是否超出 `references/baseline.json`。

## Drift Triage Protocol（偵測到 `DRIFT_DETECTED` 時必做）

當 `verify` 回傳 `DRIFT_DETECTED (20)` 時，代表 T3 Code 已更新到未審計版本或 policy/CLI 介面已變動。Agent **不可宣告安全**，必須依序執行：

1. 擷取本機新版本快照與差集：
   ```bash
   bash scripts/lockdown.sh snapshot
   # 或 Windows:
   powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Snapshot
   ```
2. 檢視 `diffAgainstBaseline`：
   - 若僅有 `versionDrift`（schema 與 CLI 未變）：仍須確認該小版號是否新增未暴露在 ADMX 的遙測開關、新環境變數或預設外連行為。
   - 若有 `addedPolicies`／`addedElements`／`addedCliSubcommands`／`addedPolicySubcommands`：逐項檢視新欄位（可跑 `t3 policy templates <tmpdir>` 讀 ADML 說明文字，或執行 `t3 <new-subcommand> --help`）。
3. 在使用者允許上網查核的情況下，核對官方 T3 Code release notes、`docs/user/managed-policy.md` 與 `telemetry.md`。
4. 向使用者清楚列出：
   - 新舊版本差異與新增欄位／命令
   - 哪些項目可能帶來新的遙測、外連或隱私風險、是否建議加入 `standard` 或 `strict` policy
   - 未完成審計並更新 `references/baseline.json` 之前，該機器處於**未確認漂移狀態**，不應視為已完全鎖定。

## 手機（iOS）設定指南：走自己的 Tailscale

依 T3 Code `docs/user/install.md`、`remote-access.md`、`telemetry.md`：

1. 手機與 host 都登入**同一個 tailnet**（使用者自己的 Tailscale）。
2. 手機安裝官方 App：App Store「T3 Code: Remote Claude & More」（id6787819824）。
3. Host 開放網路存取（擇一）：
   - 桌面 app：Settings → Sharing & access → 開 **Network access**；要 HTTPS 就同頁開 **Tailscale HTTPS**（tailnet 需開 MagicDNS + HTTPS certificates；Linux 需有 Tailscale operator 權限）。
   - CLI／WSL server：`t3 serve --lan`（或 `t3 up --lan`）。要 HTTPS：`t3 serve --tailscale-serve`，已在跑則 `t3 pair --tailscale`。
   - 注意 `--lan` 會同時監聽區網與 tailnet，**配對碼是唯一防線**；只想走 tailnet 建議用 Tailscale HTTPS 並避免在公共 Wi-Fi 長期開啟。
4. 產生配對：在 host 執行 `t3 pair`（或桌面 app Sharing & access 建連結），用手機 **Settings → Environments → Add environment** 掃 QR 或貼上配對 URL（HTTPS 需明確寫 `https://`）。配對連結等同密碼，不要貼到聊天或紀錄。
5. **不要用 T3 Connect／app.t3.codes**：policy 的 `limits.connect=false` 會擋 T3 Connect；也不要開 **Publish agent activity**（Settings → Sharing & access，會把專案／thread 標題與模型名送到 relay，關閉遙測不會停它）。
6. 手機端關閉診斷：**Settings → About T3 Code → Diagnostics**，關掉 **Send crash reports** 與 **Send connection traces**。
7. 驗證：手機 Settings → Environments 看到該機器與 route；斷開蜂巢網路只留 Tailscale 仍能連。

WSL2 backend 時，手機連的是 WSL 內 server，需確認該 server 可從 tailnet 到達（如 mirrored networking）；不要為此改防火牆／hosts，需要時請使用者決定。

## 手動項目總整理（腳本涵蓋不到）

1. **iOS App**：Diagnostics 兩個開關（Send crash reports / Send connection traces）。
2. **Publish agent activity**：在 host Settings → Sharing & access 確認關閉（`verify` 會檢視 `settings.json`，但 v0.1.11 無法由 `policy.json` 鎖定）。
3. **app.t3.codes**：無關閉開關，請避免使用。

## Antigravity 注意

只能用官方、未修改的 `agy acp`（互動、單人使用）。不要包裝 `agy -p`／`--print`，也不要讓其他 agent／harness 代為呼叫 agy，否則有被封號風險。

## Rollback

- **Linux／WSL／macOS**：`bash scripts/lockdown.sh rollback`（原地覆寫移除 rc 與 `service.env` 的 marker 區塊以保留權限與 symlink、清除 macOS launchctl；`--no-policy` 時不動 policy；將現行 policy 移到 `.removed-<時間>`，並用 `mv` 還原最近備份，重複 rollback 可逐步退回）。
- **Windows**：`powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Mode Rollback -Backend Wsl|Windows`（移除使用者環境變數；`Wsl` 還原最近 `policy.json.disabled-*`；`Windows` 將現行 policy 改名並用 `Move-Item` 還原最近備份）。
- 所有備份皆在原檔旁（`*.bak-<時間>`），還原後請重啟 T3 Code。

## 腳本與參考檔摘要

| 檔案 | 用途 |
| --- | --- |
| `references/baseline.json` | 已審計版本、Standard/Strict profile、必要環境變數、ADMX policy 與 CLI 子命令基準 |
| `scripts/lockdown.sh` | Linux／WSL／macOS：`apply`／`verify`／`rollback`／`snapshot`（支援 `--profile`、`--org`、`--policy-path`、`--no-policy`、`--t3-bin`、`--allow-unvalidated-policy`、`--json`） |
| `scripts/audit_unix.py` / `audit_lib.py` | Unix 端唯讀稽核、policy 產生與漂移偵測模組（零外部相依 Python 3 stdlib） |
| `scripts/lockdown.ps1` / `audit_windows.ps1` | Windows：`-Mode Apply\|Verify\|Rollback\|Snapshot`、`-Backend Wsl\|Windows`、`-Profile Standard\|Strict`、`-Organization`、`-T3Bin`、`-AllowUnvalidatedPolicy`、`-CheckWsl`、`-Json` |
