---
name: t3code-lockdown
description: Lock down T3 Code on a machine so it stops sending usage telemetry, cannot use T3 Connect, and does not auto-update, using env flags plus a managed policy file, with verify and rollback. Supports a WSL2-backend setup (Windows desktop app, server in WSL2; recommended) and native Linux/macOS/Windows. Use when asked to set up, harden, audit, verify, or roll back T3 Code privacy/telemetry settings on a new machine.
---

# T3 Code Lockdown

在新機器上把 T3 Code 鎖到「不送遙測、不能用 T3 Connect、不自動更新」。已對 T3 Code main `b6869fad`（2026-11-24）、desktop 0.1.11 驗證過；版本差異大時先用 `t3 policy --help` 確認欄位。

## 背景（為什麼要兩層）

- 使用分析送到 PostHog（`ingest.t3.codes`），relay tracing 送到 Axiom。
- **環境變數**：`T3CODE_TELEMETRY_ENABLED=false`、`T3CODE_OTEL_SDK_DISABLED=true`。只管伺服器端遙測。
- **Managed policy**（`schemaVersion: 1`）：`limits.telemetry=false`、`limits.connect=false`、`updates.mode="off"`。擋 T3 Connect（Cloudflare Tunnel）和自動更新（Publish agent activity 另需在 host 設定確認關閉）。
- 兩者都**不涵蓋**的項目見「手動項目總整理」。

## Agent 規則

- 不改防火牆、hosts；未經詢問不 kill／重啟任何程序（要重啟 T3 Code 就請使用者做）。
- 需要 sudo／系統管理員時先告知並請使用者提供，不自行繞過。
- 公司機器先確認使用者同意；所有修改前都會備份，且腳本不含任何機密或個人資訊。
- 不要在輸出中貼出 token、auth 檔內容。

## 各平台 policy 位置（出自 T3 Code `docs/user/managed-policy.md`）

| OS | Policy 檔 | 備註 |
| --- | --- | --- |
| Linux | `/etc/t3code/policy.json` | 需 sudo |
| macOS | `/Library/Application Support/T3Code/policy.json` | 需 sudo；也可用 configuration profile（domain `com.t3tools.t3code`），但**檔案與 profile 只能擇一** |
| Windows | `C:\Program Files\T3Code\policy.json` | 需系統管理員；也可用 GPO／`HKLM\SOFTWARE\Policies\T3Tools\T3Code`，同樣只能擇一 |
| WSL2 內 | `/etc/t3code/policy.json`（該 distro 內） | 見下方陷阱 |

- 檔案與原生 policy（profile／GPO／registry）並存時，T3 Code **拒絕啟動**；腳本偵測到 registry policy 會警告，不會改 registry。
- 環境變數：Linux／macOS 桌面 app 從 shell profile（`~/.zshrc` 等）讀；Windows 用「使用者環境變數」。`t3 service`（背景服務）不讀 rc，要寫 `~/.t3/service.env`（腳本若發現該檔會一併處理）。macOS 另外用 `launchctl setenv` 補當前登入工作階段（重開機失效，永久靠 rc）。
- **不要在 policy 加 `limits.clients` 卻漏掉 `"remote"`**：沒有 `remote` 時 server 只聽 loopback、不產生配對連結、並關掉 Tailscale Serve，手機就連不上。本 skill 的 policy 不含 `clients`，維持手機可用。

## Agent 步驟

先問清楚模式（不確定就選 A）。Organization 名稱可自訂（`--org` / `-Organization`），預設 `Local`。腳本在 `scripts/`，路徑以本 skill 目錄為基準。

### A. Windows desktop + WSL2 backend（推薦）

1. **Windows 端**（環境變數用一般權限。只有在需要改名既有 `C:\Program Files\T3Code\policy.json` 時才要系統管理員 PowerShell；本機本來就沒有該檔時不必提權，也不會建立該目錄）：
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Backend Wsl -Organization "<name>"
   ```
   - 設定使用者環境變數。
   - **重要陷阱**：只要 Windows 有任何 policy（`C:\Program Files\T3Code\policy.json`，或 GPO／registry），desktop 就**不會跑 WSL environment**，server 改在 Windows。所以 WSL backend 時 Windows 端**不能有** policy；腳本會把既有檔案改名為 `policy.json.disabled-<時間>`（registry 的只警告，交給使用者決定）。
2. **WSL 內**（需 sudo）：
   ```bash
   bash scripts/lockdown.sh apply --org "<name>"
   ```
   寫 rc 區塊（先備份）與 `/etc/t3code/policy.json`（既有檔先備份）。
3. 請使用者**登出 Windows 再登入**（或至少開新 shell），重啟 T3 Code。

### B. Linux

`bash scripts/lockdown.sh apply --org "<name>"`（sudo 寫 `/etc/t3code/policy.json`），重啟 T3 Code；若用 `t3 service`，另 `t3 service restart`。

### C. macOS

`bash scripts/lockdown.sh apply --org "<name>"`：寫 `~/.zshrc`／`~/.bashrc` 區塊、`launchctl setenv`、sudo 寫 `/Library/Application Support/T3Code/policy.json`。若機器已由 MDM 安裝 profile，先 `--no-policy` 並詢問使用者。重啟 T3 Code。Intel Mac 沒有 `t3` CLI，驗證改看 app 內 Settings。

### D. Windows 原生（server 跑在 Windows）

系統管理員 PowerShell：`powershell -ExecutionPolicy Bypass -File scripts\lockdown.ps1 -Backend Windows -Organization "<name>"`，寫 `C:\Program Files\T3Code\policy.json`。重啟 T3 Code。

## 驗證

- `bash scripts/lockdown.sh verify`／`scripts\lockdown.ps1 -Mode Verify -Backend Wsl|Windows`：檢查環境變數（含既有的 `~/.t3/service.env`）、policy 內容；有 `t3` 時另跑 `t3 policy check <path>`（`--no-policy` 時略過；失敗會讓 verify 回傳非 0）。Windows 若存在 GPO／registry policy，`-Backend Wsl` 會判定失敗。
- **重啟後**以「實際跑 T3 Code 的使用者」（WSL 模式在 WSL 內）執行 `t3 policy show`：會印出 policy 與指紋，並說明 running server 載入的是否為最新版；若顯示 "Restart T3 Code to apply the installed policy" 就代表還在用舊的。Settings 內也會看到 organization 與各項 **Managed by**。
- 驗證結果要如實回報，不要只因檔案寫入成功就說完成。

## 手機（iOS）設定指南：走自己的 Tailscale

依 T3 Code `docs/user/install.md`、`remote-access.md`、`telemetry.md`：

1. 手機與 host 都登入**同一個 tailnet**（使用者自己的 Tailscale）。
2. 手機安裝官方 App：App Store「T3 Code: Remote Claude & More」（id6787819824）。TestFlight 僅限邀請，不需要。
3. Host 開放網路存取（擇一）：
   - 桌面 app：Settings → Sharing & access → 開 **Network access**（會重啟 app）；要 HTTPS 就同頁開 **Tailscale HTTPS**（tailnet 要開 MagicDNS + HTTPS certificates；Linux 要有 Tailscale operator 權限）。
   - CLI／WSL server：`t3 serve --lan`（或 `t3 up --lan` 裝成背景服務）。要 HTTPS：`t3 serve --tailscale-serve`，已在跑則 `t3 pair --tailscale`。
   - 注意 `--lan` 會同時聽區網與 tailnet，**配對碼是唯一防線**；只想走 tailnet 可用 Tailscale HTTPS 路徑，並不要在公共 Wi-Fi 長期開著。
4. 產生配對：在 host 執行 `t3 pair`（或桌面 app Sharing & access 建連結），用手機 **Settings → Environments → Add environment** 掃 QR 或貼上配對 URL。URL 若是 HTTPS，手機輸入時要自己寫 `https://`（只輸入 IP 預設 HTTP）。配對連結等同密碼，不要貼到聊天或紀錄。
5. **不要用 T3 Connect／app.t3.codes**（走 Cloudflare Tunnel + T3 relay）。policy 的 `limits.connect=false` 會擋 T3 Connect；不要登入 T3 Connect 帳號，也不要開 **Publish agent activity**（Settings → Sharing & access，會把專案／thread 標題、模型名等送到 relay；遙測關閉也不會停它）。
6. 手機端關閉診斷：**Settings → About T3 Code → Diagnostics**，關掉 **Send crash reports** 與 **Send connection traces**（server 的環境變數與 policy 管不到手機端）。
7. 驗證：手機 Settings → Environments 看到該機器與 route；斷開蜂巢網路只留 Tailscale 仍能連。需要撤銷：host 的 Settings → Sharing & access 撤銷 session。

WSL2 backend 時，手機連的是 WSL 內的 server，需要該 server 可被 tailnet 到達（Windows host 的 Tailscale 與 WSL 網路模式相關，例如 mirrored networking）。先確認再配對，不要為此改防火牆／hosts，需要時請使用者決定。

## 手動項目總整理（腳本涵蓋不到）

1. iOS：Diagnostics 兩個開關（見上）。
2. T3 Connect／Publish agent activity：policy 擋 Connect；Publish 要在 host 設定確認關閉。
3. app.t3.codes：沒有關閉開關，避免使用。hosted web 與手機 app 仍會送自己的 relay traces。

## Antigravity 注意

只能用官方、未修改的 `agy acp`（互動、單人使用）。不要包裝 `agy -p`／`--print`，也不要讓其他 agent／harness 代為呼叫 agy，否則有被封號風險。

## Rollback

- Linux／WSL／macOS：`bash scripts/lockdown.sh rollback`（移除 rc 與 service.env 區塊、macOS 的 launchctl 設定；`--no-policy` 時不動 policy。policy 移到 `.removed-<時間>`，若有舊備份則用 `mv` 還原並消耗該備份，重複 rollback 可逐步退回，包含原本沒有 policy 的狀態。原地覆寫 rc／`service.env`，保留權限與 symlink）。
- Windows：`scripts\lockdown.ps1 -Mode Rollback -Backend Wsl|Windows`（移除使用者環境變數；`Wsl` 會用 `Move-Item` 還原最近的 `policy.json.disabled-*`，注意這會讓 server 回到跑在 Windows；`Windows` 會把目前 policy 改名，再用 `Move-Item` 還原最近備份。備份被消耗後，再 rollback 一次可退到更早狀態）。
- 所有備份都在原檔旁（`*.bak-<時間>`），也可手動還原。還原後重啟 T3 Code。

## 腳本摘要

| 檔案 | 用途 |
| --- | --- |
| `scripts/lockdown.sh` | Linux／WSL／macOS：`apply`／`verify`／`rollback`，`--org`、`--policy-path`、`--no-policy` |
| `scripts/lockdown.ps1` | Windows：`-Mode Apply\|Verify\|Rollback`、`-Backend Wsl\|Windows`、`-Organization` |

兩個腳本皆為冪等：重複執行只會顯示 `unchanged`，並印出每個變更與備份路徑。
