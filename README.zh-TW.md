[English](README.md) | **繁體中文**

# RemoteMac self-hosted relay

兩個 Python 腳本，組成一套完整的遠端控制系統，完全不需要在受控機上開任何 inbound port。

| 檔案 | 角色 | 執行位置 |
|---|---|---|
| `relay.py` | 中繼伺服器（盲管道）| 你控制的 VPS / 家用主機 |
| `remote_desktop.py` | 加密傳輸層 + 遠端桌面 + SOCKS5 proxy（五種模式）| Mac / Linux |

```
 Machine A  ──outbound──►  YOUR RELAY  ◄──outbound──  Machine B
  (client)    (encrypted)    (blind)     (encrypted)    (host)
```

---

## 架構說明

### relay.py — 盲管道

Relay 只做一件事：把兩條 outbound TCP 連線配對，然後把位元組雙向轉發。它**永遠看不到明文**，因為加解密在兩端進行。

- 不需要資料庫、不儲存任何資料
- 以 `nobody` 身分執行（systemd unit 已設定）
- 內建 DoS 防護：每 IP 最多 5 條同時連線、最多 10,000 組已登記主機

### remote_desktop.py — 加密通道 + 遠端桌面

在 relay 建立橋接之後，`remote_desktop.py` 在上面跑一層**雙向認證 + 加密**協議：

```
[relay 橋接建立 → 'P']
        │
        ▼
① 交換隨機 nonce（各 32 bytes）
        │
        ▼
② scrypt 密鑰推導
   master = scrypt(PSK, salt=nonce_h‖nonce_c, N=16384, r=8, p=1)
   → 5 組獨立子密鑰（enc_h2c、enc_c2h、mac_h2c、mac_c2h、auth）
        │
        ▼
③ 雙向 token 交換
   token = HMAC-SHA256(auth_key, role‖nonce_h‖nonce_c)
   雙方以 compare_digest 驗證 → 任一方不知道 PSK 即中斷
        │
        ▼
④ 資料傳輸（每個 frame）
   ┌──────────┬──────────────────────┬────────────────────┐
   │ 4 B len  │ 32 B HMAC-SHA256 MAC │ N B ciphertext     │
   └──────────┴──────────────────────┴────────────────────┘
   加密：SHAKE-256 XOF counter-mode（111 MB/s，一個 Keccak call/frame）
   驗整：HMAC-SHA256(mac_key, seq_num‖ciphertext)，seq_num 防 replay
```

---

## 安全性摘要

| 威脅 | 對策 |
|---|---|
| 竊聽 relay 流量 | SHAKE-256 加密，relay 只看到密文 |
| 中間人偽裝 | 雙向 token 驗證，雙方都必須知道 PSK |
| 弱 PSK 暴力破解 | scrypt(N=16384) 讓每次猜測耗時 ~50 ms + 16 MB RAM |
| Frame 偽造/竄改 | HMAC-SHA256 per-frame MAC，constant-time 比對 |
| Replay 攻擊 | 單調遞增 64-bit 序號，每個方向獨立 |
| Frame flooding | 接收端每秒最多 5,000 frames 限制 |
| 連線佔用 | Auth 30 秒逾時；閒置 120 秒斷線 |
| 大 frame 炸記憶體 | 單一 frame 上限 4 MB |

> **注意**：remote_desktop.py 的加密層與 RemoteMac app 的 TLS-PSK 無關，兩者是獨立的加密層。remote_desktop.py 是獨立的遠端桌面 / 加密管道工具，不是取代 app。

---

## 需求

- Python 3.8+ （不需要 pip 安裝任何套件）
- Relay 伺服器必須從網際網路可以連到（VPS，或家用主機有做 port forwarding）

---

## 一、架設 relay.py（伺服器端）

### 0. 確認 Python 版本

```bash
python3 --version   # 需要 3.8 以上
```

如果沒有：

```bash
# Debian / Ubuntu / Raspberry Pi OS
sudo apt update && sudo apt install -y python3

# Fedora / RHEL / CentOS / Rocky / Alma
sudo dnf install -y python3

# Arch / Manjaro
sudo pacman -S --noconfirm python

# Alpine
sudo apk add python3
```

### 1. 把檔案複製到伺服器

```bash
scp relay.py remotemac-relay.service you@YOUR_SERVER:~/
```

### 2. 先測試（前景執行）

```bash
ssh you@YOUR_SERVER
python3 relay.py 21118
# 應該看到：RemoteMac relay listening on 0.0.0.0:21118
```

確認 port 有在監聽：

```bash
ss -tlnp | grep 21118
```

按 **Ctrl-C** 停止。

### 3. 安裝成 systemd 服務（建議）

```bash
sudo mkdir -p /opt/remotemac
sudo cp relay.py /opt/remotemac/
sudo cp remotemac-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotemac-relay
sudo systemctl status remotemac-relay        # 確認 active (running)
```

看即時 log：

```bash
journalctl -u remotemac-relay -f
# host registered → Mac 已連線
# bridging        → 有 session 正在進行
```

沒有 systemd（Alpine / container / WSL）：

```bash
nohup python3 /opt/remotemac/relay.py 21118 > /var/log/remotemac-relay.log 2>&1 &
```

換 port：編輯 `/etc/systemd/system/remotemac-relay.service` 的 `ExecStart=`，然後：

```bash
sudo systemctl daemon-reload && sudo systemctl restart remotemac-relay
```

### 4. 開防火牆

```bash
# ufw（Debian/Ubuntu）
sudo ufw allow 21118/tcp

# firewalld（Fedora/RHEL）
sudo firewall-cmd --add-port=21118/tcp --permanent && sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 21118 -j ACCEPT
```

雲端 VM（AWS / GCP / Azure / DigitalOcean）還需要在控制台的 Security Group / 防火牆規則開放 21118/tcp inbound。

### 5. 確認可從外部連到

```bash
# 在伺服器上查公網 IP
curl -s https://api.ipify.org; echo

# 從另一台機器測試（例如你的 Mac）
nc -vz YOUR_RELAY_IP 21118     # 應該顯示 succeeded / open
```

### 管理服務

```bash
sudo systemctl restart remotemac-relay
sudo systemctl stop remotemac-relay
sudo systemctl disable --now remotemac-relay
journalctl -u remotemac-relay -e          # 看最近的 log
```

更新 relay：

```bash
sudo cp relay.py /opt/remotemac/ && sudo systemctl restart remotemac-relay
```

完全移除：

```bash
sudo systemctl disable --now remotemac-relay
sudo rm /etc/systemd/system/remotemac-relay.service /opt/remotemac/relay.py
sudo systemctl daemon-reload
```

---

## 二、設定 RemoteMac app（Mac + iPad）

### Mac 端

```bash
echo "YOUR_RELAY_IP:21118" > ~/.config/remotemac/relay
pkill -9 -f "RemoteMac Host.app"
open -W "/Applications/RemoteMac Host.app"
```

Relay log 應出現：`host registered id=...`

### iPad 端

**Settings ▸ Relay server** → 輸入 `YOUR_RELAY_IP:21118`。

### 連線流程

1. iPad 輸入 Device Code。
2. 同一個 Wi-Fi → 直接 LAN 連線（最快），relay 不會用到。
3. 不同網路 / 行動網路 → 雙方連到 relay → 橋接 → 進入。

---

## 三、使用 remote_desktop.py

`remote_desktop.py` 整合了加密傳輸層、遠端桌面與加密 proxy 功能，支援五種模式：

| 模式 | 說明 | 相依套件 |
|---|---|---|
| `host` | 被控端：串流螢幕 + 接收注入鍵鼠 | `mss Pillow pynput` |
| `viewer` | 控制端：顯示畫面 + 發送鍵鼠 | `Pillow`（含 tkinter）|
| `pipe` | stdin/stdout 加密橋接，無 GUI | 無（Python stdlib 即可）|
| `gateway` | 出口節點：代 client 對外建立 TCP/UDP 連線 | 無（Python stdlib 即可）|
| `socks` | 本機 SOCKS5 proxy 入口，讓其它 app 走加密隧道出去 | 無（Python stdlib 即可）|

### 安裝相依套件（host / viewer 模式）

```bash
pip install mss Pillow pynput
```

### macOS 權限設定

| 端 | 需要的權限 |
|---|---|
| host | **螢幕錄製**（System Preferences > Privacy > Screen Recording）|
| host | **輔助使用**（System Preferences > Privacy > Accessibility）— 鍵鼠注入 |

### 啟動遠端控制

```bash
# 1. Host 端先執行（被控端，等待連入）
python3 remote_desktop.py host relay.example.com:21118 mydevice --psk "strong-passphrase"

# 2. Viewer 端執行（控制端）
python3 remote_desktop.py viewer relay.example.com:21118 mydevice --psk "strong-passphrase"
```

Host 模式預設**常駐**：viewer 斷線後會自動重新向 relay 註冊、等待下一次連入；連不上 relay 時以指數退避（2s → 30s）重試。加 `--once` 可恢復「單次 session 後結束」的行為。

> **安全提醒**：`--psk` 傳入的值在 Linux 上可以被 `ps aux` 看到。更安全的方式：
> - 省略 `--psk`，程式會互動式提示輸入（不顯示在螢幕）
> - 或設定環境變數：`export REMOTEMAC_PSK="your-passphrase"`，然後省略 `--psk`

成功後：
```
[remotemac] relay: registered — waiting for peer…    ← host 端
[remotemac] auth: mutual authentication succeeded ✓

[remotemac] relay: bridge established                 ← viewer 端
[remotemac] auth: mutual authentication succeeded ✓
```

Viewer 端會開啟視窗顯示 host 的螢幕，你的滑鼠鍵盤操作即時傳到 host。

### 選項

| 參數 | 適用模式 | 說明 | 預設值 |
|---|---|---|---|
| `--fps N` | host | 擷取幀率 | 15 |
| `--quality N` | host | JPEG 品質 20–95 | 75 |
| `--once` | host | 單次 session 後結束（預設為常駐重新註冊）| 關 |
| `--no-clip` | host / viewer | 停用雙向剪貼簿同步 | 關（同步開啟）|

```bash
# 高畫質（需較好的網路）
python3 remote_desktop.py host relay.example.com:21118 myid "pw" --fps 30 --quality 85

# 省頻寬
python3 remote_desktop.py host relay.example.com:21118 myid "pw" --fps 10 --quality 60
```

### 支援的輸入

| 類型 | 說明 |
|---|---|
| 滑鼠移動 | 全螢幕座標正規化，自動適配不同解析度 |
| 左 / 右 / 中鍵 | 按下與放開 |
| 滾輪 | macOS / Linux / Windows 皆支援 |
| 鍵盤 | 一般字元 + F1–F12 + Ctrl / Alt / Shift / ⌘ / 方向鍵等 |
| 剪貼簿 | 雙向自動同步（純文字，每秒偵測變更；`--no-clip` 停用）|

### Pipe 模式（CLI 工具 / 腳本整合）

不需要 GUI，只用 stdin/stdout 橋接，適合傳檔、遠端執行指令等場合：

```bash
# 傳送檔案（host 端傳到 client 端）
cat file.bin | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk "pw"
python3 remote_desktop.py pipe relay.example.com:21118 myid client --psk "pw" > output.bin

# 遠端執行 bash
bash | python3 remote_desktop.py pipe relay.example.com:21118 myid host --psk "pw"
python3 remote_desktop.py pipe relay.example.com:21118 myid client --psk "pw"
```

### 加密 SOCKS5 Proxy（gateway / socks 模式）

除了遠端桌面，也可以把 client 機器上的其它 app（瀏覽器、curl…）的流量**經加密隧道從 host 出去**，等同自架的加密 `ssh -D`。多條連線多工在同一條 relay 橋接上，全程沿用同一套加密（scrypt 認證 + SHAKE-256 + HMAC），relay 仍只看到密文。

```bash
# 1. gateway（出口機，例如家裡的 Mac；預設常駐，斷線自動重連）
python3 remote_desktop.py gateway relay.example.com:21118 myproxy --psk "pw"

# 2. socks（本機，開一個本機 SOCKS5 proxy）
python3 remote_desktop.py socks relay.example.com:21118 myproxy --psk "pw" --port 1080

# 3. 讓 app 走 proxy（socks5h → 連 DNS 解析也走遠端）
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org        # 顯示的是 gateway 端的公網 IP
ALL_PROXY=socks5h://127.0.0.1:1080 curl https://example.com
```

瀏覽器直接設 SOCKS5 host `127.0.0.1`、port `1080` 即可全域走隧道。

- **支援**：TCP（SOCKS5 CONNECT）+ UDP（SOCKS5 UDP associate，如 DNS/QUIC）；網域名稱在 gateway 端解析。
- **安全**：任何連進 gateway 的一方都必須通過 PSK 雙向認證，未通過即斷線，所以不會變成開放 proxy。

| 參數 | 適用模式 | 說明 | 預設值 |
|---|---|---|---|
| `--port N` | socks | 本機 SOCKS5 監聽埠 | 1080 |
| `--bind ADDR` | socks | 本機監聽位址 | 127.0.0.1 |
| `--allow HOST/CIDR` | gateway | 白名單（網域字尾或 IP/CIDR），可重複；不給則全通 | 無（全通）|
| `--once` | gateway | 單次 session 後結束（預設常駐重連）| 關 |

> **防護縱深**：`socks` 預設只監聽 `127.0.0.1`，別台機器無法白嫖你的 proxy；改 `--bind 0.0.0.0` 對外開放前請三思。`gateway` 想再收斂可用 `--allow`（例如 `--allow example.com --allow 10.0.0.0/8`）限定可連目標，未列的一律拒絕。

### PSK 選擇建議

| 強度 | 範例 |
|---|---|
| 弱（不建議）| `1234`、`password` |
| 可接受 | `correct-horse-battery-staple` |
| 強（建議）| `python3 -c "import secrets; print(secrets.token_hex(24))"` |

---

## 四、Mesh overlay（實驗性 — Phase 1）

除了 1:1 遠端桌面,`coordinator.py` + `mesh.py` 把系統擴充成 **mesh**(自架的簡化版 Tailscale):多個節點加入同一張網,各自拿到穩定的 overlay IP,節點之間端到端加密。需要 `cryptography`(`pip install cryptography`)。

```bash
# Coordinator(放在對外可達的主機 — 只是控制平面,只看得到密文)
python3 coordinator.py 21200 --token "network-secret"

# 每個節點加入網路
python3 mesh.py up coord.example.com:21200 --token "network-secret" --name laptop
python3 mesh.py up coord.example.com:21200 --token "network-secret" --name mac

# 驗證兩節點間的加密路徑
python3 mesh.py up coord.example.com:21200 --token "network-secret" --ping mac
```

- 每個節點有持久的 X25519 身份(`~/.config/remotemac/mesh/key`,可用 `$REMOTEMAC_MESH_KEY` 覆寫);coordinator 從 `100.64.0.0/10` 配發 overlay IP。
- 節點間握手是雙向認證 + 前向保密(X25519 triple-DH → HKDF-SHA256 → ChaCha20-Poly1305);coordinator 只轉發**密文**(DERP 後援)。

**狀態 / 藍圖**:Phase 1(本版)交付控制平面、每節點身份、host 池 + 選擇,以及經 coordinator 轉發的加密資料路徑 —— 免 root。後續:**Phase 2** — UDP NAT 打洞的 P2P 直連(對稱 NAT 配對仍以 relay 兜底);**Phase 3** — TUN overlay 裝置 + 自動路由 + 出口節點選擇(完整 VPN,需 root)。純 Python 資料面吞吐中等,一般用途足夠。

---

## 效能

在一般開發機上測得的加密吞吐量（4 MB frame）：

| 項目 | 速度 |
|---|---|
| XOR（big-integer）| ~140 MB/s |
| SHAKE-256 加密 | ~111 MB/s |
| Auth 握手（scrypt） | ~50 ms（一次性）|
| 遠端桌面典型頻寬 | 1–8 MB/s（JPEG @75, 1080p, 15fps）|

加密開銷遠低於實際串流頻寬，瓶頸在網路而非 CPU。

---

## 疑難排解

| 症狀 | 檢查 |
|---|---|
| iPad 顯示「Mac … is offline」 | Relay log 沒有 `host registered` → Mac 的 `~/.config/remotemac/relay` 設錯，或 Mac 連不到 relay |
| `nc -vz` 從外部超時 | 防火牆 / Security Group / 路由器 port forwarding 沒開 |
| Wi-Fi 可連、行動網路不行 | Relay 沒有真正的公網路徑（家用主機沒做 port forwarding）|
| 服務啟動失敗 | `journalctl -u remotemac-relay -e` → 通常是 Python 路徑錯誤或 port 被佔用 |
| auth failed: peer does not know the PSK | 兩端 PSK 不一致，或 device_id 不同 |
| relay: host slot occupied | 已有同 device_id 從不同 IP 登記；換 device_id 或等舊連線逾時 |
| MAC verification failed | 網路中間有人篡改封包，或版本不相容 |
| remote_desktop 螢幕全黑 | Host 沒有 Screen Recording 權限 |
| remote_desktop 鍵鼠無反應 | Host 沒有 Accessibility 權限 |
| remote_desktop 連線後立即斷開 | 檢查 PSK 是否兩端一致；查看 stderr 輸出 |
| socks / gateway 連不上 | 兩端 device_id 與 PSK 需一致；gateway 要先啟動並向 relay 註冊 |
| curl 走 proxy 卻解析失敗 | 用 `socks5h://`（h 代表 DNS 走遠端），不要用 `socks5://` |

---

## 檔案列表

| 檔案 | 說明 |
|---|---|
| `relay.py` | 中繼伺服器，Python 3.8+，無相依套件 |
| `remote_desktop.py` | 加密傳輸層 + 遠端桌面 + SOCKS5 proxy（host / viewer / pipe / gateway / socks 五種模式）|
| `coordinator.py` | Mesh 控制平面（Phase 1）— 節點註冊、overlay IP 配發、DERP 轉發。需 `cryptography` |
| `mesh.py` | Mesh 節點 — X25519 身份、加入網路、節點間加密資料路徑。需 `cryptography` |
| `remotemac-relay.service` | systemd unit，讓 relay.py 開機自動啟動 |
