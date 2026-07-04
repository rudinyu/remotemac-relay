[English](INSTALL.md) | **繁體中文**

# 安裝與部署

讓 RemoteMac 跑起來的 task-oriented 指南。挑你需要的部分:

| 你想要… | 部署 | 需要 |
|---|---|---|
| 遠端桌面 / proxy 的中繼 | `relay.py` | 一台對外可達的主機(VPS / 有轉埠的機器)|
| 一張 mesh(簡化版 Tailscale VPN)| `coordinator.py` + `mesh.py` 節點 | coordinator 需一台對外可達的主機 |
| 遠端控制某台 Mac/Linux | `remote_desktop.py`(host + viewer)| 上面的 relay |

**relay** 與 **coordinator** 是你在對外可達主機上跑一次的伺服器;其他(mesh 節點、遠端桌面)都是**往外**連到它們。

---

## 1. 需求

- 每台機器 **Python 3.8+**(`python3 --version`)。
- **relay/coordinator 主機**必須從網際網路可達 —— VPS,或家用主機有做轉埠。
- **mesh 節點與 coordinator** 需要 `pip install cryptography`(coordinator 用 X25519 做註冊的持有性證明)。relay 與遠端桌面的 `pipe`/`gateway`/`socks` 模式是**純 stdlib**(免 pip)。遠端桌面 `host`/`viewer` 需要 `pip install mss Pillow pynput`。(Docker 映像與 `scripts/install-linux.sh` 會自動幫你裝。)
- **Docker**(選用):一鍵部署伺服器,需要 Docker Engine + Compose plugin。

---

## 2. 取得程式碼

```bash
git clone https://github.com/rudinyu/remotemac-relay.git
cd remotemac-relay
```

(或把個別 `.py` 檔複製到需要的地方 —— 它們沒有共用的套件結構。)

---

## 3. 部署伺服器

你需要 **relay**(遠端桌面 / proxy)和/或 **coordinator**(mesh)。挑一種方式。

### 方式 A —— Docker(建議)

一鍵把 relay **和** mesh coordinator 都拉起(非 root 容器):

```bash
cp docker/.env.example .env          # 編輯 .env,設 REMOTEMAC_MESH_TOKEN
docker compose up -d --build
docker compose logs -f               # 看兩個服務的 log
```

- 產生強 token:`openssl rand -base64 24` → 填進 `.env`。
- 埠:**relay 21118/tcp**、**coordinator 21200/tcp + 21200/udp**(STUN 共用同埠)。要開埠(見 §7)。
- coordinator 的 overlay IP 配發持久化在 `coordinator-state` volume。
- `docker compose down` 停止(加 `-v` 連 state volume 一起刪)。

只要 relay 的話,只跑那個服務:`docker compose up -d --build relay`。

### 方式 B —— 一鍵腳本(systemd,Linux)

一行指令把 relay + coordinator 裝成 systemd 服務:

```bash
sudo ./scripts/install-linux.sh                        # 兩個都裝;會提示或自動產生 token
sudo ./scripts/install-linux.sh --relay-only           # 只裝 relay
sudo ./scripts/install-linux.sh --coord-only --open-firewall
```

它會把程式碼複製到 `/opt/remotemac`、寫入 systemd unit(relay 以 `nobody` 執行;coordinator 用 `StateDirectory` 存 overlay-IP 狀態、token 放在只有 root 讀得到的 `EnvironmentFile`)、啟用並啟動,並在加 `--open-firewall` 時用 ufw/firewalld 開埠。重跑即可更新。`--help` 列出所有參數(`--relay-port`、`--coord-port`、`--token`、`--prefix`)。若不給 token,它會自動產生並印出來 —— 把那個值給每個節點用。

### 方式 C —— 手動

**Relay**(systemd 服務):

```bash
sudo mkdir -p /opt/remotemac
sudo cp relay.py /opt/remotemac/
sudo cp remotemac-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now remotemac-relay
sudo systemctl status remotemac-relay        # active (running)
journalctl -u remotemac-relay -f             # 即時 log
```

換埠:改 unit 裡的 `ExecStart=`,再 `sudo systemctl daemon-reload && sudo systemctl restart remotemac-relay`。

**Coordinator**(mesh 控制平面):

```bash
# 前景測試
REMOTEMAC_MESH_TOKEN="your-strong-secret" python3 coordinator.py 21200

# 或當背景服務(範例)
sudo cp coordinator.py remote_desktop.py /opt/remotemac/
REMOTEMAC_MESH_TOKEN="your-strong-secret" \
  nohup python3 /opt/remotemac/coordinator.py 21200 \
  --state /opt/remotemac/coordinator-state.json > /var/log/remotemac-coord.log 2>&1 &
```

token 可用 `--token` 或 `REMOTEMAC_MESH_TOKEN`;建議用環境變數,才不會在 `ps` 看到。`--state PATH` 持久化 overlay IP 配發。

沒有 systemd(Alpine / container / WSL)時 relay 一樣可跑:`nohup python3 /opt/remotemac/relay.py 21118 > /var/log/remotemac-relay.log 2>&1 &`。

---

## 4. 加入 mesh(節點)

在每台要加入網路的機器上(先 `pip install cryptography`):

```bash
# 基本節點:只有控制通道,用 --ping 驗證加密路徑
python3 mesh.py up coord.example.com:21200 --token "your-strong-secret" --name laptop
python3 mesh.py up coord.example.com:21200 --token "your-strong-secret" --ping gw
```

每個節點從 `100.64.0.0/10` 拿到穩定的 overlay IP。`--name` 預設用系統主機名。token 要跟 coordinator 一致。

**VPN 資料面** —— 讓真實 app 用 overlay IP 連 peer(需 root):

```bash
sudo python3 mesh.py up coord.example.com:21200 --token "…" --name laptop --tun
ping 100.64.0.3        # 另一節點的 overlay IP;log 顯示 [direct] 或 [derp]
```

**子網路由** —— 把某台 Linux 節點背後的 LAN 開放給 mesh:

```bash
sudo python3 mesh.py up coord…:21200 --token "…" --name gw --tun --advertise-routes 192.168.1.0/24
# 在 client:
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --accept-routes
```

**Full-tunnel 出口節點** —— 全流量繞經某台 Linux 出口(opt-in):

```bash
sudo python3 mesh.py up coord…:21200 --token "…" --name exit   --tun --exit
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --exit-node exit
curl https://ifconfig.me   # 顯示出口的公網 IP
```

**split-DNS** —— 用名字連 peer(`ssh laptop.mesh`):

```bash
sudo python3 mesh.py up coord…:21200 --token "…" --name laptop --tun --dns
```

> `--tun` 與路由/DNS 功能需要 **root**。Linux 上的 subnet/exit 節點還需要 `nftables`(或 `iptables`)與 IP forwarding —— 工具會幫你設好。在容器裡跑 mesh 節點另外需要 `--cap-add=NET_ADMIN --device /dev/net/tun`。細節見 [README](README.zh-TW.md) 的 mesh 章節。

---

## 5. 遠端桌面(選用)

透過 relay 控制 Mac/Linux 桌面(`pip install mss Pillow pynput`):

```bash
# 被控端(host)
python3 remote_desktop.py host relay.example.com:21118 mydevice --psk "strong-passphrase"
# 控制端(viewer)
python3 remote_desktop.py viewer relay.example.com:21118 mydevice --psk "strong-passphrase"
```

macOS host 需要**螢幕錄製** + **輔助使用**權限。建議用 `REMOTEMAC_PSK` 而非 `--psk`,才不會在 `ps` 看到密碼。`gateway` / `socks` / `pipe` 模式見 [README](README.zh-TW.md#三使用-remote_desktoppy)。

---

## 6. 驗證

```bash
# relay 從外部可達
nc -vz YOUR_RELAY_IP 21118            # succeeded / open

# coordinator 有起來(從節點主機)
nc -vz YOUR_COORD_IP  21200

# mesh 路徑通
python3 mesh.py up coord…:21200 --token "…" --ping <peer>   # "pong … [direct: …]" 或 "[derp…]"
```

Docker:`docker compose ps` 顯示兩個服務 `healthy`。

---

## 7. 埠與防火牆

| 服務 | 埠 | 說明 |
|---|---|---|
| relay | `21118/tcp` | client 進來 |
| coordinator | `21200/tcp` | mesh 控制通道 |
| coordinator | `21200/udp` | STUN(端點發現)|
| mesh 節點 | UDP(隨機,或 `--udp-port`)| 往外連;轉埠可提升 P2P 成功率,否則走 DERP |

在主機**和**任何雲端 security group 開 relay/coordinator 的埠:

```bash
sudo ufw allow 21118/tcp
sudo ufw allow 21200/tcp
sudo ufw allow 21200/udp
```

mesh 節點是**往外**連,不需 inbound 埠;固定並轉發 `--udp-port` 只是提高打洞直連的機率。

---

## 8. 升級與移除

**Docker**:`git pull && docker compose up -d --build`。移除:`docker compose down -v` 再刪映像。

**systemd relay**:`sudo cp relay.py /opt/remotemac/ && sudo systemctl restart remotemac-relay`。移除:

```bash
sudo systemctl disable --now remotemac-relay
sudo rm /etc/systemd/system/remotemac-relay.service /opt/remotemac/relay.py
sudo systemctl daemon-reload
```

**Mesh 節點**:停掉程序(Ctrl-C)。`--tun` 節點結束時會還原路由 / DNS / NAT。它的身份金鑰在 `~/.config/remotemac/mesh/key`(刪掉即遺忘該節點);coordinator 的 overlay IP 對照表在它的 `--state` 檔 / Docker volume。

---

架構、安全模型、完整參數請見 [README](README.zh-TW.md)。
