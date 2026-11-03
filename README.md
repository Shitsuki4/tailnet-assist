# tailnet-assist

经 Tailscale 给已授权的电脑做远程排障：外部的 Codex 通过 SSH 在对方机器上跑命令，通过 [Cua Driver](https://github.com/trycua/cua)（MIT）截图、点击、打字。不需要公网 IP，不需要自己的 VPS，不用手动分配端口。

Codex 不在本项目里。这里只提供：目标机上的一键授权脚本、控制端的小工具 `tna`（管理密钥、SSH 配置和诊断），以及给你自己的 Codex 用的配置示例。

> 只用在你自己的设备，或机器主人明确同意协助的设备上。脚本必须由机器主人在自己的桌面上运行、核对密钥指纹、输入 YES；安装和连接都不隐藏，对方随时可以 `revoke` 撤销。

## 架构

```
控制端（你的电脑）                                       目标机（被协助的电脑，已登录桌面）
┌──────────────────────────┐                             ┌────────────────────────────────────┐
│ Codex（独立安装，不在本项目）   │                             │ sshd（系统自带，端口 22）            │
│  ├─ shell: ssh tna-xxx "cmd" │   Tailscale（WireGuard）    │  └─ 只认 tna 密钥，且只接受       │
│  └─ MCP: ssh tna-xxx         │ ───────────────────────────► │     100.64.0.0/10 等 Tailscale 地址 │
│       cua-driver mcp …     │  能直连就直连，不能就经   │ cua-driver mcp（进程随 SSH 会话启停）│
│ tna（本项目）               │  Tailscale DERP 中继（加密）│  └─ 本机 socket / 命名管道          │
│  └─ ~/.tailnet-assist/     │                             │      └─ cua-driver serve（桌面会话里） │
└──────────────────────────┘                             └────────────────────────────────────┘
```

- **网络**：两台机器都登录 Tailscale。能打洞就点对点直连；打不通时自动走 Tailscale 的 DERP 中继，流量仍然是端到端加密的，只是延迟会高一些。不需要你自己的华为云 / VPS。
- **跑命令**：普通 SSH。控制端用一把专用密钥，目标机的主机公钥在添加时固定（变了就拒绝连接）。
- **看屏幕 / 点击 / 打字**：Cua Driver 的守护进程 `cua-driver serve` 跑在目标机的桌面会话里，只监听本机的 Unix socket（Linux，权限 0600）或命名管道 `\\.\pipe\cua-driver`（Windows）。Codex 把 `ssh … cua-driver mcp --socket …` 当作一个 stdio MCP 服务器启动，MCP 流量走的是同一条 SSH。没有任何 HTTP 端口。

更多设计说明见 [docs/架构说明.md](docs/架构说明.md)。

## 安全边界

目标机上每一项改动都会先列出来，对方输入 YES 才会执行：

| 层 | 限制 |
|---|---|
| Tailscale | 只有同一个 tailnet（或被共享了这台设备）的设备能连。可以用访问规则只放行 tcp:22，见 [examples/tailscale-policy.hujson](examples/tailscale-policy.hujson) |
| 防火墙（Windows） | 脚本新装的 OpenSSH 服务端，22 端口只允许 `100.64.0.0/10`、`fd7a:115c:a1e0::/48`（Tailscale 地址段）。原来就装了 sshd 的，防火墙规则不动 |
| SSH 密钥 | `authorized_keys` 里的那一行带 `restrict,pty,from="Tailscale地址段",expiry-time="到期时间"`：禁止端口转发和代理转发，只接受 Tailscale 来源，默认 7 天后自动失效 |
| 账号 | 登录的就是运行脚本的那个桌面用户，权限不会比它更高 |
| Cua Driver | 只在本机 socket/命名管道上服务；不绕过系统权限（macOS 要主人自己在弹窗里允许辅助功能和屏幕录制；Windows 上以管理员权限运行的窗口可能拒绝操作）。默认关闭它的使用统计 |
| 撤销 | `revoke` 删掉授权行；`uninstall` 再停掉自启动、还原防火墙和 sshd 启动方式；也可以直接在 Tailscale 里断开或删除设备 |

地址、用户名、主机公钥通过一行 `TNA1:...` 交给控制端，里面没有任何密码、私钥或令牌。

## 快速开始

### 0. 两边都要的

- 控制端：Python 3.8+、OpenSSH 客户端（Windows 10/11 自带）、[Tailscale](https://tailscale.com/download)，以及你自己的 Codex。
- 目标机：有人登录着桌面。脚本会自己装 Tailscale（Windows/Linux）、OpenSSH 服务端和 Cua Driver，macOS 的 Tailscale 要主人从 App Store 或官网装。
- 两台机器在同一个 tailnet：可以都登你的账号（自己的机器），或者你在 Tailscale 后台邀请对方加入，或者对方把设备共享给你。

### 1. 控制端：生成密钥和邀请命令

```bash
git clone https://github.com/Shitsuki4/tailnet-assist && cd tailnet-assist
python3 controller/tna.py init                    # 生成 ~/.tailnet-assist/id_ed25519，只给本工具用
python3 controller/tna.py invite --os windows      # 或 --os linux / --os macos；--expires 8h / 7d / never
```

Windows 上把 `python3` 换成 `python` 或 `py`。`invite` 会打印一行命令和你的密钥指纹。这行命令会从本仓库的固定版本（默认 tag `v0.1.0`）下载脚本，**先校验 SHA256，对不上就不运行**。

### 2. 目标机：主人自己运行那行命令

- Windows：在桌面上打开普通 PowerShell（不用「以管理员身份运行」）粘贴。需要管理员的步骤会弹一次 UAC。
- Linux / macOS：在桌面会话的终端里粘贴（不要在 SSH 里跑），需要 sudo 的步骤会问密码。

脚本会显示要做的事和密钥指纹，主人核对后输入 `YES`。之后按提示登录 Tailscale（浏览器里确认）。完成时屏幕上会出现一行 `TNA1:...`（Windows/macOS 会自动复制到剪贴板），发给控制端。

想先看脚本再运行，也可以直接下载 [target/windows/tna-target.ps1](target/windows/tna-target.ps1) 或 [target/unix/tna-target.sh](target/unix/tna-target.sh) 手动执行 `setup`。

### 3. 控制端：添加、诊断、接入 Codex

```bash
python3 controller/tna.py add 'TNA1:eyJ2Ijox...'          # 固定主机公钥，生成 ~/.tailnet-assist/ssh_config
python3 controller/tna.py doctor desk-pc --screenshot s.png # SSH 登录 + MCP 握手 + 截一张图（只读）
python3 controller/tna.py ssh desk-pc -- ipconfig /all      # 自己跑一条命令
python3 controller/tna.py codex-add desk-pc                 # 调用 codex mcp add 写入 Codex 配置
```

`codex-add` 就是替你执行了类似下面这样的命令（用 `tna mcp-config desk-pc` 可以只打印不执行）：

```bash
codex mcp add cua-desk-pc -- ssh -F ~/.tailnet-assist/ssh_config -T tna-desk-pc \
  'cd /d "C:\Users\…\AppData\Local\Programs\Cua\cua-driver\bin" && cua-driver.exe mcp --socket \\.\pipe\cua-driver'
```

建议把启动超时调大（SSH 握手可能超过 Codex 默认的 10 秒），`tna mcp-config desk-pc --format toml` 会输出带 `startup_timeout_sec = 45` 的完整片段，贴进 `~/.codex/config.toml` 即可。完整示例见 [examples/codex-config.toml](examples/codex-config.toml)。

### 4. 让 Codex 干活

- **界面操作**：Codex 里会出现 `cua-desk-pc` 这组 MCP 工具（`get_desktop_state` 截图、`list_windows`、`get_window_state`、`click`、`type_text`、`press_key`、`hotkey` 等）。
- **跑命令**：让 Codex 在它自己的 shell 里执行 `ssh -F ~/.tailnet-assist/ssh_config tna-desk-pc "<命令>"`。把 [examples/AGENTS.md](examples/AGENTS.md) 的内容放进你的工作目录，Codex 就知道怎么做。Codex 默认沙箱不许联网，需要在 `config.toml` 里打开 `[sandbox_workspace_write] network_access = true`，或者每次按提示批准。

## 平台差异与限制

| | Windows 10/11 | macOS 14+ | Linux（x86_64） |
|---|---|---|---|
| SSH 服务 | 装并启用系统自带 OpenSSH Server（要管理员，弹 UAC） | 打开「远程登录」（必要时跳到系统设置） | 没有就用包管理器装 openssh-server |
| 管理员账号的密钥 | 写进 `C:\ProgramData\ssh\administrators_authorized_keys`（Windows 规定），ACL 只留 Administrators 和 SYSTEM。这个文件对本机所有管理员账号生效 | `~/.ssh/authorized_keys` | `~/.ssh/authorized_keys` |
| Cua Driver 守护进程 | 官方安装脚本装到 `%LOCALAPPDATA%\Programs\Cua`，登录时自启动（计划任务），命名管道 `\\.\pipe\cua-driver` | CuaDriver.app，`cua-driver mcp` 自动代理到它 | systemd 用户服务（跟随图形会话），socket `~/.cache/cua-driver/cua-driver.sock` |
| 系统权限 | 以管理员权限运行的窗口（高完整性级别）可能拒绝操作 | 主人要在弹窗里允许「辅助功能」和「屏幕录制」 | X11 支持最完整；Wayland 默认走 XWayland，原生 Wayland 要设 `CUA_DRIVER_RS_ENABLE_WAYLAND=1` 且各桌面环境限制不同（GNOME 还要装 Cua 的 Shell 辅助扩展） |
| 屏幕锁定 / 未登录 | 只能跑命令，看不到也点不了界面 | 同左 | 同左 |
| Tailscale | 默认只在用户登录时运行（本脚本不开启 unattended 模式），注销就断网 | App Store / 独立安装包 | 官方 install.sh |

Windows 的 OpenSSH 默认 shell 是 cmd。让 Codex 跑 PowerShell 命令时写成 `powershell -NoProfile -Command "..."`。如果对方把 DefaultShell 改成了 PowerShell，脚本会报告给控制端，MCP 启动命令会自动换写法。

OpenSSH 低于 8.2 不支持 `expiry-time`，脚本会提醒并跳过到期设置，这时要用完手动 `revoke`。

## 撤销、卸载、诊断

目标机（主人操作）：

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File $env:TEMP\tna-target.ps1 status
powershell -ExecutionPolicy Bypass -File $env:TEMP\tna-target.ps1 revoke            # 删掉全部授权（-Label xxx 只删一个）
powershell -ExecutionPolicy Bypass -File $env:TEMP\tna-target.ps1 uninstall         # 再停自启动、还原防火墙和 sshd；-RemoveOpenSSH -LogoutTailscale 可选
```

```bash
# Linux / macOS
bash tna-target.sh status
bash tna-target.sh revoke
bash tna-target.sh uninstall [--remove-cua] [--logout-tailscale]
```

`revoke` 之后新连接会被拒绝；已经连着的会话不会自动断，要立即断开就在 Tailscale 里断开连接。脚本不会卸载 Tailscale 本身。

控制端：

```bash
python3 controller/tna.py list
python3 controller/tna.py doctor desk-pc     # 哪一步不通就停在哪一步，并提示该查什么
python3 controller/tna.py remove desk-pc     # 只删本机记录；再执行 codex mcp remove cua-desk-pc
```

常见问题：

- **SSH 连不上**：两边 `tailscale status` 是否都在线；Tailscale 访问规则是否放行 tcp:22；对方是否已 revoke 或已到期（目标机 `status` 可看到期时间）。
- **SSH 通了但 MCP 失败**：对方桌面是否登录且没锁屏；在对方机器上运行 `cua-driver status` 或 `cua-driver doctor`。
- **主机公钥变了**（对方重装了系统或 sshd）：让对方重新跑一次 setup，用新的 `TNA1:` 行 `add --force`。

## 测试与验证范围

CI（`.github/workflows/ci.yml`）每次提交都会跑：

- 三个系统上的控制端单元测试、两个目标端脚本的单元测试（PowerShell 5.1 和 7 都跑）、shellcheck / ruff / PSScriptAnalyzer。
- **Linux 端到端**（真实桌面，不含 Tailscale）：Xvfb 桌面 + 官方安装的 Cua Driver + 本机 sshd，由目标端脚本配置、控制端添加后：经 SSH 跑命令、经 SSH 启动 MCP 截图、点击 xterm 并打字回车（验证生成的文件）；再验证 `from=` 拦截非允许来源、过期密钥被拒、端口转发被拒、revoke 后无法登录。
- **Windows**（GitHub 的 Windows 虚拟机，不含 Tailscale 和 Cua）：目标端脚本安装/启用 OpenSSH、写入 administrators_authorized_keys 并设 ACL，控制端登录跑命令，revoke 后被拒，uninstall 还原。

**没有自动化验证的**：Tailscale 的登录和实际组网（需要真实账号）；Windows 上经 SSH 连命名管道的 Cua Driver MCP（按 Cua 官方文档的做法实现）；macOS 全流程。第一次在真实机器上使用时请先用 `tna doctor --screenshot` 确认。

## 依赖与许可

- [Tailscale](https://tailscale.com)：客户端开源，协调服务是 Tailscale 公司的（也可以自建 [Headscale](https://github.com/juanfont/headscale)，但那又需要一台服务器）。
- [Cua Driver](https://github.com/trycua/cua)：MIT。本项目只调用它的官方安装脚本，不再分发。
- 本项目：MIT。
