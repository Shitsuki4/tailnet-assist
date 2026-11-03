#!/usr/bin/env bash
# tailnet-assist target side for Linux and macOS.
#
# Run by the OWNER of the machine, in a terminal inside their logged-in
# desktop session. Every change is shown first and needs explicit consent.
#
#   bash tna-target.sh setup --operator-key 'ssh-ed25519 AAAA... comment' [--expires 7d]
#   bash tna-target.sh status
#   bash tna-target.sh revoke [--label NAME]
#   bash tna-target.sh uninstall [--logout-tailscale] [--remove-cua]
#
# Nothing listens on a new network port: SSH is the system sshd, the
# operator key only works from Tailscale addresses (from=...), and Cua
# Driver talks over a 0600 Unix socket / the macOS app, never TCP.
set -euo pipefail

TNA_VERSION="0.1.0"
TS_CIDRS_DEFAULT="100.64.0.0/10,fd7a:115c:a1e0::/48"
CUA_INSTALL_URL="https://cua.ai/driver/install.sh"
CUA_UNINSTALL_URL="https://cua.ai/driver/uninstall.sh"
TS_LINUX_INSTALL_URL="https://tailscale.com/install.sh"

OS_KIND="$(uname -s)"
case "$OS_KIND" in
  Linux) OS_NAME=linux ;;
  Darwin) OS_NAME=macos ;;
  *) echo "不支持的系统: $OS_KIND" >&2; exit 1 ;;
esac

STATE_DIR="${TNA_STATE_DIR:-$HOME/.config/tailnet-assist}"
STATE_FILE="$STATE_DIR/target.state"
AUTH_KEYS="${TNA_AUTHORIZED_KEYS:-$HOME/.ssh/authorized_keys}"
HOST_KEY_DIR="${TNA_HOST_KEY_DIR:-/etc/ssh}"

ACTION="${1:-help}"; [[ $# -gt 0 ]] && shift
OPERATOR_KEY=""; EXPIRES="7d"; LABEL="operator"; ASSUME_YES=0
SKIP_TS=0; SKIP_SSHD=0; SKIP_CUA=0; KEEP_TELEMETRY=0
ALLOW_FROM="$TS_CIDRS_DEFAULT"; NAME=""; HOST_OVERRIDE=""
LOGOUT_TS=0; REMOVE_CUA=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator-key) OPERATOR_KEY="${2:?}"; shift 2 ;;
    --expires) EXPIRES="${2:?}"; shift 2 ;;
    --label) LABEL="${2:?}"; shift 2 ;;
    --name) NAME="${2:?}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --skip-tailscale) SKIP_TS=1; shift ;;
    --skip-ssh-server) SKIP_SSHD=1; shift ;;
    --skip-cua) SKIP_CUA=1; shift ;;
    --keep-telemetry) KEEP_TELEMETRY=1; shift ;;
    --allow-from) ALLOW_FROM="${2:?}"; shift 2 ;;
    --host) HOST_OVERRIDE="${2:?}"; shift 2 ;;
    --logout-tailscale) LOGOUT_TS=1; shift ;;
    --remove-cua) REMOVE_CUA=1; shift ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf '注意: %s\n' "$*" >&2; }
die()  { printf '错误: %s\n' "$*" >&2; exit 1; }

confirm() {
  # confirm "question" -> returns 0 on yes
  if [[ $ASSUME_YES -eq 1 ]]; then return 0; fi
  local ans
  read -r -p "$1 [y/N] " ans </dev/tty || return 1
  [[ "$ans" == "y" || "$ans" == "Y" || "$ans" == "yes" ]]
}

state_get() { [[ -f "$STATE_FILE" ]] && grep -E "^$1=" "$STATE_FILE" | tail -1 | cut -d= -f2- || true; }
state_set() {
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  touch "$STATE_FILE"; chmod 600 "$STATE_FILE"
  local tmp; tmp="$(mktemp)"
  grep -v -E "^$1=" "$STATE_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  cat "$tmp" > "$STATE_FILE"; rm -f "$tmp"
}

have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [[ $(id -u) -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

# ------------------------------------------------------------ pure helpers (unit tested)

validate_pubkey() {
  [[ "$1" =~ ^(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa)\ [A-Za-z0-9+/]+={0,3}(\ .*)?$ ]]
}

sanitize_label() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-40; }

# expiry_stamp 7d|8h|never -> YYYYMMDDHHMMZ (UTC) or empty
expiry_stamp() {
  local spec="$1" n unit secs now
  [[ "$spec" == "never" ]] && { printf ''; return 0; }
  [[ "$spec" =~ ^([0-9]{1,3})([hd])$ ]] || return 1
  n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
  if [[ $unit == h ]]; then secs=$((n*3600)); else secs=$((n*86400)); fi
  now="$(date -u +%s)"
  if date -u -d "@$((now+secs))" +%Y%m%d%H%M >/dev/null 2>&1; then
    printf '%sZ' "$(date -u -d "@$((now+secs))" +%Y%m%d%H%M)"
  else
    printf '%sZ' "$(date -u -r "$((now+secs))" +%Y%m%d%H%M)"
  fi
}

# build_key_line <pubkey> <label> <keyid> <allow_from> <expiry_stamp>
build_key_line() {
  local key="$1" label="$2" keyid="$3" from="$4" exp="$5" opts body
  body="$(printf '%s' "$key" | awk '{print $1" "$2}')"
  opts="restrict,pty"
  [[ -n "$from" ]] && opts="$opts,from=\"$from\""
  [[ -n "$exp" ]] && opts="$opts,expiry-time=\"$exp\""
  printf '%s %s tna:%s:%s\n' "$opts" "$body" "$label" "$keyid"
}

# remove_tna_lines <file> [label] -> prints number removed
remove_tna_lines() {
  local file="$1" label="${2:-}" tmp before after pat
  [[ -f "$file" ]] || { echo 0; return 0; }
  if [[ -n "$label" ]]; then pat=" tna:${label}:[0-9a-f]+$"; else pat=" tna:[A-Za-z0-9._-]+:[0-9a-f]+$"; fi
  tmp="$(mktemp)"
  before=$(wc -l < "$file")
  grep -v -E "$pat" "$file" > "$tmp" || true
  after=$(wc -l < "$tmp")
  cat "$tmp" > "$file"; rm -f "$tmp"
  echo $((before - after))
}

key_fingerprint() {
  if have ssh-keygen; then
    printf '%s\n' "$1" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}'
  fi
}

b64url() { base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }
json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# ------------------------------------------------------------ components

ts_bin() {
  if have tailscale; then command -v tailscale; return; fi
  if [[ -x /Applications/Tailscale.app/Contents/MacOS/Tailscale ]]; then
    echo /Applications/Tailscale.app/Contents/MacOS/Tailscale; return; fi
  echo ""
}

ts_ip() {
  local ts; ts="$(ts_bin)"; [[ -n "$ts" ]] || return 1
  "$ts" ip -4 2>/dev/null | head -1
}

ensure_tailscale() {
  step "Tailscale（两台机器之间的加密虚拟网络）"
  local ts; ts="$(ts_bin)"
  if [[ -z "$ts" ]]; then
    if [[ $OS_NAME == linux ]]; then
      say "本机没有 Tailscale。将运行官方安装脚本: $TS_LINUX_INSTALL_URL（需要 sudo）"
      confirm "安装 Tailscale？" || die "已取消"
      local f; f="$(mktemp)"; curl -fsSL "$TS_LINUX_INSTALL_URL" -o "$f"; sh "$f"; rm -f "$f"
      state_set installed_tailscale 1
    else
      say "本机没有 Tailscale。请从 App Store 或 https://tailscale.com/download/mac 安装并登录。"
      open "https://tailscale.com/download/mac" 2>/dev/null || true
      read -r -p "装好并登录后按回车继续..." _ </dev/tty
    fi
    ts="$(ts_bin)"; [[ -n "$ts" ]] || die "仍然找不到 tailscale 命令"
  fi
  if ! "$ts" ip -4 >/dev/null 2>&1; then
    say "需要登录 Tailscale。登录哪个账号/网络由你决定：这决定了哪些设备能看到本机。"
    local up=(up)
    if [[ -n "${TNA_TS_AUTHKEY:-}" ]]; then
      local kf; kf="$(mktemp)"; chmod 600 "$kf"; printf '%s' "$TNA_TS_AUTHKEY" > "$kf"
      up+=("--auth-key=file:$kf")
      if [[ $OS_NAME == linux ]]; then as_root "$ts" "${up[@]}"; else "$ts" "${up[@]}"; fi
      rm -f "$kf"
    else
      if [[ $OS_NAME == linux ]]; then as_root "$ts" "${up[@]}"; else "$ts" "${up[@]}"; fi
    fi
  fi
  local ip; ip="$(ts_ip)" || true
  [[ -n "$ip" ]] || die "Tailscale 没有分到地址，请检查 tailscale status"
  say "Tailscale 地址: $ip"
}

ensure_sshd_linux() {
  if ! have sshd && [[ ! -x /usr/sbin/sshd ]]; then
    say "本机没有 SSH 服务端（openssh-server）。"
    confirm "用系统包管理器安装 openssh-server？" || die "已取消"
    if have apt-get; then as_root apt-get update -qq && as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server
    elif have dnf; then as_root dnf install -y openssh-server
    elif have zypper; then as_root zypper --non-interactive install openssh
    elif have pacman; then as_root pacman -S --noconfirm openssh
    else die "不认识的包管理器，请手动安装 openssh-server 后重试"; fi
    state_set installed_sshd 1
  fi
  if have systemctl; then
    if ! systemctl is-active --quiet ssh 2>/dev/null && ! systemctl is-active --quiet sshd 2>/dev/null; then
      confirm "启动并开机自启 SSH 服务？" || die "已取消"
      as_root systemctl enable --now ssh 2>/dev/null || as_root systemctl enable --now sshd
      state_set enabled_sshd 1
    fi
  fi
  if have sudo || [[ $(id -u) -eq 0 ]]; then
    local eff; eff="$(as_root sshd -T 2>/dev/null || true)"
    if [[ -n "$eff" ]]; then
      grep -qi '^pubkeyauthentication yes' <<<"$eff" || warn "sshd 关闭了公钥登录（PubkeyAuthentication），控制端将无法登录"
      grep -qi '^authorizedkeysfile.*\.ssh/authorized_keys' <<<"$eff" || warn "sshd 的 AuthorizedKeysFile 不含 .ssh/authorized_keys"
    fi
  fi
}

ensure_sshd_macos() {
  local st; st="$(sudo systemsetup -getremotelogin 2>/dev/null || true)"
  if [[ "$st" == *": On"* ]]; then say "远程登录（Remote Login）已开启"; return; fi
  say "需要打开 macOS 的「远程登录」（系统自带 SSH 服务）。"
  confirm "现在打开远程登录？" || die "已取消"
  if sudo systemsetup -setremotelogin on 2>/dev/null; then
    state_set enabled_remotelogin 1
  else
    say "命令行没有权限打开（新版 macOS 需要完全磁盘访问权限）。正在打开「系统设置 > 通用 > 共享」，请手动打开「远程登录」。"
    open "x-apple.systempreferences:com.apple.Sharing-Settings.extension" 2>/dev/null || true
    read -r -p "打开后按回车继续..." _ </dev/tty
    state_set enabled_remotelogin 1
  fi
}

install_key() {
  step "授权控制端的 SSH 公钥"
  local exp keyid line
  exp="$(expiry_stamp "$EXPIRES")" || die "--expires 格式应为 8h / 7d / never"
  keyid="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  line="$(build_key_line "$OPERATOR_KEY" "$LABEL" "$keyid" "$ALLOW_FROM" "$exp")"
  mkdir -p "$(dirname "$AUTH_KEYS")"; chmod 700 "$(dirname "$AUTH_KEYS")"
  touch "$AUTH_KEYS"; chmod 600 "$AUTH_KEYS"
  local removed; removed="$(remove_tna_lines "$AUTH_KEYS" "$LABEL")"
  [[ "$removed" != "0" ]] && say "替换了同标签的旧授权 $removed 条"
  printf '%s\n' "$line" >> "$AUTH_KEYS"
  state_set keyid "$keyid"; state_set label "$LABEL"; state_set expires "${exp:-never}"
  KEYID="$keyid"; EXP_STAMP="${exp:-never}"
  say "已写入 $AUTH_KEYS（只接受来自 $ALLOW_FROM 的连接，到期: ${exp:-不过期}）"
}

cua_bin() {
  if [[ -x "$HOME/.local/bin/cua-driver" ]]; then echo "$HOME/.local/bin/cua-driver"; return; fi
  if have cua-driver; then command -v cua-driver; return; fi
  echo ""
}

write_systemd_unit() {
  local unit_dir="$HOME/.config/systemd/user" bin="$1"
  mkdir -p "$unit_dir"
  cat > "$unit_dir/cua-driver.service" <<EOF
# Installed by tailnet-assist. Remove with: tna-target.sh uninstall
[Unit]
Description=Cua Driver daemon (tailnet-assist)
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart=$bin serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
EOF
}

ensure_cua() {
  step "Cua Driver（截图、点击、键盘，只在本机 socket 上提供服务）"
  local bin; bin="$(cua_bin)"
  if [[ -z "$bin" ]]; then
    say "将运行 Cua Driver 官方安装脚本: $CUA_INSTALL_URL（MIT 许可，装到当前用户目录，不需要 sudo）"
    confirm "安装 Cua Driver？" || die "已取消"
    local f; f="$(mktemp)"; curl -fsSL "$CUA_INSTALL_URL" -o "$f"
    CUA_DRIVER_NO_MODIFY_PATH=1 bash "$f"; rm -f "$f"
    state_set installed_cua 1
    bin="$(cua_bin)"; [[ -n "$bin" ]] || die "Cua Driver 安装后找不到 cua-driver"
  fi
  CUA_BIN="$bin"
  if [[ $KEEP_TELEMETRY -eq 0 ]]; then "$bin" telemetry disable >/dev/null 2>&1 && say "已关闭 Cua Driver 使用统计" || true; fi
  if [[ $OS_NAME == macos ]]; then
    say "接下来 macOS 会弹窗申请「辅助功能」和「屏幕录制」权限，请按提示允许（不允许就只能跑命令，不能看屏幕或点击）。"
    "$bin" permissions grant || warn "权限没有全部授予，可稍后运行: $bin permissions grant"
    CUA_SOCKET=""
    return
  fi
  CUA_SOCKET="$HOME/.cache/cua-driver/cua-driver.sock"
  if have systemctl && systemctl --user show-environment >/dev/null 2>&1; then
    write_systemd_unit "$bin"
    systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS XDG_SESSION_TYPE 2>/dev/null || true
    systemctl --user daemon-reload
    systemctl --user enable --now cua-driver.service
    systemctl --user restart cua-driver.service
    state_set cua_unit systemd
  else
    mkdir -p "$HOME/.config/autostart"
    cat > "$HOME/.config/autostart/cua-driver.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Cua Driver (tailnet-assist)
Exec=$bin serve
X-GNOME-Autostart-enabled=true
EOF
    nohup "$bin" serve >/dev/null 2>&1 &
    state_set cua_unit xdg
  fi
  for _ in $(seq 1 20); do
    "$bin" status 2>/dev/null | grep -q 'is running' && break
    sleep 0.5
  done
  "$bin" status 2>/dev/null | grep -q 'is running' || warn "Cua Driver 守护进程没有跑起来，请运行 $bin doctor 查看"
  say "Cua Driver 守护进程 socket: $CUA_SOCKET（权限 0600，只有本用户能连）"
}

host_key() {
  local f
  for f in "$HOST_KEY_DIR/ssh_host_ed25519_key.pub" "$HOST_KEY_DIR/ssh_host_ecdsa_key.pub"; do
    [[ -r "$f" ]] && { awk '{print $1" "$2}' "$f"; return; }
  done
  return 1
}

emit_info() {
  local host="$1" hk name user json
  hk="$(host_key)" || die "读不到 SSH 主机公钥（$HOST_KEY_DIR）"
  user="$(id -un)"
  name="${NAME:-$(hostname -s 2>/dev/null || hostname)}"
  name="$(printf '%s' "$name" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | cut -c1-40)"
  json="{\"v\":1,\"name\":\"$(json_esc "$name")\",\"os\":\"$OS_NAME\",\"user\":\"$(json_esc "$user")\",\"host\":\"$(json_esc "$host")\",\"ip\":\"$(json_esc "$host")\",\"hostkey\":\"$(json_esc "$hk")\",\"shell\":\"sh\""
  [[ -n "${CUA_BIN:-}" ]] && json="$json,\"cua\":\"$(json_esc "$CUA_BIN")\""
  [[ -n "${CUA_SOCKET:-}" ]] && json="$json,\"socket\":\"$(json_esc "$CUA_SOCKET")\""
  [[ -n "${TNA_SSH_PORT:-}" ]] && json="$json,\"port\":$((TNA_SSH_PORT))"
  json="$json,\"expires\":\"${EXP_STAMP:-never}\",\"keyid\":\"${KEYID:-}\",\"created\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
  INFO_LINE="TNA1:$(printf '%s' "$json" | b64url)"
  printf '%s\n' "$INFO_LINE" > "$STATE_DIR/connection-info.txt"
}

# ------------------------------------------------------------ actions

do_setup() {
  [[ -n "$OPERATOR_KEY" ]] || die "缺少 --operator-key（由控制端 tna invite 生成）"
  validate_pubkey "$OPERATOR_KEY" || die "--operator-key 不是有效的 SSH 公钥"
  LABEL="$(sanitize_label "$LABEL")"
  expiry_stamp "$EXPIRES" >/dev/null || die "--expires 格式应为 8h / 7d / never"
  if [[ -n "${SSH_CONNECTION:-}" && $SKIP_CUA -eq 0 ]]; then
    die "请在本机桌面会话的终端里运行，不要通过 SSH 运行（Cua Driver 必须跑在桌面会话里）"
  fi
  if [[ $OS_NAME == linux && $SKIP_CUA -eq 0 && -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
    die "没有检测到图形桌面（DISPLAY/WAYLAND_DISPLAY 为空）。请在桌面终端里运行，或加 --skip-cua 只开启命令行排障"
  fi
  local fp; fp="$(key_fingerprint "$OPERATOR_KEY")"
  if have ssh-keygen && [[ -z "$fp" ]]; then die "--operator-key 不是有效的 SSH 公钥（ssh-keygen 无法解析）"; fi
  cat <<EOF
================ tailnet-assist 远程协助授权 ================
你将允许下面这把密钥的持有人，以当前用户 $(id -un) 的身份：
  - 通过 SSH 在本机运行命令（权限等同于你当前账号）
  - 通过 Cua Driver 查看你的屏幕、点击、打字（你会看到它的操作）
密钥指纹: ${fp:-（无法计算）}   标签: $LABEL
有效期: $EXPIRES        只接受来自: $ALLOW_FROM
将要做的事（每一步会单独询问）:
  $( [[ $SKIP_TS -eq 1 ]] && echo '-' || echo '✓') 安装/登录 Tailscale
  $( [[ $SKIP_SSHD -eq 1 ]] && echo '-' || echo '✓') 开启系统 SSH 服务
  ✓ 把上面的公钥写入 $AUTH_KEYS
  $( [[ $SKIP_CUA -eq 1 ]] && echo '-' || echo '✓') 安装 Cua Driver 并在登录桌面时自动启动
随时撤销: bash $0 revoke     全部还原: bash $0 uninstall
=================================================================
EOF
  if [[ $ASSUME_YES -eq 0 ]]; then
    local ans; read -r -p "请核对指纹与对方告诉你的一致。同意请输入 YES: " ans </dev/tty
    [[ "$ans" == "YES" ]] || die "未同意，什么都没改"
  fi
  state_set version "$TNA_VERSION"
  local host="$HOST_OVERRIDE"
  if [[ $SKIP_TS -eq 0 ]]; then ensure_tailscale; host="${host:-$(ts_ip)}"; fi
  [[ -n "$host" ]] || die "不知道本机地址（跳过 Tailscale 时请用 --host 指定）"
  if [[ $SKIP_SSHD -eq 0 ]]; then
    step "SSH 服务"
    if [[ $OS_NAME == linux ]]; then ensure_sshd_linux; else ensure_sshd_macos; fi
  fi
  install_key
  CUA_BIN=""; CUA_SOCKET=""
  [[ $SKIP_CUA -eq 0 ]] && ensure_cua
  emit_info "$host"
  cat <<EOF

================ 完成 ================
把下面这一行发给协助你的人（里面只有地址、用户名和主机公钥，没有任何密码或私钥）：

$INFO_LINE

也保存在 $STATE_DIR/connection-info.txt
查看状态: bash $0 status    撤销授权: bash $0 revoke
EOF
  if [[ $OS_NAME == macos ]] && have pbcopy; then printf '%s' "$INFO_LINE" | pbcopy && say "（已复制到剪贴板）"; fi
}

do_status() {
  say "tailnet-assist 目标端状态（$OS_NAME）"
  local ts; ts="$(ts_bin)"
  if [[ -n "$ts" ]]; then say "Tailscale: $("$ts" ip -4 2>/dev/null | head -1 || echo 未连接)"; else say "Tailscale: 未安装"; fi
  if [[ $OS_NAME == linux ]] && have systemctl; then
    say "SSH 服务: $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || true)"
  fi
  say "已授权的控制端密钥（$AUTH_KEYS）:"
  if [[ -f "$AUTH_KEYS" ]] && grep -E ' tna:[A-Za-z0-9._-]+:[0-9a-f]+$' "$AUTH_KEYS" >/dev/null; then
    grep -E ' tna:[A-Za-z0-9._-]+:[0-9a-f]+$' "$AUTH_KEYS" | while read -r l; do
      local exp; exp="$(printf '%s' "$l" | sed -n 's/.*expiry-time="\([0-9Z]*\)".*/\1/p')"
      say "  ${l##* }  到期: ${exp:-不过期}"
    done
  else
    say "  （无）"
  fi
  local bin; bin="$(cua_bin)"
  if [[ -n "$bin" ]]; then say "Cua Driver: $("$bin" status 2>/dev/null | head -1 || echo 未运行)"; else say "Cua Driver: 未安装"; fi
  [[ -f "$STATE_DIR/connection-info.txt" ]] && say "连接信息: $(cat "$STATE_DIR/connection-info.txt")"
  return 0
}

do_revoke() {
  local label=""
  [[ "$LABEL" != "operator" ]] && label="$(sanitize_label "$LABEL")"
  local n; n="$(remove_tna_lines "$AUTH_KEYS" "$label")"
  say "已从 $AUTH_KEYS 删除 $n 条 tailnet-assist 授权。之后的新连接会被拒绝。"
  if [[ $n != 0 ]]; then
    say "已经连着的会话不会自动断开。要立即断开，可以断开 Tailscale（tailscale down）或重启 SSH 服务。"
  fi
}

do_uninstall() {
  confirm "撤销全部授权并还原 tailnet-assist 做过的更改？" || die "已取消"
  LABEL=operator; do_revoke
  local bin; bin="$(cua_bin)"
  case "$(state_get cua_unit)" in
    systemd) systemctl --user disable --now cua-driver.service 2>/dev/null || true
             rm -f "$HOME/.config/systemd/user/cua-driver.service"; systemctl --user daemon-reload 2>/dev/null || true
             say "已移除 Cua Driver 自启动（systemd 用户服务）" ;;
    xdg) rm -f "$HOME/.config/autostart/cua-driver.desktop"; say "已移除 Cua Driver 自启动（autostart）" ;;
  esac
  [[ -n "$bin" ]] && "$bin" stop >/dev/null 2>&1 || true
  if [[ $REMOVE_CUA -eq 1 ]]; then
    local f; f="$(mktemp)"; curl -fsSL "$CUA_UNINSTALL_URL" -o "$f" && bash "$f"; rm -f "$f"
  elif [[ "$(state_get installed_cua)" == 1 ]]; then
    say "Cua Driver 程序还在（不再自动启动）。要删掉程序加 --remove-cua。"
  fi
  if [[ "$(state_get enabled_sshd)" == 1 || "$(state_get installed_sshd)" == 1 ]] && have systemctl; then
    if confirm "SSH 服务是 tailnet-assist 启用的，现在停用它？"; then
      as_root systemctl disable --now ssh 2>/dev/null || as_root systemctl disable --now sshd 2>/dev/null || true
    fi
  fi
  if [[ "$(state_get enabled_remotelogin)" == 1 ]]; then
    confirm "「远程登录」是 tailnet-assist 打开的，现在关闭？" && { sudo systemsetup -f -setremotelogin off 2>/dev/null || say "请在系统设置 > 通用 > 共享里手动关闭「远程登录」"; }
  fi
  if [[ $LOGOUT_TS -eq 1 ]]; then
    local ts; ts="$(ts_bin)"
    [[ -n "$ts" ]] && { if [[ $OS_NAME == linux ]]; then as_root "$ts" logout; else "$ts" logout; fi; say "已登出 Tailscale"; }
  else
    say "Tailscale 没动。要让本机离开网络：tailscale logout，或在 Tailscale 管理后台删除本设备。"
  fi
  rm -f "$STATE_DIR/connection-info.txt" "$STATE_FILE"
  say "完成。"
}

case "$ACTION" in
  setup) do_setup ;;
  status) do_status ;;
  revoke) do_revoke ;;
  uninstall) do_uninstall ;;
  __lib) : ;;  # sourced by tests
  help|-h|--help) sed -n '2,14p' "$0" ;;
  *) die "未知操作: $ACTION（setup / status / revoke / uninstall）" ;;
esac
