#!/usr/bin/env bash
# Full local end-to-end on one Linux box, without Tailscale:
#   Xvfb desktop + cua-driver serve  <-  sshd on 127.0.0.1:2222  <-  controller (tna)
# The target script and controller run exactly as shipped; only the address
# restriction is changed from the Tailscale ranges to 127.0.0.1 because both
# ends are on the same machine.
#
# Needs: sudo, openssh-server, Xvfb, openbox, xterm, dbus-x11, at-spi2-core,
#        cua-driver in ~/.local/bin (install: curl -fsSL https://cua.ai/driver/install.sh | bash)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d /tmp/tna-e2e.XXXXXX)"
PORT="${TNA_E2E_PORT:-2222}"
DISP="${TNA_E2E_DISPLAY:-:91}"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  [[ -f "$T/sshd.pid" ]] && sudo kill "$(cat "$T/sshd.pid")" 2>/dev/null || true
}
trap cleanup EXIT
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }

# --- sshd (root, PAM on, so the normal user account can log in by key)
ssh-keygen -q -t ed25519 -N '' -f "$T/ssh_host_ed25519_key"
mkdir -p "$T/hk" && cp "$T/ssh_host_ed25519_key.pub" "$T/hk/"
touch "$T/authorized_keys"; chmod 600 "$T/authorized_keys"
cat > "$T/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $T/ssh_host_ed25519_key
PidFile $T/sshd.pid
AuthorizedKeysFile $T/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
StrictModes no
AllowUsers $(id -un)
EOF
sudo mkdir -p /run/sshd
sudo /usr/sbin/sshd -f "$T/sshd_config" -E "$T/sshd.log"

# --- desktop session
export DISPLAY="$DISP"
Xvfb "$DISP" -screen 0 1280x800x24 >/dev/null 2>&1 & PIDS+=($!)
sleep 1
eval "$(dbus-launch --sh-syntax)"; PIDS+=("$DBUS_SESSION_BUS_PID")
openbox >/dev/null 2>&1 & PIDS+=($!)
for l in /usr/libexec/at-spi-bus-launcher /usr/lib/at-spi2-core/at-spi-bus-launcher; do
  [[ -x $l ]] && { "$l" --launch-immediately >/dev/null 2>&1 & PIDS+=($!); break; }
done
xterm -T e2e-term >/dev/null 2>&1 & PIDS+=($!)
sleep 1

# --- controller init + invite (invite output is only printed, the target runs the local script)
export TNA_HOME="$T/operator"
python3 "$ROOT/controller/tna.py" init
PUB="$(cat "$TNA_HOME/id_ed25519.pub")"
python3 "$ROOT/controller/tna.py" invite --os linux --expires 2h --label e2e >"$T/invite.txt"
grep -q 'sha256sum -c' "$T/invite.txt" && pass "invite one-liner generated" || fail "invite"

# --- target setup, as the desktop user (no Tailscale / no system sshd changes in this test)
(
  unset SSH_CONNECTION
  export TNA_STATE_DIR="$T/target" TNA_AUTHORIZED_KEYS="$T/authorized_keys" TNA_HOST_KEY_DIR="$T/hk" TNA_SSH_PORT="$PORT"
  bash "$ROOT/target/unix/tna-target.sh" setup --operator-key "$PUB" --expires 2h --label e2e --yes \
    --skip-tailscale --skip-ssh-server --host 127.0.0.1 --allow-from 127.0.0.1 --name e2e-linux
) >"$T/setup.log" 2>&1 || { cat "$T/setup.log"; fail "target setup"; }
grep -q 'restrict,pty,from="127.0.0.1",expiry-time="[0-9]\{12\}Z" ssh-ed25519 .* tna:e2e:[0-9a-f]\{8\}$' "$T/authorized_keys" \
  && pass "authorized_keys line has restrict/from/expiry/marker" || { cat "$T/authorized_keys"; fail "key line"; }

# --- controller add + doctor (SSH + MCP handshake + screenshot)
python3 "$ROOT/controller/tna.py" add "$(cat "$T/target/connection-info.txt")"
python3 "$ROOT/controller/tna.py" doctor e2e-linux --screenshot "$T/shot.png" | tee "$T/doctor.log"
head -c 8 "$T/shot.png" | od -An -tx1 | grep -q '89 50 4e 47' && pass "screenshot over SSH is a PNG ($(wc -c <"$T/shot.png") bytes)" || fail "screenshot"

# --- run a command over SSH
out="$(python3 "$ROOT/controller/tna.py" ssh e2e-linux -- echo cmd-ok 2>&1)"
[[ "$out" == *cmd-ok* ]] && pass "command over SSH" || fail "command over SSH: $out"

# --- click + keyboard through MCP: type into the xterm, then check the file it created
rm -f "$T/typed.txt"
python3 "$ROOT/tests/e2e/gui_over_ssh.py" e2e-linux "$T/typed.txt" "${TNA_E2E_SHOT:-$T/gui-shot.png}"
for _ in $(seq 1 20); do [[ -s "$T/typed.txt" ]] && break; sleep 0.25; done
[[ "$(cat "$T/typed.txt" 2>/dev/null)" == tna-e2e-ok ]] && pass "click + type_text + press_key reached the desktop" || fail "GUI input"

# --- Codex config text is valid TOML and points at ssh
python3 "$ROOT/controller/tna.py" mcp-config e2e-linux --format toml >"$T/codex.toml"
python3 - "$T/codex.toml" <<'EOF' && pass "codex TOML parses"
import sys
try:
    import tomllib
except ImportError:
    sys.exit(0)
d = tomllib.load(open(sys.argv[1], "rb"))
s = d["mcp_servers"]["cua-e2e-linux"]
assert s["command"] == "ssh" and "mcp" in s["args"][-1], s
EOF
# (python exits 0 without tomllib on old Pythons; the unit tests cover it too)

# --- from= restriction: same key, but only allowed from another address -> rejected
cp "$T/authorized_keys" "$T/ak.bak"
sed -i 's/from="127.0.0.1"/from="100.64.0.0\/10"/' "$T/authorized_keys"
if python3 "$ROOT/controller/tna.py" ssh e2e-linux -- echo should-not-run >/dev/null 2>&1; then fail "from= not enforced"; else pass "from= blocks non-tailnet source"; fi
# --- expiry-time in the past -> rejected
cp "$T/ak.bak" "$T/authorized_keys"
sed -i 's/expiry-time="[0-9]*Z"/expiry-time="200001010000Z"/' "$T/authorized_keys"
if python3 "$ROOT/controller/tna.py" ssh e2e-linux -- echo should-not-run >/dev/null 2>&1; then fail "expiry not enforced"; else pass "expired key rejected"; fi
cp "$T/ak.bak" "$T/authorized_keys"
# --- restrict: port forwarding refused
# (-W asks the server for a direct-tcpip channel; restrict must refuse it)
if timeout 20 ssh -F "$TNA_HOME/ssh_config" -o ClearAllForwardings=no -W 127.0.0.1:"$PORT" tna-e2e-linux </dev/null 2>"$T/fwd.err" | head -c 4 | grep -q SSH; then
  fail "port forwarding allowed"; else pass "port forwarding refused (restrict): $(tr -d '\r' <"$T/fwd.err" | tail -1)"; fi

# --- status + revoke on the target, then the controller can no longer connect
st="$(TNA_STATE_DIR="$T/target" TNA_AUTHORIZED_KEYS="$T/authorized_keys" bash "$ROOT/target/unix/tna-target.sh" status)"
[[ "$st" == *tna:e2e:* ]] && pass "status lists the grant" || fail "status: $st"
rv="$(TNA_STATE_DIR="$T/target" TNA_AUTHORIZED_KEYS="$T/authorized_keys" bash "$ROOT/target/unix/tna-target.sh" revoke)"
[[ "$rv" == *"删除 1 条"* ]] && pass "revoke removed 1 grant" || fail "revoke: $rv"
if python3 "$ROOT/controller/tna.py" ssh e2e-linux -- echo should-not-run >/dev/null 2>&1; then fail "still works after revoke"; else pass "login refused after revoke"; fi
echo "ALL E2E CHECKS PASSED"
