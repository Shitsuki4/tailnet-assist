#!/usr/bin/env python3
"""End-to-end: drive a real desktop through `ssh ... cua-driver mcp`.

Usage: TNA_HOME=... python3 tests/e2e/gui_over_ssh.py <target-name> <marker-file>

On the target there must be an xterm window open (title e2e-term). The test:
  1. lists windows and finds the xterm
  2. takes a screenshot (get_desktop_state)
  3. clicks into the xterm
  4. types `echo tna-e2e-ok > <marker-file>` and presses Enter
The caller then checks that <marker-file> contains tna-e2e-ok.

Input is first sent with Cua Driver's default delivery_mode "background".
Some hosts (e.g. GitHub's Ubuntu runners) refuse or drop background
injection, so when a call errors, or the marker file does not appear
(the controller and target share a filesystem in this e2e), the click and
keystrokes are repeated with delivery_mode "foreground". Set
TNA_E2E_DELIVERY=foreground to skip the background attempt.
"""
import base64
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "controller"))
import tna  # noqa: E402


def act(c, tool: str, args: dict, mode: str) -> dict:
    """Call an input tool in `mode`; return the result (isError is checked by the caller)."""
    a = dict(args)
    if mode == "foreground":
        a["delivery_mode"] = "foreground"
    return c.call(tool, a)


def marker_ok(marker: str, wait: float) -> bool:
    end = time.time() + wait
    while time.time() < end:
        try:
            if Path(marker).read_text().strip() == "tna-e2e-ok":
                return True
        except OSError:
            pass
        time.sleep(0.25)
    return False


def drive(c, target: dict, x: int, y: int, marker: str, mode: str) -> str:
    """Click + type + Enter in one delivery mode. Returns '' on success, else the reason."""
    r = act(c, "click", dict(target, x=x, y=y), mode)
    if r.get("isError"):
        return "click failed: " + tna.text_of(r)[:300]
    print(f"[{mode}] click:", (tna.text_of(r) or "ok")[:200])
    time.sleep(0.5)
    # Ctrl+U clears anything a previous, partly delivered attempt left on the shell line.
    # Best effort: a failure here is not the thing under test.
    r = act(c, "press_key", dict(target, key="u", modifiers=["ctrl"]), mode)
    if r.get("isError"):
        print(f"[{mode}] ctrl+u ignored: " + tna.text_of(r)[:200])
    r = act(c, "type_text", dict(target, text=f"echo tna-e2e-ok > {marker}"), mode)
    if r.get("isError"):
        return "type_text failed: " + tna.text_of(r)[:300]
    print(f"[{mode}] type_text: ok")
    r = act(c, "press_key", dict(target, key="return"), mode)
    if r.get("isError"):
        return "press_key failed: " + tna.text_of(r)[:300]
    print(f"[{mode}] press_key: ok")
    if not marker_ok(marker, 5):
        return "marker file did not appear (input reported ok but did not reach the shell)"
    return ""


def main() -> int:
    name, marker = sys.argv[1], sys.argv[2]
    t = tna.get_target(name)
    c = tna.McpClient(tna.mcp_launch_argv(name, t), timeout=60)
    try:
        c.initialize()
        win = None
        text = ""
        for _ in range(15):
            res = c.call("list_windows", {})
            data = res.get("structuredContent") or {}
            text = tna.text_of(res)
            wins = data.get("windows") if isinstance(data, dict) else None
            for w in wins or []:
                if "xterm" in json.dumps(w).lower() or "e2e-term" in json.dumps(w):
                    win = w
                    break
            if win:
                break
            time.sleep(1)
        if win is None:
            print("list_windows output:", text[:1500])
            raise SystemExit("xterm window not found")
        pid = win.get("pid")
        wid = win.get("window_id") or win.get("id")
        print("window:", {k: win.get(k) for k in ("pid", "window_id", "id", "title", "app_name")})

        shot = c.call("get_desktop_state", {"max_image_dimension": 1280})
        imgs = [x for x in shot.get("content", []) if x.get("type") == "image"]
        assert imgs, "no screenshot image returned"
        raw = base64.b64decode(imgs[0]["data"])
        print("screenshot bytes:", len(raw), "mime:", imgs[0].get("mimeType"))
        if len(sys.argv) > 3:
            Path(sys.argv[3]).write_bytes(raw)

        b = win.get("bounds") or {}
        x = int(b.get("width", 200) / 2)
        y = int(b.get("height", 100) / 2)
        ws = c.call("get_window_state", {"pid": pid, "window_id": wid})
        assert not ws.get("isError"), "get_window_state failed: " + tna.text_of(ws)[:300]
        target = {"pid": pid, "window_id": wid}
        # Foreground is tried up to three times: right after startup the window
        # manager does not always hand focus over on the first activation.
        fg = ["foreground"] * 3
        modes = fg if os.environ.get("TNA_E2E_DELIVERY") == "foreground" else ["background"] + fg
        reasons = []
        for i, mode in enumerate(modes):
            if i:
                time.sleep(1)
            why = drive(c, target, x, y, marker, mode)
            if not why:
                print(f"GUI input delivered in {mode} mode")
                break
            print(f"[{mode}] {why}")
            reasons.append(f"{mode}: {why}")
        else:
            raise SystemExit("GUI input failed in every delivery mode: " + " | ".join(reasons))
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
