#!/usr/bin/env python3
"""End-to-end: drive a real desktop through `ssh ... cua-driver mcp`.

Usage: TNA_HOME=... python3 tests/e2e/gui_over_ssh.py <target-name> <marker-file>

On the target there must be an xterm window open (title e2e-term). The test:
  1. lists windows and finds the xterm
  2. takes a screenshot (get_desktop_state)
  3. clicks into the xterm
  4. types `echo tna-e2e-ok > <marker-file>` and presses Enter
The caller then checks that <marker-file> contains tna-e2e-ok.
"""
import base64
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "controller"))
import tna  # noqa: E402


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
        r = c.call("click", {"pid": pid, "window_id": wid, "x": x, "y": y})
        assert not r.get("isError"), "click failed: " + tna.text_of(r)[:300]
        print("click:", (tna.text_of(r) or "ok")[:200])
        time.sleep(0.5)
        r = c.call("type_text", {"pid": pid, "window_id": wid, "text": f"echo tna-e2e-ok > {marker}"})
        assert not r.get("isError"), "type_text failed: " + tna.text_of(r)[:300]
        print("type_text: ok")
        r = c.call("press_key", {"pid": pid, "window_id": wid, "key": "return"})
        assert not r.get("isError"), "press_key failed: " + tna.text_of(r)[:300]
        print("press_key: ok")
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
