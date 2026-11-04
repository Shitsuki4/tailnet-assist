"""Unit tests for controller/tna.py (stdlib unittest; runs on Windows, macOS, Linux)."""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "controller"))
import tna  # noqa: E402

HOSTKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL"


def info(**kw):
    d = {"v": 1, "name": "desk-pc", "os": "linux", "user": "alice", "host": "100.101.102.103",
         "ip": "100.101.102.103", "hostkey": HOSTKEY, "shell": "sh",
         "cua": "/home/alice/.local/bin/cua-driver", "socket": "/home/alice/.cache/cua-driver/cua-driver.sock",
         "expires": "202611101342Z", "keyid": "deadbeef", "created": "2026-11-03T13:42:00Z"}
    d.update(kw)
    return d


class InfoTests(unittest.TestCase):
    def test_roundtrip(self):
        line = tna.encode_info(info())
        self.assertTrue(line.startswith("TNA1:"))
        self.assertEqual(tna.decode_info(line)["host"], "100.101.102.103")

    def test_rejects_newline_in_host(self):
        with self.assertRaises(tna.TnaError):
            tna.decode_info(tna.encode_info(info(host="1.2.3.4\nProxyCommand evil")))

    def test_rejects_bad_hostkey(self):
        with self.assertRaises(tna.TnaError):
            tna.decode_info(tna.encode_info(info(hostkey="ssh-ed25519 AAAA\n@cert-authority * x")))

    def test_rejects_quote_in_windows_path(self):
        with self.assertRaises(tna.TnaError):
            tna.decode_info(tna.encode_info(info(os="windows", shell="cmd", socket=r"\\.\pipe\cua-driver",
                                                 cua='C:\\x" & calc & "\\cua-driver.exe')))

    def test_rejects_bad_pipe(self):
        with self.assertRaises(tna.TnaError):
            tna.decode_info(tna.encode_info(info(os="windows", shell="cmd", cua=r"C:\a\cua-driver.exe",
                                                 socket=r"\\server\pipe\x")))

    def test_name_normalised(self):
        self.assertEqual(tna.decode_info(tna.encode_info(info(name="DESKTOP 01_X")))["name"], "desktop-01-x")

    def test_user_with_space_and_domain(self):
        i = tna.decode_info(tna.encode_info(info(os="windows", shell="cmd", user="CORP\\Alice Wang",
                                               cua=r"C:\Users\Alice Wang\AppData\Local\Programs\Cua\cua-driver\bin\cua-driver.exe",
                                               socket=r"\\.\pipe\cua-driver")))
        self.assertEqual(i["user"], "CORP\\Alice Wang")

    def test_bad_port(self):
        with self.assertRaises(tna.TnaError):
            tna.decode_info(tna.encode_info(info(port="22; rm")))


class CommandTests(unittest.TestCase):
    def test_linux_mcp(self):
        t = tna.validate_info(info())
        self.assertEqual(tna.remote_mcp_command(t),
                         "/home/alice/.local/bin/cua-driver mcp --socket /home/alice/.cache/cua-driver/cua-driver.sock")

    def test_macos_mcp_has_no_socket(self):
        t = tna.validate_info(info(os="macos", cua="/Users/a/.local/bin/cua-driver", socket=None))
        self.assertEqual(tna.remote_mcp_command(t), "/Users/a/.local/bin/cua-driver mcp")

    def test_windows_cmd(self):
        t = tna.validate_info(info(os="windows", shell="cmd", user="alice",
                                   cua=r"C:\Users\Alice Wang\AppData\Local\Programs\Cua\cua-driver\bin\cua-driver.exe",
                                   socket=r"\\.\pipe\cua-driver"))
        cmd = tna.remote_mcp_command(t)
        self.assertEqual(cmd, r'cd /d "C:\Users\Alice Wang\AppData\Local\Programs\Cua\cua-driver\bin" && cua-driver.exe mcp --socket \\.\pipe\cua-driver')
        self.assertNotEqual(cmd[0], '"')

    def test_windows_powershell(self):
        t = tna.validate_info(info(os="windows", shell="powershell", user="alice",
                                   cua=r"C:\Users\a\AppData\Local\Programs\Cua\cua-driver\bin\cua-driver.exe",
                                   socket=r"\\.\pipe\cua-driver"))
        self.assertEqual(tna.remote_mcp_command(t),
                         r"& 'C:\Users\a\AppData\Local\Programs\Cua\cua-driver\bin\cua-driver.exe' mcp --socket '\\.\pipe\cua-driver'")

    def test_no_cua(self):
        with self.assertRaises(tna.TnaError):
            tna.remote_mcp_command(tna.validate_info(info(cua=None)))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["TNA_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("TNA_HOME", None)
        self.tmp.cleanup()

    def test_ssh_config_and_known_hosts(self):
        t = tna.validate_info(info(port=2222))
        tna.save_targets({"desk-pc": t})
        cfg = tna.ssh_config_path().read_text()
        self.assertIn("Host tna-desk-pc", cfg)
        self.assertIn("HostKeyAlias tna-desk-pc", cfg)
        self.assertIn("StrictHostKeyChecking yes", cfg)
        self.assertIn("IdentitiesOnly yes", cfg)
        self.assertIn("Port 2222", cfg)
        self.assertIn("ClearAllForwardings yes", cfg)
        self.assertEqual(tna.known_hosts_path().read_text(), f"tna-desk-pc {HOSTKEY}\n")

    def test_codex_toml(self):
        t = tna.validate_info(info())
        tna.save_targets({"desk-pc": t})
        text = tna.codex_toml("desk-pc", t)
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11")
        d = tomllib.loads(text)["mcp_servers"]["cua-desk-pc"]
        self.assertEqual(d["command"], "ssh")
        self.assertEqual(d["args"][:3], ["-F", str(tna.ssh_config_path()), "-T"])
        self.assertEqual(d["args"][3], "tna-desk-pc")
        self.assertTrue(d["args"][4].endswith("cua-driver.sock"))
        self.assertEqual(d["startup_timeout_sec"], 45)

    def test_codex_cli(self):
        t = tna.validate_info(info())
        argv = tna.codex_cli("desk-pc", t)
        self.assertEqual(argv[:5], ["codex", "mcp", "add", "cua-desk-pc", "--"])
        self.assertEqual(argv[5], "ssh")


class InviteTests(unittest.TestCase):
    PUB = HOSTKEY + " tna-operator:me@pc"

    def test_windows_invite(self):
        s = tna.invite_command("windows", self.PUB, "7d", "me-pc", "Shitsuki4/tailnet-assist", "v0.1.0", "ab" * 32)
        self.assertIn("https://raw.githubusercontent.com/Shitsuki4/tailnet-assist/v0.1.0/target/windows/tna-target.ps1", s)
        self.assertIn("Get-FileHash", s)
        self.assertIn("'" + ("AB" * 32) + "'", s)
        self.assertIn("-OperatorKey '" + self.PUB + "'", s)
        self.assertNotIn("iex", s.lower().replace("-executionpolicy", ""))

    def test_unix_invite(self):
        s = tna.invite_command("linux", self.PUB, "8h", "me-pc", "Shitsuki4/tailnet-assist", "v0.1.0", "cd" * 32)
        self.assertIn("sha256sum -c -", s)
        self.assertIn("shasum -a 256 -c -", s)
        self.assertIn("--expires 8h", s)
        self.assertNotIn("| bash", s)

    def test_script_hash_matches_file(self):
        for os_name in ("windows", "linux"):
            p = tna.target_script(os_name)
            self.assertTrue(p.exists(), p)
            self.assertEqual(len(tna.sha256_file(p)), 64)


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_shape(self):
        fp = tna.key_fingerprint(HOSTKEY)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertEqual(len(fp), 7 + 43)


class Utf8OutputTests(unittest.TestCase):
    """Chinese output must not crash on a non-UTF-8 stream (Windows CI / English console pipes)."""

    def test_force_utf8_on_cp1252_stream(self):
        buf = io.BytesIO()
        fake = io.TextIOWrapper(buf, encoding="cp1252")
        old = sys.stdout
        sys.stdout = fake
        try:
            tna.force_utf8_stdio()
            print("已生成专用密钥")
            sys.stdout.flush()
        finally:
            sys.stdout = old
        self.assertEqual(buf.getvalue().decode("utf-8").strip(), "已生成专用密钥")

    @unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
    def test_init_with_cp1252_pipe(self):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, TNA_HOME=d, PYTHONIOENCODING="cp1252")
            env.pop("PYTHONUTF8", None)
            r = subprocess.run([sys.executable, str(Path(tna.__file__)), "init"], env=env,
                               capture_output=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
            out = r.stdout.decode("utf-8")
            self.assertIn("已生成专用密钥", out)
            self.assertIn("SHA256:", out)


if __name__ == "__main__":
    unittest.main()
