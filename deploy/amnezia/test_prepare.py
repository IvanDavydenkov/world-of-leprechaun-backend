"""Preparation tests use an isolated fake host filesystem and Docker responses."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "services/vpn-configs/internal/infrastructure/amnezia/assets/prepare.py"

class PrepareTests(unittest.TestCase):
    def run_prepare(self, action="install", old=None, health=True, allowed=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os_release = root / "os-release"
            os_release.write_text("ID=ubuntu\n")
            binary_dir = root / "libexec"
            binary_dir.mkdir()
            target = binary_dir / "leprechaun-awg"
            if old is not None:
                target.write_bytes(old)
            fake_fcntl = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4, flock=lambda *args: None)
            with patch.dict(sys.modules, {"fcntl": fake_fcntl}):
                spec = importlib.util.spec_from_file_location("test_preparer", SCRIPT)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            def path(value):
                return {"/etc/os-release": os_release, "/var/lib/leprechaun-awg": root / "journal", "/usr/local/libexec": binary_dir}.get(str(value), Path(value))
            calls = []
            def run(*args, data=None):
                calls.append(args)
                if args[:3] == ("docker", "ps", "--format"):
                    return "amnezia-awg2\n"
                if "--version" in args:
                    return "amneziawg-tools v3.1.20260812"
                if "interfaces" in args:
                    return "awg0"
                if "listen-port" in args:
                    return "48892"
                if args[:2] == ("docker", "inspect"):
                    return json.dumps({"48892/udp": [{"HostIp": "0.0.0.0", "HostPort": "48892"}]})
                if "test" in args:
                    return ""
                if args == (str(target),):
                    if not health:
                        raise RuntimeError("private-data-must-not-leak")
                    return '{"healthy":true,"version":"2.0.0"}'
                raise AssertionError("Unexpected command")
            helper = b'#!/usr/bin/env python3\nHELPER_VERSION="2.0.0"\n'
            payload = {"action": action, "selection": {"candidate_id": hashlib.sha256(b"amnezia-awg2\0awg0").hexdigest()[:16], "udp_port": 48892}, "helper": base64.b64encode(helper).decode(), "sha256": hashlib.sha256(helper).hexdigest(), "allowed_hashes": allowed or []}
            output = io.StringIO()
            with patch.object(module, "Path", side_effect=path), patch.object(module, "run", side_effect=run), patch.object(module.os, "geteuid", return_value=0, create=True), patch.object(module.os, "chown", create=True), patch.object(module.sys, "stdin", io.StringIO(json.dumps(payload))), contextlib.redirect_stdout(output):
                try:
                    module.main()
                except SystemExit as exc:
                    self.assertEqual(exc.code, 0)
            result = json.loads(output.getvalue())
            installed = target.read_bytes() if target.exists() else None
            for args in calls:
                self.assertNotIn("syncconf", args)
                self.assertNotIn("setconf", args)
            self.assertNotIn("private-data", output.getvalue())
            return result, installed, helper

    def test_discovery_does_not_install_or_change_peer(self):
        result, installed, _ = self.run_prepare(action="discover")
        self.assertEqual(result["candidates"][0]["published_udp_ports"], [48892])
        self.assertIsNone(installed)

    def test_install_and_health(self):
        result, installed, helper = self.run_prepare()
        self.assertEqual(installed, helper)
        self.assertEqual(result["helper_hash"], hashlib.sha256(helper).hexdigest())

    def test_unknown_helper_is_not_overwritten(self):
        result, installed, _ = self.run_prepare(old=b"unknown-binary")
        self.assertEqual(result["error"], "helper_conflict")
        self.assertEqual(installed, b"unknown-binary")

    def test_failed_health_restores_approved_previous_helper(self):
        old = b"previous-approved-helper"
        result, installed, _ = self.run_prepare(old=old, allowed=[hashlib.sha256(old).hexdigest()], health=False)
        self.assertEqual(result["error"], "helper_verify_failed")
        self.assertEqual(installed, old)

if __name__ == "__main__":
    unittest.main()