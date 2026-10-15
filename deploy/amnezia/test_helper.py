import base64
import json
from pathlib import Path
import tempfile
import unittest

from leprechaun_awg import Backend, CONFIG, TABLE, DIRECTORY, sections, settings

def key(byte):
    return base64.b64encode(bytes([byte])*32).decode()

SERVER = """[Interface]
PrivateKey = server-secret
Address = 10.8.1.0/24
ListenPort = 51820
Jc = 4
Jmin = 40
Jmax = 70
S1 = 100
S2 = 100
S3 = 100
S4 = 100
H1 = 1-10
H2 = 11-20
H3 = 21-30
H4 = 31-40
HeaderProtectionKey = protected
# I1 = <b 0x012345>
"""

class FakeBackend(Backend):
    def __init__(self, path):
        super().__init__(path)
        self.files = {CONFIG: SERVER, TABLE: "[]",
                      DIRECTORY+"/wireguard_psk.key": key(2),
                      DIRECTORY+"/wireguard_server_public_key.key": key(3)}
        self.runtime = set()
        self.keys = 0
        self.fail_sync = False
        self.fail_active_save = False

    def read(self, path):
        return self.files[path]

    def write(self, path, value):
        self.files[path] = value

    def sync(self):
        if self.fail_sync:
            raise RuntimeError("uncertain sync")
        self.runtime = {settings(peer)["PublicKey"] for peer in sections(self.files[CONFIG])[1]}

    def peers(self):
        return self.runtime

    def keypair(self):
        self.keys += 1
        return key(100+self.keys), key(10+self.keys)

    def save(self, path, state):
        if self.fail_active_save and state["state"] == "active":
            raise RuntimeError("crash after host apply")
        # Persistence algorithm is POSIX-specific; these tests exercise lifecycle
        # on Windows too without pretending to test fsync or permissions.
        path.write_text(json.dumps(state), encoding="utf-8")


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.backend = FakeBackend(self.temp.name)

    def request(self, generation="gen1"):
        return {"action": "create", "generation": generation,
                "owner": "alice", "name": "Phone", "endpoint": "vpn.example.org:51820"}

    def test_retries_return_same_file_and_revoked_generation_never_recreates(self):
        first = self.backend.handle(self.request())
        repeated = self.backend.handle(self.request())
        self.assertEqual(first, repeated)
        self.assertIn("HeaderProtectionKey = protected", first["file"])
        self.assertIn("I1 = <b 0x012345>", first["file"])
        self.assertNotIn("server-secret", first["file"])
        self.assertEqual(self.backend.keys, 1)
        self.assertEqual(len(json.loads(self.backend.files[TABLE])), 1)
        revoke = {"action": "revoke", "generation": "gen1", "remote_id": first["remote_id"]}
        self.assertTrue(self.backend.handle(revoke)["revoked"])
        self.assertTrue(self.backend.handle(revoke)["revoked"])
        self.assertNotIn(first["remote_id"], self.backend.runtime)
        with self.assertRaises(ValueError):
            self.backend.handle(self.request())
        second = self.backend.handle(self.request("gen2"))
        self.assertNotEqual(second["remote_id"], first["remote_id"])
        self.assertNotEqual(second["file"], first["file"])

    def test_crash_after_apply_preserves_keys_and_does_not_duplicate_peer(self):
        self.backend.fail_active_save = True
        with self.assertRaises(RuntimeError):
            self.backend.handle(self.request())
        self.backend.fail_active_save = False
        result = self.backend.handle(self.request())
        self.assertIn(result["remote_id"], self.backend.runtime)
        self.assertEqual(self.backend.keys, 1)
        self.assertEqual(len(sections(self.backend.files[CONFIG])[1]), 1)

    def test_planned_issuance_reserves_address(self):
        planned = self.backend.plan(self.request())
        self.backend.save(Path(self.temp.name)/"gen1.json", planned)
        other = self.backend.plan(self.request("gen2"))
        self.assertNotEqual(planned["address"], other["address"])

    def test_sync_failure_leaves_recoverable_intent(self):
        self.backend.fail_sync = True
        with self.assertRaises(RuntimeError):
            self.backend.handle(self.request())
        stored = json.loads((Path(self.temp.name)/"gen1.json").read_text())
        self.assertEqual(stored["state"], "planned")
        self.backend.fail_sync = False
        self.backend.handle(self.request())
        self.assertEqual(self.backend.keys, 1)

    def test_existing_unmanaged_peers_survive(self):
        unmanaged = key(50)
        self.backend.files[CONFIG] += "\n[Peer]\nPublicKey = "+unmanaged+"\nAllowedIPs = 10.8.1.1/32\n"
        self.backend.files[TABLE] = json.dumps([{"clientId":unmanaged,"userData":{"clientName":"Existing"}}])
        result = self.backend.handle(self.request())
        self.assertIn("Address = 10.8.1.2/32",result["file"])
        self.backend.handle({"action":"revoke","generation":"gen1","remote_id":result["remote_id"]})
        self.assertIn(unmanaged,self.backend.runtime)
        self.assertEqual(json.loads(self.backend.files[TABLE])[0]["clientId"],unmanaged)

    def test_input_cannot_escape_journal(self):
        for generation in ["../bad", "a/b", "a;touch x", ""]:
            request = self.request(generation)
            with self.assertRaises(ValueError):
                self.backend.handle(request)
        self.assertEqual(self.backend.keys,0)


if __name__ == "__main__":
    unittest.main()
