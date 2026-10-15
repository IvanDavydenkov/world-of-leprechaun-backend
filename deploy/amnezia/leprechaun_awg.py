#!/usr/bin/env python3
"""Root-owned Ubuntu helper for the app-managed amnezia-awg2 container.
JSON request on stdin, JSON response on stdout. Never print configs to stderr.
"""
import base64
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

CONTAINER = "amnezia-awg2"
DIRECTORY = "/opt/amnezia/awg"
CONFIG = DIRECTORY + "/awg0.conf"
TABLE = DIRECTORY + "/clientsTable"
JOURNAL = Path("/var/lib/leprechaun-awg")
PARAMETERS = (
    "Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 "
    "HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout "
    "RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies"
).split()


def run(*args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=True, timeout=20).stdout


def public_key(value):
    if len(base64.b64decode(value, validate=True)) != 32:
        raise ValueError("invalid key")
    return value


def sections(text):
    parts = re.split(r"(?m)^[ \t]*\[Peer\][ \t]*\r?$", text)
    return parts[0], parts[1:]


def settings(text):
    result = {}
    for line in text.splitlines():
        # Amnezia keeps client-only I1-I5 parameters commented in the server config.
        line = line.strip()
        if re.match(r"^#\s*I[1-5]\s*=", line):
            line = line.lstrip("#").strip()
        elif line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def without_peer(text, key):
    interface, peers = sections(text)
    return interface + "".join("[Peer]" + peer for peer in peers
                               if settings(peer).get("PublicKey") != key)


def atomic_journal(path, value):
    # Journal contains private client material and is readable by root only.
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Backend:
    def __init__(self, journal=JOURNAL):
        self.journal = Path(journal)

    def read(self, path):
        return run("docker", "exec", CONTAINER, "cat", path)

    def write(self, path, value):
        temporary = path + ".leprechaun.tmp"
        run("docker", "exec", "-i", CONTAINER, "sh", "-c",
            'umask 077; cat > "$1"; chmod 600 "$1"; mv -f "$1" "$2"',
            "sh", temporary, path, data=value)

    def sync(self):
        # Preserve strip's exit status: process substitution can otherwise hide
        # a strip failure and accidentally sync an empty configuration.
        run("docker", "exec", CONTAINER, "bash", "-c",
            "set -e; umask 077; tmp=/opt/amnezia/awg/.leprechaun-sync.conf; "
            "trap 'rm -f \"$tmp\"' EXIT; "
            "awg-quick strip /opt/amnezia/awg/awg0.conf > \"$tmp\"; "
            "test -s \"$tmp\"; awg syncconf awg0 \"$tmp\"")

    def peers(self):
        return set(run("docker", "exec", CONTAINER, "awg", "show", "awg0", "peers").split())

    def keypair(self):
        private = run("docker", "exec", CONTAINER, "awg", "genkey").strip()
        public = run("docker", "exec", "-i", CONTAINER, "awg", "pubkey", data=private+"\n").strip()
        return private, public_key(public)

    def save(self, path, state):
        atomic_journal(path, state)

    def apply(self, state, remove=False):
        key = state["public"]
        original = self.read(CONFIG)
        if not remove:
            _, peers = sections(original)
            for peer in peers:
                values = settings(peer)
                if values.get("PublicKey") == key:
                    continue
                for allowed in values.get("AllowedIPs", "").split(","):
                    if allowed.strip() and ipaddress.ip_address(state["address"]) in ipaddress.ip_network(allowed.strip(), strict=False):
                        raise ValueError("reserved address already in use")
        updated = without_peer(original, key)
        if not remove:
            updated = updated.rstrip()+"\n\n[Peer]\nPublicKey = "+key+"\nPresharedKey = "+state["psk"]+"\nAllowedIPs = "+state["address"]+"/32\n"
        table_text = self.read(TABLE)
        table = json.loads(table_text)
        if not isinstance(table, list):
            raise ValueError("unsupported clientsTable")
        table = [entry for entry in table if entry.get("clientId") != key]
        if not remove:
            table.append({"clientId": key, "userData": {
                "clientName": state["name"],
                "creationDate": state["created"],
                "allowedIps": state["address"]+"/32",
            }})
        # Detect modifications observed before our writes; the Amnezia app must
        # not perform management concurrently (it does not share our host lock).
        if self.read(CONFIG) != original or self.read(TABLE) != table_text:
            raise ValueError("concurrent external management")
        self.write(CONFIG, updated)
        self.sync()
        if (key in self.peers()) == remove:
            raise ValueError("runtime verification failed")
        self.write(TABLE, json.dumps(table, ensure_ascii=False))

    def plan(self, request):
        original = self.read(CONFIG)
        interface, peer_blocks = sections(original)
        values = settings(interface)
        # Unknown protocol version fails before generating keys or changing peers.
        if not all(values.get(key) for key in ("Address", "ListenPort", "Jc", "S1", "S2", "H1", "H2", "H3", "H4")):
            raise ValueError("unsupported server config")
        network = ipaddress.IPv4Interface(values["Address"].split(",")[0].strip())
        used = [ipaddress.ip_network(allowed.strip(), strict=False)
                for peer in peer_blocks
                for allowed in settings(peer).get("AllowedIPs", "").split(",")
                if allowed.strip()]
        # A crash after journaling but before updating awg0.conf still reserves its IP.
        for path in self.journal.glob("*.json"):
            previous = json.loads(path.read_text())
            if previous.get("state") != "revoked":
                used.append(ipaddress.ip_network(previous["address"]+"/32"))
        address = next((str(ip) for ip in network.network.hosts()
                        if ip != network.ip and not any(ip in subnet for subnet in used)), None)
        if address is None:
            raise ValueError("subnet exhausted")
        private, public = self.keypair()
        psk = public_key(self.read(DIRECTORY+"/wireguard_psk.key").strip())
        server_public = public_key(self.read(DIRECTORY+"/wireguard_server_public_key.key").strip())
        endpoint = request["endpoint"]
        # Endpoint is supplied explicitly: Docker's UDP mapping may differ from ListenPort.
        if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]{1,5}", endpoint):
            raise ValueError("invalid public endpoint")
        port = int(endpoint.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise ValueError("invalid public port")
        lines = ["[Interface]", "PrivateKey = "+private, "Address = "+address+"/32",
                 "DNS = 1.1.1.1, 1.0.0.1", "MTU = 1280"]
        for key in PARAMETERS:
            if values.get(key):
                lines.append(key+" = "+values[key])
        lines += ["", "[Peer]", "PublicKey = "+server_public, "PresharedKey = "+psk,
                  "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = "+endpoint,
                  "PersistentKeepalive = 25", ""]
        return {"state": "planned", "owner": request["owner"], "name": request["name"],
                "public": public, "psk": psk, "address": address,
                "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "file": "\n".join(lines), "endpoint": endpoint}

    def handle(self, request):
        generation = request.get("generation", "")
        if not isinstance(generation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", generation):
            raise ValueError("invalid generation")
        path = self.journal/(generation+".json")
        state = json.loads(path.read_text()) if path.exists() else None
        if request.get("action") == "create":
            if not all(isinstance(request.get(key), str) and 0 < len(request[key]) <= 256
                       for key in ("owner", "name", "endpoint")):
                raise ValueError("invalid issuance")
            if state is None:
                state = self.plan(request)
                self.save(path, state)  # Durable private keys before the first host mutation.
            if any(state.get(key) != request[key] for key in ("owner", "name", "endpoint")):
                raise ValueError("generation parameter mismatch")
            if state["state"] in ("revoking", "revoked"):
                raise ValueError("generation revoked")
            if state["state"] == "planned":
                self.apply(state)
                state["state"] = "active"
                self.save(path, state)
            elif state["public"] not in self.peers():
                # Never silently recreate a peer revoked outside this backend.
                raise ValueError("active generation missing from host")
            return {"remote_id": state["public"], "file": state["file"]}
        if request.get("action") == "revoke":
            if state is None or state["public"] != request.get("remote_id"):
                raise ValueError("unknown generation")
            state["state"] = "revoking"
            self.save(path, state)
            self.apply(state, remove=True)
            state["state"] = "revoked"
            state.pop("file", None)
            state.pop("psk", None)
            self.save(path, state)
            return {"revoked": True}
        raise ValueError("unknown action")


def main():
    import fcntl  # Ubuntu only; core functions can be unit tested on other platforms.
    if os.geteuid() != 0:
        raise ValueError("root required")
    os.umask(0o077)
    JOURNAL.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(JOURNAL, 0o700)
    with open(JOURNAL/".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        raw = sys.stdin.read(16385)
        if len(raw) > 16384:
            raise ValueError("request too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("invalid request")
        if "v3.1.20260812" not in run("docker", "exec", CONTAINER, "awg", "--version"):
            raise ValueError("unsupported tools version")
        print(json.dumps(Backend().handle(request)))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Neither exception strings nor subprocess stdout/stderr may expose keys.
        print('{"error":"awg_operation_unconfirmed"}', file=sys.stderr)
        sys.exit(1)
