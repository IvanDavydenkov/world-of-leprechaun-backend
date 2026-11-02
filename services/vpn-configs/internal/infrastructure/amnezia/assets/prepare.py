"""Trusted preparation program. Input and output are bounded JSON; never emit subprocess errors."""
import base64, fcntl, hashlib, json, os, re, subprocess, sys, tempfile, time
from pathlib import Path

def fail(code):
    print(json.dumps({"error": code})); sys.exit(0)
def run(*args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=True, timeout=20).stdout

def main():
    request=json.loads(sys.stdin.read(1024*1024))
    if os.geteuid()!=0: fail("sudo_required")
    if "ID=ubuntu" not in Path("/etc/os-release").read_text(): fail("unsupported_os")
    try: names=run("docker","ps","--format","{{.Names}}").split()
    except Exception: fail("docker_missing")
    candidates=[]
    unsupported=False
    for container in names:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",container): continue
        try:
            version=run("docker","exec",container,"awg","--version")
            if "v3.1.20260812" not in version:
                unsupported=True
                continue
            interfaces=run("docker","exec",container,"awg","show","interfaces").split()
            mapping=json.loads(run("docker","inspect","--format","{{json .NetworkSettings.Ports}}",container))
            for interface in interfaces:
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}",interface): continue
                # Read only listen port, never dump interface or client configuration.
                listen=int(run("docker","exec",container,"awg","show",interface,"listen-port").strip())
                ports=sorted({int(x["HostPort"]) for x in (mapping or {}).get(str(listen)+"/udp",[]) if x.get("HostIp") in ("0.0.0.0","::","")})
                if not ports: continue
                run("docker","exec",container,"test","-f","/opt/amnezia/awg/"+interface+".conf")
                cid=hashlib.sha256((container+"\0"+interface).encode()).hexdigest()[:16]
                candidates.append({"candidate_id":cid,"container":container,"interface":interface,"published_udp_ports":ports})
        except Exception: continue
    if not candidates: fail("awg_unsupported" if unsupported else "awg_not_found")
    if request.get("action")=="discover":
        print(json.dumps({"candidates":candidates}));return
    selection=request["selection"]
    candidate=next((c for c in candidates if c["candidate_id"]==selection["candidate_id"] and selection["udp_port"] in c["published_udp_ports"]),None)
    if candidate is None: fail("discovery_changed")
    data=base64.b64decode(request["helper"],validate=True)
    sha=hashlib.sha256(data).hexdigest()
    if sha!=request["sha256"]: fail("helper_install_failed")
    compile(data,"leprechaun-awg","exec")
    root=Path("/var/lib/leprechaun-awg");root.mkdir(mode=0o700,exist_ok=True);root.chmod(0o700)
    with open(root/".lock","a") as lock:
        deadline=time.monotonic()+25
        while True:
            try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline: fail("helper_install_failed")
                time.sleep(.1)
        folder=Path("/usr/local/libexec");folder.mkdir(mode=0o755,exist_ok=True)
        target=folder/"leprechaun-awg"
        if target.is_symlink(): fail("helper_conflict")
        old=target.read_bytes() if target.exists() else None
        if old is not None and hashlib.sha256(old).hexdigest() not in request["allowed_hashes"]+[sha]: fail("helper_conflict")
        if old!=data:
            fd,tmp=tempfile.mkstemp(prefix=".leprechaun-",dir=folder)
            try:
                with os.fdopen(fd,"wb") as stream: stream.write(data);stream.flush();os.fsync(stream.fileno())
                os.chmod(tmp,0o755);os.chown(tmp,0,0);os.replace(tmp,target)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
        # The health command uses the same host lock; release only after atomic install.
        fcntl.flock(lock,fcntl.LOCK_UN)
    health={"action":"health","container":candidate["container"],"interface":candidate["interface"]}
    try:
        result=json.loads(run(str(target),data=json.dumps(health)))
        if result.get("healthy") is not True: raise ValueError()
    except Exception:
        # Restore under the host lock, never overwrite a subsequent installer.
        with open(root/".lock","a") as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest()==sha:
                if old is None: target.unlink()
                else:
                    fd,tmp=tempfile.mkstemp(prefix=".rollback-",dir=folder)
                    with os.fdopen(fd,"wb") as stream: stream.write(old);stream.flush();os.fsync(stream.fileno())
                    os.chmod(tmp,0o755);os.replace(tmp,target)
        fail("helper_verify_failed")
    print(json.dumps({"candidate":candidate,"helper_version":result["version"],"helper_hash":sha}))

if __name__=="__main__":
    try: main()
    except Exception: fail("helper_install_failed")