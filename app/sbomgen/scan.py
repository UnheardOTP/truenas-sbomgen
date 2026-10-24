"""One scan run: SBOMs for the TrueNAS host and each container image, then Grype, KEV, diff, uploads."""
import fcntl
import http.client
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import report
from .config import Config

log = logging.getLogger("sbomgen")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HOST_EXCLUDES = ["./mnt/**", "./proc/**", "./sys/**", "./dev/**", "./run/**", "./tmp/**",
                 "./var/lib/docker/**", "./var/lib/incus/**", "./var/lib/kubelet/**", "./var/log/**"]


# --- status file shown on the web page ------------------------------------------------
def write_status(cfg: Config, **fields) -> None:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    tmp = cfg.data_dir / "status.json.tmp"
    tmp.write_text(json.dumps(fields))
    tmp.replace(cfg.data_dir / "status.json")


def read_status(cfg: Config) -> dict:
    try:
        return json.loads((cfg.data_dir / "status.json").read_text())
    except (OSError, ValueError):
        return {}


# --- Docker API (through the socket proxy, read-only) ----------------------------------
class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=60)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path)


def docker_get(cfg: Config, path: str):
    host = cfg.docker_host or "unix:///var/run/docker.sock"
    if host.startswith("unix://"):
        conn = _UnixConn(host[len("unix://"):])
    else:
        conn = http.client.HTTPConnection(re.sub(r"^(tcp|http)://", "", host), timeout=60)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    if resp.status != 200:
        raise RuntimeError(f"Docker API {path} returned {resp.status}")
    return json.loads(body)


# --- TrueNAS platform SBOM (release + running kernel) -----------------------------------
def platform_sbom(cfg: Config) -> dict:
    """Syft gets the Debian packages; this records what Syft can't name: the TrueNAS release
    and the running kernel (containers share the host kernel, so uname is the host's)."""
    version = "unknown"
    vfile = cfg.host_root / "etc" / "version"
    if vfile.is_file() and vfile.read_text().strip():
        version = vfile.read_text().split()[0]
    kernel = os.uname().release
    kver = kernel.split("-")[0]
    hostname = (cfg.host_root / "etc" / "hostname").read_text().strip() \
        if (cfg.host_root / "etc" / "hostname").is_file() else "truenas"
    comps = [
        {"type": "operating-system", "bom-ref": f"truenas@{version}", "name": "truenas", "version": version,
         "supplier": {"name": "iXsystems"}, "purl": f"pkg:generic/ixsystems/truenas@{version}",
         "cpe": f"cpe:2.3:o:ixsystems:truenas:{version}:*:*:*:*:*:*:*"},
        {"type": "operating-system", "bom-ref": f"linux-kernel@{kernel}", "name": "linux-kernel", "version": kver,
         "purl": f"pkg:generic/kernel.org/linux@{kver}",
         "cpe": f"cpe:2.3:o:linux:linux_kernel:{kver}:*:*:*:*:*:*:*",
         "properties": [{"name": "truenas:kernel-release", "value": kernel}]},
    ]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "truenas-sbomgen"}]},
            "component": {"type": "device", "bom-ref": f"host:{hostname}", "name": hostname, "version": version,
                          "description": f"TrueNAS {version}, kernel {kernel}"},
        },
        "components": comps,
        "dependencies": [{"ref": f"host:{hostname}", "dependsOn": [c["bom-ref"] for c in comps]}],
    }


# --- helpers ----------------------------------------------------------------------------
def safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "unnamed"


def run(cmd: list[str], logf, timeout: int = 3600) -> bool:
    logf.write(f"$ {' '.join(cmd)}\n")
    logf.flush()
    try:
        return subprocess.run(cmd, stdout=logf, stderr=logf, timeout=timeout).returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        logf.write(f"{e}\n")
        return False


def tool_version(tool: str) -> str:
    try:
        out = subprocess.run([tool, "version"], capture_output=True, text=True, timeout=20).stdout
        return next((l.split()[1] for l in out.splitlines() if l.startswith("Version:")), "unknown")
    except OSError:
        return "not installed"


def post_json(url: str, payload: dict, headers: dict | None = None) -> int:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status


def dt_upload(cfg: Config, project: str, sbom: Path) -> int:
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in (("autoCreate", "true"), ("projectName", project), ("projectVersion", "current")):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="bom"; filename="{sbom.name}"\r\n'
                 f"Content-Type: application/json\r\n\r\n".encode() + sbom.read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(f"{cfg.dt_url}/api/v1/bom", data=b"".join(parts), method="POST",
                                 headers={"X-Api-Key": cfg.dt_api_key,
                                          "Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status


def notify(cfg: Config, title: str, msg: str) -> None:
    if not cfg.webhook_url or cfg.notify == "off":
        return
    text = f"**{title}**\n{msg}"
    payload = {"content": text} if "discord.com/api/webhooks" in cfg.webhook_url else {"text": text}
    try:
        post_json(cfg.webhook_url, payload)
    except Exception as e:  # never fail a scan over a notification
        log.warning("webhook failed: %s", e)


# --- the scan ---------------------------------------------------------------------------
def is_running(cfg: Config) -> bool:
    """True while any process holds the scan lock (web-triggered, scheduled or `docker exec`)."""
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    with open(cfg.data_dir / ".scan.lock", "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(f, fcntl.LOCK_UN)
        return False


def scan(cfg: Config) -> None:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    with open(cfg.data_dir / ".scan.lock", "a") as lockf:
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log.info("scan already running")
            return
        try:
            _scan(cfg)
        except Exception as e:
            log.exception("scan crashed")
            write_status(cfg, state="failed", error=str(e), at=datetime.now().isoformat(timespec="seconds"))
            notify(cfg, "TrueNAS SBOM scan failed", str(e))


def _scan(cfg: Config) -> None:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = cfg.runs_dir / stamp
    (run_dir / "sbom").mkdir(parents=True)
    (run_dir / "vulns").mkdir()
    tmp = cfg.data_dir / "tmp"           # image exports are large; keep them on the dataset
    tmp.mkdir(exist_ok=True)
    os.environ["TMPDIR"] = str(tmp)
    os.environ["GRYPE_DB_CACHE_DIR"] = str(cfg.data_dir / "grype-db")
    write_status(cfg, state="running", run=stamp)
    log.info("scan %s started", stamp)
    errors: list[str] = []

    with open(run_dir / "scan.log", "w") as logf:
        # 1. Host: TrueNAS release + kernel, then everything Syft finds on the root filesystem
        if cfg.scan_host:
            (run_dir / "sbom" / "truenas-platform.cdx.json").write_text(json.dumps(platform_sbom(cfg), indent=1))
            if not cfg.host_root.is_dir() or not (cfg.host_root / "etc" / "os-release").exists():
                errors.append(f"host root not mounted at {cfg.host_root}")
            else:
                cmd = ["syft", "scan", f"dir:{cfg.host_root}", "-q", "--source-name", "truenas-host",
                       "-o", f"cyclonedx-json={run_dir / 'sbom' / 'truenas-host.cdx.json'}"]
                for ex in HOST_EXCLUDES:
                    cmd += ["--exclude", ex]
                if not run(cmd, logf):
                    errors.append("host filesystem SBOM")

        # 2. Containers: one SBOM per distinct image, named after its first container
        if cfg.scan_containers:
            try:
                seen: dict[str, str] = {}
                for c in docker_get(cfg, "/containers/json?all=1"):
                    name = (c.get("Names") or ["/" + c["Id"][:12]])[0].lstrip("/")
                    if c["ImageID"] in seen:
                        logf.write(f"{name} shares an image with {seen[c['ImageID']]}, skipped\n")
                        continue
                    seen[c["ImageID"]] = name
                    out = run_dir / "sbom" / f"container-{safe(name)}.cdx.json"
                    if not run(["syft", "scan", f"docker:{c['ImageID']}", "-q", "--source-name", name,
                                "--source-version", c.get("Image", ""), "-o", f"cyclonedx-json={out}"], logf):
                        errors.append(f"container {name}")
                logf.write(f"{len(seen)} container image(s)\n")
            except Exception as e:
                errors.append(f"container listing: {e}")
                logf.write(f"container listing failed: {e}\n")

        # 3. Vulnerabilities
        stats = None
        if cfg.vuln_scan:
            if not run(["grype", "db", "update", "-q"], logf, timeout=1800):
                logf.write("grype db update failed; using cached database\n")
            try:
                with urllib.request.urlopen(KEV_URL, timeout=60) as r:
                    (cfg.data_dir / "kev.json").write_bytes(r.read())
            except Exception as e:
                logf.write(f"KEV download failed, using cached copy: {e}\n")
            for sbom in sorted((run_dir / "sbom").glob("*.cdx.json")):
                if not run(["grype", f"sbom:{sbom}", "-q", "-o",
                            f"json={run_dir / 'vulns' / sbom.name.replace('.cdx.json', '.json')}"], logf):
                    errors.append(f"grype {sbom.name}")
            prev = cfg.latest.resolve() if cfg.latest.is_symlink() and cfg.latest.resolve().is_dir() else None
            stats = report.summarize(run_dir, report.load_kev(cfg.data_dir / "kev.json"), prev)
            logf.write(f"summary: {stats}\n")

        # 4. Dependency-Track
        if cfg.dt_url and cfg.dt_api_key:
            for sbom in sorted((run_dir / "sbom").glob("*.cdx.json")):
                project = sbom.name.replace(".cdx.json", "")
                try:
                    dt_upload(cfg, project, sbom)
                    logf.write(f"uploaded {project} to Dependency-Track\n")
                except Exception as e:
                    errors.append(f"Dependency-Track {project}")
                    logf.write(f"Dependency-Track upload of {project} failed: {e}\n")

        for e in errors:
            logf.write(f"ERROR: {e}\n")

    # 5. Finish: point latest here, prune, notify
    tmp_link = cfg.data_dir / "latest.tmp"
    tmp_link.unlink(missing_ok=True)
    tmp_link.symlink_to(Path("runs") / stamp)
    tmp_link.replace(cfg.latest)
    if cfg.keep_runs > 0:
        for old in sorted(p for p in cfg.runs_dir.iterdir() if p.is_dir())[:-cfg.keep_runs]:
            shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)

    write_status(cfg, state="finished", run=stamp, errors=errors, stats=stats,
                 at=datetime.now().isoformat(timespec="seconds"))
    log.info("scan %s finished, %d error(s), %s", stamp, len(errors), stats)

    if stats:
        msg = (f"New: {stats['new']} (KEV {stats['new_kev']}, critical {stats['new_crit']}). "
               f"Totals: critical {stats['critical']}, high {stats['high']}, KEV {stats['kev']}.")
        if cfg.notify == "always" or (cfg.notify == "new" and stats["new"]):
            notify(cfg, "TrueNAS SBOM scan: new vulnerabilities" if stats["new"] else "TrueNAS SBOM scan complete", msg)
    if errors:
        notify(cfg, "TrueNAS SBOM scan had errors", "; ".join(errors))
