"""Small password-protected web page: status, stats, Scan now, downloads."""
import base64
import hmac
import html
import json
import logging
import secrets
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import report, schedule
from .config import Config
from .scan import is_running, read_status, scan, tool_version

log = logging.getLogger("sbomgen")
CSRF = secrets.token_urlsafe(24)   # per process; embedded in the Scan now form

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5f6b7a;--line:#dfe3e8;--accent:#2563eb;--kev:#d92d20;--warn:#b54708}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--fg:#e6e9ee;--muted:#98a2b3;--line:#2a313b;--accent:#6ea0ff;--kev:#ff6b5e;--warn:#f5a524}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:0 0 12px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-top:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}.stat b{display:block;font-size:26px}
.stat.kev b{color:var(--kev)}.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.btn{display:inline-block;padding:8px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);text-decoration:none;font:inherit;cursor:pointer}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn[disabled]{opacity:.5;cursor:default}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;padding:6px 8px;border-top:1px solid var(--line)}th{color:var(--muted);font-weight:500}
.err{color:var(--warn)}code{font-size:13px}
"""


def _runs(cfg: Config, n: int = 6) -> list[tuple[str, dict | None]]:
    if not cfg.runs_dir.is_dir():
        return []
    out = []
    for d in sorted((p for p in cfg.runs_dir.iterdir() if p.is_dir()), reverse=True)[:n]:
        try:
            out.append((d.name, json.loads((d / "summary.json").read_text())["stats"]))
        except (OSError, ValueError, KeyError):
            out.append((d.name, None))
    return out


def _fmt_run(name: str) -> str:
    return f"{name[0:4]}-{name[4:6]}-{name[6:8]} {name[9:11]}:{name[11:13]}" if len(name) == 15 else name


def render(cfg: Config) -> str:
    e = html.escape
    st = read_status(cfg)
    running = is_running(cfg)
    if st.get("state") == "running" and not running:   # app restarted mid-scan
        st = {"state": "failed", "error": f"scan {st.get('run', '')} was interrupted (app restarted)"}
    stats = st.get("stats")
    nxt = schedule.next_run(cfg)

    if running:
        status = f"Scan running (started {_fmt_run(st.get('run', ''))}). This page refreshes on its own."
    elif st.get("state") == "finished":
        errs = st.get("errors") or []
        status = f"Last scan {_fmt_run(st['run'])}, " + (
            f"<span class=err>{len(errs)} error(s): {e('; '.join(errs))}</span>" if errs else "no errors")
    elif st.get("state") == "failed":
        status = f"<span class=err>Last scan failed: {e(st.get('error', ''))}</span>"
    else:
        status = "No scans yet."

    tiles = ""
    if stats:
        tiles = "<div class=stats>" + "".join(
            f"<div class='stat{' kev' if k == 'kev' else ''}'><b>{stats[k]:,}</b><span class=muted>{label}</span></div>"
            for k, label in (("kev", "known exploited"), ("critical", "critical"), ("high", "high"),
                             ("new", "new since previous scan"))) + "</div>"

    has_report = (cfg.latest / "summary.json").is_file()
    downloads = ("<div class=row style='margin-top:16px'>"
                 "<a class=btn href='/download/md'>Download report</a>"
                 "<a class=btn href='/download/csv'>Download findings (CSV)</a>"
                 "<a class=btn href='/download/tgz'>Download everything</a></div>") if has_report else ""

    rows = "".join(
        f"<tr><td>{_fmt_run(n)}</td>" + (
            f"<td>{s['kev']}</td><td>{s['critical']}</td><td>{s['high']}</td><td>{s['new']}</td>" if s
            else "<td colspan=4 class=muted>no vulnerability summary</td>") + "</tr>"
        for n, s in _runs(cfg))
    history = (f"<div class=card><h2>Recent scans</h2><table><tr><th>Run</th><th>KEV</th><th>Critical</th>"
               f"<th>High</th><th>New</th></tr>{rows}</table></div>") if rows else ""

    scope = ", ".join(x for x, on in (("host OS", cfg.scan_host), ("containers", cfg.scan_containers),
                                      ("Grype", cfg.vuln_scan)) if on) or "nothing"
    sched = f"{cfg.schedule}" + (f", next {nxt:%a %b %d %H:%M}" if nxt else "")
    extras = ", ".join(x for x, on in (("Dependency-Track upload", cfg.dt_url and cfg.dt_api_key),
                                       (f"webhook ({cfg.notify})", cfg.webhook_url)) if on) or "none"

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>TrueNAS SBOM</title>
{'<meta http-equiv=refresh content=15>' if running else ''}<style>{CSS}</style></head><body><main>
<h1>TrueNAS SBOM Generator</h1>
<div class=muted>Syft {e(tool_version('syft'))} · Grype {e(tool_version('grype'))}</div>
<div class=card><p style=margin-top:0>{status}</p>{tiles}{downloads}
<form method=post action=/scan class=row style='margin-top:16px'>
<input type=hidden name=csrf value="{CSRF}">
<button class='btn primary' {'disabled' if running else ''}>{'Scanning…' if running else 'Scan now'}</button></form></div>
{history}
<div class=card><h2>Settings</h2><table>
<tr><th>Scans</th><td>{e(scope)}</td></tr><tr><th>Schedule</th><td>{e(sched)}</td></tr>
<tr><th>Integrations</th><td>{e(extras)}</td></tr><tr><th>Data</th><td><code>{e(str(cfg.data_dir))}</code></td></tr>
</table><p class=muted style=margin-bottom:0>Change these in the app's environment variables (Apps → Edit).</p></div>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    cfg: Config
    auth: str

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _authed(self) -> bool:
        got = self.headers.get("Authorization", "")
        if hmac.compare_digest(got.encode(), self.auth.encode()):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="TrueNAS SBOM"')
        self.end_headers()
        return False

    def _send(self, code: int, body: bytes, ctype: str, filename: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _latest(self) -> Path | None:
        runs = self.cfg.runs_dir.resolve()
        run = self.cfg.latest.resolve()
        return run if run.is_dir() and run.parent == runs else None

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if not self._authed():
            return
        if self.path == "/":
            return self._send(200, render(self.cfg).encode(), "text/html; charset=utf-8")
        if self.path.startswith("/download/"):
            return self._download(self.path.rsplit("/", 1)[1])
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if not self._authed():
            return
        if self.path != "/scan":
            return self._send(404, b"not found", "text/plain")
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        form = dict(p.split("=", 1) for p in self.rfile.read(length).decode().split("&") if "=" in p)
        if not hmac.compare_digest(form.get("csrf", ""), CSRF):
            return self._send(403, b"stale form; reload the page", "text/plain")
        if not is_running(self.cfg):
            threading.Thread(target=scan, args=(self.cfg,), name="scan", daemon=True).start()
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def _download(self, kind: str):
        run = self._latest()
        if not run:
            return self._send(404, b"No completed scan yet.", "text/plain")
        base = f"sbom-{run.name}"
        if kind == "md" and (run / "summary.md").is_file():
            return self._send(200, (run / "summary.md").read_bytes(), "text/markdown; charset=utf-8",
                              f"{base}-report.md")
        if kind == "csv" and (run / "summary.json").is_file():
            return self._send(200, report.to_csv(run / "summary.json"), "text/csv; charset=utf-8",
                              f"{base}-findings.csv")
        if kind == "tgz":
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Disposition", f'attachment; filename="{base}.tar.gz"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with tarfile.open(fileobj=self.wfile, mode="w|gz") as tar:
                tar.add(run, arcname=run.name)
            return
        self._send(404, b"Not available for this run.", "text/plain")


def serve(cfg: Config) -> None:
    password = cfg.ui_password
    if not password:
        password = secrets.token_urlsafe(12)
        log.warning("UI_PASSWORD not set; generated one for this start: user=%s password=%s",
                    cfg.ui_user, password)
    Handler.cfg = cfg
    Handler.auth = "Basic " + base64.b64encode(f"{cfg.ui_user}:{password}".encode()).decode()
    srv = ThreadingHTTPServer(("0.0.0.0", cfg.port), Handler)
    log.info("web UI on port %d", cfg.port)
    srv.serve_forever()
