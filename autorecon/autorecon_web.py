#!/usr/bin/env python3
"""
autorecon_web.py - small web dashboard for autorecon.py (authorized testing only).
Put this file in the same folder as autorecon.py, then:
    python3 autorecon_web.py
"""
import argparse
import hmac
import json
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
RECON = HERE / "autorecon.py"
JOBS_DIR = HERE / "web_jobs"
MAX_RUNNING = 2

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PATTERN_RE = re.compile(r"^(\*\.)?[a-z0-9.*-]{1,253}$")

JOBS = {}
LOCK = threading.Lock()
TOKEN = ""

PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoRecon</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#667085;--line:#e4e7ec;--accent:#2563eb;--ok:#16a34a;--bad:#dc2626;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--text:#e6e9ef;--muted:#98a2b3;--line:#272d38;--accent:#60a5fa;--ok:#4ade80;--bad:#f87171;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:16px}
h1{font-size:1.2rem;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:14px}
label{display:block;font-weight:600;margin:10px 0 4px}label small{font-weight:400;color:var(--muted)}
input[type=text],input[type=number],textarea{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
textarea{min-height:70px;font-family:ui-monospace,monospace;font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:640px){.grid{grid-template-columns:1fr}}
.opts{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px}.opts label{display:flex;gap:6px;align-items:center;font-weight:500;margin:0}
button{font:inherit;padding:8px 14px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
button.sec{background:transparent;color:var(--text);border-color:var(--line)}button:disabled{opacity:.5}
.warn{background:#fff4d6;color:#5b4300;border-radius:8px;padding:8px 10px;font-size:13px;margin:10px 0}
@media(prefers-color-scheme:dark){.warn{background:#3a2f0a;color:#f5dd9a}}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left}
tr.job{cursor:pointer}tr.job:hover{background:var(--bg)}
.st{font-weight:600}.st.running{color:var(--accent)}.st.done{color:var(--ok)}.st.failed,.st.stopped{color:var(--bad)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:340px;font-size:12.5px;white-space:pre-wrap;word-break:break-word;margin:6px 0}
.files a{margin-right:12px}
</style></head><body><div class="wrap">
<h1>AutoRecon dashboard</h1><p class="sub">Scope-aware recon for authorized bug bounty testing.</p>

<div class="card">
 <div class="warn">Run this only against assets that are in scope of a program or that you have written permission to test.</div>
 <label for="domain">Root domain</label><input type="text" id="domain" placeholder="example.com" autocomplete="off">
 <div class="grid">
  <div><label for="scope">In-scope patterns <small>(one per line, optional)</small></label><textarea id="scope" placeholder="*.example.com"></textarea></div>
  <div><label for="oos">Out-of-scope patterns <small>(one per line, optional)</small></label><textarea id="oos" placeholder="mail.example.com"></textarea></div>
 </div>
 <div class="opts">
  <label><input type="checkbox" id="active"> Active (httpx probe + crawl)</label>
  <label><input type="checkbox" id="urls"> Archived URLs (gau / wayback)</label>
  <label>Rate (req/s) <input type="number" id="rate" value="10" min="1" max="50" style="width:80px"></label>
 </div>
 <label style="display:flex;gap:8px;align-items:center;font-weight:500;margin-top:12px"><input type="checkbox" id="auth"> I have authorization to test these assets</label>
 <div style="margin-top:12px"><button id="go" disabled>Start recon</button> <span id="msg" style="color:var(--bad);margin-left:8px"></span></div>
</div>

<div class="card"><b>Jobs</b>
 <table id="jobs"><thead><tr><th>Domain</th><th>Mode</th><th>Status</th><th>Started</th></tr></thead><tbody></tbody></table>
</div>

<div class="card" id="detail" hidden>
 <b id="dtitle"></b> <button class="sec" id="stop" hidden>Stop</button>
 <div class="files" id="files"></div>
 <div style="margin-top:8px"><b>Log</b><pre id="log"></pre></div>
 <div><b>Report</b><pre id="report">(available when the job finishes)</pre></div>
</div>
</div>
<script>
const TOKEN=new URLSearchParams(location.search).get('token')||'';
const $=id=>document.getElementById(id);
let current=null;
async function api(path,opts={}){
  const r=await fetch(path,{...opts,headers:{'X-Token':TOKEN,'Content-Type':'application/json'}});
  if(!r.ok){let t='';try{t=(await r.json()).error}catch(e){}throw new Error(t||r.status)}
  return r.json();
}
$('auth').onchange=()=>$('go').disabled=!$('auth').checked;
const lines=v=>v.split('\n').map(s=>s.trim()).filter(Boolean);
$('go').onclick=async()=>{
  $('msg').textContent='';
  try{
    const j=await api('/api/start',{method:'POST',body:JSON.stringify({
      domain:$('domain').value.trim(),scope:lines($('scope').value),oos:lines($('oos').value),
      active:$('active').checked,urls:$('urls').checked,rate:+$('rate').value,authorized:$('auth').checked})});
    current=j.id;refresh();
  }catch(e){$('msg').textContent=e.message}
};
$('stop').onclick=async()=>{if(current){await api('/api/stop/'+current,{method:'POST',body:'{}'});refresh()}};
function row(j){
  const tr=document.createElement('tr');tr.className='job';
  [j.domain,j.mode,null,new Date(j.started*1000).toLocaleString()].forEach((v,i)=>{
    const td=document.createElement('td');
    if(i===2){td.textContent=j.status;td.className='st '+j.status}else td.textContent=v;tr.append(td)});
  tr.onclick=()=>{current=j.id;refresh()};return tr;
}
async function refresh(){
  try{
    const {jobs}=await api('/api/jobs');
    const tb=$('jobs').querySelector('tbody');tb.replaceChildren(...jobs.map(row));
    if(current){
      const d=await api('/api/job/'+current);
      $('detail').hidden=false;$('dtitle').textContent=d.domain+' - '+d.status;
      $('stop').hidden=d.status!=='running';
      $('log').textContent=d.log||'';$('log').scrollTop=$('log').scrollHeight;
      $('report').textContent=d.report||'(available when the job finishes)';
      const f=$('files');f.replaceChildren();
      d.files.forEach(n=>{const a=document.createElement('a');a.textContent=n;a.href='#';
        a.onclick=async e=>{e.preventDefault();const r=await fetch('/api/job/'+current+'/file/'+encodeURIComponent(n),{headers:{'X-Token':TOKEN}});
          const b=await r.blob();const u=URL.createObjectURL(b);const x=document.createElement('a');x.href=u;x.download=n;x.click();URL.revokeObjectURL(u)};
        f.append(a)});
    }
  }catch(e){$('msg').textContent=e.message}
}
refresh();setInterval(refresh,2500);
</script></body></html>
"""


def clean_patterns(items):
    out = []
    for p in items or []:
        p = str(p).strip().lower()
        if not p or p.startswith("#"):
            continue
        if not PATTERN_RE.match(p):
            raise ValueError(f"invalid scope pattern: {p[:60]}")
        out.append(p)
    return out


def start_job(body):
    domain = str(body.get("domain", "")).strip().lower()
    if not DOMAIN_RE.match(domain):
        raise ValueError("enter a valid root domain, e.g. example.com")
    if body.get("authorized") is not True:
        raise ValueError("you must confirm authorization")
    scope = clean_patterns(body.get("scope"))
    oos = clean_patterns(body.get("oos"))
    try:
        rate = max(1, min(50, int(body.get("rate", 10))))
    except (TypeError, ValueError):
        raise ValueError("rate must be a number")
    active, urls = bool(body.get("active")), bool(body.get("urls"))

    with LOCK:
        if sum(1 for j in JOBS.values() if j["status"] == "running") >= MAX_RUNNING:
            raise ValueError(f"max {MAX_RUNNING} jobs at a time, wait for one to finish")
        jid = secrets.token_hex(6)
        jdir = JOBS_DIR / jid
        jdir.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, str(RECON), "-d", domain, "-y", "-o", str(jdir / "out"), "--rate", str(rate)]
        if scope:
            (jdir / "scope.txt").write_text("\n".join(scope) + "\n")
            cmd += ["--scope", str(jdir / "scope.txt")]
        if oos:
            (jdir / "oos.txt").write_text("\n".join(oos) + "\n")
            cmd += ["--out-of-scope", str(jdir / "oos.txt")]
        if active:
            cmd.append("--active")
        if urls:
            cmd.append("--urls")
        logf = open(jdir / "job.log", "w")
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        JOBS[jid] = {"id": jid, "domain": domain, "mode": "active" if active else ("passive+urls" if urls else "passive"),
                     "status": "running", "started": time.time(), "proc": proc, "dir": jdir, "logf": logf, "stopped": False}
    threading.Thread(target=watch, args=(jid,), daemon=True).start()
    return jid


def watch(jid):
    j = JOBS[jid]
    rc = j["proc"].wait()
    j["logf"].close()
    j["status"] = "stopped" if j["stopped"] else ("done" if rc == 0 else "failed")


def job_files(jdir):
    out = Path(jdir) / "out"
    if not out.exists():
        return None
    subs = sorted([d for d in out.iterdir() if d.is_dir()])
    return subs[-1] if subs else None


def job_detail(jid):
    j = JOBS[jid]
    rd = job_files(j["dir"])
    files, report = [], ""
    if rd:
        files = sorted(p.name for p in rd.iterdir() if p.is_file())
        rp = rd / "report.md"
        if rp.exists():
            report = rp.read_text(errors="replace")[:60000]
    try:
        log = (j["dir"] / "job.log").read_text(errors="replace")[-20000:]
    except OSError:
        log = ""
    return {"id": jid, "domain": j["domain"], "status": j["status"], "log": log, "report": report, "files": files}


class Handler(BaseHTTPRequestHandler):
    server_version = "autorecon-web"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj))

    def _authed(self):
        return hmac.compare_digest(self.headers.get("X-Token", ""), TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            tok = parse_qs(u.query).get("token", [""])[0]
            if not hmac.compare_digest(tok, TOKEN):
                return self._send(403, "Missing or wrong token. Use the URL printed in the terminal.", "text/plain")
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if not self._authed():
            return self._json(403, {"error": "forbidden"})
        if u.path == "/api/jobs":
            with LOCK:
                jobs = sorted(({k: v[k] for k in ("id", "domain", "mode", "status", "started")} for v in JOBS.values()),
                              key=lambda x: -x["started"])
            return self._json(200, {"jobs": jobs})
        m = re.match(r"^/api/job/([a-f0-9]{12})$", u.path)
        if m and m.group(1) in JOBS:
            return self._json(200, job_detail(m.group(1)))
        m = re.match(r"^/api/job/([a-f0-9]{12})/file/([A-Za-z0-9_.-]+)$", u.path)
        if m and m.group(1) in JOBS:
            rd = job_files(JOBS[m.group(1)]["dir"])
            f = (rd / m.group(2)) if rd else None
            if f and f.is_file() and f.parent == rd:
                return self._send(200, f.read_bytes(), "application/octet-stream",
                                  {"Content-Disposition": f'attachment; filename="{f.name}"'})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._json(403, {"error": "forbidden"})
        u = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._json(400, {"error": "bad request"})
        if u.path == "/api/start":
            try:
                return self._json(200, {"id": start_job(body)})
            except ValueError as e:
                return self._json(400, {"error": str(e)})
        m = re.match(r"^/api/stop/([a-f0-9]{12})$", u.path)
        if m and m.group(1) in JOBS:
            j = JOBS[m.group(1)]
            if j["status"] == "running":
                j["stopped"] = True
                j["proc"].terminate()
            return self._json(200, {"ok": True})
        self._json(404, {"error": "not found"})


def main():
    global TOKEN
    ap = argparse.ArgumentParser(description="Web dashboard for autorecon.py")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--token", help="access token (default: random)")
    a = ap.parse_args()
    if not RECON.exists():
        sys.exit("autorecon.py must be in the same folder as autorecon_web.py")
    TOKEN = a.token or secrets.token_urlsafe(18)
    JOBS_DIR.mkdir(exist_ok=True)
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    shown = "127.0.0.1" if a.host in ("0.0.0.0", "::") else a.host
    print(f"AutoRecon dashboard: http://{shown}:{a.port}/?token={TOKEN}")
    if a.host not in ("127.0.0.1", "localhost"):
        print("WARNING: listening beyond localhost. Use a firewall, HTTPS reverse proxy or an SSH tunnel.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
