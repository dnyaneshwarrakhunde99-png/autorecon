#!/usr/bin/env python3
"""
autorecon.py - scope-aware recon orchestrator for authorized bug bounty testing.

Pipeline:
  1. Passive subdomain enumeration  (subfinder, assetfinder, amass -passive)
  2. Scope filtering                (in-scope / out-of-scope patterns)
  3. Live host probing              (httpx)          [--active]
  4. URL / endpoint collection      (gau or waybackurls, katana) [--urls / --active]
  5. Interesting-finding triage     (admin/dev/staging hosts, juicy paths, JS files)
  6. Markdown + JSON report

It only wraps well-known recon tools. It does NOT exploit anything.
Use it ONLY on assets that are in scope of a program or that you have
written permission to test.
"""
import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

BANNER = "autorecon - authorized testing only"

PASSIVE_TOOLS = {
    "subfinder":   ["subfinder", "-silent", "-d", "{d}"],
    "assetfinder": ["assetfinder", "--subs-only", "{d}"],
    "amass":       ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d", "{d}"],
}
URL_TOOLS = {
    "gau":         ["gau", "--subs", "{d}"],
    "waybackurls": ["waybackurls", "{d}"],
}
HTTPX_CMD = ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect",
             "-web-server", "-follow-redirects", "-rate-limit", "{rate}", "-l", "{in}"]
KATANA_CMD = ["katana", "-silent", "-jc", "-d", "2", "-rate-limit", "{rate}", "-list", "{in}"]

INTERESTING_HOST = re.compile(
    r"(^|[.-])(admin|dev|stag(e|ing)|test|qa|uat|beta|internal|vpn|jenkins|gitlab|jira|"
    r"grafana|kibana|sso|old|legacy|backup|api|portal|demo|sandbox|git|ci)([.-]|$)", re.I)
INTERESTING_PATH = re.compile(
    r"(/admin|/login|/signin|/register|/api/|/graphql|/swagger|/openapi|/v[0-9]+/|/debug|"
    r"/actuator|/console|/upload|/export|/backup|/\.git|/\.env|/config|/internal|/reset|"
    r"/oauth|/callback|/redirect|/download|/phpinfo)", re.I)
INTERESTING_PARAM = re.compile(
    r"[?&](url|redirect|next|return|callback|file|path|page|template|dest|continue|"
    r"id|user|uid|account|token|key|api_key|debug)=", re.I)
STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webp)(\?|$)", re.I)


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def have(tool):
    return shutil.which(tool) is not None


def run(cmd, timeout, stdin_text=None):
    """Run a command, return stdout lines. Never raises on tool failure."""
    try:
        p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in p.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        log(f"  timeout: {cmd[0]}")
    except Exception as e:  # noqa
        log(f"  error running {cmd[0]}: {e}")
    return []


def fill(cmd, **kw):
    return [str(a).format(**kw) if "{" in str(a) else a for a in cmd]


def load_patterns(path):
    if not path:
        return []
    pats = []
    for line in Path(path).read_text().splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            pats.append(line)
    return pats


def host_of(item):
    item = item.strip().lower()
    if "://" in item:
        item = urlparse(item).hostname or ""
    return item.split(":")[0].lstrip("*.")


def matches(host, pat):
    pat = pat.lower()
    if pat.startswith("*."):
        return host == pat[2:] or fnmatch.fnmatch(host, pat)
    return host == pat or fnmatch.fnmatch(host, pat)


class Scope:
    def __init__(self, inscope, outscope):
        self.inscope, self.outscope = inscope, outscope

    def ok(self, item):
        h = host_of(item)
        if not h:
            return False
        if any(matches(h, p) for p in self.outscope):
            return False
        return any(matches(h, p) for p in self.inscope)


def write(path, lines):
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def stage_subdomains(domain, scope, outdir, timeout, dry):
    log("Stage 1: passive subdomain enumeration")
    tools = [(n, c) for n, c in PASSIVE_TOOLS.items() if have(n)]
    for n in PASSIVE_TOOLS:
        if not have(n):
            log(f"  skip {n} (not installed)")
    if dry:
        for n, c in tools:
            log("  would run: " + " ".join(fill(c, d=domain)))
        return []
    found = set()

    def job(item):
        n, c = item
        res = run(fill(c, d=domain), timeout)
        log(f"  {n}: {len(res)} results")
        return res

    with ThreadPoolExecutor(max_workers=max(1, len(tools))) as ex:
        for res in ex.map(job, tools):
            found.update(host_of(r) for r in res)
    found.add(domain)
    allf = sorted(h for h in found if h)
    kept = [h for h in allf if scope.ok(h)]
    log(f"  {len(allf)} found, {len(kept)} in scope, {len(allf) - len(kept)} dropped by scope")
    write(outdir / "subdomains_all.txt", allf)
    write(outdir / "subdomains.txt", kept)
    return kept


def stage_probe(hosts, scope, outdir, rate, timeout, dry):
    log("Stage 2: live host probing (httpx)")
    if not have("httpx"):
        log("  skip: httpx not installed")
        return []
    inp = outdir / "subdomains.txt"
    cmd = fill(HTTPX_CMD, rate=rate, **{"in": inp})
    if dry:
        log("  would run: " + " ".join(cmd))
        return []
    live = []
    for line in run(cmd, timeout):
        try:
            j = json.loads(line)
        except ValueError:
            continue
        url = j.get("url", "")
        if not scope.ok(url):
            continue
        live.append({
            "url": url,
            "status": j.get("status_code"),
            "title": (j.get("title") or "")[:80],
            "tech": j.get("tech") or j.get("technologies") or [],
            "server": j.get("webserver", ""),
        })
    log(f"  {len(live)} live hosts")
    write(outdir / "live.txt", [x["url"] for x in live])
    (outdir / "live.json").write_text(json.dumps(live, indent=2))
    return live


def stage_urls(domain, live, scope, outdir, rate, timeout, crawl, dry):
    log("Stage 3: URL / endpoint collection")
    urls = set()
    for n, c in URL_TOOLS.items():
        if not have(n):
            log(f"  skip {n} (not installed)")
            continue
        if dry:
            log("  would run: " + " ".join(fill(c, d=domain)))
            continue
        res = run(fill(c, d=domain), timeout)
        log(f"  {n}: {len(res)} urls")
        urls.update(res)
    if crawl and live and have("katana"):
        cmd = fill(KATANA_CMD, rate=rate, **{"in": outdir / "live.txt"})
        if dry:
            log("  would run: " + " ".join(cmd))
        else:
            res = run(cmd, timeout)
            log(f"  katana: {len(res)} urls")
            urls.update(res)
    elif crawl and not have("katana"):
        log("  skip katana (not installed)")
    kept = sorted(u for u in urls if scope.ok(u) and not STATIC_EXT.search(u))
    write(outdir / "urls.txt", kept)
    log(f"  {len(kept)} in-scope non-static urls")
    return kept


def triage(hosts, live, urls):
    hosts_i = [h for h in hosts if INTERESTING_HOST.search(h)]
    paths_i = [u for u in urls if INTERESTING_PATH.search(u)]
    params_i = [u for u in urls if INTERESTING_PARAM.search(u)]
    js = [u for u in urls if re.search(r"\.js(\?|$)", u, re.I)]
    status = {}
    for x in live:
        status.setdefault(str(x["status"]), []).append(x["url"])
    return {"hosts": hosts_i, "paths": paths_i[:500], "params": params_i[:500],
            "js": js[:500], "status": status}


def report(domain, outdir, hosts, live, urls, tri, started):
    md = [f"# Recon report: {domain}", "",
          f"- Started: {started:%Y-%m-%d %H:%M}",
          f"- In-scope subdomains: **{len(hosts)}**",
          f"- Live hosts: **{len(live)}**",
          f"- URLs collected: **{len(urls)}**", ""]
    if tri["hosts"]:
        md += ["## Interesting hostnames", ""] + [f"- `{h}`" for h in tri["hosts"][:100]] + [""]
    if live:
        md += ["## Live hosts", "", "| URL | Status | Title | Tech |", "|---|---|---|---|"]
        for x in sorted(live, key=lambda z: str(z["status"])):
            md.append(f"| {x['url']} | {x['status']} | {x['title'].replace('|', '/')} | "
                      f"{', '.join(x['tech'][:4])} |")
        md.append("")
    for title, key in (("Interesting paths", "paths"), ("URLs with interesting parameters", "params"),
                       ("JavaScript files (review for endpoints/secrets)", "js")):
        if tri[key]:
            md += [f"## {title}", ""] + [f"- {u}" for u in tri[key][:60]]
            if len(tri[key]) > 60:
                md.append(f"- ... {len(tri[key]) - 60} more in urls.txt")
            md.append("")
    md += ["## Next steps (manual)", "",
           "- Review interesting hosts and login/admin panels by hand",
           "- Test access control with two accounts (IDOR/BOLA)",
           "- Read JS files for hidden endpoints and keys",
           "- Check parameters flagged above for redirect/SSRF/injection behaviour within program rules", ""]
    (outdir / "report.md").write_text("\n".join(md))
    (outdir / "summary.json").write_text(json.dumps(
        {"domain": domain, "subdomains": len(hosts), "live": len(live), "urls": len(urls),
         "interesting_hosts": tri["hosts"], "status_groups": {k: len(v) for k, v in tri["status"].items()}},
        indent=2))


def main():
    ap = argparse.ArgumentParser(description=BANNER)
    ap.add_argument("-d", "--domain", required=True, help="root domain, e.g. example.com")
    ap.add_argument("--scope", help="file with in-scope patterns (one per line, *.example.com ok). "
                                    "Default: the domain and its subdomains")
    ap.add_argument("--out-of-scope", help="file with out-of-scope patterns")
    ap.add_argument("--active", action="store_true", help="probe hosts with httpx and crawl with katana")
    ap.add_argument("--urls", action="store_true", help="collect archived URLs (gau/waybackurls)")
    ap.add_argument("--rate", type=int, default=10, help="max requests/sec for active tools (default 10)")
    ap.add_argument("--timeout", type=int, default=600, help="per-tool timeout in seconds")
    ap.add_argument("-o", "--output", default="recon_out", help="output base directory")
    ap.add_argument("--dry-run", action="store_true", help="show what would run, execute nothing")
    ap.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt")
    a = ap.parse_args()

    domain = a.domain.lower().strip()
    inscope = load_patterns(a.scope) or [domain, f"*.{domain}"]
    outscope = load_patterns(a.out_of_scope)
    scope = Scope(inscope, outscope)
    if not scope.ok(domain):
        sys.exit(f"Refusing to run: {domain} is not inside the scope you gave.")

    print(BANNER)
    print(f"In scope:     {', '.join(inscope)}")
    print(f"Out of scope: {', '.join(outscope) or '-'}")
    if not (a.yes or a.dry_run):
        if input("Do you have authorization to test these assets? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted.")

    started = datetime.now()
    outdir = Path(a.output) / f"{domain}_{started:%Y%m%d_%H%M%S}"
    outdir.mkdir(parents=True, exist_ok=True)

    hosts = stage_subdomains(domain, scope, outdir, a.timeout, a.dry_run)
    live = []
    if a.active:
        live = stage_probe(hosts, scope, outdir, a.rate, a.timeout, a.dry_run)
    urls = []
    if a.urls or a.active:
        urls = stage_urls(domain, live, scope, outdir, a.rate, a.timeout, a.active, a.dry_run)

    if a.dry_run:
        log("Dry run finished, nothing executed.")
        return
    tri = triage(hosts, live, urls)
    report(domain, outdir, hosts, live, urls, tri, started)
    log(f"Done. Report: {outdir / 'report.md'}")


if __name__ == "__main__":
    main()
