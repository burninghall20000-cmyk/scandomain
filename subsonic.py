#!/usr/bin/env python3
"""
SUBSONIC v3.1 - High Accuracy Subdomain Scanner + Wayback History
Author: AI Assistant
Features:
- DNS parallel (A/CNAME/AAAA/MX)
- HTTP/HTTPS probe
- Multi-source subdomain collection (crt.sh, RapidDNS)
- Live Wayback Machine check (2 years)
- Progress bar & summary file
"""

import re
import requests
import os
import json
import time
import threading
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich import print as rprint

console = Console()
RESULT_FOLDER = "subsonic_results"
os.makedirs(RESULT_FOLDER, exist_ok=True)
SUMMARY_FILE = os.path.join(RESULT_FOLDER, "all_live_subdomains.txt")
CACHE_FILE = os.path.join(RESULT_FOLDER, "subdomain_cache.json")
thread_local = threading.local()

# ===== Thread session =====
def get_thread_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=200)
        thread_local.session.mount('http://', adapter)
        thread_local.session.mount('https://', adapter)
        thread_local.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        thread_local.session.timeout = 3
    return thread_local.session

def fetch_url(url, timeout=5):
    try:
        return get_thread_session().get(url, timeout=timeout).text
    except:
        return ""

# ===== Validasi subdomain =====
def valid_subdomain(sub, domain):
    pattern = r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$"
    return sub.endswith(f".{domain}") and re.match(pattern, sub.lower())

def clean_subdomain(sub, domain):
    sub = sub.lower().strip()
    sub = re.sub(r"^\*\.", "", sub)
    sub = re.sub(r"^\.+|\.+$", "", sub)
    return sub if valid_subdomain(sub, domain) else None

# ===== DNS Resolver =====
def setup_dns_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8','1.1.1.1','8.8.4.4','1.0.0.1','9.9.9.9']
    resolver.timeout = 1
    resolver.lifetime = 1
    return resolver

def dns_resolve(sub, resolver):
    try:
        for rtype in ['A','CNAME','AAAA','MX']:
            try:
                answers = resolver.resolve(sub, rtype, raise_on_no_answer=False)
                if answers.rrset:
                    return True
            except:
                continue
    except:
        return False
    return False

# ===== Subdomain sources =====
def get_subdomains_from_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    text = fetch_url(url)
    subs = set()
    try:
        data = json.loads(text)
        for item in data:
            for field in ['name_value','common_name']:
                values = str(item.get(field,'')).split('\n')
                for v in values:
                    c = clean_subdomain(v, domain)
                    if c: subs.add(c)
    except: pass
    return subs

def get_subdomains_from_rapiddns(domain):
    text = fetch_url(f"https://rapiddns.io/subdomain/{domain}?full=1")
    subs = set()
    if text:
        pattern = re.compile(rf">([a-z0-9._-]+\.{re.escape(domain)})<", re.I)
        for match in pattern.findall(text):
            c = clean_subdomain(match, domain)
            if c: subs.add(c)
    return subs

SOURCES = [get_subdomains_from_crtsh, get_subdomains_from_rapiddns]

# ===== Probing =====
def probe_subdomain(sub, resolver):
    if dns_resolve(sub, resolver):
        for scheme in ["https://","http://"]:
            try:
                resp = get_thread_session().head(f"{scheme}{sub}", timeout=3, allow_redirects=True)
                if resp.status_code < 400: return f"{scheme}{sub}"
            except:
                continue
        return f"dns-only://{sub}"
    return None

# ===== Wayback Machine Check =====
def check_wayback(subdomain, years=2):
    try:
        url = f"http://archive.org/wayback/available?url={subdomain}"
        data = get_thread_session().get(url, timeout=5).json()
        archived_snap = data.get('archived_snapshots', {}).get('closest', {})
        if archived_snap:
            timestamp = archived_snap.get('timestamp')
            if timestamp and int(timestamp[:4]) >= int(time.strftime("%Y")) - years:
                return archived_snap.get('url')
    except:
        pass
    return None

# ===== Scan domain =====
def scan_domain(domain):
    console.print(Panel.fit(f"[cyan]Scanning: {domain}[/cyan]", border_style="green"))
    start = time.time()
    resolver = setup_dns_resolver()
    all_subs = set()
    
    # Ambil subdomain dari semua source
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as executor:
        futures = {executor.submit(s, domain): s.__name__ for s in SOURCES}
        for f in as_completed(futures):
            all_subs.update(f.result())
    
    console.print(f"[bold]Collected subdomains:[/bold] {len(all_subs)}")
    live_subs = []
    
    # Probe dan cek Wayback
    with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(),
                  TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()) as progress:
        task = progress.add_task("Probing...", total=len(all_subs))
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_sub = {executor.submit(probe_subdomain, s, resolver): s for s in all_subs}
            for future in as_completed(future_to_sub):
                progress.update(task, advance=1)
                res = future.result()
                if res:
                    live_subs.append(res)
                    # Cek Wayback Machine
                    wayback_url = check_wayback(res)
                    if wayback_url:
                        console.print(f"[yellow]Wayback found:[/yellow] {res} -> {wayback_url}")

    elapsed = time.time()-start
    console.print(f"[green]✓ {len(live_subs)} live subdomains found in {elapsed:.2f}s[/green]")
    
    # Simpan hasil
    with open(os.path.join(RESULT_FOLDER,f"{domain}.txt"), "w") as f:
        [f.write(s+"\n") for s in sorted(live_subs)]
    with open(SUMMARY_FILE, "a") as f:
        [f.write(s+"\n") for s in live_subs]
    
    return live_subs

# ===== Main =====
def main():
    rprint(Panel.fit("[bold blue]SUBSONIC v3.1 - Accurate Subdomain Scanner[/bold blue]", subtitle="[green]Fast, Precise & Wayback Enabled[/green]"))
    
    if not os.path.exists("domains.txt"):
        console.print("[red]Error:[/red] File domains.txt tidak ditemukan!"); return
    
    domains = [re.sub(r"^https?://(www\.)?|^www\.", "", d.strip()) for d in open("domains.txt") if d.strip()]
    if not domains:
        console.print("[red]Error:[/red] Tidak ada domain valid!"); return
    
    if os.path.exists(SUMMARY_FILE): os.remove(SUMMARY_FILE)
    
    all_results = {}
    total_start = time.time()
    for domain in domains:
        all_results[domain] = scan_domain(domain)
        console.print("")
    
    total_time = time.time()-total_start
    total_live = sum(len(v) for v in all_results.values())
    console.print(Panel.fit(f"[bold]SCAN SUMMARY[/bold]\nTotal live subdomains: {total_live}\nTime: {total_time:.2f}s\nResults: {SUMMARY_FILE}", border_style="blue"))

if __name__=="__main__":
    main()
