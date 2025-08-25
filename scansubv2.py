#!/usr/bin/env python3
import re, requests, os
from fake_useragent import UserAgent
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep
from rich.console import Console
from rich.table import Table

console = Console()

# Folder hasil
RESULT_FOLDER = "results"
os.makedirs(RESULT_FOLDER, exist_ok=True)
SUMMARY_FILE_TXT = os.path.join(RESULT_FOLDER, "all_live_subdomains.txt")

session = requests.Session()

# Fungsi bantu untuk fetch URL
def fetch_url(url, retries=2, timeout=6):
    for _ in range(retries):
        try:
            session.headers.update({'User-Agent': UserAgent().random})
            r = session.get(url, timeout=timeout)
            if r.status_code < 500:
                return r
        except:
            sleep(0.5)
    return None

# Validasi subdomain
def valid_subdomain(sub, domain):
    return sub.endswith(f".{domain}") and len(sub) > len(domain) and re.match(r"^[a-zA-Z0-9.-]+$", sub)

# Ambil subdomain dari sumber
def get_subdomains(url, pattern, domain):
    subs = set()
    r = fetch_url(url)
    if r and r.status_code == 200:
        for sub in pattern.findall(r.text):
            if valid_subdomain(sub, domain):
                subs.add(sub.lower())
    return subs

# Probe subdomain apakah live
def probe_url(sub):
    for scheme in ["https://", "http://"]:
        try:
            r = session.get(scheme + sub, timeout=4, headers={'User-Agent': UserAgent().random})
            if 200 <= r.status_code < 400:
                return scheme + sub
        except:
            continue
    return None

# Scan domain
def scan_domain(domain):
    console.print(f"🔍 Scanning: [cyan]{domain}[/cyan]")
    pattern = re.compile(rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}")
    sources = [
        # Web Archive
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey",
        # SSL crt.sh
        f"https://crt.sh/?q=%25.{domain}",
        # RapidDNS
        f"https://rapiddns.io/subdomain/{domain}?full=1",
        # HackerTarget
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        # OTX AlienVault
        f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns",
        # URLScan
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000",
        # Anubis
        f"https://jldc.me/anubis/subdomains/{domain}",
    ]

    all_subdomains = set()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_subdomains, url, pattern, domain): url for url in sources}
        for future in as_completed(futures):
            all_subdomains.update(future.result())

    live_subdomains = set()
    if all_subdomains:
        table = Table(title=f"🌐 Live Subdomains - {domain}", header_style="bold magenta")
        table.add_column("No", style="cyan", justify="right")
        table.add_column("Subdomain", style="green")

        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = {executor.submit(probe_url, sub): sub for sub in all_subdomains}
            counter = 1
            for future in as_completed(futures):
                live = future.result()
                if live:
                    live_subdomains.add(live)
                    table.add_row(str(counter), live)
                    counter += 1
                    console.clear()
                    console.print(table)

    return live_subdomains

# MAIN
if __name__ == "__main__":
    if not os.path.exists("domains.txt"):
        console.print("⚠️ [red]Create domains.txt with one domain per line[/red]")
        exit()

    with open("domains.txt", "r") as f:
        domains = [d.strip().lower().replace("http://","").replace("https://","").replace("www.","") for d in f if d.strip()]

    all_live_subs = set()
    for domain in domains:
        live = scan_domain(domain)
        all_live_subs.update(live)

    if all_live_subs:
        with open(SUMMARY_FILE_TXT, "w") as ftxt:
            for sub in sorted(all_live_subs):
                ftxt.write(sub + "\n")
        console.print(f"\n🎯 Scan complete! All live subdomains saved to TXT:", style="green")
        console.print(f"📂 TXT: {SUMMARY_FILE_TXT}")
    else:
        console.print("❌ No live subdomains found.", style="red")
