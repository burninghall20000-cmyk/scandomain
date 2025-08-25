#!/usr/bin/env python3
import re
import requests
from fake_useragent import UserAgent
import os
import json
from concurrent.futures import ThreadPoolExecutor
from time import sleep

# 🎨 Warna terminal
LIME    = '\033[1;92m'
ORANGE  = '\033[1;33m'
TEAL    = '\033[1;36m'
PURPLE  = '\033[1;35m'
WHITE   = '\033[1;37m'
RED     = '\033[1;31m'
RESET   = '\033[0m'

# 🗂️ Folder hasil
RESULT_FOLDER = "results"
os.makedirs(RESULT_FOLDER, exist_ok=True)
FINAL_TXT = os.path.join(RESULT_FOLDER, "all_subdomains.txt")

# 🎉 Banner
print(f"""{TEAL}
🛰️  SUBSONIC SCANNER V6  🛰️
===========================================
💎 Multi-Domain Subdomain Finder + Live Checker
📂 Results: {RESULT_FOLDER}
📝 Final TXT: {FINAL_TXT}
===========================================
{RESET}""")

# ================================
# Fungsi bantu
# ================================
def fetch_url(url, headers, retries=2):
    for _ in range(retries):
        try:
            return requests.get(url, timeout=15, headers=headers)
        except:
            sleep(1)
    return None

def valid_subdomain(sub, domain):
    return (
        sub.endswith(f".{domain}") and
        len(sub) > len(domain) and
        re.match(r"^[a-zA-Z0-9.-]+$", sub)
    )

def get_subdomains(url, pattern, domain, subdomains_set):
    try:
        headers = {'User-Agent': UserAgent().random}
        response = fetch_url(url, headers)
        if response and response.status_code == 200:
            for subdomain in pattern.findall(response.text):
                if valid_subdomain(subdomain, domain):
                    subdomains_set.add(subdomain.lower())
    except:
        pass

def probe_url(url, unique_urls):
    headers = {'User-Agent': UserAgent().random}
    for test_url in [f"https://{url}", f"http://{url}"]:
        try:
            resp = requests.get(test_url, timeout=6, headers=headers, allow_redirects=True)
            if 200 <= resp.status_code < 400:
                unique_urls.add(url)
                return
        except:
            continue

def print_table(domain, urls):
    print(f"{ORANGE}╔════════════════════════════════════╗{RESET}")
    print(f"{ORANGE}║ Active subdomains for {domain:<15} ║{RESET}")
    print(f"{ORANGE}╠════════════════════════════════════╣{RESET}")
    for u in urls:
        print(f"{WHITE}║ {u:<34} ║{RESET}")
    print(f"{ORANGE}╚════════════════════════════════════╝{RESET}")

# ================================
# Scan domain
# ================================
def scan_domain(domain):
    print(f"\n{ORANGE}🛰️ Scanning: {TEAL}{domain}{RESET}")

    txt_file = FINAL_TXT
    subdomains_set = set()
    unique_urls = set()
    domain_regex = rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}"

    sources = [
        (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey", re.compile(domain_regex)),
        (f"https://crt.sh/?q=%25.{domain}", re.compile(domain_regex)),
        (f"https://rapiddns.io/subdomain/{domain}?full=1", re.compile(domain_regex)),
        (f"https://api.hackertarget.com/hostsearch/?q={domain}", re.compile(domain_regex)),
        (f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/passive_dns", re.compile(domain_regex)),
        (f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000", re.compile(domain_regex)),
        (f"https://jldc.me/anubis/subdomains/{domain}", re.compile(domain_regex)),
    ]

    # Ambil subdomain paralel
    with ThreadPoolExecutor(10) as executor:
        for src, pat in sources:
            executor.submit(get_subdomains, src, pat, domain, subdomains_set)

    if not subdomains_set:
        print(f"{RED}❌ No subdomains found for {domain}{RESET}")
        return []

    print(f"{LIME}📄 {len(subdomains_set)} subdomains found, checking which are live...{RESET}")

    # Cek subdomain aktif
    with ThreadPoolExecutor(20) as executor:
        executor.map(lambda u: probe_url(u, unique_urls), subdomains_set)

    # Print table di CMD
    if unique_urls:
        print_table(domain, sorted(unique_urls))

    # Simpan semua subdomain (aktif & non-aktif) di 1 file TXT
    with open(txt_file, "a") as f:
        for sub in sorted(subdomains_set):
            f.write(sub + "\n")
    return sorted(subdomains_set)

# ================================
# MAIN PROGRAM
# ================================
if __name__ == "__main__":
    if not os.path.exists("domains.txt"):
        print(f"{RED}⚠️ Please create domains.txt with one domain per line{RESET}")
        exit()

    with open("domains.txt", "r") as f:
        domain_list = [
            d.strip().lower()
             .replace("http://","")
             .replace("https://","")
             .replace("www.","")
             .rstrip("/")
            for d in f if d.strip()
        ]

    all_subdomains = []

    def process_domain(d):
        subs = scan_domain(d)
        all_subdomains.extend(subs)

    with ThreadPoolExecutor(5) as executor:
        executor.map(process_domain, domain_list)

    print(f"\n{LIME}🎯 Scan completed! Total subdomains found: {len(all_subdomains)}")
    print(f"📝 All results saved to {FINAL_TXT}{RESET}")
