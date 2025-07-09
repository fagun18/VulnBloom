import requests
import threading
from colorama import Fore, Style
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import os
import signal
import json
import html
import re
import itertools

# Banner
print(
    Fore.CYAN + Style.BRIGHT +
    """
[ VulnBloom | Advanced XSS Scanner ]  by @Fagun  |  https://www.linkedin.com/in/mejbaur/
"""
    + Style.RESET_ALL
)
time.sleep(0.5)
print("\n")

def enumerate_subdomains_crtsh(domain, retries=2):
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] crt.sh error: {res.status_code}" + Fore.RESET)
                return set()
            entries = json.loads(res.text)
            subdomains = set()
            for entry in entries:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] crt.sh timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] crt.sh connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error enumerating subdomains from crt.sh: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from crt.sh after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_hackertarget(domain, retries=2):
    url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200 or 'error' in res.text.lower():
                print(Fore.RED + f"[!] hackertarget error: {res.status_code}" + Fore.RESET)
                return set()
            subdomains = set()
            for line in res.text.splitlines():
                parts = line.split(',')
                if parts and parts[0].endswith(domain):
                    subdomains.add(parts[0].strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] hackertarget timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] hackertarget connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error enumerating subdomains from hackertarget: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from hackertarget after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_alienvault(domain, retries=2):
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] AlienVault OTX error: {res.status_code}" + Fore.RESET)
                return set()
            data = res.json()
            subdomains = set()
            for entry in data.get('passive_dns', []):
                hostname = entry.get('hostname')
                if hostname and hostname.endswith(domain):
                    subdomains.add(hostname.strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] AlienVault OTX timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] AlienVault OTX connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from AlienVault OTX: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from AlienVault OTX after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_rapiddns(domain, retries=2):
    url = f'https://rapiddns.io/subdomain/{domain}?full=1'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] RapidDNS error: {res.status_code}" + Fore.RESET)
                return set()
            # Parse subdomains from HTML table
            subdomains = set()
            for line in res.text.splitlines():
                if line.startswith('<td>') and domain in line:
                    sub = line.split('>')[1].split('<')[0].strip()
                    if sub.endswith(domain):
                        subdomains.add(sub)
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] RapidDNS timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] RapidDNS connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from RapidDNS: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from RapidDNS after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_threatcrowd(domain, retries=2):
    url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] ThreatCrowd error: {res.status_code}" + Fore.RESET)
                return set()
            data = res.json()
            subdomains = set()
            for sub in data.get('subdomains', []):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] ThreatCrowd timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] ThreatCrowd connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from ThreatCrowd: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from ThreatCrowd after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_certspotter(domain, retries=2):
    url = f'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] CertSpotter error: {res.status_code}" + Fore.RESET)
                return set()
            data = res.json()
            subdomains = set()
            for entry in data:
                for name in entry.get('dns_names', []):
                    if name.endswith(domain):
                        subdomains.add(name.strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] CertSpotter timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] CertSpotter connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from CertSpotter: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from CertSpotter after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_bufferover(domain, retries=2):
    url = f'https://dns.bufferover.run/dns?q=.{domain}'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] BufferOver error: {res.status_code}" + Fore.RESET)
                return set()
            data = res.json()
            subdomains = set()
            for entry in data.get('FDNS_A', []) + data.get('RDNS', []):
                parts = entry.split(',')
                sub = parts[-1].strip()
                if sub.endswith(domain):
                    subdomains.add(sub)
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] BufferOver timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] BufferOver connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from BufferOver: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from BufferOver after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_anubisdb(domain, retries=2):
    url = f'https://jldc.me/anubis/subdomains/{domain}'
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] AnubisDB error: {res.status_code}" + Fore.RESET)
                return set()
            data = res.json()
            subdomains = set()
            for sub in data:
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
            return subdomains
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] AnubisDB timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] AnubisDB connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error from AnubisDB: {e}" + Fore.RESET)
            return set()
    print(Fore.RED + f"[!] Failed to fetch from AnubisDB after {retries} attempts." + Fore.RESET)
    return set()

def enumerate_subdomains_dns(domain):
    # Small built-in wordlist for demonstration
    wordlist = [
        'www', 'mail', 'ftp', 'test', 'dev', 'admin', 'portal', 'webmail', 'ns1', 'ns2', 'blog', 'staging', 'api', 'm', 'shop', 'static', 'cdn', 'img', 'beta', 'demo', 'vpn', 'cpanel', 'secure', 'server', 'db', 'app', 'forum', 'news', 'support', 'mobile', 'old', 'new', 'auth', 'login', 'files', 'download', 'upload', 'docs', 'wiki', 'dashboard', 'monitor', 'status', 'gateway', 'proxy', 'smtp', 'pop', 'imap', 'test1', 'test2', 'test3', 'dev1', 'dev2', 'dev3'
    ]
    import socket
    subdomains = set()
    for prefix in wordlist:
        sub = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(sub)
            subdomains.add(sub)
        except Exception:
            continue
    return subdomains

def is_valid_subdomain(sub):
    # Basic check: no @, no spaces, only valid domain chars
    if '@' in sub or ' ' in sub:
        return False
    # Must have at least one dot and not start/end with dot
    if sub.startswith('.') or sub.endswith('.') or '.' not in sub:
        return False
    # Only allow valid domain characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', sub):
        return False
    return True

def enumerate_subdomains(domain):
    print(Fore.CYAN + f"[+] Collecting subdomains from multiple sources..." + Fore.RESET)
    all_subs = []
    crtsh_subs = enumerate_subdomains_crtsh(domain)
    print(Fore.YELLOW + f"  - {len(crtsh_subs)} from crt.sh" + Fore.RESET)
    all_subs.extend(crtsh_subs)
    ht_subs = enumerate_subdomains_hackertarget(domain)
    print(Fore.YELLOW + f"  - {len(ht_subs)} from hackertarget" + Fore.RESET)
    all_subs.extend(ht_subs)
    av_subs = enumerate_subdomains_alienvault(domain)
    print(Fore.YELLOW + f"  - {len(av_subs)} from AlienVault OTX" + Fore.RESET)
    all_subs.extend(av_subs)
    rdns_subs = enumerate_subdomains_rapiddns(domain)
    print(Fore.YELLOW + f"  - {len(rdns_subs)} from RapidDNS" + Fore.RESET)
    all_subs.extend(rdns_subs)
    tc_subs = enumerate_subdomains_threatcrowd(domain)
    print(Fore.YELLOW + f"  - {len(tc_subs)} from ThreatCrowd" + Fore.RESET)
    all_subs.extend(tc_subs)
    cs_subs = enumerate_subdomains_certspotter(domain)
    print(Fore.YELLOW + f"  - {len(cs_subs)} from CertSpotter" + Fore.RESET)
    all_subs.extend(cs_subs)
    bo_subs = enumerate_subdomains_bufferover(domain)
    print(Fore.YELLOW + f"  - {len(bo_subs)} from BufferOver" + Fore.RESET)
    all_subs.extend(bo_subs)
    anubis_subs = enumerate_subdomains_anubisdb(domain)
    print(Fore.YELLOW + f"  - {len(anubis_subs)} from AnubisDB" + Fore.RESET)
    all_subs.extend(anubis_subs)
    dns_subs = enumerate_subdomains_dns(domain)
    print(Fore.YELLOW + f"  - {len(dns_subs)} from DNS brute-force" + Fore.RESET)
    all_subs.extend(dns_subs)
    print(Fore.CYAN + f"[+] Total subdomains (with duplicates): {len(all_subs)}" + Fore.RESET)
    # Remove duplicates and invalid subdomains
    unique_subs = [s for s in set(all_subs) if is_valid_subdomain(s)]
    print(Fore.CYAN + f"[+] Unique valid subdomains after deduplication: {len(unique_subs)}" + Fore.RESET)
    return unique_subs

def fetch_wayback_urls(domain):
    url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=text&fl=original&collapse=urlkey'
    try:
        r = requests.get(url, timeout=15)
        urls = set(line.strip() for line in r.text.splitlines() if line.strip())
        return list(urls)
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching URLs from Wayback Machine: {e}" + Fore.RESET)
        return []

def load_payloads(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def inject_payloads(url, payload):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        return [url + ("&" if "?" in url else "?") + f"xss={urllib.parse.quote(payload)}"]
    mutated_urls = []
    for param in query:
        mutated = query.copy()
        mutated[param] = [payload]
        new_query = urllib.parse.urlencode(mutated, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        mutated_urls.append(new_url)
    return mutated_urls

def scan_url(url, payload, timeout=10):
    try:
        res = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        reflected = payload in res.text
        context = ''
        is_xss = False
        if reflected:
            idx = res.text.find(payload)
            snippet = res.text[max(0, idx-40):idx+len(payload)+40]
            if '<script' in snippet.lower():
                context = 'Inside <script>'
                is_xss = True
            elif 'onerror' in snippet.lower() or 'onload' in snippet.lower():
                context = 'Inside attribute'
                is_xss = True
            elif '<' in snippet and '>' in snippet:
                context = 'Inside HTML tag'
                is_xss = True
            else:
                context = 'Reflected in body'
        return {
            'url': url,
            'payload': payload,
            'reflected': is_xss,  # Only true if dangerous context
            'context': context,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'payload': payload,
            'reflected': False,
            'context': '',
            'error': str(e)
        }

def write_html_report(results, domain, extra_info=None):
    html_lines = [
        '<!DOCTYPE html>',
        '<html lang="en">',
        '<head>',
        '<meta charset="UTF-8">',
        f'<title>VulnBloom XSS Scan Report for {html.escape(domain)}</title>',
        '<style>',
        'body { font-family: Arial, sans-serif; background: #181818; color: #eee; }',
        'table { border-collapse: collapse; width: 100%; margin-top: 20px; }',
        'th, td { border: 1px solid #444; padding: 8px; text-align: left; }',
        'th { background: #222; }',
        '.found { background: #2e7d32; color: #fff; }',
        'a.vuln-link { color: #fff; text-decoration: underline; }',
        '</style>',
        '</head>',
        '<body>',
        f'<h1>VulnBloom XSS Scan Report for {html.escape(domain)}</h1>',
    ]
    if extra_info:
        html_lines.append(f'<p><b>Total subdomains:</b> {extra_info.get("total_subdomains", "-")} | '
                         f'<b>Total URLs (with duplicates):</b> {extra_info.get("total_urls_with_dupes", "-")} | '
                         f'<b>Total URLs (after deduplication):</b> {extra_info.get("total_urls_deduped", "-")} | '
                         f'<b>Total payloads:</b> {extra_info.get("total_payloads", "-")}</p>')
    html_lines.append(
        f'<p>Total tests: {len(results)} | XSS found: {sum(1 for r in results if r["reflected"])}, Not vulnerable: {sum(1 for r in results if not r["reflected"] and not r["error"])}, Errors: {sum(1 for r in results if r["error"])} </p>'
    )
    html_lines += [
        '<table>',
        '<tr><th>#</th><th>URL</th><th>Payload</th><th>Context</th></tr>'
    ]
    vuln_results = [r for r in results if r['reflected']]
    for i, r in enumerate(vuln_results, 1):
        rowclass = 'found'
        url_html = f'<a class="vuln-link" href="{html.escape(r["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(r["url"])}</a>'
        html_lines.append(f'<tr class="{rowclass}"><td>{i}</td><td>{url_html}</td><td>{html.escape(r["payload"])}</td><td>{html.escape(r["context"] or "")}</td></tr>')
    html_lines += ['</table>', '</body>', '</html>']
    with open(f'report_{domain}.html', 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_lines))

def fetch_urlscan_urls(domain, retries=2):
    # Public search, no API key needed for basic queries
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
    urls = set()
    for attempt in range(1, retries+1):
        try:
            res = requests.get(url, timeout=20)
            if res.status_code != 200:
                print(Fore.RED + f"[!] URLScan.io error: {res.status_code}" + Fore.RESET)
                return []
            data = res.json()
            for result in data.get('results', []):
                page_url = result.get('page', {}).get('url')
                if page_url:
                    urls.add(page_url)
            return list(urls)
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] URLScan.io timed out (attempt {attempt}/{retries})..." + Fore.RESET)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] URLScan.io connection error (attempt {attempt}/{retries})..." + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"[!] Error fetching URLs from URLScan.io: {e}" + Fore.RESET)
            return []
    print(Fore.RED + f"[!] Failed to fetch from URLScan.io after {retries} attempts." + Fore.RESET)
    return []

def main():
    try:
        domain = input(Fore.GREEN + 'Enter your url/domain (e.g. example.com): ' + Fore.RESET).strip()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] User interrupted input. Exiting..." + Fore.RESET)
        sys.exit(0)
    print(Fore.CYAN + f"[+] Enumerating subdomains for {domain}..." + Fore.RESET)
    subdomains = enumerate_subdomains(domain)
    if not subdomains:
        print(Fore.YELLOW + f"[!] No subdomains found, using only the main domain." + Fore.RESET)
        subdomains = [domain]
    print(Fore.CYAN + f"[+] Total subdomains to scan: {len(subdomains)}" + Fore.RESET)

    all_urls = []
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    for idx, sub in enumerate(subdomains, 1):
        print(Fore.MAGENTA + f"{idx}/{len(subdomains)} - {sub}" + Fore.RESET)
        print(Fore.CYAN + f"[+] Fetching URLs for {sub}... ", end='', flush=True)
        sys.stdout.write(next(spinner))
        sys.stdout.flush()
        urls = fetch_wayback_urls(sub)
        sys.stdout.write('\r')
        print(Fore.YELLOW + f"  - {len(urls)} URLs found for {sub} (Wayback)" + Fore.RESET)
        all_urls.extend(urls)
        urlscan_urls = fetch_urlscan_urls(sub)
        print(Fore.YELLOW + f"  - {len(urlscan_urls)} URLs found for {sub} (URLScan.io)" + Fore.RESET)
        all_urls.extend(urlscan_urls)
    print(Fore.CYAN + f"[+] Total URLs (with duplicates): {len(all_urls)}" + Fore.RESET)
    # Remove duplicates and invalid URLs
    unique_urls = [u for u in set(all_urls) if u and u.startswith('http')]
    print(Fore.CYAN + f"[+] Removing duplicate URLs..." + Fore.RESET)
    print(Fore.CYAN + f"[+] Total URLs after deduplication: {len(unique_urls)}" + Fore.RESET)
    payloads = load_payloads('payloads.txt')
    print(Fore.CYAN + f"[+] Total payloads loaded: {len(payloads)}" + Fore.RESET)
    if not unique_urls:
        print(Fore.RED + '[!] No URLs found for any subdomain. Exiting.' + Fore.RESET)
        return

    tested = set()
    results = []
    found_count = 0
    not_found_count = 0
    errors = 0
    lock = threading.Lock()
    interrupted = False

    extra_info = {
        "total_subdomains": len(subdomains),
        "total_urls_with_dupes": len(all_urls),
        "total_urls_deduped": len(unique_urls),
        "total_payloads": len(payloads)
    }

    def save_and_exit():
        print(Fore.MAGENTA + "\n[!] Interrupted! Saving results so far..." + Fore.RESET)
        write_html_report(results, domain, extra_info)
        print(Fore.CYAN + f"[+] HTML report saved as report_{domain}.html" + Fore.RESET)
        sys.exit(0)

    def signal_handler(sig, frame):
        nonlocal interrupted
        interrupted = True
        save_and_exit()

    signal.signal(signal.SIGINT, signal_handler)

    total_tests = len(unique_urls) * len(payloads)
    url_progress = {url: 0 for url in unique_urls}

    def task(url, payload, url_idx, total_urls):
        nonlocal found_count, not_found_count, errors
        if interrupted:
            return
        for mutated_url in inject_payloads(url, payload):
            key = (mutated_url, payload)
            if key in tested:
                continue
            tested.add(key)
            result = scan_url(mutated_url, payload)
            with lock:
                results.append(result)
                print(Fore.CYAN + f"[{url_idx}/{total_urls}] Testing: {mutated_url} | Payload: {payload}" + Fore.RESET)
                if result['reflected']:
                    found_count += 1
                    print(Fore.GREEN + f"[XSS FOUND] {mutated_url} | Payload: {payload} | {result['context']}" + Fore.RESET)
                elif result['error']:
                    errors += 1
                    print(Fore.YELLOW + f"[ERROR] {mutated_url} | {result['error']}" + Fore.RESET)
                else:
                    not_found_count += 1
                    print(Fore.RED + f"[NOT VULN] {mutated_url} | Payload: {payload}" + Fore.RESET)
                write_html_report(results, domain, extra_info)

    max_workers = min(32, (os.cpu_count() or 4) * 2)
    print(Fore.CYAN + f"[+] Scanning with {max_workers} threads..." + Fore.RESET)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for url_idx, url in enumerate(unique_urls, 1):
            for payload in payloads:
                futures.append(executor.submit(task, url, payload, url_idx, len(unique_urls)))
        for i, future in enumerate(as_completed(futures), 1):
            if interrupted:
                break

    print(Fore.CYAN + f"[+] Scan complete. {found_count} XSS found, {not_found_count} not vulnerable, {errors} errors." + Fore.RESET)
    write_html_report(results, domain, extra_info)
    print(Fore.CYAN + f"[+] HTML report saved as report_{domain}.html" + Fore.RESET)

if __name__ == '__main__':
    main()
