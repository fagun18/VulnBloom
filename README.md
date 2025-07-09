![insafweb-19-03-2020-xss_cross-site_bg](https://user-images.githubusercontent.com/60549548/165462787-dcc49017-8876-45de-ac01-9e3a7c79dd1a.jpg)

<a href="/Lu3ky13/"><img src="https://camo.githubusercontent.com/f5054ffcd4245c10d3ec85ef059e07aacf787b560f83ad4aec2236364437d097/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f636f6e747269627574696f6e732d77656c636f6d652d627269676874677265656e2e7376673f7374796c653d666c6174" data-canonical-src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat" style="max-width: 100%;"></a> <br>

                                 🐛   🐛   VulnBloom 🐛 🐛 
   
######  <g-emoji class="g-emoji" alias="cd" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f4bf.png">💿</g-emoji> VulnBloom finds XSS vulnerabilities on large websites by leveraging archive.org to discover thousands of historical URLs, then tests each with your payloads. It features colorful output, progress indicators, deduplication, and XSS type detection. <g-emoji class="g-emoji" alias="cd" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f4bf.png">💿</g-emoji>

<h1><g-emoji class="g-emoji" alias="ledger" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f4d2.png">📒</g-emoji> How it works <g-emoji class="g-emoji" alias="ledger" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f4d2.png">📒</g-emoji> </h1>

- Download the script (requires Python 3):
  ```bash
  python3 fagun_xss.py
  ```
- Create a file named `payloads.txt` and add your XSS payloads (one per line).
- Run the tool:
  ```bash
  python3 fagun_xss.py
  ```
- Enter your target domain when prompted (e.g., `example.com`).

### Features
- Collects subdomains from multiple sources (crt.sh, hackertarget, DNS brute-force)
- Fetches historical URLs from archive.org for each subdomain
- Colorful, animated CLI output with progress indicators
- Deduplicates and validates subdomains and URLs
- Loads payloads from `payloads.txt`
- Scans for XSS vulnerabilities and detects:
  - Reflected XSS
  - Path-based XSS
  - (Notes for stored/DOM-based XSS)
- Generates a beautiful HTML report with clickable vulnerable URLs and XSS type
- Real-time result saving and progress tracking

### Example Output

```
1/48 - example.com
[+] Fetching URLs for example.com...  - 5 URLs found for example.com
...
48/48 - demo.example.com
[+] Fetching URLs for demo.example.com...  - 5 URLs found for demo.example.com
[+] Total URLs (with duplicates): 100
[+] Removing duplicate URLs...
[+] Total URLs after deduplication: 51
[+] Total payloads loaded: 3000
```

### HTML Report
- Only valid XSS vulnerabilities are listed
- Each finding is clickable and labeled with its XSS type
- Notes for stored and DOM-based XSS are included
- Shows total subdomains, URLs, payloads, and test summary

---

```
          \\|///
        \\  - -  //
         (  @ @  )
  -----oOOo-(_)-oOOo----------
 |                           |
 |   VulnBloom by @Fagun     |
 |                           |
 |                           |
  ----------------------------

 [ https://twitter.com/fagun18 ]

Enter your url:- testphp.vulnweb.com
```
