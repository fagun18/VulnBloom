# 🌸 **VulnBloom** — Advanced XSS Scanner

![VulnBloom Banner](https://user-images.githubusercontent.com/60549548/165462787-dcc49017-8876-45de-ac01-9e3a7c79dd1a.jpg)

<p align="center">
  <img src="https://img.shields.io/badge/python-3.7%2B-blue?logo=python" />
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/contributions-welcome-brightgreen" />
</p>

<p align="center">
  <b>VulnBloom</b> is a powerful, colorful, and modern XSS scanner for bug bounty hunters and security professionals.
  <br>
  <i>Finds XSS vulnerabilities by leveraging historical URLs, subdomain enumeration, and custom payloads.</i>
</p>

---

## 🌟 **Features**

| 🚀 Feature                        | ✅ Description                                                                 |
|-----------------------------------|-------------------------------------------------------------------------------|
| 🔎 Subdomain Enumeration          | Collects subdomains from crt.sh, hackertarget, DNS brute-force, and more      |
| 🕰️ Historical URL Collection      | Fetches thousands of URLs from archive.org and urlscan.io                     |
| 🎨 Colorful CLI                   | Beautiful, animated output with progress bars and color coding                |
| 🧹 Deduplication & Validation     | Removes duplicate/invalid subdomains and URLs, strict domain matching         |
| 💉 Custom Payloads                | Loads your XSS payloads from `payloads.txt`                                   |
| ⚡ Multi-threaded Scanning         | Fast, concurrent XSS testing                                                  |
| 🧪 XSS Type Detection             | Detects reflected and path-based XSS, context-aware reporting                 |
| 📊 Real-time HTML Report          | Generates a live, clickable, and detailed HTML report                         |
| 🔄 Real-time Result Saving        | Saves results as soon as they are found                                       |
| 📈 Progress Tracking              | Shows scan progress for every URL and payload                                 |

---

## 🚀 **Quick Start**

```bash
# 1. Clone the repo
$ git clone https://github.com/fagun18/VulnBloom.git
$ cd VulnBloom

# 2. Add your payloads
$ nano payloads.txt  # or use your favorite editor

# 3. Run the scanner
$ python3 VulnBloomXSS.py
```

- Enter your target domain when prompted (e.g., `example.com`).

---

## 🖥️ **Example Output**

```shell
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

---

## 📑 **HTML Report**
- Only valid XSS vulnerabilities are listed
- Each finding is clickable and labeled with its XSS type
- Notes for stored and DOM-based XSS are included
- Shows total subdomains, URLs, payloads, and test summary

---

## 🧠 **How It Works**

1. **Subdomain Enumeration:**
   - Uses multiple sources to find as many subdomains as possible.
2. **Historical URL Collection:**
   - Gathers thousands of URLs from archive.org and urlscan.io for each subdomain.
3. **Payload Injection:**
   - Loads your custom payloads from `payloads.txt` and injects them into URLs.
4. **XSS Scanning:**
   - Tests each URL+payload combo for reflected and path-based XSS.
5. **Real-time Reporting:**
   - Saves and updates a beautiful HTML report as soon as results are found.

---

## 📝 **Credits & Contact**

- Developed by [@Fagun](https://twitter.com/fagun18)
- Connect on [LinkedIn](https://www.linkedin.com/in/mejbaur/)
- Contributions, issues, and PRs are welcome!

---

<p align="center">
  <b>Happy Hacking! 🌸</b>
</p>
