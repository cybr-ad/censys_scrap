# Censys Host IP Scraper (Playwright Edition)

A powerful, high-performance web scraper for [Censys Platform](https://platform.censys.io) built with Python and Playwright. It bypasses Cloudflare Turnstile CAPTCHA and rate limitations by injecting genuine authenticated session cookies directly from your everyday browser.

---

## 🚀 Key Features
 
* **100% Cloudflare Turnstile Bypass**: Injects clean browser cookies (`auth_v1`, `cf_clearance`, `csrf_v2`), eliminating Turnstile verification loops and bot blocks.
* **Intelligent Query Auto-Correction**: Automatically checks query syntax, waits for Censys's AI **`GENERATED QUERY`** suggestion (e.g. converting `services.service_name: KERBEROS` &rarr; `host.services.protocol: "KERBEROS"`), and executes the corrected query seamlessly.
* **Multi-Line Cookie Support**: Supports direct pasting of formatted, pretty-printed JSON from Cookie-Editor without needing to minify into a single line.
* **Deep Multi-Page Pagination**: Automatically navigates through search result pages (Page 1, 2, 3...) to extract maximum results.
* **Ultra-Fast V8 IP Extraction**: Uses in-browser JavaScript evaluation (`~15ms` per page), eliminating Playwright CDP locator timeouts.
* **In-Memory Tracking & Deduplication**: Ensures every host IP collected is valid, unique, and atomicly saved to file in real time.
* **Resilient Multi-Browser Launch**: Automatically prioritizes your installed **Google Chrome** or **Microsoft Edge** with anti-detection flags.

---

## 📋 Prerequisites & Installation

### 1. Clone or Download the Repository
```bash
git clone https://github.com/cybr-ad/censys_scrap.git
cd censys_scrap
```

### 2. Install Python Dependencies
Ensure you have Python 3.9+ installed, then run:

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

---

## 🍪 How to Get Cookies (1-Click Export)

To scrape beyond page 1 and access deep results using your free Censys account, you need to copy your login cookies from your normal browser.

### Step 1: Install the Cookie-Editor Extension
Install the official **Cookie-Editor** extension from the Chrome Web Store:

👉 **[Download Cookie-Editor for Chrome](https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm?utm_source=chatgpt.com)**

### Step 2: Export Cookies
1. Open your regular browser (Chrome / Edge / Brave).
2. Go to **[https://platform.censys.io](https://platform.censys.io)** and make sure you are logged in.
3. Click the **Cookie-Editor** extension icon in your browser toolbar.
4. Click the **Export** icon at the bottom right corner (**`📄➔`**).
5. Select **Export as JSON** (this instantly copies all cookies to your clipboard in one clean format).

> **Tip:** You can also save the copied JSON directly into a file named `cookies.json` in this project folder!

---

### Windows:
* Double click **`run.bat`**, or run:
  ```powershell
  python censys_scraper.py
  ```

### Debian / Ubuntu / Kali Linux:
* Run the automated setup and launcher script:
  ```bash
  chmod +x run.sh
  ./run.sh
  ```

### Interactive Steps:
1. **Search Query**: Enter your desired query (or press `Enter` to use default `host.services.port: 88 and host.services.port: 389`):
   ```text
   [?] Enter Censys Search Query [Default: host.services.port: 88 and host.services.port: 389]:
   ```
   * **Intelligent Query Auto-Correction**: If you enter a query with deprecated or invalid syntax (e.g. `services.service_name: KERBEROS`), the scraper automatically enters it into Censys, waits for Censys's **`GENERATED QUERY`** suggestion (e.g. `host.services.protocol: "KERBEROS"`), automatically switches to the corrected query, and executes the search!

2. **Cookies Setup**:
   - If `cookies.json` already has valid saved cookies, press `Enter` to reuse them.
   - **Multi-line JSON Supported**: You can paste formatted multi-line JSON directly from Cookie-Editor (`Ctrl + V`) without needing to convert it to a single line! The script automatically detects the closing brackets and parses it.
   - Alternatively, you can paste the JSON directly into `cookies.json` in this folder.
   - *(Optional)* Press `Enter` without pasting to run in **Fast Guest Mode**.

3. **Automated Scraping**:
   - The browser opens in visible GUI mode (`headless=False`).
   - Validates query syntax on Censys, loads results, extracts unique IPs, and paginates automatically.

---

## 📁 Output

All extracted host IP addresses are automatically deduplicated and saved line-by-line to:

```text
censys-query2ip.txt
```

Example output:
```text
177.136.239.193
51.161.195.2
94.130.39.149
212.227.84.107
185.173.104.202
145.131.8.192
...
```

---

## 🛡️ Anti-Detection & Reliability Details

* **No Automation Controlled Flag**: Runs with `--disable-blink-features=AutomationControlled` to hide `navigator.webdriver`.
* **Realistic User-Agent & Headers**: Adopts authentic Chrome headers and language configurations.
* **Persistent Sessions**: Once `cookies.json` is saved locally, future runs will reuse it automatically without prompting you to re-paste.

---

## ⚖️ Disclaimer

This tool is designed for authorized security research, asset inventory, and defensive enumeration. Always adhere to [Censys Terms of Service](https://censys.io/terms-of-service/) and all applicable cybersecurity laws.
