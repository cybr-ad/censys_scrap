#!/usr/bin/env python3
"""
Censys Search & Host IP Scraper (Playwright)
===========================================
Bypasses Cloudflare Turnstile by injecting session cookies exported via Cookie-Editor.
Supports authenticated multi-page scraping, in-memory deduplication, and fast IP extraction.
"""

import asyncio
import json
import os
import random
import re
from urllib.parse import quote_plus
from playwright.async_api import async_playwright

COOKIES_FILE = "cookies.json"
OUTPUT_FILE = "censys-query2ip.txt"
DEFAULT_QUERY = "host.services.port: 88 and host.services.port: 389"


async def random_delay(min_sec: float = 1.0, max_sec: float = 2.0):
    """Adds a human-like delay between browser navigation steps."""
    await asyncio.sleep(random.uniform(min_sec, max_sec))


def parse_cookie_input(raw_input: str) -> list:
    """
    Parses cookies from:
    1. Local JSON file path (e.g. cookies.json)
    2. JSON string (from Cookie-Editor export)
    3. HTTP Cookie header string ('name=val; name2=val2')
    """
    raw = raw_input.strip()
    if os.path.exists(raw):
        try:
            with open(raw, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except Exception as e:
            print(f"[!] Error reading file '{raw}': {e}")
            return []

    cookies = []

    # Format 1: JSON array from Cookie-Editor
    if raw.startswith("[") or raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for c in data:
                    c_dict = {
                        "name": str(c.get("name")),
                        "value": str(c.get("value")),
                        "domain": str(c.get("domain", ".censys.io")),
                        "path": str(c.get("path", "/"))
                    }
                    if "sameSite" in c and c["sameSite"] in ["Strict", "Lax", "None"]:
                        c_dict["sameSite"] = c["sameSite"]
                    cookies.append(c_dict)
                return cookies
            elif isinstance(data, dict) and "cookies" in data:
                return data["cookies"]
        except Exception:
            pass

    # Format 2: HTTP Cookie header string
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, val = part.split("=", 1)
        name = key.strip()
        value = val.strip()
        if name and value:
            domain = "platform.censys.io" if ("csrf" in name.lower() or "platform" in name.lower()) else ".censys.io"
            cookies.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/"
            })

    return cookies


async def launch_browser(p, headless: bool = False):
    """
    Launches Chrome, Edge, or bundled Chromium with anti-detection flags.
    Prioritizes installed Google Chrome for the highest bypass compatibility.
    """
    browser_args = [
        "--disable-blink-features=AutomationControlled",
        "--start-maximized",
        "--no-sandbox",
        "--disable-infobars",
        "--disable-features=IsolateOrigins,site-per-process",
        "--lang=en-US,en"
    ]

    for channel in ["chrome", "msedge", None]:
        try:
            kwargs = {
                "headless": headless,
                "args": browser_args
            }
            if channel:
                kwargs["channel"] = channel
                browser = await p.chromium.launch(**kwargs)
                print(f"[+] Launched browser using system engine: '{channel.upper()}'")
                return browser
            else:
                browser = await p.chromium.launch(**kwargs)
                print("[+] Launched browser using Playwright Chromium")
                return browser
        except Exception:
            continue

    return await p.chromium.launch(headless=headless, args=browser_args)


async def extract_ips_from_page(page) -> set:
    """
    Extracts all IPv4 addresses in the V8 engine runtime (~15ms).
    Prevents CDP locator timeouts on large search result cards.
    """
    found_ips = set()
    try:
        raw_ips = await page.evaluate("""() => {
            const ips = new Set();
            const ipv4Regex = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/g;

            // 1. Direct host links: href="/hosts/x.x.x.x"
            const hostLinks = document.querySelectorAll("a[href*='/hosts/']");
            for (const a of hostLinks) {
                const hrefMatch = a.href.match(/\\/hosts\\/([0-9]{1,3}(?:\\.[0-9]{1,3}){3})/);
                if (hrefMatch) ips.add(hrefMatch[1]);
                const textMatches = (a.innerText || "").match(ipv4Regex);
                if (textMatches) {
                    for (const ip of textMatches) ips.add(ip);
                }
            }

            // 2. Highlighting elements and card text
            const cards = document.querySelectorAll("[data-testid='search-results-list'], main, div[class*='SearchResult']");
            for (const card of cards) {
                const textMatches = (card.innerText || "").match(ipv4Regex);
                if (textMatches) {
                    for (const ip of textMatches) ips.add(ip);
                }
            }

            return Array.from(ips);
        }""")

        for ip in raw_ips:
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                found_ips.add(ip)

    except Exception as e:
        print(f"[!] Host IP extraction notice: {e}")

    return found_ips


async def wait_for_search_results(page, timeout: int = 35) -> bool:
    """Waits for Censys search result cards to finish rendering."""
    print("[*] Waiting for search results to load...")
    start_time = asyncio.get_event_loop().time()

    while asyncio.get_event_loop().time() - start_time < timeout:
        try:
            err = page.locator("text='Something went wrong'")
            if await err.is_visible(timeout=300):
                print("[!] Encountered 'Something went wrong'. Clicking Refresh...")
                refresh_btn = page.locator("button:has-text('Refresh'), button:has-text('Try again')").first
                if await refresh_btn.is_visible(timeout=600):
                    await refresh_btn.click()
                    await asyncio.sleep(2.0)
                continue
        except Exception:
            pass

        try:
            loading = page.locator("text='Searching every corner of the internet'")
            skeleton = page.locator("[data-testid='search-loading']")
            if (await loading.is_visible(timeout=300)) or (await skeleton.is_visible(timeout=300)):
                await asyncio.sleep(1.0)
                continue
        except Exception:
            pass

        try:
            host_links = page.locator("a[href*='/hosts/']")
            count = await host_links.count()
            if count > 0:
                print(f"[+] Page content ready! Detected {count} host card elements.")
                await asyncio.sleep(0.8)
                return True
        except Exception:
            pass

        try:
            no_results = page.locator("text='Your query returned no results'")
            if await no_results.is_visible(timeout=300):
                print("[*] Censys confirmed 0 results for this query.")
                return True
        except Exception:
            pass

        await asyncio.sleep(0.8)

    return False


async def scrape_censys_search(page, query: str):
    """Executes query on Censys, collects unique IPs in memory, saves to file, and paginates."""
    encoded_query = quote_plus(query)
    search_url = f"https://platform.censys.io/search?q={encoded_query}"

    print(f"\n[*] Navigating to search URL: {search_url}")
    await page.goto(search_url, wait_until="domcontentloaded", timeout=45000)
    await random_delay(1.5, 2.5)

    memory_ips_set = set()
    memory_ips_list = []

    page_num = 1
    max_pages = 50

    while page_num <= max_pages:
        print(f"\n" + "-" * 55)
        print(f" [+] Scraping Page {page_num}...")
        print("-" * 55)

        ready = await wait_for_search_results(page, timeout=35)
        if not ready:
            print("[!] Results did not load within timeout. Attempting extraction on current DOM...")

        page_ips = await extract_ips_from_page(page)
        new_on_page = 0

        for ip in page_ips:
            if ip not in memory_ips_set:
                memory_ips_set.add(ip)
                memory_ips_list.append(ip)
                new_on_page += 1

        print(f"[+] Page {page_num}: Found {len(page_ips)} hosts ({new_on_page} new).")
        print(f"[+] Total unique hosts collected in memory: {len(memory_ips_list)}")

        # Save to output file
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for ip in memory_ips_list:
                f.write(f"{ip}\n")
        print(f"[+] Saved {len(memory_ips_list)} IPs to '{OUTPUT_FILE}'.")

        # Next page navigation
        try:
            next_selectors = [
                "button[aria-label='Next page']:not([disabled])",
                "button[aria-label='Next']:not([disabled])",
                "a[aria-label='Next page']",
                "button:has-text('Next'):not([disabled])",
                "nav[aria-label*='pagination' i] button:not([disabled]):last-child"
            ]

            next_btn = None
            for sel in next_selectors:
                candidate = page.locator(sel).first
                if await candidate.is_visible(timeout=2000):
                    is_dis = await candidate.get_attribute("disabled")
                    aria_dis = await candidate.get_attribute("aria-disabled")
                    if not is_dis and aria_dis != "true":
                        next_btn = candidate
                        break

            if next_btn:
                print("[*] Clicking 'Next' page button...")
                await random_delay(1.5, 2.5)
                await next_btn.click()
                page_num += 1
                await random_delay(2.0, 3.5)
            else:
                page_num += 1
                next_url = f"https://platform.censys.io/search?q={encoded_query}&page={page_num}"
                print(f"[*] Trying next page URL: {next_url}")
                await page.goto(next_url, wait_until="domcontentloaded", timeout=30000)
                await random_delay(1.5, 2.5)

                links_count = await page.locator("a[href*='/hosts/']").count()
                if links_count == 0:
                    print("[*] Reached end of available results or pagination limit.")
                    break

        except Exception as e:
            print(f"[*] Pagination finished: {e}")
            break

    print("\n" + "=" * 65)
    print(" [SUCCESS] Censys search & scraping completed!")
    print(f" [*] Query executed         : {query}")
    print(f" [*] Total unique IPs saved : {len(memory_ips_list)}")
    print(f" [*] Output file location   : {os.path.abspath(OUTPUT_FILE)}")
    print("=" * 65)


async def main():
    print("=" * 65)
    print(" Censys Host IP Scraper (Cookie Injection Edition)")
    print(" 100% Cloudflare Turnstile Bypass via Cookie-Editor")
    print("=" * 65)

    # 1. Search Query
    user_query = input(f"\n[?] Enter Censys Search Query\n    [Default: {DEFAULT_QUERY}]: ").strip()
    if not user_query:
        user_query = DEFAULT_QUERY
        print(f"[*] Using default query: {user_query}")

    # 2. Cookies Setup
    cookies_to_inject = []
    if os.path.exists(COOKIES_FILE):
        print(f"\n[+] Found existing '{COOKIES_FILE}'.")
        reuse = input(f"[?] Reuse saved '{COOKIES_FILE}'? (Y/n, or paste new cookies): ").strip()
        if reuse.lower() in ["", "y", "yes"]:
            with open(COOKIES_FILE, "r", encoding="utf-8") as f:
                cookies_to_inject = parse_cookie_input(f.read())
            print(f"[+] Loaded {len(cookies_to_inject)} cookies from '{COOKIES_FILE}'.")
        else:
            cookies_to_inject = parse_cookie_input(reuse)
            if cookies_to_inject:
                with open(COOKIES_FILE, "w", encoding="utf-8") as f:
                    json.dump(cookies_to_inject, f, indent=2)
                print(f"[+] Updated '{COOKIES_FILE}' with {len(cookies_to_inject)} cookies.")
    else:
        print("\n" + "-" * 55)
        print(" [!] Cookie Setup (Recommended for Full Pagination)")
        print("     Export cookies as JSON from Cookie-Editor extension")
        print("     and paste here (or press Enter to run as Guest):")
        print("-" * 55)
        pasted = input("[?] Paste Cookie JSON (or press Enter to skip): ").strip()
        if pasted:
            cookies_to_inject = parse_cookie_input(pasted)
            if cookies_to_inject:
                with open(COOKIES_FILE, "w", encoding="utf-8") as f:
                    json.dump(cookies_to_inject, f, indent=2)
                print(f"[+] Saved {len(cookies_to_inject)} cookies to '{COOKIES_FILE}' for future runs.")

    # 3. Launch Browser
    print("\n[*] Launching visible browser window (headless=False)...")
    async with async_playwright() as p:
        browser = await launch_browser(p, headless=False)

        context_kwargs = {
            "viewport": None,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "ignore_https_errors": True
        }

        context = await browser.new_context(**context_kwargs)

        # Anti-detection stealth scripts
        await context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.chrome = { runtime: {} };
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
        """)

        # Inject cookies
        if cookies_to_inject:
            try:
                await context.add_cookies(cookies_to_inject)
                print(f"[+] Injected {len(cookies_to_inject)} cookies! Cloudflare bypassed.")
            except Exception as e:
                print(f"[!] Notice adding cookies: {e}")
        else:
            print("[*] Running in Guest Mode (no cookies provided)...")

        page = await context.new_page()

        # 4. Scrape
        await scrape_censys_search(page, user_query)

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
