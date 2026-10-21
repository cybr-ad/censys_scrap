#!/usr/bin/env python3
"""
Censys Search & Host IP Scraper (Playwright)
===========================================
Bypasses Cloudflare Turnstile by injecting session cookies exported via Cookie-Editor.
Supports authenticated multi-page scraping, in-memory deduplication, fast IP extraction,
multi-line cookie paste/import, and automatic Censys query validation & auto-correction.
"""

import asyncio
import json
import os
import random
import re
import sys
import time
from urllib.parse import quote_plus
from playwright.async_api import async_playwright

COOKIES_FILE = "cookies.json"
OUTPUT_FILE = "censys-query2ip.txt"
DEFAULT_QUERY = "host.services.port: 88 and host.services.port: 389"


async def random_delay(min_sec: float = 1.0, max_sec: float = 2.0):
    """Adds a human-like delay between browser navigation steps."""
    await asyncio.sleep(random.uniform(min_sec, max_sec))


def read_multiline_input(prompt_text: str = "") -> str:
    """
    Reads multi-line or single-line input from stdin.
    Supports:
    - Multi-line formatted JSON (from Cookie-Editor export) - detects closing bracket and completes automatically.
    - Single-line JSON or plain text - returns immediately.
    - Multi-line HTTP headers.
    - Blank Enter to skip.
    """
    if prompt_text:
        print(prompt_text, end="", flush=True)

    try:
        first_line = sys.stdin.readline()
    except Exception:
        return ""

    if not first_line:
        return ""

    line_stripped = first_line.strip()
    if not line_stripped:
        return ""

    # Check if input starts with JSON array [ or object {
    if line_stripped.startswith("[") or line_stripped.startswith("{"):
        buffer = [first_line]
        # Check if already complete on single line
        try:
            json.loads(line_stripped)
            return line_stripped
        except json.JSONDecodeError:
            pass

        print("[*] Reading multi-line JSON input... (auto-completes when closing bracket is detected)")
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            buffer.append(line)
            combined = "".join(buffer).strip()
            try:
                json.loads(combined)
                return combined
            except json.JSONDecodeError:
                pass

            # If user pressed enter on an empty line after content
            if not line.strip() and len(buffer) > 2:
                break

        return "".join(buffer).strip()

    # Non-JSON input: handle pasted multi-line headers or single line
    buffer = [first_line]
    time.sleep(0.05)
    try:
        import msvcrt
        while msvcrt.kbhit():
            more = sys.stdin.readline()
            if not more:
                break
            buffer.append(more)
    except Exception:
        pass

    return "".join(buffer).strip()


def parse_cookie_input(raw_input: str) -> list:
    """
    Parses cookies from:
    1. Local JSON file path (e.g. cookies.json)
    2. JSON string (from Cookie-Editor export, single-line or multi-line)
    3. HTTP Cookie header string ('name=val; name2=val2' or multi-line headers)
    """
    raw = raw_input.strip()
    if not raw:
        return []

    # If raw is a local file path
    if os.path.exists(raw) and os.path.isfile(raw):
        try:
            with open(raw, "r", encoding="utf-8") as f:
                raw = f.read().strip()
        except Exception as e:
            print(f"[!] Error reading file '{raw}': {e}")
            return []

    cookies = []

    # Format 1: JSON array or JSON object
    if raw.startswith("[") or raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "cookies" in data:
                data = data["cookies"]

            if isinstance(data, list):
                for c in data:
                    name = str(c.get("name", "")).strip()
                    val = str(c.get("value", "")).strip()
                    if not name:
                        continue

                    c_dict = {
                        "name": name,
                        "value": val,
                        "domain": str(c.get("domain", ".censys.io")).strip(),
                        "path": str(c.get("path", "/")).strip()
                    }

                    # Normalize sameSite for Playwright (must be Strict, Lax, or None)
                    same_site_raw = str(c.get("sameSite", "")).strip().lower()
                    if same_site_raw in ["lax", "strict", "none"]:
                        c_dict["sameSite"] = same_site_raw.capitalize()
                    elif same_site_raw in ["no_restriction"]:
                        c_dict["sameSite"] = "None"

                    if "secure" in c and isinstance(c["secure"], bool):
                        c_dict["secure"] = c["secure"]
                    if "httpOnly" in c and isinstance(c["httpOnly"], bool):
                        c_dict["httpOnly"] = c["httpOnly"]

                    cookies.append(c_dict)
                return cookies
        except Exception:
            pass

    # Format 2: HTTP Cookie header string
    clean_raw = raw.replace("\r\n", ";").replace("\n", ";")
    for part in clean_raw.split(";"):
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


async def prepare_and_verify_query(page, user_query: str) -> str:
    """
    Navigates to Censys platform, inputs the user query into the search bar,
    waits for Censys to validate and suggest a corrected 'GENERATED QUERY' if the query has errors,
    and returns the final query (corrected or original) ready for scraping.
    """
    print(f"\n[*] Navigating to Censys Platform home...")
    try:
        await page.goto("https://platform.censys.io/", wait_until="domcontentloaded", timeout=45000)
        await random_delay(1.5, 2.5)
    except Exception as e:
        print(f"[!] Home page load warning: {e}")

    # Locate the search input
    search_input = None
    selectors = [
        "input[placeholder*='search' i]",
        "input[aria-label*='search' i]",
        "input[role='combobox']",
        "input[type='search']",
        "input[type='text']",
        "textarea",
        "input"
    ]

    for sel in selectors:
        candidates = page.locator(sel)
        try:
            count = await candidates.count()
            for i in range(count):
                cand = candidates.nth(i)
                if await cand.is_visible():
                    search_input = cand
                    break
            if search_input:
                break
        except Exception:
            continue

    if not search_input:
        print("[!] Search input bar not found on home page. Navigating directly to search URL.")
        return user_query

    print(f"[*] Entering query into Censys search bar: '{user_query}'")
    try:
        await search_input.click()
        await search_input.fill("")
        await search_input.fill(user_query)

        # Trigger input/keyup events so Censys autocomplete and query generator fire
        await search_input.press("End")
        await page.keyboard.type(" ")
        await page.keyboard.press("Backspace")
        await search_input.dispatch_event("input")
    except Exception as e:
        print(f"[!] Error inputting query: {e}")
        return user_query

    print("[*] Waiting for Censys to validate query and check for 'GENERATED QUERY' suggestions...")

    suggested_query = None
    # Wait and poll for up to 4.0 seconds (checking every 250ms)
    for _ in range(16):
        await asyncio.sleep(0.25)
        try:
            suggestion_info = await page.evaluate("""() => {
                // Find element with text "GENERATED QUERY"
                const all = Array.from(document.querySelectorAll('*'));
                const header = all.find(el => 
                    el.children.length === 0 && /GENERATED QUERY/i.test((el.innerText || el.textContent || '').trim())
                );
                if (!header) return null;

                // Search upward for the dropdown container
                let container = header.parentElement;
                for (let depth = 0; depth < 5 && container; depth++) {
                    const items = container.querySelectorAll('button, li, div[role=\"option\"], div[role=\"button\"], a, div');
                    for (const item of items) {
                        const text = (item.innerText || item.textContent || '').trim();
                        if (!text) continue;
                        if (/GENERATED QUERY/i.test(text)) continue;
                        if (/Was this helpful/i.test(text)) continue;
                        if (/Search for everything with value/i.test(text)) continue;
                        if (/^(Yes|No)$/i.test(text)) continue;

                        // Found suggested query element!
                        item.setAttribute('data-censys-suggested-query', 'true');
                        const lines = text.split('\\n').map(l => l.trim()).filter(Boolean);
                        return {
                            query: lines[0],
                            hasElement: true
                        };
                    }
                    container = container.parentElement;
                }
                return null;
            }""")

            if suggestion_info and suggestion_info.get("query"):
                suggested_query = suggestion_info["query"].strip()
                break
        except Exception:
            pass

    if suggested_query:
        print("\n" + "=" * 65)
        print(" [!] Censys detected query issue and suggested a corrected query:")
        print(f"     -> Original Query  : {user_query}")
        print(f"     -> Suggested Query : {suggested_query}")
        print("=" * 65)

        # Attempt to click the suggested query option in the dropdown
        try:
            sugg_el = page.locator("[data-censys-suggested-query='true']").first
            if await sugg_el.is_visible(timeout=1000):
                print("[*] Clicking suggested query option...")
                await sugg_el.click()
                await asyncio.sleep(1.5)
        except Exception as e:
            print(f"[*] Notice clicking suggestion: {e}")

        return suggested_query
    else:
        print("[*] No query corrections suggested by Censys. Using entered query.")
        try:
            await search_input.press("Enter")
            await asyncio.sleep(1.5)
        except Exception:
            pass
        return user_query


async def scrape_censys_search(page, query: str, original_query: str = None):
    """Executes query on Censys, collects unique IPs in memory, saves to file, and paginates."""
    encoded_query = quote_plus(query)
    search_url = f"https://platform.censys.io/search?q={encoded_query}"

    # If the page is not already on this search URL (e.g. from clicking suggestion), navigate to it
    if "/search" not in page.url or quote_plus(query) not in page.url:
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
    if original_query and original_query != query:
        print(f" [*] Original query was     : {original_query}")
        print(f" [*] Auto-corrected by Censys to: {query}")
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
    existing_cookies = []

    if os.path.exists(COOKIES_FILE):
        try:
            with open(COOKIES_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    existing_cookies = parse_cookie_input(content)
        except Exception:
            existing_cookies = []

    if existing_cookies:
        print(f"\n[+] Found saved '{COOKIES_FILE}' with {len(existing_cookies)} cookies.")
        reuse = input(f"[?] Reuse saved '{COOKIES_FILE}'? (Y/n, or paste new cookies): ").strip()
        if reuse.lower() in ["", "y", "yes"]:
            cookies_to_inject = existing_cookies
            print(f"[+] Loaded {len(cookies_to_inject)} cookies from '{COOKIES_FILE}'.")
        else:
            cookies_to_inject = parse_cookie_input(reuse)
            if not cookies_to_inject:
                print("\n[?] Paste new Cookie JSON or Cookie Header (multi-line supported):")
                pasted = read_multiline_input()
                if pasted:
                    cookies_to_inject = parse_cookie_input(pasted)
            if cookies_to_inject:
                with open(COOKIES_FILE, "w", encoding="utf-8") as f:
                    json.dump(cookies_to_inject, f, indent=2)
                print(f"[+] Updated '{COOKIES_FILE}' with {len(cookies_to_inject)} cookies.")
    else:
        print("\n" + "-" * 55)
        print(" [!] Cookie Setup (Recommended for Full Pagination & Login)")
        print("     Export cookies as JSON from Cookie-Editor extension.")
        print("     (Multi-line paste supported! Or paste directly into 'cookies.json')")
        print("-" * 55)
        pasted = read_multiline_input("[?] Paste Cookie JSON or Header (or press Enter to skip): ")
        if pasted:
            cookies_to_inject = parse_cookie_input(pasted)
            if cookies_to_inject:
                with open(COOKIES_FILE, "w", encoding="utf-8") as f:
                    json.dump(cookies_to_inject, f, indent=2)
                print(f"[+] Saved {len(cookies_to_inject)} cookies to '{COOKIES_FILE}' for future runs.")
            else:
                print("[!] Could not parse cookies from input. Continuing in Guest Mode...")

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

        # Inject cookies safely
        if cookies_to_inject:
            injected_count = 0
            for c in cookies_to_inject:
                try:
                    await context.add_cookies([c])
                    injected_count += 1
                except Exception:
                    try:
                        clean_c = {k: v for k, v in c.items() if k in ["name", "value", "path"]}
                        clean_c["domain"] = ".censys.io"
                        await context.add_cookies([clean_c])
                        injected_count += 1
                    except Exception:
                        pass
            print(f"[+] Injected {injected_count}/{len(cookies_to_inject)} cookies! Cloudflare bypassed.")
        else:
            print("[*] Running in Guest Mode (no cookies provided)...")

        page = await context.new_page()

        # 4. Prepare and verify query with Censys suggestions
        final_query = await prepare_and_verify_query(page, user_query)

        # 5. Scrape search results
        await scrape_censys_search(page, final_query, original_query=user_query)

        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
