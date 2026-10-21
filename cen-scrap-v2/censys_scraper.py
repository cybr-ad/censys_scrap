#!/usr/bin/env python3
"""
Censys Intelligent Host IP Scraper (Absolute Patience Edition)
==============================================================
- Waits up to 5 minutes for Censys to finish "Analyzing distribution..."
- Polling is slowed down to 3s to prevent React SPA interference.
- Detects "Something went wrong" -> Waits -> Clicks "Refresh" button.
- Auto-corrects wrong queries using Censys suggestions.
"""

import asyncio
import json
import os
import random
import re
import sys
sys.dont_write_bytecode = True

# Ensure unbuffered real-time output on Windows
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

# Dual logging: Automatically flush to console AND write to scraper.log
import builtins
_orig_print = builtins.print
LOG_FILE = "scraper.log"

def _tee_print(*args, **kwargs):
    kwargs.setdefault("flush", True)
    _orig_print(*args, **kwargs)
    try:
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        msg = sep.join(str(a) for a in args) + end
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(msg)
    except Exception:
        pass

builtins.print = _tee_print

# Clean any pycache folders in project directory
pycache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__")
if os.path.exists(pycache_dir):
    try:
        import shutil
        shutil.rmtree(pycache_dir, ignore_errors=True)
    except Exception:
        pass

import time
from typing import Optional, Set, Tuple, List
from urllib.parse import quote_plus
from playwright.async_api import async_playwright

COOKIES_FILE    = "cookies.json"
QUERIES_DB_FILE = "queries_db.json"
OUTPUT_FILE     = "censys-query2ip.txt"
DEFAULT_QUERY   = "host.services.port: 88 and host.services.port: 389"

# --- Timing & Safety Knobs ---
PAGE_LOAD_TIMEOUT         = 300    # 5 Minutes! (Censys free plan takes time)
PAGE_POLL_INTERVAL        = 3.0    # 3 seconds (do NOT interfere with SPA render)
PAGE_DISPLAY_PAUSE        = 2.0
PAGINATION_DELAY_MIN      = 2.0
PAGINATION_DELAY_MAX      = 3.0
SCROLL_STEPS              = 4
SCROLL_STEP_WAIT          = 1.0
QUERY_CONVERSION_MAX_WAIT = 15
PASTE_SETTLE_SECONDS      = 2.0

HARD_CAP_PAGES            = 500
MAX_PAGE_RETRIES          = 3
PAGE_STABLE_POLLS         = 3      # IPs must be identical for 3 polls
RETRY_BACKOFF_SECONDS     = [5, 10, 20]

# =====================================================================
#  1. Intelligent Query Database
# =====================================================================
def load_queries_db() -> dict:
    if os.path.exists(QUERIES_DB_FILE):
        try:
            with open(QUERIES_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_query_to_db(original_query: str, corrected_query: str, is_valid: bool = True) -> None:
    orig = original_query.strip()
    corr = corrected_query.strip()
    if not orig or not corr: return
    db = load_queries_db()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    db[orig] = {"corrected_query": corr, "is_valid": is_valid, "timestamp": ts}
    if corr not in db:
        db[corr] = {"corrected_query": corr, "is_valid": True, "timestamp": ts}
    try:
        with open(QUERIES_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        print(f"[+] Intelligent DB updated: '{orig}' -> '{corr}'")
    except Exception as e:
        print(f"[!] Could not save queries DB: {e}")

def get_intelligent_query(user_query: str) -> str:
    db = load_queries_db()
    q = user_query.strip()
    if q in db:
        corrected = (db[q].get("corrected_query") or "").strip()
        if corrected and corrected != q:
            print(f"\n[+] Intelligent DB hit: '{q}' -> '{corrected}'")
            return corrected
    return user_query

# =====================================================================
#  2. Output file
# =====================================================================
def load_existing_ips() -> Set[str]:
    existing: Set[str] = set()
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip: existing.add(ip)
            print(f"[+] Loaded {len(existing)} existing IPs.")
        except Exception: pass
    return existing

def append_new_ips_to_file(new_ips: List[str]) -> int:
    if not new_ips: return 0
    try:
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            for ip in new_ips: f.write(f"{ip}\n")
        return len(new_ips)
    except Exception: return 0

async def human_delay(min_sec: float = 1.0, max_sec: float = 2.0, note: str = "") -> None:
    sec = round(random.uniform(min_sec, max_sec), 1)
    if note: print(f"[*] {note} ({sec}s)...")
    await asyncio.sleep(sec)

# =====================================================================
#  3. Cookie & Browser Setup
# =====================================================================
def parse_cookie_input(raw_input: str) -> list:
    raw = (raw_input or "").strip()
    if not raw: return []
    if os.path.exists(raw) and os.path.isfile(raw):
        try:
            with open(raw, "r", encoding="utf-8") as f: raw = f.read().strip()
        except Exception: return []
    if not raw: return []

    cookies = []
    if raw.startswith("[") or raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "cookies" in data: data = data["cookies"]
            if isinstance(data, list):
                for c in data:
                    name = str(c.get("name", "")).strip()
                    val = str(c.get("value", "")).strip()
                    if not name or name.lower() in ("__cf_bm", "_cfuvid", "__cflb"): continue
                    cd = {"name": name, "value": val, "domain": str(c.get("domain", ".censys.io")), "path": str(c.get("path", "/"))}
                    if c.get("sameSite") in ("Lax", "Strict", "None"): cd["sameSite"] = c["sameSite"]
                    if c.get("secure"): cd["secure"] = True
                    if c.get("expirationDate"): cd["expires"] = int(float(c["expirationDate"]))
                    cookies.append(cd)
                return cookies
        except Exception: pass
    return cookies

async def inject_cookies_to_context(context, cookies: list) -> int:
    if not cookies: return 0
    n = 0
    for c in cookies:
        for kw in (
            {"name": c["name"], "value": c["value"], "domain": c.get("domain", ".censys.io"), "path": c.get("path", "/")},
            {"name": c["name"], "value": c["value"], "url": "https://platform.censys.io/"},
        ):
            try:
                await context.add_cookies([kw]); n += 1; break
            except Exception: continue
    return n

async def launch_browser(p, headless: bool = False):
    args = ["--disable-blink-features=AutomationControlled", "--start-maximized", "--no-sandbox"]
    for channel in ("chrome", "msedge", None):
        try:
            kw = {"headless": headless, "args": args}
            if channel: kw["channel"] = channel
            b = await p.chromium.launch(**kw)
            print(f"[+] Browser: {channel.upper() if channel else 'Playwright Chromium'}")
            return b
        except Exception: continue
    return await p.chromium.launch(headless=headless, args=args)

# =====================================================================
#  4. Query Validation & Auto-Correction
# =====================================================================
async def check_search_box_validation(page) -> dict:
    try:
        return await page.evaluate("""() => {
            const input = document.querySelector("textarea#global-search-bar-input, textarea[name='q'], textarea[placeholder*='search' i], input[name='q']");
            if (!input) return { is_green_tick: false, is_red_cross: false, has_generated_query: false };
            const form = input.closest('form') || input.parentElement;
            if (!form) return { is_green_tick: false, is_red_cross: false, has_generated_query: false };

            let isGreen = false, isRed = false;
            for (const el of form.querySelectorAll('i, svg, [class*="icon" i], [class*="valid" i]')) {
                // Ignore clear buttons / reset icons inside clickable elements
                if (el.closest('button[aria-label*="clear" i], button[title*="clear" i], button[name*="clear" i], [data-testid*="clear" i], button:has(svg)')) {
                    const ariaLabel = (el.getAttribute('aria-label') || '').toLowerCase();
                    const title = (el.getAttribute('title') || '').toLowerCase();
                    if (ariaLabel.includes('clear') || title.includes('clear')) continue;
                }
                const cls = (el.className || '').toLowerCase();
                const st = window.getComputedStyle(el);
                const s = cls + ' ' + (st.color || '') + ' ' + (st.fill || '');
                if (s.includes('check') || s.includes('green') || s.includes('#10b981') || s.includes('rgb(16, 185, 129)')) isGreen = true;
                if ((s.includes('error') || s.includes('invalid') || s.includes('#ef4444') || s.includes('rgb(239, 68, 68)')) && !s.includes('clear')) isRed = true;
            }
            const hasGen = /GENERATED QUERY/i.test(document.body ? document.body.innerText : '');
            if (hasGen) { isRed = true; isGreen = false; }
            return { is_green_tick: isGreen && !isRed, is_red_cross: isRed, has_generated_query: hasGen };
        }""")
    except Exception:
        return {"is_green_tick": False, "is_red_cross": False, "has_generated_query": False}

async def extract_censys_generated_query(page) -> Optional[str]:
    try:
        q = await page.evaluate("""() => {
            const bad = /GENERATED QUERY|SYNTAX ERROR|QUERY CONVERSIONS|Learn about/i;
            for (const el of document.querySelectorAll('body *')) {
                if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') continue;
                if (/^GENERATED QUERY$/i.test((el.innerText || '').trim())) {
                    const p = el.parentElement;
                    if (!p) continue;
                    const sib = Array.from(p.children);
                    const i = sib.indexOf(el);
                    for (let j = i + 1; j < sib.length; j++) {
                        const s = (sib[j].innerText || '').trim();
                        if (!s || bad.test(s)) continue;
                        const first = s.split('\\n')[0].trim();
                        if (first.includes('host.') || /:\\s*\\S/.test(first)) return first;
                    }
                }
            }
            return null;
        }""")
        if q: return q.strip()
    except Exception: pass
    return None

async def wait_for_censys_query_conversion(page, max_wait: float = QUERY_CONVERSION_MAX_WAIT) -> Optional[str]:
    print(f"[*] Waiting for Censys suggestion (up to {max_wait}s)...")
    start = time.monotonic()
    while time.monotonic() - start < max_wait:
        s = await extract_censys_generated_query(page)
        if s: return s
        await asyncio.sleep(0.5)
    return None

async def wait_for_cloudflare(page, max_wait: float = 30.0) -> bool:
    start = time.monotonic()
    while time.monotonic() - start < max_wait:
        try:
            title = (await page.title() or "").lower()
            text = (await page.evaluate("() => document.body ? document.body.innerText.toLowerCase() : ''") or "")
            is_cf = ("just a moment" in title or 
                     "security verification" in text or 
                     "verifying you are not a bot" in text or 
                     "performance and security by cloudflare" in text)
            if not is_cf:
                return True
            print("[*] Cloudflare security verification active, waiting for it to clear...")
            await asyncio.sleep(2.0)
        except Exception:
            await asyncio.sleep(1.0)
    return False

async def paste_query_and_search(page, raw_query: str) -> str:
    active_query = get_intelligent_query(raw_query)
    search_url = f"https://platform.censys.io/search?q={quote_plus(active_query)}"

    print(f"\n[*] Navigating directly to Censys Search with query: '{active_query}'...")
    try:
        await page.goto(search_url, wait_until="domcontentloaded", timeout=60000)
    except Exception: pass

    # Ensure Cloudflare challenge (if any) completes
    await wait_for_cloudflare(page, max_wait=30.0)

    # Check if Censys provides an inline query conversion/suggestion for this query
    try:
        suggested = await wait_for_censys_query_conversion(page, max_wait=3.0)
        if suggested and suggested.strip() != active_query.strip():
            print(f"[+] Censys auto-suggestion detected: '{suggested}'")
            save_query_to_db(raw_query, suggested, is_valid=True)
            active_query = suggested.strip()
            print(f"[*] Navigating to corrected query: '{active_query}'...")
            await page.goto(f"https://platform.censys.io/search?q={quote_plus(active_query)}", wait_until="domcontentloaded", timeout=60000)
            await wait_for_cloudflare(page, max_wait=15.0)
    except Exception: pass

    # Brief settle for SPA render
    await asyncio.sleep(2.0)
    return active_query

# =====================================================================
#  5. IP Extraction
# =====================================================================
async def extract_ips_from_page(page) -> Set[str]:
    found: Set[str] = set()
    for _ in range(3):
        try:
            raw = await page.evaluate("""() => {
                const ips = new Set();
                const ipv4Re = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/g;
                const ipv6Re = /\\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\\b/g;
                try {
                    for (const a of document.querySelectorAll("a[href*='/host'], a[href*='/hosts/'], a[href*='/ip/']")) {
                        const href = a.getAttribute('href') || '';
                        const m = href.match(/\\/hosts?\\/([0-9a-fA-F.:_-]+)/);
                        if (m) {
                            const rawIp = m[1].split('/')[0].split('?')[0];
                            if (rawIp) ips.add(rawIp);
                        }
                    }
                } catch(e){}
                try {
                    const main = document.querySelector("main, [data-testid*='search'], div[class*='Results']") || document.body;
                    const skip = 'nav, footer, header, aside, [role="navigation"], form, [role="search"]';
                    for (const el of main.querySelectorAll("a, span, div, h2, h3, h4, p, strong")) {
                        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.closest(skip)) continue;
                        const t = (el.innerText || '').trim();
                        if (!t) continue;
                        const v4Matches = t.match(ipv4Re);
                        if (v4Matches) {
                            for (const ip of v4Matches) {
                                if (ip !== '0.0.0.0' && ip !== '255.255.255.0' && ip !== '127.0.0.1') ips.add(ip);
                            }
                        }
                        const v6Matches = t.match(ipv6Re);
                        if (v6Matches) {
                            for (const ip of v6Matches) {
                                if (ip !== '::1' && !ip.startsWith('fe80:')) ips.add(ip);
                            }
                        }
                    }
                } catch(e){}
                return Array.from(ips);
            }""")
            if raw:
                for ip in raw:
                    ip = ip.strip()
                    parts = ip.split(".")
                    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) and parts[0] not in ("0", "255") and ip != "127.0.0.1":
                        found.add(ip)
                    elif ":" in ip and 2 <= ip.count(":") <= 7:
                        found.add(ip)
            break
        except Exception:
            await asyncio.sleep(1.0)
    return found

# =====================================================================
#  6. Page State Detection (Loading, Errors, Pagination)
# =====================================================================
async def check_page_state(page) -> dict:
    try:
        return await page.evaluate("""() => {
            if (!document.body) return { loading: true, error: false, empty: false, has_results: false };
            const text = document.body.innerText.toLowerCase();
            
            // 1. Check if host cards / search results are rendered
            const hostCards = document.querySelectorAll("a[href*='/hosts/'], a[href*='/host/'], [data-testid*='host'], [class*='host-card']");
            const has_results = hostCards.length > 0;
            
            // 2. Error detection
            const error = text.includes('something went wrong') || text.includes('hang tight') || text.includes('internal server error');
            
            // 3. Empty detection
            const empty = text.includes('no results found') || text.includes('returned 0 results');

            // 4. Loading detection (ONLY if results are not already rendered)
            let loading = false;
            if (!has_results && !empty && !error) {
                const loadingText = text.includes('searching every corner') || 
                                    text.includes('loading results');
                let visibleSkeletons = 0;
                for (const el of document.querySelectorAll('.animate-pulse, [class*="skeleton"]')) {
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) visibleSkeletons++;
                }
                loading = loadingText || visibleSkeletons > 4;
            }

            return { loading: loading, error: error, empty: empty, has_results: has_results };
        }""")
    except Exception:
        return {"loading": True, "error": False, "empty": False, "has_results": False}

async def detect_pagination_info(page) -> dict:
    info = {"total_results": None, "total_pages": None, "per_page": 100, "max_pages": None}
    try:
        data = await page.evaluate("""() => {
            const text = document.body.innerText || '';
            const out = {};
            let m = text.match(/page\\s+\\d+\\s+of\\s+([\\d,]+)/i);
            if (m) out.total_pages = parseInt(m[1].replace(/,/g, ''), 10);
            m = text.match(/(?:showing\\s+)?[\\d,]+\\s*[-–]\\s*[\\d,]+\\s+of\\s+([\\d,]+)/i);
            if (m) out.total_results = parseInt(m[1].replace(/,/g, ''), 10);
            m = text.match(/([\\d,]+)\\s+per\\s+page/i);
            if (m) out.per_page = parseInt(m[1].replace(/,/g, ''), 10);
            return out;
        }""")
        info.update(data)
    except Exception: pass

    if info["total_pages"] is None and info["total_results"]:
        info["total_pages"] = (info["total_results"] + (info["per_page"] or 100) - 1) // (info["per_page"] or 100)
    if info["total_pages"]:
        info["max_pages"] = min(info["total_pages"], HARD_CAP_PAGES)
    return info

# =====================================================================
#  7. Patience Loop (Wait Until Perfectly Loaded)
# =====================================================================
async def wait_for_page_ready(page, page_num: int, active_query: str = "", previous_page_ips: Optional[Set[str]] = None) -> Tuple[str, Set[str]]:
    start_time = time.monotonic()
    last_ips = None
    stable_polls = 0
    retries = 0

    print(f"\\n[*] Monitoring Page {page_num} load state (Timeout: {PAGE_LOAD_TIMEOUT}s)...")

    while time.monotonic() - start_time < PAGE_LOAD_TIMEOUT:
        # STEP 1: Always check for real IPs/Cards first!
        # Do not wait on background widgets/maps if host cards are already loaded.
        current_ips = await extract_ips_from_page(page)

        if current_ips:
            if last_ips is not None and current_ips == last_ips:
                stable_polls += 1
            else:
                stable_polls = 1
            last_ips = current_ips
            
            if stable_polls >= PAGE_STABLE_POLLS:
                print(f"[+] Page {page_num} fully loaded and stable ({len(current_ips)} IPs).")
                return "OK", current_ips
            else:
                print(f"    ... {len(current_ips)} IPs found, ensuring stability ({stable_polls}/{PAGE_STABLE_POLLS})...")
                await asyncio.sleep(PAGE_POLL_INTERVAL)
                continue

        # STEP 2: If no IPs found yet, check page state
        state = await check_page_state(page)

        if state.get("error"):
            print(f"    [!] Error detected ('Something went wrong').")
            if retries < MAX_PAGE_RETRIES:
                retries += 1
                print(f"    [*] Reloading query URL directly (Retry {retries}/{MAX_PAGE_RETRIES})...")
                await asyncio.sleep(3.0)
                try:
                    if active_query:
                        await page.goto(f"https://platform.censys.io/search?q={quote_plus(active_query)}", wait_until="domcontentloaded", timeout=45000)
                    else:
                        await page.reload(wait_until="domcontentloaded", timeout=30000)
                except Exception: pass
                continue
            else:
                print("    [!] Error persisted after max retries. Stopping page.")
                return "ERROR_PERSISTENT", set()

        if state.get("empty"):
            print("[*] Censys reports 0 results.")
            return "ZERO_RESULTS", set()

        if state.get("loading"):
            print("    ... Results are still loading, waiting...")
            await asyncio.sleep(PAGE_POLL_INTERVAL)
            continue

        print("    ... Waiting for host cards to render...")
        await asyncio.sleep(PAGE_POLL_INTERVAL)

    if last_ips:
        print(f"[!] Timeout reached, but found {len(last_ips)} IPs. Proceeding with partial data.")
        return "OK", last_ips
    return "TIMEOUT", set()

async def _scroll_and_finalize(page, page_num: int, current_ips: Set[str]) -> Set[str]:
    print(f"[+] Scrolling to force render all cards on Page {page_num}...")
    gathered = set(current_ips)
    cards = page.locator("a[href*='/hosts/'], a[href*='/host/']")
    
    for _ in range(SCROLL_STEPS):
        try:
            if await cards.count() > 0:
                await cards.last.scroll_into_view_if_needed()
        except Exception: pass
        await asyncio.sleep(SCROLL_STEP_WAIT)
        gathered.update(await extract_ips_from_page(page))

    try:
        await page.evaluate("window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });")
        await asyncio.sleep(1.0)
        gathered.update(await extract_ips_from_page(page))
        await page.evaluate("window.scrollTo({top:0, behavior:'smooth'})")
        await asyncio.sleep(1.0)
    except Exception: pass

    return gathered

# =====================================================================
#  8. Pagination & Main Loop
# =====================================================================
async def scrape_all_pages_one_by_one(page, active_query: str, raw_user_query: str) -> None:
    current_query = active_query
    existing = load_existing_ips()

    page_num = 1
    pages_succeeded = 0
    previous_page_ips: Set[str] = set()
    expected_max_pages: Optional[int] = None
    seen_cursors: Set[str] = set()
    no_new_count = 0

    while page_num <= HARD_CAP_PAGES:
        print("\n" + "=" * 60)
        print(f" [+] PROCESSING PAGE {page_num}")
        if expected_max_pages: print(f"     (Expected total: {expected_max_pages} pages)")
        print("=" * 60)

        status, page_ips = await wait_for_page_ready(page, page_num, active_query=current_query, previous_page_ips=previous_page_ips)

        if status == "ZERO_RESULTS": break
        if status == "ERROR_PERSISTENT": break

        page_ips = await _scroll_and_finalize(page, page_num, page_ips)

        if page_num == 1 and expected_max_pages is None:
            info = await detect_pagination_info(page)
            if info["max_pages"]:
                expected_max_pages = info["max_pages"]
                print("\n" + "★" * 65)
                print(f" [+] PAGINATION DETECTED")
                print(f"     Total results : {info['total_results']:,}")
                print(f"     Total pages   : {expected_max_pages}")
                print("★" * 65 + "\n")

        new_ips = [ip for ip in page_ips if ip not in existing]
        for ip in new_ips: existing.add(ip)

        if new_ips:
            append_new_ips_to_file(new_ips)
            print(f"[+] Saved +{len(new_ips)} NEW IPs. Total unique: {len(existing)}.")
            no_new_count = 0
        else:
            no_new_count += 1
            print(f"[*] No new IPs on this page ({no_new_count}/2 before stopping).")
            if no_new_count >= 2: break

        previous_page_ips = set(page_ips)
        pages_succeeded += 1

        if expected_max_pages and page_num >= expected_max_pages: break

        print(f"\n[*] Preparing to advance to Page {page_num + 1}...")
        next_btn = None
        is_locked = False
        for sel in ("button[name='cursor']", "button[aria-label*='Next' i]", "button:has-text('Next')", "button:has-text('›')"):
            try:
                cand = page.locator(sel).first
                if await cand.is_visible(timeout=1000):
                    html = (await cand.inner_html()).lower()
                    aria_dis = await cand.get_attribute("aria-disabled")
                    is_dis = not await cand.is_enabled() or aria_dis == "true"
                    if "lock" in html or is_dis:
                        is_locked = True
                    else:
                        next_btn = cand
                        break
            except Exception: continue

        if is_locked and not next_btn:
            print("[*] Censys Next button is locked (Free plan / guest limit reached). Finished scraping accessible pages.")
            break

        if not next_btn:
            print("[*] Next button missing/disabled. End of results.")
            break

        prev_url = page.url
        try:
            await next_btn.scroll_into_view_if_needed()
            await asyncio.sleep(0.5)
            await next_btn.click()
        except Exception: break

        for _ in range(15):
            await asyncio.sleep(0.5)
            if page.url != prev_url: break
        
        m = re.search(r"[?&]cursor=([^&]+)", page.url)
        if m:
            cur = m.group(1)
            if cur in seen_cursors:
                print("[!] Cursor already visited. Loop detected. Stopping.")
                break
            seen_cursors.add(cur)

        page_num += 1
        await human_delay(PAGINATION_DELAY_MIN, PAGINATION_DELAY_MAX, f"page {page_num} transition")

    print("\n" + "=" * 65)
    print(" [SUCCESS] Scraping complete.")
    print(f" [*] Total pages collected : {pages_succeeded}")
    print(f" [*] Total unique IPs      : {len(existing)}")
    print("=" * 65)

async def main() -> None:
    print("=" * 65)
    print(" Censys Scraper (Absolute Patience Edition)")
    print("=" * 65)

    if len(sys.argv) > 1:
        user_query = " ".join(sys.argv[1:]).strip()
        print(f"\n[+] Query from arguments: {user_query}")
    else:
        print(f"\n[?] Enter Query\n    [Default: {DEFAULT_QUERY}]: ", end="", flush=True)
        raw_val = input()
        user_query = raw_val.strip() or DEFAULT_QUERY

    cookies = []
    if os.path.exists(COOKIES_FILE):
        try:
            with open(COOKIES_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content: cookies = parse_cookie_input(content)
        except Exception: pass

    async with async_playwright() as p:
        browser = await launch_browser(p, headless=False)
        context = await browser.new_context(
            viewport=None,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            ignore_https_errors=True
        )
        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', { get: () => undefined });")

        if cookies:
            n = await inject_cookies_to_context(context, cookies)
            print(f"[+] Loaded {n} cookies.")

        page = await context.new_page()
        active_query = await paste_query_and_search(page, user_query)
        await scrape_all_pages_one_by_one(page, active_query, raw_user_query=user_query)

        await browser.close()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n[!] Interrupted by user.")