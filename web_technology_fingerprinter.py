#!/usr/bin/env python3
"""
Web Technology Fingerprinter
A passive + optional active web technology detection tool.

Author: T4z4r
Date: November 02, 2025
Country: TZ
License: MIT
"""

import re
import json
import sys
import time
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from typing import Dict, List, Optional, Any

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


# ====================================================================
# TOOL INFO
# ====================================================================
__tool__ = "Web Technology Fingerprinter"
__version__ = "2.1.0"
__author__ = "T4z4r"
__date__ = "November 10, 2025"
__country__ = "TZ"


# ====================================================================
# 1. TECHNOLOGY DATABASE (Regex → Name + Optional Version)
# ====================================================================
TECH_DB = {
    # ---- Web Servers ------------------------------------------------
    "server": {
        r"Apache(?:/([\d\.]+))?"                    : "Apache",
        r"nginx(?:/([\d\.]+))?"                     : "nginx",
        r"Microsoft-IIS(?:/([\d\.]+))?"             : "IIS",
        r"cloudflare"                               : "Cloudflare",
        r"openresty(?:/([\d\.]+))?"                 : "OpenResty",
        r"LiteSpeed"                                : "LiteSpeed",
        r"GWS"                                      : "Google Web Server",
        r"awselb"                                   : "AWS ELB",
        r"Netlify"                                  : "Netlify",
        r"Vercel"                                   : "Vercel",
        r"CloudFront"                               : "Amazon CloudFront",
        r"Fastly"                                   : "Fastly",
        r"Akamai"                                   : "Akamai",
    },

    # ---- Frameworks & CMS -------------------------------------------
    "framework": {
        r"Django/([\d\.]+)"                         : "Django",
        r"Laravel"                                  : "Laravel",
        r"Express"                                  : "Express",
        r"Ruby on Rails"                            : "Ruby on Rails",
        r"ASP\.NET"                                 : "ASP.NET",
        r"Spring"                                   : "Spring",
        r"Flask"                                    : "Flask",
        r"FastAPI"                                  : "FastAPI",
        r"NestJS"                                   : "NestJS",
        r"CodeIgniter"                              : "CodeIgniter",
        r"Symfony"                                  : "Symfony",
        r"Phusion Passenger"                        : "Phusion Passenger",
        r"WordPress"                                : "WordPress",
        r"Joomla"                                   : "Joomla",
        r"Drupal"                                   : "Drupal",
        r"Magento"                                  : "Magento",
        r"PrestaShop"                               : "PrestaShop",
        r"Shopify"                                  : "Shopify",
        r"Ghost(?:\.org)?"                          : "Ghost",
        r"Strapi"                                   : "Strapi",
        r"SvelteKit"                                : "SvelteKit",
        r"Gatsby"                                   : "Gatsby",
        r"Hugo"                                     : "Hugo",
        r"Next\.js"                                 : "Next.js",
        r"Nuxt\.js"                                 : "Nuxt.js",
        r"Wix"                                      : "Wix",
        r"Squarespace"                              : "Squarespace",
    },

    # ---- Databases --------------------------------------------------
    "database": {
        r"mysql|mariadb"                            : "MySQL/MariaDB",
        r"postgres|postgresql"                      : "PostgreSQL",
        r"mongodb"                                  : "MongoDB",
        r"sqlite"                                   : "SQLite",
        r"oracle"                                   : "Oracle",
        r"redis"                                    : "Redis",
        r"couchdb"                                  : "CouchDB",
        r"cassandra"                                : "Cassandra",
        r"firebase"                                 : "Firebase",
    },

    # ---- JavaScript Libraries ---------------------------------------
    "jslib": {
        r"jQuery(?: \(?v?([\d\.]+)\)?)?"            : "jQuery",
        r"React(?:/([\d\.]+))?"                     : "React",
        r"Vue(?:\.js)?(?:/([\d\.]+))?"              : "Vue.js",
        r"Angular(?:JS)?(?:/([\d\.]+))?"            : "Angular",
        r"Bootstrap(?:/([\d\.]+))?"                 : "Bootstrap",
        r"Alpine\.js"                               : "Alpine.js",
        r"Tailwind"                                 : "Tailwind CSS",
        r"Three\.js"                                : "Three.js",
        r"D3\.js"                                   : "D3.js",
        r"Lodash"                                   : "Lodash",
        r"Moment\.js"                               : "Moment.js",
        r"GSAP"                                     : "GSAP",
        r"Chart\.js"                                : "Chart.js",
    },

    # ---- Programming Languages --------------------------------------
    "language": {
        r"PHP(?:/([\d\.]+))?"                       : "PHP",
        r"Node\.js"                                 : "Node.js",
        r"Go(?:/([\d\.]+))?"                        : "Go",
        r"Java"                                     : "Java",
        r"\.NET Core"                               : ".NET Core",
        r"Python"                                   : "Python",
        r"Ruby"                                     : "Ruby",
    },

    # ---- Analytics & Other ------------------------------------------
    "other": {
        r"Google Analytics"                         : "Google Analytics",
        r"gtag\.js"                                 : "Google Tag Manager",
        r"fb-root|fbq\("                            : "Facebook Pixel",
        r"HubSpot"                                  : "HubSpot",
        r"Hotjar"                                   : "Hotjar",
        r"Stripe"                                   : "Stripe",
        r"PayPal"                                   : "PayPal",
        r"Intercom"                                 : "Intercom",
        r"Zendesk"                                  : "Zendesk",
    },
}


# ====================================================================
# 2. ACTIVE PROBING PATHS (Only used if --active is enabled)
# ====================================================================
ACTIVE_PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/adminer.php",
    "/phpMyAdmin/index.php",
    "/pma/",
    "/server-status",
    "/.env",
    "/web.config",
    "/wp-config.php.bak",
    "/config.php",
    "/debug/default/view",
    "/server-info",
    "/laravel/.env",
    "/admin/",
    "/admin/login",
]


# ====================================================================
# 3. CORE FINGERPRINTING ENGINE
# ====================================================================
class WebTechFingerprinter:
    def __init__(self, timeout: int = 10, user_agent: str = None, active: bool = False):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent or (
            f"{__tool__}/{__version__} (+https://github.com/t4z4r)"
        )
        self.timeout = timeout
        self.active = active

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            return resp
        except Exception as e:
            print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
            return None

    def _match_group(self, patterns: Dict[str, str], text: str) -> List[Dict]:
        findings = []
        for pattern, name in patterns.items():
            m = re.search(pattern, text, re.I)
            if m:
                version = m.group(1) if len(m.groups()) > 0 else None
                findings.append({"name": name, "version": version})
        return findings

    def _detect_from_headers(self, headers: Dict[str, str]) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        for cat, patterns in TECH_DB.items():
            result[cat].extend(self._match_group(patterns, blob))
        return result

    def _detect_from_html(self, html: str, url: str) -> Dict[str, List[Dict]]:
        result = defaultdict(list)
        soup = BeautifulSoup(html, "html.parser")

        # Meta generator
        for meta in soup.find_all("meta", attrs={"name": re.compile(r"generator", re.I)}):
            content = meta.get("content", "")
            for cat, patterns in TECH_DB.items():
                result[cat].extend(self._match_group(patterns, content))

        # Scripts & links
        for tag in soup.find_all(["script", "link"], src=True):
            src = tag.get("src") or tag.get("href", "")
            full_url = urljoin(url, src)
            for cat, patterns in TECH_DB.items():
                result[cat].extend(self._match_group(patterns, full_url))

        # Inline scripts
        for script in soup.find_all("script"):
            if script.string:
                for cat, patterns in TECH_DB.items():
                    result[cat].extend(self._match_group(patterns, script.string))

        # Path-based CMS detection
        lower_html = html.lower()
        path_signatures = {
            "WordPress": ["/wp-includes/", "/wp-content/", "wp-json", "wordpress"],
            "Magento": ["/magento/", "/skin/frontend/", "mage/"],
            "PrestaShop": ["/prestashop/", "ps_", "prestashop"],
            "Shopify": ["shopify", "checkout.shopify.com", "myshopify.com"],
            "Ghost": ["ghost.org", "/content/images/", "ghost"],
            "Strapi": ["/admin", "strapi.io"],
            "Laravel": ["/laravel/", "laravel_session"],
            "Joomla": ["/joomla/", "joomla!"],
            "Drupal": ["/drupal/", "drupal.js"],
        }
        for tech, paths in path_signatures.items():
            if any(p in lower_html for p in paths):
                result["framework"].append({"name": tech, "version": None})

        return result

    def _extract_php_version(self, html: str) -> Optional[str]:
        m = re.search(r"PHP Version ([\\d\.]+)", html, re.I)
        return m.group(1) if m else None

    def _get_page_title(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("title")
        return tag.get_text(strip=True)[:60] if tag else "No Title"

    def _active_probe(self, base_url: str) -> Dict[str, List[Dict]]:
        if not self.active:
            return {}

        print("\n" + "="*60)
        print(" ACTIVE PROBING MODE ")
        print("="*60)
        print("WARNING: You are about to send multiple requests to the target.")
        print("Only proceed if you have explicit permission to test this system.\n")
        confirm = input("Type 'YES' to continue with active scanning: ").strip().upper()
        if confirm != "YES":
            print("[*] Active probing cancelled by user.")
            return {}

        findings = defaultdict(list)
        print(f"\n[*] Probing {len(ACTIVE_PATHS)} common paths...")
        for path in tqdm(ACTIVE_PATHS, desc="Scanning", unit="path"):
            url = urljoin(base_url + "/", path)
            resp = self._fetch(url)
            if resp and resp.status_code in (200, 301, 302, 403):
                title = self._get_page_title(resp.text)
                findings["active"].append({
                    "path": path,
                    "status": resp.status_code,
                    "title": title
                })

                content = resp.text.lower()
                if "phpinfo()" in content or "system information" in content:
                    ver = self._extract_php_version(resp.text)
                    findings["language"].append({"name": "PHP", "version": ver})
                if "adminer" in content:
                    findings["database"].append({"name": "Adminer", "version": None})
                if ".env" in path and any(k in content for k in ["db_", "password", "secret"]):
                    findings["other"].append({"name": "Exposed .env", "version": None})

            time.sleep(0.3)
        return dict(findings)

    def fingerprint(self, target_url: str) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "https://" + target_url
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        resp = self._fetch(target_url)
        if not resp:
            return {"error": "Failed to fetch target"}

        findings = defaultdict(list)

        # Passive: Headers
        findings.update(self._detect_from_headers(resp.headers))

        # Passive: HTML
        if "text/html" in resp.headers.get("content-type", ""):
            findings.update(self._detect_from_html(resp.text, resp.url))

        # Passive: Cookies
        for cookie in self.session.cookies:
            for cat, patterns in TECH_DB.items():
                findings[cat].extend(self._match_group(patterns, cookie.name))
                findings[cat].extend(self._match_group(patterns, cookie.value))

        # Active probing
        active_findings = self._active_probe(base_url)
        if active_findings:
            findings.update(active_findings)

        # Deduplicate
        final = {}
        for cat, items in findings.items():
            seen = set()
            uniq = []
            for it in items:
                key = (
                    cat,
                    it["name"],
                    it.get("version") or "",
                    it.get("path") or "",
                    it.get("title") or ""
                )
                if key not in seen:
                    seen.add(key)
                    uniq.append(it)
            if uniq:
                final[cat] = uniq

        return {
            "tool": __tool__,
            "version": __version__,
            "author": __author__,
            "date": __date__,
            "country": __country__,
            "target": resp.url,
            "status_code": resp.status_code,
            "active_mode": self.active,
            "detected": dict(final)
        }


# ====================================================================
# 4. REPORTING
# ====================================================================
def print_banner():
    banner = f"""
    {__tool__} v{__version__}
    Author: {__author__} | {__country__} | {__date__}
    {"="*60}
    """
    print(banner)

def print_report(report: Dict):
    print_banner()
    print(f"Target URL : {report.get('target')}")
    print(f"HTTP Status: {report.get('status_code')}")
    print(f"Active Mode: {'YES' if report.get('active_mode') else 'NO'}\n")

    if "error" in report:
        print(f"Error: {report['error']}")
        return

    detected = report.get("detected", {})
    order = ["server", "framework", "database", "jslib", "language", "other", "active"]

    for cat in order:
        items = detected.get(cat, [])
        if not items:
            continue
        print(f"{cat.upper():<12} :")
        for it in items:
            ver = f" (v{it['version']})" if it.get("version") else ""
            path = f" [{it['path']}]" if it.get("path") else ""
            title = f" → {it.get('title')}" if it.get("title") else ""
            print(f"  • {it['name']}{ver}{path}{title}")
        print()


# ====================================================================
# 5. CLI
# ====================================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description=f"{__tool__} - Detect web technologies (passive + optional active)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("-o", "--output", choices=["pretty", "json"], default="pretty",
                        help="Output format")
    parser.add_argument("--active", action="store_true",
                        help="Enable active probing (requires 'YES' confirmation)")
    parser.add_argument("--no-banner", action="store_true", help="Hide banner")
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    if args.active:
        print("[!] Active mode enabled. You will be asked to confirm.")

    fp = WebTechFingerprinter(timeout=args.timeout, active=args.active)
    result = fp.fingerprint(args.url)

    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings()
    main()