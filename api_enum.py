#!/usr/bin/env python3
"""
api_enum.py - Public & API-based subdomain enumeration for TEAM INTRUDERS

Updated to include only:
  - Public sources: crtsh, wayback
  - API sources: virustotal, securitytrails, otx

Collector functions for removed sources (anubis/shodan/censys) have been removed.
"""
import argparse
import os
import sys
import re
import time
from typing import Dict, Set, List
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

import util
from util import (
    print_banner, info, ok, warn, error, ensure_config, get_domain_results_path,
    save_text, save_json, save_csv, save_html_table, normalize_domain, sanitize_basename,
    get_requests_session, bulk_resolve
)

# default will be overridden in run_api_enum from config
REQUEST_TIMEOUT = None

PUBLIC_SOURCES = ["crtsh", "wayback"]
API_SOURCES = ["virustotal", "securitytrails", "otx"]
ALL_SOURCES = PUBLIC_SOURCES + API_SOURCES


# ----------------- PUBLIC SOURCES -----------------
def collect_crtsh(domain: str, session: requests.Session) -> Set[str]:
    out = set()
    try:
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            warn(f"crt.sh returned HTTP {r.status_code}")
            return out
        try:
            data = r.json()
            for entry in data:
                name = entry.get("name_value") or entry.get("common_name")
                if not name:
                    continue
                for n in str(name).splitlines():
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain):
                        out.add(n)
        except ValueError:
            pattern = re.compile(rf"[\w\.-]+\.{re.escape(domain)}", re.IGNORECASE)
            for m in pattern.findall(r.text):
                candidate = m.strip().lstrip("*.")
                if candidate.endswith(domain):
                    out.add(candidate)
    except Exception as e:
        warn(f"crtsh error: {e}")
    for s in sorted(out):
        info(f"[crtsh] {s}")
    return out


def collect_wayback(domain: str, session: requests.Session) -> Set[str]:
    out = set()
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}&output=json&fl=original&limit=5000"
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            warn(f"Wayback returned HTTP {r.status_code}")
            return out
        data = r.json()
        for item in data[1:]:
            try:
                from urllib.parse import urlparse
                p = urlparse(item[0])
                host = p.hostname
                if host and host.endswith(domain):
                    out.add(host)
            except Exception:
                continue
    except Exception as e:
        warn(f"Wayback error: {e}")
    for s in sorted(out):
        info(f"[wayback] {s}")
    return out


# ----------------- API SOURCES -----------------
def collect_virustotal(domain: str, session: requests.Session, cfg: dict) -> Set[str]:
    out = set()
    api_key = cfg.get("virustotal")
    if not api_key:
        return out
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
        headers = {"x-apikey": api_key}
        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for d in data.get("data", []):
                s = d.get("id")
                if s and s.endswith(domain):
                    out.add(s)
        else:
            warn(f"VirusTotal returned HTTP {r.status_code}")
    except Exception as e:
        warn(f"VirusTotal error: {e}")
    for s in sorted(out):
        info(f"[virustotal] {s}")
    return out


def collect_securitytrails(domain: str, session: requests.Session, cfg: dict) -> Set[str]:
    out = set()
    api_key = cfg.get("securitytrails")
    if not api_key:
        return out
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": api_key}
        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for s in data.get("subdomains", []):
                fqdn = f"{s}.{domain}"
                out.add(fqdn)
        else:
            warn(f"SecurityTrails returned HTTP {r.status_code}")
    except Exception as e:
        warn(f"SecurityTrails error: {e}")
    for s in sorted(out):
        info(f"[securitytrails] {s}")
    return out


def collect_otx(domain: str, session: requests.Session, cfg: dict) -> Set[str]:
    out = set()
    api_key = cfg.get("otx")
    if not api_key:
        return out
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {"X-OTX-API-KEY": api_key}
        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for rec in data.get("passive_dns", []):
                host = rec.get("hostname")
                if host and host.endswith(domain):
                    out.add(host)
        else:
            warn(f"OTX returned HTTP {r.status_code}")
    except Exception as e:
        warn(f"OTX error: {e}")
    for s in sorted(out):
        info(f"[otx] {s}")
    return out


# -------------------------
# dispatch helper
# -------------------------
def collect_dispatch(source: str, domain: str, session: requests.Session, cfg: dict) -> Set[str]:
    s = source.lower()
    if s == "crtsh":
        return collect_crtsh(domain, session)
    if s == "wayback":
        return collect_wayback(domain, session)
    if s == "virustotal":
        return collect_virustotal(domain, session, cfg)
    if s == "securitytrails":
        return collect_securitytrails(domain, session, cfg)
    if s == "otx":
        return collect_otx(domain, session, cfg)
    warn(f"Unknown source: {source}")
    return set()


# -------------------------
# main runner
# -------------------------
def run_api_enum(domain: str,
                 apis: List[str] = None,
                 output_base: str = None,
                 no_save: bool = False,
                 formats: List[str] = None,
                 resolve_timeout: int = None,
                 resolve_threads: int = None) -> Dict[str, List[str]]:
    """
    domain: target domain
    apis: list of sources (or ["all"])
    """
    global REQUEST_TIMEOUT
    print_banner()
    cfg = ensure_config()
    domain = normalize_domain(domain)
    if not domain:
        raise ValueError("Domain required")

    # set request timeout from config default if not set
    if REQUEST_TIMEOUT is None:
        REQUEST_TIMEOUT = int(cfg.get("default_timeout", 5))

    # resolve params
    if resolve_timeout is None:
        resolve_timeout = int(cfg.get("default_timeout", 5))
    if resolve_threads is None:
        resolve_threads = int(cfg.get("default_threads", 20))

    # parse apis input
    req = apis or ["all"]
    if len(req) == 1 and isinstance(req[0], str) and "," in req[0]:
        req = [s.strip() for s in req[0].split(",") if s.strip()]
    req = [r.lower() for r in req]

    # select sources
    if "all" in req:
        selected = ALL_SOURCES[:]
    else:
        selected = [s for s in ALL_SOURCES if s in req]

    info(f"Public+API sources to query: {', '.join(selected)}")

    session = get_requests_session(retries=3, backoff_factor=0.6)

    per_source = {}
    combined = set()

    with ThreadPoolExecutor(max_workers=min(len(selected), 6) or 1) as ex:
        futures = {}
        # submit tasks and print upfront missing-key warnings for API sources
        for src in selected:
            if src in ["virustotal", "securitytrails", "otx"] and not cfg.get(src):
                warn(f"{src.capitalize()} API key missing; skipping {src}.")
                per_source[src] = []
                continue
            futures[ex.submit(collect_dispatch, src, domain, session, cfg)] = src

        # progress bar
        pbar = tqdm(total=len(selected), desc="Collecting", unit="source")
        # update pbar for already skipped sources
        skipped = len([s for s in selected if s in per_source and not per_source[s]])
        for _ in range(skipped):
            pbar.update(1)

        for fut in as_completed(list(futures.keys())):
            src = futures[fut]
            try:
                subs = fut.result()
                per_source[src] = sorted(subs)
                combined.update(subs)
                if subs:
                    ok(f"{src}: found {len(subs)} entries")
                else:
                    warn(f"{src}: found 0 entries")
            except Exception as e:
                warn(f"{src} failed: {e}")
                per_source[src] = []
            pbar.update(1)
        pbar.close()

    if not combined:
        warn("No subdomains discovered by selected sources.")
        return per_source

    info(f"Total unique subdomains found: {len(combined)}")

    # Resolve discovered hostnames to IPs
    info("Resolving discovered hostnames to IPs...")
    mapping, unresolved = bulk_resolve(sorted(combined), timeout=resolve_timeout, workers=resolve_threads)

    # prepare outputs
    domain_dir = get_domain_results_path(domain)
    base_name = sanitize_basename(output_base or f"{normalize_domain(domain)}_api", domain)
    base = os.path.join(domain_dir, base_name)

    fmts = formats or cfg.get("export_formats", ["txt", "json", "csv"])

    if not no_save:
        # only resolved entries in main exports
        resolved = {s: ips for s, ips in mapping.items() if ips}

        if "txt" in fmts or "all" in fmts:
            lines = [f"{s} -> {', '.join(resolved[s])}" for s in sorted(resolved)]
            save_text(lines, base + ".txt")

        if "json" in fmts or "all" in fmts:
            save_json(resolved, base + ".json")

        if "csv" in fmts or "all" in fmts:
            rows = [[s, ";".join(resolved[s])] for s in sorted(resolved)]
            save_csv(rows, ["subdomain", "ips"], base + ".csv")

        if "html" in fmts or "all" in fmts:
            rows = [[s, ", ".join(resolved[s])] for s in sorted(resolved)]
            save_html_table(rows, ["subdomain", "ips"], base + ".html", title=f"API results for {domain}")

        if unresolved:
            save_text(unresolved, base + "_unres.txt")

    ok("API enumeration complete.")
    return per_source


# -------------------------
# CLI / interactive
# -------------------------
def interactive_wizard(cfg):
    print("\nInteractive wizard — API enumeration\n(press Enter to accept defaults)\n")
    domain = input("Target domain (example.com): ").strip()
    while not domain:
        domain = input("Target domain is required. Enter target domain: ").strip()

    default_sources = ",".join(ALL_SOURCES)
    srcs = input(f"APIs to use (comma list) [{default_sources}]: ").strip() or default_sources
    apis = [s.strip() for s in srcs.split(",")]

    default_base = f"{normalize_domain(domain)}_api"
    out = input(f"Output base name [{default_base}]: ").strip() or default_base

    cfg_formats = cfg.get("export_formats", ["txt", "json", "csv"])
    default_formats = ",".join(cfg_formats)
    fmt_in = input(f"Formats (csv,json,txt,html or 'all') [{default_formats}]: ").strip() or default_formats
    formats = [s.strip() for s in fmt_in.split(",")] if fmt_in else None

    ns = input("Skip saving results? (y/N): ").strip().lower()
    no_save = True if ns == "y" else False

    return {"domain": domain, "apis": apis, "output_base": out, "formats": formats, "no_save": no_save}


def print_help_examples():
    print("""
Examples:
  python api_enum.py -d example.com
  python api_enum.py -d example.com --apis crtsh,virustotal
  python api_enum.py --interactive

Notes:
 - Put API keys in config/config.json (virustotal, securitytrails, otx)
 - Missing API keys will be skipped with a warning.
 - Output base (-oA) should be a name without extension (it will be sanitized).
""")

def main():
    print_banner()
    cfg = ensure_config()

    parser = argparse.ArgumentParser(prog="api_enum", description="API/OSINT enumeration for TEAM INTRUDERS")
    parser.add_argument("-d", "--domain", required=False, help="Target domain")
    parser.add_argument("--apis", nargs="*", help="APIs to use")
    parser.add_argument("-oA", help="Output base name (no extension)")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats (txt,json,csv,html,all)")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--interactive", action="store_true", help="Interactive wizard")
    parser.add_argument("--debug", action="store_true", help="Show debug tracebacks on error")

    if len(sys.argv) == 1:
        parser.print_help()
        print_help_examples()
        return

    args = parser.parse_args()

    try:
        if args.interactive:
            opts = interactive_wizard(cfg)
            run_api_enum(opts["domain"], apis=opts["apis"], output_base=opts["output_base"],
                         no_save=opts["no_save"], formats=opts["formats"])
            return

        domain = args.domain or input("Enter domain: ").strip()
        if not domain:
            print("Domain required. Exiting.")
            return

        run_api_enum(domain, apis=args.apis or ["all"], output_base=args.oA,
                     no_save=args.no_save, formats=args.F)

    except Exception as e:
        if getattr(args, "debug", False):
            raise
        error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
