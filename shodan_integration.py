#!/usr/bin/env python3
"""
shodan_integration.py - Scrape Shodan host pages for public IPs (no API)

Behavior notes:
 - Defensive fixes applied to avoid TypeErrors when numeric values are None or malformed.
 - Ensures `delay` and `timeout` are numeric and `ports` are filtered before casting to int.
"""
import argparse
import os
import re
import time
import json
import ipaddress
from typing import List, Dict, Tuple

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# project util (must provide these helpers)
import util
from util import (
    print_banner, ensure_config, get_domain_results_path, normalize_domain, sanitize_basename,
    save_text, save_json, save_csv, save_html_table, info, ok, warn, error
)

# attempt to import ip_extractor.run_ip_extractor if present
try:
    import ip_extractor
    run_ip_extractor = getattr(ip_extractor, "run_ip_extractor", None)
except Exception:
    run_ip_extractor = None

# Hard-coded scraper defaults
DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 2
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


# ----------------- Scraper -----------------
def parse_shodan_host(ip: str, timeout: int = DEFAULT_TIMEOUT) -> Dict:
    """
    Scrape Shodan host page and extract hostnames, ports, services, CVEs.
    Returns a dict with keys: ip, status ('ok' or 'not_found'), hostnames, ports, services, cves, error(optional)
    """
    url = f"https://www.shodan.io/host/{ip}"
    result = {"ip": ip, "status": "error", "hostnames": [], "ports": [], "services": [], "cves": [], "error": None}

    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
    except requests.RequestException as e:
        result["error"] = f"request failed: {e}"
        result["status"] = "not_found"
        return result

    if r.status_code == 404:
        result["status"] = "not_found"
        return result

    body = (r.text or "").lower()
    if "404: not found" in body or "no information available for" in body:
        result["status"] = "not_found"
        return result

    if r.status_code != 200:
        result["status"] = "not_found"
        result["error"] = f"HTTP {r.status_code}"
        return result

    try:
        soup = BeautifulSoup(r.text, "html.parser")

        # --- Hostnames ---
        hostnames = []
        try:
            label_candidates = soup.find_all(lambda tag: tag.name in ("label", "h3", "h2") and "hostnames" in tag.get_text(strip=True).lower())
            for lab in label_candidates:
                nxt = lab.find_next()
                if nxt:
                    txt = nxt.get_text(" ", strip=True)
                    for token in re.split(r"[,\s]+", txt):
                        tok = token.strip()
                        if tok:
                            hostnames.append(tok)
        except Exception:
            pass
        # fallback: look for anchor texts looking like hostnames
        if not hostnames:
            for el in soup.find_all("a"):
                txt = el.get_text(strip=True)
                if txt and re.match(r".+\.\w{2,}$", txt):
                    hostnames.append(txt)
        result["hostnames"] = list(dict.fromkeys(hostnames))

        # --- Ports ---
        ports = []
        try:
            port_section = soup.find("div", id="ports") or soup.find("section", {"class": "module--host-ports"}) or soup
            if port_section:
                for a in port_section.find_all(["a", "span"]):
                    txt = a.get_text(strip=True)
                    if txt:
                        # accept only numeric-looking tokens
                        m = re.fullmatch(r"(\d{1,5})", txt)
                        if m:
                            ports.append(m.group(1))
        except Exception:
            pass
        # FIX: filter out non-numeric entries before int() conversion
        try:
            valid_ports = {p for p in ports if p and re.fullmatch(r"\d{1,5}", str(p))}
            ports_sorted = sorted(valid_ports, key=lambda x: int(x)) if valid_ports else []
        except Exception:
            ports_sorted = []
        result["ports"] = ports_sorted

        # --- Services ---
        services = []
        try:
            for h in soup.find_all(lambda tag: tag.name in ("h1", "h2", "h3") and ("banner" in " ".join(tag.get("class") or []))):
                services.append(h.get_text(strip=True))
            for h in soup.find_all("h1", class_="banner-title"):
                services.append(h.get_text(strip=True))
            for pre in soup.find_all("pre", class_="banner"):
                line = pre.get_text(strip=True).splitlines()[0].strip()
                if line:
                    services.append(line.split()[0])
        except Exception:
            pass
        result["services"] = list(dict.fromkeys([s for s in services if s]))

        # --- CVEs ---
        try:
            cves = sorted(set(re.findall(r"(CVE-\d{4}-\d{4,7})", r.text, flags=re.IGNORECASE)))
            result["cves"] = [cve.upper() for cve in cves]
        except Exception:
            result["cves"] = []

        result["status"] = "ok"
        return result

    except Exception as e:
        result["error"] = f"parsing failed: {e}"
        result["status"] = "not_found"
        return result


# ----------------- Input & IP extraction -----------------
def extract_public_ips_from_file(path: str) -> List[str]:
    """
    Extract IPv4 addresses from the file and return only public ones.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read()
    except Exception as e:
        warn(f"Failed to read {path}: {e}")
        return []

    ips_set = set()
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, dict) and "ips" in v:
                    for ip in v.get("ips") or []:
                        ips_set.add(str(ip))
                elif isinstance(v, list):
                    for ip in v:
                        ips_set.add(str(ip))
        elif isinstance(parsed, list):
            for v in parsed:
                ips_set.add(str(v))
    except Exception:
        pass

    for m in re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", data):
        ips_set.add(m)

    public_ips = []
    for ip in sorted(ips_set):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private:
                public_ips.append(ip)
        except Exception:
            continue
    return public_ips


def collect_public_ips(input_file: str, try_run_ip_extractor: bool = True, cfg: dict = None) -> Tuple[List[str], Dict]:
    """
    Return (public_ips, meta). If none found and ip_extractor is available, run it.
    """
    public_ips = extract_public_ips_from_file(input_file)
    if public_ips:
        info(f"Found {len(public_ips)} public IP(s) directly in input file.")
        return public_ips, {"found_in": "input_file"}

    if try_run_ip_extractor and run_ip_extractor:
        info("No public IPs found in input directly — running ip_extractor to resolve hosts.")
        try:
            mapping = run_ip_extractor(input_file, no_save=True)
        except Exception as e:
            warn(f"ip_extractor failed: {e}")
            return [], {}

        ips_set = set()
        mapping_dict = {}
        if isinstance(mapping, tuple) and mapping:
            mapping_dict = mapping[0] if isinstance(mapping[0], dict) else mapping
        elif isinstance(mapping, dict):
            mapping_dict = mapping
        else:
            mapping_dict = mapping or {}

        try:
            for v in mapping_dict.values():
                if isinstance(v, dict) and "ips" in v:
                    for ip in v.get("ips") or []:
                        ips_set.add(str(ip))
                elif isinstance(v, list):
                    for ip in v:
                        ips_set.add(str(ip))
                elif isinstance(v, str):
                    ips_set.add(v)
        except Exception:
            pass

        for ip in sorted(ips_set):
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    public_ips.append(ip)
            except Exception:
                continue

        info(f"ip_extractor returned {len(public_ips)} public IP(s).")
        return public_ips, {"found_in": "ip_extractor", "mapping_count": len(mapping_dict) if isinstance(mapping_dict, dict) else 0}
    else:
        return [], {}


# ----------------- Output helpers -----------------
def infer_domain_from_input_filename(input_file: str):
    base = os.path.splitext(os.path.basename(input_file))[0]
    if "_" in base:
        left = base.split("_", 1)[0]
        if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", left):
            return normalize_domain(left)
    return None


def choose_output_folder_and_basename(input_file: str, output_base: str = None, first_ip: str = None):
    inferred = infer_domain_from_input_filename(input_file)
    domain_for_name = inferred
    if not domain_for_name:
        if first_ip:
            domain_for_name = first_ip.replace(".", "-")
    if not domain_for_name:
        base_file = os.path.splitext(os.path.basename(input_file))[0]
        domain_for_name = sanitize_basename(base_file, base_file)
    folder = get_domain_results_path(domain_for_name)
    if output_base:
        base_name = sanitize_basename(output_base, domain_for_name)
    else:
        base_name = f"{normalize_domain(domain_for_name)}_shodan"
    return folder, base_name, domain_for_name


# ----------------- Main runner -----------------
def run_shodan_integration(input_file: str,
                           output_base: str = None,
                           no_save: bool = False,
                           formats: List[str] = None,
                           timeout: int = DEFAULT_TIMEOUT,
                           delay: int = DEFAULT_DELAY):
    """
    Run sequential scraping of Shodan host pages for public IPs derived from input_file.
    Returns (results_list).
    """
    print_banner()
    cfg = ensure_config()

    # FIX: coerce timeout & delay to safe numeric values
    try:
        timeout = float(timeout) if timeout is not None else float(DEFAULT_TIMEOUT)
    except Exception:
        timeout = float(DEFAULT_TIMEOUT)
    try:
        delay = float(delay) if delay is not None else float(DEFAULT_DELAY)
    except Exception:
        delay = float(DEFAULT_DELAY)
    # ensure non-negative
    if delay < 0:
        delay = float(DEFAULT_DELAY)

    public_ips, meta = collect_public_ips(input_file, try_run_ip_extractor=True, cfg=cfg)
    if not public_ips:
        warn("No public IPs to query on Shodan. Exiting.")
        return []

    info(f"Will query {len(public_ips)} public IP(s) on Shodan (sequentially).")

    results = []

    folder, base_name, domain_for_name = choose_output_folder_and_basename(input_file, output_base, first_ip=public_ips[0] if public_ips else None)
    base = os.path.join(folder, base_name)

    for ip in tqdm(public_ips, desc="Shodan scraping", unit="ip"):
        scraped = parse_shodan_host(ip, timeout=int(timeout))
        if scraped.get("status") == "ok":
            results.append(scraped)
            hostnames = ", ".join(scraped.get("hostnames") or []) or "-"
            ports = ", ".join([str(x) for x in (scraped.get("ports") or [])]) or "-"
            services = ", ".join(scraped.get("services") or []) or "-"
            cves = ", ".join(scraped.get("cves") or []) or "-"
            ok(f"{ip} → Hostnames: {hostnames} | Ports: {ports} | Services: {services} | CVEs: {cves}")
        else:
            scraped["status"] = "not_found"
            results.append(scraped)
            warn(f"{ip} → not found in Shodan")
        # FIX: ensure delay is numeric and usable by time.sleep
        try:
            time.sleep(float(delay))
        except Exception:
            time.sleep(float(DEFAULT_DELAY))

    # Save outputs (no _unres)
    if not no_save:
        fmts = formats or cfg.get("export_formats", ["txt", "json", "csv"])

        # TXT (human readable)
        if "txt" in fmts or "all" in fmts:
            lines = []
            for r in results:
                if r.get("status") == "ok":
                    lines.append(
                        f"{r['ip']} -> Hostnames: {', '.join(r.get('hostnames') or []) or '-'} | "
                        f"Ports: {', '.join([str(x) for x in (r.get('ports') or [])]) or '-'} | "
                        f"Services: {', '.join(r.get('services') or []) or '-'} | "
                        f"CVEs: {', '.join(r.get('cves') or []) or '-'}"
                    )
                else:
                    lines.append(f"{r['ip']} -> not found in Shodan")
            save_text(lines, base + ".txt")

        # JSON
        if "json" in fmts or "all" in fmts:
            save_json(results, base + ".json")

        # CSV
        if "csv" in fmts or "all" in fmts:
            rows = []
            for r in results:
                rows.append([
                    r.get("ip"),
                    ";".join([str(x) for x in (r.get("hostnames") or [])]),
                    ";".join([str(x) for x in (r.get("ports") or [])]),
                    ";".join([str(x) for x in (r.get("services") or [])]),
                    ";".join([str(x) for x in (r.get("cves") or [])]),
                    r.get("status") or ""
                ])
            save_csv(rows, ["ip", "hostnames", "ports", "services", "cves", "status"], base + ".csv")

        # HTML
        if "html" in fmts or "all" in fmts:
            rows = []
            for r in results:
                rows.append([
                    r.get("ip"),
                    ", ".join([str(x) for x in (r.get("hostnames") or [])]),
                    ", ".join([str(x) for x in (r.get("ports") or [])]),
                    ", ".join([str(x) for x in (r.get("services") or [])]),
                    ", ".join([str(x) for x in (r.get("cves") or [])]),
                    r.get("status") or ""
                ])
            save_html_table(rows, ["ip", "hostnames", "ports", "services", "cves", "status"], base + ".html", title=f"Shodan scrape for {domain_for_name}")

    ok(f"Shodan scraping complete. Total entries: {len(results)}")
    return results


# ----------------- CLI / Interactive -----------------
def interactive_mode(cfg):
    print("\nInteractive mode — Shodan scraping (no API)\n(press Enter to accept defaults)\n")
    infile = input("Input file path (ip_extractor output or any supported input): ").strip()
    out = input("Output base name (no extension) [<domain>_shodan]: ").strip()
    fmts = input(f"Formats (txt,json,csv,html or 'all') [{','.join(cfg.get('export_formats', ['txt','json','csv']))}]: ").strip()
    if not fmts:
        formats = cfg.get("export_formats", ["txt","json","csv"])
    elif fmts.lower() == "all":
        formats = ["all"]
    else:
        formats = [s.strip() for s in fmts.split(",")]
    ns = input("Skip saving results? (y/N): ").strip().lower() == "y"
    return {"input": infile, "output_base": out if out else None, "formats": formats, "no_save": ns}


def print_help_examples():
    print("""
Examples:
  python shodan_integration.py -i results/example.com/example.com_ip.txt
  python shodan_integration.py --interactive

Notes:
 - This tool scrapes shodan.io pages sequentially. Defaults: timeout=15s, delay=2s between requests.
 - If a Shodan host page is 404 or contains "No information available", the IP is written as 'not found in Shodan' in main outputs.
 - No separate _unres file is created for Shodan results.
""")


def main():
    print_banner()
    cfg = ensure_config()

    parser = argparse.ArgumentParser(prog="shodan_integration", description="Scrape Shodan host pages (no API)")
    parser.add_argument("-i", "--input", help="Input file path (any supported format)")
    parser.add_argument("-oS", help="Output base name (no extension). Default = <domain>_shodan")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats to export (txt,json,csv,html,all)")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--interactive", action="store_true", help="Run interactive wizard")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    parser.add_argument("--delay", type=int, default=DEFAULT_DELAY, help="Delay between requests (seconds)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    if args.interactive:
        opts = interactive_mode(cfg)
        run_shodan_integration(opts["input"], output_base=opts["output_base"], no_save=opts["no_save"], formats=opts["formats"])
        return

    if not args.input:
        parser.print_help()
        print_help_examples()
        return

    try:
        fmts = args.formats if args.formats else cfg.get("export_formats", ["txt","json","csv"])
        run_shodan_integration(args.input, output_base=args.oS, no_save=args.no_save, formats=fmts, timeout=args.timeout, delay=args.delay)
    except Exception as e:
        if args.debug:
            raise
        error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
