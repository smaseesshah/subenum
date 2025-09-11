#!/usr/bin/env python3
"""
livecheck.py - Probe subdomains for liveness for TEAM INTRUDERS

Behavior:
 - Infers domain for naming in this order:
     1) If input filename looks like "<domain>_<mode>.*" (e.g. google.com_api.txt), use <domain>
     2) Else use sanitized input filename base (without extension)
     3) Else fallback to first live host's normalized domain
 - Exports are written as <domain>_live.* in results/<domain>/
 - Unresolved/dead lists are saved as <domain>_live_dead.txt (same folder)
 - Timeouts and threads read from config when not provided
"""

import argparse
import os
import re
import socket
import concurrent.futures
import requests
from tqdm import tqdm

import util
from util import (
    print_banner, info, ok, warn, error,
    ensure_config, get_domain_results_path, normalize_domain, sanitize_basename,
    save_text, save_json, save_csv, save_html_table
)


# --------- Helpers ---------
def extract_domains_from_file(file_path: str) -> list:
    """Extract domains/subdomains from any text-based file."""
    domains = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()

        # Basic hostname extraction (will find FQDNs and many URLs)
        pattern = re.compile(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")
        for m in pattern.findall(content):
            domains.add(m.strip().lower())

    except Exception as e:
        warn(f"Failed to parse input file {file_path}: {e}")
    return sorted(domains)


def probe_schemes(host: str, timeout: int):
    """Check which schemes (http/https) respond for host and return list of working URLs."""
    live_schemes = []
    for scheme in ("http", "https"):
        url = f"{scheme}://{host}"
        try:
            r = requests.get(url, timeout=timeout, verify=False)
            # treat most 2xx/3xx/4xx (except 5xx) as "responsive"
            if r.status_code < 500:
                live_schemes.append(url)
        except Exception:
            continue
    return live_schemes


def resolve_host(host: str):
    """Return list of resolved IPs or []"""
    try:
        return list(set(socket.gethostbyname_ex(host)[2]))
    except Exception:
        return []


def infer_domain_from_input_filename(input_file: str):
    """
    If filename is like '<domain>_<mode>.(txt|json|csv|html)', return '<domain>'.
    Example: 'uetpeshawar.edu.pk_api.txt' -> 'uetpeshawar.edu.pk'
    Returns None if no such pattern found.
    """
    base = os.path.splitext(os.path.basename(input_file))[0]
    if "_" in base:
        left = base.split("_", 1)[0]
        # sanity check: left should look like a domain (contain a dot and TLD-like suffix)
        if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", left):
            return normalize_domain(left)
    return None


def detect_output_folder_and_default_name(input_file: str, output_base: str, first_live_host: str = None):
    """
    Decide folder and base name to use for results.
    - Prefer domain extracted from input filename if possible.
    - Else prefer provided output_base (sanitized)
    - Else use sanitized input filename base
    - Else fall back to normalized first_live_host
    Returns (folder, base_name, domain_for_name)
    """
    # 1) try to infer domain from input file name (domain_mode.ext)
    inferred = infer_domain_from_input_filename(input_file)
    if inferred:
        domain_for_name = inferred
    else:
        # 2) if output_base provided and looks like '<domain>_live' or contains a domain part, try to use it
        if output_base:
            # if the provided output base contains an underscore with a domain-like left part, prefer that
            if "_" in output_base:
                maybe = output_base.split("_", 1)[0]
                if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", maybe):
                    domain_for_name = normalize_domain(maybe)
                else:
                    # fallback to using sanitized output_base as a name (not domain)
                    domain_for_name = None
            else:
                domain_for_name = None
        else:
            domain_for_name = None

    # 3) If still None, try to use the first_live_host if provided
    if not inferred and not domain_for_name and first_live_host:
        # We want the registered hostname (full), not just label-less
        domain_for_name = normalize_domain(first_live_host)

    # 4) As a final fallback, use sanitized input filename base
    if not domain_for_name:
        base_file = os.path.splitext(os.path.basename(input_file))[0]
        domain_for_name = sanitize_basename(base_file, base_file)

    # Folder is results/<domain_for_name> (normalize for path)
    folder = get_domain_results_path(domain_for_name)
    # Build default base name (unless caller provided explicit output_base)
    if output_base:
        base_name = sanitize_basename(output_base, domain_for_name)
    else:
        base_name = f"{normalize_domain(domain_for_name)}_live"

    return folder, base_name, domain_for_name


# --------- Main Runner ---------
def run_livecheck(input_file: str, output_base: str = None,
                  no_save: bool = False, formats=None,
                  threads: int = None, timeout: int = None,
                  out_format: str = "map"):
    """
    input_file: path to an input file containing subdomains (or mappings or urls)
    output_base: base name (no ext). If None, defaults to <domain>_live (domain inferred)
    formats: list like ["txt","json","csv","html"] or None to use config default
    threads: number of worker threads (if None, read from config.default_threads)
    timeout: request timeout seconds (if None, read from config.default_timeout)
    out_format: one of "map" (domain->ips), "domain" (domains only), "url" (http/https urls)
    """
    print_banner()
    cfg = ensure_config()

    # Use config defaults if not provided
    if threads is None:
        threads = int(cfg.get("default_threads", 30))
    if timeout is None:
        timeout = int(cfg.get("default_timeout", 5))

    domains = extract_domains_from_file(input_file)
    if not domains:
        warn("No domains parsed from input file.")
        return {}, []

    info(f"Loaded {len(domains)} domains from {input_file}")

    live, dead, mapping, urlmap = [], [], {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futs = {executor.submit(probe_schemes, d, timeout): d for d in domains}
        for fut in tqdm(concurrent.futures.as_completed(futs), total=len(futs), desc="Probing"):
            d = futs[fut]
            try:
                schemes = fut.result()
                if schemes:
                    ips = resolve_host(d)
                    mapping[d] = ips
                    urlmap[d] = schemes
                    live.append(d)
                    ok(f"[LIVE] {d} -> {', '.join(ips) if ips else 'unresolved'} ({', '.join(schemes)})")
                else:
                    dead.append(d)
                    warn(f"[DEAD] {d}")
            except Exception as e:
                dead.append(d)
                warn(f"[ERROR] {d}: {e}")

    if not live:
        warn("No live hosts found.")
        return mapping, live

    # Determine folder and base name using improved inference:
    folder, base_name, domain_for_name = detect_output_folder_and_default_name(
        input_file=input_file,
        output_base=output_base,
        first_live_host=live[0] if live else None
    )
    base = os.path.join(folder, base_name)

    if not no_save:
        fmts = formats or cfg.get("export_formats", ["txt", "json", "csv"])

        # Prepare only-resolved mapping for convenience (if you want to filter)
        resolved_only = {s: ips for s, ips in mapping.items() if ips}

        # -------- TEXT --------
        if "txt" in fmts or "all" in fmts:
            lines = []
            if out_format == "map":
                # include mapping lines for each live host (resolved or 'unresolved')
                lines = [f"{d} -> {', '.join(mapping[d]) if mapping[d] else 'unresolved'}" for d in live]
            elif out_format == "domain":
                lines = live
            elif out_format == "url":
                for d in live:
                    lines.extend(urlmap[d])
            save_text(lines, base + ".txt")

        # -------- JSON --------
        if "json" in fmts or "all" in fmts:
            if out_format == "map":
                save_json(mapping, base + ".json")
            elif out_format == "domain":
                save_json(live, base + ".json")
            elif out_format == "url":
                save_json(urlmap, base + ".json")

        # -------- CSV --------
        if "csv" in fmts or "all" in fmts:
            if out_format == "map":
                rows = [[d, ";".join(mapping[d])] for d in live]
                save_csv(rows, ["domain", "ips"], base + ".csv")
            elif out_format == "domain":
                rows = [[d] for d in live]
                save_csv(rows, ["domain"], base + ".csv")
            elif out_format == "url":
                rows = [[d, ";".join(urlmap[d])] for d in live]
                save_csv(rows, ["domain", "urls"], base + ".csv")

        # -------- HTML --------
        if "html" in fmts or "all" in fmts:
            if out_format == "map":
                rows = [[d, ", ".join(mapping[d])] for d in live]
                save_html_table(rows, ["domain", "ips"], base + ".html", title="Livecheck results")
            elif out_format == "domain":
                rows = [[d] for d in live]
                save_html_table(rows, ["domain"], base + ".html", title="Livecheck results")
            elif out_format == "url":
                rows = [[d, ", ".join(urlmap[d])] for d in live]
                save_html_table(rows, ["domain", "urls"], base + ".html", title="Livecheck results")

        # dead file (always in same domain folder)
        if dead:
            save_text(dead, base + "_dead.txt")

    return mapping, live


# --------- Interactive ---------
def interactive_mode(cfg):
    print("\nInteractive mode — Livecheck\n(press Enter to accept defaults)\n")
    infile = input("Input file path: ").strip()
    fmt = input("Output format (map,domain,url) [map]: ").strip() or "map"
    threads_default = cfg.get("default_threads", 30)
    timeout_default = cfg.get("default_timeout", 5)
    threads = input(f"Threads (default {threads_default}): ").strip() or threads_default
    timeout = input(f"Timeout (default {timeout_default}): ").strip() or timeout_default
    output_base = input(f"Output base name [<domain>_live]: ").strip()
    fmts = input("Formats (txt,json,csv,html or 'all') [txt,json,csv]: ").strip()
    if not fmts:
        formats = ["txt", "json", "csv"]
    elif fmts.lower() == "all":
        formats = ["all"]
    else:
        formats = [f.strip() for f in fmts.split(",")]
    ns = input("Skip saving results? (y/N): ").strip().lower() == "y"
    return {
        "input": infile, "format": fmt,
        "threads": int(threads), "timeout": int(timeout),
        "output_base": output_base if output_base else None,
        "formats": formats, "no_save": ns
    }


# --------- CLI ---------
def main():
    print_banner()
    parser = argparse.ArgumentParser(
        prog="livecheck",
        description="Probe subdomains for liveness for TEAM INTRUDERS",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--input", help="Input file path")
    parser.add_argument("-oL", help="Output base name (no extension). Default = <domain>_live")
    parser.add_argument("--format", choices=["map", "domain", "url"], default="map", help="Output format for live hosts")
    parser.add_argument("-t", "--threads", type=int, help="Threads (override config.default_threads)")
    parser.add_argument("--timeout", type=int, help="Timeout seconds (override config.default_timeout)")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats to export (txt,json,csv,html,all). Default=config/export_formats")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--interactive", action="store_true", help="Run interactive wizard for livecheck")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()
    cfg = ensure_config()

    if args.interactive:
        opts = interactive_mode(cfg)
        run_livecheck(
            opts["input"], opts["output_base"], opts["no_save"], opts["formats"],
            opts["threads"], opts["timeout"], opts["format"]
        )
        return

    if not args.input:
        parser.print_help()
        print("\nUsage examples:\n"
              "  python livecheck.py -i results/example_api.txt --format map\n"
              "  python livecheck.py -i subs.txt --format url\n"
              "  python livecheck.py --interactive")
        return

    try:
        run_livecheck(
            args.input,
            args.oL,
            args.no_save,
            args.formats,
            args.threads,   # if None, run_livecheck will read config default
            args.timeout,   # if None, run_livecheck will read config default
            args.format
        )
    except Exception as e:
        if args.debug:
            raise
        error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
