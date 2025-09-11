#!/usr/bin/env python3
"""
ip_extractor.py - Extract IP information from live subdomains.

Features:
 - Accepts input files of many types (txt, json, csv, html, etc.)
 - Extracts subdomains from the input, resolves them (even if IPs present),
   and classifies IPs into private vs public.
 - Determines an "origin" IP per subdomain (first resolved IP).
 - Exports: txt, json, csv, html (or 'all'). Default formats read from config.
 - Interactive mode (--interactive), CLI with -oIP for output basename.
 - Naming convention: results/<domain>/<domain>_ip.* (domain inferred from filename or input)
 - Unresolved subdomains saved to <base>_unres.txt in same domain folder.
"""

import argparse
import os
import re
import socket
import ipaddress
import json
import concurrent.futures
from typing import List, Dict, Set
from tqdm import tqdm

import util
from util import (
    print_banner, info, ok, warn, error,
    ensure_config, get_domain_results_path, normalize_domain, sanitize_basename,
    save_text, save_json, save_csv, save_html_table, bulk_resolve
)


# ---------- Helpers ----------
def extract_hosts_from_file(path: str) -> List[str]:
    """
    Parse an input file and extract FQDN-like hostnames.
    This is intentionally liberal: it will find hostnames inside JSON, CSV, HTML, TXT, etc.
    """
    hosts = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception as e:
        warn(f"Failed to read {path}: {e}")
        return []

    # Regex finds domain-like tokens (including subdomains and many ccTLDs)
    pattern = re.compile(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")
    for m in pattern.findall(content):
        # filter out common false-positives like numbers with dots but no TLD
        token = m.strip().lower()
        # quick sanity check: must have at least one dot and a letter-only TLD of length>=2
        if re.match(r"^[a-z0-9._-]+\.[a-z]{2,}$", token, re.IGNORECASE) or token.count(".") >= 1:
            hosts.add(token)
    return sorted(hosts)


def is_private_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private
    except Exception:
        return False


def infer_domain_from_filename(input_file: str):
    """
    If filename is like '<domain>_<mode>.*', return '<domain>'.
    E.g. 'uetpeshawar.edu.pk_api.txt' -> 'uetpeshawar.edu.pk'
    Otherwise return None.
    """
    base = os.path.splitext(os.path.basename(input_file))[0]
    if "_" in base:
        left = base.split("_", 1)[0]
        if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", left):
            return normalize_domain(left)
    return None


def choose_output_folder_and_basename(input_file: str, output_base: str, first_host: str = None, default_suffix="ip"):
    """
    Decide results folder and base_name.
    Priority:
      1) domain inferred from input filename (<domain>_<mode>)
      2) if output_base provided -> use that (sanitized)
      3) else use sanitized input filename base (no ext)
      4) else fallback to normalized first_host
    Returns (folder, base_name, domain_for_name)
    """
    # 1
    inferred = infer_domain_from_filename(input_file)
    domain_for_name = inferred

    # 2
    if not domain_for_name and output_base:
        # if output_base contains underscore and left part is domain-like, prefer left half
        if "_" in output_base:
            maybe = output_base.split("_", 1)[0]
            if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", maybe):
                domain_for_name = normalize_domain(maybe)
        # otherwise keep None and use output_base only for base_name
    # 3
    if not domain_for_name:
        if output_base:
            # domain_for_name can be derived from output_base or fallback to input filename
            pass
        else:
            base_file = os.path.splitext(os.path.basename(input_file))[0]
            # if base_file like domain_mode -> use left part if it's a domain
            if "_" in base_file:
                left = base_file.split("_", 1)[0]
                if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", left):
                    domain_for_name = normalize_domain(left)
            if not domain_for_name:
                # fallback to sanitized filename base
                domain_for_name = sanitize_basename(base_file, base_file)

    # 4 final fallback:
    if not domain_for_name and first_host:
        domain_for_name = normalize_domain(first_host)

    # folder
    folder = get_domain_results_path(domain_for_name)

    # base_name
    if output_base:
        base_name = sanitize_basename(output_base, domain_for_name)
    else:
        base_name = f"{normalize_domain(domain_for_name)}_{default_suffix}"

    return folder, base_name, domain_for_name


# ---------- Core ----------
def run_ip_extractor(input_file: str,
                     output_base: str = None,
                     no_save: bool = False,
                     formats: List[str] = None,
                     threads: int = None,
                     timeout: int = None) -> Dict[str, Dict]:
    """
    Parse input_file for hosts, resolve them (even if IPs present), classify IPs,
    and export results.
    Returns mapping dict: subdomain -> info dict
    """
    print_banner()
    cfg = ensure_config()

    # defaults from config
    if threads is None:
        threads = int(cfg.get("default_threads", 20))
    if timeout is None:
        timeout = int(cfg.get("default_timeout", 5))

    # extract hosts
    hosts = extract_hosts_from_file(input_file)
    if not hosts:
        warn("No hosts extracted from input file.")
        return {}

    info(f"Extracted {len(hosts)} hosts from {input_file}")

    # Resolve (bulk_resolve prints progress and resolves with threads)
    mapping, unresolved = bulk_resolve(hosts, timeout=timeout, workers=threads)

    # classify and pick origin
    results = {}
    for host in sorted(hosts):
        ips = mapping.get(host, []) or []
        public_ips = [ip for ip in ips if not is_private_ip(ip)]
        private_ips = [ip for ip in ips if is_private_ip(ip)]
        origin = ips[0] if ips else None
        results[host] = {
            "ips": ips,
            "origin": origin,
            "public_ips": public_ips,
            "private_ips": private_ips
        }

    # output naming
    folder, base_name, domain_for_name = choose_output_folder_and_basename(input_file, output_base, first_host=hosts[0] if hosts else None, default_suffix="ip")
    base = os.path.join(folder, base_name)
    fmts = formats or cfg.get("export_formats", ["txt", "json", "csv"])

    if not no_save:
        # TXT: human-friendly lines
        if "txt" in fmts or "all" in fmts:
            lines = []
            for host, info_d in sorted(results.items()):
                ips = info_d["ips"]
                origin = info_d["origin"] or ""
                pub = ", ".join(info_d["public_ips"]) or "-"
                priv = ", ".join(info_d["private_ips"]) or "-"
                allips = ", ".join(ips) or "-"
                lines.append(f"{host} -> origin: {origin} | public: {pub} | private: {priv} | all: {allips}")
            save_text(lines, base + ".txt")

        # JSON
        if "json" in fmts or "all" in fmts:
            save_json(results, base + ".json")

        # CSV
        if "csv" in fmts or "all" in fmts:
            rows = []
            for host, info_d in sorted(results.items()):
                rows.append([host, info_d["origin"] or "", ";".join(info_d["public_ips"]), ";".join(info_d["private_ips"]), ";".join(info_d["ips"])])
            save_csv(rows, ["subdomain", "origin", "public_ips", "private_ips", "all_ips"], base + ".csv")

        # HTML
        if "html" in fmts or "all" in fmts:
            rows = []
            for host, info_d in sorted(results.items()):
                rows.append([host, info_d["origin"] or "", ", ".join(info_d["public_ips"]), ", ".join(info_d["private_ips"]), ", ".join(info_d["ips"])])
            save_html_table(rows, ["subdomain", "origin", "public_ips", "private_ips", "all_ips"], base + ".html", title=f"IP extraction for {domain_for_name}")

        # unresolved
        if unresolved:
            save_text(unresolved, base + "_unres.txt")

    ok(f"IP extraction complete. Resolved: {len([h for h in results if results[h]['ips']])}, unresolved: {len(unresolved)}")
    return results


# ---------- Interactive & CLI ----------
def interactive_mode(cfg):
    print("\nInteractive mode — IP extraction\n(press Enter to accept defaults)\n")
    infile = input("Input file path: ").strip()
    threads = input(f"Threads (default {cfg.get('default_threads',20)}): ").strip() or cfg.get('default_threads', 20)
    timeout = input(f"Timeout (default {cfg.get('default_timeout',5)}): ").strip() or cfg.get('default_timeout', 5)
    out = input("Output base name (no extension) [<domain>_ip]: ").strip()
    fmts = input(f"Formats (txt,json,csv,html or 'all') [{','.join(cfg.get('export_formats', ['txt','json','csv']))}]: ").strip()
    if not fmts:
        formats = cfg.get('export_formats', ['txt','json','csv'])
    elif fmts.lower() == "all":
        formats = ["all"]
    else:
        formats = [s.strip() for s in fmts.split(",")]
    ns = input("Skip saving results? (y/N): ").strip().lower() == "y"
    return {
        "input": infile,
        "threads": int(threads),
        "timeout": int(timeout),
        "output_base": out if out else None,
        "formats": formats,
        "no_save": ns
    }


def print_examples():
    print("""
Usage examples:
  python ip_extractor.py -i results/example.com/example.com_live.txt
  python ip_extractor.py --interactive
Notes:
 - Provide -oIP base name without extension; outputs will be written to results/<domain>/<base>.<ext>
 - Default formats read from config.json (key: export_formats)
""")


def main():
    print_banner()
    cfg = ensure_config()
    parser = argparse.ArgumentParser(prog="ip_extractor", description="Extract IPs from live subdomains for TEAM INTRUDERS")
    parser.add_argument("-i", "--input", help="Input file path (txt/json/csv/html etc.)")
    parser.add_argument("-oIP", help="Output base name (no extension). Default = <domain>_ip")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats to export (txt,json,csv,html,all)")
    parser.add_argument("-t", "--threads", type=int, help="Threads (override config)")
    parser.add_argument("--timeout", type=int, help="Timeout seconds (override config)")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--interactive", action="store_true", help="Run interactive wizard")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    if args.interactive:
        opts = interactive_mode(cfg)
        run_ip_extractor(opts["input"], opts["output_base"], opts["no_save"], opts["formats"], opts["threads"], opts["timeout"])
        return

    if not args.input:
        parser.print_help()
        print_examples()
        return

    try:
        run_ip_extractor(
            args.input,
            output_base=args.oIP,
            no_save=args.no_save,
            formats=args.formats,
            threads=args.threads,
            timeout=args.timeout
        )
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
