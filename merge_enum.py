#!/usr/bin/env python3
"""
merge_enum.py - Merge two subdomain result files (any supported format) into one.

Features:
 - Accepts two input files (txt/json/csv/html etc.), extracts subdomains from both,
   merges them (deduplicates), and exports in chosen formats.
 - Interactive mode (--interactive), supports -oM for output base name (no ext).
 - Naming: results/<domain>/<domain>_merge.* (domain inferred from input filename or sanitized filename).
 - If both input filenames contain a domain_<mode> pattern and they match, the domain is used.
   Otherwise first matching domain or sanitized filename is used.
"""

import argparse
import os
import re
from typing import List, Set
from tqdm import tqdm

import util
from util import (
    print_banner, info, ok, warn, error,
    ensure_config, get_domain_results_path, normalize_domain, sanitize_basename,
    save_text, save_json, save_csv, save_html_table
)


# ---------- Helpers ----------
def extract_hosts_from_file(path: str) -> List[str]:
    """
    Reuse same liberal extraction as other tools.
    """
    hosts = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception as e:
        warn(f"Failed to read {path}: {e}")
        return []

    pattern = re.compile(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})")
    for m in pattern.findall(content):
        token = m.strip().lower()
        hosts.add(token)
    return sorted(hosts)


def infer_domain_from_filename(input_file: str):
    base = os.path.splitext(os.path.basename(input_file))[0]
    if "_" in base:
        left = base.split("_", 1)[0]
        if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", left):
            return normalize_domain(left)
    return None


def choose_merge_domain_and_paths(file1: str, file2: str, output_base: str = None):
    """
    Decide domain_for_name and folder + base_name for merge output.
    Priority:
      1) If either filename matches <domain>_<mode>, use that domain (prefer file1).
      2) Else if output_base provided and looks domain-like left of underscore -> use left
      3) Else fallback to sanitized base of file1
    """
    d1 = infer_domain_from_filename(file1)
    d2 = infer_domain_from_filename(file2)

    domain_for_name = d1 or d2

    if not domain_for_name and output_base:
        if "_" in output_base:
            maybe = output_base.split("_", 1)[0]
            if re.match(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", maybe):
                domain_for_name = normalize_domain(maybe)

    if not domain_for_name:
        base1 = os.path.splitext(os.path.basename(file1))[0]
        domain_for_name = sanitize_basename(base1, base1)

    folder = get_domain_results_path(domain_for_name)
    if output_base:
        base_name = sanitize_basename(output_base, domain_for_name)
    else:
        base_name = f"{normalize_domain(domain_for_name)}_merge"

    return folder, base_name, domain_for_name


# ---------- Core ----------
def run_merge(file1: str, file2: str, output_base: str = None,
              formats: List[str] = None, no_save: bool = False):
    print_banner()
    cfg = ensure_config()

    hosts1 = extract_hosts_from_file(file1)
    hosts2 = extract_hosts_from_file(file2)

    if not hosts1 and not hosts2:
        warn("No hosts found in either file.")
        return []

    combined = list(dict.fromkeys(sorted(set(hosts1) | set(hosts2))))  # dedup preserve sorted order

    info(f"Merged total unique hosts: {len(combined)} (file1: {len(hosts1)}, file2: {len(hosts2)})")

    folder, base_name, domain_for_name = choose_merge_domain_and_paths(file1, file2, output_base)
    base = os.path.join(folder, base_name)
    fmts = formats or cfg.get("export_formats", ["txt", "json", "csv"])

    if not no_save:
        # TXT
        if "txt" in fmts or "all" in fmts:
            save_text(combined, base + ".txt")
        # JSON
        if "json" in fmts or "all" in fmts:
            save_json(combined, base + ".json")
        # CSV
        if "csv" in fmts or "all" in fmts:
            rows = [[h] for h in combined]
            save_csv(rows, ["subdomain"], base + ".csv")
        # HTML
        if "html" in fmts or "all" in fmts:
            rows = [[h] for h in combined]
            save_html_table(rows, ["subdomain"], base + ".html", title=f"Merged list for {domain_for_name}")

    ok(f"Merge complete. Output saved as {base}.[txt,json,csv,html] (as requested)")
    return combined


# ---------- Interactive & CLI ----------
def interactive_mode(cfg):
    print("\nInteractive mode — Merge two files\n(press Enter to accept defaults)\n")
    f1 = input("Input file 1: ").strip()
    f2 = input("Input file 2: ").strip()
    out = input("Output base name (no extension) [<domain>_merge]: ").strip()
    fmts = input(f"Formats (txt,json,csv,html or 'all') [{','.join(cfg.get('export_formats', ['txt','json','csv']))}]: ").strip()
    if not fmts:
        formats = cfg.get('export_formats', ['txt','json','csv'])
    elif fmts.lower() == "all":
        formats = ["all"]
    else:
        formats = [s.strip() for s in fmts.split(",")]
    ns = input("Skip saving results? (y/N): ").strip().lower() == "y"
    return {"file1": f1, "file2": f2, "output_base": out if out else None, "formats": formats, "no_save": ns}


def print_examples():
    print("""
Examples:
  python merge_enum.py file1.txt file2.json
  python merge_enum.py --interactive
Notes:
 - Output base (-oM) should be a name without extension.
 - Default formats come from config.json (key: export_formats).
""")


def main():
    print_banner()
    cfg = ensure_config()

    parser = argparse.ArgumentParser(prog="merge_enum", description="Merge two subdomain result files")
    parser.add_argument("file1", nargs="?", help="First input file")
    parser.add_argument("file2", nargs="?", help="Second input file")
    parser.add_argument("-oM", help="Output base name (no extension)")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats to export (txt,json,csv,html,all)")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--interactive", action="store_true", help="Run interactive wizard")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    if args.interactive:
        opts = interactive_mode(cfg)
        run_merge(opts["file1"], opts["file2"], output_base=opts["output_base"], formats=opts["formats"], no_save=opts["no_save"])
        return

    if not args.file1 or not args.file2:
        parser.print_help()
        print_examples()
        return

    try:
        run_merge(args.file1, args.file2, output_base=args.oM, formats=args.formats, no_save=args.no_save)
    except Exception as e:
        if getattr(args, "debug", False):
            raise
        error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
