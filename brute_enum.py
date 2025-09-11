#!/usr/bin/env python3
"""
brute_enum.py - Bruteforce subdomain enumeration module for TEAM INTRUDERS

Behavior:
 - Uses defaults from config/config.json (via util.ensure_config()) when args are None.
 - Shows a tqdm progress bar while resolving candidates (same UX as other modules).
 - Logs resolution failures so issues are visible during workflow runs.
 - Saves outputs to results/<domain>/<base>.<ext> according to config/export_formats.
"""

import argparse
import os
import sys
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Iterable

import util
from util import (
    print_banner, info, ok, warn, error, ensure_config, get_domain_results_path,
    save_text, save_json, save_csv, save_html_table, normalize_domain
)
from tqdm import tqdm


# -------------------------
# Internal helpers
# -------------------------
def _read_wordlist(path: str) -> List[str]:
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
    return words


def resolve_host_local(host: str, timeout: int) -> List[str]:
    """
    Resolve a hostname to IPv4 addresses using socket.getaddrinfo / gethostbyname_ex.
    Returns a list of unique IPv4 addresses or [] on failure.
    This function sets a temporary default socket timeout for the attempt.
    """
    old = None
    try:
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
        except Exception:
            pass
        # use getaddrinfo to gather addresses (works for IPv4 and IPv6). We'll filter IPv4.
        addrs = []
        for res in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            addr = res[4][0]
            if ":" not in addr and addr not in addrs:  # filter out IPv6 here
                addrs.append(addr)
        # Fallback to gethostbyname_ex if nothing found
        if not addrs:
            try:
                info = socket.gethostbyname_ex(host)
                for a in info[2] or []:
                    if ":" not in a and a not in addrs:
                        addrs.append(a)
            except Exception:
                pass
        return addrs
    except Exception:
        return []
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass


def _resolve_candidate(sub: str, timeout: int) -> Tuple[str, List[str]]:
    """Attempt to resolve subdomain and return (subdomain, [ips])."""
    ips = resolve_host_local(sub, timeout=timeout)
    return sub, ips


def _sanitize_basename(bname: str, domain: str) -> str:
    if not bname:
        return f"{normalize_domain(domain)}_brute"
    bname = os.path.basename(bname)
    allowed_exts = {"txt", "json", "csv", "html"}
    root, ext = os.path.splitext(bname)
    if ext.lstrip(".").lower() in allowed_exts:
        bname = root
    bname = bname.replace(" ", "_")
    bname = re.sub(r"[^A-Za-z0-9._\-]", "", bname)
    bname = re.sub(r"\.{2,}", ".", bname)
    bname = bname.strip(".-")
    if not bname:
        bname = f"{normalize_domain(domain)}_brute"
    return bname


def _make_output_base(domain_dir: str, domain: str, oB: str = None) -> str:
    if oB:
        bname = _sanitize_basename(oB, domain)
    else:
        bname = f"{normalize_domain(domain)}_brute"
    return os.path.join(domain_dir, bname)


def _fmt_txt_lines(mapping: Dict[str, List[str]]) -> List[str]:
    lines = []
    for sub in sorted(mapping.keys()):
        ips = mapping[sub]
        if ips:
            lines.append(f"{sub} -> {', '.join(ips)}")
        else:
            lines.append(f"{sub} ->")
    return lines


def _fmt_csv_rows(mapping: Dict[str, List[str]]) -> List[List[str]]:
    rows = []
    for sub in sorted(mapping.keys()):
        ips = mapping[sub]
        rows.append([sub, ";".join(ips)])
    return rows


def _fmt_html_rows(mapping: Dict[str, List[str]]) -> List[List[str]]:
    rows = []
    for sub in sorted(mapping.keys()):
        ips = mapping[sub]
        rows.append([sub, ", ".join(ips)])
    return rows


# -------------------------
# Core function
# -------------------------
def run_bruteforce(domain: str,
                   wordlist: str = None,
                   threads: int = None,
                   timeout: int = None,
                   output_base: str = None,
                   formats: Iterable[str] = None,
                   no_save: bool = False) -> Dict[str, List[str]]:
    """
    Run brute-force subdomain enumeration.

    NOTE: when an argument is None, the value will be taken from config/config.json.
    """
    print_banner()
    cfg = ensure_config()

    domain = normalize_domain(domain)
    if not domain:
        raise ValueError("Domain is required")

    # Use config defaults when arguments are None
    wordlist = wordlist or cfg.get("default_wordlist")
    threads = int(threads or cfg.get("default_threads", 20))
    timeout = int(timeout or cfg.get("default_timeout", 3))

    # Determine formats (respect 'all' if given)
    allowed = ["txt", "json", "csv", "html"]
    if formats:
        fmt_list = []
        for f in formats:
            for p in str(f).split(","):
                p = p.strip().lower()
                if not p:
                    continue
                if p == "all":
                    fmt_list = allowed[:]
                    break
                if p in allowed:
                    fmt_list.append(p)
        if not fmt_list:
            fmt_list = cfg.get("export_formats", allowed)
    else:
        fmt_list = cfg.get("export_formats", allowed)
    # dedupe & preserve order
    seen = set()
    fmt_list = [x for x in fmt_list if not (x in seen or seen.add(x))]

    info(f"Starting bruteforce for {domain}")
    info(f"Wordlist: {wordlist}")
    info(f"Threads: {threads}  Timeout: {timeout}s")
    info(f"Export formats: {', '.join(fmt_list)}")

    # Read wordlist
    try:
        words = _read_wordlist(wordlist)
    except Exception as e:
        error(f"Failed to read wordlist: {e}")
        return {}

    # Build candidates
    candidates = [f"{w}.{domain}" for w in words]
    info(f"Prepared {len(candidates)} candidates from wordlist")

    # Resolve each candidate concurrently, show progress with tqdm
    results: Dict[str, List[str]] = {}
    if not candidates:
        warn("No candidates generated from wordlist.")
    else:
        max_workers = max(1, min(len(candidates), threads))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_resolve_candidate, cand, timeout): cand for cand in candidates}
            for fut in tqdm(as_completed(futures), total=len(futures), desc="Brute", unit="sub"):
                cand = futures[fut]
                try:
                    sub, ips = fut.result(timeout=timeout + 1)
                    if ips:
                        results[sub] = ips
                        info(f"Resolved: {sub} -> {', '.join(ips)}")
                except Exception as e:
                    # log resolution exceptions instead of silently ignoring
                    warn(f"Resolution error for {cand}: {e}")

    if not results:
        warn("No subdomains resolved from brute force.")
    else:
        ok(f"Found {len(results)} subdomains.")

    # Save outputs
    domain_dir = get_domain_results_path(domain)
    base = _make_output_base(domain_dir, domain, output_base)

    if not no_save:
        if "txt" in fmt_list:
            txt_path = base + ".txt"
            save_text(_fmt_txt_lines(results), txt_path)
        if "json" in fmt_list:
            save_json(results, base + ".json")
        if "csv" in fmt_list:
            save_csv(_fmt_csv_rows(results), ["subdomain", "ips"], base + ".csv")
        if "html" in fmt_list:
            save_html_table(_fmt_html_rows(results), ["subdomain", "ips"], base + ".html",
                            title=f"Brute results for {domain}")

    return results


# -------------------------
# Interactive helper
# -------------------------
def interactive_wizard_brute(cfg):
    print_banner()
    print("\nInteractive mode — Bruteforce\n(press Enter to accept defaults)\n")

    domain = input("Target domain (example.com): ").strip()
    while not domain:
        domain = input("Target domain is required. Enter target domain: ").strip()

    default_wordlist = cfg.get("default_wordlist")
    wl = input(f"Wordlist [{default_wordlist}]: ").strip() or default_wordlist

    default_threads = str(cfg.get("default_threads", 20))
    th = input(f"Threads [{default_threads}]: ").strip() or default_threads
    try:
        th = int(th)
    except Exception:
        th = int(cfg.get("default_threads", 20))

    default_timeout = str(cfg.get("default_timeout", 3))
    to = input(f"DNS timeout seconds [{default_timeout}]: ").strip() or default_timeout
    try:
        to = int(to)
    except Exception:
        to = int(cfg.get("default_timeout", 3))

    domain_dir = get_domain_results_path(domain)
    default_base = f"{normalize_domain(domain)}_brute"
    out = input(f"Output base name [{default_base}]: ").strip() or default_base

    cfg_formats = cfg.get("export_formats", ["txt", "json", "csv"])
    default_formats = ",".join(cfg_formats)
    fmt_in = input(f"Formats (csv,json,txt,html or 'all') [{default_formats}]: ").strip() or default_formats
    formats = [s.strip() for s in fmt_in.split(",")] if fmt_in else None

    ns = input("Skip saving results? (y/N): ").strip().lower()
    no_save = True if ns == "y" else False

    return {
        "domain": domain,
        "wordlist": wl,
        "threads": th,
        "timeout": to,
        "output_base": out,
        "formats": formats,
        "no_save": no_save
    }


# -------------------------
# CLI
# -------------------------
def print_detailed_help():
    print("""
Usage examples:
  python brute_enum.py -d example.com -w /path/wordlist.txt -t 50 -F txt,json
  python brute_enum.py --interactive
Notes:
 - Use --interactive to run a guided wizard.
 - With -oB, give only a base name (no extension). Example: -oB example_brute
 - Output files: results/<domain>/<base>.<ext>
""")


def main():
    print_banner()
    cfg = ensure_config()

    parser = argparse.ArgumentParser(prog="brute_enum", description="Brute-force subdomain enumeration for TEAM INTRUDERS")
    parser.add_argument("-d", "--domain", required=False, help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file")
    parser.add_argument("-t", "--threads", type=int, help="Threads")
    parser.add_argument("--timeout", type=int, help="DNS timeout seconds")
    parser.add_argument("-oB", help="Output base name (no extension)")
    parser.add_argument("-F", "--formats", nargs="*", help="Formats (txt,json,csv,html,all)")
    parser.add_argument("--no-save", action="store_true", help="Do not save results")
    parser.add_argument("--debug", action="store_true", help="Show debug info")
    parser.add_argument("--interactive", action="store_true", help="Run interactive wizard")

    if len(sys.argv) == 1:
        parser.print_help()
        print_detailed_help()
        return

    args = parser.parse_args()

    try:
        if args.interactive:
            opts = interactive_wizard_brute(cfg)
            run_bruteforce(
                opts["domain"],
                wordlist=opts["wordlist"],
                threads=opts["threads"],
                timeout=opts["timeout"],
                output_base=opts["output_base"],
                formats=opts["formats"],
                no_save=opts["no_save"]
            )
            return

        domain = args.domain or input("Enter target domain: ").strip()
        if not domain:
            print("Domain is required. Exiting.")
            return

        run_bruteforce(
            domain,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            output_base=args.oB,
            formats=args.formats,
            no_save=args.no_save
        )

    except Exception as e:
        if getattr(args, "debug", False):
            import traceback
            traceback.print_exc()
        else:
            error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
