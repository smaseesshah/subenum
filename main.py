#!/usr/bin/env python3
"""
main.py - Interactive entry for TEAM INTRUDERS

- Reads defaults from config/config.json via util.ensure_config()
- --interactive launches a terminal menu-driven UI
- --gui will attempt to import gui.py and call run_gui() if present (or run gui.app if available)
- Running with no args prints an explanatory about/help message
- There is no non-interactive mode in this front-end; it's interactive or GUI only.

Workflow (automated) sequence:
  brute -> api -> merge -> ip_extractor -> livecheck -> shodan

All called modules are expected to read defaults from config when arguments are None.
"""
from typing import List, Optional
import argparse
import os
import importlib

import util
from util import print_banner, ensure_config, get_domain_results_path, normalize_domain, sanitize_basename, info, ok, warn, error

# optional project modules; we'll import and handle missing gracefully
try:
    import brute_enum
except Exception:
    brute_enum = None

try:
    import api_enum
except Exception:
    api_enum = None

try:
    import merge_enum
except Exception:
    merge_enum = None

try:
    import ip_extractor
except Exception:
    ip_extractor = None

try:
    import livecheck
except Exception:
    livecheck = None

try:
    import shodan_integration
except Exception:
    shodan_integration = None


# -------------------------
# Helpers
# -------------------------
def parse_formats(raw: Optional[str], cfg_formats: List[str]) -> List[str]:
    """Return list of formats; 'all' preserved as single-element list."""
    if not raw:
        return cfg_formats[:]
    raw = raw.strip()
    if raw.lower() == "all":
        return ["all"]
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def build_basenames(domain: str) -> dict:
    d = normalize_domain(domain)
    return {
        "brute": sanitize_basename(f"{d}_brute", d),
        "api": sanitize_basename(f"{d}_api", d),
        "merge": sanitize_basename(f"{d}_merge", d),
        "ip": sanitize_basename(f"{d}_ip", d),
        "live": sanitize_basename(f"{d}_live", d),
        "shodan": sanitize_basename(f"{d}_shodan", d),
    }


def ensure_domain_dir(domain: str):
    return get_domain_results_path(domain)


# -------------------------
# Interactive actions
# -------------------------
def run_api_interactive(cfg):
    if not api_enum:
        warn("api_enum module is missing. Cannot run API enumeration.")
        return

    domain = input("Target domain (example.com): ").strip()
    if not domain:
        print("Domain required.")
        return
    domain = normalize_domain(domain)
    bases = build_basenames(domain)

    default_sources = ",".join(api_enum.ALL_SOURCES) if hasattr(api_enum, "ALL_SOURCES") else "all"
    srcs = input(f"Sources (comma) [{default_sources}]: ").strip() or default_sources
    apis = [s.strip() for s in srcs.split(",")]

    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get("export_formats"))
    # Use config defaults in api_enum if None passed (do not prompt for resolve timeout)
    ok("Running API enumeration...")
    api_enum.run_api_enum(domain, apis=apis, output_base=bases["api"], no_save=False, formats=fmts)


def run_brute_interactive(cfg):
    if not brute_enum:
        warn("brute_enum module is missing. Cannot run bruteforce.")
        return

    domain = input("Target domain (example.com): ").strip()
    if not domain:
        print("Domain required.")
        return
    domain = normalize_domain(domain)
    bases = build_basenames(domain)

    wordlist = input(f"Wordlist path [{cfg.get('default_wordlist')}]: ").strip() or cfg.get('default_wordlist')
    threads = input(f"Threads [{cfg.get('default_threads')}]: ").strip() or cfg.get('default_threads')
    timeout = input(f"DNS timeout [{cfg.get('default_timeout')}]: ").strip() or cfg.get('default_timeout')

    try:
        threads = int(threads)
    except Exception:
        threads = int(cfg.get('default_threads', 20))
    try:
        timeout = int(timeout)
    except Exception:
        timeout = int(cfg.get('default_timeout', 3))

    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))

    ok("Running bruteforce...")
    brute_enum.run_bruteforce(domain, wordlist=wordlist, threads=threads, timeout=timeout,
                              output_base=bases["brute"], formats=fmts, no_save=False)


def run_both_interactive(cfg):
    if not brute_enum or not api_enum or not merge_enum:
        warn("One of brute_enum/api_enum/merge_enum is missing. Cannot run 'both' flow.")
        return

    domain = input("Target domain (example.com): ").strip()
    if not domain:
        print("Domain required.")
        return
    domain = normalize_domain(domain)
    bases = build_basenames(domain)
    ensure_domain_dir(domain)

    fmts = parse_formats(input(f"Formats for both (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))
    wordlist = input(f"Brute wordlist path [{cfg.get('default_wordlist')}]: ").strip() or cfg.get('default_wordlist')
    brute_threads = input(f"Brute threads [{cfg.get('default_threads')}]: ").strip() or cfg.get('default_threads')
    brute_timeout = input(f"Brute DNS timeout [{cfg.get('default_timeout')}]: ").strip() or cfg.get('default_timeout')

    try:
        brute_threads = int(brute_threads)
    except Exception:
        brute_threads = int(cfg.get('default_threads', 20))
    try:
        brute_timeout = int(brute_timeout)
    except Exception:
        brute_timeout = int(cfg.get('default_timeout', 3))

    apis_raw = input(f"APIs to use (comma) [all]: ").strip()
    apis = [s.strip() for s in apis_raw.split(",")] if apis_raw else None

    # Phase 1
    ok("Phase 1: bruteforce")
    brute_enum.run_bruteforce(domain, wordlist=wordlist, threads=brute_threads, timeout=brute_timeout,
                              output_base=bases["brute"], formats=fmts, no_save=False)

    # Phase 2
    ok("Phase 2: api enumeration")
    # do not prompt for API resolve timeout — rely on api_enum to use config defaults when None passed
    api_enum.run_api_enum(domain, apis=apis or ["all"], output_base=bases["api"], no_save=False, formats=fmts)

    # Phase 3: merge generated TXT outputs
    domain_dir = get_domain_results_path(domain)
    brute_txt = os.path.join(domain_dir, bases["brute"] + ".txt")
    api_txt = os.path.join(domain_dir, bases["api"] + ".txt")
    ok("Phase 3: merging")
    merge_enum.run_merge(brute_txt, api_txt, output_base=bases["merge"], formats=fmts, no_save=False)
    ok("Both enumeration paths completed and merged.")


def run_ip_interactive(cfg):
    if not ip_extractor:
        warn("ip_extractor module is missing. Cannot run IP extraction.")
        return

    infile = input("Input file path (e.g. results/<domain>/<file>.txt): ").strip()
    if not infile:
        print("Input required.")
        return
    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))
    threads = input(f"Threads [{cfg.get('default_threads')}]: ").strip() or cfg.get('default_threads')
    timeout = input(f"Timeout [{cfg.get('default_timeout')}]: ").strip() or cfg.get('default_timeout')

    try:
        threads = int(threads)
    except Exception:
        threads = int(cfg.get('default_threads', 20))
    try:
        timeout = int(timeout)
    except Exception:
        timeout = int(cfg.get('default_timeout', 5))

    ok("Running IP extraction...")
    ip_extractor.run_ip_extractor(infile, output_base=None, no_save=False, formats=fmts, threads=threads, timeout=timeout)


def run_live_interactive(cfg):
    if not livecheck:
        warn("livecheck module is missing. Cannot run livecheck.")
        return

    infile = input("Input file path: ").strip()
    if not infile:
        print("Input required.")
        return
    out_format = input("Output format (map/domain/url) [map]: ").strip() or "map"
    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))
    threads = input(f"Threads [{cfg.get('default_threads')}]: ").strip() or cfg.get('default_threads')
    timeout = input(f"Timeout [{cfg.get('default_timeout')}]: ").strip() or cfg.get('default_timeout')

    try:
        threads = int(threads)
    except Exception:
        threads = int(cfg.get('default_threads', 30))
    try:
        timeout = int(timeout)
    except Exception:
        timeout = int(cfg.get('default_timeout', 5))

    ok("Running livecheck...")
    livecheck.run_livecheck(infile, output_base=None, no_save=False, formats=fmts, threads=threads, timeout=timeout, out_format=out_format)


def run_shodan_interactive(cfg):
    if not shodan_integration:
        warn("shodan_integration module is missing. Cannot run Shodan scraping.")
        return

    infile = input("Input file path (ip_extractor output recommended): ").strip()
    if not infile:
        print("Input required.")
        return
    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))
    timeout = shodan_integration.DEFAULT_TIMEOUT if hasattr(shodan_integration, "DEFAULT_TIMEOUT") else 15
    delay = shodan_integration.DEFAULT_DELAY if hasattr(shodan_integration, "DEFAULT_DELAY") else 2

    # allow overrides (optional)
    t_in = input(f"Shodan timeout [{timeout}]: ").strip()
    d_in = input(f"Delay between requests [{delay}]: ").strip()
    try:
        timeout = int(t_in) if t_in else timeout
    except Exception:
        pass
    try:
        delay = int(d_in) if d_in else delay
    except Exception:
        pass

    ok("Running Shodan scraping (sequential)...")
    shodan_integration.run_shodan_integration(infile, output_base=None, no_save=False, formats=fmts, timeout=timeout, delay=delay)


def run_merge_interactive(cfg):
    if not merge_enum:
        warn("merge_enum module is missing. Cannot run merge.")
        return

    f1 = input("Input file 1: ").strip()
    f2 = input("Input file 2: ").strip()
    if not f1 or not f2:
        print("Two inputs required.")
        return
    fmts = parse_formats(input(f"Formats (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))
    out = input("Output base name (no ext) [<domain>_merge]: ").strip() or None
    ok("Merging...")
    merge_enum.run_merge(f1, f2, output_base=out, formats=fmts, no_save=False)


def run_workflow(cfg):
    """
    Automated workflow:
      brute -> api -> merge -> ip_extractor -> livecheck -> shodan
    Uses config defaults when user accepts defaults.
    """
    # Check modules present
    missing = []
    for mod, name in ((brute_enum, "brute_enum"), (api_enum, "api_enum"), (merge_enum, "merge_enum"),
                      (ip_extractor, "ip_extractor"), (livecheck, "livecheck"), (shodan_integration, "shodan_integration")):
        if not mod:
            missing.append(name)
    if missing:
        warn(f"Cannot run workflow; missing modules: {', '.join(missing)}")
        return

    proceed = input("Proceed with workflow (this will create/save many files)? [y/N]: ").strip().lower() == "y"
    if not proceed:
        print("Workflow cancelled.")
        return

    domain = input("Workflow target domain (example.com): ").strip()
    if not domain:
        print("Domain required.")
        return
    domain = normalize_domain(domain)
    bases = build_basenames(domain)
    ensure_domain_dir(domain)

    fmts = parse_formats(input(f"Export formats for the whole workflow (comma or 'all') [{','.join(cfg.get('export_formats'))}]: "), cfg.get('export_formats'))

    # bruteforce settings (prompt user, but defaults come from config)
    wl = input(f"Brute wordlist path [{cfg.get('default_wordlist')}]: ").strip() or cfg.get('default_wordlist')
    brute_threads = input(f"Brute threads [{cfg.get('default_threads')}]: ").strip() or cfg.get('default_threads')
    brute_to = input(f"Brute DNS timeout [{cfg.get('default_timeout')}]: ").strip() or cfg.get('default_timeout')

    try:
        brute_threads = int(brute_threads)
    except Exception:
        brute_threads = int(cfg.get('default_threads', 20))
    try:
        brute_to = int(brute_to)
    except Exception:
        brute_to = int(cfg.get('default_timeout', 3))

    # APIs to use (optional)
    apis_raw = input("APIs to use (comma) [all]: ").strip()
    apis = [s.strip() for s in apis_raw.split(",")] if apis_raw else None

    # Phase 1: brute
    ok("Workflow phase 1: running bruteforce (and saving results)...")
    brute_enum.run_bruteforce(domain, wordlist=wl, threads=brute_threads, timeout=brute_to,
                              output_base=bases["brute"], formats=fmts, no_save=False)

    # Phase 2: api (use config defaults for resolve timeout/threads)
    ok("Workflow phase 2: running API enumeration (and saving results)...")
    api_enum.run_api_enum(domain, apis=apis or ["all"], output_base=bases["api"], no_save=False, formats=fmts)

    # Phase 3: merge (merge brute + api outputs)
    domain_dir = get_domain_results_path(domain)
    brute_txt = os.path.join(domain_dir, bases["brute"] + ".txt")
    api_txt = os.path.join(domain_dir, bases["api"] + ".txt")
    ok("Workflow phase 3: merging bruteforce + api outputs...")
    merge_enum.run_merge(brute_txt, api_txt, output_base=bases["merge"], formats=fmts, no_save=False)
    merged_txt = os.path.join(domain_dir, bases["merge"] + ".txt")

    # Phase 4: IP extraction on merged list
    ok("Workflow phase 4: running IP extraction on merged list...")
    ip_extractor.run_ip_extractor(merged_txt, output_base=bases["ip"], no_save=False, formats=fmts,
                                  threads=None, timeout=None)  # None -> modules use config defaults
    ip_txt = os.path.join(domain_dir, bases["ip"] + ".txt")

    # Phase 5: livecheck on merged list
    ok("Workflow phase 5: running livecheck on merged list...")
    livecheck.run_livecheck(merged_txt, output_base=bases["live"], no_save=False, formats=fmts,
                             threads=None, timeout=None, out_format="map")

    # Phase 6: shodan on IP extractor output
    ok("Workflow phase 6: running Shodan scraping on IP extractor output...")
    shodan_integration.run_shodan_integration(ip_txt, output_base=bases["shodan"], no_save=False, formats=fmts,
                                             timeout=None, delay=None)  # modules should handle None -> defaults

    ok("Workflow complete. All intermediate and final outputs saved under results/<domain>/.")


# -------------------------
# Main interactive loop
# -------------------------
def interactive_main(cfg):
    print("\nInteractive mode — TEAM INTRUDERS")
    print("(press Enter to accept defaults shown in prompts)\n")

    while True:
        print("\nMenu:")
        print("  1) Subdomain enumeration (api / bruteforce / both)")
        print("  2) IP extraction (ip_extractor)")
        print("  3) Live subdomain probe (livecheck)")
        print("  4) Open ports & CVEs (shodan scraping)")
        print("  5) Merge two files (merge_enum)")
        print("  6) Workflow (automated end-to-end)")
        print("  Q) Quit")
        choice = input("Choice: ").strip().upper()
        if choice == "1":
            m = input("Method (api/bruteforce/both) [api]: ").strip().lower() or "api"
            if m == "api":
                run_api_interactive(cfg)
            elif m == "bruteforce":
                run_brute_interactive(cfg)
            else:
                run_both_interactive(cfg)
        elif choice == "2":
            run_ip_interactive(cfg)
        elif choice == "3":
            run_live_interactive(cfg)
        elif choice == "4":
            run_shodan_interactive(cfg)
        elif choice == "5":
            run_merge_interactive(cfg)
        elif choice == "6":
            run_workflow(cfg)
        elif choice == "Q":
            print("Bye.")
            return
        else:
            print("Invalid choice.")


# -------------------------
# About/help + CLI entry
# -------------------------
def print_about():
    cfg = ensure_config()
    print_banner()
    print("\nTEAM INTRUDERS — interactive toolkit for subdomain discovery, IP extraction, probing, and Shodan scraping.")
    print("This front-end only supports interactive and GUI modes (no non-interactive single-run mode).")
    print("Run with --interactive to launch the terminal menu, or --gui to launch a GUI if gui.py is present.")
    print("\nDefaults are read from config/config.json (wordlists, threads, timeouts, export_formats, API keys).")
    print("Functionalities available:")
    print("  - Subdomain enumeration: api (passive), bruteforce (active), or both (and merge results)")
    print("  - IP extraction from lists")
    print("  - Live host probing (http/https)")
    print("  - Shodan scraping (host pages, no API required)")
    print("  - Merge two result files")
    print("  - Workflow: brute -> api -> merge -> ip_extractor -> livecheck -> shodan")
    print("\nNote: individual modules will use config defaults when you pass None/skip prompts.\n")


def main():
    parser = argparse.ArgumentParser(prog="team_intruders", add_help=False)
    parser.add_argument("--interactive", action="store_true", help="Run interactive UI")
    parser.add_argument("--gui", action="store_true", help="Run GUI (requires gui.py)")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    args = parser.parse_args()

    cfg = ensure_config()  # read config early (creates template if missing)

    # If no explicit mode or help requested -> show about/help
    if not args.interactive and not args.gui or args.help:
        print_about()
        return

    # print banner once
    print_banner()

    if args.gui:
        # Robust GUI launcher: prefer gui.run_gui(), fallback to gui.app (Flask) if present
        try:
            gui = importlib.import_module("gui")
            # If module provides a run_gui() callable, use it
            if hasattr(gui, "run_gui") and callable(getattr(gui, "run_gui")):
                ok("Launching GUI using gui.run_gui()...")
                try:
                    gui.run_gui()
                except Exception as e:
                    error(f"gui.run_gui() raised an exception: {e}")
            # Fallback: if gui.app is a Flask instance, run it directly
            elif hasattr(gui, "app"):
                app_obj = getattr(gui, "app")
                try:
                    ok("Launching Flask app instance from gui.app on http://127.0.0.1:5555 ...")
                    # run with debug=False to avoid reloader duplicating prints
                    app_obj.run(host="127.0.0.1", port=5555, debug=False, threaded=True)
                except Exception as e:
                    error(f"Failed to run Flask app from gui.app: {e}")
            else:
                warn("gui.py found but neither run_gui() nor a 'app' Flask instance were detected. Please implement run_gui() or expose 'app'.")
        except Exception as e:
            warn(f"Could not import or launch GUI (gui.py): {e}")
        return

    if args.interactive:
        interactive_main(cfg)


if __name__ == "__main__":
    main()
