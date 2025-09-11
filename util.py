#!/usr/bin/env python3
"""
util.py - Shared utilities for TEAM INTRUDERS tools.

Provides banner, config, results folder helpers, logging, export helpers,
HTTP session factory and bulk_resolve.

This updated version normalizes config/config.json so both:
 - legacy modules expecting top-level keys (virustotal, securitytrails, otx, shodan)
 - and the GUI expecting nested api_keys (api_keys.virustotal, ...)
work consistently.
"""

import os
import json
import socket
import csv
import html
from typing import List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from colorama import Fore, Style, init
from pyfiglet import Figlet
import urllib3
# silence urllib3 InsecureRequestWarning when verify=False is used intentionally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# initialize colorama
init(autoreset=True)

# Constants
CONFIG_DIR = "config"
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
RESULTS_DIR = "results"

# Banner once guard
_BANNER_PRINTED = False


# -------------------------
# Banner + logging
# -------------------------
def show_banner():
    global _BANNER_PRINTED
    if not _BANNER_PRINTED:
        f = Figlet(font="slant")
        print(Fore.CYAN + f.renderText("TEAM INTRUDERS") + Style.RESET_ALL)
        _BANNER_PRINTED = True


# alias used across modules
print_banner = show_banner


def info(msg: str):
    print(Fore.BLUE + "[i] " + Style.RESET_ALL + str(msg))


def ok(msg: str):
    print(Fore.GREEN + "[✔] " + Style.RESET_ALL + str(msg))


def warn(msg: str):
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + str(msg))


def error(msg: str):
    print(Fore.RED + "[!] " + Style.RESET_ALL + str(msg))


# -------------------------
# Config & results helpers
# -------------------------
def _default_config_template() -> dict:
    """
    Return the canonical template for config/config.json.
    This template intentionally includes both the legacy top-level API keys
    and the nested 'api_keys' mapping for compatibility.
    """
    return {
        "default_wordlist": "wordlist.txt",
        "default_threads": 20,
        "default_timeout": 5,
        "export_formats": ["txt", "json", "csv", "html"],
        # legacy top-level api keys (kept for older modules)
        "virustotal": "",
        "securitytrails": "",
        "otx": "",
        "shodan": "",
        # canonical nested mapping (used by GUI)
        "api_keys": {
            "virustotal": "",
            "securitytrails": "",
            "otx": "",
            "shodan": ""
        }
    }


def ensure_config() -> dict:
    """
    Ensure config/config.json exists and return a normalized config dict.
    Normalization:
      - ensures 'export_formats' is a list
      - ensures both top-level keys (virustotal, securitytrails, otx, shodan) and
        nested config['api_keys'] exist and contain the same values (non-destructive merge)
      - if config missing, create a template and warn user
      - writes back a normalized config (so file becomes canonical)
    """
    # ensure dir exists
    if not os.path.isdir(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
        except Exception as e:
            warn(f"Could not create config directory {CONFIG_DIR}: {e}")

    template = _default_config_template()

    # if file doesn't exist, create it
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
                json.dump(template, fh, indent=2)
            warn(f"Created template config: {CONFIG_PATH}. Please add API keys/defaults if needed.")
        except Exception as e:
            error(f"Failed to create config file: {e}")
            # return template dict (in-memory) for callers
            return template.copy()
        return template.copy()

    # if file exists, load and normalize
    conf = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            conf = json.load(fh) or {}
    except Exception as e:
        error(f"Failed to read config file {CONFIG_PATH}: {e}")
        # return safe defaults (template)
        return template.copy()

    # Ensure export_formats is a list
    if "export_formats" not in conf or not isinstance(conf.get("export_formats"), list):
        conf["export_formats"] = template["export_formats"].copy()

    # Ensure default_wordlist / threads / timeout exist
    for k in ("default_wordlist", "default_threads", "default_timeout"):
        if k not in conf:
            conf[k] = template[k]

    # Build unified api_keys mapping from either conf['api_keys'] or top-level keys
    api_keys = {}
    # If nested mapping exists and is a dict, start from it
    if isinstance(conf.get("api_keys"), dict):
        api_keys.update(conf.get("api_keys"))
    # Also accept legacy top-level keys and copy them into api_keys if present (non-empty)
    for legacy_key in ("virustotal", "securitytrails", "otx", "shodan"):
        val = conf.get(legacy_key, None)
        if val is not None and str(val).strip() != "":
            # prefer nested value if it already exists and not empty
            if not api_keys.get(legacy_key):
                api_keys[legacy_key] = val
    # ensure all known keys exist (possibly empty string)
    for kk in ("virustotal", "securitytrails", "otx", "shodan"):
        api_keys.setdefault(kk, "")

    # Now ensure top-level legacy keys reflect api_keys (so older modules can read them)
    for kk in ("virustotal", "securitytrails", "otx", "shodan"):
        # only overwrite top-level if empty and api_keys has value OR keep existing top-level
        top_val = conf.get(kk, "")
        nested_val = api_keys.get(kk, "")
        if (not top_val or str(top_val).strip() == "") and nested_val:
            conf[kk] = nested_val
        else:
            # ensure key exists even if empty
            conf.setdefault(kk, top_val if top_val is not None else "")

    # ensure the nested mapping is present in conf
    conf["api_keys"] = api_keys

    # Persist normalized config back to file (best-effort)
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(conf, fh, indent=2)
    except Exception as e:
        warn(f"Could not persist normalized config to {CONFIG_PATH}: {e}")

    return conf


def ensure_results_folder() -> str:
    if not os.path.isdir(RESULTS_DIR):
        os.makedirs(RESULTS_DIR, exist_ok=True)
    return RESULTS_DIR


def get_domain_results_path(domain: str) -> str:
    """
    Ensure and return results/<domain>/ path.
    """
    d = ensure_results_folder()
    safe = sanitize_basename(domain, domain)
    path = os.path.join(d, safe)
    os.makedirs(path, exist_ok=True)
    return path


# -------------------------
# Domain normalization / sanitization
# -------------------------
def normalize_domain(domain: str) -> str:
    if not domain:
        return ""
    d = domain.strip().lower()
    # strip scheme
    if d.startswith("http://"):
        d = d[len("http://"):]
    elif d.startswith("https://"):
        d = d[len("https://"):]
    # strip path
    d = d.split("/")[0]
    # strip www.
    if d.startswith("www."):
        d = d[len("www."):]
    return d.strip()


def sanitize_basename(name: str, domain_hint: str = "") -> str:
    """
    Return a filesystem-safe basename (no extension removal).
    IMPORTANT: Do NOT strip the final dot/TLD (fix for previously truncated domains).
    If name is empty, use domain_hint.
    """
    if not name:
        name = domain_hint or "output"
    # do NOT call splitext here — keep full domain (e.g., uop.edu.pk)
    # allow letters, digits, dash, dot, underscore
    safe = "".join([c if (c.isalnum() or c in "-._") else "_" for c in name])
    # collapse multiple underscores
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe


# -------------------------
# File saving helpers
# -------------------------
def save_text(lines: List[str], path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for l in lines:
                fh.write(str(l) + "\n")
        ok(f"Saved text output: {path}")
    except Exception as e:
        error(f"Failed to save text file {path}: {e}")


def save_json(obj, path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        ok(f"Saved JSON output: {path}")
    except Exception as e:
        error(f"Failed to save json file {path}: {e}")


def save_csv(rows: List[List[str]], headers: List[str], path: str):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            if headers:
                writer.writerow(headers)
            for row in rows:
                writer.writerow(row)
        ok(f"Saved CSV output: {path}")
    except Exception as e:
        error(f"Failed to save csv file {path}: {e}")


def save_html_table(rows: List[List[str]], headers: List[str], path: str, title: str = "Results"):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("<!doctype html>\n<html>\n<head>\n")
            fh.write(f"<meta charset='utf-8'><title>{html.escape(title)}</title>\n")
            fh.write("</head>\n<body>\n")
            fh.write(f"<h2>{html.escape(title)}</h2>\n")
            fh.write("<table border='1' cellpadding='4' cellspacing='0'>\n")
            if headers:
                fh.write("<thead><tr>" + "".join(f"<th>{html.escape(str(h))}</th>" for h in headers) + "</tr></thead>\n")
            fh.write("<tbody>\n")
            for row in rows:
                fh.write("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>\n")
            fh.write("</tbody>\n</table>\n</body>\n</html>")
        ok(f"Saved HTML output: {path}")
    except Exception as e:
        error(f"Failed to save html file {path}: {e}")


# -------------------------
# HTTP session factory
# -------------------------
def get_requests_session(retries: int = 3, backoff_factor: float = 0.3, status_forcelist=(500, 502, 504)) -> requests.Session:
    sess = requests.Session()
    retries_obj = Retry(total=retries, read=retries, connect=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retries_obj)
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


# -------------------------
# Bulk resolver
# -------------------------
def _resolve_one(host: str) -> Tuple[str, List[str]]:
    """
    Attempt to resolve host; return (host, [ips]) or (host, []) on failure.
    Uses socket.gethostbyname_ex for A records.
    """
    try:
        # Attempt to resolve
        info = socket.gethostbyname_ex(host)
        ips = list(set(info[2] or []))
        return host, ips
    except Exception:
        return host, []


def bulk_resolve(hosts: List[str], timeout: int = 2, workers: int = 20) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Resolve a list of hosts concurrently and return (mapping_dict, unresolved_list).
    Note: socket operations inherit the default socket timeout.
    """
    # set default socket timeout for resolution attempts
    try:
        socket.setdefaulttimeout(timeout)
    except Exception:
        pass

    mapping = {}
    unresolved = []

    with ThreadPoolExecutor(max_workers=min(len(hosts) or 1, workers)) as ex:
        futures = {ex.submit(_resolve_one, h): h for h in hosts}
        for fut in as_completed(futures):
            h = futures[fut]
            try:
                host, ips = fut.result()
                mapping[host] = ips
                if not ips:
                    unresolved.append(host)
            except Exception:
                mapping[h] = []
                unresolved.append(h)

    return mapping, unresolved
