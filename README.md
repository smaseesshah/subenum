# Subenum — Subdomain & IP Enumeration Toolkit
> A modular OSINT/enumeration pipeline created by **TEAM INTRUDERS**.
> Combine brute-force + API collectors → merge → resolve → live-check → Shodan Integration

---

## Table of Contents

1. [About](#about)
2. [Highlights & features](#highlights--features)
3. [Install & prerequisites](#install--prerequisites)
4. [Configuration](#configuration)
5. [Usage — interactive, GUI, and direct CLI](#usage---interactive-gui-and-direct-cli)
6. [Outputs & formats](#outputs--formats)
7. [Recommended workflow / examples](#recommended-workflow--examples)
8. [Security & ethics](#security--ethics)
9. [Files & module map](#files--module-map)
10. [References](#references)

---

## About

This toolkit was developed by **TEAM INTRUDERS** to streamline subdomain enumeration, IP resolution, liveness checks, and enrichment via Shodan scraping. Modules are standalone but can be chained via the interactive menu (`main.py`) or the GUI (`gui.py`).

---

## Highlights & features

* Brute-force subdomain discovery (active).
* Passive / API-based collection of hostnames. **Public sources:** `crt.sh` and the Wayback Machine are public collectors used by `api_enum`.
* API-based collectors (require keys): VirusTotal, SecurityTrails, AlienVault OTX, and other services.
* Merge and deduplicate multiple sources into a canonical host list.
* Resolve hostnames to IPs in parallel.
* Live host checks (HTTP status, page titles, banners, basic port checks).
* Shodan enrichment through **scraping** (no Shodan API key required).
* Export formats: `txt`, `json`, `csv`, `html`.
* Interactive terminal menu (`main.py --interactive`) and an optional Flask GUI (`main.py --gui`).

---

## Install & prerequisites

```bash
# 1. Clone the repository
git clone https://github.com/smaseesshah/subenum.git
cd subenum

# 2. Setup environment
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Configuration

* Runtime defaults are read from `config/config.json`. If missing it will be generated on first run.
* Add API keys (VirusTotal, SecurityTrails, OTX, etc.) in `config/config.json` if you plan to use those collectors.
* Adjust concurrency (`threads`), timeouts, and default export formats in config.
* Shodan enrichment is implemented via scraping; no API key required for that mode.

> **Security note:** Keep keys out of version control. Treat `config/config.json` as sensitive if it contains secrets.

---

## Usage — interactive, GUI, and direct CLI

### Interactive menu (recommended)

```bash
python3 main.py --interactive
```

* The script presents a menu-driven workflow: choose flows (brute, api, merge, ip\_extractor, livecheck, shodan) and set parameters at prompts.

### GUI mode

```bash
python3 main.py --gui
```

* Attempts to launch the Flask GUI defined in `gui.py`.

### Module CLI reference

Run `python3 <module>.py --help` for runtime help. Key arguments:

* **`brute_enum.py`**
  `-d DOMAIN`, `-w WORDLIST`, `-t THREADS`, `--timeout`, `-oB`, `-F FORMATS`, `--no-save`, `--interactive`, `--debug`

* **`api_enum.py`**
  `-d DOMAIN`, `--apis API1 API2 …`, `-oA`, `-F FORMATS`, `--no-save`, `--timeout`, `--delay`, `--interactive`, `--debug`

* **`merge_enum.py`**
  `file1 file2`, `-oM`, `-F FORMATS`, `--no-save`, `--interactive`, `--debug`

* **`ip_extractor.py`**
  `-i INPUT`, `-oIP`, `-F FORMATS`, `-t THREADS`, `--timeout`, `--no-save`, `--interactive`, `--debug`

* **`livecheck.py`**
  `-i INPUT`, `-oL`, `--format map|domain|url`, `-t THREADS`, `--timeout`, `-F FORMATS`, `--no-save`, `--interactive`, `--debug`

* **`shodan_integration.py`**
  `-i INPUT`, `-oS`, `-F FORMATS`, `--timeout`, `--delay`, `--no-save`, `--interactive`, `--debug`
  *(Per project instructions, Shodan integration uses scraping rather than the Shodan API.)*

* **`main.py`**
  `--interactive` (menu)
  `--gui` (Flask GUI)

---

## Outputs & formats

* Supported: `txt`, `json`, `csv`, `html`.
* Default save folder is `results/` (configured via `config/config.json`).
* Use `--no-save` for dry runs.

---

## Recommended workflow / examples

```bash
# 1) Active brute-force enumeration
python3 brute_enum.py -d example.com -w wordlist.txt -t 40 -F txt,json

# 2) Passive collection via APIs / public sources
python3 api_enum.py -d example.com --apis crtsh wayback -F json

# 3) Merge results
python3 merge_enum.py results/brute_example.txt results/api_example.json -oM results/example_merged

# 4) Resolve to IPs
python3 ip_extractor.py -i results/example_merged.txt -oIP results/example_ips -F json,csv -t 50

# 5) Live checks
python3 livecheck.py -i results/example_ips.json -oL results/example_live -F json -t 40

# 6) Shodan enrichment by scraping
python3 shodan_integration.py -i results/example_ips.json -oS results/example_shodan -F json --delay 2
```

---

## Files & module map

* `main.py` — launcher & menu
* `brute_enum.py` — brute-force enumerator
* `api_enum.py` — API/public-source collectors (crt.sh, Wayback, etc.)
* `merge_enum.py` — merge & deduplicate results
* `ip_extractor.py` — resolve hostnames to IPs
* `livecheck.py` — liveness checks & banners
* `shodan_integration.py` — Shodan scraping enrichment
* `util.py` — utilities (config, saving, resolving)
* `gui.py` — Flask GUI

---

## References

* [crt.sh — Certificate Transparency search](https://crt.sh)
* [Wayback Machine / Internet Archive](https://archive.org/web)
* [VirusTotal API docs](https://developers.virustotal.com)
* [SecurityTrails](https://securitytrails.com)
* [AlienVault OTX](https://otx.alienvault.com)
* [OWASP Testing Guide (ethics & guidance)](https://owasp.org)
