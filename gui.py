#!/usr/bin/env python3
"""
gui.py - Flask GUI backend for Team Intruders

- Uses config/config.json as canonical settings store.
- Provides compatibility endpoints:
    GET/PUT /api/settings           -> uses config/config.json
    GET/PUT /config/config.json     -> direct file access (for frontend fallback)
    GET/PUT /.project/settings.json -> legacy fallback (in .project/)
- Projects stored under .project/<domain>.json
- Uploads saved under .project/<domain>/uploads/
- Results under results/<domain>/
- Job execution and SSE log streaming supported.
- Intended for local / trusted usage.
"""

import os
import re
import json
import time
import uuid
import threading
from queue import Queue, Empty
from typing import Dict, Any, Optional, List
from pathlib import Path
from flask import Flask, request, jsonify, Response, send_from_directory, abort, render_template

from flask_cors import CORS

import util

# optional scanning modules (may be missing)
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

# Paths
HERE = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.join(HERE, ".project")
RESULTS_ROOT = os.path.join(HERE, "results")
CONFIG_DIR = os.path.join(HERE, "config")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LEGACY_SETTINGS_PATH = os.path.join(PROJECT_ROOT, "config.json")

os.makedirs(PROJECT_ROOT, exist_ok=True)
os.makedirs(RESULTS_ROOT, exist_ok=True)
os.makedirs(CONFIG_DIR, exist_ok=True)

# Ensure config exists (util.ensure_config handles creation/migration)
cfg = util.ensure_config()

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

# -----------------------
# Jobs storage and helpers
# -----------------------
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()

def _make_job(domain: str, flow: str, params: Optional[dict]=None) -> str:
    jid = str(uuid.uuid4())
    job = {
        "id": jid,
        "project": domain,
        "domain": domain,
        "flow": flow,
        "params": params or {},
        "status": "queued",
        "created_at": time.time(),
        "started_at": None,
        "finished_at": None,
        "logs_q": Queue(),
        "thread": None
    }
    with _jobs_lock:
        _jobs[jid] = job
    return jid

def _append_log(job_id: str, level: str, msg: str):
    j = _jobs.get(job_id)
    if not j:
        return
    entry = {"t": time.time(), "level": level, "msg": str(msg)}
    try:
        j["logs_q"].put_nowait(entry)
    except Exception:
        pass

class UtilLoggerPatch:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self._orig = {"info": util.info, "ok": util.ok, "warn": util.warn, "error": util.error}

    def _wrap(self, level_name):
        def _fn(msg):
            try:
                _append_log(self.job_id, level_name, msg)
            except Exception:
                pass
            try:
                self._orig[level_name](msg)
            except Exception:
                pass
        return _fn

    def apply(self):
        util.info = self._wrap("info")
        util.ok = self._wrap("ok")
        util.warn = self._wrap("warn")
        util.error = self._wrap("error")

    def restore(self):
        util.info = self._orig["info"]
        util.ok = self._orig["ok"]
        util.warn = self._orig["warn"]
        util.error = self._orig["error"]

# -----------------------
# Helpers: projects/results/settings
# -----------------------
def _domain_to_project_path(domain: str) -> str:
    safe = util.sanitize_basename(domain, domain)
    return os.path.join(PROJECT_ROOT, f"{safe}.json")

def list_projects() -> List[Dict[str, Any]]:
    out = []
    for fn in sorted(os.listdir(PROJECT_ROOT)):
        if not fn.endswith(".json"):
            continue
        name = fn[:-5]
        p = load_project(name) or {}
        out.append({"domain": name, "meta": p.get("meta", {}), "created_at": p.get("created_at")})
    return out

def load_project(domain: str) -> Optional[Dict[str,Any]]:
    pth = _domain_to_project_path(domain)
    if not os.path.exists(pth):
        return None
    try:
        with open(pth, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

def save_project(domain: str, meta: Optional[dict]=None) -> bool:
    pth = _domain_to_project_path(domain)
    data = {"created_at": time.time(), "meta": meta or {}}
    try:
        with open(pth, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.makedirs(os.path.join(PROJECT_ROOT, util.sanitize_basename(domain, domain), "uploads"), exist_ok=True)
        return True
    except Exception:
        return False

def delete_project(domain: str) -> bool:
    pth = _domain_to_project_path(domain)
    try:
        if os.path.exists(pth):
            os.remove(pth)
        uploads_dir = os.path.join(PROJECT_ROOT, util.sanitize_basename(domain, domain))
        if os.path.isdir(uploads_dir):
            import shutil
            shutil.rmtree(uploads_dir, ignore_errors=True)
        return True
    except Exception:
        return False

def list_result_files(domain: str) -> List[str]:
    try:
        dd = util.get_domain_results_path(domain)
    except Exception:
        dd = os.path.join(RESULTS_ROOT, domain)
    out = []
    if os.path.isdir(dd):
        for fn in sorted(os.listdir(dd)):
            out.append(fn)
    return out

def save_upload(domain: str, filename: str, file_stream) -> str:
    safe_domain = util.sanitize_basename(domain, domain)
    upl_dir = os.path.join(PROJECT_ROOT, safe_domain, "uploads")
    os.makedirs(upl_dir, exist_ok=True)
    safe_name = util.sanitize_basename(filename, filename)
    dest = os.path.join(upl_dir, safe_name)
    with open(dest, "wb") as fh:
        fh.write(file_stream.read())
    return dest

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
def validate_domain(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    d = util.normalize_domain(domain)
    return bool(DOMAIN_RE.match(d))

# -----------------------
# Job runner
# -----------------------
def _safe_call(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except Exception as e:
        util.error(f"Exception in {getattr(fn,'__name__',str(fn))}: {e}")

def _run_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        return
    job["status"] = "running"
    job["started_at"] = time.time()
    patch = UtilLoggerPatch(job_id)
    patch.apply()
    domain = job["domain"]
    params = job.get("params", {}) or {}
    try:
        flow = job["flow"]
        if flow == "brute":
            if not brute_enum:
                util.warn("brute_enum module not available")
            else:
                util.info(f"[job] bruteforce -> {domain}")
                _safe_call(brute_enum.run_bruteforce,
                           domain,
                           params.get("wordlist"),
                           params.get("threads"),
                           params.get("timeout"),
                           params.get("output_base"),
                           params.get("formats"),
                           params.get("no_save", False))
        elif flow == "api":
            if not api_enum:
                util.warn("api_enum module not available")
            else:
                util.info(f"[job] api_enum -> {domain}")
                _safe_call(api_enum.run_api_enum,
                           domain,
                           params.get("apis"),
                           params.get("output_base"),
                           params.get("no_save", False),
                           params.get("formats"),
                           params.get("resolve_timeout"),
                           params.get("resolve_threads"))
        elif flow == "merge":
            if not merge_enum:
                util.warn("merge_enum module not available")
            else:
                file1 = params.get("file1")
                file2 = params.get("file2")
                if not file1 or not file2:
                    dd = util.get_domain_results_path(domain)
                    file1 = file1 or os.path.join(dd, util.sanitize_basename(f"{domain}_brute", domain) + ".txt")
                    file2 = file2 or os.path.join(dd, util.sanitize_basename(f"{domain}_api", domain) + ".txt")
                util.info(f"[job] merge -> {file1} + {file2}")
                _safe_call(merge_enum.run_merge, file1, file2, params.get("output_base"), params.get("formats"), params.get("no_save", False))
        elif flow == "ip":
            if not ip_extractor:
                util.warn("ip_extractor module not available")
            else:
                infile = params.get("input")
                if not infile:
                    infile = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_merge", domain) + ".txt")
                util.info(f"[job] ip_extractor -> {infile}")
                _safe_call(ip_extractor.run_ip_extractor, infile, params.get("output_base"), params.get("no_save", False), params.get("formats"), params.get("threads"), params.get("timeout"))
        elif flow == "live":
            if not livecheck:
                util.warn("livecheck module not available")
            else:
                infile = params.get("input")
                if not infile:
                    infile = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_merge", domain) + ".txt")
                util.info(f"[job] livecheck -> {infile}")
                _safe_call(livecheck.run_livecheck, infile, params.get("output_base"), params.get("no_save", False), params.get("formats"), params.get("threads"), params.get("timeout"), params.get("out_format", "map"))
        elif flow == "shodan":
            if not shodan_integration:
                util.warn("shodan_integration module not available")
            else:
                infile = params.get("input")
                if not infile:
                    infile = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_ip", domain) + ".txt")
                util.info(f"[job] shodan_integration -> {infile}")
                # safe-guard: ensure timeout/delay are integers (fixes earlier 'NoneType cannot be interpreted as int')
                try:
                    timeout = int(params.get("timeout") or util.ensure_config().get("default_timeout", 15))
                except Exception:
                    timeout = 15
                try:
                    delay = int(params.get("delay") or 2)
                except Exception:
                    delay = 2
                _safe_call(shodan_integration.run_shodan_integration, infile, params.get("output_base"), params.get("no_save", False), params.get("formats"), timeout, delay)
        elif flow == "workflow":
            util.info("[job] starting workflow (brute -> api -> merge -> ip -> live -> shodan)")
            if brute_enum:
                util.info("[workflow] phase 1: brute")
                _safe_call(brute_enum.run_bruteforce, domain, params.get("wordlist"), params.get("brute_threads"), params.get("brute_timeout"), None, params.get("formats"), False)
            else:
                util.warn("[workflow] brute missing")
            if api_enum:
                util.info("[workflow] phase 2: api")
                _safe_call(api_enum.run_api_enum, domain, params.get("apis") or ["all"], None, False, params.get("formats"))
            else:
                util.warn("[workflow] api missing")
            if merge_enum:
                util.info("[workflow] phase 3: merge")
                dd = util.get_domain_results_path(domain)
                brute_txt = os.path.join(dd, util.sanitize_basename(f"{domain}_brute", domain) + ".txt")
                api_txt = os.path.join(dd, util.sanitize_basename(f"{domain}_api", domain) + ".txt")
                _safe_call(merge_enum.run_merge, brute_txt, api_txt, None, params.get("formats"), False)
            else:
                util.warn("[workflow] merge missing")
            if ip_extractor:
                util.info("[workflow] phase 4: ip_extractor")
                merged_txt = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_merge", domain) + ".txt")
                _safe_call(ip_extractor.run_ip_extractor, merged_txt, None, False, params.get("formats"), params.get("threads"), params.get("timeout"))
            else:
                util.warn("[workflow] ip_extractor missing")
            if livecheck:
                util.info("[workflow] phase 5: livecheck")
                merged_txt = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_merge", domain) + ".txt")
                _safe_call(livecheck.run_livecheck, merged_txt, None, False, params.get("formats"), params.get("threads"), params.get("timeout"), "map")
            else:
                util.warn("[workflow] livecheck missing")
            if shodan_integration:
                util.info("[workflow] phase 6: shodan")
                ip_txt = os.path.join(util.get_domain_results_path(domain), util.sanitize_basename(f"{domain}_ip", domain) + ".txt")
                # normalize timeout/delay as above
                try:
                    timeout = int(params.get("timeout") or util.ensure_config().get("default_timeout", 15))
                except Exception:
                    timeout = 15
                try:
                    delay = int(params.get("delay") or 2)
                except Exception:
                    delay = 2
                _safe_call(shodan_integration.run_shodan_integration, ip_txt, None, False, params.get("formats"), timeout, delay)
            else:
                util.warn("[workflow] shodan missing")
        else:
            util.warn(f"[job] unknown flow: {flow}")

        job["status"] = "finished"
    except Exception as e:
        util.error(f"[job] unexpected exception: {e}")
        job["status"] = "failed"
    finally:
        job["finished_at"] = time.time()
        _append_log(job["id"], "info", "[job] finished")
        patch.restore()

def _start_job_thread(job_id: str):
    t = threading.Thread(target=_run_job, args=(job_id,), daemon=True)
    with _jobs_lock:
        _jobs[job_id]["thread"] = t
    t.start()

# -----------------------
# SSE events
# -----------------------
@app.route("/api/jobs/<jid>/events")
def job_events(jid):
    if jid not in _jobs:
        return abort(404)
    def gen():
        job = _jobs[jid]
        q = job["logs_q"]
        while True:
            try:
                entry = q.get(timeout=0.5)
                yield f"data: {json.dumps(entry)}\n\n"
            except Empty:
                if job["status"] in ("finished", "failed") and q.empty():
                    break
                continue
        time.sleep(0.05)
    return Response(gen(), mimetype="text/event-stream")

# -----------------------
# Routes: UI root
# -----------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

# -----------------------
# Projects API
# -----------------------
@app.route("/api/projects", methods=["GET", "POST"])
def api_projects():
    if request.method == "GET":
        return jsonify(list_projects())
    data = request.get_json() or {}
    domain = (data.get("domain") or "").strip()
    meta = data.get("meta", {})
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    if not validate_domain(domain):
        return jsonify({"error": "invalid domain format"}), 400
    if load_project(domain):
        return jsonify({"error": "project already exists"}), 409
    ok = save_project(domain, meta)
    if not ok:
        return jsonify({"error": "failed to save project"}), 500
    return jsonify({"ok": True, "domain": domain})

@app.route("/api/projects/<domain>", methods=["GET", "PUT", "DELETE"])
def api_project(domain):
    domain = util.normalize_domain(domain)
    if request.method == "GET":
        p = load_project(domain)
        if not p:
            return jsonify({"error": "not found"}), 404
        return jsonify({"domain": domain, "meta": p})
    if request.method == "PUT":
        data = request.get_json() or {}
        meta = data.get("meta", {})
        ok = save_project(domain, meta)
        if not ok:
            return jsonify({"error": "failed to save"}), 500
        return jsonify({"ok": True})
    if request.method == "DELETE":
        ok = delete_project(domain)
        return jsonify({"ok": ok})

# -----------------------
# Upload endpoints
# -----------------------
@app.route("/api/uploads/<domain>/wordlist", methods=["POST"])
def upload_wordlist(domain):
    domain = util.normalize_domain(domain)
    if not validate_domain(domain):
        return jsonify({"error": "invalid domain"}), 400
    if 'file' not in request.files:
        return jsonify({"error": "file field required (multipart/form-data 'file')"}), 400
    f = request.files['file']
    filename = f.filename or "wordlist.txt"
    saved = save_upload(domain, filename, f.stream)
    rel = os.path.relpath(saved, PROJECT_ROOT)
    return jsonify({"ok": True, "saved": rel})

@app.route("/api/uploads/<domain>/file", methods=["POST"])
def upload_file(domain):
    domain = util.normalize_domain(domain)
    if not validate_domain(domain):
        return jsonify({"error": "invalid domain"}), 400
    if 'file' not in request.files:
        return jsonify({"error": "file field required (multipart/form-data 'file')"}), 400
    f = request.files['file']
    filename = f.filename or "upload.bin"
    saved = save_upload(domain, filename, f.stream)
    rel = os.path.relpath(saved, PROJECT_ROOT)
    return jsonify({"ok": True, "saved": rel})

# -----------------------
# Jobs API
# -----------------------
@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    with _jobs_lock:
        out = []
        for j in _jobs.values():
            out.append({
                "id": j["id"],
                "project": j["project"],
                "domain": j["domain"],
                "flow": j["flow"],
                "status": j["status"],
                "created_at": j["created_at"],
                "started_at": j["started_at"],
                "finished_at": j["finished_at"]
            })
    return jsonify(out)

@app.route("/api/jobs/start", methods=["POST"])
def api_jobs_start():
    data = request.get_json() or {}
    domain = util.normalize_domain(data.get("domain") or "")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if not validate_domain(domain):
        return jsonify({"error": "invalid domain"}), 400
    if not load_project(domain):
        return jsonify({"error": "project not found; create project first (domain acts as project name)"}), 404
    flow = data.get("flow") or "workflow"
    params = data.get("params") or {}
    jid = _make_job(domain, flow, params)
    _append_log(jid, "info", f"[job] queued: {flow} for {domain}")
    _start_job_thread(jid)
    return jsonify({"ok": True, "job_id": jid})

# -----------------------
# Dashboard helpers & results
# -----------------------
@app.route("/api/dashboard", methods=["GET"])
@app.route("/api/dashboard/<domain>", methods=["GET"])
def api_dashboard(domain: Optional[str]=None):
    projects = [domain] if domain else [p["domain"] for p in list_projects()]
    totals = {"subdomains": 0, "ips": 0, "live": 0, "shodan": 0, "projects": len(list_projects())}
    detail = {}
    for proj in projects:
        p = load_project(proj) or {}
        dom = proj
        s_count = 0
        try:
            s_count, _ = count_subdomains_from_results(dom)
        except Exception:
            s_count = 0
        ip_count = 0
        try:
            ip_count, _ = count_ips_from_ipfile(dom)
        except Exception:
            ip_count = 0
        sh_count = 0
        try:
            sh_count, _ = count_shodan_entries(dom)
        except Exception:
            sh_count = 0
        live_count = 0
        try:
            dd = util.get_domain_results_path(dom)
            lf = os.path.join(dd, f"{dom}_live.txt")
            if os.path.exists(lf):
                with open(lf, "r", encoding="utf-8") as fh:
                    live_count = sum(1 for _ in fh)
        except Exception:
            pass
        totals["subdomains"] += s_count
        totals["ips"] += ip_count
        totals["shodan"] += sh_count
        totals["live"] += live_count
        detail[proj] = {"subdomains": s_count, "ips": ip_count, "live": live_count, "shodan": sh_count}
    return jsonify({"totals": totals, "details": detail})

def count_subdomains_from_results(domain: str):
    dd = util.get_domain_results_path(domain)
    candidates = []
    for base in (f"{domain}_merge.txt", f"{domain}_api.txt", f"{domain}_brute.txt"):
        p = os.path.join(dd, base)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    if "->" in line:
                        sub = line.split("->", 1)[0].strip()
                    else:
                        sub = line.split()[0].strip()
                    candidates.append(sub)
    return len(set(candidates)), sorted(set(candidates))

def count_ips_from_ipfile(domain: str):
    dd = util.get_domain_results_path(domain)
    p = os.path.join(dd, f"{domain}_ip.txt")
    ips = set()
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if "all:" in line:
                    parts = line.split("all:", 1)[1].strip()
                    for ip in parts.split(","):
                        ip = ip.strip()
                        if ip:
                            ips.add(ip)
                else:
                    import re
                    for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                        ips.add(m)
    return len(ips), sorted(ips)

def count_shodan_entries(domain: str):
    dd = util.get_domain_results_path(domain)
    p = os.path.join(dd, f"{domain}_shodan.json")
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return len(data), data
        except Exception:
            return 0, []
    return 0, []

@app.route("/api/results/<domain>", methods=["GET"])
def api_results(domain):
    domain = util.normalize_domain(domain)
    if not validate_domain(domain):
        return jsonify({"error": "invalid domain"}), 400
    files = list_result_files(domain)
    return jsonify({"domain": domain, "files": files})

@app.route("/api/download/<domain>/<path:filename>", methods=["GET"])
def api_download(domain, filename):
    domain = util.normalize_domain(domain)
    if not validate_domain(domain):
        return abort(403)
    domain_dir = util.get_domain_results_path(domain)
    requested = os.path.normpath(os.path.join(domain_dir, filename))
    if not requested.startswith(os.path.normpath(domain_dir)):
        return abort(403)
    if not os.path.exists(requested):
        return abort(404)
    return send_from_directory(domain_dir, filename, as_attachment=True)

# -----------------------
# Settings endpoints (canonical API)
# -----------------------
def load_settings() -> Dict[str, Any]:
    try:
        # keep util.ensure_config as canonical source of truth
        return util.ensure_config()
    except Exception:
        return {}

def save_settings(data: Dict[str, Any]) -> bool:
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        # Save canonical normalized shape: write back as-is
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return True
    except Exception:
        return False

@app.route("/api/settings", methods=["GET", "PUT"])
def api_settings():
    if request.method == "GET":
        return jsonify(load_settings())
    data = request.get_json() or {}
    ok = save_settings(data)
    if not ok:
        return jsonify({"error": "failed to save settings"}), 500
    # also persist to legacy .project/settings.json for compatibility
    try:
        os.makedirs(PROJECT_ROOT, exist_ok=True)
        with open(LEGACY_SETTINGS_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass
    return jsonify({"ok": True})

# Direct file endpoints for frontend fallback / convenience
@app.route("/config/config.json", methods=["GET", "PUT"])
def config_file():
    if request.method == "GET":
        return jsonify(load_settings())
    # PUT: accept JSON body and overwrite config file
    data = request.get_json() or {}
    ok = save_settings(data)
    if not ok:
        return jsonify({"error": "failed to save config"}), 500
    return jsonify({"ok": True})

@app.route("/config/config.json", methods=["GET", "PUT"])
def legacy_settings_file():
    if request.method == "GET":
        # return legacy settings if exists, else return canonical settings
        if os.path.exists(LEGACY_SETTINGS_PATH):
            try:
                with open(LEGACY_SETTINGS_PATH, "r", encoding="utf-8") as fh:
                    return jsonify(json.load(fh))
            except Exception:
                return jsonify(load_settings())
        return jsonify(load_settings())
    data = request.get_json() or {}
    try:
        os.makedirs(os.path.dirname(LEGACY_SETTINGS_PATH), exist_ok=True)
        with open(LEGACY_SETTINGS_PATH, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        # also save canonical config to CONFIG_PATH for consistency
        save_settings(data)
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"error": "failed to save legacy settings"}), 500

@app.route("/api/settings/test", methods=["POST"])
def api_settings_test():
    data = request.get_json() or {}
    key_name = data.get("key_name")
    key_value = data.get("key_value")
    if not key_name:
        return jsonify({"error": "key_name required"}), 400
    if not key_value:
        return jsonify({"ok": False, "message": "empty key"})
    return jsonify({"ok": True, "message": "Key present (no live verification)"})

@app.route("/api/ping")
def api_ping():
    return jsonify({"ok": True})

# -----------------------
# Run helper
# -----------------------
def run_gui(host="127.0.0.1", port=5555, debug=False):
    print(f"Starting Team Intruders GUI at http://{host}:{port} (config: {CONFIG_PATH})")
    app.run(host=host, port=port, debug=debug, threaded=True)

if __name__ == "__main__":
    run_gui()
