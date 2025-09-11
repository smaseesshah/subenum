// static/app.js — Finalized frontend script for Team Intruders
// - Fix: when "both" selected, starts brute and api separately (not workflow)
// - Keeps all previous UI wiring, SSE, uploads, settings handling, and safety guards.

(function () {
  "use strict";

  /* ==========================
     Small DOM helpers
     ========================== */
  const $ = (sel, ctx = document) => (ctx || document).querySelector(sel);
  const $$ = (sel, ctx = document) => Array.from((ctx || document).querySelectorAll(sel));
  const safeSetText = (el, txt) => { if (el) el && (el.textContent = (txt === undefined || txt === null) ? "" : String(txt)); };

  /* ==========================
     Network helpers
     ========================== */
  async function apiGET(path) {
    const res = await fetch(path, { credentials: "same-origin" });
    if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
    return res.json();
  }
  async function apiPOST(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    });
    return res.json();
  }
  async function apiPUT(path, body) {
    const res = await fetch(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {})
    });
    try { return await res.json(); } catch (e) { return null; }
  }
  async function fetchJsonSafe(url) {
    try {
      const r = await fetch(url, { credentials: "same-origin" });
      if (!r.ok) return null;
      return await r.json();
    } catch (e) { return null; }
  }

  /* ==========================
     Modal (custom) - returns choice string
     NOTE: captures inputs into window._lastModalInputs before hiding so callers can read them.
     ========================== */
  const modalOverlay = () => $("#modalOverlay");
  const modalTitleEl = () => $("#modalTitle");
  const modalBodyEl = () => $("#modalBody");
  const modalFooterEl = () => $("#modalFooter");
  const modalCloseBtn = () => $("#modalClose");

  function _gatherModalInputs(overlay) {
    const data = {};
    if (!overlay) return data;
    const inputs = overlay.querySelectorAll("input,textarea,select");
    inputs.forEach(inp => {
      if (inp.id) data[inp.id] = inp.type === "checkbox" ? inp.checked : (inp.value === undefined ? "" : inp.value);
    });
    return data;
  }

  function showModal(title = "", bodyHtml = "", buttons = [{ txt: "OK", cls: "btn primary", ret: "ok" }]) {
    return new Promise(resolve => {
      const overlay = modalOverlay();
      if (!overlay) {
        const r = confirm(bodyHtml) ? "ok" : "cancel";
        return resolve(r);
      }

      // set content
      if (modalTitleEl()) modalTitleEl().textContent = title || "";
      if (modalBodyEl()) modalBodyEl().innerHTML = bodyHtml || "";
      const footer = modalFooterEl();
      footer.innerHTML = "";
      buttons.forEach(b => {
        const btn = document.createElement("button");
        btn.className = b.cls || "btn";
        btn.textContent = b.txt || "OK";
        btn.addEventListener("click", () => {
          // capture inputs before hiding
          try {
            window._lastModalInputs = _gatherModalInputs(overlay);
          } catch (e) {
            window._lastModalInputs = window._lastModalInputs || {};
          }
          hideModal();
          resolve(b.ret === undefined ? b.txt : b.ret);
        });
        footer.appendChild(btn);
      });

      // show
      overlay.classList.remove("hidden");
      overlay.setAttribute("aria-hidden", "false");

      // close binding
      const close = modalCloseBtn();
      const onClose = () => {
        window._lastModalInputs = _gatherModalInputs(overlay);
        hideModal();
        resolve("close");
      };
      if (close) close.onclick = onClose;

      // focus first input after showing
      setTimeout(() => {
        const first = overlay.querySelector("input,textarea,select,button");
        if (first) first.focus();
      }, 50);
    });
  }

  function hideModal() {
    const overlay = modalOverlay();
    if (!overlay) return;
    overlay.classList.add("hidden");
    overlay.setAttribute("aria-hidden", "true");
    if (modalBodyEl()) modalBodyEl().innerHTML = "";
    if (modalFooterEl()) modalFooterEl().innerHTML = "";
    if (modalCloseBtn()) modalCloseBtn().onclick = null;
  }

  /* ==========================
     Toasts (styled)
     ========================== */
  let toastTimer = null;
  function showToast(msg, timeout = 3000) {
    const el = $("#toast");
    if (!el) { console.warn("Toast element missing:", msg); return; }
    el.textContent = msg;
    el.classList.remove("hidden");
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.add("hidden");
      toastTimer = null;
    }, timeout);
  }

  /* ==========================
     Utility helpers
     ========================== */
  function normalizeDomain(d) {
    if (!d) return "";
    return d.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].replace(/^www\./, "");
  }
  function isValidDomain(d) {
    if (!d) return false;
    const n = normalizeDomain(d);
    return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(n);
  }

  /* ==========================
     Job log streaming (SSE)
     ========================== */
  const jobEventSources = {}; // jobId -> EventSource

  function appendDashboardLog(line) {
    const el = $("#dashboard_log");
    if (!el) return;
    el.textContent += line + "\n";
    el.scrollTop = el.scrollHeight;
  }

  function watchJobLogs(jobId, onFinished) {
    if (!jobId) return;
    if (jobEventSources[jobId]) {
      try { jobEventSources[jobId].close(); } catch (e) {}
    }
    const url = `/api/jobs/${encodeURIComponent(jobId)}/events`;
    const es = new EventSource(url);
    jobEventSources[jobId] = es;
    es.onmessage = ev => {
      try {
        const obj = JSON.parse(ev.data);
        const t = new Date(obj.t * 1000).toLocaleTimeString();
        const line = `[${t}] ${obj.level.toUpperCase()}: ${obj.msg}`;
        appendDashboardLog(line);
      } catch (e) { /* ignore */ }
    };
    es.onerror = () => {
      try { es.close(); } catch (e) {}
      delete jobEventSources[jobId];
      if (typeof onFinished === "function") onFinished();
    };
  }

  /* ==========================
     Projects management
     ========================== */
  async function loadProjects() {
    const sel = $("#projectSelect");
    try {
      const list = await apiGET("/api/projects");
      if (sel) {
        sel.innerHTML = "";
        const placeholder = document.createElement("option");
        placeholder.value = "";
        placeholder.textContent = "-- select project (domain) --";
        sel.appendChild(placeholder);
        (list || []).forEach(p => {
          const o = document.createElement("option");
          o.value = p.domain || p;
          o.textContent = (p.domain || p).toUpperCase();
          sel.appendChild(o);
        });
      }
      safeSetText($("#cardProjectsValue"), (list && list.length) || 0);
      safeSetText($("#cardProjects"), (list && list.length) || 0);
    } catch (e) {
      console.error("Failed to load projects", e);
      showToast("Failed to load projects");
    }
  }

  async function createProjectFlow(domain) {
    domain = normalizeDomain(domain || "");
    if (!domain) { showToast("Please enter a valid domain"); return null; }
    if (!isValidDomain(domain)) { showToast("Invalid domain format"); return null; }
    try {
      const res = await apiPOST("/api/projects", { domain });
      if (res && res.ok) {
        showToast(`Project ${domain} created`);
        await loadProjects();
        const sel = $("#projectSelect");
        if (sel) sel.value = domain;
        onProjectSelectionChanged(domain);
        return domain;
      } else if (res && res.error) {
        showToast(`Project creation failed: ${res.error}`);
        return null;
      } else {
        showToast("Project creation failed");
        return null;
      }
    } catch (e) {
      console.error("createProjectFlow error", e);
      showToast("Project creation failed (network)");
      return null;
    }
  }

  function getSelectedProject() {
    const sel = $("#projectSelect");
    return sel ? (sel.value || "") : "";
  }
  function setSelectedProjectDisplay(domain) {
    const name = domain || "—";
    ["#quick_project_display", "#sd_project_name", "#ip_project_name", "#live_project_name", "#shodan_project_name"].forEach(id => {
      const el = $(id); if (el) safeSetText(el, name.toUpperCase());
    });
  }

  function onProjectSelectionChanged(domain) {
    setSelectedProjectDisplay(domain || "");
    if (domain) refreshAllResultsForProject(domain);
    else populateEmptyTables();
  }

  /* ==========================
     Upload helpers
     ========================== */
  async function uploadWordlist(domain, fileInput, statusEl) {
    if (!domain || !fileInput || !fileInput.files || fileInput.files.length === 0) {
      showToast("Choose a wordlist file first");
      return null;
    }
    const f = fileInput.files[0];
    const fd = new FormData();
    fd.append("file", f, f.name);
    try {
      if (statusEl) statusEl.textContent = "Uploading...";
      const res = await fetch(`/api/uploads/${encodeURIComponent(domain)}/wordlist`, {
        method: "POST",
        body: fd,
        credentials: "same-origin"
      });
      const data = await res.json();
      if (data && data.ok) {
        if (statusEl) statusEl.textContent = `Uploaded: ${f.name}`;
        showToast("Wordlist uploaded");
        return data.saved;
      } else {
        if (statusEl) statusEl.textContent = `Upload failed`;
        showToast("Wordlist upload failed");
        return null;
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = `Upload failed`;
      console.error("uploadWordlist", e);
      showToast("Wordlist upload failed (network)");
      return null;
    }
  }

  async function uploadGenericFile(domain, fileInput, statusEl) {
    if (!domain || !fileInput || !fileInput.files || fileInput.files.length === 0) {
      showToast("Choose a file first");
      return null;
    }
    const f = fileInput.files[0];
    const fd = new FormData();
    fd.append("file", f, f.name);
    try {
      if (statusEl) statusEl.textContent = "Uploading...";
      const res = await fetch(`/api/uploads/${encodeURIComponent(domain)}/file`, {
        method: "POST",
        body: fd,
        credentials: "same-origin"
      });
      const data = await res.json();
      if (data && data.ok) {
        if (statusEl) statusEl.textContent = `Uploaded: ${f.name}`;
        showToast("File uploaded");
        return data.saved;
      } else {
        if (statusEl) statusEl.textContent = "Upload failed";
        showToast("Upload failed");
        return null;
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = "Upload failed";
      console.error("uploadGenericFile", e);
      showToast("Upload failed (network)");
      return null;
    }
  }

  /* ==========================
     Start job wrapper
     ========================== */
  async function startJob(domain, flow, params = {}) {
    domain = normalizeDomain(domain || "");
    if (!domain) {
      showToast("Select a project first");
      return null;
    }
    try {
      const check = await fetch(`/api/projects/${encodeURIComponent(domain)}`, { credentials: "same-origin" });
      if (!check.ok) {
        showToast("Project not found; create project first");
        return null;
      }
    } catch (e) {
      showToast("Failed to verify project (network)");
      return null;
    }

    // remove thread param if present - threads only configurable in settings
    if (params.threads) delete params.threads;

    try {
      const res = await apiPOST("/api/jobs/start", { domain, flow, params });
      if (res && res.job_id) {
        showToast(`Started ${flow} for ${domain}`);
        // start logs & refresh results when job finishes
        watchJobLogs(res.job_id, async () => { await refreshAllResultsForProject(domain); });
        return res.job_id;
      } else {
        showToast(`Failed to start job: ${res && res.error ? res.error : "unknown"}`);
        return null;
      }
    } catch (e) {
      console.error("startJob error", e);
      showToast("Failed to start job (network)");
      return null;
    }
  }

  /* ==========================
     Results listing & parsing
     ========================== */
  async function listResultFiles(domain) {
    try {
      const res = await apiGET(`/api/results/${encodeURIComponent(domain)}`);
      return (res && res.files) ? res.files : [];
    } catch (e) {
      return [];
    }
  }
  async function fetchResultText(domain, filename) {
    try {
      const url = `/api/download/${encodeURIComponent(domain)}/${encodeURIComponent(filename)}`;
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) return null;
      return await res.text();
    } catch (e) { return null; }
  }

  function parseLinesToSubdomains(text) {
    const out = [];
    if (!text) return out;
    text.split("\n").forEach(l => {
      const line = l.trim(); if (!line) return;
      let sub;
      if (line.includes("->")) sub = line.split("->", 1)[0].trim();
      else sub = line.split(/\s+/)[0].trim();
      if (sub && !out.includes(sub)) out.push(sub);
    });
    return out;
  }

  function parseLinesToIPs(text) {
    const out = [];
    if (!text) return out;
    text.split("\n").forEach(l => {
      const line = l.trim(); if (!line) return;
      let host = line;
      if (line.includes("->")) host = line.split("->", 1)[0].trim();
      else host = line.split(/\s+/)[0].trim();
      const ips = Array.from(new Set((line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])));
      out.push({ host: host, ips: ips });
    });
    return out;
  }

  function parseLinesToLive(text) {
    const out = [];
    if (!text) return out;
    text.split("\n").forEach(l => {
      const line = l.trim(); if (!line) return;
      const host = line.split(/\s+/)[0].trim();
      if (host && !out.includes(host)) out.push(host);
    });
    return out;
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (/^10\./.test(ip)) return true;
    if (/^192\.168\./.test(ip)) return true;
    if (/^127\./.test(ip)) return true;
    if (/^169\.254\./.test(ip)) return true;
    const m = ip.match(/^172\.(\d{1,3})\./);
    if (m) { const n = Number(m[1]); if (n >= 16 && n <= 31) return true; }
    return false;
  }

  function populateEmptyTables() {
    fillSubdomains([]); fillIpTable([]); fillLive([]); fillShodan([]);
  }
  function fillSubdomains(list) {
    const tbody = $("#subdomains_table tbody"); if (!tbody) return;
    tbody.innerHTML = "";
    (list || []).forEach(s => {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.textContent = s;
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }
  function fillIpTable(rows) {
    const tbody = $("#ip_table tbody"); if (!tbody) return;
    tbody.innerHTML = "";
    (rows || []).forEach(r => {
      const tr = document.createElement("tr");
      const tdHost = document.createElement("td"); tdHost.textContent = r.host || "-";
      const tdOrigin = document.createElement("td");
      const ips = Array.isArray(r.ips) ? r.ips : [];
      if (ips.length) {
        ips.forEach((ip, idx) => {
          const span = document.createElement("span");
          span.className = "ip-badge " + (isPrivateIp(ip) ? "ip-private" : "ip-public");
          span.textContent = ip;
          tdOrigin.appendChild(span);
          if (idx !== ips.length - 1) tdOrigin.appendChild(document.createTextNode(" "));
        });
      } else tdOrigin.textContent = "-";
      tr.appendChild(tdHost); tr.appendChild(tdOrigin); tbody.appendChild(tr);
    });
  }
  function fillLive(list) {
    const tbody = $("#live_table tbody"); if (!tbody) return;
    tbody.innerHTML = "";
    (list || []).forEach(h => {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.textContent = h || "-";
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
  }
  function fillShodan(rows) {
    const tbody = $("#shodan_table tbody"); if (!tbody) return;
    tbody.innerHTML = "";
    (rows || []).forEach(r => {
      const tr = document.createElement("tr");
      const tdIP = document.createElement("td"); tdIP.textContent = r.ip || "-";
      const tdHost = document.createElement("td"); tdHost.textContent = r.hostnames || "-";
      const tdPorts = document.createElement("td"); tdPorts.textContent = r.ports || "-";
      const tdServices = document.createElement("td"); tdServices.textContent = r.services || "-";
      const tdCves = document.createElement("td"); tdCves.textContent = r.cves || "-";
      tr.appendChild(tdIP); tr.appendChild(tdHost); tr.appendChild(tdPorts); tr.appendChild(tdServices); tr.appendChild(tdCves);
      tbody.appendChild(tr);
    });
  }

  async function refreshAllResultsForProject(domain) {
    if (!domain) { populateEmptyTables(); return; }
    try {
      const files = await listResultFiles(domain);
      const mergeName = `${domain}_merge.txt`;
      const apiName = `${domain}_api.txt`;
      const bruteName = `${domain}_brute.txt`;
      const liveName = `${domain}_live.txt`;
      const ipName = `${domain}_ip.txt`;
      const shodanJson = `${domain}_shodan.json`;

      // Subdomains: prefer merge, api, brute
      let subText = null;
      if (files.includes(mergeName)) subText = await fetchResultText(domain, mergeName);
      else if (files.includes(apiName)) subText = await fetchResultText(domain, apiName);
      else if (files.includes(bruteName)) subText = await fetchResultText(domain, bruteName);
      fillSubdomains(parseLinesToSubdomains(subText || ""));

      // IPs
      let ipText = null;
      if (files.includes(ipName)) ipText = await fetchResultText(domain, ipName);
      fillIpTable(parseLinesToIPs(ipText || ""));

      // Live
      let liveText = null;
      if (files.includes(liveName)) liveText = await fetchResultText(domain, liveName);
      fillLive(parseLinesToLive(liveText || ""));

      // Shodan
      let shodanText = null;
      if (files.includes(shodanJson)) shodanText = await fetchResultText(domain, shodanJson);
      if (shodanText) {
        try {
          const data = JSON.parse(shodanText);
          const rows = (Array.isArray(data) ? data : []).map(r => ({
            ip: r.ip || "",
            hostnames: (r.hostnames || []).join(", "),
            ports: (r.ports || []).join(", "),
            services: (r.services || []).join(", "),
            cves: (r.cves || []).join(", ")
          }));
          fillShodan(rows);
        } catch (e) { fillShodan([]); }
      } else fillShodan([]);

    } catch (e) {
      console.error("refreshAllResultsForProject", e);
      populateEmptyTables();
    }
  }

  /* ==========================
     Export & Collapse wiring
     ========================== */
  function wireExportAndCollapse() {
    // Subdomains
    const sdExportBtn = $("#sd_export"); const sdExportFmt = $("#sd_export_format");
    if (sdExportBtn) sdExportBtn.addEventListener("click", () => {
      const proj = getSelectedProject(); if (!proj) { showToast("Select project from header"); return; }
      const fmt = (sdExportFmt && sdExportFmt.value) || "txt";
      window.open(`/api/download/${encodeURIComponent(proj)}/${encodeURIComponent(`${proj}_merge.${fmt}`)}`, "_blank");
    });
    const sdToggle = $("#sd_toggle_results"); const sdBlock = $("#sd_results_block");
    if (sdToggle && sdBlock) sdToggle.addEventListener("click", () => {
      sdBlock.classList.toggle("results-collapsed"); sdToggle.textContent = sdBlock.classList.contains("results-collapsed") ? "Expand" : "Collapse";
    });

    // IP
    const ipExportBtn = $("#ip_export"); const ipExportFmt = $("#ip_export_format");
    if (ipExportBtn) ipExportBtn.addEventListener("click", () => {
      const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
      const fmt = (ipExportFmt && ipExportFmt.value) || "txt";
      window.open(`/api/download/${encodeURIComponent(proj)}/${encodeURIComponent(`${proj}_ip.${fmt}`)}`, "_blank");
    });
    const ipToggle = $("#ip_toggle_results"); const ipBlock = $("#ip_results_block");
    if (ipToggle && ipBlock) ipToggle.addEventListener("click", () => {
      ipBlock.classList.toggle("results-collapsed"); ipToggle.textContent = ipBlock.classList.contains("results-collapsed") ? "Expand" : "Collapse";
    });

    // Live
    const liveExportBtn = $("#live_export"); const liveExportFmt = $("#live_export_format");
    if (liveExportBtn) liveExportBtn.addEventListener("click", () => {
      const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
      const fmt = (liveExportFmt && liveExportFmt.value) || "txt";
      window.open(`/api/download/${encodeURIComponent(proj)}/${encodeURIComponent(`${proj}_live.${fmt}`)}`, "_blank");
    });
    const liveToggle = $("#live_toggle_results"); const liveBlock = $("#live_results_block");
    if (liveToggle && liveBlock) liveToggle.addEventListener("click", () => {
      liveBlock.classList.toggle("results-collapsed"); liveToggle.textContent = liveBlock.classList.contains("results-collapsed") ? "Expand" : "Collapse";
    });

    // Shodan
    const shodanExportBtn = $("#shodan_export"); const shodanExportFmt = $("#shodan_export_format");
    if (shodanExportBtn) shodanExportBtn.addEventListener("click", () => {
      const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
      const fmt = (shodanExportFmt && shodanExportFmt.value) || "json";
      window.open(`/api/download/${encodeURIComponent(proj)}/${encodeURIComponent(`${proj}_shodan.${fmt}`)}`, "_blank");
    });
    const shodanToggle = $("#shodan_toggle_results"); const shodanBlock = $("#shodan_results_block");
    if (shodanToggle && shodanBlock) shodanToggle.addEventListener("click", () => {
      shodanBlock.classList.toggle("results-collapsed"); shodanToggle.textContent = shodanBlock.classList.contains("results-collapsed") ? "Expand" : "Collapse";
    });
  }

  /* ==========================
     Sections wiring
     ========================== */
  function wireSubdomainsSection() {
    const methodEl = $("#sd_method");
    const sdStart = $("#sd_start");
    const sdWordlistFile = $("#sd_wordlist_file");
    const sdUploadBtn = $("#sd_upload_wordlist");
    const sdWordlistStatus = $("#sd_wordlist_status");

    function ensureApiCheckboxesIncludeRequired() {
      // force crtsh & wayback to be checked
      const crt = $$("input[name=sd_api][value=crtsh]");
      const way = $$("input[name=sd_api][value=wayback]");
      crt.forEach(i => { i.checked = true; i.disabled = true; });
      way.forEach(i => { i.checked = true; i.disabled = true; });
    }
    ensureApiCheckboxesIncludeRequired();

    if (sdUploadBtn && sdWordlistFile) {
      sdUploadBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project from header"); return; }
        const saved = await uploadWordlist(proj, sdWordlistFile, sdWordlistStatus);
        if (saved && sdWordlistStatus) sdWordlistStatus.dataset.saved = saved;
      });
    }

    if (sdStart) {
      sdStart.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Please select a project"); return; }
        const method = methodEl ? (methodEl.value || "api") : "api";
        const commonFormats = ["txt", "json", "csv"];
        const params = { formats: commonFormats };

        // gather checked apis but enforce crtsh & wayback
        let checked = $$("input[name=sd_api]:checked").map(i => i.value);
        if (!Array.isArray(checked)) checked = [];
        if (!checked.includes("crtsh")) checked.unshift("crtsh");
        if (!checked.includes("wayback")) checked.unshift("wayback");
        checked = Array.from(new Set(checked));
        params.apis = checked.length ? checked : ["crtsh", "wayback"];

        if (method === "brute" || method === "both") {
          if (sdWordlistStatus && sdWordlistStatus.dataset && sdWordlistStatus.dataset.saved) {
            params.wordlist = sdWordlistStatus.dataset.saved;
          } else {
            try {
              const settings = await apiGET("/api/settings");
              params.wordlist = settings.default_wordlist || "wordlist.txt";
            } catch (e) {
              params.wordlist = "wordlist.txt";
            }
          }
        }

        // Start flows depending on method
        if (method === "brute") {
          await startJob(proj, "brute", params);
        } else if (method === "api") {
          await startJob(proj, "api", params);
        } else if (method === "both") {
          // Start brute and api separately (not the full workflow)
          const bruteParams = Object.assign({}, params);
          delete bruteParams.apis; // not needed
          const apiParams = Object.assign({}, params);
          delete apiParams.wordlist;
          const jobBrute = await startJob(proj, "brute", bruteParams);
          const jobApi = await startJob(proj, "api", apiParams);
          if (jobBrute) watchJobLogs(jobBrute, async () => { await refreshAllResultsForProject(proj); });
          if (jobApi) watchJobLogs(jobApi, async () => { await refreshAllResultsForProject(proj); });
        } else {
          // Fallback to api
          await startJob(proj, "api", params);
        }
      });
    }
  }

  function wireIpSection() {
    const uploadFile = $("#ip_upload_file");
    const uploadBtn = $("#ip_upload_btn");
    const uploadStatus = $("#ip_upload_status");
    const startBtn = $("#ip_start");

    if (uploadBtn && uploadFile) {
      uploadBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const saved = await uploadGenericFile(proj, uploadFile, uploadStatus);
        if (saved) uploadStatus.dataset.saved = saved;
      });
    }

    if (startBtn) {
      startBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const useUpload = document.querySelector('input[name=ip_source]:checked')?.value === "upload";
        const params = {};
        if (useUpload) {
          if (!uploadStatus?.dataset?.saved) { showToast("Upload a file first"); return; }
          params.input = uploadStatus.dataset.saved;
        }
        await startJob(proj, "ip", params);
      });
    }
  }

  function wireLiveSection() {
    const liveUploadFile = $("#live_upload_file");
    const liveUploadBtn = $("#live_upload_btn");
    const liveUploadStatus = $("#live_upload_status");
    const liveStart = $("#live_start");

    if (liveUploadBtn && liveUploadFile) {
      liveUploadBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const saved = await uploadGenericFile(proj, liveUploadFile, liveUploadStatus);
        if (saved) liveUploadStatus.dataset.saved = saved;
      });
    }
    if (liveStart) {
      liveStart.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const useUpload = document.querySelector('input[name=live_source]:checked')?.value === "upload";
        const params = {};
        if (useUpload) {
          if (!liveUploadStatus?.dataset?.saved) { showToast("Upload a file first"); return; }
          params.input = liveUploadStatus.dataset.saved;
        }
        await startJob(proj, "live", params);
      });
    }
  }

  function wireShodanSection() {
    const shodanUploadFile = $("#shodan_upload_file");
    const shodanUploadBtn = $("#shodan_upload_btn");
    const shodanUploadStatus = $("#shodan_upload_status");
    const shodanStart = $("#shodan_start");

    if (shodanUploadBtn && shodanUploadFile) {
      shodanUploadBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const saved = await uploadGenericFile(proj, shodanUploadFile, shodanUploadStatus);
        if (saved) shodanUploadStatus.dataset.saved = saved;
      });
    }
    if (shodanStart) {
      shodanStart.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const useUpload = document.querySelector('input[name=shodan_source]:checked')?.value === "upload";
        const params = { timeout: Number($("#shodan_timeout")?.value || 15) || 15, delay: Number($("#shodan_delay")?.value || 2) || 2 };
        if (useUpload) {
          if (!shodanUploadStatus?.dataset?.saved) { showToast("Upload a file first"); return; }
          params.input = shodanUploadStatus.dataset.saved;
        }
        await startJob(proj, "shodan", params);
      });
    }
  }

  /* ==========================
     Settings wiring
     ========================== */
  async function loadSettingsToForm() {
    let s = null;
    try { s = await apiGET("/api/settings"); } catch (e) { s = null; }
    if (!s || typeof s !== "object") {
      const cfg = await fetchJsonSafe("/config/config.json");
      if (cfg) s = { ...s, ...cfg };
      else {
        const legacy = await fetchJsonSafe("/.project/settings.json");
        if (legacy) s = { ...s, ...legacy };
      }
    }
    if (!s) s = {};
    if ($("#set_wordlist")) $("#set_wordlist").value = s.default_wordlist || "";
    if ($("#set_threads")) $("#set_threads").value = s.default_threads || 20;
    if ($("#set_timeout")) $("#set_timeout").value = s.default_timeout || 5;
    if ($("#key_virustotal")) $("#key_virustotal").value = (s.api_keys && s.api_keys.virustotal) || s.virustotal || "";
    if ($("#key_securitytrails")) $("#key_securitytrails").value = (s.api_keys && s.api_keys.securitytrails) || s.securitytrails || "";
    if ($("#key_otx")) $("#key_otx").value = (s.api_keys && s.api_keys.otx) || s.otx || "";
    // remove shodan API element if exists (we use upload method)
    const shEl = $("#key_shodan"); if (shEl) shEl.closest("div")?.remove?.();
  }

  async function saveSettingsFromForm() {
    try {
      let current = {};
      try { current = await apiGET("/api/settings") || {}; } catch (e) { current = {}; }
      const setWord = $("#set_wordlist"), setThreads = $("#set_threads"), setTimeout = $("#set_timeout");
      const keyVT = $("#key_virustotal"), keyST = $("#key_securitytrails"), keyOTX = $("#key_otx");
      const existingApiKeys = (current.api_keys && typeof current.api_keys === "object") ? current.api_keys : {};
      const newApiKeys = {
        virustotal: keyVT ? keyVT.value.trim() : (existingApiKeys.virustotal || ""),
        securitytrails: keyST ? keyST.value.trim() : (existingApiKeys.securitytrails || ""),
        otx: keyOTX ? keyOTX.value.trim() : (existingApiKeys.otx || "")
      };
      const body = {
        ...current,
        default_wordlist: setWord ? setWord.value.trim() : (current.default_wordlist || ""),
        default_threads: setThreads ? Number(setThreads.value || 20) : (current.default_threads || 20),
        default_timeout: setTimeout ? Number(setTimeout.value || 5) : (current.default_timeout || 5),
        api_keys: newApiKeys
      };
      const res = await apiPUT("/api/settings", body);
      if (res && res.ok) showToast("Settings saved to /api/settings");
      else showToast("Saved (server may not persist /api/settings)");
      // try write to config route (server might not accept)
      try { await fetch("/config/config.json", { method: "PUT", headers: {"Content-Type":"application/json"}, credentials: "same-origin", body: JSON.stringify(body) }); } catch (e) {}
      try { await fetch("/.project/settings.json", { method: "PUT", headers: {"Content-Type":"application/json"}, credentials: "same-origin", body: JSON.stringify(body) }); } catch (e) {}
    } catch (e) {
      console.error("saveSettingsFromForm", e);
      showToast("Failed to save settings (network)");
    }
  }

  /* ==========================
     Topbar & Dashboard quick actions wiring
     ========================== */
  function wireTopbarAndDashboardQuick() {
    const btnCreate = $("#btnCreateProject");
    const btnDelete = $("#btnDeleteProject");
    const sel = $("#projectSelect");

    if (btnCreate) {
      btnCreate.addEventListener("click", async () => {
        const ans = await showModal("Create Project (domain)", `<p>Enter project domain (e.g. example.com):</p><input id="modalDomainInput" type="text" style="width:100%" placeholder="example.com" />`, [
          { txt: "Create", cls: "btn primary", ret: "create" },
          { txt: "Cancel", cls: "btn", ret: "cancel" }
        ]);
        if (ans === "create") {
          // Try to read the input from DOM first; if missing (modal cleared), fall back to window._lastModalInputs
          let inputVal = "";
          const domInput = document.getElementById("modalDomainInput");
          if (domInput && domInput.value) inputVal = domInput.value.trim();
          else if (window._lastModalInputs && window._lastModalInputs.modalDomainInput) inputVal = ("" + window._lastModalInputs.modalDomainInput).trim();
          if (!inputVal) { showToast("Please enter a domain"); return; }
          if (!isValidDomain(inputVal)) { showToast("Invalid domain format"); return; }
          await createProjectFlow(inputVal);
        }
      });
    }

    if (btnDelete) {
      btnDelete.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const ans = await showModal("Delete Project", `<p>Delete project <strong>${proj}</strong>?</p>`, [
          { txt: "Delete", cls: "btn danger", ret: "delete" },
          { txt: "Cancel", cls: "btn", ret: "cancel" }
        ]);
        if (ans === "delete") {
          try {
            const r = await fetch(`/api/projects/${encodeURIComponent(proj)}`, { method: "DELETE", credentials: "same-origin" });
            if (!r.ok) throw new Error("delete failed");
            await loadProjects();
            const s = $("#projectSelect");
            if (s && s.value === proj) { s.value = ""; onProjectSelectionChanged(""); }
            showToast("Project deleted");
          } catch (e) { console.error(e); showToast("Delete failed"); }
        }
      });
    }

    if (sel) sel.addEventListener("change", () => { const val = sel.value || ""; onProjectSelectionChanged(val); });

    // Header quick start (if present)
    const headerQuickStart = $("#quickStartBtn");
    if (headerQuickStart) {
      headerQuickStart.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const mode = $("#quickScanMode")?.value || "workflow";
        // dashboard/header quick doesn't include "both" option, so map normally
        await startJob(proj, mode, {});
      });
    }

    // Dashboard quick actions: support ids used in some HTML variants
    const dashMode = $("#dashboardQuickMode") || $("#quickScanMode"); // fallback to header select if dashboard lacks one
    const dashStart = $("#dashboardQuickStart") || $("#quickStartBtn"); // fallback to header
    if (dashStart) {
      dashStart.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const mode = dashMode ? (dashMode.value || "workflow") : "workflow";
        await startJob(proj, mode, {});
      });
    }

    // Refresh results quick button on dashboard (if present)
    const btnRefresh = $("#btnRefreshResults");
    if (btnRefresh) btnRefresh.addEventListener("click", () => {
      const proj = getSelectedProject();
      if (!proj) { showToast("Select project"); return; }
      refreshAllResultsForProject(proj);
    });
  }

  /* ==========================
     Wire settings upload & test buttons
     ========================== */
  function wireSettings() {
    const setUploadBtn = $("#set_wordlist_upload"), setUploadFile = $("#set_wordlist_file"), setUploadStatus = $("#set_wordlist_status");
    if (setUploadBtn && setUploadFile) {
      setUploadBtn.addEventListener("click", async () => {
        const proj = getSelectedProject(); if (!proj) { showToast("Select project"); return; }
        const saved = await uploadWordlist(proj, setUploadFile, setUploadStatus);
        if (saved && $("#set_wordlist")) $("#set_wordlist").value = saved;
      });
    }
    const saveBtn = $("#saveSettings"); if (saveBtn) saveBtn.addEventListener("click", saveSettingsFromForm);
    $$(".test-key").forEach(btn => {
      btn.addEventListener("click", async (ev) => {
        const key = ev.currentTarget.dataset.key;
        const input = $(`#key_${key}`);
        const val = input ? input.value : "";
        try {
          const res = await apiPOST("/api/settings/test", { key_name: key, key_value: val });
          if (res && res.ok) showToast(`${key} test OK`);
          else showToast(`${key} test failed: ${res && res.message ? res.message : "invalid"}`);
        } catch (e) {
          showToast(`${key} test failed (network)`);
        }
      });
    });
  }

  /* ==========================
     Dashboard refresh + init
     ========================== */
  async function refreshDashboard() {
    try {
      const data = await apiGET("/api/dashboard");
      if (data && data.totals) {
        safeSetText($("#cardSubdomains"), data.totals.subdomains ?? "-");
        safeSetText($("#cardIps"), data.totals.ips ?? "-");
        safeSetText($("#cardLive"), data.totals.live ?? "-");
        safeSetText($("#cardShodan"), data.totals.shodan ?? "-");
        safeSetText($("#lastUpdated"), new Date().toLocaleString());
        const jobs = await apiGET("/api/jobs");
        const list = $("#activityList");
        if (list) {
          list.innerHTML = "";
          (jobs || []).slice().reverse().slice(0, 12).forEach(j => {
            const li = document.createElement("li");
            const t = new Date((j.started_at || j.created_at || Date.now()) * 1000).toLocaleTimeString();
            li.textContent = `${t} • ${j.domain} • ${j.flow} • ${j.status}`;
            list.appendChild(li);
          });
        }
      }
    } catch (e) { console.warn("dashboard refresh failed", e); }
  }

  /* ==========================
     Initialize & wire everything
     ========================== */
  async function init() {
    if (!document.body) return;

    // sidebar nav
    $$(".side-item").forEach(li => {
      li.addEventListener("click", () => {
        $(".side-item.active")?.classList.remove("active");
        li.classList.add("active");
        const page = li.dataset.page;
        $$(".page").forEach(p => p.classList.toggle("active", p.id === page));
      });
    });

    await loadProjects();
    await loadSettingsToForm();

    wireTopbarAndDashboardQuick();
    wireSubdomainsSection();
    wireIpSection();
    wireLiveSection();
    wireShodanSection();
    wireExportAndCollapse();
    wireSettings();

    // reflect header project select into per-tab displays
    const mainProjSel = $("#projectSelect");
    if (mainProjSel) {
      mainProjSel.addEventListener("change", () => {
        const val = mainProjSel.value;
        onProjectSelectionChanged(val);
      });
    }

    // start periodic dashboard refresh
    refreshDashboard();
    setInterval(refreshDashboard, 5000);

    // modal overlay click to close
    const overlay = modalOverlay();
    if (overlay) overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) hideModal();
    });

    // initial empty tables
    populateEmptyTables();

    showToast("UI ready");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // expose debug helpers
  window.TI = {
    reloadProjects: loadProjects,
    refreshResults: refreshAllResultsForProject,
    startJobForSelected: async (flow, params) => startJob(getSelectedProject(), flow, params)
  };

})();
