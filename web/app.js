"use strict";

const SAMPLE_SCAN = JSON.stringify({
  host: "10.0.0.5",
  ports: [
    { port: 80,  service: "Apache httpd", version: "2.4.49",  banner: "Apache/2.4.49" },
    { port: 21,  service: "vsftpd",        version: "2.3.4",   banner: "220 vsftpd 2.3.4" },
    { port: 22,  service: "OpenSSH",       version: "7.4",     banner: "SSH-2.0-OpenSSH_7.4" },
    { port: 443, service: "OpenSSL",       version: "1.0.1",   banner: "" }
  ]
}, null, 2);

// -------------------------------------------------------------------------- //
// DOM helpers                                                                 //
// -------------------------------------------------------------------------- //

function el(id) { return document.getElementById(id); }

function setScanStatus(msg) {
  const log = el("scan-log");
  // Append a new line for each stage update so the user sees the progression.
  const p = document.createElement("p");
  p.className = "status-log-entry";
  p.textContent = msg;
  log.appendChild(p);
}

function clearScanLog() {
  const log = el("scan-log");
  log.innerHTML = "";
}

function setPasteStatus(msg) {
  el("paste-hint").textContent = msg;
}

function severityClass(s) {
  const map = { critical: "severity-critical", high: "severity-high",
                medium: "severity-medium", low: "severity-low" };
  return map[s] || "severity-low";
}

// All server-supplied strings pass through escHtml before innerHTML insertion.
// Numeric fields go through safeNum, which rejects non-finite values.
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeNum(n, fallback = 0) {
  const v = Number(n);
  return Number.isFinite(v) ? v : fallback;
}

// -------------------------------------------------------------------------- //
// Rendering                                                                   //
// -------------------------------------------------------------------------- //

function renderCveList(cves) {
  if (!cves || cves.length === 0) return "<p>No CVEs matched for this service.</p>";
  const items = cves.map(c => {
    const kevBadge = c.kev ? `<span class="cve-kev" aria-label="CISA Known Exploited">KEV</span>` : "";
    const score   = safeNum(c.composite_score);
    const cvss    = safeNum(c.cvss).toFixed(1);
    const epss    = (safeNum(c.epss) * 100).toFixed(0);
    const summary = escHtml(String(c.summary || "").substring(0, 90));
    const ellipsis = String(c.summary || "").length > 90 ? "..." : "";
    return `
      <li class="cve-item">
        <span class="cve-id">${escHtml(c.id)}</span>
        ${kevBadge}
        <span class="score-pill" title="Composite risk score">score ${score}</span>
        <span class="score-pill" title="CVSS base score">CVSS ${cvss}</span>
        <span class="score-pill" title="EPSS exploit probability">EPSS ${epss}%</span>
        <span style="color:var(--text-muted);font-size:0.78rem;flex:1">${summary}${ellipsis}</span>
      </li>`;
  }).join("");
  return `<ul class="cve-list" aria-label="CVE list">${items}</ul>`;
}

function renderMitre(mitre) {
  if (!mitre || mitre.length === 0) return "";
  const tags = mitre.map(m =>
    `<span class="mitre-tag" title="${escHtml(m.name)}">${escHtml(m.technique)} ${escHtml(m.tactic)}</span>`
  ).join("");
  return `<div class="mitre-tags" aria-label="MITRE ATT&CK techniques">${tags}</div>`;
}

function renderRemediationCommand(cmd) {
  if (!cmd) return "";
  return `
    <div class="remediation-cmd" role="note" aria-label="Copy-paste remediation command">
      <span class="remediation-cmd-label">Command</span>
      <code class="remediation-cmd-code" title="Click to select">${escHtml(cmd)}</code>
    </div>`;
}

function renderFinding(f) {
  const sevClass = severityClass(f.contextual_severity);
  const port     = safeNum(f.port);
  const priority = safeNum(f.priority);
  return `
    <article class="finding-card" aria-label="Finding: port ${port} ${escHtml(f.service)}">
      <div class="finding-header">
        <span class="priority-badge" aria-label="Priority ${priority}">#${priority}</span>
        <span class="severity-badge ${sevClass}" role="img" aria-label="Severity ${escHtml(f.contextual_severity)}">${escHtml(f.contextual_severity)}</span>
        <span class="service-name">${escHtml(f.service)}</span>
        <span class="port-label">port ${port} &middot; ${escHtml(f.version)}</span>
      </div>
      ${renderCveList(f.cves)}
      ${renderMitre(f.mitre)}
      <p class="finding-detail">${escHtml(f.rationale)}</p>
      <div class="finding-remediation" role="note" aria-label="Recommended remediation">
        ${escHtml(f.remediation)}
      </div>
      ${renderRemediationCommand(f.remediation_command)}
    </article>`;
}

function renderComparison(findings, naiveCvssOrder) {
  if (!naiveCvssOrder || naiveCvssOrder.length < 2) return "";

  // Sentinel order: findings sorted by priority ascending (already sorted).
  const sentinelRows = (findings || []).map((f, i) => {
    const topScore = Math.max(0, ...(f.cves || []).map(c => safeNum(c.composite_score)));
    return `
      <div class="comparison-row">
        <span class="comparison-rank">${i + 1}.</span>
        <span class="comparison-svc">${escHtml(f.service)} <span style="color:var(--text-muted);font-size:0.72rem">:${safeNum(f.port)}</span></span>
        <span class="comparison-score">score ${topScore}</span>
      </div>`;
  }).join("");

  const cvssRows = naiveCvssOrder.map((e, i) => {
    return `
      <div class="comparison-row">
        <span class="comparison-rank">${i + 1}.</span>
        <span class="comparison-svc">${escHtml(e.service)} <span style="color:var(--text-muted);font-size:0.72rem">:${safeNum(e.port)}</span></span>
        <span class="comparison-score">CVSS ${safeNum(e.cvss).toFixed(1)}</span>
      </div>`;
  }).join("");

  return `
    <section class="comparison-section" aria-label="Priority comparison: CVSS vs Sentinel">
      <h3>How prioritization changes</h3>
      <div class="comparison-grid">
        <div class="comparison-col">
          <div class="comparison-col-title">Sorted by CVSS alone</div>
          ${cvssRows}
        </div>
        <div class="comparison-col">
          <div class="comparison-col-title sentinel">Sentinel composite priority</div>
          ${sentinelRows}
        </div>
      </div>
    </section>`;
}

function renderAttackPath(ap) {
  if (!ap) return "";
  const steps = (ap.steps || []).map((s, i) => {
    const arrow = i < ap.steps.length - 1 ? `<span class="step-arrow" aria-hidden="true">&#8594;</span>` : "";
    const fport = safeNum(s.finding_port);
    return `
      <div class="attack-step">
        <div>${escHtml(s.technique)}</div>
        <div class="attack-step-tactic">${escHtml(s.tactic)}</div>
        <div style="font-size:0.7rem;color:var(--text-muted)">port ${fport}</div>
      </div>
      ${arrow}`;
  }).join("");

  return `
    <section class="attack-path-section" aria-labelledby="attack-path-heading">
      <h3 id="attack-path-heading">Attack path (MITRE ATT&CK)</h3>
      <div class="attack-path-card">
        <p class="attack-path-narrative">${escHtml(ap.narrative)}</p>
        <div class="attack-steps" role="list" aria-label="Attack chain steps">${steps}</div>
        <div class="break-point" role="note" aria-label="Highest-leverage fix">
          ${escHtml(ap.break_point)}
        </div>
      </div>
    </section>`;
}

function renderResult(data) {
  const riskScore = Math.min(100, Math.max(0, safeNum(data.host_risk_score)));
  const riskColor = riskScore >= 80 ? "var(--critical-fg)"
                  : riskScore >= 60 ? "var(--high-fg)"
                  : riskScore >= 35 ? "var(--medium-fg)"
                  : "var(--low-fg)";

  const findingCount = safeNum((data.findings || []).length);
  const findings = (data.findings || []).map(renderFinding).join("");
  const comparison = renderComparison(data.findings, data.naive_cvss_order);

  return `
    <div class="host-header" role="region" aria-labelledby="host-heading">
      <h2 id="host-heading">${escHtml(data.host)}</h2>
      <p style="color:var(--text-muted);font-size:0.85rem;margin-top:0.25rem">${escHtml(data.summary)}</p>
      <div class="risk-bar-wrap" aria-label="Host risk score ${riskScore} out of 100">
        <div class="risk-bar-track" role="progressbar" aria-valuenow="${riskScore}" aria-valuemin="0" aria-valuemax="100">
          <div class="risk-bar-fill" style="width:${riskScore}%"></div>
        </div>
        <span class="risk-score-label" style="color:${riskColor}">${riskScore}</span>
      </div>
    </div>

    ${comparison}

    <section class="findings-section" aria-label="Findings ranked by risk">
      <h3>Findings (${findingCount}, ranked worst-first)</h3>
      ${findings}
    </section>

    ${renderAttackPath(data.attack_path)}`;
}

function showError(msg) {
  const resultsEl = el("results");
  resultsEl.innerHTML = `<div class="error-card" role="alert"><strong>Error:</strong> ${escHtml(msg)}</div>`;
  resultsEl.classList.add("visible");
}

function showResults(data) {
  const resultsEl = el("results");
  resultsEl.innerHTML = renderResult(data);
  resultsEl.classList.add("visible");
  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

function clearResults() {
  const resultsEl = el("results");
  resultsEl.innerHTML = "";
  resultsEl.classList.remove("visible");
}

// -------------------------------------------------------------------------- //
// Primary: scan flow                                                          //
// -------------------------------------------------------------------------- //

async function runScan() {
  const host = el("host-input").value.trim();
  if (!host) {
    setScanStatus("Enter a target host first.");
    el("host-input").focus();
    return;
  }

  const btn = el("scan-btn");
  btn.disabled = true;
  clearResults();
  clearScanLog();
  setScanStatus(`Scanning ports and grabbing banners on ${host}...`);

  // Staged progress messages that reflect the real pipeline steps.
  const stageTimers = [
    setTimeout(() => setScanStatus("Enriching findings via threat intel..."),   3000),
    setTimeout(() => setScanStatus("Scoring and mapping MITRE ATT&CK..."), 6000),
    setTimeout(() => setScanStatus("Ranking and writing remediation..."),        8000),
  ];

  function cancelStages() { stageTimers.forEach(clearTimeout); }

  try {
    const resp = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host }),
    });
    cancelStages();
    const data = await resp.json();
    if (!resp.ok) {
      showError(data.error || `Server returned ${resp.status}`);
      setScanStatus("Scan failed.");
      return;
    }
    showResults(data);
    const n = (data.findings || []).length;
    const backendLabel = data.threat_backend === "oracle"
      ? "Oracle 23ai Vector DB"
      : "local threat cache";
    setScanStatus(`Done. ${n} finding(s) analyzed via ${backendLabel}.`);
  } catch (err) {
    cancelStages();
    showError(`Could not reach the server: ${err.message}`);
    setScanStatus("Scan failed.");
  } finally {
    btn.disabled = false;
  }
}

// -------------------------------------------------------------------------- //
// Secondary: paste scan JSON flow                                             //
// -------------------------------------------------------------------------- //

async function runTriage() {
  const scan = el("scan-input").value.trim();
  if (!scan) {
    setPasteStatus("Paste scan JSON first.");
    el("scan-input").focus();
    return;
  }

  const btn = el("triage-btn");
  btn.disabled = true;
  clearResults();
  setPasteStatus("Enriching findings via threat intel...");

  const stageTimers = [
    setTimeout(() => setPasteStatus("Scoring and mapping MITRE ATT&CK..."), 1000),
    setTimeout(() => setPasteStatus("Ranking and writing remediation..."),       2000),
  ];

  function cancelStages() { stageTimers.forEach(clearTimeout); }

  try {
    const resp = await fetch("/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan }),
    });
    cancelStages();
    const data = await resp.json();
    if (!resp.ok) {
      showError(data.error || `Server returned ${resp.status}`);
      setPasteStatus("Analysis failed.");
      return;
    }
    showResults(data);
    const n = (data.findings || []).length;
    const backendLabel = data.threat_backend === "oracle"
      ? "Oracle 23ai Vector DB"
      : "local threat cache";
    setPasteStatus(`Done. ${n} finding(s) analyzed via ${backendLabel}.`);
  } catch (err) {
    cancelStages();
    showError(`Could not reach the server: ${err.message}`);
    setPasteStatus("Analysis failed.");
  } finally {
    btn.disabled = false;
  }
}

// -------------------------------------------------------------------------- //
// Event wiring                                                                //
// -------------------------------------------------------------------------- //

el("scan-btn").addEventListener("click", runScan);

el("host-input").addEventListener("keydown", e => {
  if (e.key === "Enter") {
    e.preventDefault();
    runScan();
  }
});

el("triage-btn").addEventListener("click", runTriage);

el("scan-input").addEventListener("keydown", e => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    runTriage();
  }
});

el("sample-btn").addEventListener("click", () => {
  el("scan-input").value = SAMPLE_SCAN;
  setPasteStatus("Sample scan loaded. Click Analyze to run.");
  el("scan-input").focus();
});

el("clear-btn").addEventListener("click", () => {
  el("scan-input").value = "";
  clearResults();
  setPasteStatus("Paste scan JSON, then click Analyze.");
  el("scan-input").focus();
});
