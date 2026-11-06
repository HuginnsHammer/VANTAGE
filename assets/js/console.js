const $ = (id) => document.getElementById(id);
const API = "/api/v1";
let pollHandle = null;
let currentFindings = [];

async function request(path, options = {}) {
  const response = await fetch(API + path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail;
    const message = typeof detail === "string" ? detail : detail?.message || JSON.stringify(detail || body);
    throw new Error(message || `Request failed (${response.status})`);
  }
  return body;
}
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[char]);
}
function date(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "—" : parsed.toLocaleString();
}
function setConnection(online, label) {
  $("connection").classList.toggle("online", online);
  $("connection").innerHTML = `<i></i>${esc(label)}`;
  $("offline").hidden = online;
}
async function loadHealth() {
  try {
    const health = await request("/health");
    setConnection(true, health.scanner_available ? "API ONLINE · CLOUDSENTRY READY" : "API ONLINE · SCANNER NOT FOUND");
    if (!health.scanner_available) {
      $("connection").title = "Set VANTAGE_CLOUDSENTRY_EXECUTABLE to the CloudSentry CLI path.";
    }
  } catch {
    setConnection(false, "API OFFLINE");
    throw new Error("VANTAGE API is not reachable.");
  }
}
async function loadOverview() {
  const data = await request("/overview");
  $("metric-assets").textContent = data.assets;
  $("metric-scans").textContent = data.scans;
  $("metric-findings").textContent = data.active_findings;
  $("metric-priority").textContent = `${data.critical} / ${data.high}`;
}
async function loadAssets() {
  const data = await request("/assets");
  const host = $("assets-list");
  if (!data.items.length) {
    host.className = "asset-list empty";
    host.textContent = "No workspaces registered. Add a local project you own to begin.";
    return;
  }
  host.className = "asset-list";
  host.innerHTML = data.items.map((asset) => `
    <div class="asset-row">
      <div><div class="asset-name">${esc(asset.display_name)}</div><div class="asset-path">${esc(asset.canonical_value)}</div><div class="subtle">AUTH REF · ${esc(asset.authorization_reference)}</div></div>
      <span class="asset-kind">LOCAL WORKSPACE</span>
      <button class="small-button" data-scan="${esc(asset.id)}">Run assessment ↗</button>
    </div>`).join("");
  host.querySelectorAll("[data-scan]").forEach((button) => {
    button.addEventListener("click", () => startScan(button.dataset.scan, button));
  });
}
async function loadFindings() {
  const status = $("finding-filter").value;
  const data = await request("/findings" + (status ? "?status=" + encodeURIComponent(status) : ""));
  currentFindings = data.items;
  const host = $("findings-list");
  if (!data.items.length) {
    host.className = "finding-list empty";
    host.textContent = "No findings match this view. Run an assessment to inspect your workspace.";
    return;
  }
  host.className = "finding-list";
  host.innerHTML = data.items.map((finding) => `
    <div class="finding-row" tabindex="0" role="button" data-finding="${esc(finding.id)}">
      <span class="severity-dot ${esc(finding.severity)}"></span>
      <div><div class="finding-title">${esc(finding.title)}</div><div class="finding-meta">${esc(finding.severity)} · ${esc(finding.status)} · ${esc(finding.confidence)} CONFIDENCE</div></div>
      <span class="risk-score">${finding.risk_score}/100</span>
    </div>`).join("");
  host.querySelectorAll("[data-finding]").forEach((row) => {
    const open = () => showFinding(row.dataset.finding);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); });
  });
}
async function loadScans() {
  const data = await request("/scans");
  const host = $("scans-list");
  if (!data.items.length) {
    host.className = "scan-list empty";
    host.textContent = "No assessments have been run.";
    return;
  }
  host.className = "scan-list";
  host.innerHTML = data.items.map((scan) => `
    <div class="scan-row">
      <div><div class="scan-name">${esc(scan.asset_name)}</div><div class="finding-meta">${esc(scan.scanner_id)} · ${esc(date(scan.created_at))}</div>${scan.error ? `<div class="error">${esc(scan.error)}</div>` : ""}</div>
      <span class="scan-state ${esc(scan.state)}">${esc(scan.state)}</span>
    </div>`).join("");
}
async function refreshAll() {
  try {
    await loadHealth();
    await Promise.all([loadOverview(), loadAssets(), loadFindings(), loadScans()]);
  } catch (error) {
    setConnection(false, "API OFFLINE");
    $("assets-list").textContent = error.message;
  }
}
async function startScan(assetId, button) {
  button.disabled = true;
  button.textContent = "Queueing…";
  try {
    const scan = await request(`/assets/${encodeURIComponent(assetId)}/scans`, { method: "POST", body: "{}" });
    button.textContent = "Assessment queued";
    await refreshAll();
    if (pollHandle) clearInterval(pollHandle);
    pollHandle = setInterval(async () => {
      await refreshAll();
      const state = await request(`/scans/${encodeURIComponent(scan.id)}`);
      if (["completed", "partial", "failed", "cancelled"].includes(state.state)) {
        clearInterval(pollHandle);
        pollHandle = null;
        await refreshAll();
      }
    }, 1800);
  } catch (error) {
    button.disabled = false;
    button.textContent = "Run assessment ↗";
    alert(error.message);
  }
}
async function showFinding(id) {
  const finding = currentFindings.find((item) => item.id === id);
  if (!finding) return;
  const evidence = (finding.evidence || []).map((item) => `
    <div class="detail-section"><h3>${esc(item.kind)} · ${esc(item.source_scanner)}</h3><p>${esc(item.summary)}${item.location ? "\n" + esc(item.location) : ""}</p></div>`).join("");
  $("finding-detail").innerHTML = `
    <span class="badge">${esc(finding.severity)} · ${esc(finding.status)} · RISK ${finding.risk_score}/100</span>
    <h2 class="detail-title">${esc(finding.title)}</h2>
    <p class="subtle">FIRST SEEN ${esc(date(finding.first_seen_at))} · OBSERVED ${finding.occurrence_count} TIME(S)</p>
    <div class="detail-section"><h3>DESCRIPTION</h3><p>${esc(finding.description || "No description supplied.")}</p></div>
    ${evidence || '<div class="detail-section"><h3>EVIDENCE</h3><p>No evidence was attached by the scanner.</p></div>'}
    <div class="detail-section"><h3>RECOMMENDED REMEDIATION</h3><p>${esc(finding.remediation || "Review the affected configuration and validate the correct remediation.")}</p></div>
    <div class="detail-section"><h3>ANALYST DISPOSITION</h3><div class="detail-actions">
      <button class="small-button" data-status="open">Reopen</button>
      <button class="small-button" data-status="accepted_risk">Accept risk</button>
      <button class="small-button" data-status="suppressed">Suppress</button>
    </div><label style="margin-top:12px">Reason for disposition<input id="disposition-reason" placeholder="Required audit reason"></label><div id="disposition-error" class="error"></div></div>`;
  $("finding-detail").querySelectorAll("[data-status]").forEach((button) => {
    button.addEventListener("click", async () => {
      const reason = $("disposition-reason").value.trim();
      if (reason.length < 3) { $("disposition-error").textContent = "Enter a reason (at least 3 characters)."; return; }
      button.disabled = true;
      try {
        await request(`/findings/${encodeURIComponent(id)}`, {
          method: "PATCH", body: JSON.stringify({ status: button.dataset.status, reason }),
        });
        $("finding-dialog").close();
        await refreshAll();
      } catch (error) {
        $("disposition-error").textContent = error.message;
        button.disabled = false;
      }
    });
  });
  $("finding-dialog").showModal();
}
$("show-add").addEventListener("click", () => {
  $("add-form").hidden = !$("add-form").hidden;
  if (!$("add-form").hidden) $("workspace-path").focus();
});
$("preview-path").addEventListener("click", async () => {
  $("form-error").textContent = "";
  $("preview-result").hidden = true;
  try {
    const preview = await request("/assets/preview", {
      method: "POST", body: JSON.stringify({ path: $("workspace-path").value.trim() }),
    });
    $("preview-copy").textContent = `Resolved target: ${preview.resolved_path}. Copy the exact phrase below to authorize registration.`;
    $("confirmation").value = preview.confirmation_phrase;
    $("preview-result").hidden = false;
  } catch (error) { $("form-error").textContent = error.message; }
});
$("register-workspace").addEventListener("click", async () => {
  $("form-error").textContent = "";
  const button = $("register-workspace");
  button.disabled = true;
  try {
    await request("/assets", {
      method: "POST",
      body: JSON.stringify({
        path: $("workspace-path").value.trim(),
        authorization_reference: $("authorization-reference").value.trim(),
        confirmation: $("confirmation").value,
        display_name: $("display-name").value.trim() || null,
      }),
    });
    $("add-form").hidden = true;
    $("preview-result").hidden = true;
    $("workspace-path").value = "";
    $("authorization-reference").value = "";
    $("display-name").value = "";
    await refreshAll();
  } catch (error) { $("form-error").textContent = error.message; }
  finally { button.disabled = false; }
});
$("finding-filter").addEventListener("change", loadFindings);
$("refresh").addEventListener("click", refreshAll);
$("close-dialog").addEventListener("click", () => $("finding-dialog").close());
$("finding-dialog").addEventListener("click", (event) => {
  if (event.target === $("finding-dialog")) $("finding-dialog").close();
});
refreshAll();
