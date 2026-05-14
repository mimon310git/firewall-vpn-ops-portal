"use strict";

const API_BASE = "/api";
const ROLE_KEY = "firewallVpnOpsPortal:v2:role";

const emptyState = {
  roles: ["requester", "approver", "operator"],
  currentRole: "requester",
  labMode: false,
  rules: [],
  tunnels: [],
  checks: [],
  labTargets: [],
  audit: [],
};

let state = { ...emptyState, roles: [...emptyState.roles] };
let currentRole = localStorage.getItem(ROLE_KEY) || "requester";
let currentView = "dashboard";
let currentSnippet = "Generate an OPNsense or pfSense snippet from approved and deployed rules.";

const viewTitles = {
  dashboard: "Firewall and VPN Operations",
  firewall: "Firewall Rule Requests",
  theory: "Firewall and VPN Theory",
  vpn: "VPN Tunnel Inventory",
  approvals: "Approval Queue",
  health: "Health Checks",
  lab: "Lab Tools",
};

const pageTitle = document.querySelector("#pageTitle");
const navItems = document.querySelectorAll("[data-view]");
const viewLinks = document.querySelectorAll("[data-view-link]");
const ruleForm = document.querySelector("#ruleForm");
const tunnelForm = document.querySelector("#tunnelForm");
const ruleError = document.querySelector("#ruleError");
const tunnelError = document.querySelector("#tunnelError");
const commandPreview = document.querySelector("#commandPreview");
const roleSelect = document.querySelector("#roleSelect");
const globalMessage = document.querySelector("#globalMessage");
const runChecksBtn = document.querySelector("#runChecksBtn");
const runChecksTopBtn = document.querySelector("#runChecksTopBtn");
const exportBtn = document.querySelector("#exportBtn");
const resetBtn = document.querySelector("#resetBtn");
const labTargetForm = document.querySelector("#labTargetForm");
const labTargetError = document.querySelector("#labTargetError");
const runLabChecksBtn = document.querySelector("#runLabChecksBtn");
const generateSnippetBtn = document.querySelector("#generateSnippetBtn");
const snippetPlatform = document.querySelector("#snippetPlatform");
const snippetPreview = document.querySelector("#snippetPreview");
const labModePill = document.querySelector("#labModePill");

if (!emptyState.roles.includes(currentRole)) {
  currentRole = "requester";
}

roleSelect.value = currentRole;

navItems.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

viewLinks.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.viewLink));
});

roleSelect.addEventListener("change", async () => {
  currentRole = roleSelect.value;
  localStorage.setItem(ROLE_KEY, currentRole);
  clearMessage();
  await loadState();
});

runChecksBtn.addEventListener("click", runHealthChecks);
runChecksTopBtn.addEventListener("click", runHealthChecks);
exportBtn.addEventListener("click", exportData);
resetBtn.addEventListener("click", resetData);
runLabChecksBtn.addEventListener("click", runLabChecks);
generateSnippetBtn.addEventListener("click", generateSnippet);

ruleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(ruleForm);
  const rule = {
    source: clean(formData.get("source")),
    destination: clean(formData.get("destination")),
    protocol: clean(formData.get("protocol")),
    port: clean(formData.get("port")),
    reason: clean(formData.get("reason")),
    owner: clean(formData.get("owner")),
  };

  try {
    await apiRequest("/rules", {
      method: "POST",
      body: JSON.stringify(rule),
    });
    ruleError.textContent = "";
    ruleForm.reset();
    await loadState();
    showMessage("Firewall request created.", "success");
  } catch (error) {
    ruleError.textContent = error.message;
  }
});

tunnelForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(tunnelForm);
  const tunnel = {
    name: clean(formData.get("name")),
    type: clean(formData.get("type")),
    peer: clean(formData.get("peer")),
    localNet: clean(formData.get("localNet")),
    remoteNet: clean(formData.get("remoteNet")),
    owner: clean(formData.get("owner")),
  };

  try {
    await apiRequest("/tunnels", {
      method: "POST",
      body: JSON.stringify(tunnel),
    });
    tunnelError.textContent = "";
    tunnelForm.reset();
    await loadState();
    showMessage("VPN entry created.", "success");
  } catch (error) {
    tunnelError.textContent = error.message;
  }
});

labTargetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(labTargetForm);
  const target = {
    name: clean(formData.get("name")),
    kind: clean(formData.get("kind")),
    host: clean(formData.get("host")),
    port: Number(clean(formData.get("port"))),
    enabled: formData.has("enabled"),
  };

  try {
    await apiRequest("/lab-targets", {
      method: "POST",
      body: JSON.stringify(target),
    });
    labTargetError.textContent = "";
    labTargetForm.reset();
    labTargetForm.elements.enabled.checked = true;
    await loadState();
    showMessage("Lab target created.", "success");
  } catch (error) {
    labTargetError.textContent = error.message;
  }
});

async function loadState() {
  try {
    state = await apiRequest("/state");
    currentRole = state.currentRole || currentRole;
    roleSelect.value = currentRole;
    render();
  } catch (error) {
    state = { ...emptyState, roles: [...emptyState.roles], currentRole };
    render();
    showMessage(
      `FastAPI backend is not reachable. Start it with: uvicorn backend.main:app --reload`,
      "error",
    );
  }
}

async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  headers.set("X-User-Role", currentRole);
  headers.set("X-User-Name", currentRole);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  } catch {
    throw new Error("API request failed.");
  }

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();

  if (!response.ok) {
    const detail = typeof payload === "object" && payload !== null ? payload.detail : payload;
    throw new Error(detail || `Request failed with status ${response.status}.`);
  }

  return payload;
}

function showView(viewName) {
  currentView = viewName;
  navItems.forEach((item) => item.classList.toggle("is-active", item.dataset.view === viewName));
  document
    .querySelectorAll(".view")
    .forEach((view) => view.classList.toggle("is-visible", view.id === `view-${viewName}`));
  pageTitle.textContent = viewTitles[viewName] || viewTitles.dashboard;
}

function render() {
  renderMetrics();
  renderRules();
  renderTunnels();
  renderApprovals();
  renderHealth();
  renderLabTools();
  renderAudit();
  syncRoleControls();
  showView(currentView);
}

function syncRoleControls() {
  setFormEnabled(ruleForm, can("requester"));
  setFormEnabled(tunnelForm, can("requester"));
  runChecksBtn.disabled = !can("operator");
  runChecksTopBtn.disabled = !can("operator");
  resetBtn.disabled = !can("operator");
  runLabChecksBtn.disabled = !can("operator");
  generateSnippetBtn.disabled = !can("operator");
  setFormEnabled(labTargetForm, can("operator"));
}

function setFormEnabled(form, enabled) {
  form.querySelectorAll("input, select, textarea, button").forEach((control) => {
    control.disabled = !enabled;
  });
}

function renderMetrics() {
  const metrics = [
    {
      label: "Firewall rules",
      value: state.rules.length,
      note: `${countBy(state.rules, "pending")} pending approval`,
    },
    {
      label: "VPN tunnels",
      value: state.tunnels.length,
      note: `${countBy(state.tunnels, "up")} currently up`,
    },
    {
      label: "Failed checks",
      value: countBy(state.checks, "fail"),
      note: "Needs investigation",
    },
    {
      label: "High risk",
      value: state.rules.filter((rule) => rule.risk === "high").length,
      note: "Broad or exposed access",
    },
    {
      label: "Lab targets",
      value: state.labTargets.length,
      note: state.labMode ? "Real checks enabled" : "Controlled mode off",
    },
  ];

  document.querySelector("#metricGrid").innerHTML = metrics
    .map(
      (metric) => `
        <article class="metric-card">
          <span>${escapeHtml(metric.label)}</span>
          <strong>${metric.value}</strong>
          <small>${escapeHtml(metric.note)}</small>
        </article>
      `,
    )
    .join("");
}

function renderRules() {
  const table = document.querySelector("#rulesTable");
  if (!state.rules.length) {
    table.innerHTML = `<tr><td colspan="6">No firewall rules yet.</td></tr>`;
    return;
  }

  table.innerHTML = state.rules
    .map((rule) => {
      const actions = [];
      if (rule.status === "approved") {
        actions.push(`<button class="table-action" type="button" data-command="${rule.id}">Command</button>`);
        if (can("operator")) {
          actions.push(`<button class="table-action" type="button" data-deploy="${rule.id}">Deploy</button>`);
        }
      }
      if (rule.status === "pending" && can("approver")) {
        actions.push(`<button class="table-action" type="button" data-approve="${rule.id}">Approve</button>`);
      }

      return `
        <tr>
          <td><code>${escapeHtml(rule.source)}</code></td>
          <td><code>${escapeHtml(rule.destination)}</code></td>
          <td>${escapeHtml(rule.protocol)}/${escapeHtml(rule.port)}</td>
          <td><span class="status-pill ${rule.status}">${escapeHtml(rule.status)}</span></td>
          <td><span class="status-pill ${rule.risk}">${escapeHtml(rule.risk)}</span></td>
          <td>
            <div class="button-row">${actions.join("") || `<span class="muted-cell">-</span>`}</div>
          </td>
        </tr>
      `;
    })
    .join("");

  table.querySelectorAll("[data-approve]").forEach((button) => {
    button.addEventListener("click", () => approveRule(button.dataset.approve));
  });

  table.querySelectorAll("[data-deploy]").forEach((button) => {
    button.addEventListener("click", () => deployRule(button.dataset.deploy));
  });

  table.querySelectorAll("[data-command]").forEach((button) => {
    button.addEventListener("click", () => previewCommand(button.dataset.command));
  });
}

function renderTunnels() {
  const grid = document.querySelector("#tunnelGrid");
  if (!state.tunnels.length) {
    grid.innerHTML = `<div class="empty-state">No VPN tunnels yet.</div>`;
    return;
  }

  grid.innerHTML = state.tunnels
    .map((tunnel) => {
      const actions = can("operator")
        ? `<div class="button-row">
            <button class="table-action" type="button" data-tunnel-up="${tunnel.id}">Mark up</button>
            <button class="table-action danger" type="button" data-tunnel-down="${tunnel.id}">Mark down</button>
          </div>`
        : "";

      return `
        <article class="tunnel-card">
          <header>
            <div>
              <strong>${escapeHtml(tunnel.name)}</strong>
              <div class="panel-label">${escapeHtml(tunnel.type)}</div>
            </div>
            <span class="status-pill ${tunnel.status}">${escapeHtml(tunnel.status)}</span>
          </header>
          <dl class="detail-list">
            <div><dt>Peer</dt><dd>${escapeHtml(tunnel.peer)}</dd></div>
            <div><dt>Local</dt><dd>${escapeHtml(tunnel.localNet)}</dd></div>
            <div><dt>Remote</dt><dd>${escapeHtml(tunnel.remoteNet)}</dd></div>
            <div><dt>Owner</dt><dd>${escapeHtml(tunnel.owner)}</dd></div>
          </dl>
          ${actions}
        </article>
      `;
    })
    .join("");

  grid.querySelectorAll("[data-tunnel-up]").forEach((button) => {
    button.addEventListener("click", () => updateTunnel(button.dataset.tunnelUp, "up"));
  });

  grid.querySelectorAll("[data-tunnel-down]").forEach((button) => {
    button.addEventListener("click", () => updateTunnel(button.dataset.tunnelDown, "down"));
  });
}

function renderApprovals() {
  const queue = document.querySelector("#approvalQueue");
  const pendingRules = state.rules.filter((rule) => rule.status === "pending");
  const pendingTunnels = state.tunnels.filter((tunnel) => tunnel.status === "pending");

  if (!pendingRules.length && !pendingTunnels.length) {
    queue.innerHTML = `<div class="empty-state">Approval queue is empty.</div>`;
    return;
  }

  queue.innerHTML = [
    ...pendingRules.map(
      (rule) => `
        <article class="approval-item">
          <header>
            <div>
              <strong>${escapeHtml(rule.id)} firewall rule</strong>
              <p>${escapeHtml(rule.source)} -> ${escapeHtml(rule.destination)} ${escapeHtml(rule.protocol)}/${escapeHtml(rule.port)}</p>
            </div>
            <span class="status-pill ${rule.risk}">${escapeHtml(rule.risk)} risk</span>
          </header>
          <p>${escapeHtml(rule.reason)}</p>
          ${renderApprovalActions(rule.id, "rule")}
        </article>
      `,
    ),
    ...pendingTunnels.map(
      (tunnel) => `
        <article class="approval-item">
          <header>
            <div>
              <strong>${escapeHtml(tunnel.id)} VPN tunnel</strong>
              <p>${escapeHtml(tunnel.name)}: ${escapeHtml(tunnel.localNet)} -> ${escapeHtml(tunnel.remoteNet)}</p>
            </div>
            <span class="status-pill pending">pending</span>
          </header>
          <p>Peer ${escapeHtml(tunnel.peer)} managed by ${escapeHtml(tunnel.owner)}.</p>
          ${renderApprovalActions(tunnel.id, "tunnel")}
        </article>
      `,
    ),
  ].join("");

  queue.querySelectorAll("[data-approve]").forEach((button) => {
    button.addEventListener("click", () => approveRule(button.dataset.approve));
  });

  queue.querySelectorAll("[data-reject]").forEach((button) => {
    button.addEventListener("click", () => rejectRule(button.dataset.reject));
  });

  queue.querySelectorAll("[data-tunnel-approve]").forEach((button) => {
    button.addEventListener("click", () => approveTunnel(button.dataset.tunnelApprove));
  });

  queue.querySelectorAll("[data-tunnel-reject]").forEach((button) => {
    button.addEventListener("click", () => rejectTunnel(button.dataset.tunnelReject));
  });
}

function renderApprovalActions(id, type) {
  if (!can("approver")) {
    return `<span class="status-pill neutral">approver action</span>`;
  }

  if (type === "rule") {
    return `
      <div class="button-row">
        <button class="table-action" type="button" data-approve="${id}">Approve</button>
        <button class="table-action danger" type="button" data-reject="${id}">Reject</button>
      </div>
    `;
  }

  return `
    <div class="button-row">
      <button class="table-action" type="button" data-tunnel-approve="${id}">Approve as up</button>
      <button class="table-action danger" type="button" data-tunnel-reject="${id}">Reject / down</button>
    </div>
  `;
}

function renderHealth() {
  const grid = document.querySelector("#healthGrid");
  if (!state.checks.length) {
    grid.innerHTML = `<div class="empty-state">No health checks are available.</div>`;
    return;
  }

  grid.innerHTML = state.checks
    .map(
      (check) => `
        <article class="health-card">
          <header>
            <div>
              <strong>${escapeHtml(check.name)}</strong>
              <div class="panel-label">${escapeHtml(check.type)}</div>
            </div>
            <span class="status-pill ${check.status}">${escapeHtml(check.status)}</span>
          </header>
          <p>${escapeHtml(check.target)}</p>
          <dl class="detail-list">
            <div><dt>Latency</dt><dd>${check.latency ? `${check.latency} ms` : "n/a"}</dd></div>
            <div><dt>Last run</dt><dd>${escapeHtml(check.lastRun)}</dd></div>
          </dl>
          <p>${escapeHtml(check.detail)}</p>
        </article>
      `,
    )
    .join("");
}

function renderLabTools() {
  labModePill.textContent = state.labMode ? "Lab mode on" : "Lab mode off";
  labModePill.className = `status-pill ${state.labMode ? "ok" : "neutral"}`;
  snippetPreview.textContent = currentSnippet;

  const grid = document.querySelector("#labTargetGrid");
  if (!state.labTargets.length) {
    grid.innerHTML = `<div class="empty-state">No lab targets are configured.</div>`;
    return;
  }

  grid.innerHTML = state.labTargets
    .map((target) => {
      const action = can("operator")
        ? `<button class="table-action" type="button" data-toggle-lab="${target.id}">
            ${target.enabled ? "Disable" : "Enable"}
          </button>`
        : "";
      const statusClass = target.enabled ? target.lastStatus : "neutral";
      return `
        <article class="lab-card">
          <header>
            <div>
              <strong>${escapeHtml(target.name)}</strong>
              <div class="panel-label">${escapeHtml(target.kind)} ${escapeHtml(target.host)}:${target.port}</div>
            </div>
            <span class="status-pill ${statusClass}">${escapeHtml(target.enabled ? target.lastStatus : "disabled")}</span>
          </header>
          <dl class="detail-list">
            <div><dt>Enabled</dt><dd>${target.enabled ? "yes" : "no"}</dd></div>
            <div><dt>Last run</dt><dd>${escapeHtml(target.lastRun)}</dd></div>
          </dl>
          <p>${escapeHtml(target.lastDetail)}</p>
          <div class="button-row">${action}</div>
        </article>
      `;
    })
    .join("");

  grid.querySelectorAll("[data-toggle-lab]").forEach((button) => {
    const target = state.labTargets.find((item) => item.id === button.dataset.toggleLab);
    button.addEventListener("click", () => toggleLabTarget(target.id, !target.enabled));
  });
}

function renderAudit() {
  const feed = document.querySelector("#recentAudit");
  if (!state.audit.length) {
    feed.innerHTML = `<div class="empty-state">No audit events yet.</div>`;
    return;
  }

  feed.innerHTML = state.audit
    .slice(0, 6)
    .map(
      (event) => `
        <article class="audit-event">
          <strong>${escapeHtml(event.action)}</strong>
          <span>${escapeHtml(event.at)} - ${escapeHtml(event.actor)} - ${escapeHtml(event.target)}</span>
        </article>
      `,
    )
    .join("");
}

async function approveRule(id) {
  try {
    const rule = await apiRequest(`/rules/${id}/approve`, { method: "POST" });
    previewCommandFromRule(rule);
    await loadState();
    showMessage("Firewall request approved.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function rejectRule(id) {
  try {
    await apiRequest(`/rules/${id}/reject`, { method: "POST" });
    await loadState();
    showMessage("Firewall request rejected.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function deployRule(id) {
  try {
    const rule = await apiRequest(`/rules/${id}/deploy`, { method: "POST" });
    previewCommandFromRule(rule);
    await loadState();
    showMessage("Firewall rule marked as deployed.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

function previewCommand(id) {
  const rule = state.rules.find((item) => item.id === id);
  if (!rule) return;
  previewCommandFromRule(rule);
}

function previewCommandFromRule(rule) {
  const comment = rule.reason.replaceAll('"', "'");
  const command =
    rule.protocol === "ICMP"
      ? `# Simulated deployment note for ${rule.id}
# Create a pass ICMP rule from ${rule.source} to ${rule.destination}.
# Reason: ${comment}`
      : `# Simulated deployment command for ${rule.id}
sudo ufw allow proto ${rule.protocol.toLowerCase()} from ${rule.source} to ${rule.destination} port ${rule.port} comment "${comment}"`;
  commandPreview.textContent = command;
}

async function approveTunnel(id) {
  try {
    await apiRequest(`/tunnels/${id}/approve`, { method: "POST" });
    await loadState();
    showMessage("VPN tunnel approved.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function rejectTunnel(id) {
  try {
    await apiRequest(`/tunnels/${id}/reject`, { method: "POST" });
    await loadState();
    showMessage("VPN tunnel rejected.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function updateTunnel(id, status) {
  try {
    await apiRequest(`/tunnels/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    });
    await loadState();
    showMessage(`VPN tunnel marked ${status}.`, "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function runHealthChecks() {
  try {
    await apiRequest("/checks/run", { method: "POST" });
    await loadState();
    showMessage("Health checks completed.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function runLabChecks() {
  try {
    const result = await apiRequest("/lab-checks/run", { method: "POST" });
    state.labMode = result.labMode;
    state.labTargets = result.targets;
    render();
    showMessage(
      result.labMode
        ? "Read-only lab checks completed."
        : "Lab checks skipped. Enable OPS_PORTAL_LAB_MODE=enabled on the backend to contact lab hosts.",
      result.labMode ? "success" : "info",
    );
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function toggleLabTarget(id, enabled) {
  try {
    await apiRequest(`/lab-targets/${id}/toggle`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
    await loadState();
    showMessage(enabled ? "Lab target enabled." : "Lab target disabled.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function generateSnippet() {
  try {
    const response = await apiRequest(`/snippets/${snippetPlatform.value}`);
    currentSnippet = response.snippet;
    snippetPreview.textContent = currentSnippet;
    showMessage(`${response.platform} snippet generated for manual review.`, "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

async function resetData() {
  try {
    state = await apiRequest("/reset", { method: "POST" });
    commandPreview.textContent = "Select an approved rule to generate a deployment command.";
    render();
    showMessage("Demo data reset.", "success");
  } catch (error) {
    showMessage(error.message, "error");
  }
}

function exportData() {
  const exportPayload = {
    rules: state.rules,
    tunnels: state.tunnels,
    checks: state.checks,
    labTargets: state.labTargets,
    audit: state.audit,
  };
  const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "firewall-vpn-ops-export.json";
  link.click();
  URL.revokeObjectURL(url);
}

function can(role) {
  return currentRole === role;
}

function countBy(collection, value) {
  return collection.filter((item) => item.status === value).length;
}

function clean(value) {
  return String(value || "").trim();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showMessage(message, type = "info") {
  globalMessage.textContent = message;
  globalMessage.className = `global-message is-visible ${type}`;
}

function clearMessage() {
  globalMessage.textContent = "";
  globalMessage.className = "global-message";
}

loadState();
