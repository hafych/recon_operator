const state = {
  lastResult: null,
  previousResult: null,
  lastPlan: null,
  lastBrief: null,
  lastDiff: null,
  lastPosture: null,
  toolsContext: "",
  view: "summary",
  apiHeader: "X-API-KEY",
  apiAuthRequired: true,
  authIdentity: null,
  connectedToken: null,
  activeJobId: null,
  activeEngagementId: null,
  catalog: { presets: [], playbooks: [] },
  jobs: [],
  tasks: [],
  historyIds: [],
  selectedResultId: null,
  lastResultId: null,
  previousResultId: null,
  lastRefreshAt: null,
  lastScanStartedAt: null,
  lastScanFinishedAt: null,
  lastScanDurationMs: null,
};

const $ = (id) => document.getElementById(id);
const terminalJobStatuses = new Set(["completed", "failed", "cancelled", "timeout"]);
const terminalEngagementStatuses = new Set(["completed", "failed", "cancelled"]);

function createElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function formatClock(value) {
  if (!value) return "never";
  try {
    return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return String(value);
  }
}

function formatDateTime(value) {
  if (!value) return "unknown time";
  try {
    return new Date(value).toLocaleString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return String(value);
  }
}

function formatDuration(ms) {
  if (ms == null || Number.isNaN(ms)) return "";
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
}

function elapsedBetween(start, finish) {
  if (!start) return "";
  const startMs = Date.parse(start);
  const finishMs = finish ? Date.parse(finish) : Date.now();
  if (!Number.isFinite(startMs) || !Number.isFinite(finishMs)) return "";
  return formatDuration(finishMs - startMs);
}

function updateTimingPills() {
  $("lastRefresh").textContent = state.lastRefreshAt
    ? `refreshed ${formatClock(state.lastRefreshAt)}`
    : "never refreshed";
  if (state.lastScanFinishedAt) {
    const duration = formatDuration(state.lastScanDurationMs);
    $("lastScanMeta").textContent = duration
      ? `${formatClock(state.lastScanFinishedAt)} · ${duration}`
      : formatClock(state.lastScanFinishedAt);
  } else if (state.lastScanStartedAt) {
    $("lastScanMeta").textContent = `running · ${formatClock(state.lastScanStartedAt)}`;
  } else {
    $("lastScanMeta").textContent = "none";
  }
}

const tokenInput = $("apiToken");
tokenInput.value = sessionStorage.getItem("recon_api_token")
  || sessionStorage.getItem("nmap_api_token")
  || "";

function saveToken() {
  const value = tokenInput.value;
  sessionStorage.setItem("recon_api_token", value);
  sessionStorage.setItem("nmap_api_token", value);
}

function resetOwnerWorkspace() {
  state.lastResult = null;
  state.previousResult = null;
  state.lastResultId = null;
  state.previousResultId = null;
  state.lastPlan = null;
  state.lastBrief = null;
  state.lastDiff = null;
  state.lastPosture = null;
  state.toolsContext = "";
  state.activeJobId = null;
  state.activeEngagementId = null;
  state.selectedResultId = null;
  state.historyIds = [];
  state.jobs = [];
  state.tasks = [];
  state.lastScanStartedAt = null;
  state.lastScanFinishedAt = null;
  state.lastScanDurationMs = null;
  renderJobs([]);
  renderTasks([]);
  renderHistory([]);
  renderPlaybookPreview();
  $("toolsBox").value = "";
  $("auditList").replaceChildren(
    createElement("div", "empty-state", "Load audit events with an authorized admin key."),
  );
  $("postureOutput").textContent = "No posture evaluation yet.";
  selectResultView("summary");
  updateTimingPills();
}

function headers() {
  const token = tokenInput.value.trim();
  return token
    ? { "Content-Type": "application/json", [state.apiHeader]: token }
    : { "Content-Type": "application/json" };
}

function setConnectionState(label, tone = "neutral") {
  $("connectionLabel").textContent = label;
  $("connectionState").dataset.tone = tone;
}

function setButtonBusy(button, busy, busyLabel = "Working…") {
  if (!button) return;
  if (busy) {
    button.dataset.idleLabel = button.textContent;
    button.textContent = busyLabel;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
  } else {
    button.textContent = button.dataset.idleLabel || button.textContent;
    button.disabled = false;
    button.removeAttribute("aria-busy");
    delete button.dataset.idleLabel;
  }
}

function say(message, tone = "info") {
  const toast = $("toast");
  toast.textContent = message;
  toast.dataset.tone = tone;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...headers(), ...(options.headers || {}) },
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!response.ok) {
    const detail = body && body.error ? body.error : response.statusText;
    const error = new Error(`${response.status}: ${detail}`);
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

function scanPayload() {
  const body = {
    target: $("target").value.trim(),
    interval: Number($("interval").value),
  };
  const preset = $("preset").value.trim();
  if (preset) {
    body.preset = preset;
  } else {
    body.scan_type = $("scanType").value;
  }
  const ports = $("ports").value.trim();
  const scripts = $("scripts").value.trim();
  const discovery = $("discovery").value.trim();
  if (ports) body.ports = ports;
  if (scripts) body.scripts = scripts;
  if (discovery) body.discovery = discovery;
  return body;
}

function observations(result) {
  if (!result || !Array.isArray(result.hosts)) return [];
  const rows = [];
  for (const host of result.hosts) {
    rows.push({
      type: "host",
      host: host.host,
      hostname: host.hostname,
      state: host.state,
    });
    for (const [protocol, ports] of Object.entries(host.protocols || {})) {
      for (const port of ports) {
        rows.push({
          type: "service",
          host: host.host,
          hostname: host.hostname,
          protocol,
          port: port.port,
          state: port.state,
          service: {
            name: port.name,
            product: port.product,
            version: port.version,
            extrainfo: port.extrainfo,
          },
          llm_hint: `${host.host} has ${protocol}/${port.port} ${port.state} (${port.name || "unknown"})`,
        });
      }
    }
  }
  return rows;
}

function openServices(result) {
  return observations(result).filter((row) => row.type === "service" && row.state === "open");
}

function metrics(result) {
  const hosts = Array.isArray(result?.hosts) ? result.hosts : [];
  const services = openServices(result);
  const serviceNames = new Set(services.map((row) => row.service.name || "unknown"));
  return {
    hosts: hosts.length,
    up: hosts.filter((host) => host.state === "up").length,
    open: services.length,
    services: serviceNames.size,
  };
}

function summary(result) {
  if (!result) return "";
  const lines = [
    `Product: ${result.product || "Recon Operator"}`,
    `Scan time: ${result.scan_time || result.generated_at || "unknown"}`,
    `Profile: ${result.scan_type || result.profile || "unknown"}`,
    "",
  ];
  for (const host of result.hosts || []) {
    lines.push(`${host.host || "unknown"}${host.hostname ? ` (${host.hostname})` : ""} — ${host.state || "unknown"}`);
    const rows = [];
    for (const [protocol, ports] of Object.entries(host.protocols || {})) {
      for (const port of ports) {
        if (port.state !== "open") continue;
        const version = [port.product, port.version, port.extrainfo].filter(Boolean).join(" ");
        rows.push(`  ${protocol}/${port.port}  ${port.name || "unknown"}${version ? ` — ${version}` : ""}`);
      }
    }
    lines.push(...(rows.length ? rows : ["  no open ports observed"]), "");
  }
  return lines.join("\n").trim();
}

function diffText(diff) {
  if (!diff) return "No diff available.";
  const report = diff.diff || diff;
  const summaryRow = diff.summary || report.summary || {};
  const lines = [
    `Changed: ${summaryRow.changed ? "yes" : "no"}`,
    `Ports opened: ${summaryRow.ports_opened || 0}`,
    `Ports closed: ${summaryRow.ports_closed || 0}`,
    `Hosts added: ${summaryRow.hosts_added || 0}`,
    `Hosts removed: ${summaryRow.hosts_removed || 0}`,
  ];
  const changes = report.changes || diff.changes || [
    ...(report.ports_opened || []).map((change) => ({ ...change, type: "opened" })),
    ...(report.ports_closed || []).map((change) => ({ ...change, type: "closed" })),
    ...(report.hosts_added || []).map((host) => ({ host, type: "host added" })),
    ...(report.hosts_removed || []).map((host) => ({ host, type: "host removed" })),
  ];
  if (changes.length) {
    lines.push("", "Changes:");
    for (const change of changes) {
      lines.push(`- ${change.type || change.op || "change"}: ${change.host || ""} ${change.protocol || ""}/${change.port || ""}`.trim());
    }
  }
  return lines.join("\n");
}

function planText(plan) {
  if (!plan) return "No recon plan built.";
  if (typeof plan === "string") return plan;
  const lines = [];
  if (plan.summary) {
    lines.push(
      `Recommendations: ${plan.summary.recommendations || 0}`,
      `Ready: ${plan.summary.ready || 0}`,
      `Missing tools: ${plan.summary.missing || 0}`,
      "",
    );
  }
  for (const item of plan.recommendations || plan.steps || []) {
    lines.push(
      `${item.status ? `[${item.status}] ` : ""}${item.title || item.tool || item.id || "Next step"}`,
      item.command ? `  ${item.command}` : "",
      item.reason ? `  ${item.reason}` : "",
      "",
    );
  }
  return lines.filter((line, index, values) => line || values[index - 1]).join("\n").trim();
}

function resultDisplayName(result, sourceId) {
  const target = result?.target || result?.scan_target;
  const profile = result?.scan_type || result?.profile;
  if (target && profile) return `${target} · ${profile}`;
  if (target) return target;
  if (sourceId) return humanizeResultId(sourceId);
  return "Scan result";
}

function humanizeResultId(value) {
  return String(value || "")
    .replace(/^o[a-f0-9]{12}_/, "")
    .replace(/\.json$/, "")
    .replace(/_\d{8}_\d{6}_\d{6}$/, "")
    .replaceAll("_", " ");
}

function renderServiceTable(result) {
  const body = $("serviceTableBody");
  body.replaceChildren();
  const rows = openServices(result);
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = createElement("td", "table-empty", "No open services observed.");
    td.colSpan = 5;
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    const host = row.hostname ? `${row.host} (${row.hostname})` : row.host;
    const version = [row.service.product, row.service.version, row.service.extrainfo]
      .filter(Boolean)
      .join(" ");
    for (const value of [
      host || "unknown",
      row.state || "unknown",
      `${row.protocol}/${row.port}`,
      row.service.name || "unknown",
      version || "—",
    ]) {
      tr.appendChild(createElement("td", "", value));
    }
    body.appendChild(tr);
  }
}

function renderServiceSummary(result) {
  const counts = new Map();
  for (const row of openServices(result)) {
    const name = row.service.name || "unknown";
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  const parts = [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 8)
    .map(([name, count]) => `${name} ${count}`);
  $("serviceBars").textContent = parts.length
    ? `Observed services: ${parts.join(" · ")}`
    : "No service distribution yet.";
}

function renderResult() {
  const result = state.lastResult;
  const resultMetrics = metrics(result);
  $("hostMetric").textContent = resultMetrics.hosts;
  $("upMetric").textContent = resultMetrics.up;
  $("openMetric").textContent = resultMetrics.open;
  $("serviceMetric").textContent = resultMetrics.services;

  $("resultTitle").textContent = result
    ? resultDisplayName(result, state.selectedResultId)
    : "No result selected";
  $("resultSource").textContent = state.selectedResultId
    ? `Encrypted history · ${humanizeResultId(state.selectedResultId)}`
    : result
      ? "Current session"
      : "No source";
  $("resultLabel").textContent = result
    ? `${state.view.toUpperCase()} view · ${result.scan_time || result.generated_at || "timestamp unavailable"}`
    : "Run a scan or open encrypted history to inspect evidence.";

  renderServiceSummary(result);
  renderServiceTable(result);
  $("serviceTableWrap").classList.toggle("is-hidden", state.view !== "summary");

  let content = "";
  if (state.view === "json") content = result ? JSON.stringify(result, null, 2) : "";
  else if (state.view === "jsonl") content = observations(result).map((row) => JSON.stringify(row)).join("\n");
  else if (state.view === "plan") content = planText(state.lastPlan);
  else if (state.view === "brief") content = state.lastBrief || "Build an AI pack from the selected result.";
  else if (state.view === "diff") content = diffText(state.lastDiff);
  else content = summary(result);
  $("resultBox").value = content;

  for (const id of ["planBtn", "briefBtn", "copyBtn", "exportBtn"]) {
    $(id).disabled = !result;
  }
  $("diffBtn").disabled = !(state.previousResult && state.lastResult) && state.historyIds.length < 2;
}

function selectResultView(view, { focus = false } = {}) {
  state.view = view;
  document.querySelectorAll(".tabs button").forEach((button) => {
    const selected = button.dataset.view === view;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
    if (selected && focus) button.focus();
  });
  renderResult();
}

function presetFallback(id) {
  return {
    discovery: { label: "Host discovery", description: "Lightweight liveness check using Ping.", scan_type: "Ping", order: 1 },
    map: { label: "Service map", description: "Version detection on common service ports.", scan_type: "Version", order: 2 },
    safe: { label: "Safe NSE depth", description: "Version scan with safe NSE scripts.", scan_type: "Safe", order: 3 },
    depth: { label: "Full TCP/script pass", description: "Broader TCP and default-script coverage.", scan_type: "Full", order: 4 },
    vuln: { label: "Vuln NSE", description: "Vulnerability scripts; explicit authorization required.", scan_type: "Vuln", order: 5 },
    hybrid: { label: "Hybrid discovery", description: "Fast discovery followed by Nmap service detection.", scan_type: "Hybrid", order: 2 },
  }[id];
}

function renderPresetMeta() {
  const id = $("preset").value;
  const preset = state.catalog.presets.find((item) => item.id === id) || presetFallback(id);
  const root = $("presetMeta");
  root.replaceChildren();
  if (!preset) {
    root.append(
      createElement("strong", "", `Custom · ${$("scanType").value}`),
      createElement("span", "", "Operator-defined profile. Review advanced ports, scripts, and discovery options before launch."),
    );
    $("presetRisk").textContent = ["Vuln", "Full", "Aggressive", "OS", "UDP"].includes($("scanType").value)
      ? "Review impact"
      : "Operator defined";
    $("presetRisk").dataset.tone = ["Vuln", "Aggressive"].includes($("scanType").value) ? "warning" : "neutral";
    return;
  }
  if ([...$("scanType").options].some((option) => option.value === preset.scan_type)) {
    $("scanType").value = preset.scan_type;
  }
  root.append(
    createElement("strong", "", `${preset.label} · ${preset.scan_type}`),
    createElement("span", "", preset.description || "Named authorized reconnaissance preset."),
  );
  const order = Number(preset.order || 1);
  $("presetRisk").textContent = order >= 5 ? "Explicit authorization" : order >= 4 ? "Higher impact" : order >= 3 ? "Moderate depth" : "Low impact";
  $("presetRisk").dataset.tone = order >= 5 ? "danger" : order >= 4 ? "warning" : order >= 3 ? "info" : "success";
}

function renderPlaybookPreview(record = null) {
  const selectedId = record?.playbook || $("playbookSelect").value;
  const catalog = state.catalog.playbooks.find((item) => item.id === selectedId);
  const fallback = {
    quick: { description: "discovery → map", phases: ["discovery", "map"] },
    standard: { description: "discovery → map → safe", phases: ["discovery", "map", "safe"] },
    deep: { description: "discovery → map → safe → depth", phases: ["discovery", "map", "safe", "depth"] },
  }[selectedId] || { description: "Custom ordered phases", phases: [] };
  const playbook = catalog || fallback;
  $("playbookMeta").textContent = playbook.description || "Sequential authorized scan phases.";

  const timeline = $("playbookTimeline");
  timeline.replaceChildren();
  const steps = record?.steps || (playbook.phases || []).map((phase) => ({ phase, status: "pending" }));
  if (!steps.length) {
    const item = createElement("li", "", "No phases available.");
    item.dataset.status = "pending";
    timeline.appendChild(item);
    return;
  }
  for (const step of steps) {
    const item = document.createElement("li");
    item.dataset.status = step.status || "pending";
    const details = [step.scan_type, step.status].filter(Boolean).join(" · ");
    const text = createElement("span", "", `${step.phase || "phase"}${details ? ` — ${details}` : ""}${step.error ? ` — ${step.error}` : ""}`);
    item.appendChild(text);
    timeline.appendChild(item);
  }
}

async function refreshKeyMeta() {
  const token = tokenInput.value.trim();
  if (state.apiAuthRequired && !token) {
    if (state.authIdentity !== null) resetOwnerWorkspace();
    state.authIdentity = null;
    state.connectedToken = null;
    $("keyMeta").textContent = "Key not identified.";
    setConnectionState("Not connected", "neutral");
    return false;
  }
  try {
    const key = await api("/auth/whoami");
    const identity = key.owner_id_prefix || key.key_id || "local";
    if (state.authIdentity !== null && state.authIdentity !== identity) {
      resetOwnerWorkspace();
    }
    state.authIdentity = identity;
    state.connectedToken = token;
    const scopes = Array.isArray(key.scopes) ? key.scopes.join(", ") : "unknown scopes";
    $("keyMeta").textContent = `${key.label || key.key_id || "API key"} · ${scopes}`;
    $("productVersion").textContent = key.version ? `v${key.version}` : "local";
    setConnectionState(key.label || key.key_id || "Connected", "success");
    return true;
  } catch (error) {
    if (state.authIdentity !== null) resetOwnerWorkspace();
    state.authIdentity = null;
    state.connectedToken = null;
    $("keyMeta").textContent = error.message;
    setConnectionState("Authentication failed", "error");
    return false;
  }
}

function populateSelect(select, items, labelBuilder) {
  if (!items.length) return;
  const selected = select.value;
  select.replaceChildren();
  for (const item of items) {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = labelBuilder(item);
    select.appendChild(option);
  }
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
}

async function refreshCatalog() {
  try {
    const payload = await api("/presets");
    state.catalog.presets = Array.isArray(payload.presets) ? payload.presets : [];
    state.catalog.playbooks = Array.isArray(payload.playbooks) ? payload.playbooks : [];
    const presetSelect = $("preset");
    const custom = document.createElement("option");
    custom.value = "";
    custom.textContent = "Custom profile";
    const selectedPreset = presetSelect.value;
    presetSelect.replaceChildren(custom);
    for (const preset of state.catalog.presets) {
      const option = document.createElement("option");
      option.value = preset.id;
      option.textContent = `${preset.label} — ${preset.scan_type}`;
      presetSelect.appendChild(option);
    }
    if ([...presetSelect.options].some((option) => option.value === selectedPreset)) {
      presetSelect.value = selectedPreset;
    }
    populateSelect($("playbookSelect"), state.catalog.playbooks, (item) => item.label || item.id);
    renderPresetMeta();
    renderPlaybookPreview();
  } catch {
    renderPresetMeta();
    renderPlaybookPreview();
  }
}

function renderJobs(jobs) {
  state.jobs = Array.isArray(jobs) ? jobs : [];
  const root = $("jobs");
  root.replaceChildren();
  const active = state.jobs.filter((job) => !terminalJobStatuses.has(job.status));
  $("jobCount").textContent = state.jobs.length;
  $("runningCount").textContent = active.length;
  $("jobSummary").textContent = state.jobs.length ? `${state.jobs.length} recent · ${active.length} active` : "No jobs";

  if (!state.jobs.length) {
    root.appendChild(createElement("div", "empty-state", "No scan jobs yet."));
    return;
  }

  for (const job of state.jobs.slice(0, 10)) {
    const item = createElement("article", "activity-item");
    const main = createElement("div", "activity-main");
    const top = createElement("div", "activity-topline");
    top.append(
      createElement("span", "activity-target", job.target || "unknown target"),
      createElement("span", "status-badge", job.status || "unknown"),
    );
    top.lastElementChild.dataset.status = job.status || "unknown";
    const duration = elapsedBetween(job.started_at || job.created_at, job.finished_at);
    const meta = [job.scan_type, job.kind, duration, formatDateTime(job.created_at)].filter(Boolean).join(" · ");
    main.append(top, createElement("div", "activity-meta", job.error ? `${meta} · ${job.error}` : meta));
    item.appendChild(main);

    if (!terminalJobStatuses.has(job.status)) {
      const cancel = createElement("button", "button danger", "Cancel");
      cancel.type = "button";
      cancel.setAttribute("aria-label", `Cancel ${job.status} job for ${job.target || "target"}`);
      cancel.addEventListener("click", () => cancelJob(job));
      item.appendChild(cancel);
    } else if (job.result_file) {
      const open = createElement("button", "button secondary", "Open result");
      open.type = "button";
      open.addEventListener("click", () => openResult(job.result_file));
      item.appendChild(open);
    }
    root.appendChild(item);
  }
}

function renderTasks(tasks) {
  state.tasks = Array.isArray(tasks) ? tasks : [];
  const root = $("tasks");
  root.replaceChildren();
  $("taskCount").textContent = state.tasks.length;
  $("scheduleSummary").textContent = `${state.tasks.length} configured`;
  if (!state.tasks.length) {
    root.appendChild(createElement("div", "empty-state", "No scheduled scans."));
    return;
  }
  for (const task of state.tasks) {
    const item = createElement("article", "activity-item");
    const main = createElement("div", "activity-main");
    const top = createElement("div", "activity-topline");
    top.append(
      createElement("span", "activity-target", task.target || task.id),
      createElement("span", "status-badge", task.running ? "active" : "waiting"),
    );
    top.lastElementChild.dataset.status = task.running ? "running" : "queued";
    main.append(
      top,
      createElement("div", "activity-meta", `${task.scan_type || "scan"} · every ${task.interval_minutes || "?"} minutes`),
    );
    const cancel = createElement("button", "button danger", "Cancel");
    cancel.type = "button";
    cancel.setAttribute("aria-label", `Cancel scheduled task ${task.id}`);
    cancel.addEventListener("click", () => cancelTask(task));
    item.append(main, cancel);
    root.appendChild(item);
  }
}

async function cancelJob(job) {
  if (!window.confirm(`Cancel ${job.status} job for ${job.target}?`)) return;
  try {
    await api(`/jobs/${encodeURIComponent(job.job_id)}`, { method: "DELETE" });
    say(`Cancelled job for ${job.target}.`, "success");
    await refresh({ announce: false });
  } catch (error) {
    say(error.message, "error");
  }
}

async function cancelTask(task) {
  if (!window.confirm(`Cancel scheduled ${task.scan_type || "scan"} for ${task.target || task.id}?`)) return;
  try {
    await api(`/tasks/${encodeURIComponent(task.id)}`, { method: "DELETE" });
    say(`Cancelled schedule for ${task.target || task.id}.`, "success");
    await refresh({ announce: false });
  } catch (error) {
    say(error.message, "error");
  }
}

async function refreshActivity() {
  const [jobs, tasks] = await Promise.all([api("/jobs"), api("/tasks")]);
  renderJobs(jobs);
  renderTasks(tasks);
}

async function refresh({ announce = true } = {}) {
  const button = $("refreshBtn");
  setButtonBusy(button, true, "Refreshing…");
  try {
    let health;
    try {
      health = await api("/health");
      $("apiStatus").textContent = health.status || "healthy";
      $("nmapStatus").textContent = health.nmap_available ? "ready" : "unavailable";
    } catch (error) {
      health = error.body && typeof error.body === "object" ? error.body : null;
      $("apiStatus").textContent = error.status === 503 ? "degraded" : "offline";
      $("nmapStatus").textContent = "unknown";
    }
    if (health) {
      state.apiHeader = health.api_auth_header || "X-API-KEY";
      state.apiAuthRequired = health.api_auth_required !== false;
    }

    const authenticated = await refreshKeyMeta();
    if (authenticated) {
      await Promise.all([
        refreshActivity(),
        refreshHistory({ announce: false }),
        refreshCatalog(),
      ]);
    } else {
      renderJobs([]);
      renderTasks([]);
      renderHistory([]);
    }
    state.lastRefreshAt = Date.now();
    updateTimingPills();
    if (announce) {
      say(
        authenticated
          ? "Workspace refreshed."
          : "API is reachable. Connect a valid key to load operator data.",
        authenticated ? "success" : "warning",
      );
    }
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

function renderHistory(items) {
  const rows = Array.isArray(items) ? items : [];
  const root = $("history");
  root.replaceChildren();
  $("historyCount").textContent = rows.length;
  $("historyPaneCount").textContent = rows.length;
  if (!rows.length) {
    root.appendChild(createElement("div", "empty-state", "No encrypted results yet."));
    return;
  }
  for (const item of rows) {
    const id = item.id || item.filename;
    const button = createElement("button", "history-item");
    button.type = "button";
    button.setAttribute("aria-current", String(id === state.selectedResultId));
    const main = createElement("div", "history-main");
    const top = createElement("div", "history-topline");
    top.appendChild(createElement("span", "history-target", humanizeResultId(id)));
    main.append(
      top,
      createElement("div", "history-meta", formatDateTime(item.modified_at)),
      createElement("div", "history-id", id),
    );
    button.appendChild(main);
    button.setAttribute("aria-label", `Open result ${humanizeResultId(id)}`);
    button.addEventListener("click", () => openResult(id));
    root.appendChild(button);
  }
}

async function openResult(id) {
  try {
    const payload = await api(`/results/${encodeURIComponent(id)}`);
    state.selectedResultId = id;
    rememberResult(payload.result, id);
    selectResultView("summary");
    await refreshHistory({ announce: false });
    $("results").scrollIntoView({ block: "start", behavior: "smooth" });
    say(`Loaded ${humanizeResultId(id)}.`, "success");
  } catch (error) {
    say(error.message, "error");
  }
}

async function refreshHistory({ announce = true } = {}) {
  try {
    const payload = await api("/results?limit=30");
    const items = payload.results || [];
    state.historyIds = items.map((item) => item.id || item.filename);
    renderHistory(items);
    renderResult();
    if (announce) say(`History refreshed: ${items.length} results.`, "success");
  } catch (error) {
    if (error.status === 401) renderHistory([]);
    if (announce) say(error.message, "error");
  }
}

function renderTools(inventory, context) {
  const summaryRow = inventory.summary || {};
  const profiles = inventory.profiles || [];
  const missing = summaryRow.missing_packages || [];
  state.toolsContext = typeof context === "string" ? context : JSON.stringify(context || {});
  $("toolChecked").textContent = summaryRow.packages_checked || 0;
  $("toolAvailable").textContent = summaryRow.available || 0;
  $("toolMissing").textContent = summaryRow.missing || 0;
  $("toolProfiles").textContent = profiles.length;

  const missingRoot = $("missingTools");
  missingRoot.replaceChildren();
  if (!missing.length) {
    missingRoot.textContent = "No missing packages reported in the selected inventory scope.";
  } else {
    missingRoot.appendChild(createElement("strong", "", `${missing.length} missing: `));
    for (const name of missing.slice(0, 18)) {
      missingRoot.appendChild(createElement("span", "missing-chip", name));
    }
  }

  const lines = [
    `Schema: ${inventory.schema || "unknown"}`,
    `Source: ${inventory.source || "local system"}`,
    `Profiles: ${profiles.map((profile) => profile.profile || profile.name).join(", ") || "none"}`,
    `Packages checked: ${summaryRow.packages_checked || 0}`,
    `Ready: ${summaryRow.available || 0}`,
    `Missing: ${summaryRow.missing || 0}`,
  ];
  if (missing.length) lines.push("", "Missing packages:", ...missing.map((name) => `- ${name}`));
  $("toolsBox").value = lines.join("\n");
}

async function refreshTools() {
  const button = $("toolsBtn");
  setButtonBusy(button, true, "Inspecting…");
  try {
    const [inventory, context] = await Promise.all([
      api("/tools?expand=0"),
      api("/tools/ai-context?format=jsonl&expand=0"),
    ]);
    renderTools(inventory, context);
    say(`Tool inventory refreshed: ${(inventory.summary || {}).available || 0} ready.`, "success");
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

function rememberResult(result, sourceId = null) {
  const normalizedId = sourceId ? String(sourceId) : null;
  const isDifferent = normalizedId
    ? normalizedId !== state.lastResultId
    : state.lastResult !== null && state.lastResult !== result;
  if (state.lastResult && isDifferent) {
    state.previousResult = state.lastResult;
    state.previousResultId = state.lastResultId;
  }
  state.lastResult = result;
  state.lastResultId = normalizedId;
  state.lastPlan = null;
  state.lastBrief = null;
  state.lastDiff = null;
  state.lastPosture = null;
}

function upsertLiveJob(job) {
  const index = state.jobs.findIndex((item) => item.job_id === job.job_id);
  if (index >= 0) state.jobs[index] = { ...state.jobs[index], ...job };
  else state.jobs.unshift(job);
  renderJobs(state.jobs);
}

async function waitForJob(jobId) {
  while (true) {
    const job = await api(`/jobs/${encodeURIComponent(jobId)}`);
    state.activeJobId = jobId;
    upsertLiveJob(job);
    if (terminalJobStatuses.has(job.status)) return job;
    say(`Scan ${job.status} for ${job.target}…`, "info");
    await sleep(850);
  }
}

async function loadAiBrief({ retest = false } = {}) {
  if (!state.lastResult) {
    say("Select a result first.", "warning");
    return;
  }
  const button = $("briefBtn");
  setButtonBusy(button, true, "Building…");
  try {
    const payload = { scan: state.lastResult, budget: "s" };
    let path = "/ai/pack?budget=s";
    if (retest && state.previousResult) {
      payload.baseline = state.previousResult;
      path = "/ai/pack?mode=retest&budget=s";
    }
    const response = await fetch(path, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(payload),
    });
    const text = await response.text();
    if (!response.ok) {
      let detail = response.statusText;
      try {
        detail = JSON.parse(text).error || detail;
      } catch {
        // Plain-text error response.
      }
      throw new Error(`${response.status}: ${detail}`);
    }
    state.lastBrief = text;
    selectResultView("brief");
    say(`AI pack ready: ${text.split("\n").filter(Boolean).length} compact lines.`, "success");
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function runScan() {
  const button = $("scanBtn");
  setButtonBusy(button, true, "Running…");
  say("Queueing authorized scan…", "info");
  state.lastScanStartedAt = Date.now();
  state.lastScanFinishedAt = null;
  state.lastScanDurationMs = null;
  state.selectedResultId = null;
  updateTimingPills();
  try {
    const job = await api("/scan", {
      method: "POST",
      body: JSON.stringify(scanPayload()),
    });
    upsertLiveJob(job);
    const finished = await waitForJob(job.job_id);
    state.lastScanFinishedAt = Date.now();
    state.lastScanDurationMs = state.lastScanFinishedAt - state.lastScanStartedAt;
    updateTimingPills();
    if (finished.status !== "completed") {
      throw new Error(finished.error || `Scan ${finished.status}`);
    }
    rememberResult(finished.result, finished.result_file);
    state.selectedResultId = finished.result_file || null;
    selectResultView("summary");
    const duration = formatDuration(state.lastScanDurationMs) || "under 1s";
    say(`Scan complete in ${duration}. Evidence encrypted and added to history.`, "success");
    await refresh({ announce: false });
    $("results").scrollIntoView({ block: "start", behavior: "smooth" });
  } catch (error) {
    state.lastScanFinishedAt = Date.now();
    if (state.lastScanStartedAt) state.lastScanDurationMs = state.lastScanFinishedAt - state.lastScanStartedAt;
    updateTimingPills();
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
    state.activeJobId = null;
  }
}

async function importXml() {
  const xml = $("xmlImport").value.trim();
  if (!xml) {
    say("Paste Nmap XML first.", "warning");
    return;
  }
  const button = $("importBtn");
  setButtonBusy(button, true, "Importing…");
  try {
    const payload = await api("/results/import", {
      method: "POST",
      body: JSON.stringify({ xml, target: $("target").value.trim() || "xml-import" }),
    });
    rememberResult(payload.result, payload.filename);
    state.selectedResultId = payload.filename || null;
    selectResultView("summary");
    say("XML imported into encrypted history.", "success");
    await refreshHistory({ announce: false });
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function diffLastTwo() {
  const button = $("diffBtn");
  setButtonBusy(button, true, "Comparing…");
  try {
    let baseline = state.previousResult;
    let current = state.lastResult;
    if (
      state.previousResultId
      && state.lastResultId
      && state.previousResultId === state.lastResultId
    ) {
      baseline = null;
    }
    if ((!baseline || !current) && state.historyIds.length >= 2) {
      const [newer, older] = state.historyIds;
      const [currentPayload, baselinePayload] = await Promise.all([
        api(`/results/${encodeURIComponent(newer)}`),
        api(`/results/${encodeURIComponent(older)}`),
      ]);
      current = currentPayload.result;
      baseline = baselinePayload.result;
    }
    if (!baseline || !current) throw new Error("Two results are required for a diff.");
    state.lastDiff = await api("/results/diff", {
      method: "POST",
      body: JSON.stringify({ baseline, current }),
    });
    selectResultView("diff");
    const summaryRow = state.lastDiff.summary || {};
    say(summaryRow.changed ? `Diff ready: ${summaryRow.ports_opened || 0} opened, ${summaryRow.ports_closed || 0} closed.` : "Diff ready: no changes.", "success");
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function buildPlan() {
  if (!state.lastResult) {
    say("Select a result first.", "warning");
    return;
  }
  const button = $("planBtn");
  setButtonBusy(button, true, "Building…");
  try {
    state.lastPlan = await api("/recon/plan", {
      method: "POST",
      body: JSON.stringify({ scan: state.lastResult }),
    });
    selectResultView("plan");
    say(`Review-only plan ready: ${(state.lastPlan.summary || {}).recommendations || 0} steps.`, "success");
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function scheduleScan() {
  const button = $("scheduleBtn");
  setButtonBusy(button, true, "Scheduling…");
  try {
    await api("/schedule", { method: "POST", body: JSON.stringify(scanPayload()) });
    say(`Schedule created for ${$("target").value.trim()}.`, "success");
    await refresh({ announce: false });
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

async function pollPlaybook(engagementId) {
  while (state.activeEngagementId === engagementId) {
    const record = await api(`/playbook/${encodeURIComponent(engagementId)}`);
    renderEngagement(record);
    if (terminalEngagementStatuses.has(record.status)) return record;
    await sleep(1000);
  }
  return null;
}

function renderEngagement(record) {
  $("playbookStatus").textContent = record.status || "unknown";
  $("playbookStatus").dataset.tone = record.status === "completed"
    ? "success"
    : record.status === "failed"
      ? "error"
      : record.status === "cancelled"
        ? "warning"
        : "info";
  renderPlaybookPreview(record);
  $("cancelPlaybookBtn").disabled = terminalEngagementStatuses.has(record.status);
}

async function runPlaybook() {
  const button = $("playbookBtn");
  setButtonBusy(button, true, "Starting…");
  try {
    const record = await api("/playbook/run", {
      method: "POST",
      body: JSON.stringify({ target: $("target").value.trim(), playbook: $("playbookSelect").value }),
    });
    state.activeEngagementId = record.engagement_id;
    renderEngagement(record);
    $("cancelPlaybookBtn").disabled = false;
    say(`Playbook ${record.playbook} started for ${record.target}.`, "info");
    const finished = await pollPlaybook(record.engagement_id);
    if (finished) {
      say(`Playbook ${finished.status}: ${finished.steps.filter((step) => step.status === "completed").length}/${finished.steps.length} phases completed.`, finished.status === "completed" ? "success" : "warning");
      await refresh({ announce: false });
    }
  } catch (error) {
    say(error.message, "error");
  } finally {
    state.activeEngagementId = null;
    $("cancelPlaybookBtn").disabled = true;
    setButtonBusy(button, false);
  }
}

async function cancelPlaybook() {
  if (!state.activeEngagementId) return;
  if (!window.confirm("Cancel the active playbook? The current scan job is handled by the job lifecycle.")) return;
  try {
    const record = await api(`/playbook/${encodeURIComponent(state.activeEngagementId)}`, { method: "DELETE" });
    renderEngagement(record);
    state.activeEngagementId = null;
    say("Playbook cancelled.", "warning");
  } catch (error) {
    say(error.message, "error");
  }
}

function postureFromResult() {
  if (!state.lastResult) {
    say("Select a result before creating a posture baseline.", "warning");
    return;
  }
  const services = openServices(state.lastResult).map((row) => ({
    host: row.host,
    proto: row.protocol,
    port: Number(row.port),
    name: row.service.name || "unknown",
  }));
  $("postureInput").value = JSON.stringify({ deny_unexpected: true, services }, null, 2);
  $("postureOutput").textContent = `Baseline prepared from ${services.length} observed open services. Review it before evaluation.`;
}

function renderPosture(report) {
  const driftCount = (report.unexpected || 0) + (report.missing || 0);
  $("postureStatus").textContent = report.enabled ? `${driftCount} drift` : "not configured";
  $("postureStatus").dataset.tone = !report.enabled ? "neutral" : driftCount ? "warning" : "success";
  const lines = [
    `Expected: ${report.expected_count || 0} · Observed: ${report.open_count || 0}`,
    `Unexpected: ${report.unexpected || 0} · Missing: ${report.missing || 0}`,
  ];
  for (const drift of report.drifts || []) {
    lines.push(`${drift.op === "unexpected" ? "+" : "−"} ${drift.host} ${drift.proto}/${drift.port} ${drift.service || ""}`.trim());
  }
  $("postureOutput").textContent = lines.join("\n");
}

async function evaluatePosture() {
  if (!state.lastResult) {
    say("Select a result first.", "warning");
    return;
  }
  const raw = $("postureInput").value.trim();
  if (!raw) {
    say("Define expected services or create a baseline from the current result.", "warning");
    return;
  }
  let posture;
  try {
    posture = JSON.parse(raw);
  } catch {
    say("Expected services must be valid JSON.", "error");
    return;
  }
  const button = $("postureBtn");
  setButtonBusy(button, true, "Evaluating…");
  try {
    state.lastPosture = await api("/posture/evaluate", {
      method: "POST",
      body: JSON.stringify({ scan: state.lastResult, posture }),
    });
    renderPosture(state.lastPosture);
    const driftCount = (state.lastPosture.unexpected || 0) + (state.lastPosture.missing || 0);
    say(driftCount ? `Posture drift detected: ${driftCount} differences.` : "Posture matches expected services.", driftCount ? "warning" : "success");
  } catch (error) {
    say(error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
}

function renderAudit(events) {
  const rows = Array.isArray(events) ? events : [];
  const root = $("auditList");
  root.replaceChildren();
  $("auditCount").textContent = rows.length;
  if (!rows.length) {
    root.appendChild(createElement("div", "empty-state", "No audit events in the selected window."));
    return;
  }
  for (const event of rows) {
    const item = createElement("article", "audit-item");
    item.append(
      createElement("div", "audit-action", event.action || "event"),
      createElement("div", "audit-meta", [formatDateTime(event.ts), event.target, event.status, event.actor_key_id].filter(Boolean).join(" · ")),
    );
    root.appendChild(item);
  }
}

async function refreshAudit() {
  const button = $("auditBtn");
  setButtonBusy(button, true, "Loading…");
  try {
    const payload = await api("/audit?limit=30");
    renderAudit(payload.events || []);
    say(`Loaded ${payload.count || 0} audit events.`, "success");
  } catch (error) {
    if (error.status === 403) {
      $("auditList").replaceChildren(createElement("div", "empty-state", "This API key does not have admin scope."));
      say("Admin scope is required for the audit trail.", "warning");
    } else {
      say(error.message, "error");
    }
  } finally {
    setButtonBusy(button, false);
  }
}

async function copyText(content, successMessage) {
  if (!content) {
    say("Nothing to copy yet.", "warning");
    return;
  }
  try {
    await navigator.clipboard.writeText(content);
    say(successMessage, "success");
  } catch {
    say("Copy failed. Select the text and copy it manually.", "error");
  }
}

function exportCurrentView() {
  const content = $("resultBox").value;
  if (!content) {
    say("Nothing to export yet.", "warning");
    return;
  }
  const type = state.view === "json" ? "application/json" : "text/plain";
  const extension = state.view === "json" ? "json" : "txt";
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `recon-operator-${state.view}.${extension}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  say(`Exported ${state.view.toUpperCase()} view.`, "success");
}

tokenInput.addEventListener("input", () => {
  const nextToken = tokenInput.value.trim();
  if (state.connectedToken !== null && nextToken !== state.connectedToken) {
    resetOwnerWorkspace();
    state.authIdentity = null;
    state.connectedToken = null;
    setConnectionState("Not connected", "neutral");
  }
  saveToken();
});
$("connectBtn").addEventListener("click", async () => {
  saveToken();
  await refresh();
  document.querySelector(".connection-menu")?.removeAttribute("open");
});
$("clearTokenBtn").addEventListener("click", () => {
  tokenInput.value = "";
  saveToken();
  resetOwnerWorkspace();
  state.authIdentity = null;
  state.connectedToken = null;
  $("keyMeta").textContent = "Key not identified.";
  setConnectionState("Not connected", "neutral");
  say("Token cleared from this tab session.", "info");
});
$("scanBtn").addEventListener("click", runScan);
$("scheduleBtn").addEventListener("click", scheduleScan);
$("importBtn").addEventListener("click", importXml);
$("diffBtn").addEventListener("click", diffLastTwo);
$("refreshBtn").addEventListener("click", () => refresh());
$("historyBtn").addEventListener("click", () => refreshHistory());
$("toolsBtn").addEventListener("click", refreshTools);
$("planBtn").addEventListener("click", buildPlan);
$("briefBtn").addEventListener("click", () => loadAiBrief({ retest: false }));
$("copyToolsBtn").addEventListener("click", () => copyText(state.toolsContext || $("toolsBox").value, "Copied tool AI context."));
$("copyBtn").addEventListener("click", () => copyText($("resultBox").value, "Copied current view."));
$("exportBtn").addEventListener("click", exportCurrentView);
$("playbookBtn").addEventListener("click", runPlaybook);
$("cancelPlaybookBtn").addEventListener("click", cancelPlaybook);
$("postureFromResultBtn").addEventListener("click", postureFromResult);
$("postureBtn").addEventListener("click", evaluatePosture);
$("auditBtn").addEventListener("click", refreshAudit);
$("preset").addEventListener("change", renderPresetMeta);
$("scanType").addEventListener("change", renderPresetMeta);
$("playbookSelect").addEventListener("change", () => renderPlaybookPreview());

document.querySelectorAll(".tabs button").forEach((button) => {
  button.addEventListener("click", () => selectResultView(button.dataset.view));
  button.addEventListener("keydown", (event) => {
    if (!new Set(["ArrowLeft", "ArrowRight", "Home", "End"]).has(event.key)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll(".tabs button")];
    const current = tabs.indexOf(button);
    let next = current;
    if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
    if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = tabs.length - 1;
    selectResultView(tabs[next].dataset.view, { focus: true });
  });
});

updateTimingPills();
renderPresetMeta();
renderPlaybookPreview();
renderResult();
refresh({ announce: false });
