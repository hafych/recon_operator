"""Operator dashboard HTML shell.

CSS/JS live under ``static/`` and are served as cacheable assets.
"""

UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>Recon Operator</title>
  <link rel="icon" href="/static/favicon.svg?v=2026.07.2" type="image/svg+xml">
  <link rel="stylesheet" href="/static/dashboard.css?v=2026.07.2" nonce="__CSP_NONCE__">
</head>
<body>
  <a class="skip-link" href="#mainContent">Skip to workspace</a>

  <header class="app-header">
    <div class="header-inner">
      <div class="brand-block">
        <div class="brand-mark" aria-hidden="true">RO</div>
        <div>
          <div class="brand-line">
            <h1>Recon Operator</h1>
            <span class="version-badge" id="productVersion">local</span>
          </div>
          <p>Authorized reconnaissance, from scope to evidence.</p>
        </div>
      </div>

      <div class="header-actions">
        <span class="connection-state" id="connectionState" data-tone="neutral">
          <span class="status-dot" aria-hidden="true"></span>
          <span id="connectionLabel">Not connected</span>
        </span>
        <button class="button secondary" id="refreshBtn" type="button">Refresh workspace</button>
        <details class="connection-menu">
          <summary class="button secondary">Connection</summary>
          <div class="connection-popover">
            <label for="apiToken">API token</label>
            <input id="apiToken" type="password" autocomplete="new-password" placeholder="X-API-KEY">
            <p class="field-help" id="keyMeta" aria-live="polite">Key not identified.</p>
            <div class="button-row compact">
              <button class="button primary" id="connectBtn" type="button">Connect</button>
              <button class="button ghost" id="clearTokenBtn" type="button">Clear token</button>
            </div>
            <p class="privacy-note">Stored only in this tab session. Never sent in URLs.</p>
          </div>
        </details>
      </div>
    </div>
  </header>

  <nav class="section-nav" aria-label="Workspace sections">
    <div class="nav-inner">
      <a href="#operate">Operate</a>
      <a href="#activity">Activity</a>
      <a href="#results">Results</a>
      <a href="#assurance">Assurance</a>
    </div>
  </nav>

  <main class="shell" id="mainContent">
    <section class="overview" aria-labelledby="overviewTitle">
      <h2 class="sr-only" id="overviewTitle">Workspace overview</h2>
      <div class="overview-card">
        <span class="overview-label">API</span>
        <strong id="apiStatus">checking</strong>
        <span class="overview-detail" id="lastRefresh">never refreshed</span>
      </div>
      <div class="overview-card">
        <span class="overview-label">Scanner</span>
        <strong id="nmapStatus">unknown</strong>
        <span class="overview-detail">Nmap readiness</span>
      </div>
      <div class="overview-card">
        <span class="overview-label">Active work</span>
        <strong><span id="jobCount">0</span> jobs</strong>
        <span class="overview-detail"><span id="taskCount">0</span> schedules</span>
      </div>
      <div class="overview-card">
        <span class="overview-label">Last scan</span>
        <strong id="lastScanMeta">none</strong>
        <span class="overview-detail"><span id="historyCount">0</span> stored results</span>
      </div>
    </section>

    <div class="primary-grid">
      <section class="panel operate-panel" id="operate" aria-labelledby="operateTitle">
        <header class="panel-header">
          <div>
            <p class="eyebrow">Operate</p>
            <h2 id="operateTitle">Start authorized recon</h2>
          </div>
          <span class="risk-badge" id="presetRisk">Low impact</span>
        </header>

        <div class="panel-body">
          <div class="field-grid target-grid">
            <label for="target">
              Target
              <input id="target" value="127.0.0.1" spellcheck="false" aria-describedby="targetHelp">
            </label>
            <label for="preset">
              Engagement preset
              <select id="preset">
                <option value="">Custom profile</option>
                <option value="discovery">Discovery — host liveness</option>
                <option value="map">Map — common services</option>
                <option value="safe">Safe — NSE depth</option>
                <option value="depth">Depth — full TCP/scripts</option>
                <option value="vuln">Vuln — authorized only</option>
                <option value="hybrid">Hybrid — fast discovery + version</option>
              </select>
            </label>
          </div>
          <p class="field-help" id="targetHelp">Only scan systems you own or are explicitly authorized to assess.</p>

          <div class="preset-explainer" id="presetMeta" aria-live="polite">
            <strong>Custom profile</strong>
            <span>Choose the exact Nmap profile and optional discovery frontend.</span>
          </div>

          <details class="disclosure" id="advancedOptions">
            <summary>Advanced options</summary>
            <div class="disclosure-body">
              <div class="field-grid two-up">
                <label for="scanType">
                  Scan profile
                  <select id="scanType">
                    <option>Ping</option>
                    <option selected>TCP</option>
                    <option>SYN</option>
                    <option>UDP</option>
                    <option>Version</option>
                    <option>Safe</option>
                    <option>Vuln</option>
                    <option>Full</option>
                    <option>Hybrid</option>
                    <option>HybridNaabu</option>
                    <option>HybridRustScan</option>
                    <option>OS</option>
                    <option>Aggressive</option>
                  </select>
                </label>
                <label for="discovery">
                  Discovery frontend
                  <select id="discovery">
                    <option value="" selected>Nmap only</option>
                    <option value="auto">Auto (Naabu → RustScan)</option>
                    <option value="naabu">Naabu</option>
                    <option value="rustscan">RustScan</option>
                  </select>
                </label>
              </div>
              <div class="field-grid two-up">
                <label for="ports">
                  Ports (optional)
                  <input id="ports" placeholder="22,80,443 or 1-1000" spellcheck="false">
                </label>
                <label for="scripts">
                  Extra NSE (optional)
                  <input id="scripts" placeholder="banner,http-title" spellcheck="false">
                </label>
              </div>
            </div>
          </details>

          <div class="button-row primary-actions">
            <button class="button primary" id="scanBtn" type="button">Run scan</button>
            <button class="button secondary" id="scheduleBtn" type="button">Create schedule</button>
          </div>

          <details class="disclosure secondary-disclosure">
            <summary>Schedule and import</summary>
            <div class="disclosure-body">
              <label for="interval">
                Schedule interval (minutes)
                <input id="interval" type="number" value="30" min="1" step="1">
              </label>
              <label for="xmlImport">
                Import Nmap XML
                <textarea id="xmlImport" rows="5" placeholder="Paste Nmap XML to add it to encrypted history."></textarea>
              </label>
              <div class="button-row compact">
                <button class="button secondary" id="importBtn" type="button">Import XML</button>
                <button class="button ghost" id="diffBtn" type="button">Diff last two</button>
              </div>
            </div>
          </details>

          <div class="toast" id="toast" role="status" aria-live="polite" aria-atomic="true" data-tone="info">
            Connect an API key to begin.
          </div>
        </div>
      </section>

      <section class="panel activity-panel" id="activity" aria-labelledby="activityTitle">
        <header class="panel-header">
          <div>
            <p class="eyebrow">Activity</p>
            <h2 id="activityTitle">Jobs and schedules</h2>
          </div>
          <span class="count-badge"><strong id="runningCount">0</strong> active</span>
        </header>
        <div class="panel-body activity-body">
          <section aria-labelledby="jobsTitle">
            <div class="section-heading">
              <h3 id="jobsTitle">Recent jobs</h3>
              <span id="jobSummary">No jobs</span>
            </div>
            <div class="activity-list" id="jobs">
              <div class="empty-state">Connect to load recent work.</div>
            </div>
          </section>

          <section aria-labelledby="tasksTitle">
            <div class="section-heading">
              <h3 id="tasksTitle">Schedules</h3>
              <span id="scheduleSummary">0 configured</span>
            </div>
            <div class="activity-list" id="tasks">
              <div class="empty-state">No scheduled scans.</div>
            </div>
          </section>
        </div>
      </section>
    </div>

    <section class="panel results-panel" id="results" aria-labelledby="resultsTitle">
      <header class="panel-header results-header">
        <div>
          <p class="eyebrow">Results</p>
          <h2 id="resultsTitle">Evidence workspace</h2>
        </div>
        <div class="button-row compact">
          <button class="button secondary" id="historyBtn" type="button">Refresh history</button>
          <button class="button ghost" id="exportBtn" type="button">Export view</button>
        </div>
      </header>

      <div class="results-layout">
        <aside class="history-pane" aria-labelledby="historyTitle">
          <div class="section-heading">
            <h3 id="historyTitle">Scan History</h3>
            <span><span id="historyPaneCount">0</span> items</span>
          </div>
          <div class="history-list" id="history">
            <div class="empty-state">No encrypted results yet.</div>
          </div>
        </aside>

        <div class="result-detail">
          <div class="result-title-row">
            <div>
              <span class="result-kicker" id="resultSource">No source</span>
              <h3 id="resultTitle">No result selected</h3>
              <p id="resultLabel">Run a scan or open encrypted history to inspect evidence.</p>
            </div>
            <div class="button-row compact">
              <button class="button secondary" id="planBtn" type="button">Build plan</button>
              <button class="button secondary" id="briefBtn" type="button">AI pack</button>
              <button class="button ghost" id="copyBtn" type="button">Copy view</button>
            </div>
          </div>

          <div class="metric-grid" aria-label="Result summary">
            <div class="metric"><b id="hostMetric">0</b><span>hosts</span></div>
            <div class="metric"><b id="upMetric">0</b><span>up</span></div>
            <div class="metric"><b id="openMetric">0</b><span>open ports</span></div>
            <div class="metric"><b id="serviceMetric">0</b><span>services</span></div>
          </div>

          <div class="service-summary" id="serviceBars">No service distribution yet.</div>

          <div class="tabs" role="tablist" aria-label="Result view">
            <button class="active" data-view="summary" type="button" role="tab" aria-selected="true" aria-controls="resultBox">Summary</button>
            <button data-view="json" type="button" role="tab" aria-selected="false" aria-controls="resultBox">JSON</button>
            <button data-view="jsonl" type="button" role="tab" aria-selected="false" aria-controls="resultBox">JSONL</button>
            <button data-view="plan" type="button" role="tab" aria-selected="false" aria-controls="resultBox">Recon Plan</button>
            <button data-view="brief" type="button" role="tab" aria-selected="false" aria-controls="resultBox">AI Brief</button>
            <button data-view="diff" type="button" role="tab" aria-selected="false" aria-controls="resultBox">Diff</button>
          </div>

          <div class="table-wrap" id="serviceTableWrap">
            <table class="data-table" id="serviceTable">
              <caption class="sr-only">Open services in the selected scan result</caption>
              <thead>
                <tr><th>Host</th><th>State</th><th>Port</th><th>Service</th><th>Version</th></tr>
              </thead>
              <tbody id="serviceTableBody">
                <tr><td colspan="5" class="table-empty">No open services observed.</td></tr>
              </tbody>
            </table>
          </div>

          <label class="sr-only" for="resultBox">Selected scan result view</label>
          <textarea id="resultBox" role="tabpanel" readonly aria-label="Selected scan result view"></textarea>
        </div>
      </div>
    </section>

    <section id="assurance" aria-labelledby="assuranceTitle">
      <div class="section-intro">
        <div>
          <p class="eyebrow">Assurance</p>
          <h2 id="assuranceTitle">Automate, compare, and audit</h2>
        </div>
        <p>Advanced controls stay reviewable: playbooks only queue authorized scan presets and recommendations never auto-execute.</p>
      </div>

      <div class="assurance-grid">
        <section class="panel" aria-labelledby="playbookTitle">
          <header class="panel-header compact-header">
            <div>
              <h3 id="playbookTitle">Playbook runner</h3>
              <p>Ordered, visible scan phases.</p>
            </div>
            <span class="count-badge" id="playbookStatus">idle</span>
          </header>
          <div class="panel-body">
            <label for="playbookSelect">
              Playbook
              <select id="playbookSelect">
                <option value="quick">Quick — discovery → map</option>
                <option value="standard" selected>Standard — discovery → map → safe</option>
                <option value="deep">Deep — discovery → map → safe → depth</option>
              </select>
            </label>
            <p class="field-help" id="playbookMeta">Sequential phases stop on failure and never run planner commands.</p>
            <div class="button-row compact">
              <button class="button primary" id="playbookBtn" type="button">Run playbook</button>
              <button class="button danger" id="cancelPlaybookBtn" type="button" disabled>Cancel playbook</button>
            </div>
            <ol class="timeline" id="playbookTimeline">
              <li data-status="pending"><span>Choose a playbook to preview its phases.</span></li>
            </ol>
          </div>
        </section>

        <section class="panel" aria-labelledby="postureTitle">
          <header class="panel-header compact-header">
            <div>
              <h3 id="postureTitle">Posture drift</h3>
              <p>Compare observed services with intent.</p>
            </div>
            <span class="count-badge" id="postureStatus">not evaluated</span>
          </header>
          <div class="panel-body">
            <label for="postureInput">
              Expected services (JSON)
              <textarea id="postureInput" rows="6" placeholder='{"deny_unexpected":true,"services":[{"port":443,"proto":"tcp","name":"https"}]}'></textarea>
            </label>
            <div class="button-row compact">
              <button class="button secondary" id="postureFromResultBtn" type="button">Use observed baseline</button>
              <button class="button primary" id="postureBtn" type="button">Evaluate drift</button>
            </div>
            <div class="compact-output" id="postureOutput">Select a result, define expected services, then evaluate.</div>
          </div>
        </section>

        <section class="panel" aria-labelledby="toolsTitle">
          <header class="panel-header compact-header">
            <div>
              <h3 id="toolsTitle">Tool Inventory</h3>
              <p>Kali profiles and local command readiness.</p>
            </div>
            <span class="count-badge"><strong id="toolAvailable">0</strong> ready</span>
          </header>
          <div class="panel-body">
            <div class="metric-grid compact-metrics">
              <div class="metric"><b id="toolChecked">0</b><span>checked</span></div>
              <div class="metric"><b id="toolMissing">0</b><span>missing</span></div>
              <div class="metric"><b id="toolProfiles">0</b><span>profiles</span></div>
            </div>
            <div class="missing-tools" id="missingTools">Refresh to inspect local tool readiness.</div>
            <div class="button-row compact">
              <button class="button primary" id="toolsBtn" type="button">Refresh tools</button>
              <button class="button ghost" id="copyToolsBtn" type="button">Copy AI context</button>
            </div>
            <details class="disclosure secondary-disclosure">
              <summary>Raw inventory summary</summary>
              <div class="disclosure-body">
                <label class="sr-only" for="toolsBox">Tool inventory output</label>
                <textarea id="toolsBox" readonly aria-label="Tool inventory output" placeholder="Refresh to build a Kali tool inventory and AI handoff."></textarea>
              </div>
            </details>
          </div>
        </section>

        <section class="panel" aria-labelledby="auditTitle">
          <header class="panel-header compact-header">
            <div>
              <h3 id="auditTitle">Audit trail</h3>
              <p>Recent operator actions without secrets.</p>
            </div>
            <span class="count-badge"><strong id="auditCount">0</strong> events</span>
          </header>
          <div class="panel-body">
            <div class="button-row compact first-row">
              <button class="button secondary" id="auditBtn" type="button">Load audit trail</button>
            </div>
            <div class="audit-list" id="auditList">
              <div class="empty-state">Admin scope is required to view audit events.</div>
            </div>
          </div>
        </section>
      </div>
    </section>
  </main>

  <footer class="app-footer">
    <p>Local-first · encrypted evidence · review-only follow-up</p>
    <a href="/api/docs">API docs</a>
  </footer>

  <script src="/static/dashboard.js?v=2026.07.2" nonce="__CSP_NONCE__" defer></script>
</body>
</html>
"""
