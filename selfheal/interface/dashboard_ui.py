"""Self-contained HTML/CSS/JS dashboard UI for Slime (offline, zero external dependencies)."""


def render_dashboard_html(*, demo_mode: bool = False) -> str:
    """Return the complete single-page HTML document for the Slime dashboard."""
    demo_flag = "true" if demo_mode else "false"
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Slime DevOps Self-Healing Agent — Local Dashboard</title>
  <style>
    /* ==========================================================================
       1. DESIGN TOKENS (Single Source of Truth — see docs/DESIGN.md)
       WCAG 2.1 AA verified in both Light and Dark themes
       ========================================================================== */
    :root, [data-theme="light"] {{
      --bg-canvas: #f8fafc;
      --bg-surface: #ffffff;
      --bg-elevated: #f1f5f9;
      --bg-muted: #e2e8f0;
      --border-subtle: #e2e8f0;
      --border-default: #cbd5e1;
      --border-strong: #64748b;
      --text-primary: #0f172a;
      --text-secondary: #334155;
      --text-muted: #475569;
      --accent-fg: #0369a1;
      --accent-bg: #e0f2fe;
      --accent-border: #7dd3fc;
      --ok-fg: #166534;
      --ok-bg: #dcfce7;
      --ok-border: #86efac;
      --warn-fg: #854d0e;
      --warn-bg: #fef9c3;
      --warn-border: #fde047;
      --danger-fg: #991b1b;
      --danger-bg: #fee2e2;
      --danger-border: #fca5a5;
      --focus-ring: #0284c7;

      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

      --text-xs: 0.75rem;
      --text-sm: 0.875rem;
      --text-base: 0.9375rem;
      --text-lg: 1.125rem;
      --text-xl: 1.375rem;

      --space-1: 4px;
      --space-2: 8px;
      --space-3: 12px;
      --space-4: 16px;
      --space-5: 24px;
      --space-6: 32px;

      --radius-sm: 4px;
      --radius-md: 6px;
      --radius-lg: 8px;

      --z-header: 10;
      --z-banner: 20;
      --z-modal: 50;
    }}

    @media (prefers-color-scheme: dark) {{
      :root:not([data-theme="light"]) {{
        --bg-canvas: #0b0f19;
        --bg-surface: #111827;
        --bg-elevated: #1e293b;
        --bg-muted: #0f172a;
        --border-subtle: #1f2937;
        --border-default: #334155;
        --border-strong: #64748b;
        --text-primary: #f8fafc;
        --text-secondary: #cbd5e1;
        --text-muted: #94a3b8;
        --accent-fg: #38bdf8;
        --accent-bg: #082f49;
        --accent-border: #0284c7;
        --ok-fg: #4ade80;
        --ok-bg: #052e16;
        --ok-border: #166534;
        --warn-fg: #facc15;
        --warn-bg: #422006;
        --warn-border: #854d0e;
        --danger-fg: #f87171;
        --danger-bg: #450a0a;
        --danger-border: #991b1b;
        --focus-ring: #38bdf8;
      }}
    }}

    [data-theme="dark"] {{
      --bg-canvas: #0b0f19;
      --bg-surface: #111827;
      --bg-elevated: #1e293b;
      --bg-muted: #0f172a;
      --border-subtle: #1f2937;
      --border-default: #334155;
      --border-strong: #64748b;
      --text-primary: #f8fafc;
      --text-secondary: #cbd5e1;
      --text-muted: #94a3b8;
      --accent-fg: #38bdf8;
      --accent-bg: #082f49;
      --accent-border: #0284c7;
      --ok-fg: #4ade80;
      --ok-bg: #052e16;
      --ok-border: #166534;
      --warn-fg: #facc15;
      --warn-bg: #422006;
      --warn-border: #854d0e;
      --danger-fg: #f87171;
      --danger-bg: #450a0a;
      --danger-border: #991b1b;
      --focus-ring: #38bdf8;
    }}

    /* ==========================================================================
       2. RESET, ACCESSIBILITY & MOTION CONSTRAINTS
       ========================================================================== */
    *, *::before, *::after {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      font-family: var(--font-sans);
      font-size: var(--text-base);
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      line-height: 1.5;
      min-height: 100dvh;
      overflow-x: hidden;
    }}

    .tabular, time, code, .count, td, .badge {{
      font-variant-numeric: tabular-nums;
    }}

    code, pre, .mono {{
      font-family: var(--font-mono);
    }}

    :focus-visible {{
      outline: 2px solid var(--focus-ring);
      outline-offset: 2px;
    }}

    .skip-link {{
      position: absolute;
      left: -9999px;
      top: var(--space-2);
      background: var(--bg-surface);
      color: var(--text-primary);
      padding: var(--space-2) var(--space-3);
      border: 2px solid var(--focus-ring);
      border-radius: var(--radius-sm);
      z-index: 100;
      font-weight: 600;
    }}
    .skip-link:focus {{
      left: var(--space-3);
    }}

    .sr-only {{
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }}

    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }}
    }}

    /* ==========================================================================
       3. PERSISTENT HEADER & MODE BANNERS
       ========================================================================== */
    .top-header {{
      position: sticky;
      top: 0;
      z-index: var(--z-header);
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-default);
      padding: var(--space-3) var(--space-5);
    }}

    .header-row {{
      max-width: 1360px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-3);
    }}

    .brand-group {{
      display: flex;
      align-items: center;
      gap: var(--space-3);
      flex-wrap: wrap;
    }}

    .brand-title {{
      font-size: var(--text-lg);
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: var(--space-2);
    }}

    .mode-banner {{
      display: inline-flex;
      align-items: center;
      gap: var(--space-2);
      padding: 4px 12px;
      border-radius: var(--radius-sm);
      font-size: var(--text-xs);
      font-weight: 700;
      letter-spacing: 0.02em;
      border: 1px solid transparent;
    }}
    .mode-dryrun {{
      background: var(--accent-bg);
      color: var(--accent-fg);
      border-color: var(--accent-border);
    }}
    .mode-live {{
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }}
    .mode-halted {{
      background: var(--danger-bg);
      color: var(--danger-fg);
      border-color: var(--danger-border);
    }}

    .header-controls {{
      display: flex;
      align-items: center;
      gap: var(--space-2);
      flex-wrap: wrap;
    }}

    .conn-pill {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: var(--text-xs);
      color: var(--text-secondary);
      padding: 4px 10px;
      border-radius: var(--radius-sm);
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
    }}
    .conn-pill.disconnected {{
      background: var(--danger-bg);
      color: var(--danger-fg);
      border-color: var(--danger-border);
      font-weight: 700;
    }}

    /* ==========================================================================
       4. NAVIGATION TABS
       ========================================================================== */
    .nav-bar {{
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-default);
      padding: 0 var(--space-5);
      overflow-x: auto;
    }}

    .tab-list {{
      max-width: 1360px;
      margin: 0 auto;
      display: flex;
      gap: var(--space-1);
      list-style: none;
    }}

    .tab-btn {{
      background: transparent;
      color: var(--text-secondary);
      border: none;
      border-bottom: 2px solid transparent;
      padding: var(--space-3) var(--space-3);
      font-size: var(--text-sm);
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: opacity 120ms ease-out;
    }}
    .tab-btn:hover {{
      color: var(--text-primary);
    }}
    .tab-btn[aria-selected="true"] {{
      color: var(--accent-fg);
      border-bottom-color: var(--accent-fg);
    }}

    .tab-count {{
      font-size: 0.7rem;
      padding: 1px 6px;
      border-radius: 999px;
      background: var(--bg-elevated);
      color: var(--text-secondary);
    }}
    .tab-count.urgent {{
      background: var(--warn-bg);
      color: var(--warn-fg);
      border: 1px solid var(--warn-border);
    }}

    /* ==========================================================================
       5. BANNERS, LAYOUT & CARDS
       ========================================================================== */
    .alert-banner {{
      max-width: 1360px;
      margin: var(--space-4) auto 0;
      padding: var(--space-3) var(--space-4);
      border-radius: var(--radius-md);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-3);
      flex-wrap: wrap;
      font-size: var(--text-sm);
    }}
    .alert-danger {{
      background: var(--danger-bg);
      color: var(--danger-fg);
      border: 1px solid var(--danger-border);
    }}
    .alert-warn {{
      background: var(--warn-bg);
      color: var(--warn-fg);
      border: 1px solid var(--warn-border);
    }}
    .alert-info {{
      background: var(--accent-bg);
      color: var(--accent-fg);
      border: 1px solid var(--accent-border);
    }}
    .alert-ok {{
      background: var(--ok-bg);
      color: var(--ok-fg);
      border: 1px solid var(--ok-border);
    }}

    main {{
      max-width: 1360px;
      margin: 0 auto;
      padding: var(--space-5);
      transition: opacity 150ms ease-out;
    }}
    main.stale-dimmed {{
      opacity: 0.55;
    }}

    .four-questions-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: var(--space-3);
      margin-bottom: var(--space-5);
    }}

    .q-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-3) var(--space-4);
    }}
    .q-label {{
      font-size: var(--text-xs);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: var(--space-1);
    }}
    .q-value {{
      font-size: var(--text-lg);
      font-weight: 700;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: var(--space-2);
    }}
    .q-sub {{
      font-size: var(--text-xs);
      color: var(--text-secondary);
      margin-top: 2px;
    }}

    .section-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: var(--space-4);
      margin-bottom: var(--space-5);
    }}

    .card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-4);
      margin-bottom: var(--space-4);
      min-width: 0;
    }}

    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-2);
      flex-wrap: wrap;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: var(--space-2);
      margin-bottom: var(--space-3);
    }}

    .card-title {{
      font-size: var(--text-lg);
      font-weight: 700;
      color: var(--text-primary);
      text-wrap: balance;
    }}

    /* ==========================================================================
       6. BADGES, BUTTONS, TABLES & OVERFLOW
       ========================================================================== */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: var(--radius-sm);
      font-size: var(--text-xs);
      font-weight: 700;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .badge-ok {{
      background: var(--ok-bg);
      color: var(--ok-fg);
      border-color: var(--ok-border);
    }}
    .badge-warn {{
      background: var(--warn-bg);
      color: var(--warn-fg);
      border-color: var(--warn-border);
    }}
    .badge-danger {{
      background: var(--danger-bg);
      color: var(--danger-fg);
      border-color: var(--danger-border);
    }}
    .badge-info {{
      background: var(--accent-bg);
      color: var(--accent-fg);
      border-color: var(--accent-border);
    }}
    .badge-neutral {{
      background: var(--bg-elevated);
      color: var(--text-secondary);
      border-color: var(--border-default);
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: var(--radius-sm);
      font-size: var(--text-sm);
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border-default);
      background: var(--bg-elevated);
      color: var(--text-primary);
      transition: opacity 120ms ease-out;
    }}
    .btn:hover:not(:disabled) {{
      opacity: 0.88;
    }}
    .btn:disabled {{
      opacity: 0.45;
      cursor: not-allowed;
    }}
    .btn-primary {{
      background: var(--accent-fg);
      color: #ffffff;
      border-color: var(--accent-fg);
    }}
    [data-theme="dark"] .btn-primary {{
      color: #0b0f19;
    }}
    .btn-danger {{
      background: var(--danger-bg);
      color: var(--danger-fg);
      border-color: var(--danger-border);
    }}
    .btn-ok {{
      background: var(--ok-bg);
      color: var(--ok-fg);
      border-color: var(--ok-border);
    }}

    .table-wrap {{
      width: 100%;
      overflow-x: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: var(--text-sm);
      text-align: left;
    }}

    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--border-subtle);
      vertical-align: top;
    }}

    th {{
      font-size: var(--text-xs);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--text-muted);
      font-weight: 700;
      background: var(--bg-elevated);
    }}

    tr.clickable-row {{
      cursor: pointer;
    }}
    tr.clickable-row:hover {{
      background: var(--bg-elevated);
    }}

    .service-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
      gap: var(--space-3);
    }}

    .service-card {{
      background: var(--bg-elevated);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      padding: var(--space-3);
      display: flex;
      flex-direction: column;
      gap: var(--space-2);
    }}

    .resolution-strip {{
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-3);
      padding: var(--space-3);
      background: var(--bg-elevated);
      border-radius: var(--radius-md);
      border: 1px solid var(--border-subtle);
    }}

    .res-item {{
      display: flex;
      align-items: center;
      gap: var(--space-2);
      font-size: var(--text-sm);
    }}

    .code-box, pre {{
      background: var(--bg-elevated);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-sm);
      padding: var(--space-3);
      font-size: var(--text-xs);
      overflow-x: auto;
      overflow-wrap: anywhere;
      white-space: pre-wrap;
      word-break: break-word;
      max-width: 100%;
      color: var(--text-primary);
    }}

    .filter-bar {{
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-2);
      margin-bottom: var(--space-3);
      padding: var(--space-3);
      background: var(--bg-elevated);
      border-radius: var(--radius-md);
    }}

    .filter-bar select, .filter-bar input {{
      background: var(--bg-surface);
      color: var(--text-primary);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-sm);
      padding: 6px 10px;
      font-size: var(--text-sm);
    }}

    .gate-list {{
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}

    .gate-item {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--space-2);
      padding: 8px 12px;
      border-radius: var(--radius-sm);
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      font-size: var(--text-sm);
      flex-wrap: wrap;
    }}
    .gate-item.gate-stopped {{
      background: var(--danger-bg);
      border-color: var(--danger-border);
      color: var(--danger-fg);
      font-weight: 700;
    }}

    .progress-track {{
      width: 100%;
      height: 10px;
      background: var(--bg-elevated);
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid var(--border-default);
      margin-top: 6px;
    }}
    .progress-fill {{
      height: 100%;
      background: var(--ok-fg);
    }}

    /* Modal Dialog */
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.65);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: var(--z-modal);
      padding: var(--space-4);
    }}
    .modal-backdrop[hidden] {{
      display: none;
    }}
    .modal-card {{
      background: var(--bg-surface);
      border: 2px solid var(--border-strong);
      border-radius: var(--radius-lg);
      max-width: 480px;
      width: 100%;
      padding: var(--space-5);
    }}

    .empty-state {{
      padding: var(--space-5);
      text-align: left;
      background: var(--bg-elevated);
      border: 1px dashed var(--border-default);
      border-radius: var(--radius-md);
      color: var(--text-secondary);
    }}

    @media (max-width: 640px) {{
      .top-header, .nav-bar, main {{
        padding-left: var(--space-3);
        padding-right: var(--space-3);
      }}
      th, td {{
        padding: 8px 6px;
        font-size: var(--text-xs);
      }}
    }}
  </style>
</head>
<body>
  <a href="#main-content" class="skip-link">Skip to main content</a>
  <div id="aria-polite" class="sr-only" aria-live="polite" aria-atomic="true"></div>
  <div id="aria-assertive" class="sr-only" aria-live="assertive" aria-atomic="true"></div>

  <!-- a) PERSISTENT HEADER -->
  <header class="top-header" role="banner">
    <div class="header-row">
      <div class="brand-group">
        <h1 class="brand-title">
          <span aria-hidden="true">[Slime]</span>
          <span>Slime DevOps Agent</span>
        </h1>
        <span id="mode-banner" class="mode-banner mode-dryrun" role="status">
          DRY-RUN — observe only
        </span>
        <span id="learning-badge" class="badge badge-info" hidden>
          Observing: day 1 of 7
        </span>
        <span id="demo-badge" class="badge badge-warn" hidden>
          READ-ONLY DEMO
        </span>
      </div>

      <div class="header-controls">
        <div id="conn-pill" class="conn-pill" role="status">
          <span id="conn-label">Connecting...</span>
          <time id="last-updated-time" datetime=""></time>
        </div>
        <button type="button" id="dryrun-toggle-btn" class="btn" aria-label="Toggle Dry-Run Mode">
          Switch Mode
        </button>
        <button type="button" id="killswitch-btn" class="btn btn-danger" aria-label="Toggle Global Kill Switch">
          Kill Switch: OFF
        </button>
        <button type="button" id="theme-toggle-btn" class="btn" aria-label="Toggle color theme">
          Theme: Light
        </button>
      </div>
    </div>
  </header>

  <!-- PRIMARY NAVIGATION TABS -->
  <nav class="nav-bar" aria-label="Dashboard sections">
    <div class="tab-list" role="tablist" id="main-tablist">
      <button role="tab" aria-selected="true" aria-controls="panel-overview" id="tab-overview" class="tab-btn" data-tab="overview">
        Overview
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-incident" id="tab-incident" class="tab-btn" data-tab="incident">
        Incident Detail <span id="tab-count-incidents" class="tab-count">0</span>
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-approvals" id="tab-approvals" class="tab-btn" data-tab="approvals">
        Approvals <span id="tab-count-approvals" class="tab-count">0</span>
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-activity" id="tab-activity" class="tab-btn" data-tab="activity">
        Activity
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-services" id="tab-services" class="tab-btn" data-tab="services">
        Services
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-safety" id="tab-safety" class="tab-btn" data-tab="safety">
        Safety
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-system" id="tab-system" class="tab-btn" data-tab="system">
        System (Doctor)
      </button>
      <button role="tab" aria-selected="false" aria-controls="panel-guide" id="tab-guide" class="tab-btn" data-tab="guide">
        First-Run Guide
      </button>
    </div>
  </nav>

  <!-- GLOBAL STATE BANNERS (Disconnected / Error / Halted / Demo Switcher) -->
  <div id="global-banners"></div>

  <!-- MAIN WORKSPACE -->
  <main id="main-content" tabindex="-1">
    <div id="screen-container">
      <div class="card">
        <p class="tabular">Loading system state from 127.0.0.1...</p>
      </div>
    </div>
  </main>

  <!-- ACCESSIBLE CONFIRMATION DIALOG -->
  <div id="confirm-modal" class="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="modal-title" hidden>
    <div class="modal-card">
      <h2 id="modal-title" class="card-title" style="margin-bottom: 8px;">Confirm Operator Action</h2>
      <p id="modal-body" style="color: var(--text-secondary); font-size: var(--text-sm); margin-bottom: 16px;"></p>
      <div id="modal-token-wrap" style="margin-bottom: 16px;">
        <label for="modal-token-input" style="display: block; font-size: var(--text-xs); font-weight: 700; margin-bottom: 4px;">
          Session Token (printed in terminal by <code>selfheal dashboard</code>):
        </label>
        <input id="modal-token-input" type="password" style="width: 100%; padding: 8px; border: 1px solid var(--border-default); border-radius: 4px; background: var(--bg-elevated); color: var(--text-primary);" placeholder="Paste session token">
      </div>
      <div style="display: flex; justify-content: flex-end; gap: 8px;">
        <button type="button" id="modal-cancel-btn" class="btn">Cancel</button>
        <button type="button" id="modal-confirm-btn" class="btn btn-primary">Confirm</button>
      </div>
    </div>
  </div>

  <script>
    (function() {{
      "use strict";

      const DEMO_MODE = {demo_flag};
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get("token")) {{
        sessionStorage.setItem("slimeSessionToken", urlParams.get("token"));
      }}

      let currentTab = urlParams.get("tab") || "overview";
      let selectedIncidentId = urlParams.get("incident") || null;
      let demoStateOverride = urlParams.get("demo_state") || "";
      let forceDisconnected = urlParams.get("simulate") === "disconnected";
      let forceError = urlParams.get("simulate") === "error";
      let guideDismissed = localStorage.getItem("slimeGuideDismissed") === "1";

      let appState = null;
      let lastUpdatedIso = null;
      let lastUpdatedEpoch = 0;
      let isConnected = true;
      let lastErrorMsg = null;
      let knownIncidentIds = new Set();

      // Activity filters
      let activityFilter = {{ service: "", action: "", rule: "", result: "" }};

      // ========================================================================
      // PURE DOM BUILDER — ZERO innerHTML WITH DATA (XSS-immune by construction)
      // ========================================================================
      function el(tag, attrs, ...children) {{
        const node = document.createElement(tag);
        if (attrs) {{
          for (const [k, v] of Object.entries(attrs)) {{
            if (v === null || v === undefined || v === false) continue;
            if (k === "className") {{
              node.className = String(v);
            }} else if (k === "style" && typeof v === "object") {{
              Object.assign(node.style, v);
            }} else if (k.startsWith("on") && typeof v === "function") {{
              node.addEventListener(k.slice(2).toLowerCase(), v);
            }} else if (v === true) {{
              node.setAttribute(k, "");
            }} else {{
              node.setAttribute(k, String(v));
            }}
          }}
        }}
        for (const child of children.flat(Infinity)) {{
          if (child === null || child === undefined || child === false) continue;
          if (child instanceof Node) {{
            node.appendChild(child);
          }} else {{
            node.appendChild(document.createTextNode(String(child)));
          }}
        }}
        return node;
      }}

      function svgEl(tag, attrs, ...children) {{
        const ns = "http://www.w3.org/2000/svg";
        const node = document.createElementNS(ns, tag);
        if (attrs) {{
          for (const [k, v] of Object.entries(attrs)) {{
            if (v !== null && v !== undefined) node.setAttribute(k, String(v));
          }}
        }}
        for (const child of children.flat(Infinity)) {{
          if (!child) continue;
          if (child instanceof Node) node.appendChild(child);
          else node.appendChild(document.createTextNode(String(child)));
        }}
        return node;
      }}

      function clearAndAppend(container, ...nodes) {{
        while (container.firstChild) container.removeChild(container.firstChild);
        for (const n of nodes.flat(Infinity)) {{
          if (n instanceof Node) container.appendChild(n);
          else if (n !== null && n !== undefined && n !== false) {{
            container.appendChild(document.createTextNode(String(n)));
          }}
        }}
      }}

      // ========================================================================
      // THEME MANAGEMENT (prefers-color-scheme + explicit toggle)
      // ========================================================================
      function initTheme() {{
        const saved = localStorage.getItem("slimeTheme");
        const paramTheme = urlParams.get("theme");
        const preferred = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
        const active = paramTheme || saved || preferred;
        setTheme(active, Boolean(saved || paramTheme));
      }}

      function setTheme(theme, persist) {{
        document.documentElement.setAttribute("data-theme", theme);
        if (persist) localStorage.setItem("slimeTheme", theme);
        const btn = document.getElementById("theme-toggle-btn");
        if (btn) btn.textContent = "Theme: " + (theme === "dark" ? "Dark" : "Light");
      }}

      document.getElementById("theme-toggle-btn").addEventListener("click", () => {{
        const cur = document.documentElement.getAttribute("data-theme") || "light";
        setTheme(cur === "dark" ? "light" : "dark", true);
      }});

      // ========================================================================
      // RELATIVE TIME & STATUS BADGE HELPERS
      // ========================================================================
      function formatRelativeTime(isoStr) {{
        if (!isoStr) return "—";
        const dt = new Date(isoStr);
        if (isNaN(dt.getTime())) return String(isoStr);
        const diffSec = Math.round((Date.now() - dt.getTime()) / 1000);
        if (diffSec < 0) {{
          const rem = Math.abs(diffSec);
          const m = Math.floor(rem / 60);
          const s = rem % 60;
          return m > 0 ? "in " + m + "m " + s + "s" : "in " + s + "s";
        }}
        if (diffSec < 5) return "just now";
        if (diffSec < 60) return diffSec + "s ago";
        const diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) return diffMin + "m ago";
        const diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) return diffHr + "h ago";
        return Math.floor(diffHr / 24) + "d ago";
      }}

      function timeNode(isoStr) {{
        if (!isoStr) return el("span", {{ className: "tabular" }}, "—");
        return el(
          "time",
          {{ datetime: String(isoStr), title: String(isoStr), className: "tabular" }},
          formatRelativeTime(isoStr)
        );
      }}

      function statusBadge(label, variant, glyph) {{
        return el(
          "span",
          {{ className: "badge badge-" + variant }},
          el("span", {{ "aria-hidden": "true" }}, glyph),
          " ",
          String(label)
        );
      }}

      // ========================================================================
      // API FETCH & POLLING
      // ========================================================================
      function getHeaders(isPost) {{
        const h = {{}};
        const tok = sessionStorage.getItem("slimeSessionToken") || "";
        if (tok) {{
          h["Authorization"] = "Bearer " + tok;
          h["X-CSRF-Token"] = tok;
        }}
        if (isPost) {{
          h["Content-Type"] = "application/json";
        }}
        return h;
      }}

      async function fetchDashboardState() {{
        if (forceDisconnected) {{
          isConnected = false;
          renderHeaderAndBanners();
          return;
        }}
        if (forceError) {{
          isConnected = false;
          lastErrorMsg = "Simulated API error (HTTP 503): unable to query SQLite state.";
          renderHeaderAndBanners();
          renderActiveScreen();
          return;
        }}
        try {{
          const qs = demoStateOverride ? "?demo_state=" + encodeURIComponent(demoStateOverride) : "";
          const res = await fetch("/api/state" + qs, {{ headers: getHeaders(false) }});
          if (res.status === 401 || res.status === 403) {{
            isConnected = false;
            lastErrorMsg = "Session token required or invalid (HTTP " + res.status + "). Supply ?token=<session_token> from terminal.";
            renderHeaderAndBanners();
            renderActiveScreen();
            return;
          }}
          if (!res.ok) {{
            throw new Error("HTTP " + res.status);
          }}
          const data = await res.json();
          isConnected = true;
          lastErrorMsg = null;
          lastUpdatedIso = data.timestamp;
          lastUpdatedEpoch = Date.now();

          // Announce newly detected incidents via ARIA live region
          if (appState && data.incidents) {{
            for (const inc of data.incidents) {{
              if (!knownIncidentIds.has(inc.id)) {{
                document.getElementById("aria-polite").textContent =
                  "New incident detected: " + inc.id + " on " + (inc.services || []).join(", ");
              }}
            }}
          }}
          knownIncidentIds = new Set((data.incidents || []).map(i => i.id));
          appState = data;
          if (!selectedIncidentId && data.incidents && data.incidents.length > 0) {{
            selectedIncidentId = data.incidents[0].id;
          }}
          renderHeaderAndBanners();
          renderActiveScreen();
        }} catch (err) {{
          isConnected = false;
          lastErrorMsg = "Connection lost to 127.0.0.1 (" + (err && err.message ? err.message : "network error") + ")";
          document.getElementById("aria-assertive").textContent = "Dashboard disconnected from local server.";
          renderHeaderAndBanners();
        }}
      }}

      // ========================================================================
      // CONFIRMATION MODAL FOR STATE-CHANGING ACTIONS
      // ========================================================================
      let pendingModalAction = null;

      function openConfirmModal(title, message, onConfirm) {{
        document.getElementById("modal-title").textContent = title;
        document.getElementById("modal-body").textContent = message;
        const tokInput = document.getElementById("modal-token-input");
        tokInput.value = sessionStorage.getItem("slimeSessionToken") || "";
        pendingModalAction = onConfirm;
        const modal = document.getElementById("confirm-modal");
        modal.hidden = false;
        document.getElementById("modal-confirm-btn").focus();
      }}

      function closeConfirmModal() {{
        document.getElementById("confirm-modal").hidden = true;
        pendingModalAction = null;
      }}

      document.getElementById("modal-cancel-btn").addEventListener("click", closeConfirmModal);
      document.getElementById("modal-confirm-btn").addEventListener("click", async () => {{
        const tok = document.getElementById("modal-token-input").value.trim();
        if (tok) sessionStorage.setItem("slimeSessionToken", tok);
        const fn = pendingModalAction;
        closeConfirmModal();
        if (fn) await fn();
      }});

      window.addEventListener("keydown", (e) => {{
        if (e.key === "Escape" && !document.getElementById("confirm-modal").hidden) {{
          closeConfirmModal();
        }}
      }});

      async function postAction(endpoint, payload) {{
        try {{
          const res = await fetch(endpoint, {{
            method: "POST",
            headers: getHeaders(true),
            body: JSON.stringify(payload)
          }});
          const data = await res.json().catch(() => ({{}}));
          if (!res.ok) {{
            lastErrorMsg = data.detail || data.error || ("Action refused (HTTP " + res.status + ")");
            renderHeaderAndBanners();
            return false;
          }}
          lastErrorMsg = null;
          await fetchDashboardState();
          return true;
        }} catch (e) {{
          lastErrorMsg = "Network error communicating with 127.0.0.1";
          renderHeaderAndBanners();
          return false;
        }}
      }}

      // ========================================================================
      // HEADER & GLOBAL BANNERS
      // ========================================================================
      function renderHeaderAndBanners() {{
        const mainEl = document.getElementById("main-content");
        const connPill = document.getElementById("conn-pill");
        const connLabel = document.getElementById("conn-label");
        const timeEl = document.getElementById("last-updated-time");

        if (!isConnected) {{
          connPill.className = "conn-pill disconnected";
          connLabel.textContent = "DISCONNECTED";
          timeEl.textContent = lastUpdatedIso ? " · stale since " + formatRelativeTime(lastUpdatedIso) : "";
          mainEl.classList.add("stale-dimmed");
        }} else {{
          connPill.className = "conn-pill";
          connLabel.textContent = "Connected · Updated ";
          timeEl.textContent = formatRelativeTime(lastUpdatedIso);
          timeEl.setAttribute("datetime", lastUpdatedIso || "");
          timeEl.setAttribute("title", lastUpdatedIso || "");
          mainEl.classList.remove("stale-dimmed");
        }}

        const bannersWrap = document.getElementById("global-banners");
        const banners = [];

        if (!isConnected) {{
          banners.push(
            el("div", {{ className: "alert-banner alert-danger", role: "alert" }},
              el("div", null,
                el("strong", null, "[DISCONNECTED] Live connection to 127.0.0.1 lost. "),
                "Showing last known state from ",
                lastUpdatedIso ? timeNode(lastUpdatedIso) : "startup",
                ". Operator mutations are disabled until connection resumes."
              ),
              el("button", {{
                className: "btn",
                onClick: () => {{ forceDisconnected = false; forceError = false; fetchDashboardState(); }}
              }}, "Reconnect Now")
            )
          );
        }}

        if (lastErrorMsg) {{
          banners.push(
            el("div", {{ className: "alert-banner alert-danger", role: "alert" }},
              el("div", null, el("strong", null, "[ERROR] "), String(lastErrorMsg)),
              el("button", {{
                className: "btn",
                onClick: () => {{ lastErrorMsg = null; forceError = false; fetchDashboardState(); }}
              }}, "Retry / Dismiss")
            )
          );
        }}

        if (appState) {{
          const modeBanner = document.getElementById("mode-banner");
          modeBanner.textContent = appState.mode.banner_text;
          if (appState.mode.state === "HALTED" || appState.mode.state === "CIRCUIT_OPEN") {{
            modeBanner.className = "mode-banner mode-halted";
          }} else if (appState.mode.state === "LIVE") {{
            modeBanner.className = "mode-banner mode-live";
          }} else {{
            modeBanner.className = "mode-banner mode-dryrun";
          }}

          const learnBadge = document.getElementById("learning-badge");
          if (appState.mode.learning_period) {{
            learnBadge.hidden = false;
            learnBadge.textContent = "Observing: day " + appState.mode.learning_day + " of 7";
          }} else {{
            learnBadge.hidden = true;
          }}

          const demoBadge = document.getElementById("demo-badge");
          demoBadge.hidden = !appState.demo_mode;

          const killBtn = document.getElementById("killswitch-btn");
          const dryBtn = document.getElementById("dryrun-toggle-btn");
          killBtn.disabled = !isConnected || appState.demo_mode;
          dryBtn.disabled = !isConnected || appState.demo_mode;

          if (appState.safety.killed) {{
            killBtn.textContent = "Kill Switch: ON (Disengage)";
            killBtn.className = "btn btn-ok";
          }} else {{
            killBtn.textContent = "Kill Switch: OFF (Engage)";
            killBtn.className = "btn btn-danger";
          }}
          dryBtn.textContent = appState.mode.dry_run ? "Go Live (Disable Dry-Run)" : "Return to Dry-Run";

          // Tab badges
          const openCount = (appState.incidents || []).filter(i => i.state !== "resolved").length;
          const apprCount = (appState.approvals || []).length;
          const incBadge = document.getElementById("tab-count-incidents");
          const appBadge = document.getElementById("tab-count-approvals");
          incBadge.textContent = String(openCount);
          incBadge.className = openCount > 0 ? "tab-count urgent" : "tab-count";
          appBadge.textContent = String(apprCount);
          appBadge.className = apprCount > 0 ? "tab-count urgent" : "tab-count";

          if (appState.safety.killed) {{
            banners.push(
              el("div", {{ className: "alert-banner alert-danger", role: "alert" }},
                el("div", null,
                  el("strong", null, "[HALTED — KILL SWITCH ENGAGED] "),
                  "All automatic and approved mutations are immediately refused at Gate 1 (kill_switch)."
                )
              )
            );
          }} else if (appState.safety.circuit_open) {{
            banners.push(
              el("div", {{ className: "alert-banner alert-danger", role: "alert" }},
                el("div", null,
                  el("strong", null, "[CIRCUIT BREAKER OPEN] "),
                  "Automatic repairs are halted due to consecutive failures or an interrupted action. Follow exact recovery steps in the Safety tab: 1) selfheal reconcile <action_id>, 2) selfheal reset-circuit."
                ),
                el("button", {{ className: "btn", onClick: () => switchTab("safety") }}, "View Reset Steps")
              )
            );
          }}
        }}

        clearAndAppend(bannersWrap, banners);
      }}

      // Header button handlers
      document.getElementById("killswitch-btn").addEventListener("click", () => {{
        if (!appState) return;
        const targetEnable = !appState.safety.killed;
        openConfirmModal(
          targetEnable ? "Engage Global Kill Switch?" : "Disengage Global Kill Switch?",
          targetEnable
            ? "Engaging the kill switch immediately halts all remediation mutations across Slime and records actor 'dashboard' in the append-only audit log."
            : "Disengaging the kill switch allows policy evaluation to proceed under configured safety limits.",
          () => postAction("/api/kill-switch", {{ enabled: targetEnable }})
        );
      }});

      document.getElementById("dryrun-toggle-btn").addEventListener("click", () => {{
        if (!appState) return;
        const nextDryRun = !appState.mode.dry_run;
        openConfirmModal(
          nextDryRun ? "Enable Observe-Only Dry-Run Mode?" : "Enable Live Remediation Mode?",
          nextDryRun
            ? "Slime will detect and diagnose incidents without executing any actions."
            : "Slime will execute only explicitly enabled SAFE actions (" +
              ((appState.safety.enabled_actions || []).join(", ") || "none currently enabled") +
              ") and require approval for everything else.",
          () => postAction("/api/dry-run", {{ enabled: nextDryRun }})
        );
      }});

      // ========================================================================
      // TAB ROUTING & KEYBOARD NAVIGATION
      // ========================================================================
      function switchTab(tabName, incidentId) {{
        currentTab = tabName;
        if (incidentId) selectedIncidentId = incidentId;
        const buttons = document.querySelectorAll(".tab-btn");
        buttons.forEach(btn => {{
          const active = btn.getAttribute("data-tab") === tabName;
          btn.setAttribute("aria-selected", active ? "true" : "false");
        }});
        renderActiveScreen();
      }}

      document.getElementById("main-tablist").addEventListener("click", (e) => {{
        const btn = e.target.closest(".tab-btn");
        if (btn) switchTab(btn.getAttribute("data-tab"));
      }});

      document.getElementById("main-tablist").addEventListener("keydown", (e) => {{
        const tabs = Array.from(document.querySelectorAll(".tab-btn"));
        const idx = tabs.indexOf(document.activeElement);
        if (idx === -1) return;
        if (e.key === "ArrowRight") {{
          e.preventDefault();
          const next = tabs[(idx + 1) % tabs.length];
          next.focus();
          switchTab(next.getAttribute("data-tab"));
        }} else if (e.key === "ArrowLeft") {{
          e.preventDefault();
          const prev = tabs[(idx - 1 + tabs.length) % tabs.length];
          prev.focus();
          switchTab(prev.getAttribute("data-tab"));
        }} else if (e.key === "Home") {{
          e.preventDefault();
          const first = tabs[0];
          first.focus();
          switchTab(first.getAttribute("data-tab"));
        }} else if (e.key === "End") {{
          e.preventDefault();
          const last = tabs[tabs.length - 1];
          last.focus();
          switchTab(last.getAttribute("data-tab"));
        }}
      }});

      // ========================================================================
      // INLINE SVG DEPENDENCY MAP RENDERER
      // ========================================================================
      function renderDependencySvg(services, rootCandidates, downstreamSet) {{
        const roots = new Set(rootCandidates || []);
        const down = new Set(downstreamSet || []);
        const list = services || [];
        if (list.length === 0) {{
          return el("p", {{ style: {{ color: "var(--text-muted)" }} }}, "No services configured in dependency map.");
        }}

        const width = Math.max(620, list.length * 165);
        const height = 160;
        const svg = svgEl("svg", {{
          viewBox: "0 0 " + width + " " + height,
          width: "100%",
          height: String(height),
          role: "img",
          "aria-label": "Service dependency topology graph"
        }});

        const pos = {{}};
        list.forEach((s, idx) => {{
          pos[s.name] = {{ x: 85 + idx * 155, y: 78 }};
        }});

        // Draw directed edges: s.name -> dep
        list.forEach(s => {{
          (s.depends_on || []).forEach(dep => {{
            if (pos[s.name] && pos[dep]) {{
              const x1 = pos[s.name].x;
              const y1 = pos[s.name].y;
              const x2 = pos[dep].x;
              const y2 = pos[dep].y;
              svg.appendChild(svgEl("line", {{
                x1: x1, y1: y1, x2: x2, y2: y2,
                stroke: "var(--border-strong)",
                "stroke-width": "2",
                "stroke-dasharray": down.has(s.name) ? "4 3" : ""
              }}));
            }}
          }});
        }});

        // Draw service nodes
        list.forEach(s => {{
          const p = pos[s.name];
          const isRoot = roots.has(s.name);
          const isDown = down.has(s.name) && !isRoot;
          const stroke = isRoot
            ? "var(--danger-fg)"
            : (s.status === "healthy" ? "var(--ok-fg)" : "var(--warn-fg)");
          const fill = isRoot ? "var(--danger-bg)" : "var(--bg-elevated)";
          const roleTag = isRoot
            ? "[ROOT CAUSE]"
            : (isDown ? "[DOWNSTREAM]" : (s.critical ? "[CRITICAL]" : "[" + (s.status || "healthy").toUpperCase() + "]"));

          const g = svgEl("g", {{
            transform: "translate(" + (p.x - 62) + "," + (p.y - 34) + ")",
            opacity: isDown ? "0.68" : "1.0"
          }});
          g.appendChild(svgEl("rect", {{
            width: "124",
            height: "68",
            rx: "6",
            fill: fill,
            stroke: stroke,
            "stroke-width": isRoot ? "3" : "1.5",
            "stroke-dasharray": isDown ? "4 2" : ""
          }}));
          g.appendChild(svgEl("text", {{
            x: "62", y: "26",
            "text-anchor": "middle",
            fill: "var(--text-primary)",
            "font-size": "13",
            "font-weight": "700"
          }}, s.name));
          g.appendChild(svgEl("text", {{
            x: "62", y: "48",
            "text-anchor": "middle",
            fill: isRoot ? "var(--danger-fg)" : "var(--text-muted)",
            "font-size": "10",
            "font-weight": "700"
          }}, roleTag));
          svg.appendChild(g);
        }});

        return svg;
      }}

      // ========================================================================
      // SCREEN RENDERERS (b through i)
      // ========================================================================
      function renderActiveScreen() {{
        const container = document.getElementById("screen-container");
        if (!appState) {{
          clearAndAppend(container,
            el("div", {{ className: "card" }},
              el("p", null, lastErrorMsg ? String(lastErrorMsg) : "Loading system state from 127.0.0.1...")
            )
          );
          return;
        }}

        if (currentTab === "overview") renderOverview(container);
        else if (currentTab === "incident") renderIncidentDetail(container);
        else if (currentTab === "approvals") renderApprovals(container);
        else if (currentTab === "activity") renderActivity(container);
        else if (currentTab === "services") renderServices(container);
        else if (currentTab === "safety") renderSafety(container);
        else if (currentTab === "system") renderSystem(container);
        else if (currentTab === "guide") renderFirstRunGuide(container);
      }}

      // b) OVERVIEW SCREEN
      function renderOverview(container) {{
        const openIncs = (appState.incidents || []).filter(i => i.state !== "resolved");
        const approvals = appState.approvals || [];
        const recentActions = (appState.recent_actions || []).slice(0, 5);
        const lastAct = recentActions[0] || null;
        const isAllClear = openIncs.length === 0 && approvals.length === 0 && !appState.safety.killed && !appState.safety.circuit_open;

        // 4 Questions in <5 seconds
        const fourQ = el("div", {{ className: "four-questions-grid" }},
          el("div", {{ className: "q-card" }},
            el("div", {{ className: "q-label" }}, "1. Is everything OK?"),
            el("div", {{ className: "q-value" }},
              isAllClear
                ? statusBadge("ALL CLEAR", "ok", "[OK]")
                : (appState.safety.killed || appState.safety.circuit_open
                    ? statusBadge("HALTED", "danger", "[!]")
                    : statusBadge("DEGRADED (" + openIncs.length + " open)", "warn", "[!]"))
            ),
            el("div", {{ className: "q-sub" }},
              (appState.services || []).length + " monitored services · " + (appState.incidents || []).length + " total incidents"
            )
          ),
          el("div", {{ className: "q-card" }},
            el("div", {{ className: "q-label" }}, "2. What is the agent allowed to do?"),
            el("div", {{ className: "q-value" }},
              appState.mode.state === "DRY-RUN"
                ? statusBadge("DRY-RUN ONLY", "info", "[OBS]")
                : (appState.mode.state === "LIVE"
                    ? statusBadge("LIVE AUTO", "warn", "[LIVE]")
                    : statusBadge(appState.mode.state, "danger", "[STOP]"))
            ),
            el("div", {{ className: "q-sub" }},
              appState.safety.enabled_actions && appState.safety.enabled_actions.length > 0
                ? "Enabled: " + appState.safety.enabled_actions.join(", ")
                : "No auto-actions enabled (approval required)"
            )
          ),
          el("div", {{ className: "q-card" }},
            el("div", {{ className: "q-label" }}, "3. Does anything need me?"),
            el("div", {{ className: "q-value" }},
              approvals.length > 0
                ? statusBadge(approvals.length + " Approval(s) Pending", "warn", "[REQ]")
                : (appState.safety.circuit_open
                    ? statusBadge("Circuit Reset Needed", "danger", "[!]")
                    : statusBadge("Nothing Needs You", "ok", "[OK]"))
            ),
            el("div", {{ className: "q-sub" }},
              approvals.length > 0
                ? "Review staged proposals in Approvals tab"
                : "0 proposals waiting in approval queue"
            )
          ),
          el("div", {{ className: "q-card" }},
            el("div", {{ className: "q-label" }}, "4. What did it just do?"),
            el("div", {{ className: "q-value", style: {{ fontSize: "var(--text-base)" }} }},
              lastAct
                ? (lastAct.action + " on " + lastAct.target + " (" + lastAct.result + ")")
                : "No actions executed yet"
            ),
            el("div", {{ className: "q-sub" }},
              lastAct ? timeNode(lastAct.timestamp) : "Idle — monitoring signals"
            )
          )
        );

        const nodes = [fourQ];

        // Dismissible First-Run Guide Banner if not dismissed
        if (!guideDismissed && appState.first_run) {{
          const doneCount = appState.first_run.steps.filter(s => s.done).length;
          nodes.push(
            el("div", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "First-Run Workflow Progress (" + doneCount + " / " + appState.first_run.steps.length + " complete)"),
                el("div", {{ style: {{ display: "flex", gap: "8px" }} }},
                  el("button", {{ className: "btn", onClick: () => switchTab("guide") }}, "Open Full Guide"),
                  el("button", {{
                    className: "btn",
                    onClick: () => {{ guideDismissed = true; localStorage.setItem("slimeGuideDismissed", "1"); renderActiveScreen(); }}
                  }}, "Dismiss")
                )
              ),
              el("p", {{ style: {{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }} }},
                "Next recommended step: ",
                el("strong", null, appState.first_run.next_step)
              )
            )
          );
        }}

        // Calm All-Clear message
        if (isAllClear) {{
          nodes.push(
            el("div", {{ className: "alert-banner alert-ok", style: {{ margin: "0 0 20px 0" }} }},
              el("div", null,
                el("strong", null, "[ALL CLEAR] "),
                "All monitored services are healthy. No open incidents or pending approvals require your attention."
              )
            )
          );
        }}

        // Service Health Grid
        const svcCards = (appState.services || []).map(svc => {{
          let badge = statusBadge("HEALTHY", "ok", "[OK]");
          if (svc.in_maintenance) badge = statusBadge("IN MAINTENANCE", "info", "[MAINT]");
          else if (svc.status === "down") badge = statusBadge("DOWN", "danger", "[DOWN]");
          else if (svc.status === "degraded") badge = statusBadge("DEGRADED", "warn", "[DEG]");

          return el("div", {{ className: "service-card" }},
            el("div", {{ style: {{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "6px", flexWrap: "wrap" }} }},
              el("strong", null, svc.name),
              badge
            ),
            svc.critical
              ? el("div", null, statusBadge("CRITICAL · never auto-touched", "danger", "[LOCK]"))
              : null,
            el("div", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-secondary)" }} }},
              "Depends on: " + ((svc.depends_on && svc.depends_on.length) ? svc.depends_on.join(", ") : "none (root)")
            ),
            el("div", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }} }},
              svc.source_summary || "configured"
            )
          );
        }});

        nodes.push(
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Service Health Grid"),
              el("button", {{ className: "btn", onClick: () => switchTab("services") }}, "Topology & Maintenance")
            ),
            svcCards.length > 0
              ? el("div", {{ className: "service-grid" }}, svcCards)
              : el("div", {{ className: "empty-state" }},
                  "No services configured yet. Run ",
                  el("code", null, "selfheal init"),
                  " to scan your host and generate ",
                  el("code", null, "config.yaml"),
                  "."
                )
          )
        );

        // Open Incidents & Last 5 Actions
        const incTable = (appState.incidents || []).length === 0
          ? el("div", {{ className: "empty-state" }},
              "No incidents recorded yet. Run ",
              el("code", null, "selfheal run"),
              " to observe in dry-run, or ",
              el("code", null, "selfheal chaos"),
              " to inject a safe test fault."
            )
          : el("div", {{ className: "table-wrap" }},
              el("table", null,
                el("thead", null,
                  el("tr", null,
                    el("th", null, "ID"),
                    el("th", null, "State"),
                    el("th", null, "Services"),
                    el("th", null, "Root Cause Hypothesis"),
                    el("th", null, "Action"),
                    el("th", null, "Result / Note")
                  )
                ),
                el("tbody", null,
                  (appState.incidents || []).map(inc => {{
                    const stVariant = inc.state === "resolved" ? "ok" : (inc.state === "escalated" ? "danger" : "warn");
                    return el("tr", {{
                      className: "clickable-row",
                      tabindex: "0",
                      role: "button",
                      "aria-label": "Inspect incident " + inc.id,
                      onClick: () => switchTab("incident", inc.id),
                      onKeydown: (e) => {{ if (e.key === "Enter" || e.key === " ") {{ e.preventDefault(); switchTab("incident", inc.id); }} }}
                    }},
                      el("td", null, el("code", null, inc.id.slice(0, 14))),
                      el("td", null, statusBadge(inc.state.toUpperCase(), stVariant, "•")),
                      el("td", null, (inc.services || []).join(", ")),
                      el("td", null, inc.root_cause_summary || "—"),
                      el("td", null, el("code", null, inc.proposed_action || "—")),
                      el("td", null, inc.result_note || "—")
                    );
                  }})
                )
              )
            );

        nodes.push(
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Incidents (Click any row for Incident Detail & SVG Map)")
            ),
            incTable
          )
        );

        // Last 5 Actions + Resolution Breakdown Strip
        const resCounts = appState.resolution_breakdown || {{ rules: 0, retrieval: 0, local_llm: 0, cloud: 0, human: 0 }};
        nodes.push(
          el("div", {{ className: "section-grid" }},
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Last 5 Actions & Policy Decisions"),
                el("button", {{ className: "btn", onClick: () => switchTab("activity") }}, "Full Activity Log")
              ),
              recentActions.length === 0
                ? el("div", {{ className: "empty-state" }}, "No remediation actions or refusals recorded yet.")
                : el("div", {{ className: "table-wrap" }},
                    el("table", null,
                      el("thead", null,
                        el("tr", null,
                          el("th", null, "Time"),
                          el("th", null, "Action & Target"),
                          el("th", null, "Outcome / Rule")
                        )
                      ),
                      el("tbody", null,
                        recentActions.map(a => el("tr", null,
                          el("td", null, timeNode(a.timestamp)),
                          el("td", null, el("code", null, a.action + " (" + a.target + ")")),
                          el("td", null, a.plain_result)
                        ))
                      )
                    )
                  )
            ),
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "How Incidents Were Resolved")
              ),
              el("div", {{ className: "resolution-strip" }},
                el("div", {{ className: "res-item" }}, el("strong", {{ className: "tabular" }}, resCounts.rules), " Rules (D2)"),
                el("div", {{ className: "res-item" }}, el("strong", {{ className: "tabular" }}, resCounts.retrieval), " Retrieval (D1)"),
                el("div", {{ className: "res-item" }}, el("strong", {{ className: "tabular" }}, resCounts.local_llm), " Local LLM (D3)"),
                el("div", {{ className: "res-item" }}, el("strong", {{ className: "tabular" }}, resCounts.cloud), " Cloud (D4)"),
                el("div", {{ className: "res-item" }}, el("strong", {{ className: "tabular" }}, resCounts.human), " Human Approved")
              )
            )
          )
        );

        clearAndAppend(container, nodes);
      }}

      // c) INCIDENT DETAIL SCREEN
      function renderIncidentDetail(container) {{
        const incidents = appState.incidents || [];
        if (incidents.length === 0) {{
          clearAndAppend(container,
            el("div", {{ className: "card" }},
              el("h2", {{ className: "card-title", style: {{ marginBottom: "12px" }} }}, "Incident Detail"),
              el("div", {{ className: "empty-state" }},
                "No incidents recorded yet. Run ",
                el("code", null, "selfheal run"),
                " or ",
                el("code", null, "selfheal chaos"),
                " to generate an incident."
              )
            )
          );
          return;
        }}

        const inc = incidents.find(i => i.id === selectedIncidentId) || incidents[0];
        selectedIncidentId = inc.id;

        const selector = el("select", {{
          "aria-label": "Select incident",
          onChange: (e) => {{ selectedIncidentId = e.target.value; renderActiveScreen(); }}
        }},
          incidents.map(item =>
            el("option", {{ value: item.id, selected: item.id === inc.id }},
              item.id + " [" + item.state.toUpperCase() + "] — " + (item.services || []).join(", ")
            )
          )
        );

        const nodes = [
          el("div", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("div", {{ style: {{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }} }},
                el("h2", {{ className: "card-title" }}, "Incident " + inc.id),
                statusBadge(inc.state.toUpperCase(), inc.state === "resolved" ? "ok" : "warn", "•"),
                inc.dry_run_note ? statusBadge(inc.dry_run_note, "info", "[DRY-RUN]") : null
              ),
              el("div", {{ className: "filter-bar", style: {{ margin: "0", padding: "4px" }} }},
                el("label", {{ style: {{ fontSize: "var(--text-xs)", fontWeight: "700", alignSelf: "center" }} }}, "Switch Incident:"),
                selector
              )
            ),
            el("p", {{ style: {{ fontSize: "var(--text-sm)", color: "var(--text-secondary)", marginBottom: "12px" }} }},
              "Opened: ", timeNode(inc.opened_at),
              " · Services: ", (inc.services || []).join(", "),
              " · Root candidates: ", (inc.root_candidates || []).join(", "),
              " · Flaps: ", String(inc.flap_count),
              inc.postmortem ? el("span", null, " · ", el("a", {{ href: "#postmortem-section", style: {{ color: "var(--accent-fg)", fontWeight: "700" }} }}, "Jump to Postmortem")) : null
            ),
            el("h3", {{ style: {{ fontSize: "var(--text-sm)", marginBottom: "8px" }} }}, "Dependency Map (Root Cause Highlighted, Downstream Symptoms Muted)"),
            renderDependencySvg(appState.services || [], inc.root_candidates, inc.downstream)
          )
        ];

        // Ranked Hypotheses & Proposed Action + Live Target State
        const hypRows = (inc.hypotheses || []).map((h, idx) =>
          el("tr", null,
            el("td", null, "#" + (idx + 1) + " (" + h.tier + ")"),
            el("td", null, Number(h.confidence).toFixed(2)),
            el("td", null, h.root_cause),
            el("td", null, el("code", null, (h.action_name || "suggest-only") + (h.target ? " (" + h.target + ")" : ""))),
            el("td", null, (h.payload && h.payload.rationale) ? String(h.payload.rationale) : "—")
          )
        );

        const liveSnap = inc.live_target || {{}};
        nodes.push(
          el("div", {{ className: "section-grid" }},
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Ranked Root-Cause Hypotheses")
              ),
              hypRows.length === 0
                ? el("div", {{ className: "empty-state" }}, "No hypotheses generated for this incident.")
                : el("div", {{ className: "table-wrap" }},
                    el("table", null,
                      el("thead", null,
                        el("tr", null,
                          el("th", null, "Rank / Tier"),
                          el("th", null, "Conf"),
                          el("th", null, "Hypothesis"),
                          el("th", null, "Proposed Fix"),
                          el("th", null, "Evidence / Rationale")
                        )
                      ),
                      el("tbody", null, hypRows)
                    )
                  )
            ),
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Proposed Action & Live Target State")
              ),
              el("p", {{ style: {{ marginBottom: "8px" }} }},
                el("strong", null, "Proposed Action: "),
                el("code", null, inc.proposed_action || "none"),
                " · Risk: ",
                el("strong", null, inc.action_risk || "N/A")
              ),
              el("p", {{ style: {{ marginBottom: "8px" }} }},
                el("strong", null, "Target: "),
                el("code", null, liveSnap.target || "—"),
                " · Live State: ",
                el("strong", null, liveSnap.state || "unknown"),
                " · Revision: ",
                el("code", null, liveSnap.revision || "—")
              ),
              el("p", {{ style: {{ marginBottom: "12px" }} }},
                el("strong", null, "Outcome / Execution Note: "),
                inc.result_note || "—"
              ),
              el("div", {{ style: {{ borderTop: "1px solid var(--border-subtle)", paddingTop: "10px" }} }},
                el("strong", {{ style: {{ fontSize: "var(--text-sm)" }} }}, "Verification & Stability Window Progress:"),
                el("p", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-secondary)" }} }},
                  inc.verification_summary || "Not yet in verification window"
                ),
                el("div", {{ className: "progress-track" }},
                  el("div", {{
                    className: "progress-fill",
                    style: {{ width: (inc.verification_progress_pct || 0) + "%" }}
                  }})
                )
              )
            )
          )
        );

        // Policy Check Panel (ordered gates 1..11) + Event Timeline
        const gates = (inc.policy_check && inc.policy_check.gates) || [];
        nodes.push(
          el("div", {{ className: "section-grid" }},
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Deterministic Policy Gate Check (In Order)"),
                inc.policy_check && inc.policy_check.stopping_gate
                  ? statusBadge("STOPPED AT: " + inc.policy_check.stopping_gate, "danger", "[STOP]")
                  : statusBadge("ALL GATES PASSED", "ok", "[OK]")
              ),
              el("ul", {{ className: "gate-list" }},
                gates.map(g => {{
                  const isStop = g.status === "failed";
                  const badge = g.status === "passed"
                    ? statusBadge("PASS", "ok", "[OK]")
                    : (isStop ? statusBadge("STOPPED HERE", "danger", "[STOP]") : statusBadge("NOT REACHED", "neutral", "[--]"));
                  return el("li", {{ className: isStop ? "gate-item gate-stopped" : "gate-item" }},
                    el("span", null, el("strong", null, g.order + ". " + g.name), " — ", g.detail),
                    badge
                  );
                }})
              )
            ),
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Timeline of Events & State Transitions")
              ),
              (inc.events || []).length === 0
                ? el("div", {{ className: "empty-state" }}, "No correlated events stored.")
                : el("div", {{ className: "table-wrap" }},
                    el("table", null,
                      el("thead", null,
                        el("tr", null,
                          el("th", null, "Time"),
                          el("th", null, "Service / Kind"),
                          el("th", null, "Redacted Evidence (Text Only)")
                        )
                      ),
                      el("tbody", null,
                        (inc.events || []).map(ev => el("tr", null,
                          el("td", null, timeNode(ev.timestamp)),
                          el("td", null, ev.service + " · " + ev.kind),
                          el("td", null, el("pre", null, ev.evidence || "—"))
                        ))
                      )
                    )
                  )
            )
          )
        );

        if (inc.postmortem) {{
          nodes.push(
            el("section", {{ className: "card", id: "postmortem-section" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Resolved Incident Postmortem")
              ),
              el("pre", {{ className: "code-box" }}, inc.postmortem.markdown)
            )
          );
        }}

        clearAndAppend(container, nodes);
      }}

      // d) APPROVALS SCREEN
      function renderApprovals(container) {{
        const approvals = appState.approvals || [];
        if (approvals.length === 0) {{
          clearAndAppend(container,
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Pending Operator Approvals (0)")
              ),
              el("div", {{ className: "empty-state" }},
                "No staged proposals require approval right now. Proposals for ",
                el("code", null, "APPROVAL"),
                "-tier actions, ",
                el("code", null, "CRITICAL"),
                " services, or unenabled actions will appear here with a 5-minute expiry countdown."
              )
            )
          );
          return;
        }}

        const cards = approvals.map(item => {{
          const copyBtn = el("button", {{
            className: "btn",
            onClick: () => {{
              if (navigator.clipboard) navigator.clipboard.writeText(item.proposal_id);
              copyBtn.textContent = "Copied!";
              setTimeout(() => {{ copyBtn.textContent = "Copy Digest"; }}, 1500);
            }}
          }}, "Copy Digest");

          return el("article", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("div", {{ style: {{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }} }},
                el("h3", {{ className: "card-title" }}, item.action + " on " + item.target),
                statusBadge("Incident " + item.incident_id, "warn", "[REQ]"),
                statusBadge("Expires " + formatRelativeTime(item.expires_at), "info", "[TIMER]")
              ),
              el("div", {{ style: {{ display: "flex", gap: "8px" }} }},
                el("button", {{
                  className: "btn btn-ok",
                  disabled: !isConnected || appState.demo_mode,
                  onClick: () => openConfirmModal(
                    "Approve Staged Proposal?",
                    "Authorize single-use execution of " + item.action + " on " + item.target +
                    " (digest: " + item.proposal_id.slice(0, 16) + "..., revision: " + item.expected_revision + "). Actor 'dashboard' will be recorded.",
                    () => postAction("/api/approve", {{ proposal_id: item.proposal_id }})
                  )
                }}, "Approve"),
                el("button", {{
                  className: "btn btn-danger",
                  disabled: !isConnected || appState.demo_mode,
                  onClick: () => openConfirmModal(
                    "Reject Staged Proposal?",
                    "Remove staged proposal " + item.proposal_id.slice(0, 16) + "... for " + item.action + " on " + item.target + " from the approval queue?",
                    () => postAction("/api/reject", {{ proposal_id: item.proposal_id }})
                  )
                }}, "Reject")
              )
            ),
            el("p", {{ style: {{ fontSize: "var(--text-sm)", marginBottom: "8px" }} }},
              el("strong", null, "Evidence Summary: "),
              item.evidence_summary || "—"
            ),
            el("p", {{ style: {{ fontSize: "var(--text-sm)", marginBottom: "8px" }} }},
              el("strong", null, "Expected Target Revision: "),
              el("code", null, item.expected_revision),
              " · Confidence: ",
              el("strong", {{ className: "tabular" }}, Number(item.confidence || 0).toFixed(2))
            ),
            el("div", {{ style: {{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "8px" }} }},
              el("span", {{ style: {{ fontSize: "var(--text-xs)", fontWeight: "700" }} }}, "Proposal Digest (SHA-256):"),
              el("code", {{ className: "code-box", style: {{ padding: "4px 8px" }} }}, item.proposal_id),
              copyBtn
            ),
            el("p", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }} }},
              "Single-use lock: Bound to exact proposal digest, target parameters, and live inventory revision. CLI equivalent: ",
              el("code", null, "selfheal approve " + item.proposal_id)
            )
          );
        }});

        clearAndAppend(container,
          el("div", {{ style: {{ marginBottom: "12px" }} }},
            el("h2", {{ className: "card-title" }}, "Approval Queue (" + approvals.length + " staged proposals)"),
            el("p", {{ style: {{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }} }},
              "When multiple proposals exist for one incident, each is listed separately with its own SHA-256 digest."
            )
          ),
          cards
        );
      }}

      // e) ACTIVITY SCREEN
      function renderActivity(container) {{
        const entries = appState.activity || [];
        const services = Array.from(new Set(entries.map(e => e.service).filter(Boolean)));
        const actions = Array.from(new Set(entries.map(e => e.action).filter(Boolean)));
        const rules = Array.from(new Set(entries.map(e => e.rule).filter(Boolean)));

        const filtered = entries.filter(item => {{
          if (activityFilter.service && item.service !== activityFilter.service) return false;
          if (activityFilter.action && item.action !== activityFilter.action) return false;
          if (activityFilter.rule && item.rule !== activityFilter.rule) return false;
          if (activityFilter.result && item.result !== activityFilter.result) return false;
          return true;
        }});

        const filterBar = el("div", {{ className: "filter-bar" }},
          el("select", {{
            "aria-label": "Filter by service",
            onChange: (e) => {{ activityFilter.service = e.target.value; renderActiveScreen(); }}
          }},
            el("option", {{ value: "" }}, "All Services"),
            services.map(s => el("option", {{ value: s, selected: activityFilter.service === s }}, s))
          ),
          el("select", {{
            "aria-label": "Filter by action",
            onChange: (e) => {{ activityFilter.action = e.target.value; renderActiveScreen(); }}
          }},
            el("option", {{ value: "" }}, "All Actions"),
            actions.map(a => el("option", {{ value: a, selected: activityFilter.action === a }}, a))
          ),
          el("select", {{
            "aria-label": "Filter by policy rule",
            onChange: (e) => {{ activityFilter.rule = e.target.value; renderActiveScreen(); }}
          }},
            el("option", {{ value: "" }}, "All Rules"),
            rules.map(r => el("option", {{ value: r, selected: activityFilter.rule === r }}, r))
          ),
          el("select", {{
            "aria-label": "Filter by result",
            onChange: (e) => {{ activityFilter.result = e.target.value; renderActiveScreen(); }}
          }},
            el("option", {{ value: "" }}, "All Results"),
            ["success", "refused", "control", "failed"].map(r =>
              el("option", {{ value: r, selected: activityFilter.result === r }}, r)
            )
          ),
          el("button", {{
            className: "btn",
            onClick: () => {{ activityFilter = {{ service: "", action: "", rule: "", result: "" }}; renderActiveScreen(); }}
          }}, "Clear Filters")
        );

        clearAndAppend(container,
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Actions & Append-Only Audit Log (" + filtered.length + " entries)")
            ),
            filterBar,
            filtered.length === 0
              ? el("div", {{ className: "empty-state" }}, "No activity entries match the selected filters.")
              : el("div", {{ className: "table-wrap" }},
                  el("table", null,
                    el("thead", null,
                      el("tr", null,
                        el("th", null, "Time"),
                        el("th", null, "Service / Subject"),
                        el("th", null, "Action"),
                        el("th", null, "Rule"),
                        el("th", null, "Result"),
                        el("th", null, "Plain Explanation")
                      )
                    ),
                    el("tbody", null,
                      filtered.map(row => el("tr", null,
                        el("td", null, timeNode(row.timestamp)),
                        el("td", null, row.service || row.subject),
                        el("td", null, el("code", null, row.action || "—")),
                        el("td", null, el("code", null, row.rule)),
                        el("td", null,
                          statusBadge(
                            row.result.toUpperCase(),
                            row.result === "success" ? "ok" : (row.result === "refused" || row.result === "failed" ? "danger" : "info"),
                            "•"
                          )
                        ),
                        el("td", null, row.plain_explanation)
                      ))
                    )
                  )
                )
          )
        );
      }}

      // f) SERVICES SCREEN
      function renderServices(container) {{
        const services = appState.services || [];
        const maint = appState.maintenance_windows || [];

        clearAndAppend(container,
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Service Dependency Graph (Read-Only in v1)")
            ),
            renderDependencySvg(services, [], [])
          ),
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Configured Services & Critical Flags")
            ),
            services.length === 0
              ? el("div", {{ className: "empty-state" }}, "No services configured in config.yaml.")
              : el("div", {{ className: "table-wrap" }},
                  el("table", null,
                    el("thead", null,
                      el("tr", null,
                        el("th", null, "Service"),
                        el("th", null, "Status"),
                        el("th", null, "Critical Flag"),
                        el("th", null, "Depends On"),
                        el("th", null, "Configured Collectors / Targets")
                      )
                    ),
                    el("tbody", null,
                      services.map(s => el("tr", null,
                        el("td", null, el("strong", null, s.name)),
                        el("td", null, statusBadge((s.status || "healthy").toUpperCase(), s.status === "healthy" ? "ok" : "warn", "•")),
                        el("td", null, s.critical ? statusBadge("CRITICAL (Approval Only)", "danger", "[LOCK]") : statusBadge("Standard", "neutral", "•")),
                        el("td", null, (s.depends_on || []).join(", ") || "none"),
                        el("td", null, el("code", null, s.source_summary || "—"))
                      ))
                    )
                  )
                )
          ),
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Maintenance Windows (Read-Only in v1)")
            ),
            maint.length === 0
              ? el("div", {{ className: "empty-state" }}, "No maintenance suppression windows configured in config.yaml.")
              : el("div", {{ className: "table-wrap" }},
                  el("table", null,
                    el("thead", null,
                      el("tr", null,
                        el("th", null, "Services"),
                        el("th", null, "Start (UTC)"),
                        el("th", null, "End (UTC)"),
                        el("th", null, "Status")
                      )
                    ),
                    el("tbody", null,
                      maint.map(w => el("tr", null,
                        el("td", null, (w.services || []).join(", ")),
                        el("td", null, el("code", null, w.start)),
                        el("td", null, el("code", null, w.end)),
                        el("td", null, w.active ? statusBadge("ACTIVE NOW", "info", "[MAINT]") : statusBadge("Scheduled", "neutral", "•"))
                      ))
                    )
                  )
                )
          )
        );
      }}

      // g) SAFETY SCREEN
      function renderSafety(container) {{
        const sf = appState.safety || {{}};
        const cooldowns = sf.cooldowns || [];
        const pendingActs = sf.interrupted_actions || [];
        const ksHistory = sf.kill_switch_history || [];

        clearAndAppend(container,
          el("div", {{ className: "section-grid" }},
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Safety Budgets & Enabled Actions")
              ),
              el("p", {{ style: {{ marginBottom: "8px" }} }},
                el("strong", null, "Enabled Auto-Execution Actions: "),
                (sf.enabled_actions && sf.enabled_actions.length)
                  ? el("code", null, sf.enabled_actions.join(", "))
                  : el("span", null, "none (default — nothing auto-runs until ", el("code", null, "selfheal enable-action"), ")")
              ),
              el("p", {{ style: {{ marginBottom: "8px" }} }},
                el("strong", null, "Hourly Automatic Budget Used: "),
                el("span", {{ className: "tabular" }}, sf.hourly_used + " / " + sf.max_auto_per_hour + " reservations in last 60m")
              ),
              el("p", {{ style: {{ marginBottom: "8px" }} }},
                el("strong", null, "Minimum Confidence Threshold: "),
                el("span", {{ className: "tabular" }}, String(sf.minimum_confidence))
              ),
              el("h3", {{ style: {{ fontSize: "var(--text-sm)", margin: "14px 0 8px" }} }}, "Active Per-Target Cooldowns"),
              cooldowns.length === 0
                ? el("div", {{ className: "empty-state" }}, "No targets are currently in cooldown.")
                : el("div", {{ className: "table-wrap" }},
                    el("table", null,
                      el("thead", null,
                        el("tr", null,
                          el("th", null, "Action"),
                          el("th", null, "Target"),
                          el("th", null, "Remaining")
                        )
                      ),
                      el("tbody", null,
                        cooldowns.map(c => el("tr", null,
                          el("td", null, el("code", null, c.action)),
                          el("td", null, el("code", null, c.target)),
                          el("td", null, c.remaining_minutes + " min left (" + c.remaining_seconds + "s)")
                        ))
                      )
                    )
                  )
            ),
            el("section", {{ className: "card" }},
              el("div", {{ className: "card-header" }},
                el("h2", {{ className: "card-title" }}, "Circuit Breaker & Exact Reset Steps"),
                sf.circuit_open
                  ? statusBadge("CIRCUIT OPEN", "danger", "[OPEN]")
                  : statusBadge("CIRCUIT CLOSED", "ok", "[OK]")
              ),
              el("p", {{ style: {{ marginBottom: "10px" }} }},
                "Consecutive failures: ",
                el("strong", {{ className: "tabular" }}, sf.consecutive_failures + " / " + sf.circuit_breaker_failures)
              ),
              el("div", {{ className: "code-box", style: {{ marginBottom: "12px" }} }},
                "Exact Circuit Breaker Recovery Steps:\\n" +
                "1. Inspect any interrupted/uncertain action attempts below.\\n" +
                "2. Reconcile each interrupted attempt:\\n" +
                "   selfheal reconcile <action_id>\\n" +
                "3. Reset the circuit breaker after verifying target health:\\n" +
                "   selfheal reset-circuit"
              ),
              pendingActs.length > 0
                ? el("div", null,
                    el("strong", {{ style: {{ fontSize: "var(--text-sm)" }} }}, "Interrupted / Pending Actions Requiring Reconcile:"),
                    el("ul", {{ style: {{ marginTop: "6px", paddingLeft: "18px" }} }},
                      pendingActs.map(pa => el("li", null,
                        el("code", null, "selfheal reconcile " + pa.id),
                        " (" + pa.name + " on " + pa.target + ", status=" + pa.status + ")"
                      ))
                    )
                  )
                : el("p", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }} }}, "0 interrupted actions currently pending reconciliation.")
            )
          ),
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Kill Switch History")
            ),
            ksHistory.length === 0
              ? el("div", {{ className: "empty-state" }}, "No kill-switch activations recorded.")
              : el("div", {{ className: "table-wrap" }},
                  el("table", null,
                    el("thead", null,
                      el("tr", null,
                        el("th", null, "Timestamp"),
                        el("th", null, "Actor"),
                        el("th", null, "Transition")
                      )
                    ),
                    el("tbody", null,
                      ksHistory.map(k => el("tr", null,
                        el("td", null, timeNode(k.timestamp)),
                        el("td", null, el("code", null, k.actor)),
                        el("td", null, k.enabled ? statusBadge("ENGAGED (ON)", "danger", "[ON]") : statusBadge("DISENGAGED (OFF)", "ok", "[OFF]"))
                      ))
                    )
                  )
                )
          )
        );
      }}

      // h) SYSTEM (DOCTOR) SCREEN
      function renderSystem(container) {{
        const doc = appState.doctor || {{ groups: {{}}, capabilities: [], next_step: "" }};
        const groupNodes = Object.entries(doc.groups || {{}}).map(([groupName, items]) =>
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Doctor — " + groupName)
            ),
            el("div", {{ className: "table-wrap" }},
              el("table", null,
                el("thead", null,
                  el("tr", null,
                    el("th", null, "Component"),
                    el("th", null, "Status"),
                    el("th", null, "Detail & One-Line Fix")
                  )
                ),
                el("tbody", null,
                  items.map(it => el("tr", null,
                    el("td", null, el("strong", null, it.component)),
                    el("td", null,
                      statusBadge(
                        it.status.toUpperCase(),
                        it.needs_attention ? "warn" : "ok",
                        it.needs_attention ? "[!]" : "[OK]"
                      )
                    ),
                    el("td", null,
                      it.detail,
                      it.fix ? el("div", {{ style: {{ marginTop: "4px", fontWeight: "700", color: "var(--warn-fg)" }} }}, "Fix: " + it.fix) : null
                    )
                  ))
                )
              )
            )
          )
        );

        clearAndAppend(container,
          el("div", {{ className: "alert-banner alert-info", style: {{ margin: "0 0 16px 0" }} }},
            el("div", null, el("strong", null, "Doctor Next Step: "), doc.next_step || "Run selfheal run to monitor in dry-run.")
          ),
          groupNodes,
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "Host Capability Matrix (" + (doc.host_os || "Host") + ")")
            ),
            el("div", {{ className: "table-wrap" }},
              el("table", null,
                el("thead", null,
                  el("tr", null,
                    el("th", null, "Capability"),
                    el("th", null, "Support Status"),
                    el("th", null, "Why / Details")
                  )
                ),
                el("tbody", null,
                  (doc.capabilities || []).map(cap => el("tr", null,
                    el("td", null, el("strong", null, cap.capability)),
                    el("td", null, statusBadge(cap.status.toUpperCase(), cap.status === "works" ? "ok" : "neutral", "•")),
                    el("td", null, cap.detail)
                  ))
                )
              )
            )
          )
        );
      }}

      // i) FIRST-RUN GUIDE SCREEN
      function renderFirstRunGuide(container) {{
        const guide = appState.first_run || {{ steps: [], next_step: "" }};
        clearAndAppend(container,
          el("section", {{ className: "card" }},
            el("div", {{ className: "card-header" }},
              el("h2", {{ className: "card-title" }}, "First-Run Operational Checklist (Derived from Real State)"),
              el("button", {{
                className: "btn",
                onClick: () => {{
                  guideDismissed = !guideDismissed;
                  localStorage.setItem("slimeGuideDismissed", guideDismissed ? "1" : "0");
                  renderActiveScreen();
                }}
              }}, guideDismissed ? "Show on Overview" : "Dismiss from Overview")
            ),
            el("p", {{ style: {{ fontSize: "var(--text-sm)", color: "var(--text-secondary)", marginBottom: "16px" }} }},
              "Each step below is computed directly from your live configuration, SQLite store, and safety settings — never from manual checkboxes."
            ),
            el("ul", {{ className: "gate-list" }},
              (guide.steps || []).map(step =>
                el("li", {{ className: "gate-item" }},
                  el("div", null,
                    el("strong", null, step.order + ". " + step.title),
                    el("div", {{ style: {{ fontSize: "var(--text-xs)", color: "var(--text-secondary)" }} }}, step.detail),
                    el("code", {{ style: {{ fontSize: "var(--text-xs)" }} }}, step.command)
                  ),
                  step.done ? statusBadge("COMPLETE", "ok", "[DONE]") : statusBadge("PENDING", "warn", "[TODO]")
                )
              )
            )
          )
        );
      }}

      // Boot
      initTheme();
      switchTab(currentTab, selectedIncidentId);
      fetchDashboardState();
      setInterval(fetchDashboardState, 4000);
    }})();
  </script>
</body>
</html>"""
