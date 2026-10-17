# Slime SelfHeal Design System (`docs/DESIGN.md`)

## 1. Design Philosophy: Calm Operations
A person opening the dashboard or running a CLI status command must answer four questions in under five seconds:
1. **Is everything OK?**
2. **What is the agent allowed to do right now?**
3. **Does anything need me?**
4. **What did it just do?**

- **All-clear is quiet**: When services are healthy and no incidents or approvals are open, the screen shows a calm, neutral surface without flashing indicators, charts, or unnecessary badges.
- **Color & motion are reserved for attention**: Saturated semantic colors (`warning`, `danger`) appear only when an operator action, policy refusal, degraded service, or safety halt requires attention.
- **Color is never the only signal**: Every status indicator pairs color with both an explicit **inline SVG icon** (or ASCII glyph in terminal) and an explicit **text label** (`HEALTHY`, `DEGRADED`, `DOWN`, `MAINTENANCE`, `CRITICAL`, `DRY-RUN`, `LIVE`, `HALTED`, `CIRCUIT OPEN`).
- **Offline, zero-dependency, self-contained**: System font stack, inline SVG icons, vanilla JavaScript, and CSS custom properties served from `127.0.0.1`. No external fonts, CDNs, or frameworks.

---

## 2. Design Tokens (Single Source of Truth)

All visual tokens are defined once in `:root` (Light Theme default, matching `prefers-color-scheme: light`) and `[data-theme="dark"]` (Dark Theme, matching `prefers-color-scheme: dark` or manual toggle). All foreground/background pairs meet or exceed **WCAG 2.1 AA** contrast (`>= 4.5:1` for body text, `>= 3.0:1` for UI components and large text).

### 2.1 Color Tokens

| Token | Light Theme (`[data-theme="light"]`) | Dark Theme (`[data-theme="dark"]`) | Usage & Contrast Ratio |
| :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#f8fafc` | `#0b0f19` | Primary page background |
| `--bg-surface` | `#ffffff` | `#111827` | Cards, panels, tables, header |
| `--bg-elevated` | `#f1f5f9` | `#1e293b` | Code blocks, filter bars, secondary wells |
| `--bg-muted` | `#e2e8f0` | `#0f172a` | Subtle hover/inactive states |
| `--border-subtle` | `#e2e8f0` | `#1f2937` | Hairline dividers |
| `--border-default` | `#cbd5e1` | `#334155` | Card and control borders |
| `--border-strong` | `#64748b` | `#64748b` | High-visibility input/focus borders |
| `--text-primary` | `#0f172a` (`16.1:1`) | `#f8fafc` (`16.8:1`) | Primary text, headings, values |
| `--text-secondary` | `#334155` (`9.8:1`) | `#cbd5e1` (`11.4:1`) | Table cells, descriptions, labels |
| `--text-muted` | `#475569` (`7.0:1`) | `#94a3b8` (`6.3:1`) | Timestamps, metadata, captions |
| `--accent-fg` | `#0369a1` (`5.9:1`) | `#38bdf8` (`8.5:1`) | Interactive links, active tab indicator |
| `--accent-bg` | `#e0f2fe` | `#082f49` | Active pill / dry-run banner background (`5.17:1` light / `6.48:1` dark) |
| `--ok-fg` | `#166534` (`6.8:1`) | `#4ade80` (`9.4:1`) | Healthy, verified, closed breaker text/icon |
| `--ok-bg` | `#dcfce7` | `#052e16` | Healthy badge fill |
| `--ok-border` | `#86efac` | `#166534` | Healthy badge border |
| `--warn-fg` | `#854d0e` (`6.4:1`) | `#facc15` (`11.9:1`) | Degraded, approval needed, live mode text/icon |
| `--warn-bg` | `#fef9c3` | `#422006` | Warning badge / banner fill |
| `--warn-border` | `#fde047` | `#854d0e` | Warning badge / banner border |
| `--danger-fg` | `#991b1b` (`7.2:1`) | `#f87171` (`6.5:1`) | Halted, circuit open, down, refused text/icon |
| `--danger-bg` | `#fee2e2` | `#450a0a` | Danger badge / banner fill |
| `--danger-border` | `#fca5a5` | `#991b1b` | Danger badge / banner border |
| `--focus-ring` | `#0284c7` | `#38bdf8` | `2px solid` keyboard focus outline (`outline-offset: 2px`) |

### 2.2 Typography & Numeric Scale
- **Font stacks**:
  - `--font-sans`: `-apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, "Helvetica Neue", Arial, sans-serif`
  - `--font-mono`: `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`
- **Type scale**:
  - `--text-xs`: `0.75rem` (`12px`, line-height `1.4`) — badges, uppercase column headers, digests
  - `--text-sm`: `0.875rem` (`14px`, line-height `1.5`) — table cells, controls, secondary copy
  - `--text-base`: `0.9375rem` (`15px`, line-height `1.5`) — body text, descriptions
  - `--text-lg`: `1.125rem` (`18px`, line-height `1.4`) — card/section titles (`text-wrap: balance`)
  - `--text-xl`: `1.375rem` (`22px`, line-height `1.3`) — primary view headers and metric callouts
- **Tabular numbers**: All counts, timers, cooldowns, durations, budgets, and timestamps apply `font-variant-numeric: tabular-nums`.
- **Timestamps**: Displayed as human-readable relative times (`2m ago`, `in 4m 12s`) with a `<time datetime="...">` element and `title="2026-10-17T05:30:00Z"` showing the exact UTC ISO-8601 timestamp on hover/focus.

### 2.3 Spacing, Radii, and Z-Index Scale
- **Spacing scale**:
  - `--space-1`: `4px`
  - `--space-2`: `8px`
  - `--space-3`: `12px`
  - `--space-4`: `16px`
  - `--space-5`: `24px`
  - `--space-6`: `32px`
- **Border radii**:
  - `--radius-sm`: `4px` (badges, inline code, buttons)
  - `--radius-md`: `6px` (cards, inputs, dialogs)
  - `--radius-lg`: `8px` (top-level banners and modals)
- **Z-Index scale**:
  - `--z-header`: `10` (sticky top status bar)
  - `--z-banner`: `20` (disconnected / stale warning banner)
  - `--z-modal`: `50` (confirmation `<dialog>` / modal overlay)

### 2.4 Motion & Accessibility Rules
- **Compositor-only transitions**: Only `opacity` and `transform` are transitioned (`<= 150ms ease-out`). Layout properties (`width`, `height`, `margin`, `padding`) are never animated.
- **`prefers-reduced-motion: reduce`**: Disables all transitions and animations (`transition-duration: 0.01ms !important; animation-duration: 0.01ms !important`).
- **ARIA Live Regions**:
  - `aria-live="polite"` region announces new incidents and mode changes without stealing focus.
  - `aria-live="assertive"` announces emergency states (`HALTED`, `CIRCUIT OPEN`, `DISCONNECTED`).
- **Keyboard navigation**:
  - Skip-to-main-content link at top of DOM.
  - All tabs (`role="tablist"` / `role="tab"`), incident rows, filter controls, copy buttons, and confirmation dialogs are keyboard operable (`Enter`, `Space`, `Escape`, `ArrowLeft`/`ArrowRight`).
  - Visible `:focus-visible` ring (`2px solid var(--focus-ring)`) on every interactive element.

---

## 3. Component & Screen Architecture

### 3.1 Persistent Header (Answers Questions 1 & 2 in <5s)
- **Mode Banner**: Exact wording shared between CLI (`selfheal status`) and Dashboard:
  - `DRY-RUN — observe only (no actions execute)`
  - `LIVE — enabled actions: <list>` (or `LIVE — no auto actions enabled (approval only)`)
  - `HALTED — kill switch engaged`
  - `CIRCUIT OPEN — human reconciliation required`
- **Learning Period Indicator**: Pill showing `Observing: day N of 7` when `learning_period` is active.
- **Connection Status & Last Updated**:
  - Live indicator (`Connected · Updated 2s ago` with exact ISO timestamp on hover).
  - On poll/SSE failure: Switches immediately to `DISCONNECTED — data stale since <time>`, dims the main workspace (`opacity: 0.55`), and blocks misleading "live" assurances.
- **Safety Controls**:
  - Kill-switch toggle button with confirmation modal (`Engage Kill Switch` / `Disengage Kill Switch`).
  - Dry-run toggle button with confirmation modal.
  - Theme toggle (`Auto` / `Light` / `Dark`) with `aria-label`.

### 3.2 Screens (`role="tablist"`)
1. **Overview**:
   - **4-Question Summary Strip**:
     1. *System State*: `ALL CLEAR` / `DEGRADED (N open)` / `HALTED`
     2. *Agent Authority*: `DRY-RUN` or `LIVE (enabled actions)`
     3. *Needs You*: `N pending approvals` / `Circuit breaker`
     4. *Last Action*: Most recent executed or refused action with relative time
   - **All-Clear Calm Banner**: Shown when 0 open incidents, 0 pending approvals, kill switch off, and circuit closed: *"All monitored services are healthy. No incidents or pending approvals."*
   - **Service Health Grid**: Cards for each configured service with icon + text badge (`HEALTHY`, `DEGRADED`, `DOWN`, `IN MAINTENANCE`) and explicit `CRITICAL (never auto-touched)` badge.
   - **Open Incidents List**: Clickable rows opening **Incident Detail**.
   - **Last 5 Actions**: Recent action reservations/executions/refusals.
   - **How Incidents Were Resolved Strip**: Tabular counts across `Rules (D2)`, `Retrieval (D1)`, `Local LLM (D3)`, `Cloud (D4)`, and `Human Approval`.
2. **Incident Detail**:
   - **Header**: Incident ID, state badge, services, opened timestamp, flap count, postmortem jump link (when resolved).
   - **Inline SVG Dependency Map**: Directed graph (`upstream -> downstream`) highlighting the root cause candidate (`stroke: var(--danger-fg)`, bold icon/label) and muting downstream symptom services (`opacity: 0.65`, dashed border).
   - **Ranked Hypotheses**: Confidence score (`tabular-nums`), deciding tier (`D1_MEMORY` / `D2_RUNBOOK` / etc.), rationale, and redacted evidence references.
   - **Proposed Action & Live Target State**: Action name, risk tier (`SAFE` / `APPROVAL`), target alias, live snapshot state/revision/critical flag, and dry-run execution note (`would have auto-executed` / `would have needed approval` — shown *only* when handled in dry-run and not yet acted on).
   - **Ordered Policy Check Panel**: Displays all 11 deterministic gates in exact evaluation order (`1. kill_switch` through `11. preconditions`), marking each gate `PASS` (`[OK]`), `STOPPED HERE` (`[STOP]`), or `NOT REACHED` (`[--]`).
   - **Timeline & Verification Progress**: Chronological event + audit transitions, stability verification window progress bar (`window_seconds`), and full rendered text of the postmortem when resolved.
3. **Approvals**:
   - Queue of staged proposals (`pending_approvals`), with multiple proposals for the same incident listed as separate cards.
   - Each card shows: live expiry countdown (`Expires in 4m 12s`), incident evidence summary, exact action + target + expected revision, copyable SHA-256 `proposal_digest`, single-use lock notice, and **Approve** / **Reject** buttons with confirmation dialog.
4. **Activity**:
   - Unified view of action executions and append-only `audit_log` entries.
   - Filterable by **Service**, **Action**, **Rule**, and **Result** (`allowed`, `refused`, `success`, `failed`, `control`).
   - Plain-language refusal descriptions (e.g. `refused: cooldown, 4 min left`, `refused: critical_approval_required — target is marked critical`, `refused: dry_run — observe-only mode active`).
5. **Services**:
   - Full SVG service dependency topology, table of services with `critical` markers, configured health probes/logs/containers/units, and configured maintenance windows (`read-only in v1`).
6. **Safety**:
   - Enabled actions list, active per-target cooldown countdowns, hourly automatic budget meter (`used / max_auto_per_hour`), circuit breaker status with exact CLI/UI recovery steps (`1. selfheal reconcile <action_id>`, `2. selfheal reset-circuit`), and kill-switch audit history.
7. **System (`doctor`)**:
   - Grouped checklist (`Collectors`, `Diagnosis`, `Safety`, `Platform`), highlighting items needing attention with a one-line fix, plus the Host Capability table.
8. **First-Run Guide**:
   - Dismissible checklist mirroring `docs/WORKFLOW.md`:
     1. `selfheal init` (derived from `config.yaml` existence / configured services)
     2. Review `config.yaml` (`critical` flags, `depends_on`, maintenance windows)
     3. `selfheal doctor` (collector & diagnosis readiness)
     4. Observe in `DRY-RUN` (events/incidents collected while `dry_run=True`)
     5. Enable one safe action (`safety.enabled_actions` non-empty)
     6. Go live (`dry_run=False` with safety gates active)

---

## 4. Ten Required UI States

| State | Visual & Behavioral Rule |
| :--- | :--- |
| **1. Loading** | Calm skeleton text (`Loading system state from 127.0.0.1...`) with zero layout jump once data arrives. |
| **2. Empty (no incidents yet)** | Actionable message: *"No incidents recorded yet. Run `selfheal run` to observe your services in dry-run, or `selfheal chaos` to test a simulated fault."* |
| **3. All-Clear** | Quiet green/neutral summary banner; zero warning/danger fills in main viewport. |
| **4. Learning Period** | Header pill `Observing: day N of 7` + callout explaining baseline building and lower alert noise. |
| **5. Dry-Run** | Prominent blue/info mode badge `DRY-RUN`; incidents display `would have auto-executed` or `would have needed approval`. |
| **6. Live** | Amber/active mode badge `LIVE — enabled actions: ...`; real executions show verification progress and duration. |
| **7. Halted (`kill_switch` / `circuit_open`)** | High-contrast danger banner at top of viewport explaining why mutations are stopped and how to resume safely. |
| **8. Disconnected** | Sticky warning banner `DISCONNECTED — last updated <time>`, main content dimmed (`opacity: 0.55`), action buttons disabled until connection resumes. |
| **9. Error** | Inline error alert with exact status code / reason and a `Retry Now` button. |
| **10. Long Text Overflow** | Log evidence, digests, and paths use `overflow-wrap: anywhere` or horizontal scroll inside `<pre>` blocks (`max-width: 100%`) so no card or table overflows the viewport at `375px` mobile width. |
