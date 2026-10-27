# Aegis Phase 5.5 — SOC UI Design Specification & Visual Reference Guide

## 1. Executive Summary & Visual Reference Analysis

The Aegis Security Operations Center (SOC) dashboard UI is inspired by modern cloud-native API security platforms, specifically referencing the dark, data-dense, high-legibility interface character exemplified by the **Wallarm SOC Console**. 

Aegis reproduces the restrained dark aesthetic, compact data hierarchy, collapsible sidebar navigation, and tactical status indicators of the reference interface while maintaining 100% proprietary Aegis branding, open architecture, and an uncompromised non-intrusive **Advisory Mode** security model.

---

## 2. Typography & Font Investigation

### 2.1 Visual Reference Typography Analysis
Inspection of Wallarm's user interface indicates a clean, geometric neo-grotesque typeface characterized by tall x-height, neutral letterforms, and tight numerical spacing suited for dense financial and security telemetry.

### 2.2 Selected Typeface & Fallback Strategy
- **Primary Interface Font:** `Inter` (Open Source, SIL Open Font License).
  - Rationale: `Inter` provides exact optical alignment for user interfaces, dedicated tabular numbers for alignment in security tables, and multi-weight legibility across 400 (Regular), 500 (Medium), 600 (Semi-Bold), and 700 (Bold).
  - Fallback Stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
- **Telemetry & Monospace Font:** `JetBrains Mono`.
  - Rationale: High-distinction zero (`0` vs `O`), consistent character width for UUIDs, IP addresses, correlation IDs, and HTTP status codes.
  - Fallback Stack: `'SF Mono', Consolas, 'Fira Code', monospace`.

---

## 3. Centralized Design Tokens & Color Palette

The design tokens are centralized in [`frontend/src/styles.css`](file:///c:/Users/nikhi/aegis/frontend/src/styles.css).

### 3.1 Surface & Background Tokens
| Token | Hex Value | Semantic Purpose |
| :--- | :--- | :--- |
| `--bg-canvas` | `#0b0d13` | Deep matte charcoal outer canvas (sampled from Wallarm) |
| `--bg-header` | `#0d0f16` | Top Command & Control navbar surface |
| `--bg-sidebar` | `#0d0f16` | Collapsible left navigation rail surface |
| `--bg-card` | `#141722` | Primary elevated card surface |
| `--bg-card-hover` | `#191d2c` | Subtle card hover interaction surface |
| `--bg-surface` | `#10131b` | Secondary inset background for controls and pill groups |
| `--bg-input` | `#090b10` | High-contrast sunken input field background |

### 3.2 Border & Divider Tokens
| Token | Value | Semantic Purpose |
| :--- | :--- | :--- |
| `--border-subtle` | `rgba(255, 255, 255, 0.06)` | Minimal container separation |
| `--border-default` | `#1e2333` | Standard card and table borders |
| `--border-card` | `rgba(255, 255, 255, 0.08)` | Card elevation contour |
| `--border-focus` | `#14b8a6` | Accessible focus state indicator (WCAG 2.1 AA) |

### 3.3 Accent Palette
| Token | Hex Value | Semantic Purpose |
| :--- | :--- | :--- |
| `--accent-teal` | `#14b8a6` | Primary tactical Aegis action & link accent |
| `--accent-amber` | `#f97316` | Wallarm-inspired warm secondary accent (active tabs, warnings) |
| `--accent-violet` | `#818cf8` | Correlated threat category accent (`MULTI_VECTOR_CAMPAIGN`) |
| `--accent-cyan` | `#06b6d4` | Resource entity & probe telemetry accent |

### 3.4 Severity & Status Tokens
| Token | Color Value | Semantic Meaning |
| :--- | :--- | :--- |
| `--sev-critical` | `#ef4444` (Coral Red) | Critical threat requiring immediate analyst triage |
| `--sev-high` | `#f97316` (Vibrant Orange) | High-severity multi-resource anomaly |
| `--sev-medium` | `#eab308` (Amber Gold) | Moderate behavioral deviation |
| `--sev-low` | `#38bdf8` (Sky Blue) | Low-severity baseline anomaly |
| `--sev-info` | `#94a3b8` (Slate Gray) | Informational or telemetry baseline event |
| `--status-open` | `#f59e0b` | Incident newly detected; pending analyst review |
| `--status-investigating` | `#38bdf8` | Incident actively under analyst investigation |
| `--status-contained` | `#a855f7` | Incident verified and mitigations advised |
| `--status-resolved` | `#10b981` | Incident investigated and resolved |
| `--status-false-positive` | `#64748b` | Verified false positive; closed by analyst |

---

## 4. Navigation Architecture & Route Hierarchy

The persistent, collapsible sidebar is structured into 5 cohesive operational groups containing 15 distinct navigation destinations:

```
├── DASHBOARD
│   └── Overview (/overview) [ACTIVE]
│
├── ATTACKS & INVESTIGATION
│   ├── Incidents (/incidents) [ACTIVE]
│   ├── Attack Activity (/attacks) [ACTIVE]
│   ├── Attack Campaigns (/campaigns) [ACTIVE]
│   └── Evidence Explorer (/evidence) [ACTIVE]
│
├── API SECURITY
│   ├── API Inventory (/api-inventory) [PLANNED - Phase 6]
│   ├── API Event Explorer (/events) [ACTIVE]
│   ├── API Specifications (/api-specs) [PLANNED - Phase 6]
│   └── Data Access Monitoring (/data-access) [ACTIVE]
│
├── DETECTION & RESPONSE
│   ├── Detection Rules (/detection-rules) [ACTIVE]
│   ├── BOLA Detection (/bola-detection) [ACTIVE]
│   └── Policy Decisions (/policy-decisions) [ACTIVE]
│
└── GOVERNANCE & OPERATIONS
    ├── Audit History (/audit-history) [ACTIVE]
    ├── System Health (/system-health) [ACTIVE]
    └── Settings (/settings) [ACTIVE]
```

### 4.1 Collapsible Sidebar Mechanics
- **Expanded Desktop State:** Width `240px`, displaying section headers, text labels, and capability status badges.
- **Collapsed Desktop State:** Width `64px`, displaying icon-only rail with HTML `title` and `aria-label` tooltips on every item.
- **Mobile Off-Canvas Drawer:** On viewport width $\le 900\text{px}$, the sidebar slides off-canvas and toggles via the navbar hamburger button, backed by a darkened frosted backdrop.

---

## 5. Truthful Feature Availability Classification

Aegis strictly prohibits deceptive UX practices, such as presenting simulated traffic or displaying mock data as active security controls. Every navigation destination is classified with complete operational honesty:

| Feature / Module | Route | Operational Status | Backing Data Source |
| :--- | :--- | :--- | :--- |
| **Security Overview** | `/overview` | **Implemented** | `GET /api/v1/security/overview?windowHours={w}` |
| **Incident Queue** | `/incidents` | **Implemented** | `GET /api/v1/security/incidents` |
| **Incident Forensic Workspace** | `/incidents/:id` | **Implemented** | `GET /api/v1/security/incidents/{id}`, `/evidence`, `/history`, `/policy-decisions` |
| **Attack Activity** | `/attacks` | **Implemented** | `GET /api/v1/security/events?anomalyFlags=true` |
| **Attack Campaigns** | `/campaigns` | **Implemented** | `GET /api/v1/security/incidents` (Correlated Multi-Vector / BOLA Campaigns) |
| **Evidence Explorer** | `/evidence` | **Implemented** | Aggregated `GET /api/v1/security/incidents/{id}/evidence` |
| **API Inventory** | `/api-inventory` | **Planned (Phase 6)** | Architectural preview of passive traffic endpoint discovery |
| **API Event Explorer** | `/events` | **Implemented** | `GET /api/v1/security/events`, `GET /events/{id}` |
| **API Specifications** | `/api-specs` | **Planned (Phase 6)** | Architectural preview of OpenAPI 3.0 schema drift validation |
| **Data Access Monitoring** | `/data-access` | **Implemented** | Live telemetry with SHA-256 payload hashing & token redaction |
| **Detection Rules** | `/detection-rules` | **Implemented** | Operational status of the 6 core Aegis correlation rules |
| **BOLA Detection** | `/bola-detection` | **Implemented** | `RULE-BOLA-01` sliding window telemetry & BOLA incident queue |
| **Policy Decisions** | `/policy-decisions` | **Implemented** | `GET /api/v1/security/policy-decisions` (Advisory `LOG_ALERT` logs) |
| **Audit History** | `/audit-history` | **Implemented** | Aggregated `GET /api/v1/security/incidents/{id}/history` audit trail |
| **System Health** | `/system-health` | **Implemented** | `GET /actuator/health` + live platform tier status |
| **Settings** | `/settings` | **Implemented** | Active runtime parameters, Keycloak PKCE client configs, and advisory mode invariant |

---

## 6. Security Invariants & Advisory Architecture

1. **Non-Intrusive Advisory Mode:**
   Aegis operates in strict `ADVISORY MODE`. Responses never perform automated blocking, rate throttling, or token revocation. The `ADVISORY MODE` indicator is permanently displayed in both the navbar and sidebar footer.
2. **Privacy-Preserving Telemetry:**
   Raw credentials and sensitive account balances are never logged to database tables. `Authorization` headers are redacted to `Bearer [REDACTED]` and request/response payloads are stored exclusively as cryptographic SHA-256 hashes.
3. **Empirical Bayesian Heuristic Confidence Scores:**
   Confidence scores ($0.00 \to 1.00$) represent empirical Bayesian heuristic weights rather than calibrated frequentist probabilities. The UI explicitly documents this distinction in tooltips and advisory banners.
