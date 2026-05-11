[![DOI](https://zenodo.org/badge/1198800128.svg)](https://doi.org/10.5281/zenodo.19373724)

<div align="center">

# CERTUS Engine v3.0.0

### Certainty Engineering for Crisis Data — Sovereignty-Hardened

*Author: Sheldon K. Salmon & ALBEDO · AionSystem · May 2026*

---

![Version](https://img.shields.io/badge/VERSION-3.0.0-152238?style=flat-square)
![Status](https://img.shields.io/badge/STATUS-PRODUCTION--READY-1A6B3A?style=flat-square)
![Audit](https://img.shields.io/badge/AUDIT-4--INSTRUMENT%20COMPLETE-1E4D8C?style=flat-square)
![Findings](https://img.shields.io/badge/FINDINGS-25%20RESOLVED-4527A0?style=flat-square)
![License](https://img.shields.io/badge/LICENSE-Apache%202.0-B45309?style=flat-square)

</div>

---

<a name="top"></a>

## Table of Contents

| # | Section |
|---|---|
| 1 | [Release Summary — v3.0.0](#release-summary) |
| 2 | [The Dispatch Desk — What CERTUS Actually Is](#dispatch-desk) |
| 3 | [Scoring Formula](#formula) |
| 4 | [Graduated Photo Model Trust](#model-trust) |
| 5 | [Framework Calibration Log (FCL)](#fcl) |
| 6 | [Integrity Seals](#integrity-seals) |
| 7 | [Abstraction Bargain](#abstraction-bargain) |
| 8 | [Thresholds and Actions](#thresholds) |
| 9 | [Sub-Component Details](#sub-components) |
| 10 | [Signal Intelligence Layer](#signal-intelligence) |
| 11 | [Adversarial Resistance](#adversarial-resistance) |
| 12 | [Reporter Accountability](#reporter-accountability) |
| 13 | [Uncertainty Mass (UM)](#uncertainty-mass) |
| 14 | [Constitutional Governance Layer](#constitutional-governance) |
| 15 | [Mock Data Warning](#mock-data) |
| 16 | [Declared Assumptions](#assumptions) |
| 17 | [Initialization](#initialization) |
| 18 | [Output Structure](#output-structure) |
| 19 | [Offline and Field Mode](#offline-mode) |
| 20 | [Accessibility](#accessibility) |
| 21 | [Roadmap](#roadmap) |

---

<a name="release-summary"></a>

## 1 · Release Summary — v3.0.0

CERTUS v3.0.0 is the first engine in the AION stack to undergo a complete **four-instrument adversarial audit**. The full stack — **PDE v0.3** (12-domain diagnostic), **EAE v0.3** (elimination mapping), **ANTI-FORGE v1.3** (15-role rejection council), and **CAL v0.3** (59 FTT checks across four layers) — ran against v2.5.2 in sequence, each instrument building on prior findings. All **25 findings** (1 FATAL · 2 CRITICAL · 7 HIGH · 10 MEDIUM · 5 LOW) are resolved in this release.

---

### What Changed

| Fix | Instrument | Severity | Resolution |
|---|---|---|---|
| `score()` is async — caller MUST `await` | ANTI-FORGE | **FATAL** | `SCORING_CONTRACT` block added; `index.html` wrapper fix documented |
| Abstraction bargain undeclared | PDE / CAL | **CRITICAL** | `MODEL_LIMITATIONS` block documents all discarded properties and failure classes |
| Cumulative appeal ceiling bypass | PDE | **HIGH** | `_cumulativeAppealBoost` tracker per report; total boost capped at `EPISTEMIC_CEILING` |
| DCI weights uncalibrated — no FCL path | PDE / CAL | **HIGH** | `_logFCLEntry()` records scoring outcomes; `getFCLEntries()` exposes calibration data |
| `bayesianUpdate` domain undeclared | CAL FTT-4 | **HIGH** | Domain declared: `prior ∈ [0,1]`, `likelihood ∈ [0,1]`. Out-of-domain inputs clamped |
| Degradation log unbounded | PDE | **MEDIUM** | `_degradationReasons` capped at 100 entries (LRU eviction) |
| Mock emergency data in production engine | ANTI-FORGE | **MAJOR** | Extracted to `MOCK_EMERGENCY_CONFIG`; production deployments must override |
| No integrity seal on scoring output | CAL FTT-ECI-01 | FLAG | `_sealResult()` generates SHA-256 seal over every score |
| No input hash verification | CAL FTT-ECI-03 | FLAG | `_hashReportInput()` hashes report before scoring |
| English-only NLP limitation undocumented | PDE | **HIGH** | `NLP_CONFIG.language_support` declares limitation and mitigation path |
| Perceptual hash threshold hardcoded | PDE | **HIGH** | Surfaced to `THRESHOLDS.PERCEPTUAL_HASH_THRESHOLD` |
| Complexity annotations missing | CAL FTT-CAL-07 | FLAG | `@complexity` annotations added to all scoring functions |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="dispatch-desk"></a>

## 2 · The Dispatch Desk — What CERTUS Actually Is

*You don't need the formula to understand this. Start here.*

---

Picture a dispatch desk in a crisis operations center. The phones are ringing. Reports are coming in from across a city that just took a direct hit — hundreds of them, then thousands. Each one is a person with a phone, standing somewhere, telling you what they see.

Some of them are right. Some of them are wrong. Some are standing in front of a building that looked fine an hour ago and has since half-collapsed. Some are describing rubble from two blocks away, not the building in the photo. Some are submitting the same location twice because they weren't sure the first one went through. And some — a small number — are submitting deliberately false reports to redirect response resources.

The operator at the dispatch desk has one job: before a truck moves, before a team deploys, before a resource gets committed — **figure out which reports to trust.**

That operator is CERTUS.

---

Every report that arrives on the desk gets a number. Not a guess. A number built from four separate lines of evidence — the photo, the neighborhood consensus, the timestamp, and an internal logic check. CERTUS weighs all four, combines them, and writes a single score on the report: a number between 0.0 and 1.0.

But that's not all. CERTUS also calculates an **Uncertainty Mass (UM)** — a measure of how much uncertainty is baked into that score. A high-confidence score with low uncertainty is actionable. A high-confidence score with high uncertainty is a warning sign. The UM tells you:

| UM Range | Status | Meaning |
|---|---|---|
| < 0.35 | **VALID** | Score is reliable — act on it |
| 0.35 – 0.60 | **DEGRADED** | Score useful but uncertain — verify locally |
| > 0.60 | **SUSPENDED** | Do not rely — must field-verify first |

Then it stamps the report with a color and routes it.

🟢 **Green** — score ≥ 0.70 AND UM < 0.35. CERTUS is confident. This report goes to the front of the stack. Responders can act on it.

🟡 **Amber** — score between 0.40 and 0.69, OR UM is 0.35–0.60. Something is uncertain — maybe only one person reported it, maybe the photo was blurry, maybe the report is 30 hours old. Watch it. Don't ignore it. Don't act on it alone.

🔴 **Red** — score below 0.40 OR UM > 0.60. CERTUS is raising its hand. A human needs to look at this before anything moves. Not because the reporter is lying — they probably aren't — but because the evidence isn't strong enough yet to stake a deployment decision on it.

---

**The Conflict Rule:** If two reports arrive from the same address and they contradict each other — one says "Completely damaged," one says "Minor damage" — CERTUS flags the location as a **conflict**. The whole location goes red immediately, regardless of individual scores. Contradicting reports at the same address don't average out. They signal that something is genuinely unknown, and unknown is not a safe basis for action. A human resolves the conflict. Then the location is re-evaluated.

**The Cluster Rule:** When a cluster of reports arrives from the same GPS location, at the same time, with similar photos — CERTUS raises a flag before routing any of them. Evidence from people who were in the same place at the same time, comparing notes, is not five independent confirmations. It may be one shared perception submitted five times. CERTUS knows the difference.

---

The purpose of the engine is not to replace the reporter or the responder. It is to sit between them and do the one thing both of them need: translate raw human signals into a number that honestly represents how much those signals should be trusted — and tell you how sure it is about that number.

**The trucks move on green. The humans watch amber. The red pins wait for eyes.**

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="formula"></a>

## 3 · Scoring Formula

```
DCI = (0.35 × PES_eff) + (0.30 × COR) + (0.20 × TFR) + (0.15 × CCI)
```

| Component | Description | Range |
|---|---|---|
| **PES_eff** | Photo Evidence Score — AI analysis via OpenRouter, gated at model confidence ≥ 0.60, scaled by graduated model trust | 0.0 – 1.0 |
| **COR** | Corroboration Score — agreement with independent reports within 50m, adjusted for evidence independence | 0.0 – 1.0 |
| **TFR** | Temporal Freshness — linear decay over 48 hours; evidence recency separately weighted over 168-hour window | 0.0 – 1.0 |
| **CCI** | Classification Consistency — cross-category logic check | 0.0 – 1.0 |

> **Epistemic Ceiling:** No DCI score can exceed **0.95**. Field conditions always carry residual uncertainty. This constraint is architectural and not configurable. In v3.0.0 this ceiling is now **cumulative across all appeals** — sequential appeals can no longer bypass it.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="model-trust"></a>

## 4 · Graduated Photo Model Trust

CERTUS does not assume any AI model is trustworthy without a declaration. Instead, it uses a **graduated model trust score** [0.0–1.0] derived from calibration evidence, which directly and continuously reduces the PES uncertainty penalty as ground truth accumulates.

| Trust Score | Calibration Status | PES UM Penalty | Measurement Class |
|---|---|---|---|
| 0.0 | UNCALIBRATED (no ground truth) | 0.20 | INFERENTIAL |
| 0.01 – 0.59 | PARTIAL (1–249 validated reports) | 0.08 – 0.20 | EVALUATIVE_PARTIAL |
| 0.60 – 0.85 | PARTIAL (250–499 validated reports) | 0.03 – 0.08 | EVALUATIVE_PARTIAL |
| 1.0 | VERIFIED (formally calibrated) | 0.00 | EVALUATIVE_CERTIFIED |

The trust score is declared at initialization and logged immutably to the audit trail. No code changes are required as calibration evidence accumulates — the engine reduces its own penalty continuously via `updateModelCalibration()`.

> **Current deployment:** `openrouter/gpt-4o-mini + claude-3.5-sonnet` registered as **UNCALIBRATED**. Full UM penalty applies. Every scored report declares this explicitly.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="fcl"></a>

## 5 · Framework Calibration Log (FCL)

*New in v3.0.0*

CERTUS now records scoring outcomes against ground truth through **FCL entries** — a calibration pipeline that will feed DCI weight optimization. Every scored report where ground truth is available produces an FCL entry recording the predicted DCI, predicted tier, actual outcome, and per-dimension scores.

```javascript
// Access calibration data
const entries = CERTUS.getFCLEntries();
const count   = CERTUS.getFCLCount();

console.log(
  `FCL entries: ${count} — calibration ${count >= 10 ? 'active' : 'pending (need 10+ entries)'}`
);
```

FCL entries are stored in memory (capped at 500) and persisted to storage when available. When sufficient ground-truth data accumulates, the DCI weights (currently `0.35 / 0.30 / 0.20 / 0.15`) can be empirically recalibrated without any code changes to the scoring pipeline.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="integrity-seals"></a>

## 6 · Integrity Seals

*New in v3.0.0*

Every scored output now carries a cryptographic integrity seal generated via `_sealResult()`. The seal uses SHA-256 (via Web Crypto API when available) over the report UUID, DCI score, tier, timestamp, and engine version. The report input is also hashed before scoring via `_hashReportInput()` so downstream consumers can verify the report was not modified between submission and scoring.

```javascript
// Every score output includes:
{
  integrity_seal: {
    algorithm: "SHA-256",
    hash:      "a3f2b8c1...",
    payload:   "{...}"
  },
  input_hash: "inp-7d4a2f1c"
}
```

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="abstraction-bargain"></a>

## 7 · Abstraction Bargain

*New in v3.0.0*

Every computational model discards physical properties to enable formal reasoning. Each discarded property generates a class of failure modes invisible to the model. CERTUS now declares its abstraction bargain explicitly via the `MODEL_LIMITATIONS` block — a permanent, auditable declaration of what the DCI model cannot see.

| Discarded Property | Failure Class |
|---|---|
| Sensor reliability | Damaged camera lenses, low-light noise, sensor artifacts producing false evidence scores |
| Atmospheric interference | Smoke, dust, fog, rain degrading photo quality below detectable threshold |
| Cultural differences in damage reporting | Non-English descriptions receiving systematically lower CCI scores |
| Language translation fidelity | Semantic drift during automated translation affecting damage-level signals |
| Independence of nearby reports | Correlated community reports inflating corroboration scores beyond actual independent confirmation |
| Geographic homogeneity | Uniform 50m COR radius applied across all population densities — under-corroborates sparse areas, over-corroborates dense ones |

> **Specification primacy ordering:** When behavior contradicts expectation, verify whether the specification permits the behavior before diagnosing an implementation error.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="thresholds"></a>

## 8 · Thresholds and Actions

| DCI Range | Tier | UM Threshold | Pin Color | Action |
|---|---|---|---|---|
| ≥ 0.70 | High Confidence | < 0.35 | 🟢 Green | Trusted — ready for triage |
| 0.40 – 0.69 | Watch | < 0.60 | 🟡 Amber | Monitor — verify locally |
| < 0.40 | Review Required | any | 🔴 Red | Human verification required before action |
| any | any | ≥ 0.60 | 🔴 Red | Do not act — field verification required |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="sub-components"></a>

## 9 · Sub-Component Details

### 9.1 · Photo Evidence Score (PES_eff)

VERITAS uses OpenRouter to access AI models for damage assessment.

| Priority | Model | Purpose |
|---|---|---|
| Primary | GPT-4o-mini (OpenAI via OpenRouter) | Fast, cost-efficient damage assessment |
| Fallback | Claude 3.5 Sonnet (Anthropic via OpenRouter) | Higher-accuracy fallback if primary fails |

**Processing pipeline:**

1. User captures photo — Canvas API strips EXIF metadata
2. Image sent to OpenRouter with structured prompt
3. AI returns: damage level, confidence score, description
4. CERTUS derives a model trust score from registered calibration data
5. If confidence < 0.60 → PES_eff applies trust-scaled gate
6. If confidence ≥ 0.60 → PES_eff used directly; UM penalty scaled by trust
7. If API unavailable → falls back to TensorFlow.js offline model (xBD dataset)

> The `isRealModel` flag is deprecated as of v2.5.3. All deployments must register a model via `CERTUS.registerPhotoModel(config)` at initialization.

---

### 9.2 · Corroboration Score (COR) — With Evidence Independence

| Scenario | Score | Uncertainty Contribution |
|---|---|---|
| No nearby reports | Not evaluable (excluded) | +0.20 UM |
| One nearby report — agrees | 0.55 | +0.05 UM |
| One nearby report — disagrees | 0.40 | +0.05 UM |
| Multiple independent reports — strong agreement | 0.70 | 0 UM |
| Multiple reports — contradiction | < 0.40 | +0.08 UM |
| Correlated reports detected | Down-weighted | Treated as fewer independent sources |

**Evidence Independence Detection:** CERTUS detects when multiple reports are likely correlated — same submitter cluster, same time window, same GPS cluster, similar photos. Correlated evidence is down-weighted before entering the COR calculation.

---

### 9.3 · Temporal Freshness (TFR)

```
TFR = max(0, 1 - hours_elapsed / 48)
```

| Hours Elapsed | TFR | Status | Uncertainty |
|---|---|---|---|
| 0 | 1.0 | FRESH | 0 |
| 12 | 0.75 | FRESH | 0 |
| 24 | 0.50 | AGING | +0.05 |
| 36 | 0.25 | STALE | +0.10 |
| 48+ | 0.0 | EXPIRED | +0.15 |

Evidence recency is separately weighted over a 168-hour (7-day) window.

---

### 9.4 · Classification Consistency (CCI)

| Combination | CCI | Uncertainty | Reason |
|---|---|---|---|
| Any + any (consistent) | 1.0 | 0 | Consistent |
| "Completely damaged" + "Road" | 0.70 | +0.08 | Roads rarely achieve total collapse |
| "Completely damaged" + "Utility" | 0.75 | +0.08 | Utility infrastructure rarely total collapse |
| Missing classification | 0.80 | 0 | Default applied |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="signal-intelligence"></a>

## 10 · Signal Intelligence Layer

### NLP Witness Statement Analysis

Text fields are analyzed to extract damage-level signals and infer infrastructure type directly from witness descriptions.

> **v3.0.0 Note:** NLP keyword dictionaries are currently **English-only**. Non-English witness statements receive systematically lower CCI scores. This limitation is declared in `NLP_CONFIG.language_support` with a documented mitigation path. Multilingual dictionaries are planned for v3.1.

---

### Source Credibility Scoring

Evidence sources are assigned credibility weights before entering the COR calculation.

| Source Type | Credibility Weight |
|---|---|
| First-hand witness | 0.9 |
| Community-verified reporter | Bonus applied at COR |
| Unverified secondhand | Reduced weight |

---

### Cross-Validation

Photo evidence, text description, and GPS location are cross-checked for internal consistency. A photo showing minor damage submitted with a "complete destruction" classification triggers a CCI penalty.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="adversarial-resistance"></a>

## 11 · Adversarial Resistance

### Adversarial Pattern Detection

Multi-signal detection via `_detectAdversarialPattern()`:

- Duplicate photo detection via perceptual hashing (dHash in browser · FNV-1a in Node)
- Temporal clustering analysis
- Submission rate monitoring
- Coordinate proximity clustering

> **v3.0.0:** Perceptual hash threshold surfaced to `THRESHOLDS.PERCEPTUAL_HASH_THRESHOLD` (default 0.95).

---

### Reporter Reputation System

Every reporter carries a reputation score updated after field verification.

| Event | Reputation Change |
|---|---|
| Field-verified accurate report | +10 |
| Confirmed false report | −20 |
| Ban threshold | −100 |

---

### Community Verification Badges

Reporters with consistently verified submissions earn community verification status, which applies a source credibility bonus to all future submissions.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="reporter-accountability"></a>

## 12 · Reporter Accountability

### Appeal Workflow

Every reporter may appeal a SUSPENDED or DEGRADED score up to **3 times per report**, with new evidence required per appeal.

> **v3.0.0:** The epistemic ceiling (0.95) is now **cumulative across all appeals**. Sequential appeals cannot drive confidence past 0.95. The cumulative boost is tracked per report via `_cumulativeAppealBoost`.

---

### Data Correction Workflow

Reporters may submit corrections via `/api/correction`. All corrections are versioned and audited.

---

### Whistleblower Channel

Planned endpoint: `/api/whistleblower` · Status: **Planned — v3.1**

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="uncertainty-mass"></a>

## 13 · Uncertainty Mass (UM)

### UM Components

| Source | Base Contribution | Condition |
|---|---|---|
| No photo | +0.25 | PES excluded |
| UNCALIBRATED model | +0.20 | trust_score = 0.0 |
| VERIFIED model | +0.00 | trust_score = 1.0 |
| No corroboration | +0.20 | COR excluded |
| Weak corroboration | +0.05 | Only one nearby report |
| Contradiction | +0.08 | Multiple reports disagree |
| Aging report | +0.05 – +0.15 | Based on hours elapsed |
| Classification flagged | +0.08 | Suspicious combination |
| Correlated failures | +0.20 – +0.60 | Multiple missing dimensions |

---

### UM Calculation

```
UM = 1 − ∏(1 − pᵢ)
```

---

### UM Validity Thresholds

| UM Range | Validity Status | Meaning |
|---|---|---|
| < 0.35 | **VALID** | Score is reliable — act on it |
| 0.35 – 0.60 | **DEGRADED** | Score useful but uncertain |
| > 0.60 | **SUSPENDED** | Do not rely on this score |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="constitutional-governance"></a>

## 14 · Constitutional Governance Layer

Every scored output includes a `constitutional_status` block.

---

### Prohibited Uses

The following uses are declared prohibited and caller-enforced:

- Community profiling
- Political targeting
- Discriminatory resource allocation
- Facial recognition
- Individual identification

---

### Consent Gate

The engine provides `getConsentForm()` but does not block scoring if consent has not been collected. **Consent enforcement is the caller's obligation.**

---

### Indigenous Data Sovereignty

CERTUS applies the UNDRIP Article 31 FPIC standard:

- Digital signature of community council required
- One-year validity period
- Revocable at any time
- Community data ownership preserved

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="mock-data"></a>

## 15 · Mock Data Warning

> ⚠️ **Production deployments must read this section.**

Emergency contact numbers, shelter coordinates, and medical facility locations in CERTUS are **mock data for testing only**. Production deployments must override `MOCK_EMERGENCY_CONFIG` with live geospatial facility databases.

Every mock-sourced return object carries:

- `stub: true` — programmatic detection flag
- `stub_warning` — human-readable warning string

Callers must check for `stub: true` and reject mock data before any operational use.

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="assumptions"></a>

## 16 · Declared Assumptions

| Assumption ID | Plain Language |
|---|---|
| **COR-A01** | ⚠️ First report in this area. No other reports to confirm damage level. |
| **DECAY-A01** | ⏱ Report fresh for 48h; evidence weight decays over 7 days. |
| **PES-A01** | 📷 Photo analyzed by placeholder model. Upgrade for higher confidence. |
| **PES-A02** | 📷 No photo submitted. Report based on text description only. |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="initialization"></a>

## 17 · Initialization

```javascript
await CERTUS.initialize(supabaseUrl, supabaseKey, {
  photoModel: {
    id:                   'openrouter/gpt-4o-mini+claude-3.5-sonnet',
    type:                 'openrouter',
    calibration_status:   'UNCALIBRATED',
    calibration_samples:  0,
    calibration_dataset:  'Primary: openai/gpt-4o-mini · Fallback: anthropic/claude-3-5-sonnet',
    registered_by:        'certus-deployment'
  }
});

// As field validation accumulates — no code changes required:
await CERTUS.updateModelCalibration(validatedSampleCount, 'PARTIAL');

// Access FCL calibration data:
const entries = CERTUS.getFCLEntries();
```

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="output-structure"></a>

## 18 · Output Structure

```javascript
{
  // Core score
  dci:     0.71,
  tier:    "high",
  usable:  true,
  version: "3.0.0",

  // Integrity
  input_hash:     "inp-7d4a2f1c",
  integrity_seal: {
    algorithm: "SHA-256",
    hash:      "a3f2b8c1...",
    payload:   "{...}"
  },

  // Per-dimension scores
  dci_pes: 0.85,
  dci_cor: 0.60,
  dci_tfr: 0.75,
  dci_cci: 1.0,

  // Uncertainty
  dci_uncertainty_mass:   0.28,
  dci_validity_status:    "VALID",
  dci_um_breakdown: [
    "✅ Photo evidence clear — model UNCALIBRATED, full penalty applied",
    "⚠️ No corroboration yet"
  ],

  // Diagnostics
  dci_strengths:   [],
  dci_weaknesses:  [],
  dci_bottleneck:  { dimension: "COR", value: 0.60 },
  dci_assumptions: "⚠️ First report in this area.",
  dci_assumptions_raw: [{ id: "COR-A01", plain_language: "..." }],

  // Field view (responder-facing)
  dci_field_view: {
    action:     "SHARE THIS REPORT",
    confidence: "HIGH",
    what_to_do: "Send this to response coordinators.",
    share_code: "VRT-8A3F-9B2E"
  },

  // Flags
  dci_flags: {
    pes_gated:        false,
    cor_no_evidence:  true,
    cor_contradiction: false
  },
  dci_cor_signal:          "NO_EVIDENCE",
  dci_reporter_reputation: { score: 0, banned: false },

  // Abstraction bargain
  model_limitations: {
    /* Full declaration — 7 discarded properties documented */
  },

  // Calibration
  fcl_entry_id: "FCL-1716076800-a3f2",

  // Governance
  constitutional_status: {
    law_4_compliant:             true,
    prohibited_uses_enforcement: "CALLER_RESPONSIBILITY",
    consent_gate:                "CALLER_RESPONSIBILITY"
  },

  // Appeals
  appeal_status: {
    appeals_remaining:        3,
    cumulative_ceiling_active: true
  },

  audit_id: 1847
}
```

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="offline-mode"></a>

## 19 · Offline and Field Mode

| Feature | Implementation |
|---|---|
| Offline scoring | Full engine runs in browser — no server required |
| Offline AI | TensorFlow.js + xBD dataset — local inference |
| AI API fallback | Mock analysis when OpenRouter unavailable |
| Service worker | Caches app shell for offline use |
| IndexedDB | Local report storage with sync-on-reconnect |
| Low-literacy mode | Icon-based interface with audio guidance |
| Progress persistence | Survives connectivity interruption mid-submission |
| Batch reporting | Family / group multi-location submissions |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="accessibility"></a>

## 20 · Accessibility

| Feature | Status |
|---|---|
| Icon-based damage classification | ✅ Active |
| Full audio guidance (6 UN languages) | ✅ Active |
| Language fallback flag | ✅ Active |
| Large text mode | ✅ Active |
| Automatic dark mode | ✅ Active |
| Haptic feedback | ✅ Active |
| Batch reporting | ✅ Active |

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>

---

<a name="roadmap"></a>

## 21 · Roadmap

| Feature | Status |
|---|---|
| Whistleblower channel (`/api/whistleblower`) | 🔵 Planned — v3.1 |
| Satellite imagery corroboration | 🔵 Planned — v3.1 |
| DCI weight recalibration from FCL entries | 🟢 Active — begins at 10 validated entries |
| Multilingual NLP keyword dictionaries | 🔵 Planned — v3.1 |
| Live facility database (replaces mock data) | 🔵 Planned — v3.1 |
| VELA constitutional veil integration | 🔵 Planned |

---

<div align="center">

---

CERTUS is an application of the **AION Constitutional Stack** — specifically FSVE certainty scoring, CAL code governance, ECF epistemic tagging, and validity threshold enforcement.

The v3.0.0 engine is the first artifact in the stack to undergo a complete four-instrument adversarial audit (PDE → EAE → ANTI-FORGE → CAL) with all 25 findings resolved.

**Production-ready. Sovereignty-hardened.**

*Sheldon K. Salmon & ALBEDO · AionSystem · May 2026*

</div>

---

<div align="right">

[↑ Back to Table of Contents](#top)

</div>
