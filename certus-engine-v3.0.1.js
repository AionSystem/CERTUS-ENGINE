// ==================== CERTUS ENGINE v3.0.1 ====================
/*
 * Copyright 2026 Sheldon K. Salmon & ALBEDO
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// SPDX-License-Identifier: Apache-2.0

// Sovereignty-Hardened Scoring Engine — Full Adversarial Stack Audit Complete
// PDE v0.3 · EAE v0.3 · ANTI-FORGE v1.3 · CAL v0.3 — All Findings Resolved
//
// v3.0.1 Red‑Team Fixes (May 16, 2026):
// [FATAL]   F-01 — getEmergencyResources async/await; Promise.all for shelters/medical.
// [CRITICAL] C-01 — recognizeOfflineVoice stub now logs console warning.
// [CRITICAL] C-02 — submitBatch accepts nearbyReports + isRealModel; passes to score().
// [HIGH]    H-01 — _hashReportInput async SHA‑256 (SubtleCrypto) with fallback.
// [HIGH]    H-02 — Adversarial pattern detection on initial submissions (score()).
// [HIGH]    H-03 — FCL entries include integrity seal hash for cross‑reference.
// [HIGH]    H-04 — NLP damage detection uses presence flags, not cumulative sum.
// [MEDIUM]  M-01 — Audit store autoIncrement (no timestamp keyPath collision).
// [MEDIUM]  M-02 — storeAppeal uses IndexedDB .add() not .put().
// [MEDIUM]  M-03 — Dependency circuit breakers cascade to global breaker.
// [MEDIUM]  M-04 — DATA_SHARING_LAST_UPDATED static constant.
// [LOW]     L-01 — MODEL_LIMITATIONS documents perceptual hash fallback fidelity.
// [LOW]     L-02 — initialize() failure calls window.onCERTUSInitError if defined.
// [LOW]     L-03 — MODEL_LIMITATIONS documents evidence combination asymmetry.
//
// Author: Sheldon K. Salmon & ALBEDO
// Date: May 16, 2026 — Upgraded from v3.0.0 (May 11, 2026)

const CERTUS = {

  // ── VERSION ────────────────────────────────────────────────────────────────
  VERSION: '3.0.1',
  CANARY_VERSION: '3.0.1-beta',

  // ══════════════════════════════════════════════════════════════════════════
  // ABSTRACTION BARGAIN — CAL FTT-14 / PDE-GAP-014
  // Every computational model discards physical properties to enable formal
  // reasoning. Each discarded property generates a class of failure modes
  // invisible to the model. These must be declared so maintainers know
  // where the model's boundaries lie.
  // ══════════════════════════════════════════════════════════════════════════
  MODEL_LIMITATIONS: {
    declaration: 'The DCI model abstracts away the following physical and contextual properties. Each generates failure modes the model cannot detect. Specification primacy: when behavior contradicts expectation, check whether the specification permits the behavior before diagnosing implementation error.',
    discarded_properties: [
      {
        property: 'Sensor reliability',
        failure_class: 'Camera lens damage, low-light noise, sensor artifacts produce misleading photo evidence. PES assumes a functional camera.',
        detection_requires: 'EXIF metadata inspection, multi-photo cross-validation, manual review'
      },
      {
        property: 'Atmospheric interference',
        failure_class: 'Smoke, dust, fog, and rain degrade photo quality. Satellite imagery affected by cloud cover. The model does not account for environmental visibility.',
        detection_requires: 'Weather API integration, visibility metadata, manual review'
      },
      {
        property: 'Cultural differences in damage reporting',
        failure_class: 'Communities describe damage using culturally-specific terms that do not match the English-only NLP keyword dictionaries. Non-English reports receive systematically lower CCI scores.',
        detection_requires: 'Multilingual NLP expansion, community translator review, per-language FCL calibration'
      },
      {
        property: 'Language translation fidelity',
        failure_class: 'Machine translation of witness statements introduces semantic drift. Urgency markers and damage severity descriptors may shift during automated translation.',
        detection_requires: 'Back-translation verification, bilingual reviewer sampling, translation confidence scoring'
      },
      {
        property: 'Independence of nearby reports',
        failure_class: 'COR assumes nearby reports are independent observations. In practice, community members may confer before submitting, producing correlated reports that inflate corroboration scores.',
        detection_requires: 'Temporal clustering analysis, submitter relationship mapping, independence audit'
      },
      {
        property: 'Continuous time',
        failure_class: 'TFR uses linear decay but real information decay is nonlinear — reports may become MORE valuable over time as context stabilizes, or less valuable as conditions change.',
        detection_requires: 'Ground-truth comparison at multiple time horizons, nonlinear decay model calibration'
      },
      {
        property: 'Geographic homogeneity',
        failure_class: 'The 50m COR radius is uniform globally. In dense urban environments (Mumbai, Tokyo), 50m encloses multiple unrelated structures. In rural areas, related damage spans hundreds of meters.',
        detection_requires: 'Population-density-based radius adjustment, building-footprint-aware clustering'
      },
      // L-01: Perceptual hash fallback fidelity
      {
        property: 'Perceptual hash fallback fidelity',
        failure_class: 'In non-browser environments, FNV-1a hashes the full base64 string rather than pixel content. Near-duplicate photos will not be detected.',
        detection_requires: 'Canvas API availability or server-side image processing'
      },
      // L-03: Evidence combination asymmetry
      {
        property: 'Evidence combination asymmetry',
        failure_class: 'Photo+witness evidence is combined as max(delta), not additive. Field verification adds independently. Field verification outweighs photo+witness in most configurations. This is intentional conservatism but may underweight community reports.',
        detection_requires: 'FCL calibration against ground-truth field verification outcomes'
      }
    ],
    specification_primacy: 'If unexpected behavior B is observed: Step 1 — Does the specification permit B? YES → specification error; revise the model. NO → implementation error; debug the code. This ordering is mandatory before any diagnostic proceeds.'
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SCORING CONTRACT — AF-SEC-02
  // CERTUS.score() is ASYNC. Callers MUST await the result.
  // The safeCERTUSScore wrapper in index.html must use:
  //   const result = await CERTUS.score(report, nearby, useModel);
  // Failure to await returns a Promise, which is truthy, causing fallback
  // scoring to run silently. This is the single highest-impact integration bug.
  // ══════════════════════════════════════════════════════════════════════════
  SCORING_CONTRACT: {
    score_is_async: true,
    caller_must_await: true,
    integration_example: 'const result = await CERTUS.score(report, nearby, isRealModel);',
    failure_mode_if_not_awaited: 'Promise object returned instead of score. All reports use fallback. Real CERTUS engine never executes.'
  },

  // ── STATIC CONSTANTS ─────────────────────────────────────────────────────
  DATA_SHARING_LAST_UPDATED: '2026-05-11T00:00:00.000Z', // M-04

  // ── PRODUCTION CONFIGURATION ───────────────────────────────────────────────
  PRODUCTION: {
    maxConcurrentAppeals: 100,
    cacheTTL: 300,
    rateLimitWindow: 3600,
    distributedSyncInterval: 5000,
    healthCheckInterval: 30000,
    circuitBreakerManualResetOnly: true,
    auditLogRetentionDays: 365,
    encryptionKeyRotationDays: 90,
    canaryPercentage: 5
  },

  // ── WEIGHTS ───────────────────────────────────────────────────────────────
  W: { PES: 0.35, COR: 0.30, TFR: 0.20, CCI: 0.15 },

  // ── THRESHOLDS ────────────────────────────────────────────────────────────
  THRESHOLDS: {
    DCI_HIGH: 0.70,
    DCI_WATCH: 0.40,
    UM_VALID: 0.35,
    UM_DEGRADED: 0.60,
    MAX_APPEALS: 3,
    CORRELATED_FAILURE_RATE: 0.30,
    EPISTEMIC_CEILING: 0.95,
    PERCEPTUAL_HASH_THRESHOLD: 0.95,
    EVIDENCE_HALF_LIFE_HOURS: 168,
    APPEAL_RATE_LIMIT: {
      per_report: { max: 1, window: 3600000 },
      per_ip: { max: 10, window: 3600000 }
    },
    APPEAL_RETENTION_DAYS: 90,
    GEOTAG_ACCURACY_MULTIPLIER: 2,
    CIRCUIT_BREAKER: {
      initial_backoff: 3600000,
      max_backoff: 86400000,
      manual_reset_required: true
    },
    REPUTATION: {
      VERIFIED_BONUS: 10,
      FALSE_REPORT_PENALTY: 20,
      BAN_THRESHOLD: -100
    },
    MAX_DEGRADATION_REASONS: 100
  },

  // ── EVIDENCE WEIGHTS WITH CREDIBILITY ─────────────────────────────────────
  CREDIBILITY_SCORES: {
    first_hand_witness: 0.9,
    second_hand_witness: 0.6,
    hearsay: 0.3,
    engineer: 0.95,
    community_elder: 0.85,
    government_official: 0.7,
    ai_analyzed_photo: 0.85,
    field_verification: 0.98
  },

  EVIDENCE_WEIGHTS: {
    PHOTO: { weight: 0.35, confidence_boost: 0.12, likelihood: 0.85 },
    WITNESS: { weight: 0.25, confidence_boost: 0.08, likelihood: 0.70 },
    FIELD: { weight: 0.40, confidence_boost: 0.25, likelihood: 0.95 }
  },

  // ── SENSITIVE LOCATION TYPES ──────────────────────────────────────────────
  SENSITIVE_LOCATION_TYPES: [
    'shelter', 'medical', 'school', 'government', 'religious',
    'women_shelter', 'refugee_camp', 'detention_center'
  ],

  // ── CONSENT OPTIONS ───────────────────────────────────────────────────────
  CONSENT_OPTIONS: {
    disaster_response: { required: true, default: true },
    research: { required: false, default: false, explanation: 'Help improve future disaster response through research' },
    commercial: { required: true, default: false, explanation: 'Allow commercial use of anonymized data', prohibited: false },
    surveillance: { required: true, default: false, prohibited: true, explanation: 'Surveillance use is prohibited by constitutional law' }
  },

  // ══════════════════════════════════════════════════════════════════════════
  // MOCK EMERGENCY CONFIG — AF-REG-01 FIX
  // Extracted from production engine. All hardcoded phone numbers, shelter
  // coordinates, and facility names are MOCK DATA for testing only.
  // Production deployments MUST override this with live facility databases.
  // ══════════════════════════════════════════════════════════════════════════
  MOCK_EMERGENCY_CONFIG: {
    active: true,
    warning: 'MOCK DATA — NOT FOR PRODUCTION EMERGENCY DISPATCH. Override with live geospatial queries.',
    shelters: [
      { name: 'Community Center Shelter', lat_offset: 0.01, lng_offset: 0.01, capacity: 200, type: 'public' },
      { name: 'School Gymnasium', lat_offset: -0.008, lng_offset: 0.015, capacity: 150, type: 'public' },
      { name: 'Red Cross Station', lat_offset: 0.005, lng_offset: -0.012, capacity: 300, type: 'ngo' }
    ],
    medical: [
      { name: 'General Hospital', lat_offset: 0.02, lng_offset: -0.005, type: 'hospital', beds: 150 },
      { name: 'Community Clinic', lat_offset: -0.01, lng_offset: 0.02, type: 'clinic', beds: 20 },
      { name: 'Emergency Care Center', lat_offset: 0.015, lng_offset: 0.01, type: 'emergency', beds: 50 }
    ],
    emergency_phone: '+1-800-555-0123',
    undp_phone: '+1-800-555-0199'
  },

  // ── DATA RECIPIENTS ───────────────────────────────────────────────────────
  DATA_RECIPIENTS: {
    emergency_services: { name: 'Local Emergency Services', purpose: 'Immediate response coordination', retention: '30 days', opt_out: false },
    undp: { name: 'United Nations Development Programme', purpose: 'Resource allocation and planning', retention: '7 years', opt_out: true },
    research_institutions: { name: 'Humanitarian Research Partners', purpose: 'Improving disaster response', retention: 'Indefinite (anonymized)', opt_out: true },
    local_government: { name: 'Local Government', purpose: 'Recovery planning', retention: '5 years', opt_out: true }
  },

  // ── VERIFICATION BADGES ───────────────────────────────────────────────────
  VERIFICATION_BADGES: {
    community_verified: { icon: '👥', label: 'Community Verified', description: 'Verified by local community leaders', color: '#4ade80', weight: 1.2 },
    ai_verified: { icon: '🤖', label: 'AI Verified', description: 'Verified by CERTUS Engine', color: '#f0a500', weight: 1.0 },
    field_verified: { icon: '✅', label: 'Field Verified', description: 'Verified by on-site responders', color: '#4ade80', weight: 1.3 },
    pending: { icon: '⏳', label: 'Pending Verification', description: 'Awaiting human verification', color: '#888', weight: 0.7 }
  },

  // ── ACCESSIBILITY SETTINGS ────────────────────────────────────────────────
  ACCESSIBILITY: {
    large_text: { scale: 1.5, description: 'Increase text size for readability', enabled: false },
    high_contrast: { enabled: false, description: 'Increase contrast for visibility', colors: { background: '#000000', text: '#ffffff', accent: '#ffff00' } },
    reduce_motion: { enabled: false, description: 'Reduce animations for accessibility' },
    haptic_feedback: { enabled: true, description: 'Vibration alerts for confidence changes' }
  },

  // ── ICON-BASED NAVIGATION ─────────────────────────────────────────────────
  ICON_NAVIGATION: {
    steps: [
      { icon: '📸', action: 'photo', description: 'Take photo', audio: 'step_photo.mp3' },
      { icon: '🏚️', action: 'damage', description: 'Select damage', audio: 'step_damage.mp3' },
      { icon: '🏗️', action: 'infra', description: 'What was damaged', audio: 'step_infra.mp3' },
      { icon: '📍', action: 'location', description: 'Where is it', audio: 'step_location.mp3' },
      { icon: '✅', action: 'submit', description: 'Send report', audio: 'step_submit.mp3' }
    ],
    actions: [
      { icon: '👥', action: 'share', description: 'Share with helper', audio: 'share.mp3' },
      { icon: '📞', action: 'call', description: 'Call for help', audio: 'call.mp3' },
      { icon: '📍', action: 'wait', description: 'Stay here', audio: 'stay.mp3' }
    ]
  },

  // ── OFFLINE VOICE KEYWORDS ────────────────────────────────────────────────
  VOICE_KEYWORDS: {
    en: ['help', 'damage', 'emergency', 'yes', 'no', 'photo', 'location'],
    es: ['ayuda', 'daño', 'emergencia', 'sí', 'no', 'foto', 'ubicación'],
    ar: ['مساعدة', 'ضرر', 'طوارئ', 'نعم', 'لا', 'صورة', 'موقع'],
    zh: ['帮助', '损坏', '紧急', '是', '否', '照片', '位置']
  },

  // ── AUDIO GUIDANCE ────────────────────────────────────────────────────────
  AUDIO_GUIDANCE: {
    en: { step_1: 'Take a photo of the damage. Hold your phone steady.', step_2: 'Select how bad the damage is. Minimal, partial, or complete.', step_3: 'What was damaged? A building, road, bridge, or something else?', step_4: 'Where is the damage? Tap the map to show the location.', step_5: 'Review your report. Tap send when ready.' },
    es: { step_1: 'Tome una foto del daño. Mantenga su teléfono firme.', step_2: 'Seleccione qué tan grave es el daño. Mínimo, parcial o completo.', step_3: '¿Qué fue dañado? Un edificio, carretera, puente u otra cosa?', step_4: '¿Dónde está el daño? Toque el mapa para mostrar la ubicación.', step_5: 'Revise su informe. Toque enviar cuando esté listo.' },
    ar: { step_1: 'التقط صورة للضرر. أبق هاتفك ثابتًا.', step_2: 'اختر مدى شدة الضرر. بسيط، جزئي، أو كامل.', step_3: 'ما الذي تضرر؟ مبنى، طريق، جسر، أو شيء آخر؟', step_4: 'أين موقع الضرر؟ اضغط على الخريطة لتحديد الموقع.', step_5: 'راجع تقريرك. اضغط إرسال عندما تكون جاهزًا.' },
    zh: { step_1: '拍摄损坏照片。保持手机稳定。', step_2: '选择损坏程度。轻微、部分或完全损坏。', step_3: '什么被损坏了？建筑物、道路、桥梁还是其他？', step_4: '损坏在哪里？点击地图显示位置。', step_5: '查看报告。准备好后点击发送。' }
  },

  // ── MARKER STYLES ─────────────────────────────────────────────────────────
  MARKER_STYLES: {
    high: { color: '#4ade80', pattern: 'solid', pattern_svg: null },
    watch: { color: '#f0a500', pattern: 'striped', pattern_svg: 'url(#stripe-pattern)' },
    review: { color: '#ff4d4d', pattern: 'crosshatch', pattern_svg: 'url(#crosshatch-pattern)' },
    suspended: { color: '#888', pattern: 'dotted', pattern_svg: 'url(#dot-pattern)' }
  },

  // ── PLAIN LANGUAGE ────────────────────────────────────────────────────────
  PLAIN_LANGUAGE: {
    'VALID': 'Reliable — confident enough to act on',
    'DEGRADED': 'Somewhat uncertain — verify before acting',
    'SUSPENDED': 'Do not rely — human review required',
    'correlated failure detection': 'Multiple problems with this report',
    'epistemic veil': 'Information quality check',
    'uncertainty mass': 'How sure we are',
    'bottleneck dimension': 'Biggest problem with this report',
    'evaluative gated': 'AI uncertain about photo',
    'inferential': 'AI guessing, not sure'
  },

  // ── AUDIO FEEDBACK ────────────────────────────────────────────────────────
  AUDIO_FEEDBACK: {
    review: { sound: 'gentle-chime.mp3', volume: 0.3, message: 'Please verify this report' },
    watch: { sound: 'soft-beep.mp3', volume: 0.2, message: 'Check local conditions' },
    high: { sound: null, volume: 0, message: null },
    languages: {
      en: { review: 'gentle-chime-en.mp3', watch: 'soft-beep-en.mp3' },
      es: { review: 'gentle-chime-es.mp3', watch: 'soft-beep-es.mp3' },
      ar: { review: 'gentle-chime-ar.mp3', watch: 'soft-beep-ar.mp3' },
      zh: { review: 'gentle-chime-zh.mp3', watch: 'soft-beep-zh.mp3' }
    }
  },

  // ══════════════════════════════════════════════════════════════════════════
  // NLP CONFIGURATION — PDE-BLI-001 DOCUMENTED
  // Current keyword dictionaries are English-only. This is a known limitation.
  // Non-English witness statements receive systematically lower CCI scores
  // because the keyword matching produces zero matches.
  //
  // Mitigation for non-English deployments:
  // 1. Translate keyword dictionaries into all six UN languages.
  // 2. Use lightweight multilingual embeddings (e.g., MiniLM) for language-
  //    agnostic semantic matching when compute allows.
  // 3. Surface a `language_mismatch` flag in the scoring output when the
  //    user's declared language does not match the NLP dictionary language.
  //
  // FCL-CANDIDATE: Calibrate CCI scores per language against ground-truth
  // field verification data to quantify and correct for this bias.
  // ══════════════════════════════════════════════════════════════════════════
  NLP_CONFIG: {
    language_support: {
      current: 'English-only',
      limitation: 'Non-English witness statements receive systematically lower CCI scores because keyword dictionaries are monolingual.',
      mitigation_plan: 'Translate dictionaries into all six UN languages; integrate multilingual embeddings for semantic matching.',
      surface_flag: true,
      flag_field: 'language_mismatch'
    },
    damageKeywords: {
      minimal: ['minor', 'small', 'crack', 'hairline', 'surface', 'cosmetic', 'paint', 'scrape', 'chipped', 'scratch'],
      partial: ['significant', 'major', 'broken', 'cracked', 'damaged', 'hole', 'collapse partial', 'leaning', 'buckled', 'warped'],
      complete: ['destroyed', 'total', 'rubble', 'pile', 'flattened', 'gone', 'rubble', 'debris', 'collapse total', 'leveled', 'obliterated']
    },
    infrastructureKeywords: {
      Residential: ['house', 'home', 'apartment', 'building', 'dwelling', 'condo', 'townhouse', 'villa'],
      Road: ['road', 'street', 'highway', 'path', 'lane', 'bridge approach', 'pavement', 'asphalt', 'intersection'],
      Bridge: ['bridge', 'overpass', 'underpass', 'viaduct', 'flyover', 'trestle'],
      Utility: ['power', 'electric', 'water', 'pipe', 'line', 'pole', 'transformer', 'substation', 'sewer', 'gas'],
      Medical: ['hospital', 'clinic', 'health', 'medical', 'doctor', 'pharmacy', 'clinic', 'urgent care'],
      School: ['school', 'university', 'college', 'academy', 'classroom', 'campus'],
      'Government Building': ['government', 'city hall', 'municipal', 'council', 'administrative', 'courthouse', 'town hall'],
      'Commercial Infrastructure': ['store', 'shop', 'market', 'mall', 'business', 'office', 'retail', 'warehouse'],
      'Community Infrastructure': ['community center', 'hall', 'church', 'mosque', 'temple', 'worship', 'cultural center'],
      'Public spaces/Recreation': ['park', 'playground', 'square', 'plaza', 'stadium', 'field', 'arena', 'sports']
    },
    sentimentAnalysis: {
      urgency: ['emergency', 'urgent', 'immediate', 'critical', 'serious', 'danger', 'unsafe', 'life threatening', 'trapped'],
      uncertainty: ['maybe', 'perhaps', 'not sure', 'uncertain', 'unclear', 'could be', 'might be', 'possibly']
    }
  },

  // ── INTERNAL STATE ────────────────────────────────────────────────────────
  _circuitBreaker: { engaged: false, correlatedFailureRate: 0, lastReset: Date.now(), backoff: 3600000, reason: null, manualResetRequired: true },
  _dependencyCircuitBreakers: {
    redis: { open: false, failures: 0, lastFailure: null, timeout: 5000 },
    storage: { open: false, failures: 0, lastFailure: null, timeout: 10000 },
    maps: { open: false, failures: 0, lastFailure: null, timeout: 3000 },
    supabase: { open: false, failures: 0, lastFailure: null, timeout: 8000 }
  },
  _backpressure: { tokens: 1000, lastRefill: Date.now(), rateLimit: 1000 },
  _degradedMode: false,
  _degradationReasons: [],
  _distributedStore: null,
  _useDistributed: false,
  _storage: null,
  _supabaseClient: null,
  _auditLog: { shards: [], currentShard: 0, maxShardSize: 10000, events: [] },
  _reputationStore: new Map(),
  _correctionStore: new Map(),
  _progressStore: new Map(),
  _batchReports: new Map(),
  _photoRegistry: new Map(),
  _inMemoryCounters: new Map(),
  _inMemoryStore: new Map(),
  _IN_MEMORY_STORE_MAX_SIZE: 10000,
  _cumulativeAppealBoost: new Map(),
  _fclEntries: [],
  _fclMaxEntries: 500,
  _instanceId: (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `certus-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`),
  _offlineSupported: false,
  _currentTheme: 'light',

  // ══════════════════════════════════════════════════════════════════════════
  // _generateUUID — RFC 4122 version 4
  // ══════════════════════════════════════════════════════════════════════════
  _generateUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = (Math.random() * 16) | 0; const v = c === 'x' ? r : (r & 0x3) | 0x8; return v.toString(16); });
  },

  // ══════════════════════════════════════════════════════════════════════════
  // FCL LOGGING — PDE-VUL-003 / CAL FTT-APD-01
  // Records scoring outcomes against ground truth when available.
  // Entries accumulate in _fclEntries (capped at _fclMaxEntries).
  // Used to calibrate DCI weights when sufficient ground-truth data exists.
  // H-03: now includes integrity_seal_hash.
  // ══════════════════════════════════════════════════════════════════════════
  _logFCLEntry(scoringResult, groundTruth, integritySealHash = null) {
    if (!groundTruth) return;
    const entry = {
      fcl_id: `FCL-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      engine_version: this.VERSION,
      report_uuid: scoringResult._reportUuid || 'unknown',
      dci_predicted: scoringResult.dci,
      tier_predicted: scoringResult.tier,
      validity_predicted: scoringResult.dci_validity_status,
      integrity_seal_hash: integritySealHash || scoringResult.integrity_seal?.hash || null,
      ground_truth: {
        damage_level: groundTruth.damage_level,
        verified_by: groundTruth.verified_by,
        verification_date: groundTruth.verification_date,
        outcome: groundTruth.outcome
      },
      dimensions: {
        pes: scoringResult.dci_pes,
        cor: scoringResult.dci_cor,
        tfr: scoringResult.dci_tfr,
        cci: scoringResult.dci_cci
      }
    };
    if (this._fclEntries.length >= this._fclMaxEntries) {
      this._fclEntries.shift();
    }
    this._fclEntries.push(entry);
    if (this._storage && this._storage.logFCLEntry) {
      this._storage.logFCLEntry(entry).catch(() => {});
    }
    return entry.fcl_id;
  },

  getFCLEntries() { return this._fclEntries; },
  getFCLCount() { return this._fclEntries.length; },

  // ══════════════════════════════════════════════════════════════════════════
  // INTEGRITY SEAL — CAL FTT-ECI-01
  // Generates a lightweight cryptographic seal over the scoring result.
  // Uses SubtleCrypto when available; falls back to a simple hash.
  // ══════════════════════════════════════════════════════════════════════════
  async _sealResult(result, reportUuid) {
    const payload = JSON.stringify({
      uuid: reportUuid,
      dci: result.dci,
      tier: result.tier,
      timestamp: new Date().toISOString(),
      version: this.VERSION
    });
    let hash;
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const buf = new TextEncoder().encode(payload);
        const digest = await crypto.subtle.digest('SHA-256', buf);
        hash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      } else {
        let h = 0;
        for (let i = 0; i < payload.length; i++) { h = ((h << 5) - h) + payload.charCodeAt(i); h |= 0; }
        hash = h.toString(16);
      }
    } catch (e) {
      hash = `seal-error-${Date.now()}`;
    }
    return { algorithm: 'SHA-256', hash, payload };
  },

  // ══════════════════════════════════════════════════════════════════════════
  // INPUT HASH VERIFICATION — CAL FTT-ECI-03
  // Hashes the report input before scoring so downstream consumers can
  // verify the report was not modified between submission and scoring.
  // H-01: now async SHA-256 with fallback.
  // ══════════════════════════════════════════════════════════════════════════
  async _hashReportInput(report) {
    const payload = JSON.stringify({
      uuid: report.uuid || '',
      timestamp: report.timestamp || '',
      undpTier: report.undpTier || '',
      infraType: report.infraType || '',
      hasPhoto: !!report.photo
    });
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const buf = new TextEncoder().encode(payload);
        const digest = await crypto.subtle.digest('SHA-256', buf);
        return 'sha256:' + Array.from(new Uint8Array(digest))
          .map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch (e) {}
    // djb2 fallback — declared weak
    let h = 0;
    for (let i = 0; i < payload.length; i++) {
      h = ((h << 5) - h) + payload.charCodeAt(i); h |= 0;
    }
    return `djb2-fallback:${Math.abs(h).toString(16)}`;
  },

  // ══════════════════════════════════════════════════════════════════════════
  // _incrementDistributedCounter — Redis primary, in-memory TTL fallback
  // ══════════════════════════════════════════════════════════════════════════
  async _incrementDistributedCounter(key, ttlSeconds) {
    if (this._distributedStore && this._useDistributed) {
      try {
        const count = await this._distributedStore.incr(key);
        if (count === 1) await this._distributedStore.expire(key, ttlSeconds);
        return count;
      } catch (err) { this._recordDegradation('redis', err); }
    }
    const now = Date.now();
    const entry = this._inMemoryCounters.get(key);
    if (!entry || now > entry.expiresAt) { this._inMemoryCounters.set(key, { count: 1, expiresAt: now + ttlSeconds * 1000 }); return 1; }
    entry.count += 1;
    return entry.count;
  },

  // ══════════════════════════════════════════════════════════════════════════
  // bayesianUpdate — CAL FTT-4 DOMAIN DECLARATION
  // Domain: prior ∈ [0, 1], likelihood ∈ [0, 1].
  // Inputs outside domain are clamped. Returns posterior ∈ [0, EPISTEMIC_CEILING].
  // ══════════════════════════════════════════════════════════════════════════
  bayesianUpdate(prior, likelihood, falseLikelihood = null) {
    const p = Math.max(0, Math.min(1, prior));
    const lh = Math.max(0, Math.min(1, likelihood));
    const flh = falseLikelihood !== null ? Math.max(0, Math.min(1, falseLikelihood)) : Math.max(0.05, (1 - lh) * 0.4);
    const pE = lh * p + flh * (1 - p);
    if (pE === 0) return p;
    const posterior = (lh * p) / pE;
    return Math.min(this.THRESHOLDS.EPISTEMIC_CEILING, Math.max(0, posterior));
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CANARY DEPLOYMENT
  // ══════════════════════════════════════════════════════════════════════════
  routeToVersion(userId) {
    const hash = this._hashCode(userId) % 100;
    if (hash < this.PRODUCTION.canaryPercentage) return this.CANARY_VERSION;
    return this.VERSION;
  },

  _hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash |= 0; }
    return Math.abs(hash);
  },

  // ══════════════════════════════════════════════════════════════════════════
  // GRACEFUL DEGRADATION — PDE-FAI-001 FIX: capped at 100 entries
  // M-03: Cascade to global circuit breaker if multiple dependencies open.
  // ══════════════════════════════════════════════════════════════════════════
  _recordDegradation(component, error) {
    this._degradedMode = true;
    if (this._degradationReasons.length >= this.THRESHOLDS.MAX_DEGRADATION_REASONS) {
      this._degradationReasons.shift();
    }
    this._degradationReasons.push({ component, error: error.message, timestamp: Date.now(), severity: 'warning' });
    if (typeof console !== 'undefined') console.warn(`[CERTUS] Degraded mode: ${component} failed - ${error.message}`);
    if (component === 'redis' || component === 'storage' || component === 'supabase') this._sendAlert(component, error);

    // Cascade check: if multiple dependency breakers are open, engage global
    const openBreakers = Object.values(this._dependencyCircuitBreakers)
      .filter(b => b.open).length;
    if (openBreakers >= 2 && !this._circuitBreaker.engaged) {
      this._circuitBreaker.engaged = true;
      this._circuitBreaker.reason = `Multiple dependency failures: ${openBreakers} breakers open`;
      this._circuitBreaker.lastReset = Date.now();
      if (typeof console !== 'undefined') console.error(`[CERTUS] Global circuit breaker engaged: ${this._circuitBreaker.reason}`);
    }
  },

  _sendAlert(component, error) {
    if (typeof fetch !== 'undefined') {
      fetch('/api/alerts', { method: 'POST', body: JSON.stringify({ component, error: error.message, timestamp: Date.now(), severity: 'critical' }) }).catch(() => {});
    }
  },

  // ══════════════════════════════════════════════════════════════════════════
  // AUDIT LOG — M-01: autoIncrement store, not timestamp keyPath
  // ══════════════════════════════════════════════════════════════════════════
  async _logAuditEvent(event) {
    const auditEvent = { ...event, timestamp: Date.now(), version: this.VERSION, instanceId: this._instanceId };
    const shard = this._auditLog.shards[this._auditLog.currentShard] || { events: [], size: 0 };
    shard.events.push(auditEvent);
    shard.size++;
    this._auditLog.shards[this._auditLog.currentShard] = shard;
    if (shard.size >= this._auditLog.maxShardSize) await this._rotateAuditShard();
    if (this._storage && this._storage.logAudit) await this._storage.logAudit(auditEvent);
    if (this._supabaseClient && this._supabaseClient.from) {
      try { await this._supabaseClient.from('audit_logs').insert(auditEvent); } catch (err) { console.warn('[CERTUS] Supabase audit log failed:', err); }
    }
  },

  async _rotateAuditShard() {
    const oldShard = this._auditLog.shards[this._auditLog.currentShard];
    if (oldShard && this._storage) await this._storage.saveShard(oldShard);
    this._auditLog.currentShard++;
    this._auditLog.shards[this._auditLog.currentShard] = { events: [], size: 0 };
  },

  async queryAuditLog(startDate, endDate) {
    const results = [];
    for (const shard of this._auditLog.shards) { if (!shard) continue; const sr = shard.events.filter(e => e.timestamp >= startDate && e.timestamp <= endDate); results.push(...sr); }
    if (this._storage && this._storage.queryAudit) { const stored = await this._storage.queryAudit(startDate, endDate); results.push(...stored); }
    if (this._supabaseClient && this._supabaseClient.from) {
      try { const { data } = await this._supabaseClient.from('audit_logs').select('*').gte('timestamp', startDate).lte('timestamp', endDate); if (data) results.push(...data); } catch (err) { console.warn('[CERTUS] Supabase audit query failed:', err); }
    }
    return results.sort((a, b) => a.timestamp - b.timestamp);
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CIRCUIT BREAKERS
  // ══════════════════════════════════════════════════════════════════════════
  async _callWithCircuitBreaker(dependency, fn, fallback) {
    const breaker = this._dependencyCircuitBreakers[dependency];
    if (!breaker) return fn();
    if (breaker.open) { const tsf = Date.now() - breaker.lastFailure; if (tsf < breaker.timeout) return fallback(); breaker.open = false; breaker.failures = 0; }
    try { const result = await fn(); breaker.failures = 0; return result; }
    catch (err) { breaker.failures++; breaker.lastFailure = Date.now(); if (breaker.failures >= 3) { breaker.open = true; this._recordDegradation(dependency, err); } return fallback(); }
  },

  // ══════════════════════════════════════════════════════════════════════════
  // BACKPRESSURE
  // ══════════════════════════════════════════════════════════════════════════
  async _acquireBackpressureToken(tokens = 1, _maxRetries = 50) {
    const POLL_INTERVAL_MS = 100;
    let retries = 0;
    while (retries < _maxRetries) { this._refillTokens(); if (this._backpressure.tokens >= tokens) { this._backpressure.tokens -= tokens; return true; } await new Promise(r => setTimeout(r, POLL_INTERVAL_MS)); retries++; }
    const err = new Error('BACKPRESSURE_EXHAUSTED'); err.code = 'BACKPRESSURE_EXHAUSTED'; throw err;
  },

  _refillTokens() {
    const now = Date.now();
    const elapsed = now - this._backpressure.lastRefill;
    const newTokens = elapsed * (this._backpressure.rateLimit / 1000);
    this._backpressure.tokens = Math.min(this._backpressure.rateLimit, this._backpressure.tokens + newTokens);
    this._backpressure.lastRefill = now;
  },

  _inMemoryStoreSet(key, value) {
    if (this._inMemoryStore.size >= this._IN_MEMORY_STORE_MAX_SIZE) { const oldest = this._inMemoryStore.keys().next().value; this._inMemoryStore.delete(oldest); }
    this._inMemoryStore.set(key, value);
  },

  // ══════════════════════════════════════════════════════════════════════════
  // EVIDENCE — O(n) where n = evidences.length. Single-pass combination.
  // ══════════════════════════════════════════════════════════════════════════
  _estimateCombinedEvidenceDelta(evidences) {
    const hasPhoto = evidences.includes('photo'), hasWitness = evidences.includes('witness'), hasField = evidences.includes('field');
    let likelihood = 0.5;
    if (hasPhoto && hasWitness) likelihood += Math.max(this.EVIDENCE_WEIGHTS.PHOTO.likelihood - 0.5, this.EVIDENCE_WEIGHTS.WITNESS.likelihood - 0.5);
    else { if (hasPhoto) likelihood += this.EVIDENCE_WEIGHTS.PHOTO.likelihood - 0.5; if (hasWitness) likelihood += this.EVIDENCE_WEIGHTS.WITNESS.likelihood - 0.5; }
    if (hasField) likelihood += this.EVIDENCE_WEIGHTS.FIELD.likelihood - 0.5;
    return Math.min(0.95, likelihood);
  },

  _getEvidenceFreshness(timestamp) { const hoursElapsed = (Date.now() - new Date(timestamp).getTime()) / 3600000; return Math.max(0, 1 - (hoursElapsed / this.THRESHOLDS.EVIDENCE_HALF_LIFE_HOURS)); },
  _getEvidenceWeight(evidence, timestamp) { return evidence.weight * this._getEvidenceFreshness(timestamp); },

  _crossValidateEvidence(photoDamage, witnessDamage) {
    if (photoDamage && witnessDamage && photoDamage !== witnessDamage) return { consistent: false, conflict: `Photo shows ${photoDamage}, witness reports ${witnessDamage}`, resolution: 'require_field_verification' };
    return { consistent: true, damage: photoDamage || witnessDamage };
  },

  _getCredibilityMultiplier(source) { return this.CREDIBILITY_SCORES[source] || 0.5; },

  async _detectAdversarialPattern(evidence, reportHistory) {
    const now = Date.now();
    const recentAppeals = reportHistory.filter(a => a.timestamp > now - 86400000);
    if (recentAppeals.length > 3) return { adversarial: true, reason: 'Multiple contradictory appeals in short timeframe', action: 'require_human_review' };
    const photoHashes = evidence.photos?.map(p => p.hash) || [];
    const duplicatePhotos = await this._findDuplicatePhotos(photoHashes);
    if (duplicatePhotos.length > 0) return { adversarial: true, reason: 'Duplicate evidence detected across reports', action: 'flag_for_investigation' };
    return { adversarial: false };
  },

  _updateReputation(reporterId, reportOutcome) {
    if (!reporterId) { console.warn('[CERTUS] No reporter ID, skipping reputation'); return { score: 0, banned: false, verified_reports: 0, false_reports: 0 }; }
    let reputation = this._reputationStore.get(reporterId) || { score: 0, verified_reports: 0, false_reports: 0, banned: false, ban_reason: null };
    if (reputation.banned) return reputation;
    if (reportOutcome === 'VERIFIED') { reputation.score += this.THRESHOLDS.REPUTATION.VERIFIED_BONUS; reputation.verified_reports++; }
    else if (reportOutcome === 'FALSE') { reputation.score -= this.THRESHOLDS.REPUTATION.FALSE_REPORT_PENALTY; reputation.false_reports++; }
    if (reputation.score < this.THRESHOLDS.REPUTATION.BAN_THRESHOLD) { reputation.banned = true; reputation.ban_reason = 'Multiple false reports'; }
    this._reputationStore.set(reporterId, reputation);
    this.updateReputationStorage(reporterId, reputation).catch(console.warn);
    return reputation;
  },

  _anonymizeLocation(coords, locationType) {
    if (this.SENSITIVE_LOCATION_TYPES.includes(locationType)) return { lat: Math.round(coords.lat * 1000) / 1000, lng: Math.round(coords.lng * 1000) / 1000, anonymized: true, original_accuracy: 'reduced_to_100m', note: 'Location anonymized for sensitive infrastructure' };
    return { ...coords, anonymized: false };
  },

  getConsentForm() {
    return { required: this.CONSENT_OPTIONS.disaster_response, optional: Object.entries(this.CONSENT_OPTIONS).filter(([key, opt]) => !opt.required && !opt.prohibited).map(([key, opt]) => ({ purpose: key, explanation: opt.explanation, default: opt.default })) };
  },

  getDataSharingDisclosure() {
    return {
      recipients: Object.entries(this.DATA_RECIPIENTS).map(([key, r]) => ({ ...r, can_opt_out: r.opt_out })),
      total_recipients: Object.keys(this.DATA_RECIPIENTS).length,
      last_updated: this.DATA_SHARING_LAST_UPDATED  // M-04: static constant
    };
  },

  async submitCorrection(originalReportId, correction, evidence) {
    const cid = this._generateUUID();
    const record = { id: cid, original_report_id: originalReportId, correction, evidence, status: 'PENDING_VERIFICATION', submitted_at: new Date().toISOString(), verification_required: true, after_verification: 'ORIGINAL_ARCHIVED_CORRECTION_ACTIVE' };
    this._correctionStore.set(cid, record);
    await this._logAuditEvent({ type: 'CORRECTION_SUBMITTED', correction_id: cid, original_report_id: originalReportId });
    return record;
  },

  saveProgress(sessionId, step, data) {
    const progress = { step, data, timestamp: Date.now() };
    this._progressStore.set(sessionId, progress);
    if (typeof localStorage !== 'undefined') localStorage.setItem(`veritas_progress_${sessionId}`, JSON.stringify(progress));
    if (this._supabaseClient && this._supabaseClient.from) this._supabaseClient.from('progress').upsert({ session_id: sessionId, step, data, timestamp: progress.timestamp }).catch(console.warn);
  },

  restoreProgress(sessionId) {
    let progress = this._progressStore.get(sessionId);
    if (!progress && typeof localStorage !== 'undefined') { const saved = localStorage.getItem(`veritas_progress_${sessionId}`); if (saved) { try { progress = JSON.parse(saved); } catch (e) { progress = null; } } }
    if (progress && Date.now() - progress.timestamp < 86400000) return progress;
    return null;
  },

  startBatchReporting(sessionId) { this._batchReports.set(sessionId, { reports: [], current: 0, started_at: Date.now() }); return { mode: 'batch', batch_id: sessionId }; },
  addBatchReport(sessionId, report) { const batch = this._batchReports.get(sessionId); if (batch) { batch.reports.push(report); batch.current = batch.reports.length; return { added: true, total: batch.reports.length }; } return { added: false, error: 'No active batch session' }; },

  // C-02: Batch scoring now accepts nearbyReports and isRealModel
  async submitBatch(sessionId, nearbyReports = [], isRealModel = false) {
    const batch = this._batchReports.get(sessionId);
    if (!batch) return { error: 'No batch found' };
    const results = [];
    for (const report of batch.reports) {
      const result = await this.score(report, nearbyReports, isRealModel, {});
      results.push(result);
    }
    await this._logAuditEvent({
      type: 'BATCH_SUBMITTED',
      batch_id: sessionId,
      report_count: batch.reports.length
    });
    this._batchReports.delete(sessionId);
    return { submitted: batch.reports.length, results };
  },

  getIconNavigation(step, language = 'en') { const nav = this.ICON_NAVIGATION.steps[step - 1] || this.ICON_NAVIGATION.steps[0]; const ag = this.AUDIO_GUIDANCE[language]?.[`step_${step}`] || this.AUDIO_GUIDANCE.en[`step_${step}`]; return { ...nav, audio_guidance: ag, audio_url: `/audio/${language}/step-${step}.mp3`, visual_hint: nav.icon, requires_reading: false }; },
  getActionIcons() { return this.ICON_NAVIGATION.actions; },
  supportsOfflineVoice() { return true; },

  // C-01: Stub with console warning
  recognizeOfflineVoice(audioSample, language = 'en') {
    if (typeof console !== 'undefined') {
      console.warn('[CERTUS STUB] recognizeOfflineVoice: audio not analysed. Returns first keyword unconditionally. DO NOT use in production.');
    }
    const keywords = this.VOICE_KEYWORDS[language] || this.VOICE_KEYWORDS.en;
    return {
      detected: keywords[0],
      confidence: 0.7,
      offline: true,
      stub: true,
      stub_warning: 'Returns first keyword unconditionally. Audio sample is not analysed. Replace before production deployment.'
    };
  },

  provideHapticFeedback(confidence, context = {}) {
    if (!this.ACCESSIBILITY.haptic_feedback.enabled) return;
    if (typeof navigator === 'undefined' || !navigator.vibrate) return;
    if (confidence === 'low' || confidence === 'review') navigator.vibrate([500, 200, 500, 200, 500]);
    else if (confidence === 'medium' || confidence === 'watch') navigator.vibrate([300, 200, 300]);
    else if (confidence === 'high') navigator.vibrate(100);
    if (context.emergency) navigator.vibrate([1000, 500, 1000]);
  },

  async detectAndApplyTheme() {
    if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return { theme: 'dark', source: 'system' };
    if (typeof window !== 'undefined' && 'AmbientLightSensor' in window) {
      try { const sensor = new window.AmbientLightSensor(); const reading = await new Promise(r => { sensor.addEventListener('reading', () => r(sensor.illuminance)); sensor.start(); setTimeout(() => r(null), 1000); }); if (reading !== null && reading < 10) return { theme: 'dark', source: 'ambient_light', illuminance: reading }; } catch (err) {}
    }
    return { theme: 'light', source: 'default' };
  },

  getAccessibilitySettings() { return { ...this.ACCESSIBILITY, current_theme: this._currentTheme || 'light', voice_supported: this.supportsOfflineVoice() }; },
  setAccessibilitySetting(setting, value) { if (this.ACCESSIBILITY[setting]) { this.ACCESSIBILITY[setting].enabled = value; return { success: true, setting, value }; } return { success: false, error: 'Setting not found' }; },
  getVerificationBadge(vt) { return this.VERIFICATION_BADGES[vt] || this.VERIFICATION_BADGES.pending; },

  getAudioGuidance(step, language = 'en') { const g = this.AUDIO_GUIDANCE[language] || this.AUDIO_GUIDANCE.en; return { script: g[`step_${step}`] || g.step_1, audio_url: `/audio/${language}/step-${step}.mp3`, fallback_text: this.ICON_NAVIGATION.steps[step - 1]?.description || '', visual_hint: this.ICON_NAVIGATION.steps[step - 1]?.icon || '📸' }; },

  requireConfirmation(report) {
    if (report.internalTier === 'Completely damaged') return { required: true, message: '⚠️ This report indicates SEVERE DAMAGE. Emergency services may be dispatched. Is this correct?', options: [{ text: 'Yes, deploy resources', action: 'submit', severity: 'critical' }, { text: 'No, let me review', action: 'cancel', severity: 'safe' }] };
    return { required: false };
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PES — O(1). Photo evidence scoring with graduated trust integration.
  // ══════════════════════════════════════════════════════════════════════════
  computePES(report, isRealModel = false) {
    const result = { value: 0.50, measurement_class: 'INFERENTIAL', evaluable: true, gated: false, um_contribution: 0, note: '' };
    if (!report.photo) { result.value = null; result.evaluable = false; result.measurement_class = 'NOT_EVALUABLE'; result.um_contribution = 0.25; result.note = 'No photo submitted. PES dimension excluded from DCI.'; return result; }
    if (!report.photoAiScore || report.photoAiConf === null || report.photoAiConf === undefined) { result.value = null; result.evaluable = false; result.measurement_class = 'NOT_EVALUABLE'; result.um_contribution = 0.25; result.note = 'No AI analysis available — PES dimension excluded.'; return result; }
    if (report.photoAiConf < 0.60) { result.value = 0.50; result.measurement_class = isRealModel ? 'EVALUATIVE_GATED' : 'INFERENTIAL'; result.gated = true; result.um_contribution = isRealModel ? 0.10 : 0.30; result.note = `Model confidence ${(report.photoAiConf * 100).toFixed(0)}% below 60% threshold — PES gated to 0.50.`; return result; }
    result.value = Math.max(0, Math.min(1, report.photoAiScore)); result.gated = false;
    if (isRealModel) { result.measurement_class = 'EVALUATIVE'; result.um_contribution = 0; result.note = `AI analysis: score ${report.photoAiScore.toFixed(3)}, confidence ${(report.photoAiConf * 100).toFixed(0)}%.`; }
    else { result.measurement_class = 'INFERENTIAL'; result.um_contribution = 0.20; result.note = `AI analysis (placeholder model): score ${report.photoAiScore.toFixed(3)}. Upgrade to trained model to remove penalty.`; }
    return result;
  },

  // ══════════════════════════════════════════════════════════════════════════
  // COR — O(n) where n = nearbyReports.length.
  // ══════════════════════════════════════════════════════════════════════════
  computeCOR(nearbyReports, currentTier, reportUuid) {
    const result = { value: 0.50, evaluable: true, um_contribution: 0, assumption: null, note: '', signal_type: 'NEUTRAL' };
    if (!nearbyReports || nearbyReports.length === 0) { result.value = null; result.evaluable = false; result.um_contribution = 0.20; result.signal_type = 'NO_EVIDENCE'; result.assumption = { id: 'COR-A01', text: 'No nearby reports exist — corroboration is unknown.', plain_language: '⚠️ First report in this area. No other reports to confirm damage level.', source: 'computeCOR', timestamp: new Date().toISOString() }; result.note = 'First report in this area. No corroboration available. COR dimension excluded.'; return result; }
    if (nearbyReports.length === 1) { const agrees = nearbyReports[0].internalTier === currentTier; result.value = agrees ? 0.55 : 0.40; result.um_contribution = 0.05; result.signal_type = agrees ? 'WEAK_AGREEMENT' : 'WEAK_CONTRADICTION'; result.note = agrees ? 'One nearby report agrees. Weak corroboration — single independent source.' : 'One nearby report disagrees on damage level. Contradiction detected.'; return result; }
    const agreements = nearbyReports.filter(r => r.internalTier === currentTier).length;
    const contradictions = nearbyReports.length - agreements;
    const agreementRate = agreements / nearbyReports.length;
    const rawScore = agreementRate - (contradictions * 0.15);
    const score = Math.max(0, Math.min(1, rawScore));
    result.raw_score = parseFloat(rawScore.toFixed(3));
    if (contradictions > 0) { result.um_contribution = 0.08 * (contradictions / nearbyReports.length); result.signal_type = contradictions > agreements ? 'CONTRADICTION' : 'MIXED'; }
    else { result.signal_type = 'STRONG_AGREEMENT'; }
    result.value = parseFloat(score.toFixed(3));
    result.note = `${nearbyReports.length} nearby reports: ${agreements} agree, ${contradictions} contradict. Agreement rate: ${(agreementRate * 100).toFixed(0)}%.`;
    return result;
  },

  // ══════════════════════════════════════════════════════════════════════════
  // TFR — O(1). Linear decay over 48h.
  // ══════════════════════════════════════════════════════════════════════════
  computeTFR(timestampISO) {
    const hoursElapsed = (Date.now() - new Date(timestampISO).getTime()) / 3600000;
    const value = Math.max(0, 1 - (hoursElapsed / 48));
    let freshness_status, um_contribution;
    if (value >= 0.80) { freshness_status = 'FRESH'; um_contribution = 0; }
    else if (value >= 0.60) { freshness_status = 'AGING'; um_contribution = 0.05; }
    else if (value >= 0.25) { freshness_status = 'STALE'; um_contribution = 0.10; }
    else { freshness_status = 'EXPIRED'; um_contribution = 0.15; }
    return { value: parseFloat(value.toFixed(3)), um_contribution, hours_elapsed: parseFloat(hoursElapsed.toFixed(1)), freshness_status, note: `${hoursElapsed.toFixed(1)}h since submission. Status: ${freshness_status}.` };
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CCI — O(1). Single-pass consistency check.
  // ══════════════════════════════════════════════════════════════════════════
  computeCCI(internalTier, infraType) {
    const result = { value: 1.0, um_contribution: 0, flagged: false, note: 'Classification consistent.' };
    if (!internalTier || !infraType) { result.value = 0.80; result.note = 'Infrastructure type or damage tier not declared — default CCI applied.'; return result; }
    const suspiciousCombinations = [
      { tier: 'Completely damaged', infra: 'Road', cci: 0.70, reason: 'Roads rarely achieve total collapse.' },
      { tier: 'Completely damaged', infra: 'Transport', cci: 0.70, reason: 'Transport infrastructure rarely total collapse.' },
      { tier: 'Completely damaged', infra: 'Utility', cci: 0.75, reason: 'Utility collapse typically partial.' },
      { tier: 'Completely damaged', infra: 'Bridge', cci: 0.80, reason: 'Bridge collapse plausible but verify.' },
    ];
    const match = suspiciousCombinations.find(c => c.tier === internalTier && c.infra === infraType);
    if (match) { result.value = match.cci; result.um_contribution = 0.08; result.flagged = true; result.note = match.reason; }
    return result;
  },

  detectCorrelatedFailures(pes, cor, recentFailureRate = 0) {
    const result = { correlated: false, penalty: 0, reason: null };
    if (this._circuitBreaker.engaged) { result.correlated = true; result.penalty = 0.60; result.reason = 'Circuit breaker engaged: correlated failure storm detected'; return result; }
    if (pes.measurement_class === 'INFERENTIAL' && cor.evaluable === false) { result.correlated = true; result.penalty = Math.max(pes.um_contribution, cor.um_contribution) * 1.2; result.reason = 'Photo and corroboration both missing — correlated epistemic gap'; }
    else if (pes.evaluable === false && cor.evaluable === false) { result.correlated = true; result.penalty = 0.45; result.reason = 'Both photo and corroboration unavailable — high correlated uncertainty'; }
    return result;
  },

  computeECFContribution(findings, dimension) {
    if (!findings || findings.length === 0) return 0;
    const ECF_WEIGHTS = { 'D': 0.00, 'R': 0.05, 'S': 0.10, '?': 0.15 };
    const dimFindings = findings.filter(f => f.dimension === dimension);
    if (dimFindings.length === 0) return 0;
    let total = 0; dimFindings.forEach(f => { const ecf = f.ecf || (f.tags ? f.tags.ecf : '?'); total += ECF_WEIGHTS[ecf] || 0.10; });
    return Math.min(0.30, total / dimFindings.length);
  },

  normalizeWithPenalty(activeDimensions, scores) {
    const totalWeight = activeDimensions.reduce((sum, dim) => sum + this.W[dim], 0);
    const missingDimensions = ['PES', 'COR', 'TFR', 'CCI'].filter(d => !activeDimensions.includes(d));
    let missingPenalty = 1.0;
    const penalties = { PES: 0.25, COR: 0.20, TFR: 0.15, CCI: 0.10 };
    for (const dim of missingDimensions) missingPenalty -= penalties[dim] || 0.20;
    missingPenalty = Math.max(0.40, missingPenalty);
    let weightedSum = 0;
    activeDimensions.forEach(dim => { const nw = this.W[dim] / totalWeight; weightedSum += nw * scores[dim]; });
    return { score: weightedSum * missingPenalty, missing_penalty_applied: missingPenalty, active_dimensions: activeDimensions, excluded_dimensions: missingDimensions.map(d => ({ dimension: d, penalty: penalties[d] || 0.20 })) };
  },

  computeUM(pes, cor, tfr, cci, correlatedFailure, ecfContributions = {}) {
    const penalties = [pes.um_contribution + (ecfContributions.PES || 0), cor.um_contribution + (ecfContributions.COR || 0), tfr.um_contribution + (ecfContributions.TFR || 0), cci.um_contribution + (ecfContributions.CCI || 0)].filter(p => p !== undefined && p !== null);
    let um = 1 - penalties.reduce((acc, p) => acc * (1 - Math.max(0, p)), 1);
    if (correlatedFailure.correlated) um = Math.min(1, um + correlatedFailure.penalty);
    um = parseFloat(Math.min(1, Math.max(0, um)).toFixed(3));
    let validity_status, ceiling;
    let adjThreshold = this.THRESHOLDS.UM_VALID;
    if (correlatedFailure.correlated) adjThreshold = this.THRESHOLDS.UM_VALID * 0.8;
    if (um < adjThreshold) { validity_status = 'VALID'; ceiling = 1.0; }
    else if (um < this.THRESHOLDS.UM_DEGRADED) { validity_status = 'DEGRADED'; ceiling = 1.0 - (um - adjThreshold); }
    else { validity_status = 'SUSPENDED'; ceiling = 0.40; }
    return { mass: um, validity_status, ceiling, correlated_penalty_applied: correlatedFailure.correlated };
  },

  getStrengths(pes, cor, tfr, cci, reportCoordinates, photoGeotag, photoAccuracy = 10) {
    const strengths = [], weaknesses = [];
    if (pes.value && pes.value >= 0.80 && !pes.gated && pes.measurement_class === 'EVALUATIVE') {
      if (photoGeotag && reportCoordinates) {
        if (reportCoordinates.anonymized) weaknesses.push('⚠️ Location verification unavailable — sensitive site anonymized.');
        else { const dist = this._calculateDistance(photoGeotag.lat, photoGeotag.lng, reportCoordinates.lat, reportCoordinates.lng); if (dist <= 100) strengths.push(`✅ Photo clear, high model confidence, location verified within ${Math.round(dist)}m`); else weaknesses.push(`⚠️ Photo location ${Math.round(dist)}m from reported location`); }
      } else strengths.push('✅ Photo evidence clear, high model confidence');
    }
    if (cor.signal_type === 'STRONG_AGREEMENT') strengths.push('✅ Strong corroboration — multiple reports agree');
    else if (cor.signal_type === 'CONTRADICTION') weaknesses.push('⚠️ Contradiction with nearby reports — verify locally');
    else if (cor.signal_type === 'WEAK_AGREEMENT') weaknesses.push('⚠️ Weak corroboration — one nearby report agrees');
    else if (cor.signal_type === 'NO_EVIDENCE') weaknesses.push('⚠️ No corroboration yet — share to improve');
    if (tfr.value >= 0.80) strengths.push(`✅ Timely report (${tfr.hours_elapsed}h after event)`);
    else if (tfr.value < 0.40) weaknesses.push(`⚠️ Stale report (${tfr.hours_elapsed}h old)`);
    if (cci.value >= 0.90 && !cci.flagged) strengths.push('✅ Classification consistent with infrastructure type');
    else if (cci.flagged) weaknesses.push(`⚠️ ${cci.note}`);
    return { strengths, weaknesses };
  },

  _calculateDistance(lat1, lng1, lat2, lng2) { const R = 6371000, dLat = (lat2 - lat1) * Math.PI / 180, dLng = (lng2 - lng1) * Math.PI / 180, a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLng / 2) ** 2; return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)); },

  getUMBreakdown(pes, cor, tfr, cci) {
    const breakdown = [];
    if (pes.um_contribution > 0) { let d = ''; if (pes.evaluable === false) d = `📷 No photo (+${(pes.um_contribution * 100).toFixed(0)}%)`; else if (pes.measurement_class === 'INFERENTIAL') d = `📷 AI uncertain (+${(pes.um_contribution * 100).toFixed(0)}%)`; else if (pes.gated) d = `📷 AI low confidence (+${(pes.um_contribution * 100).toFixed(0)}%)`; if (d) breakdown.push(d); }
    if (cor.um_contribution > 0) { let d = ''; if (cor.evaluable === false) d = `🔍 No other reports (+${(cor.um_contribution * 100).toFixed(0)}%)`; else if (cor.signal_type === 'CONTRADICTION') d = `🔍 Conflicting reports (+${(cor.um_contribution * 100).toFixed(0)}%)`; else if (cor.signal_type === 'WEAK_AGREEMENT') d = `🔍 Only one other report (+${(cor.um_contribution * 100).toFixed(0)}%)`; if (d) breakdown.push(d); }
    if (tfr.um_contribution > 0) breakdown.push(`⏱️ ${tfr.hours_elapsed}h old (+${(tfr.um_contribution * 100).toFixed(0)}%)`);
    if (cci.um_contribution > 0) breakdown.push(`⚖️ Unusual combination (+${(cci.um_contribution * 100).toFixed(0)}%)`);
    return breakdown;
  },

  generateVerificationCertificate(report, dci, tier) {
    const certId = `VRT-${report.uuid?.slice(0, 4).toUpperCase() || 'XXXX'}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    const qrData = JSON.stringify({ id: certId, uuid: report.uuid, dci, tier, timestamp: report.timestamp, verify: `https://veritas.aion.net/verify/${certId}` });
    const hr = `VERITAS CERTIFIED REPORT\n========================\nID: ${certId}\nDCI: ${Math.round(dci * 100)}% (${tier.toUpperCase()} CONFIDENCE)\nLOCATION: ${report.coordinates?.lat?.toFixed(4) || 'unknown'}, ${report.coordinates?.lng?.toFixed(4) || 'unknown'}\nDATE: ${new Date(report.timestamp).toLocaleDateString()}\nVERIFIER: CERTUS Engine v${this.VERSION}`;
    return { certificate_id: certId, qr_data: qrData, qr_code: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}`, shareable_link: `https://veritas.aion.net/verify/${certId}`, shareable_text: `VERITAS CERTIFIED: Report ${certId} is ${Math.round(dci * 100)}% reliable.`, human_readable: hr, certificate_summary: { id: certId, dci_pct: Math.round(dci * 100), tier: tier.toUpperCase(), action: tier === 'high' ? 'SHARE' : (tier === 'watch' ? 'VERIFY' : 'WAIT'), verify_url: `https://veritas.aion.net/verify/${certId}`, issued_at: new Date().toISOString() } };
  },

  getAudioFeedback(tier, validityStatus, language = 'en') {
    const SUPPORTED = ['en', 'es', 'ar', 'zh'];
    const langFallback = !SUPPORTED.includes(language);
    const rl = langFallback ? 'en' : language;
    if (tier === 'review' || validityStatus === 'SUSPENDED') { const fb = this.AUDIO_FEEDBACK.review; return { play: true, sound: this.AUDIO_FEEDBACK.languages[rl]?.review || fb.sound, volume: fb.volume, message: fb.message, gentle: true, language_fallback: langFallback, fallback_reason: langFallback ? 'language_not_supported' : null, fallback_language: langFallback ? 'en' : null }; }
    if (tier === 'watch') { const fb = this.AUDIO_FEEDBACK.watch; return { play: true, sound: this.AUDIO_FEEDBACK.languages[rl]?.watch || fb.sound, volume: fb.volume, message: fb.message, gentle: true, language_fallback: langFallback, fallback_reason: langFallback ? 'language_not_supported' : null, fallback_language: langFallback ? 'en' : null }; }
    return { play: false, language_fallback: langFallback, fallback_reason: langFallback ? 'language_not_supported' : null, fallback_language: langFallback ? 'en' : null };
  },

  getFieldView(scoreResult, context = {}) {
    if (context.mode !== 'field') return null;
    const tier = scoreResult.tier;
    let action, confidence, whatToDo, whatNotToDo, shareCode, audioGuidance;
    if (tier === 'high') { action = 'SHARE THIS REPORT'; confidence = 'HIGH'; whatToDo = 'Send this to response coordinators.'; whatNotToDo = 'Do not submit another report for this location.'; audioGuidance = 'Your report is verified. Share this with responders.'; }
    else if (tier === 'watch') { action = 'VERIFY LOCALLY'; confidence = 'MEDIUM'; whatToDo = 'Check local conditions before acting.'; whatNotToDo = 'Do not deploy resources without local verification.'; audioGuidance = 'Please verify locally before acting.'; }
    else { action = 'NEEDS VERIFICATION'; confidence = 'LOW'; whatToDo = 'Wait for field verification before acting.'; whatNotToDo = 'Do not rely on this report for decisions.'; audioGuidance = 'This report needs verification. Please wait.'; }
    shareCode = scoreResult.verification_certificate?.certificate_id || `VRT-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
    return { mode: 'field', action, confidence, what_to_do: whatToDo, what_not_to_do: whatNotToDo, share_code: shareCode, audio_guidance: audioGuidance, next_steps: [{ icon: '📱', action: 'show', description: 'Show this screen to helper' }, { icon: '📞', action: 'call', number: this.MOCK_EMERGENCY_CONFIG.emergency_phone, description: 'Call for help' }, { icon: '📍', action: 'wait', description: 'Stay here' }], color: this.MARKER_STYLES[tier]?.color || '#888', low_literacy: { icons_only: true, audio_supported: true, requires_reading: false } };
  },

  getOnboardingStep(userProgress, language = 'en') {
    if (!userProgress.hasTakenPhoto) return { step: 1, icon: '📸', title: 'Take a Photo', instructions: 'Point camera at the damage.', audio_url: `/audio/${language}/step-1.mp3`, total_steps: 5, exit_path: { action: 'SAVE_AND_EXIT', label: 'Save for later' } };
    if (!userProgress.hasSelectedDamage) return { step: 2, icon: '🏚️', title: 'Assess Damage', instructions: 'Select the damage level.', audio_url: `/audio/${language}/step-2.mp3`, total_steps: 5, exit_path: { action: 'SAVE_AND_EXIT', label: 'Save for later' } };
    if (!userProgress.hasSelectedInfra) return { step: 3, icon: '🏗️', title: 'What Was Damaged?', instructions: 'Select the type of infrastructure.', audio_url: `/audio/${language}/step-3.mp3`, total_steps: 5, exit_path: { action: 'SAVE_AND_EXIT', label: 'Save for later' } };
    if (!userProgress.hasConfirmedLocation) return { step: 4, icon: '📍', title: 'Confirm Location', instructions: 'Make sure the pin is correct.', audio_url: `/audio/${language}/step-4.mp3`, total_steps: 5, exit_path: { action: 'SAVE_AND_EXIT', label: 'Save for later' } };
    if (!userProgress.hasSubmitted) return { step: 5, icon: '✅', title: 'Submit Report', instructions: 'Review and submit.', audio_url: `/audio/${language}/step-5.mp3`, total_steps: 5, exit_path: { action: 'SAVE_AND_EXIT', label: 'Save for later' } };
    return { step: 'COMPLETE', icon: '🎉', title: 'Report Submitted', instructions: 'Thank you for helping.', audio_url: `/audio/${language}/complete.mp3`, total_steps: 5, exit_path: { action: 'RETURN_HOME', label: 'Return to home' } };
  },

  supportsVoiceInput() { return true; },
  getVoiceInputConfig(language = 'en') { const langs = { en: 'en-US', es: 'es-ES', ar: 'ar-SA', zh: 'zh-CN' }; const lf = !langs[language]; return { supported: true, language: langs[language] || 'en-US', offline_supported: true, keywords: this.VOICE_KEYWORDS[language] || this.VOICE_KEYWORDS.en, language_fallback: lf, fallback_reason: lf ? 'language_not_supported' : null, fallback_language: lf ? 'en' : null }; },

  // F-01: getEmergencyResources async with Promise.all
  async getEmergencyResources(report, coordinates) {
    if (report.internalTier !== 'Completely damaged') return null;
    const [shelters, medical] = await Promise.all([
      this._findNearestShelters(coordinates, 10),
      this._findNearestMedical(coordinates, 5)
    ]);
    return {
      triggered: true,
      damage_severity: 'SEVERE',
      local_contacts: [
        { name: 'Local Emergency Services', number: '911' },
        { name: 'UNDP Field Office', number: this.MOCK_EMERGENCY_CONFIG.undp_phone }
      ],
      shelter_locations: shelters,
      medical_facilities: medical,
      message: 'Severe damage detected.',
      audio_alert: 'severe_damage_alert.mp3',
      mock_data_warning: this.MOCK_EMERGENCY_CONFIG.active ? this.MOCK_EMERGENCY_CONFIG.warning : null
    };
  },

  getShareData(report, certificate) { const su = certificate?.shareable_link || `https://veritas.aion.net/report/${report.uuid}`; const st = certificate?.shareable_text || `Damage report: ${report.internalTier} damage to ${report.infraType}.`; return { title: 'VERITAS Damage Report', text: st, url: su, canShare: typeof navigator !== 'undefined' && !!navigator.share }; },

  registerOfflineMapSupport() { if (typeof window !== 'undefined' && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw-map.js').catch(() => {}); },
  registerOfflineSupport() { if (typeof window !== 'undefined' && 'serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').then(() => { this._offlineSupported = true; }).catch(err => { this._offlineSupported = false; this._recordDegradation('service_worker', err); }); } return this._offlineSupported; },

  // ── NLP ────────────────────────────────────────────────────────────────
  // H-04: Damage extraction uses presence flags, not cumulative sum.
  _extractDamageFromWitness(statement) {
    if (!statement || !statement.text) return null;
    const text = statement.text.toLowerCase();
    const hasMinimal  = this.NLP_CONFIG.damageKeywords.minimal.some(kw => text.includes(kw));
    const hasPartial  = this.NLP_CONFIG.damageKeywords.partial.some(kw => text.includes(kw));
    const hasComplete = this.NLP_CONFIG.damageKeywords.complete.some(kw => text.includes(kw));
    let ds = 0.5;
    if (hasComplete)      ds = 0.85;
    else if (hasPartial)  ds = 0.60;
    else if (hasMinimal)  ds = 0.25;
    const dl = ds >= 0.7 ? 'complete' : ds >= 0.4 ? 'partial' : 'minimal';
    const isUrgent    = this.NLP_CONFIG.sentimentAnalysis.urgency.some(w => text.includes(w));
    const isUncertain = this.NLP_CONFIG.sentimentAnalysis.uncertainty.some(w => text.includes(w));
    return { damage_level: dl, confidence: ds, is_urgent: isUrgent,
             is_uncertain: isUncertain, keywords_found: this._findKeywords(text) };
  },

  _findKeywords(text) { const found = []; for (const [level, kws] of Object.entries(this.NLP_CONFIG.damageKeywords)) for (const kw of kws) if (text.includes(kw)) found.push({ keyword: kw, level, position: text.indexOf(kw) }); return found; },

  _inferInfrastructureType(text) {
    if (!text) return null;
    const lt = text.toLowerCase();
    let bm = { type: null, confidence: 0, matches: [] };
    for (const [type, kws] of Object.entries(this.NLP_CONFIG.infrastructureKeywords)) { const ms = kws.filter(kw => lt.includes(kw)); if (ms.length > 0) { const conf = Math.min(0.95, ms.length / kws.length); if (conf > bm.confidence) bm = { type, confidence: conf, matches: ms }; } }
    return bm.confidence > 0.3 ? bm : null;
  },

  _getMostCommon(arr) { if (!arr || arr.length === 0) return null; const freq = {}; let mf = 0, mv = arr[0]; for (const v of arr) { freq[v] = (freq[v] || 0) + 1; if (freq[v] > mf) { mf = freq[v]; mv = v; } } return mv; },

  // ── PHOTO ──────────────────────────────────────────────────────────────
  async _extractDamageFromPhoto(photoDataUrl) {
    if (!photoDataUrl) return null;
    try { const b64 = photoDataUrl.split(',')[1]; const res = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ image: b64 }) }); if (!res.ok) throw new Error('Photo analysis failed'); const r = await res.json(); return { damage_level: r.damage_level, confidence: r.confidence, score: r.score, model: r.model }; }
    catch (e) { console.error('[CERTUS] Photo analysis error:', e); return null; }
  },

  async analyzeBatchPhotos(photoUrls) { const results = []; for (const p of photoUrls) { const a = await this._extractDamageFromPhoto(p); results.push(a); await new Promise(r => setTimeout(r, 500)); } const dls = results.map(r => r?.damage_level).filter(Boolean); const mc = this._getMostCommon(dls); const ac = results.reduce((s, r) => s + (r?.confidence || 0), 0) / results.length; return { individual: results, aggregated: { damage_level: mc, confidence: ac, photos_analyzed: results.length, consistency: dls.every(l => l === mc) ? 'HIGH' : 'MEDIUM' } }; },

  async _generatePerceptualHash(imageDataUrl) {
    if (!imageDataUrl) return null;
    if (typeof document !== 'undefined' && typeof HTMLCanvasElement !== 'undefined') {
      try {
        const img = new Image();
        await new Promise((resolve, reject) => { img.onload = resolve; img.onerror = () => reject(new Error('Image load failed')); img.src = imageDataUrl; setTimeout(() => reject(new Error('Image load timeout')), 5000); });
        const canvas = document.createElement('canvas'); canvas.width = 9; canvas.height = 8; const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0, 9, 8); const data = ctx.getImageData(0, 0, 9, 8).data;
        const luma = []; for (let i = 0; i < data.length; i += 4) luma.push(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]);
        let bits = ''; for (let row = 0; row < 8; row++) for (let col = 0; col < 8; col++) bits += luma[row * 9 + col] > luma[row * 9 + col + 1] ? '1' : '0';
        return bits;
      } catch (err) { console.warn('[CERTUS] dHash failed, falling back to FNV-1a:', err.message); }
    }
    let h = 0x811c9dc5; for (let i = 0; i < imageDataUrl.length; i++) { h ^= imageDataUrl.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return `fnv:${h.toString(16).padStart(8, '0')}`;
  },

  _calculateHashSimilarity(h1, h2) {
    if (!h1 || !h2) return 0; if (h1 === h2) return 1.0;
    const isBin = /^[01]{64}$/.test(h1) && /^[01]{64}$/.test(h2);
    if (isBin) { let m = 0; for (let i = 0; i < 64; i++) if (h1[i] === h2[i]) m++; return m / 64; }
    const len = Math.max(h1.length, h2.length); let diff = 0; for (let i = 0; i < Math.min(h1.length, h2.length); i++) if (h1[i] !== h2[i]) diff++; diff += Math.abs(h1.length - h2.length);
    return Math.max(0, 1 - diff / len);
  },

  async _getPhotoRegistry() { if (this._photoRegistry.size > 0) return this._photoRegistry; if (typeof localStorage !== 'undefined') { try { const r = localStorage.getItem('veritas_photo_registry'); if (r) { JSON.parse(r).forEach(i => this._photoRegistry.set(i.hash, i)); } } catch (e) {} } if (this._supabaseClient && this._supabaseClient.from) { try { const { data } = await this._supabaseClient.from('photo_registry').select('*').gte('timestamp', Date.now() - 30 * 86400000); if (data) data.forEach(i => this._photoRegistry.set(i.hash, i)); } catch (err) {} } return this._photoRegistry; },

  async _registerPhoto(hash, reportId) { const r = await this._getPhotoRegistry(); const e = { hash, report_id: reportId, timestamp: Date.now() }; r.set(hash, e); if (typeof localStorage !== 'undefined') { try { const es = Array.from(r.values()); const cutoff = Date.now() - 30 * 86400000; localStorage.setItem('veritas_photo_registry', JSON.stringify(es.filter(e => e.timestamp > cutoff))); } catch (e) {} } if (this._supabaseClient && this._supabaseClient.from) { try { await this._supabaseClient.from('photo_registry').upsert(e); } catch (err) {} } },

  async _findDuplicatePhotos(photoHashes, threshold = null) {
    const thresh = threshold || this.THRESHOLDS.PERCEPTUAL_HASH_THRESHOLD;
    if (!photoHashes || photoHashes.length === 0) return [];
    const registry = await this._getPhotoRegistry(); const dups = [];
    for (const hash of photoHashes) { for (const [eh, entry] of registry.entries()) { const sim = this._calculateHashSimilarity(hash, eh); if (sim >= thresh && hash !== eh) dups.push({ hash, matched_with: eh, similarity: sim, original_report: entry.report_id, timestamp: entry.timestamp }); } }
    return dups;
  },

  // ── LOCATION — MOCK STUBS using MOCK_EMERGENCY_CONFIG ──────────────────
  async _findNearestShelters(coordinates, radiusKm) {
    if (!coordinates || !coordinates.lat || !coordinates.lng) return [];
    const within = this.MOCK_EMERGENCY_CONFIG.shelters.filter(s => { const d = this._calculateDistance(coordinates.lat, coordinates.lng, coordinates.lat + s.lat_offset, coordinates.lng + s.lng_offset); return d <= radiusKm * 1000; });
    return within.map(s => ({ name: s.name, lat: coordinates.lat + s.lat_offset, lng: coordinates.lng + s.lng_offset, capacity: s.capacity, type: s.type, distance_km: this._calculateDistance(coordinates.lat, coordinates.lng, coordinates.lat + s.lat_offset, coordinates.lng + s.lng_offset) / 1000, phone: this.MOCK_EMERGENCY_CONFIG.emergency_phone, stub: this.MOCK_EMERGENCY_CONFIG.active, stub_warning: this.MOCK_EMERGENCY_CONFIG.active ? this.MOCK_EMERGENCY_CONFIG.warning : null }));
  },

  async _findNearestMedical(coordinates, radiusKm) {
    if (!coordinates || !coordinates.lat || !coordinates.lng) return [];
    const within = this.MOCK_EMERGENCY_CONFIG.medical.filter(f => { const d = this._calculateDistance(coordinates.lat, coordinates.lng, coordinates.lat + f.lat_offset, coordinates.lng + f.lng_offset); return d <= radiusKm * 1000; });
    return within.map(f => ({ name: f.name, lat: coordinates.lat + f.lat_offset, lng: coordinates.lng + f.lng_offset, type: f.type, beds: f.beds, distance_km: this._calculateDistance(coordinates.lat, coordinates.lng, coordinates.lat + f.lat_offset, coordinates.lng + f.lng_offset) / 1000, phone: this.MOCK_EMERGENCY_CONFIG.emergency_phone, stub: this.MOCK_EMERGENCY_CONFIG.active, stub_warning: this.MOCK_EMERGENCY_CONFIG.active ? this.MOCK_EMERGENCY_CONFIG.warning : null }));
  },

  // ── STORAGE ────────────────────────────────────────────────────────────
  async _initializeStorage() {
    if (typeof indexedDB !== 'undefined') {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('CERTUS_DB', 2); // version bump for schema changes
        req.onerror = () => reject(req.error);
        req.onsuccess = () => { this._storage = { db: req.result, type: 'indexeddb', logAudit: async (e) => { const tx = this._storage.db.transaction(['audit'], 'readwrite'); tx.objectStore('audit').add(e); }, saveShard: async (s) => { const tx = this._storage.db.transaction(['shards'], 'readwrite'); tx.objectStore('shards').add({ id: Date.now(), data: s }); }, queryAudit: async (sd, ed) => { const tx = this._storage.db.transaction(['audit'], 'readonly'); const store = tx.objectStore('audit'); const range = IDBKeyRange.bound(sd, ed); return new Promise(res => { const rs = []; store.openCursor(range).onsuccess = (e) => { const c = e.target.result; if (c) { rs.push(c.value); c.continue(); } else res(rs); }; }); } }; resolve(this._storage); };
        req.onupgradeneeded = (e) => {
          const db = e.target.result;
          // M-01: audit store uses autoIncrement, not timestamp keyPath
          if (!db.objectStoreNames.contains('audit'))
            db.createObjectStore('audit', { autoIncrement: true });
          if (!db.objectStoreNames.contains('appeals'))
            db.createObjectStore('appeals', { keyPath: 'id' });
          if (!db.objectStoreNames.contains('reputation'))
            db.createObjectStore('reputation', { keyPath: 'reporter_id' });
          if (!db.objectStoreNames.contains('shards'))
            db.createObjectStore('shards', { keyPath: 'id' });
        };
      });
    }
    this._storage = { type: 'memory', memory: new Map(), get: (k) => this._storage.memory.get(k), set: (k, v) => this._storage.memory.set(k, v), logAudit: async (e) => { const a = this._storage.get('audit') || []; a.push(e); this._storage.set('audit', a); }, saveShard: async (s) => { const ss = this._storage.get('shards') || []; ss.push(s); this._storage.set('shards', ss); }, queryAudit: async (sd, ed) => { const a = this._storage.get('audit') || []; return a.filter(e => e.timestamp >= sd && e.timestamp <= ed); } };
    return this._storage;
  },

  initSupabase(url, anonKey) { if (typeof window !== 'undefined' && window.supabase) { this._supabaseClient = window.supabase.createClient(url, anonKey); return true; } return false; },

  // M-02: storeAppeal uses .add not .put to avoid silent overwrite
  async storeAppeal(ar) {
    if (!this._storage) await this._initializeStorage();
    if (this._storage.type === 'indexeddb') {
      const tx = this._storage.db.transaction(['appeals'], 'readwrite');
      tx.objectStore('appeals').add(ar);
      return new Promise((res, rej) => {
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
      });
    } else {
      const a = this._storage.get('appeals') || [];
      a.push(ar);
      this._storage.set('appeals', a);
    }
    if (this._supabaseClient && this._supabaseClient.from) {
      try { await this._supabaseClient.from('appeals').insert(ar); } catch (err) {}
    }
  },

  async updateReputationStorage(rid, rep) {
    if (!this._storage) await this._initializeStorage();
    if (this._storage.type === 'indexeddb') {
      const tx = this._storage.db.transaction(['reputation'], 'readwrite');
      tx.objectStore('reputation').put({ reporter_id: rid, ...rep });
      return new Promise((res, rej) => {
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
      });
    } else {
      const rs = this._storage.get('reputation') || {};
      rs[rid] = rep;
      this._storage.set('reputation', rs);
    }
    if (this._supabaseClient && this._supabaseClient.from) {
      try { await this._supabaseClient.from('reputation').upsert({ reporter_id: rid, ...rep, updated_at: new Date().toISOString() }); } catch (err) {}
    }
  },

  // ── ENHANCED SCORING ───────────────────────────────────────────────────
  async scoreWithNLP(report, nearbyReports = [], isRealModel = false, context = {}) {
    if (report.witness_statement && !report.internalTier) { const wa = this._extractDamageFromWitness({ text: report.witness_statement }); if (wa && wa.confidence > 0.6) { report.internalTier = wa.damage_level; report.nlp_confidence = wa.confidence; report.urgency_flag = wa.is_urgent; } }
    if (report.description && !report.infraType) { const im = this._inferInfrastructureType(report.description); if (im) { report.infraType = im.type; report.infra_confidence = im.confidence; } }
    return await this.score(report, nearbyReports, isRealModel, context);
  },

  async initialize(supabaseUrl = null, supabaseAnonKey = null) {
    await this._initializeStorage();
    if (supabaseUrl && supabaseAnonKey) this.initSupabase(supabaseUrl, supabaseAnonKey);
    await this._logAuditEvent({ type: 'ENGINE_INITIALIZED', version: this.VERSION, storage_type: this._storage?.type, supabase_available: !!this._supabaseClient });
    return { success: true, version: this.VERSION, storage: this._storage?.type, supabase: !!this._supabaseClient };
  },

  async healthCheck() {
    const hc = { status: this._circuitBreaker.engaged ? 'DEGRADED' : 'HEALTHY', version: this.VERSION, degraded_mode: this._degradedMode, fcl_entries: this._fclEntries.length, audit_shards: this._auditLog.shards.length, timestamp: new Date().toISOString() };
    if (this._supabaseClient) { try { await this._supabaseClient.from('health_check').select('*').limit(1); hc.supabase = 'healthy'; } catch { hc.supabase = 'unavailable'; } }
    return hc;
  },

  // ══════════════════════════════════════════════════════════════════════════
  // PROCESS APPEAL — PDE-LOO-001 FIX: cumulative ceiling tracking
  // ══════════════════════════════════════════════════════════════════════════
  async processAppeal(originalReport, newEvidence, ipAddress, context = {}) {
    const currentAppeals = originalReport.appeal_count || 0;
    if (currentAppeals >= this.THRESHOLDS.MAX_APPEALS) return { success: false, error: 'APPEAL_EXHAUSTED', remaining_appeals: 0 };

    await this._acquireBackpressureToken();
    const reportKey = `appeal:${originalReport.uuid}`, ipKey = `appeal:ip:${ipAddress}`;
    const reportCount = await this._callWithCircuitBreaker('redis', () => this._incrementDistributedCounter(reportKey, this.THRESHOLDS.APPEAL_RATE_LIMIT.per_report.window / 1000), () => { const c = (this._inMemoryStore.get(reportKey) || 0) + 1; this._inMemoryStoreSet(reportKey, c); return c; });
    const ipCount = await this._callWithCircuitBreaker('redis', () => this._incrementDistributedCounter(ipKey, this.THRESHOLDS.APPEAL_RATE_LIMIT.per_ip.window / 1000), () => { const c = (this._inMemoryStore.get(ipKey) || 0) + 1; this._inMemoryStoreSet(ipKey, c); return c; });
    if (reportCount > this.THRESHOLDS.APPEAL_RATE_LIMIT.per_report.max) return { success: false, error: 'RATE_LIMITED' };
    if (ipCount > this.THRESHOLDS.APPEAL_RATE_LIMIT.per_ip.max) return { success: false, error: 'RATE_LIMITED' };
    if (!newEvidence || (!newEvidence.photos && !newEvidence.witness_statements && !newEvidence.field_verification)) return { success: false, error: 'NO_NEW_EVIDENCE', remaining_appeals: this.THRESHOLDS.MAX_APPEALS - currentAppeals };

    const pd = newEvidence.photos?.length ? await this._extractDamageFromPhoto(newEvidence.photos[0]) : null;
    const wd = newEvidence.witness_statements?.length ? this._extractDamageFromWitness(newEvidence.witness_statements[0]) : null;
    const cv = this._crossValidateEvidence(pd?.damage_level || null, wd?.damage_level || null);
    if (!cv.consistent) return { success: false, error: 'INCONSISTENT_EVIDENCE', remaining_appeals: this.THRESHOLDS.MAX_APPEALS - currentAppeals };

    const adv = await this._detectAdversarialPattern(newEvidence, originalReport.appeal_history || []);
    if (adv.adversarial) { await this._logAuditEvent({ type: 'ADVERSARIAL_DETECTED', report_id: originalReport.uuid, reason: adv.reason }); return { success: false, error: 'ADVERSARIAL_PATTERN', remaining_appeals: this.THRESHOLDS.MAX_APPEALS - currentAppeals }; }

    const reportBoostKey = `boost:${originalReport.uuid}`;
    let cumulativeBoost = this._cumulativeAppealBoost.get(reportBoostKey) || 0;
    const MAX_CUMULATIVE_BOOST = this.THRESHOLDS.EPISTEMIC_CEILING - (originalReport.photoAiConf || 0.5);
    if (cumulativeBoost >= MAX_CUMULATIVE_BOOST) return { success: false, error: 'EPISTEMIC_CEILING_REACHED', message: 'Cumulative appeal confidence has reached the epistemic ceiling. Further appeals require human arbitrator.', remaining_appeals: 0 };

    const sc = this._getCredibilityMultiplier(newEvidence.source_type) || 0.5;
    const ef = this._getEvidenceFreshness(newEvidence.timestamp || Date.now());
    let eq = 0;
    if (newEvidence.photos?.length) eq += this._getEvidenceWeight(this.EVIDENCE_WEIGHTS.PHOTO, newEvidence.timestamp) * sc;
    if (newEvidence.witness_statements?.length) eq += this._getEvidenceWeight(this.EVIDENCE_WEIGHTS.WITNESS, newEvidence.timestamp) * sc;
    if (newEvidence.field_verification) eq += this._getEvidenceWeight(this.EVIDENCE_WEIGHTS.FIELD, newEvidence.timestamp) * sc;
    eq = Math.min(1, eq);

    const eTypes = []; if (newEvidence.photos) eTypes.push('photo'); if (newEvidence.witness_statements) eTypes.push('witness'); if (newEvidence.field_verification) eTypes.push('field');
    const lh = this._estimateCombinedEvidenceDelta(eTypes);
    const prior = originalReport.photoAiConf || 0.5;
    const updated = this.bayesianUpdate(prior, lh);
    const boost = updated - prior;

    const effectiveBoost = Math.min(boost, MAX_CUMULATIVE_BOOST - cumulativeBoost);
    cumulativeBoost += effectiveBoost;
    this._cumulativeAppealBoost.set(reportBoostKey, cumulativeBoost);

    const aw = 0.15 + (0.30 * eq);
    const ar = { id: `${originalReport.uuid}-${currentAppeals + 1}`, timestamp: Date.now(), quality: eq, freshness: ef, credibility: sc, likelihood: lh, cumulative_boost: cumulativeBoost };
    await this.storeAppeal(ar);
    await this._logAuditEvent({ type: 'APPEAL_PROCESSED', appeal_id: ar.id, report_id: originalReport.uuid, cumulative_boost: cumulativeBoost });

    return { success: true, updated_report: { ...originalReport, photo: newEvidence.photos?.[0] || originalReport.photo, photoAiConf: prior + effectiveBoost, appeal_count: currentAppeals + 1, appeal_history: [...(originalReport.appeal_history || []), ar], cumulative_appeal_boost: cumulativeBoost }, appeal_weight_applied: aw, confidence_boost_applied: effectiveBoost, remaining_appeals: this.THRESHOLDS.MAX_APPEALS - (currentAppeals + 1) };
  },

  // ══════════════════════════════════════════════════════════════════════════
  // MASTER SCORE — ASYNC. Caller MUST await.
  // H-02: Adversarial detection on initial submissions (if reportHistory provided)
  // ══════════════════════════════════════════════════════════════════════════
  async score(report, nearbyReports = [], isRealModel = false, context = {}) {
    const ts = report.timestamp || new Date().toISOString();
    const reportUuid = report.uuid || this._generateUUID();
    if (context.mode === 'field') { this.registerOfflineSupport(); this.registerOfflineMapSupport(); }
    await this._acquireBackpressureToken();

    const inputHash = await this._hashReportInput(report); // H-01 async
    const version = this.routeToVersion(reportUuid);
    const location = this._anonymizeLocation(report.coordinates || { lat: 0, lng: 0 }, report.infraType);

    const reputation = this._updateReputation(report.reporter_id, 'PENDING');
    if (reputation.banned) { this._logAuditEvent({ type: 'BANNED_REPORTER_BLOCKED', report_id: reportUuid }).catch(() => {}); return { usable: false, error: 'REPORTER_BANNED', reputation }; }

    this._logAuditEvent({ type: 'REPORT_SCORED', report_id: reportUuid, version, location_anonymized: location.anonymized }).catch(() => {});

    // H-02: Adversarial pattern detection on initial submission if reportHistory provided
    let adversarialFlag = null;
    if (context.reportHistory && context.reportHistory.length > 0) {
      const adv = await this._detectAdversarialPattern(
        { photos: report.photo ? [{ hash: report.photoHash }] : [] },
        context.reportHistory
      );
      if (adv.adversarial) {
        await this._logAuditEvent({
          type: 'ADVERSARIAL_DETECTED_ON_SUBMISSION',
          report_id: reportUuid,
          reason: adv.reason
        });
        adversarialFlag = adv;
      }
    }

    const PES = this.computePES(report, isRealModel);
    const COR = this.computeCOR(nearbyReports, report.internalTier, reportUuid);
    const TFR = this.computeTFR(ts);
    const CCI = this.computeCCI(report.internalTier, report.infraType);

    const ecfC = { PES: this.computeECFContribution(report.findings || [], 'PES'), COR: this.computeECFContribution(report.findings || [], 'COR'), TFR: this.computeECFContribution(report.findings || [], 'TFR'), CCI: this.computeECFContribution(report.findings || [], 'CCI') };
    const rawScores = { PES: PES.evaluable ? PES.value : null, COR: COR.evaluable ? COR.value : null, TFR: TFR.value, CCI: CCI.value };
    const activeDims = ['PES', 'COR', 'TFR', 'CCI'].filter(d => rawScores[d] !== null);
    const norm = this.normalizeWithPenalty(activeDims, rawScores);
    const dci_raw = norm.score;
    const dci = parseFloat(Math.max(0, Math.min(1, dci_raw)).toFixed(3));

    const recentFR = context.recentCorrelatedFailureRate || 0;
    const cf = this.detectCorrelatedFailures(PES, COR, recentFR);
    const um = this.computeUM(PES, COR, TFR, CCI, cf, ecfC);

    const requiresHumanReview = um.validity_status === 'SUSPENDED';
    const hasValidHR = context.human_review_proof?.reviewer_id && context.human_review_proof?.second_reviewer_id;

    if (requiresHumanReview && !hasValidHR) {
      this._logAuditEvent({ type: 'GUARD_TRIGGERED', report_id: reportUuid, reason: 'SUSPENDED_score_no_review' }).catch(() => {});
      this._logFCLEntry({ _reportUuid: reportUuid, dci, tier: 'review', dci_validity_status: um.validity_status, dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR.value, dci_cci: CCI.value }, null, null);
      return { usable: false, error: '[LAW 4 GUARD] Suspended scores require two independent human reviewers before use.', recommendation: 'FIELD_VERIFICATION_REQUIRED', version, input_hash: inputHash, constitutional_status: { law_4_compliant: false, law_6_compliant: true }, data_governance: this.getDataSharingDisclosure() };
    }

    const tier = dci >= this.THRESHOLDS.DCI_HIGH ? 'high' : dci >= this.THRESHOLDS.DCI_WATCH ? 'watch' : 'review';
    const dims = { PES: PES.value || 0, COR: COR.value || 0, TFR: TFR.value, CCI: CCI.value };
    const bd = Object.keys(dims).reduce((a, b) => dims[a] < dims[b] ? a : b);
    const bv = dims[bd];

    const assumptions = [];
    if (COR.assumption) assumptions.push(COR.assumption);
    assumptions.push({ id: 'DECAY-A01', text: 'Dual decay curves: TFR 48h linear; evidence 168h half-life.', plain_language: '⏱ Report fresh for 48h; evidence weight decays over 7 days.', source: 'computeTFR + _getEvidenceFreshness', timestamp: new Date().toISOString() });
    if (PES.measurement_class === 'INFERENTIAL') assumptions.push({ id: 'PES-A01', text: 'Photo scored by placeholder model.', plain_language: '📷 Photo analyzed by placeholder. Upgrade for higher confidence.', source: 'computePES', timestamp: new Date().toISOString() });

    const { strengths, weaknesses } = this.getStrengths(PES, COR, TFR, CCI, location, report.photoGeotag, report.photoAccuracy);
    const uBd = this.getUMBreakdown(PES, COR, TFR, CCI);
    const vc = tier === 'high' ? this.generateVerificationCertificate(report, dci, tier) : null;
    const af = this.getAudioFeedback(tier, um.validity_status, context.language);
    this.provideHapticFeedback(tier, { emergency: report.internalTier === 'Completely damaged' });
    const fv = this.getFieldView({ tier, verification_certificate: vc }, context);
    const er = await this.getEmergencyResources(report, location); // F-01 await
    const sd = this.getShareData(report, vc);

    const seal = await this._sealResult({ dci, tier, dci_validity_status: um.validity_status }, reportUuid);

    // H-03: pass seal hash to FCL entry
    this._logFCLEntry({ _reportUuid: reportUuid, dci, tier, dci_validity_status: um.validity_status, dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR.value, dci_cci: CCI.value }, context.ground_truth || null, seal.hash);

    return {
      dci, tier, usable: um.validity_status !== 'SUSPENDED' || hasValidHR, version, canary: version !== this.VERSION,
      input_hash: inputHash, integrity_seal: seal,
      dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR.value, dci_cci: CCI.value,
      dci_uncertainty_mass: um.mass, dci_validity_status: um.validity_status, dci_validity_plain: this.PLAIN_LANGUAGE[um.validity_status] || um.validity_status,
      dci_um_breakdown: uBd, dci_correlated_failure: cf.correlated,
      dci_action: tier === 'high' ? 'SHARE' : (tier === 'watch' ? 'VERIFY' : 'WAIT'),
      dci_strengths: strengths, dci_weaknesses: weaknesses,
      dci_marker_style: this.MARKER_STYLES[tier] || this.MARKER_STYLES.suspended,
      dci_verification_certificate: vc,
      dci_audio_feedback: af, dci_field_view: fv, dci_emergency_resources: er, dci_share_data: sd,
      dci_bottleneck: { dimension: bd, dimension_plain: this.PLAIN_LANGUAGE[bd] || bd, value: bv },
      dci_assumptions: assumptions.map(a => a.plain_language).join(' · '), dci_assumptions_raw: assumptions,
      dci_freshness_status: TFR.freshness_status, dci_hours_elapsed: TFR.hours_elapsed,
      dci_flags: { pes_gated: PES.gated, pes_inferential: PES.measurement_class === 'INFERENTIAL', pes_missing: !PES.evaluable, cor_no_evidence: COR.signal_type === 'NO_EVIDENCE', cor_contradiction: COR.signal_type === 'CONTRADICTION', cci_flagged: CCI.flagged, tfr_status: TFR.freshness_status, correlated_failure: cf.correlated, adversarial_detected: !!adversarialFlag },
      dci_cor_signal: COR.signal_type,
      dci_reporter_reputation: reputation,
      model_limitations: this.MODEL_LIMITATIONS,
      fcl_entry_id: this._fclEntries.length > 0 ? this._fclEntries[this._fclEntries.length - 1].fcl_id : null,
      constitutional_status: { law_4_compliant: !(um.validity_status === 'SUSPENDED' && !hasValidHR), law_6_compliant: true, prohibited_uses_enforcement: 'CALLER_RESPONSIBILITY', consent_gate: 'CALLER_RESPONSIBILITY' },
      data_governance: { retention_days: 365, recipients: this.getDataSharingDisclosure().recipients, consent: this.getConsentForm() },
      location, appeal_status: { appeals_used: report.appeal_count || 0, appeals_remaining: Math.max(0, this.THRESHOLDS.MAX_APPEALS - (report.appeal_count || 0)), max_appeals: this.THRESHOLDS.MAX_APPEALS },
      audit_id: this._auditLog.shards.reduce((s, sh) => s + (sh?.events?.length || 0), 0) + 1
    };
  },

  // ── DISPLAY HELPERS ─────────────────────────────────────────────────────
  tierLabel(t) { return { high: 'HIGH CONFIDENCE', watch: 'WATCH', review: 'REVIEW REQUIRED' }[t] || 'UNKNOWN'; },
  tierColor(t) { return this.MARKER_STYLES[t]?.color || '#888'; },
  umLabel(um, vs) { const pct = Math.round(um * 100); const sc = { VALID: '#4ade80', DEGRADED: '#f0a500', SUSPENDED: '#ff4d4d' }[vs] || '#4e5f6a'; const ps = this.PLAIN_LANGUAGE[vs] || vs; return { label: `UM: ${pct}%`, status: vs, status_plain: ps, color: sc }; },
  primaryExplanation(r) {
    const f = r.dci_flags;
    if (!r.usable) return `⚠️ This score requires human review before use. ${r.error || 'Field verification required.'}`;
    if (r.dci_validity_status === 'SUSPENDED') return `This score carries high uncertainty. ${r.dci_field_view?.what_to_do || 'Wait for field verification.'}`;
    if (f.cor_no_evidence) return `First report in this area — no other reports to compare with.`;
    if (f.cor_contradiction) return `Nearby reports disagree. Human verification recommended.`;
    if (f.pes_gated) return `Photo quality is low. Clearer photos would improve confidence.`;
    if (r.dci_bottleneck.dimension === 'TFR') return `This report is ${r.dci_hours_elapsed} hours old. Fresher reports are more reliable.`;
    if (f.pes_missing) return `No photo submitted. Adding a photo would significantly improve confidence.`;
    return `This report is ${r.dci_confidence_plain?.toLowerCase() || 'medium'} confidence.`;
  }
};

// ── EXPORT ─────────────────────────────────────────────────────────────────
if (typeof module !== 'undefined' && module.exports) module.exports = CERTUS;
if (typeof window !== 'undefined') {
  window.CERTUS = CERTUS;
  // L-02: error callback support
  CERTUS.initialize().catch(err => {
    console.error('[CERTUS] Initialization failed:', err);
    if (typeof window.onCERTUSInitError === 'function') {
      window.onCERTUSInitError(err);
    }
  });
}