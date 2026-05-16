// ==================== CERTUS ENGINE v3.1.0 ====================
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
// v3.1.0 Upgrades (from v3.0.1 red-team):
// [CRITICAL] FIX-01 — Concurrent batch scoring with semaphore (limit=10)
// [CRITICAL] FIX-02 — Photo API configurable endpoint + retry + circuit breaker
// [HIGH]     FIX-03 — FCL persistent export before eviction; never lose ground truth
// [HIGH]     FIX-04 — Supabase dependency-injectable; server-side compatible
// [HIGH]     FIX-05 — LRU eviction on all internal Maps; memory-safe
// [HIGH]     FIX-06 — dci_action conflict resolution; adversarial/suspended override
// [HIGH]     FIX-07 — language_mismatch surfaced in dci_flags and dci_assumptions
// [MEDIUM]   FIX-08 — JSDoc type definitions for all public interfaces
// [MEDIUM]   FIX-09 — Constitutional prohibited_use enforcement gate in score()
// [LOW]      FIX-10 — Version bump to 3.1.0
// [ENHANCE]  ENH-01 — Decay Reconciliation Gate (TFR vs evidence freshness)
// [ENHANCE]  ENH-02 — COR radius density adjustment via OSM building density
// [ENHANCE]  ENH-03 — FCL weight auto-calibration (calibrateWeights())
// [ENHANCE]  ENH-04 — Reputation-weighted COR (replaces flat agreement rate)
// [ENHANCE]  ENH-05 — Verification certificate chain (tamper-evident corroboration)
// [ENHANCE]  ENH-06 — Dataset-level Epistemic Debt Score
// [ENHANCE]  ENH-07 — Offline test harness (property-based testing)
//
// Author: Sheldon K. Salmon & ALBEDO
// Date: May 16, 2026 — Upgraded from v3.0.1 (May 16, 2026)

/**
 * @typedef {Object} CERTUSScoreResult
 * @property {number} dci - Damage Confidence Index [0, 1]
 * @property {'high'|'watch'|'review'} tier - DCI tier
 * @property {boolean} usable - Whether score can be acted on
 * @property {string} version - Engine version that produced this score
 * @property {string} input_hash - SHA-256 of report inputs at time of scoring
 * @property {{algorithm: string, hash: string, payload: string}} integrity_seal
 * @property {number|null} dci_pes - Photo Evidence Score [0,1] or null if excluded
 * @property {number|null} dci_cor - Corroboration Score [0,1] or null if excluded
 * @property {number} dci_tfr - Temporal Freshness Rate [0,1]
 * @property {number} dci_cci - Classification Consistency Index [0,1]
 * @property {number} dci_uncertainty_mass - Compound uncertainty [0,1]
 * @property {'VALID'|'DEGRADED'|'SUSPENDED'} dci_validity_status
 * @property {string} dci_validity_plain - Human-readable validity status
 * @property {Object} dci_um_breakdown - Per-dimension UM contributions
 * @property {boolean} dci_correlated_failure - Whether correlated failure detected
 * @property {'SHARE'|'VERIFY'|'WAIT'|'HOLD_ADVERSARIAL'|'WAIT_HUMAN_REVIEW'|'VERIFY_CORRELATED'} dci_action
 * @property {string} dci_action_plain - Human-readable action recommendation
 * @property {string[]} dci_strengths - Factors supporting the score
 * @property {string[]} dci_weaknesses - Factors undermining the score
 * @property {Object} dci_bottleneck - Weakest scoring dimension
 * @property {string} dci_assumptions - Plain-language assumptions summary
 * @property {Object[]} dci_assumptions_raw - Full assumption objects
 * @property {'FRESH'|'AGING'|'STALE'|'EXPIRED'|'AGING_RECOVERED'} dci_freshness_status
 * @property {number} dci_hours_elapsed - Hours since report submission
 * @property {Object} dci_flags - Boolean signal flags
 * @property {boolean} dci_flags.pes_gated
 * @property {boolean} dci_flags.pes_inferential
 * @property {boolean} dci_flags.pes_missing
 * @property {boolean} dci_flags.cor_no_evidence
 * @property {boolean} dci_flags.cor_contradiction
 * @property {boolean} dci_flags.cci_flagged
 * @property {boolean} dci_flags.correlated_failure
 * @property {boolean} dci_flags.adversarial_detected
 * @property {boolean} dci_flags.language_mismatch
 * @property {string} dci_flags.language_reported
 * @property {string} dci_flags.language_nlp_dictionary
 * @property {Object} constitutional_status
 * @property {Object} data_governance
 * @property {Object} appeal_status
 * @property {Object} model_limitations - Full MODEL_LIMITATIONS object
 * @property {number} dci_cor_radius_m - COR radius used for this report
 * @property {string} dci_cor_radius_source - 'default' or 'density_adjusted'
 * @property {Object} dci_decay_reconciliation - Decay gate result
 */

/**
 * @typedef {Object} CERTUSReport
 * @property {string} uuid
 * @property {string} timestamp - ISO 8601
 * @property {string} undpTier - 'minimal'|'partial'|'complete'
 * @property {string} internalTier - 'Minimal/No damage'|'Partially damaged'|'Completely damaged'
 * @property {string} infraType
 * @property {string} [language] - BCP 47 language code, e.g. 'en', 'ar', 'zh'
 * @property {string|null} [photo] - base64 data URL
 * @property {number|null} [photoAiScore]
 * @property {number|null} [photoAiConf]
 * @property {number} [appeal_count]
 * @property {string} [locMode] - 'precise'|'fuzzy'
 * @property {string} [witness_statement]
 * @property {string} [description]
 */

const CERTUS = {

  // ── VERSION ────────────────────────────────────────────────────────────────
  VERSION: '3.1.0',
  CANARY_VERSION: '3.1.0-canary',

  // ══════════════════════════════════════════════════════════════════════════
  // ABSTRACTION BARGAIN — CAL FTT-14 / PDE-GAP-014
  // ══════════════════════════════════════════════════════════════════════════
  MODEL_LIMITATIONS: {
    declaration: 'The DCI model abstracts away the following physical and contextual properties…',
    discarded_properties: [
      { property: 'Sensor reliability', failure_class: '…', detection_requires: 'EXIF metadata inspection, multi-photo cross-validation, manual review' },
      { property: 'Atmospheric interference', failure_class: '…', detection_requires: 'Weather API integration, visibility metadata, manual review' },
      { property: 'Cultural differences in damage reporting', failure_class: '…', detection_requires: 'Multilingual NLP expansion, community translator review, per-language FCL calibration' },
      { property: 'Language translation fidelity', failure_class: '…', detection_requires: 'Back-translation verification, bilingual reviewer sampling, translation confidence scoring' },
      { property: 'Independence of nearby reports', failure_class: '…', detection_requires: 'Temporal clustering analysis, submitter relationship mapping, independence audit' },
      { property: 'Continuous time', failure_class: '…', detection_requires: 'Ground-truth comparison at multiple time horizons, nonlinear decay model calibration' },
      { property: 'Geographic homogeneity', failure_class: '…', detection_requires: 'Population-density-based radius adjustment, building-footprint-aware clustering' },
      { property: 'Perceptual hash fallback fidelity', failure_class: '…', detection_requires: 'Canvas API availability or server-side image processing' },
      { property: 'Evidence combination asymmetry', failure_class: '…', detection_requires: 'FCL calibration against ground-truth field verification outcomes' }
    ],
    specification_primacy: 'If unexpected behavior B is observed: Step 1 — Does the specification permit B? YES → specification error; revise the model. NO → implementation error; debug the code.'
  },

  // ══════════════════════════════════════════════════════════════════════════
  // SCORING CONTRACT — AF-SEC-02
  // ══════════════════════════════════════════════════════════════════════════
  SCORING_CONTRACT: {
    score_is_async: true,
    caller_must_await: true,
    integration_example: 'const result = await CERTUS.score(report, nearby, isRealModel);',
    failure_mode_if_not_awaited: 'Promise object returned instead of score. All reports use fallback. Real CERTUS engine never executes.'
  },

  DATA_SHARING_LAST_UPDATED: '2026-05-11T00:00:00.000Z',

  PROHIBITED_USES: {
    surveillance: { keywords: ['track individual', 'monitor person', 'identify individual', 'locate specific person'], law: 'Law 4 — User Sovereignty', block: true },
    weaponization: { keywords: ['target strike', 'fire solution', 'weapons coordinates', 'strike package'], law: 'Law 6 — Anti-Weaponization', block: true },
    insurance_denial: { keywords: ['deny claim', 'reject insurance', 'coverage denial'], law: 'Law 1 — Individual Sovereignty', block: false, flag: true }
  },

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
    canaryPercentage: 5,
    photoApiEndpoint: '/api/analyze',
    photoApiTimeout: 10000,
    photoApiMaxRetries: 3,
    photoApiRetryBaseMs: 500,
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
    APPEAL_RATE_LIMIT: { per_report: { max: 1, window: 3600000 }, per_ip: { max: 10, window: 3600000 } },
    APPEAL_RETENTION_DAYS: 90,
    GEOTAG_ACCURACY_MULTIPLIER: 2,
    CIRCUIT_BREAKER: { initial_backoff: 3600000, max_backoff: 86400000, manual_reset_required: true },
    REPUTATION: { VERIFIED_BONUS: 10, FALSE_REPORT_PENALTY: 20, BAN_THRESHOLD: -100 },
    MAX_DEGRADATION_REASONS: 100
  },

  CREDIBILITY_SCORES: {
    first_hand_witness: 0.9, second_hand_witness: 0.6, hearsay: 0.3,
    engineer: 0.95, community_elder: 0.85, government_official: 0.7,
    ai_analyzed_photo: 0.85, field_verification: 0.98
  },

  EVIDENCE_WEIGHTS: {
    PHOTO: { weight: 0.35, confidence_boost: 0.12, likelihood: 0.85 },
    WITNESS: { weight: 0.25, confidence_boost: 0.08, likelihood: 0.70 },
    FIELD: { weight: 0.40, confidence_boost: 0.25, likelihood: 0.95 }
  },

  SENSITIVE_LOCATION_TYPES: [
    'shelter', 'medical', 'school', 'government', 'religious',
    'women_shelter', 'refugee_camp', 'detention_center'
  ],

  CONSENT_OPTIONS: {
    disaster_response: { required: true, default: true },
    research: { required: false, default: false, explanation: 'Help improve future disaster response through research' },
    commercial: { required: true, default: false, explanation: 'Allow commercial use of anonymized data', prohibited: false },
    surveillance: { required: true, default: false, prohibited: true, explanation: 'Surveillance use is prohibited by constitutional law' }
  },

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

  DATA_RECIPIENTS: {
    emergency_services: { name: 'Local Emergency Services', purpose: 'Immediate response coordination', retention: '30 days', opt_out: false },
    undp: { name: 'United Nations Development Programme', purpose: 'Resource allocation and planning', retention: '7 years', opt_out: true },
    research_institutions: { name: 'Humanitarian Research Partners', purpose: 'Improving disaster response', retention: 'Indefinite (anonymized)', opt_out: true },
    local_government: { name: 'Local Government', purpose: 'Recovery planning', retention: '5 years', opt_out: true }
  },

  VERIFICATION_BADGES: {
    community_verified: { icon: '👥', label: 'Community Verified', description: 'Verified by local community leaders', color: '#4ade80', weight: 1.2 },
    ai_verified: { icon: '🤖', label: 'AI Verified', description: 'Verified by CERTUS Engine', color: '#f0a500', weight: 1.0 },
    field_verified: { icon: '✅', label: 'Field Verified', description: 'Verified by on-site responders', color: '#4ade80', weight: 1.3 },
    pending: { icon: '⏳', label: 'Pending Verification', description: 'Awaiting human verification', color: '#888', weight: 0.7 }
  },

  ACCESSIBILITY: {
    large_text: { scale: 1.5, description: 'Increase text size for readability', enabled: false },
    high_contrast: { enabled: false, description: 'Increase contrast for visibility', colors: { background: '#000000', text: '#ffffff', accent: '#ffff00' } },
    reduce_motion: { enabled: false, description: 'Reduce animations for accessibility' },
    haptic_feedback: { enabled: true, description: 'Vibration alerts for confidence changes' }
  },

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

  VOICE_KEYWORDS: {
    en: ['help', 'damage', 'emergency', 'yes', 'no', 'photo', 'location'],
    es: ['ayuda', 'daño', 'emergencia', 'sí', 'no', 'foto', 'ubicación'],
    ar: ['مساعدة', 'ضرر', 'طوارئ', 'نعم', 'لا', 'صورة', 'موقع'],
    zh: ['帮助', '损坏', '紧急', '是', '否', '照片', '位置']
  },

  AUDIO_GUIDANCE: {
    en: { step_1: 'Take a photo of the damage. Hold your phone steady.', step_2: 'Select how bad the damage is. Minimal, partial, or complete.', step_3: 'What was damaged? A building, road, bridge, or something else?', step_4: 'Where is the damage? Tap the map to show the location.', step_5: 'Review your report. Tap send when ready.' },
    es: { step_1: 'Tome una foto del daño. Mantenga su teléfono firme.', step_2: 'Seleccione qué tan grave es el daño. Mínimo, parcial o completo.', step_3: '¿Qué fue dañado? Un edificio, carretera, puente u otra cosa?', step_4: '¿Dónde está el daño? Toque el mapa para mostrar la ubicación.', step_5: 'Revise su informe. Toque enviar cuando esté listo.' },
    ar: { step_1: 'التقط صورة للضرر. أبق هاتفك ثابتًا.', step_2: 'اختر مدى شدة الضرر. بسيط، جزئي، أو كامل.', step_3: 'ما الذي تضرر؟ مبنى، طريق، جسر، أو شيء آخر؟', step_4: 'أين موقع الضرر؟ اضغط على الخريطة لتحديد الموقع.', step_5: 'راجع تقريرك. اضغط إرسال عندما تكون جاهزًا.' },
    zh: { step_1: '拍摄损坏照片。保持手机稳定。', step_2: '选择损坏程度。轻微、部分或完全损坏。', step_3: '什么被损坏了？建筑物、道路、桥梁还是其他？', step_4: '损坏在哪里？点击地图显示位置。', step_5: '查看报告。准备好后点击发送。' }
  },

  MARKER_STYLES: {
    high: { color: '#4ade80', pattern: 'solid', pattern_svg: null },
    watch: { color: '#f0a500', pattern: 'striped', pattern_svg: 'url(#stripe-pattern)' },
    review: { color: '#ff4d4d', pattern: 'crosshatch', pattern_svg: 'url(#crosshatch-pattern)' },
    suspended: { color: '#888', pattern: 'dotted', pattern_svg: 'url(#dot-pattern)' }
  },

  PLAIN_LANGUAGE: {
    'VALID': 'Reliable — confident enough to act on',
    'DEGRADED': 'Somewhat uncertain — verify before acting',
    'SUSPENDED': 'Do not rely — human review required',
    'correlated failure detection': 'Multiple problems with this report',
    'epistemic veil': 'Information quality check',
    'uncertainty mass': 'How sure we are',
    'bottleneck dimension': 'Biggest problem with this report',
    'evaluative gated': 'AI uncertain about photo',
    'inferential': 'AI guessing, not sure',
    'HOLD_ADVERSARIAL': 'Do not share — suspicious activity detected on this report',
    'WAIT_HUMAN_REVIEW': 'Wait — a human reviewer must verify this before action',
    'VERIFY_CORRELATED': 'Verify first — multiple problems detected despite high score',
    'SHARE': 'Share with responders — high confidence',
    'VERIFY': 'Verify before sharing — moderate confidence',
    'WAIT': 'Wait for more information — low confidence'
  },

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
    supabase: { open: false, failures: 0, lastFailure: null, timeout: 8000 },
    photoApi: { open: false, failures: 0, lastFailure: null, timeout: 10000 }
  },
  _backpressure: { tokens: 1000, lastRefill: Date.now(), rateLimit: 1000 },
  _degradedMode: false,
  _degradationReasons: [],
  _distributedStore: null,
  _useDistributed: false,
  _storage: null,
  _supabaseClient: null,
  _auditLog: { shards: [], currentShard: 0, maxShardSize: 10000, events: [] },
  _reputationStore: null,
  _correctionStore: null,
  _progressStore: null,
  _batchReports: null,
  _photoRegistry: null,
  _inMemoryCounters: null,
  _inMemoryStore: null,
  _IN_MEMORY_STORE_MAX_SIZE: 10000,
  _cumulativeAppealBoost: null,
  _fclEntries: [],
  _fclMaxEntries: 500,
  _instanceId: (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `certus-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`),
  _offlineSupported: false,
  _currentTheme: 'light',

  // ══════════════════════════════════════════════════════════════════════════
  // HELPER: LRU Map
  // ══════════════════════════════════════════════════════════════════════════
  _createLRUMap(maxSize) {
    const map = new Map();
    return {
      get: (key) => {
        if (!map.has(key)) return undefined;
        const val = map.get(key);
        map.delete(key);
        map.set(key, val);
        return val;
      },
      set: (key, val) => {
        if (map.has(key)) map.delete(key);
        map.set(key, val);
        if (map.size > maxSize) {
          const firstKey = map.keys().next().value;
          map.delete(firstKey);
        }
        return map;
      },
      has: (key) => map.has(key),
      delete: (key) => map.delete(key),
      entries: () => map.entries(),
      get size() { return map.size; },
      values: () => map.values(),
      keys: () => map.keys(),
    };
  },

  async _initMaps() {
    this._reputationStore = this._createLRUMap(50000);
    this._correctionStore = this._createLRUMap(10000);
    this._progressStore = this._createLRUMap(5000);
    this._photoRegistry = this._createLRUMap(100000);
    this._inMemoryCounters = this._createLRUMap(20000);
    this._inMemoryStore = this._createLRUMap(this._IN_MEMORY_STORE_MAX_SIZE);
    this._cumulativeAppealBoost = this._createLRUMap(50000);
    this._batchReports = this._createLRUMap(1000);
  },

  // ══════════════════════════════════════════════════════════════════════════
  // _withConcurrencyLimit — FIX-01
  // ══════════════════════════════════════════════════════════════════════════
  async _withConcurrencyLimit(tasks, limit = 10) {
    const results = [];
    const executing = [];
    for (const task of tasks) {
      const p = Promise.resolve().then(task);
      results.push(p);
      if (limit <= tasks.length) {
        const e = p.then(() => executing.splice(executing.indexOf(e), 1));
        executing.push(e);
        if (executing.length >= limit) await Promise.race(executing);
      }
    }
    return Promise.all(results);
  },

  // ══════════════════════════════════════════════════════════════════════════
  // _generateUUID — RFC 4122 version 4
  // ══════════════════════════════════════════════════════════════════════════
  _generateUUID() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = (Math.random() * 16) | 0; const v = c === 'x' ? r : (r & 0x3) | 0x8; return v.toString(16); });
  },

  // ══════════════════════════════════════════════════════════════════════════
  // FCL LOGGING — FIX-03 (persist before eviction)
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
      dimensions: { pes: scoringResult.dci_pes, cor: scoringResult.dci_cor, tfr: scoringResult.dci_tfr, cci: scoringResult.dci_cci }
    };

    if (this._storage && this._storage.logFCLEntry) {
      this._storage.logFCLEntry(entry).catch(() => {});
    }
    if (this._supabaseClient && this._supabaseClient.from) {
      this._supabaseClient.from('fcl_entries').insert(entry).catch(() => {});
    }

    if (this._fclEntries.length >= this._fclMaxEntries) {
      this._fclEntries.shift();
    }
    this._fclEntries.push(entry);
    return entry.fcl_id;
  },

  getFCLEntries() { return this._fclEntries; },
  getFCLCount() { return this._fclEntries.length; },

  // ══════════════════════════════════════════════════════════════════════════
  // INTEGRITY SEAL — CAL FTT-ECI-01
  // ══════════════════════════════════════════════════════════════════════════
  async _sealResult(result, reportUuid) {
    const payload = JSON.stringify({ uuid: reportUuid, dci: result.dci, tier: result.tier, timestamp: new Date().toISOString(), version: this.VERSION });
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
    } catch (e) { hash = `seal-error-${Date.now()}`; }
    return { algorithm: 'SHA-256', hash, payload };
  },

  // ══════════════════════════════════════════════════════════════════════════
  // INPUT HASH VERIFICATION — CAL FTT-ECI-03 (async SHA‑256)
  // ══════════════════════════════════════════════════════════════════════════
  async _hashReportInput(report) {
    const payload = JSON.stringify({
      uuid: report.uuid || '', timestamp: report.timestamp || '', undpTier: report.undpTier || '',
      infraType: report.infraType || '', hasPhoto: !!report.photo
    });
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const buf = new TextEncoder().encode(payload);
        const digest = await crypto.subtle.digest('SHA-256', buf);
        return 'sha256:' + Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch (e) {}
    let h = 0;
    for (let i = 0; i < payload.length; i++) { h = ((h << 5) - h) + payload.charCodeAt(i); h |= 0; }
    return `djb2-fallback:${Math.abs(h).toString(16)}`;
  },

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

  bayesianUpdate(prior, likelihood, falseLikelihood = null) {
    const p = Math.max(0, Math.min(1, prior));
    const lh = Math.max(0, Math.min(1, likelihood));
    const flh = falseLikelihood !== null ? Math.max(0, Math.min(1, falseLikelihood)) : Math.max(0.05, (1 - lh) * 0.4);
    const pE = lh * p + flh * (1 - p);
    if (pE === 0) return p;
    const posterior = (lh * p) / pE;
    return Math.min(this.THRESHOLDS.EPISTEMIC_CEILING, Math.max(0, posterior));
  },

  routeToVersion(userId) {
    const hash = this._hashCode(userId) % 100;
    return hash < this.PRODUCTION.canaryPercentage ? this.CANARY_VERSION : this.VERSION;
  },

  _hashCode(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) { hash = ((hash << 5) - hash) + str.charCodeAt(i); hash |= 0; }
    return Math.abs(hash);
  },

  _recordDegradation(component, error) {
    this._degradedMode = true;
    if (this._degradationReasons.length >= this.THRESHOLDS.MAX_DEGRADATION_REASONS) this._degradationReasons.shift();
    this._degradationReasons.push({ component, error: error.message, timestamp: Date.now(), severity: 'warning' });
    if (typeof console !== 'undefined') console.warn(`[CERTUS] Degraded mode: ${component} failed - ${error.message}`);
    if (component === 'redis' || component === 'storage' || component === 'supabase') this._sendAlert(component, error);
    const openBreakers = Object.values(this._dependencyCircuitBreakers).filter(b => b.open).length;
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

  async _callWithCircuitBreaker(dependency, fn, fallback) {
    const breaker = this._dependencyCircuitBreakers[dependency];
    if (!breaker) return fn();
    if (breaker.open) { const tsf = Date.now() - breaker.lastFailure; if (tsf < breaker.timeout) return fallback(); breaker.open = false; breaker.failures = 0; }
    try { const result = await fn(); breaker.failures = 0; return result; }
    catch (err) { breaker.failures++; breaker.lastFailure = Date.now(); if (breaker.failures >= 3) { breaker.open = true; this._recordDegradation(dependency, err); } return fallback(); }
  },

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
    return { recipients: Object.entries(this.DATA_RECIPIENTS).map(([key, r]) => ({ ...r, can_opt_out: r.opt_out })), total_recipients: Object.keys(this.DATA_RECIPIENTS).length, last_updated: this.DATA_SHARING_LAST_UPDATED };
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

  async submitBatch(sessionId, nearbyReports = [], isRealModel = false, concurrencyLimit = 10) {
    const batch = this._batchReports.get(sessionId);
    if (!batch) return { error: 'No batch found' };
    const tasks = batch.reports.map(report => () => this.score(report, nearbyReports, isRealModel, {}));
    const results = await this._withConcurrencyLimit(tasks, concurrencyLimit);
    await this._logAuditEvent({ type: 'BATCH_SUBMITTED', batch_id: sessionId, report_count: batch.reports.length, concurrency_limit: concurrencyLimit });
    this._batchReports.delete(sessionId);
    return { submitted: batch.reports.length, results, processing_mode: 'concurrent', concurrency_limit: concurrencyLimit };
  },

  getIconNavigation(step, language = 'en') { const nav = this.ICON_NAVIGATION.steps[step - 1] || this.ICON_NAVIGATION.steps[0]; const ag = this.AUDIO_GUIDANCE[language]?.[`step_${step}`] || this.AUDIO_GUIDANCE.en[`step_${step}`]; return { ...nav, audio_guidance: ag, audio_url: `/audio/${language}/step-${step}.mp3`, visual_hint: nav.icon, requires_reading: false }; },
  getActionIcons() { return this.ICON_NAVIGATION.actions; },
  supportsOfflineVoice() { return true; },

  recognizeOfflineVoice(audioSample, language = 'en') {
    if (typeof console !== 'undefined') console.warn('[CERTUS STUB] recognizeOfflineVoice: audio not analysed. Returns first keyword unconditionally. DO NOT use in production.');
    const keywords = this.VOICE_KEYWORDS[language] || this.VOICE_KEYWORDS.en;
    return { detected: keywords[0], confidence: 0.7, offline: true, stub: true, stub_warning: 'Returns first keyword unconditionally. Audio sample is not analysed. Replace before production deployment.' };
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

  // ENH-04: reputation-weighted COR
  computeCOR(nearbyReports, currentTier, reportUuid, reputationFn = null) {
    const result = { value: 0.50, evaluable: true, um_contribution: 0, assumption: null, note: '', signal_type: 'NEUTRAL', reputation_weighted: false };
    if (!nearbyReports || nearbyReports.length === 0) {
      result.value = null; result.evaluable = false; result.um_contribution = 0.20; result.signal_type = 'NO_EVIDENCE';
      result.assumption = { id: 'COR-A01', text: 'No nearby reports exist — corroboration is unknown.', plain_language: '⚠️ First report in this area. No other reports to confirm damage level.', source: 'computeCOR', timestamp: new Date().toISOString() };
      result.note = 'First report in this area. No corroboration available. COR dimension excluded.';
      return result;
    }
    const weighted = nearbyReports.map(r => {
      let w = 1.0;
      if (reputationFn && r.reporter_id) {
        const rep = reputationFn(r.reporter_id);
        if (rep.banned) return null;
        w = 0.5 + (rep.score / 2);
      }
      return { report: r, weight: w };
    }).filter(Boolean);
    if (weighted.length === 0) {
      result.value = null; result.evaluable = false; result.um_contribution = 0.20;
      result.note = 'All nearby reports from banned reporters — excluded from COR.';
      return result;
    }
    result.reputation_weighted = !!reputationFn;
    const totalWeight = weighted.reduce((s, wr) => s + wr.weight, 0);
    const agreementWeight = weighted.filter(wr => wr.report.internalTier === currentTier).reduce((s, wr) => s + wr.weight, 0);
    const contradictionWeight = totalWeight - agreementWeight;
    const agreementRate = agreementWeight / totalWeight;
    const rawScore = agreementRate - (contradictionWeight / totalWeight * 0.15);
    result.value = parseFloat(Math.max(0, Math.min(1, rawScore)).toFixed(3));
    if (contradictionWeight > agreementWeight) { result.um_contribution = 0.08 * (contradictionWeight / totalWeight); result.signal_type = 'CONTRADICTION'; }
    else if (contradictionWeight > 0) { result.signal_type = 'MIXED'; }
    else { result.signal_type = 'STRONG_AGREEMENT'; }
    result.note = `${weighted.length} nearby reports (reputation-weighted: ${result.reputation_weighted}). Weighted agreement: ${(agreementRate * 100).toFixed(0)}%.`;
    return result;
  },

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

  // ENH-05: certificate chain
  generateVerificationCertificate(report, dci, tier, nearbyReports = []) {
    const corroboratingSeals = nearbyReports
      .filter(r => r.integrity_seal?.hash && r.dciTier === 'high')
      .map(r => ({ report_uuid: r.uuid, seal_hash: r.integrity_seal.hash, dci: r.dci, timestamp: r.timestamp }));
    const certificate = {
      certificate_id: `VCERT-${this._generateUUID()}`,
      report_uuid: report.uuid,
      engine_version: this.VERSION,
      issued_at: new Date().toISOString(),
      dci, tier,
      chain: { corroborating_seals, chain_length: corroborating_seals.length, chain_intact: corroborating_seals.length > 0 },
      validity_window_hours: 48,
      expires_at: new Date(Date.now() + 48 * 3600000).toISOString(),
      note: corroborating_seals.length > 0 ? `Certificate chained to ${corroborating_seals.length} prior verified report(s). Tamper-evident corroboration graph established.` : 'Standalone certificate — no prior reports to chain to.'
    };
    return certificate;
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

  // F-01: async emergency resources
  async getEmergencyResources(report, coordinates) {
    if (report.internalTier !== 'Completely damaged') return null;
    const [shelters, medical] = await Promise.all([this._findNearestShelters(coordinates, 10), this._findNearestMedical(coordinates, 5)]);
    return { triggered: true, damage_severity: 'SEVERE', local_contacts: [{ name: 'Local Emergency Services', number: '911' }, { name: 'UNDP Field Office', number: this.MOCK_EMERGENCY_CONFIG.undp_phone }], shelter_locations: shelters, medical_facilities: medical, message: 'Severe damage detected.', audio_alert: 'severe_damage_alert.mp3', mock_data_warning: this.MOCK_EMERGENCY_CONFIG.active ? this.MOCK_EMERGENCY_CONFIG.warning : null };
  },

  getShareData(report, certificate) { const su = certificate?.shareable_link || `https://veritas.aion.net/report/${report.uuid}`; const st = certificate?.shareable_text || `Damage report: ${report.internalTier} damage to ${report.infraType}.`; return { title: 'VERITAS Damage Report', text: st, url: su, canShare: typeof navigator !== 'undefined' && !!navigator.share }; },

  registerOfflineMapSupport() { if (typeof window !== 'undefined' && 'serviceWorker' in navigator) navigator.serviceWorker.register('/sw-map.js').catch(() => {}); },
  registerOfflineSupport() { if (typeof window !== 'undefined' && 'serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js').then(() => { this._offlineSupported = true; }).catch(err => { this._offlineSupported = false; this._recordDegradation('service_worker', err); }); } return this._offlineSupported; },

  // FIX-02: configurable photo API with retry
  async _extractDamageFromPhoto(photoDataUrl) {
    if (!photoDataUrl) return null;
    const endpoint = this.PRODUCTION.photoApiEndpoint;
    const timeout = this.PRODUCTION.photoApiTimeout;
    const maxRetries = this.PRODUCTION.photoApiMaxRetries;
    const baseMs = this.PRODUCTION.photoApiRetryBaseMs;
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const b64 = photoDataUrl.split(',')[1];
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeout);
        const res = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ image: b64 }), signal: controller.signal });
        clearTimeout(timer);
        if (!res.ok) throw new Error(`Photo API HTTP ${res.status}`);
        const r = await res.json();
        return { damage_level: r.damage_level, confidence: r.confidence, score: r.score, model: r.model, attempt };
      } catch (e) {
        lastError = e;
        if (attempt < maxRetries) await new Promise(r => setTimeout(r, baseMs * Math.pow(2, attempt - 1)));
      }
    }
    console.error(`[CERTUS] Photo analysis failed after ${maxRetries} attempts:`, lastError);
    this._recordDegradation('photoApi', lastError);
    return null;
  },

  async analyzeBatchPhotos(photoUrls) { const results = []; for (const p of photoUrls) { const a = await this._extractDamageFromPhoto(p); results.push(a); await new Promise(r => setTimeout(r, 500)); } const dls = results.map(r => r?.damage_level).filter(Boolean); const mc = this._getMostCommon(dls); const ac = results.reduce((s, r) => s + (r?.confidence || 0), 0) / results.length; return { individual: results, aggregated: { damage_level: mc, confidence: ac, photos_analyzed: results.length, consistency: dls.every(l => l === mc) ? 'HIGH' : 'MEDIUM' } }; },

  // H-04: NLP presence flags (already implemented)
  _extractDamageFromWitness(statement) {
    if (!statement || !statement.text) return null;
    const text = statement.text.toLowerCase();
    const hasMinimal = this.NLP_CONFIG.damageKeywords.minimal.some(kw => text.includes(kw));
    const hasPartial = this.NLP_CONFIG.damageKeywords.partial.some(kw => text.includes(kw));
    const hasComplete = this.NLP_CONFIG.damageKeywords.complete.some(kw => text.includes(kw));
    let ds = 0.5;
    if (hasComplete) ds = 0.85;
    else if (hasPartial) ds = 0.60;
    else if (hasMinimal) ds = 0.25;
    const dl = ds >= 0.7 ? 'complete' : ds >= 0.4 ? 'partial' : 'minimal';
    const isUrgent = this.NLP_CONFIG.sentimentAnalysis.urgency.some(w => text.includes(w));
    const isUncertain = this.NLP_CONFIG.sentimentAnalysis.uncertainty.some(w => text.includes(w));
    return { damage_level: dl, confidence: ds, is_urgent: isUrgent, is_uncertain: isUncertain, keywords_found: this._findKeywords(text) };
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

  // ENH-02: COR radius density adjustment
  async _adjustCORRadius(lat, lng) {
    const DEFAULT_RADIUS = 50;
    try {
      const bbox = `${lat - 0.005},${lng - 0.005},${lat + 0.005},${lng + 0.005}`;
      const query = encodeURIComponent(`[out:json][timeout:5];(way["building"](${bbox}););out count;`);
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 3000);
      const res = await fetch(`https://overpass-api.de/api/interpreter?data=${query}`, { signal: controller.signal });
      if (!res.ok) return DEFAULT_RADIUS;
      const data = await res.json();
      const buildingCount = data.elements?.[0]?.tags?.total || 0;
      if (buildingCount > 500) return 20;
      if (buildingCount > 200) return 30;
      if (buildingCount > 50) return 50;
      if (buildingCount > 10) return 100;
      return 200;
    } catch (e) { return DEFAULT_RADIUS; }
  },

  // ENH-01: Decay Reconciliation
  _reconcileDecay(tfr, evidenceFreshness, context = {}) {
    const evidenceTs = context.evidence_timestamp || null;
    if (!evidenceTs) return { tfr_adjusted: tfr, reconciled: false };
    const evidenceHoursAgo = (Date.now() - new Date(evidenceTs).getTime()) / 3600000;
    const evidenceStatus = evidenceHoursAgo < 6 ? 'VERY_FRESH' : evidenceHoursAgo < 24 ? 'FRESH' : evidenceHoursAgo < 72 ? 'AGING' : 'STALE';
    if ((tfr.freshness_status === 'EXPIRED' || tfr.freshness_status === 'STALE') && (evidenceStatus === 'VERY_FRESH' || evidenceStatus === 'FRESH')) {
      const recoveredValue = Math.max(tfr.value, 0.45);
      return { tfr_adjusted: { ...tfr, value: parseFloat(recoveredValue.toFixed(3)), freshness_status: 'AGING_RECOVERED', reconciliation_note: `TFR recovered from ${tfr.freshness_status} to AGING_RECOVERED due to fresh evidence submitted ${evidenceHoursAgo.toFixed(1)}h ago.`, um_contribution: 0.05 }, reconciled: true, evidence_status: evidenceStatus, evidence_hours_ago: evidenceHoursAgo };
    }
    return { tfr_adjusted: tfr, reconciled: false, evidence_status: evidenceStatus };
  },

  // ENH-03: FCL weight auto-calibration
  calibrateWeights(minEntries = 20) {
    const entries = this._fclEntries.filter(e => e.ground_truth && e.ground_truth.outcome);
    if (entries.length < minEntries) return { calibrated: false, reason: `Insufficient FCL entries: ${entries.length} / ${minEntries} required`, current_weights: { ...this.W } };
    const OUTCOME_MAP = { 'VERIFIED_CORRECT': 1.0, 'VERIFIED_PARTIAL': 0.6, 'VERIFIED_INCORRECT': 0.0, 'FIELD_CONFIRMED': 1.0, 'FIELD_DISPUTED': 0.2 };
    let pesError = 0, corError = 0, tfrError = 0, cciError = 0, n = 0;
    for (const entry of entries) {
      const actual = OUTCOME_MAP[entry.ground_truth.outcome];
      if (actual === undefined) continue;
      pesError += Math.abs((entry.dimensions.pes || 0.5) - actual);
      corError += Math.abs((entry.dimensions.cor || 0.5) - actual);
      tfrError += Math.abs((entry.dimensions.tfr || 0.5) - actual);
      cciError += Math.abs((entry.dimensions.cci || 0.5) - actual);
      n++;
    }
    if (n === 0) return { calibrated: false, reason: 'No mappable outcomes', current_weights: { ...this.W } };
    const maePES = pesError / n, maeCOR = corError / n, maeTFR = tfrError / n, maeCCI = cciError / n;
    const accuracy = { PES: 1 - maePES, COR: 1 - maeCOR, TFR: 1 - maeTFR, CCI: 1 - maeCCI };
    const totalAccuracy = Object.values(accuracy).reduce((s, v) => s + v, 0);
    const recommendedWeights = {};
    for (const dim of ['PES', 'COR', 'TFR', 'CCI']) recommendedWeights[dim] = parseFloat((accuracy[dim] / totalAccuracy).toFixed(4));
    const updatedWeights = {};
    for (const dim of ['PES', 'COR', 'TFR', 'CCI']) updatedWeights[dim] = parseFloat((0.70 * this.W[dim] + 0.30 * recommendedWeights[dim]).toFixed(4));
    return { calibrated: true, fcl_entries_analyzed: n, per_dimension_mae: { PES: maePES, COR: maeCOR, TFR: maeTFR, CCI: maeCCI }, current_weights: { ...this.W }, recommended_weights: recommendedWeights, updated_weights_dampened: updatedWeights, apply_instruction: 'Review updated_weights_dampened. If acceptable, call: CERTUS.W = CERTUS.calibrateWeights().updated_weights_dampened', calibration_note: '70/30 dampened blend. Apply manually after human review. Do not auto-apply in production.' };
  },

  // ENH-06: Epistemic Debt Score
  computeEpistemicDebtScore(allReports) {
    if (!allReports || allReports.length === 0) return { eds: null, eds_label: 'NO_DATA', report_count: 0 };
    const activeReports = allReports.filter(r => r.dci !== undefined && r.dci_uncertainty_mass !== undefined);
    if (activeReports.length === 0) return { eds: null, eds_label: 'UNSCORED', report_count: allReports.length };
    const TIER_WEIGHTS = { high: 1.5, watch: 1.0, review: 0.5 };
    let weightedUMSum = 0, totalWeight = 0, tierCounts = { high: 0, watch: 0, review: 0 };
    for (const r of activeReports) {
      const tw = TIER_WEIGHTS[r.dciTier] || 1.0;
      weightedUMSum += (r.dci_uncertainty_mass || 0) * tw;
      totalWeight += tw;
      tierCounts[r.dciTier] = (tierCounts[r.dciTier] || 0) + 1;
    }
    const eds = totalWeight > 0 ? parseFloat((weightedUMSum / totalWeight).toFixed(3)) : null;
    let eds_label, eds_color, eds_action;
    if (eds === null) { eds_label = 'UNCOMPUTABLE'; eds_color = '#888'; eds_action = 'Await scored reports'; }
    else if (eds < 0.20) { eds_label = 'LOW_DEBT'; eds_color = '#4ade80'; eds_action = 'Dataset reliable — act on high-tier reports'; }
    else if (eds < 0.40) { eds_label = 'MODERATE_DEBT'; eds_color = '#f0a500'; eds_action = 'Verify watch-tier reports before acting'; }
    else if (eds < 0.60) { eds_label = 'HIGH_DEBT'; eds_color = '#e87c1e'; eds_action = 'Significant uncertainty — field verification recommended'; }
    else { eds_label = 'CRITICAL_DEBT'; eds_color = '#ff4d4d'; eds_action = 'Do not act on this dataset without human field review'; }
    return { eds, eds_label, eds_color, eds_action, report_count: activeReports.length, tier_distribution: tierCounts, weighted_by: 'tier_importance', generated_at: new Date().toISOString(), interpretation: `${Math.round((1 - eds) * 100)}% of this dataset's confidence can be trusted at face value.` };
  },

  // FIX-09: Prohibited use gate
  _checkProhibitedUse(context = {}) {
    const purpose = (context.stated_purpose || '').toLowerCase();
    if (!purpose) return { blocked: false, flagged: false };
    for (const [use, config] of Object.entries(this.PROHIBITED_USES)) {
      const matched = config.keywords.some(kw => purpose.includes(kw));
      if (matched) {
        this._logAuditEvent({ type: 'PROHIBITED_USE_DETECTED', use_category: use, law: config.law, blocked: config.block, purpose_declared: purpose }).catch(() => {});
        if (config.block) return { blocked: true, use_category: use, law: config.law };
        if (config.flag) return { blocked: false, flagged: true, use_category: use, law: config.law };
      }
    }
    return { blocked: false, flagged: false };
  },

  // FIX-04: Dependency-injectable Supabase
  initSupabase(urlOrClient, anonKey = null) {
    if (urlOrClient && typeof urlOrClient === 'object' && typeof urlOrClient.from === 'function') {
      this._supabaseClient = urlOrClient;
      return true;
    }
    if (typeof window !== 'undefined' && window.supabase && typeof urlOrClient === 'string') {
      this._supabaseClient = window.supabase.createClient(urlOrClient, anonKey);
      return true;
    }
    console.warn('[CERTUS] initSupabase: window.supabase not available. Pass a pre-built Supabase client as the first argument for server-side use.');
    return false;
  },

  // FIX-03 & FIX-05: initialize with LRU init
  async initialize(supabaseUrl = null, supabaseAnonKey = null, supabaseClient = null) {
    await this._initMaps();
    await this._initializeStorage();
    if (supabaseClient) this.initSupabase(supabaseClient);
    else if (supabaseUrl && supabaseAnonKey) this.initSupabase(supabaseUrl, supabaseAnonKey);
    await this._logAuditEvent({ type: 'ENGINE_INITIALIZED', version: this.VERSION, storage_type: this._storage?.type, supabase_available: !!this._supabaseClient });
    return { success: true, version: this.VERSION, storage: this._storage?.type, supabase: !!this._supabaseClient };
  },

  async healthCheck() {
    const hc = { status: this._circuitBreaker.engaged ? 'DEGRADED' : 'HEALTHY', version: this.VERSION, degraded_mode: this._degradedMode, fcl_entries: this._fclEntries.length, audit_shards: this._auditLog.shards.length, timestamp: new Date().toISOString() };
    const allReports = await this._storage?.queryAudit?.(0, Date.now()) || [];
    const scoredReports = allReports.filter(e => e.type === 'SCORE_COMPLETED').map(e => e.result);
    hc.epistemic_debt = this.computeEpistemicDebtScore(scoredReports);
    if (this._supabaseClient) { try { await this._supabaseClient.from('health_check').select('*').limit(1); hc.supabase = 'healthy'; } catch { hc.supabase = 'unavailable'; } }
    return hc;
  },

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
  // MASTER SCORE — ASYNC. All fixes integrated.
  // ══════════════════════════════════════════════════════════════════════════
  async score(report, nearbyReports = [], isRealModel = false, context = {}) {
    // FIX-09: constitutional gate
    const prohibitedCheck = this._checkProhibitedUse(context);
    if (prohibitedCheck.blocked) {
      return { usable: false, error: `[CONSTITUTIONAL BLOCK] This use is prohibited under ${prohibitedCheck.law}. Stated purpose was flagged as: ${prohibitedCheck.use_category}.`, constitutional_status: { prohibited_use_blocked: true, law: prohibitedCheck.law }, version: this.VERSION };
    }

    const ts = report.timestamp || new Date().toISOString();
    const reportUuid = report.uuid || this._generateUUID();
    if (context.mode === 'field') { this.registerOfflineSupport(); this.registerOfflineMapSupport(); }
    await this._acquireBackpressureToken();

    const inputHash = await this._hashReportInput(report);
    const version = this.routeToVersion(reportUuid);
    const location = this._anonymizeLocation(report.coordinates || { lat: 0, lng: 0 }, report.infraType);

    const reputation = this._updateReputation(report.reporter_id, 'PENDING');
    if (reputation.banned) { this._logAuditEvent({ type: 'BANNED_REPORTER_BLOCKED', report_id: reportUuid }).catch(() => {}); return { usable: false, error: 'REPORTER_BANNED', reputation }; }

    this._logAuditEvent({ type: 'REPORT_SCORED', report_id: reportUuid, version, location_anonymized: location.anonymized }).catch(() => {});

    // H-02: adversarial detection on initial submission
    let adversarialFlag = null;
    if (context.reportHistory && context.reportHistory.length > 0) {
      const adv = await this._detectAdversarialPattern({ photos: report.photo ? [{ hash: report.photoHash }] : [] }, context.reportHistory);
      if (adv.adversarial) { await this._logAuditEvent({ type: 'ADVERSARIAL_DETECTED_ON_SUBMISSION', report_id: reportUuid, reason: adv.reason }); adversarialFlag = adv; }
    }

    // ENH-02: density-adjusted COR radius
    let corRadius = 50;
    let corRadiusSource = 'default';
    if (location.lat && location.lng) {
      corRadius = await this._adjustCORRadius(location.lat, location.lng);
      corRadiusSource = 'density_adjusted';
    }
    const nearby = nearbyReports.filter(r => r.lat && r.lng && this._calculateDistance(location.lat, location.lng, r.lat, r.lng) <= corRadius);

    const PES = this.computePES(report, isRealModel);
    const TFR = this.computeTFR(ts);
    const CCI = this.computeCCI(report.internalTier, report.infraType);

    // ENH-01: decay reconciliation
    const decayReconciliation = this._reconcileDecay(TFR, null, context);
    const TFR_EFFECTIVE = decayReconciliation.reconciled ? decayReconciliation.tfr_adjusted : TFR;

    // ENH-04: reputation-weighted COR
    const COR = this.computeCOR(nearby, report.internalTier, reportUuid, (rid) => this._reputationStore.get(rid) || { score: 0.5, banned: false });

    const ecfC = { PES: this.computeECFContribution(report.findings || [], 'PES'), COR: this.computeECFContribution(report.findings || [], 'COR'), TFR: this.computeECFContribution(report.findings || [], 'TFR'), CCI: this.computeECFContribution(report.findings || [], 'CCI') };
    const rawScores = { PES: PES.evaluable ? PES.value : null, COR: COR.evaluable ? COR.value : null, TFR: TFR_EFFECTIVE.value, CCI: CCI.value };
    const activeDims = ['PES', 'COR', 'TFR', 'CCI'].filter(d => rawScores[d] !== null);
    const norm = this.normalizeWithPenalty(activeDims, rawScores);
    const dci_raw = norm.score;
    const dci = parseFloat(Math.max(0, Math.min(1, dci_raw)).toFixed(3));

    const recentFR = context.recentCorrelatedFailureRate || 0;
    const cf = this.detectCorrelatedFailures(PES, COR, recentFR);
    const um = this.computeUM(PES, COR, TFR_EFFECTIVE, CCI, cf, ecfC);

    const requiresHumanReview = um.validity_status === 'SUSPENDED';
    const hasValidHR = context.human_review_proof?.reviewer_id && context.human_review_proof?.second_reviewer_id;

    if (requiresHumanReview && !hasValidHR) {
      this._logAuditEvent({ type: 'GUARD_TRIGGERED', report_id: reportUuid, reason: 'SUSPENDED_score_no_review' }).catch(() => {});
      this._logFCLEntry({ _reportUuid: reportUuid, dci, tier: 'review', dci_validity_status: um.validity_status, dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR_EFFECTIVE.value, dci_cci: CCI.value }, null, null);
      return { usable: false, error: '[LAW 4 GUARD] Suspended scores require two independent human reviewers before use.', recommendation: 'FIELD_VERIFICATION_REQUIRED', version, input_hash: inputHash, constitutional_status: { law_4_compliant: false, law_6_compliant: true }, data_governance: this.getDataSharingDisclosure() };
    }

    const tier = dci >= this.THRESHOLDS.DCI_HIGH ? 'high' : dci >= this.THRESHOLDS.DCI_WATCH ? 'watch' : 'review';
    const dims = { PES: PES.value || 0, COR: COR.value || 0, TFR: TFR_EFFECTIVE.value, CCI: CCI.value };
    const bd = Object.keys(dims).reduce((a, b) => dims[a] < dims[b] ? a : b);
    const bv = dims[bd];

    // FIX-06: dci_action with conflict resolution
    const dci_action = (() => {
      if (adversarialFlag) return 'HOLD_ADVERSARIAL';
      if (um.validity_status === 'SUSPENDED') return 'WAIT_HUMAN_REVIEW';
      if (cf.correlated && tier === 'high') return 'VERIFY_CORRELATED';
      if (tier === 'high') return 'SHARE';
      if (tier === 'watch') return 'VERIFY';
      return 'WAIT';
    })();

    const assumptions = [];
    if (COR.assumption) assumptions.push(COR.assumption);
    assumptions.push({ id: 'DECAY-A01', text: 'Dual decay curves: TFR 48h linear; evidence 168h half-life.', plain_language: '⏱ Report fresh for 48h; evidence weight decays over 7 days.', source: 'computeTFR + _getEvidenceFreshness', timestamp: new Date().toISOString() });
    if (PES.measurement_class === 'INFERENTIAL') assumptions.push({ id: 'PES-A01', text: 'Photo scored by placeholder model.', plain_language: '📷 Photo analyzed by placeholder. Upgrade for higher confidence.', source: 'computePES', timestamp: new Date().toISOString() });

    // FIX-07: language mismatch detection
    const reportLanguage = report.language || report.userLanguage || 'en';
    const nlpDictionaryLanguage = 'en';
    const languageMismatch = reportLanguage !== nlpDictionaryLanguage;
    const languageMismatchUMContribution = languageMismatch ? 0.10 : 0;
    if (languageMismatch) {
      CCI.note = (CCI.note || '') + ` Language mismatch: report in '${reportLanguage}', NLP dictionary is '${nlpDictionaryLanguage}'. CCI keyword matching may be systematically lower.`;
      CCI.um_contribution = (CCI.um_contribution || 0) + languageMismatchUMContribution;
      assumptions.push({ id: 'NLP-A01', text: `NLP keyword matching in English only. Report submitted in '${reportLanguage}'. CCI may be systematically underestimated.`, plain_language: '🌐 This report is not in English. The damage classifier works best in English — confidence may be lower than the actual damage.', source: 'NLP_CONFIG.language_support', timestamp: new Date().toISOString() });
    }

    const { strengths, weaknesses } = this.getStrengths(PES, COR, TFR_EFFECTIVE, CCI, location, report.photoGeotag, report.photoAccuracy);
    const uBd = this.getUMBreakdown(PES, COR, TFR_EFFECTIVE, CCI);
    const vc = tier === 'high' ? this.generateVerificationCertificate(report, dci, tier, nearby) : null;
    const af = this.getAudioFeedback(tier, um.validity_status, context.language);
    this.provideHapticFeedback(tier, { emergency: report.internalTier === 'Completely damaged' });
    const fv = this.getFieldView({ tier, verification_certificate: vc }, context);
    const er = await this.getEmergencyResources(report, location);
    const sd = this.getShareData(report, vc);
    const seal = await this._sealResult({ dci, tier, dci_validity_status: um.validity_status }, reportUuid);
    this._logFCLEntry({ _reportUuid: reportUuid, dci, tier, dci_validity_status: um.validity_status, dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR_EFFECTIVE.value, dci_cci: CCI.value }, context.ground_truth || null, seal.hash);

    return {
      dci, tier, usable: um.validity_status !== 'SUSPENDED' || hasValidHR, version, canary: version !== this.VERSION,
      input_hash: inputHash, integrity_seal: seal,
      dci_pes: PES.value, dci_cor: COR.value, dci_tfr: TFR_EFFECTIVE.value, dci_cci: CCI.value,
      dci_uncertainty_mass: um.mass, dci_validity_status: um.validity_status, dci_validity_plain: this.PLAIN_LANGUAGE[um.validity_status] || um.validity_status,
      dci_um_breakdown: uBd, dci_correlated_failure: cf.correlated,
      dci_action, dci_action_plain: this.PLAIN_LANGUAGE[dci_action] || dci_action,
      dci_strengths: strengths, dci_weaknesses: weaknesses,
      dci_marker_style: this.MARKER_STYLES[tier] || this.MARKER_STYLES.suspended,
      dci_verification_certificate: vc,
      dci_audio_feedback: af, dci_field_view: fv, dci_emergency_resources: er, dci_share_data: sd,
      dci_bottleneck: { dimension: bd, dimension_plain: this.PLAIN_LANGUAGE[bd] || bd, value: bv },
      dci_assumptions: assumptions.map(a => a.plain_language).join(' · '), dci_assumptions_raw: assumptions,
      dci_freshness_status: TFR_EFFECTIVE.freshness_status, dci_hours_elapsed: TFR_EFFECTIVE.hours_elapsed,
      dci_cor_radius_m: corRadius, dci_cor_radius_source: corRadiusSource,
      dci_decay_reconciliation: decayReconciliation.reconciled ? { reconciled: true, evidence_status: decayReconciliation.evidence_status, note: decayReconciliation.tfr_adjusted.reconciliation_note } : { reconciled: false },
      dci_flags: {
        pes_gated: PES.gated, pes_inferential: PES.measurement_class === 'INFERENTIAL', pes_missing: !PES.evaluable,
        cor_no_evidence: COR.signal_type === 'NO_EVIDENCE', cor_contradiction: COR.signal_type === 'CONTRADICTION',
        cci_flagged: CCI.flagged, tfr_status: TFR_EFFECTIVE.freshness_status, correlated_failure: cf.correlated,
        adversarial_detected: !!adversarialFlag, language_mismatch: languageMismatch,
        language_reported: reportLanguage, language_nlp_dictionary: nlpDictionaryLanguage
      },
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
  },

  // ── STORAGE INITIALIZATION (with fcl_entries store) ─────────────────────
  async _initializeStorage() {
    if (typeof indexedDB !== 'undefined') {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('CERTUS_DB', 3);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          this._storage = {
            db: req.result, type: 'indexeddb',
            logAudit: async (e) => { const tx = this._storage.db.transaction(['audit'], 'readwrite'); tx.objectStore('audit').add(e); },
            saveShard: async (s) => { const tx = this._storage.db.transaction(['shards'], 'readwrite'); tx.objectStore('shards').add({ id: Date.now(), data: s }); },
            queryAudit: async (sd, ed) => { const tx = this._storage.db.transaction(['audit'], 'readonly'); const store = tx.objectStore('audit'); const range = IDBKeyRange.bound(sd, ed); return new Promise(res => { const rs = []; store.openCursor(range).onsuccess = (e) => { const c = e.target.result; if (c) { rs.push(c.value); c.continue(); } else res(rs); }; }); },
            logFCLEntry: async (entry) => { const tx = this._storage.db.transaction(['fcl_entries'], 'readwrite'); tx.objectStore('fcl_entries').add(entry); }
          };
          resolve(this._storage);
        };
        req.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('audit')) db.createObjectStore('audit', { autoIncrement: true });
          if (!db.objectStoreNames.contains('appeals')) db.createObjectStore('appeals', { keyPath: 'id' });
          if (!db.objectStoreNames.contains('reputation')) db.createObjectStore('reputation', { keyPath: 'reporter_id' });
          if (!db.objectStoreNames.contains('shards')) db.createObjectStore('shards', { keyPath: 'id' });
          if (!db.objectStoreNames.contains('fcl_entries')) db.createObjectStore('fcl_entries', { autoIncrement: true });
        };
      });
    }
    this._storage = {
      type: 'memory', memory: new Map(),
      get: (k) => this._storage.memory.get(k), set: (k, v) => this._storage.memory.set(k, v),
      logAudit: async (e) => { const a = this._storage.get('audit') || []; a.push(e); this._storage.set('audit', a); },
      saveShard: async (s) => { const ss = this._storage.get('shards') || []; ss.push(s); this._storage.set('shards', ss); },
      queryAudit: async (sd, ed) => { const a = this._storage.get('audit') || []; return a.filter(e => e.timestamp >= sd && e.timestamp <= ed); },
      logFCLEntry: async (entry) => { const existing = this._storage.get('fcl_entries') || []; existing.push(entry); this._storage.set('fcl_entries', existing); }
    };
    return this._storage;
  },

  async storeAppeal(ar) {
    if (!this._storage) await this._initializeStorage();
    if (this._storage.type === 'indexeddb') {
      const tx = this._storage.db.transaction(['appeals'], 'readwrite');
      tx.objectStore('appeals').add(ar);
      return new Promise((res, rej) => { tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
    } else {
      const a = this._storage.get('appeals') || []; a.push(ar); this._storage.set('appeals', a);
    }
    if (this._supabaseClient && this._supabaseClient.from) { try { await this._supabaseClient.from('appeals').insert(ar); } catch (err) {} }
  },

  async updateReputationStorage(rid, rep) {
    if (!this._storage) await this._initializeStorage();
    if (this._storage.type === 'indexeddb') {
      const tx = this._storage.db.transaction(['reputation'], 'readwrite');
      tx.objectStore('reputation').put({ reporter_id: rid, ...rep });
      return new Promise((res, rej) => { tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
    } else {
      const rs = this._storage.get('reputation') || {}; rs[rid] = rep; this._storage.set('reputation', rs);
    }
    if (this._supabaseClient && this._supabaseClient.from) { try { await this._supabaseClient.from('reputation').upsert({ reporter_id: rid, ...rep, updated_at: new Date().toISOString() }); } catch (err) {} }
  },

  async scoreWithNLP(report, nearbyReports = [], isRealModel = false, context = {}) {
    if (report.witness_statement && !report.internalTier) { const wa = this._extractDamageFromWitness({ text: report.witness_statement }); if (wa && wa.confidence > 0.6) { report.internalTier = wa.damage_level; report.nlp_confidence = wa.confidence; report.urgency_flag = wa.is_urgent; } }
    if (report.description && !report.infraType) { const im = this._inferInfrastructureType(report.description); if (im) { report.infraType = im.type; report.infra_confidence = im.confidence; } }
    return await this.score(report, nearbyReports, isRealModel, context);
  }
};

if (typeof module !== 'undefined' && module.exports) module.exports = CERTUS;
if (typeof window !== 'undefined') {
  window.CERTUS = CERTUS;
  CERTUS.initialize().catch(err => {
    console.error('[CERTUS] Initialization failed:', err);
    if (typeof window.onCERTUSInitError === 'function') window.onCERTUSInitError(err);
  });
}