// xdr/brute-force/decide.mjs
// 심판이 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// - import 문 없음, 파일 읽기/쓰기 없음, 바깥 호출 없음. 혼자 계산해서 바로 답한다.
// - 아래 PATTERNS 는 xdr/brute-force/patterns.json 의 내용을 그대로 옮겨 적은 상수다.
//   (patterns.json 을 고치면 이 상수도 같이 고친다.)
// - confidence(0~1)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 스스로 매긴 값이다.

const PATTERNS = [
  {
    id: 'login-failure-burst',
    name: 'Repeated Login Failure Burst',
    mitreSubTechnique: 'T1110.001',
    conditions: [
      { field: 'failed_count', operator: '>=', value: 30 },
      { field: 'window_seconds', operator: '<=', value: 180 },
      { field: 'distinct_accounts', operator: '<=', value: 2 },
    ],
    basis: 'Emotet, OilRig and Dragonfly guessed passwords against few accounts with many rapid failed logins (T1110.001).',
  },
  {
    id: 'shared-password-multi-account',
    name: 'Shared Password Across Many Accounts',
    mitreSubTechnique: 'T1110.003',
    conditions: [
      { field: 'distinct_accounts', operator: '>=', value: 8 },
      { field: 'max_attempts_per_account', operator: '<=', value: 3 },
      { field: 'unique_password_ratio', operator: '<=', value: 0.1 },
    ],
    basis: 'APT28, APT29 (2023-24 Microsoft mail intrusion) and APT33 sprayed one common password across many accounts (T1110.003).',
  },
  {
    id: 'leaked-credential-multi-account',
    name: 'Leaked Credential Pairs Across Many Accounts',
    mitreSubTechnique: 'T1110.004',
    conditions: [
      { field: 'distinct_accounts', operator: '>=', value: 10 },
      { field: 'max_attempts_per_account', operator: '<=', value: 2 },
      { field: 'unique_password_ratio', operator: '>=', value: 0.9 },
    ],
    basis: 'Chimera and the 2023 23andMe incident replayed leaked username/password pairs, one attempt per account (T1110.004).',
  },
];

// 행동 기준: 0.85 이상 block, 0.5 이상 alert, 그 아래 record.
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// confidence = 패턴 일치도 60% + 경보 규칙 수준 40%.
const PATTERN_WEIGHT = 0.6;
const LEVEL_WEIGHT = 0.4;
const LEVEL_FLOOR = 2;   // 이 수준 이하는 0점
const LEVEL_RANGE = 10;  // 수준 12 이상은 만점

// 경보 설명(한국어)에서 수치를 뽑는 정규식. 코드는 영문/유니코드 이스케이프만 쓴다.
const WINDOW_MINUTES_TEXT = /(\d+)\s*\uBD84/u;                     // "<N>minutes"
const ACCOUNT_COUNT_TEXT = /\uACC4\uC815\s*(\d+)\s*\uAC1C/u;       // "accounts <N>"
const SAME_PASSWORD_TEXT = /\uAC19\uC740\s*\uBE44\uBC00\uBC88\uD638/u; // "same password"

// "same password" 문구가 있으면 비밀번호가 거의 하나라는 뜻으로 낮은 비율을 준다.
const SHARED_PASSWORD_RATIO = 0.05;

function toNumber(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

// 경보 한 건에서 패턴 조건에 쓸 수치를 뽑는다. 없는 값은 null.
function extractFeatures(alert) {
  const source = alert !== null && typeof alert === 'object' ? alert : {};
  const data = source.data !== null && typeof source.data === 'object' ? source.data : {};
  const rule = source.rule !== null && typeof source.rule === 'object' ? source.rule : {};
  const description = typeof rule.description === 'string' ? rule.description : '';

  let accounts = null;
  if (typeof data.accounts === 'string') {
    const names = new Set(data.accounts.split(',').map((s) => s.trim()).filter(Boolean));
    if (names.size > 0) accounts = names.size;
  }
  if (accounts === null) {
    const match = ACCOUNT_COUNT_TEXT.exec(description);
    if (match) accounts = Number(match[1]);
  }

  const failed = toNumber(data.count);
  const windowMatch = WINDOW_MINUTES_TEXT.exec(description);

  return {
    level: toNumber(rule.level) ?? 0,
    hasUser: typeof data.srcuser === 'string' && data.srcuser.length > 0,
    failed_count: failed,
    window_seconds: windowMatch ? Number(windowMatch[1]) * 60 : null,
    distinct_accounts: accounts,
    max_attempts_per_account: failed !== null && accounts !== null && accounts > 0 ? failed / accounts : null,
    unique_password_ratio: SAME_PASSWORD_TEXT.test(description) ? SHARED_PASSWORD_RATIO : null,
  };
}

// 조건 하나의 일치도(0~1). 만족하면 1, 못 미치면 기준에 가까운 정도에 따라 부분 점수.
function conditionScore(value, condition) {
  if (condition.operator === '>=') {
    if (value >= condition.value) return 1;
    return condition.value > 0 ? Math.sqrt(value / condition.value) : 0;
  }
  if (condition.operator === '<=') {
    if (value <= condition.value) return 1;
    return value > 0 ? Math.sqrt(condition.value / value) : 0;
  }
  return 0;
}

// 패턴 하나의 일치도. 첫 조건은 관문이라 경보에서 잴 수 없으면 0점.
// 나머지 조건은 잴 수 있는 것만 평균낸다. 계정 수를 모르면 한 계정으로 본다.
function scorePattern(pattern, features) {
  let total = 0;
  let known = 0;
  for (let i = 0; i < pattern.conditions.length; i += 1) {
    const condition = pattern.conditions[i];
    let value = features[condition.field];
    if ((value === null || value === undefined) && i > 0 && condition.field === 'distinct_accounts' && features.hasUser) {
      value = 1;
    }
    if (value === null || value === undefined) {
      if (i === 0) return 0;
      continue;
    }
    total += conditionScore(value, condition);
    known += 1;
  }
  return known > 0 ? total / known : 0;
}

function pickAction(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

export function decide(alert) {
  try {
    const features = extractFeatures(alert);

    let best = null;
    let bestScore = 0;
    for (const pattern of PATTERNS) {
      const score = scorePattern(pattern, features);
      if (score > bestScore) {
        best = pattern;
        bestScore = score;
      }
    }

    const levelScore = clamp((features.level - LEVEL_FLOOR) / LEVEL_RANGE, 0, 1);
    const confidence = round2(clamp(PATTERN_WEIGHT * bestScore + LEVEL_WEIGHT * levelScore, 0, 1));
    const action = pickAction(confidence);

    let reason = 'No known brute-force pattern matched';
    if (best !== null) {
      reason = action === 'record'
        ? `Weak match: ${best.name} (${best.mitreSubTechnique})`
        : `${best.name} (${best.mitreSubTechnique})`;
    }
    return { action, confidence, reason };
  } catch {
    return { action: 'record', confidence: 0, reason: 'Alert could not be evaluated' };
  }
}
