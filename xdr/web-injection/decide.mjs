// xdr/web-injection/decide.mjs
// 심판이 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// - import 문 없음, 파일 읽기/쓰기 없음, 바깥 호출 없음. 혼자 계산해서 바로 답한다.
// - 아래 PATTERNS 는 xdr/web-injection/patterns.json 의 내용을 그대로 옮겨 적은 상수다.
// - confidence(0~1)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 스스로 매긴 값이다.

const PATTERNS = [
  {
    id: 'sql-statement-injection',
    name: 'SQL Statement Injection In Request Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'sql_keyword_count', operator: '>=', value: 2 },
      { field: 'sql_metachar_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 8 },
    ],
    basis: 'Cl0p exploited the MOVEit Transfer SQL injection (CVE-2023-34362) and APT41 used SQL injection against public web applications (T1190).',
  },
  {
    id: 'script-tag-injection',
    name: 'Script Tag Injection In Request Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'script_tag_count', operator: '>=', value: 1 },
      { field: 'event_handler_count', operator: '>=', value: 0 },
      { field: 'repeat_count', operator: '>=', value: 5 },
    ],
    basis: 'APT28 and Winter Vivern sent script injection payloads to Roundcube webmail (CVE-2020-35730, CVE-2023-5631) to run code in victim sessions (T1190).',
  },
  {
    id: 'path-traversal-repeat',
    name: 'Repeated Parent Directory Traversal Sequences',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'traversal_sequence_count', operator: '>=', value: 3 },
      { field: 'decoded_traversal_levels', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 5 },
    ],
    basis: 'APT41 exploited the Citrix ADC directory traversal (CVE-2019-19781) and UNC5221 the Ivanti Connect Secure path traversal (CVE-2023-46805) (T1190).',
  },
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const PATTERN_WEIGHT = 0.6;
const LEVEL_WEIGHT = 0.4;
const LEVEL_FLOOR = 2;
const LEVEL_RANGE = 10;

const SQL_WORDS = ['select', 'insert', 'update', 'delete', 'union', 'where', 'from', 'or', 'and'];
const SCRIPT_WORDS = ['<script', '</script', 'onerror=', 'onload=', 'javascript:'];
const TRAVERSAL_WORDS = ['../', '..\\'];

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function textOf(alert) {
  const source = alert && typeof alert === 'object' ? alert : {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const rule = source.rule && typeof source.rule === 'object' ? source.rule : {};
  const url = typeof data.url === 'string' ? data.url : '';
  const description = typeof rule.description === 'string' ? rule.description : '';
  const id = typeof source.id === 'string' ? source.id : '';
  return `${url} ${description} ${id}`.toLowerCase();
}

function extractFeatures(alert) {
  const source = alert && typeof alert === 'object' ? alert : {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const rule = source.rule && typeof source.rule === 'object' ? source.rule : {};
  const text = textOf(alert);
  const url = typeof data.url === 'string' ? data.url : '';
  const count = Number(data.count);
  const level = Number(rule.level);

  let sqlKeywordCount = 0;
  for (const word of SQL_WORDS) if (text.includes(word)) sqlKeywordCount += 1;

  let sqlMetacharCount = 0;
  if (text.includes("'")) sqlMetacharCount += 1;
  if (text.includes('"')) sqlMetacharCount += 1;
  if (text.includes('--')) sqlMetacharCount += 1;
  if (text.includes(';')) sqlMetacharCount += 1;
  if (text.includes('/*')) sqlMetacharCount += 1;
  if (text.includes('*/')) sqlMetacharCount += 1;

  let scriptTagCount = 0;
  for (const word of SCRIPT_WORDS) if (text.includes(word)) scriptTagCount += 1;

  let traversalSequenceCount = 0;
  for (const word of TRAVERSAL_WORDS) {
    let index = text.indexOf(word);
    while (index !== -1) {
      traversalSequenceCount += 1;
      index = text.indexOf(word, index + word.length);
    }
  }
  const decodedTraversalLevels = traversalSequenceCount;

  return {
    level: Number.isFinite(level) ? level : 0,
    repeat_count: Number.isFinite(count) ? count : 1,
    sql_keyword_count: sqlKeywordCount,
    sql_metachar_count: sqlMetacharCount,
    script_tag_count: scriptTagCount,
    event_handler_count: /on[a-z]+=/u.test(text) ? 1 : 0,
    traversal_sequence_count: traversalSequenceCount,
    decoded_traversal_levels: decodedTraversalLevels,
    urlLength: url.length,
  };
}

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

function scorePattern(pattern, features) {
  let total = 0;
  let known = 0;
  for (let i = 0; i < pattern.conditions.length; i += 1) {
    const condition = pattern.conditions[i];
    const value = features[condition.field];
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
    const reason = best ? best.name : 'No known web-injection pattern matched';
    return { action, confidence, reason };
  } catch {
    return { action: 'record', confidence: 0, reason: 'Alert could not be evaluated' };
  }
}
