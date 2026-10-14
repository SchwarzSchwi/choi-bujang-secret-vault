// xdr/known-cve/decide.mjs
// 심판이 인터넷 없이 이 파일 하나만 불러와 경보마다 decide(alert)를 부른다.
// - import 문 없음, 파일 읽기/쓰기 없음, 바깥 호출 없음. 혼자 계산해서 바로 답한다.
// - 아래 PATTERNS 는 xdr/known-cve/patterns.json 의 내용을 그대로 옮겨 적은 상수다.
// - confidence(0~1)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 스스로 매긴 값이다.
//   confidence = 0.5 * 악용 신호 + 0.3 * 패턴 일치도 + 0.2 * 경보 수준
//   (악용 신호: 경보에 T1190 표시가 있거나 패턴이 뚜렷하게 맞을 때 1, 아니면 0)

const PATTERNS = [
  {
    id: 'remote-lookup-header-injection',
    name: 'Remote Lookup Or Expression Injection In Request Headers And Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'lookup_token_count', operator: '>=', value: 1 },
      { field: 'obfuscation_layer_count', operator: '>=', value: 2 },
      { field: 'injected_header_count', operator: '>=', value: 2 },
    ],
    basis: 'Log4Shell (CVE-2021-44228) attacks by Khonsari and Night Sky ransomware operators planted nested JNDI lookups in User-Agent and other headers, and Confluence OGNL injection (CVE-2022-26134) used the same request-side pattern (T1190).',
  },
  {
    id: 'known-cve-scanner-trace',
    name: 'Known Vulnerability Scanner And Mass Probe Traces',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'distinct_cve_path_count', operator: '>=', value: 3 },
      { field: 'requests_per_minute', operator: '>=', value: 30 },
      { field: 'scanner_signature_count', operator: '>=', value: 1 },
    ],
    basis: 'Mass scanning for Citrix ADC (CVE-2019-19781) and Exchange ProxyLogon (CVE-2021-26855) began within days of disclosure, and Hafnium probed many Exchange servers before exploiting them (T1190).',
  },
  {
    id: 'exploit-to-code-execution-chain',
    name: 'Exploit Request Followed By Web Shell Or Command Execution',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'command_token_count', operator: '>=', value: 1 },
      { field: 'script_file_write_count', operator: '>=', value: 1 },
      { field: 'seconds_to_follow_up', operator: '<=', value: 60 },
    ],
    basis: 'Hafnium chained Exchange CVE-2021-26855 and CVE-2021-27065 to drop China Chopper web shells, and Mirai botnet operators used Spring4Shell (CVE-2022-22965) to write a JSP web shell and run commands (T1190).',
  },
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const SIGNAL_WEIGHT = 0.5;
const PATTERN_WEIGHT = 0.3;
const LEVEL_WEIGHT = 0.2;
const LEVEL_FLOOR = 4;
const LEVEL_RANGE = 6;
const CLEAR_MATCH_AT = 0.5;
const WEAK_MATCH_AT = 0.2;
const MITRE_TAG = 'T1190';
const MAX_UNWRAP_ROUNDS = 5;

const SCANNER_SIGNATURES = [
  'nuclei', 'zgrab', 'masscan', 'nmap', 'nikto', 'sqlmap', 'acunetix',
  'log4j-scan', 'log4shell-scanner', 'interact.sh', 'oast.', 'dnslog',
  'burpcollaborator', 'canarytokens',
];
const COMMAND_TOKENS = [
  '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell', 'whoami', 'wget ', 'curl ',
  'runtime.getruntime', 'processbuilder', 'nc -e',
];

const LOOKUP_PATTERN = /\$\{jndi:[^}]*\}/giu;
const WRAPPER_PATTERN = /\$\{(?:lower:|upper:|::-|[^:}$]*:-)([^${}]*)\}/giu;
const CVE_PATTERN = /cve-\d{4}-\d{4,7}/giu;
const WEB_SHELL_PATTERN = /(?:shell|cmd|chopper|backdoor|tomcatwar)[a-z0-9_-]*\.(?:jsp|jspx|aspx|php)\b/giu;

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function asObject(value) {
  return value && typeof value === 'object' ? value : {};
}

function decodeText(value) {
  let out = typeof value === 'string' ? value : '';
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(out.replace(/\+/gu, ' '));
      if (next === out) break;
      out = next;
    } catch {
      break;
    }
  }
  return out;
}

// ${lower:j} 나 ${::-j} 같은 감싸기를 풀어 낸다. 풀린 횟수가 가림 겹 수다.
function unwrap(text) {
  let out = text;
  let layers = 0;
  for (let i = 0; i < MAX_UNWRAP_ROUNDS; i += 1) {
    let changed = 0;
    out = out.replace(WRAPPER_PATTERN, (_match, inner) => {
      changed += 1;
      return inner;
    });
    if (changed === 0) break;
    layers += changed;
  }
  return { text: out, layers };
}

function countMatches(text, pattern) {
  const found = text.match(pattern);
  return found ? found.length : 0;
}

function countTokens(text, tokens) {
  let total = 0;
  for (const token of tokens) if (text.includes(token)) total += 1;
  return total;
}

function finiteOr(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

// 요청 머리글 값과 인자 값을 각각 한 칸으로 본다.
function requestFields(alert) {
  const data = asObject(asObject(alert).data);
  const headerValues = [data.useragent];
  const headers = asObject(data.headers);
  for (const key of Object.keys(headers)) headerValues.push(headers[key]);
  const parameterValues = [data.url, data.query];
  return [...headerValues, ...parameterValues]
    .filter((value) => typeof value === 'string' && value.length > 0)
    .map((value) => decodeText(value));
}

function extractFeatures(alert) {
  const source = asObject(alert);
  const data = asObject(source.data);
  const rule = asObject(source.rule);
  const fields = requestFields(source);

  let lookupTokenCount = 0;
  let injectedFieldCount = 0;
  let wrapperLayers = 0;
  for (const field of fields) {
    const unwrapped = unwrap(field);
    const lookups = countMatches(unwrapped.text, LOOKUP_PATTERN);
    lookupTokenCount += lookups;
    if (lookups > 0) {
      injectedFieldCount += 1;
      wrapperLayers += unwrapped.layers;
    }
  }

  const joined = fields.join(' ').toLowerCase();
  const cveIds = new Set((joined.match(CVE_PATTERN) ?? []).map((id) => id.toLowerCase()));
  const repeatCount = finiteOr(data.count, 1);
  const followUp = Number(data.followup_seconds);
  const tags = Array.isArray(rule.mitre) ? rule.mitre : [];

  return {
    level: finiteOr(rule.level, 0),
    tagged: tags.some((tag) => String(tag).toUpperCase().startsWith(MITRE_TAG)),
    lookup_token_count: lookupTokenCount,
    obfuscation_layer_count: (lookupTokenCount > 0 ? 1 : 0) + wrapperLayers,
    injected_header_count: injectedFieldCount,
    distinct_cve_path_count: cveIds.size,
    // 경보 한 건이 묶는 시간 안의 요청 수를 분당 요청 수로 본다. 값이 따로 오면 그 값을 쓴다.
    requests_per_minute: finiteOr(data.requests_per_minute, repeatCount),
    scanner_signature_count: countTokens(joined, SCANNER_SIGNATURES),
    command_token_count: countTokens(joined, COMMAND_TOKENS),
    script_file_write_count: countMatches(joined, WEB_SHELL_PATTERN),
    seconds_to_follow_up: Number.isFinite(followUp) && data.followup_seconds !== undefined ? followUp : null,
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

// 관측되지 않은 값(null)은 건너뛰고, 첫 조건 값이 없으면 맞지 않는 것으로 본다.
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

    const signal = features.tagged || bestScore >= CLEAR_MATCH_AT ? 1 : 0;
    const levelScore = clamp((features.level - LEVEL_FLOOR) / LEVEL_RANGE, 0, 1);
    const confidence = round2(
      clamp(SIGNAL_WEIGHT * signal + PATTERN_WEIGHT * bestScore + LEVEL_WEIGHT * levelScore, 0, 1),
    );
    const action = pickAction(confidence);

    let reason = 'No known-CVE exploit pattern matched';
    if (best && bestScore >= WEAK_MATCH_AT) reason = best.name;
    else if (features.tagged) reason = 'Tagged T1190 but no known-CVE pattern matched clearly';
    return { action, confidence, reason };
  } catch {
    return { action: 'record', confidence: 0, reason: 'Alert could not be evaluated' };
  }
}
