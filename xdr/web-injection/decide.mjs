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
      { field: 'repeat_count', operator: '>=', value: 8 },
      { field: 'level', operator: '>=', value: 10 },
    ],
    basis: 'APT41 used SQL injection for initial access in C0017, APT28, APT39, Axiom, Agrius, Dragonfly, Night Dragon and Operation Digital Eye used SQL injection, and Havij and sqlmap automate it (T1190).',
  },
  {
    id: 'script-tag-injection',
    name: 'Script Tag Injection In Request Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'script_tag_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 5 },
      { field: 'level', operator: '>=', value: 10 },
    ],
    basis: 'Winter Vivern exploited Roundcube Webmail servers and the page cites the OWASP top 10 web flaws, no CVE for script injection is named on the page (T1190).',
  },
  {
    id: 'command-injection-marker',
    name: 'Operating System Command Injection Markers',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'command_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 5 },
      { field: 'level', operator: '>=', value: 10 },
    ],
    basis: 'Cutting Edge exploited Ivanti Connect Secure command injection (CVE-2024-21887) and the Mexico government breach used remote command execution on an internet-facing server (T1190).',
  },
  {
    id: 'path-traversal-sequence',
    name: 'Directory Traversal Sequences In Request Paths',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'traversal_sequence_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 5 },
      { field: 'level', operator: '>=', value: 10 },
    ],
    basis: 'APT41 exploited Citrix ADC directory traversal (CVE-2019-19781) and traversal flaws in C0017, APT29 and Dragonfly reused CVE-2019-19781 and FortiOS CVE-2018-13379 (T1190).',
  },
  {
    id: 'remote-lookup-string',
    name: 'Remote Lookup String In Request Headers Or Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'remote_lookup_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 3 },
      { field: 'level', operator: '>=', value: 9 },
    ],
    basis: 'APT41 in C0017, C0018, Magic Hound and Cinnamon Tempest exploited Log4Shell (CVE-2021-44228) through remote lookup strings (T1190).',
  },
  {
    id: 'serialized-object-payload',
    name: 'Serialized Object Payload In Request Data',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'serialized_marker_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 3 },
      { field: 'level', operator: '>=', value: 9 },
    ],
    basis: 'APT41 exploited Zoho ManageEngine unsafe deserialization (CVE-2020-10189), Blue Mockingbird exploited Telerik CVE-2019-18935 and FIN13 used WebSphere SOAP deserialization CVE-2015-7450 (T1190).',
  },
  {
    id: 'expression-language-injection',
    name: 'Expression Language Injection In Request Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'expression_marker_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 3 },
      { field: 'level', operator: '>=', value: 9 },
    ],
    basis: 'FIN13 exploited Primefaces expression language injection (CVE-2017-1000486), Ember Bear exploited Confluence CVE-2021-26084 and Rocke exploited Apache Struts (T1190).',
  },
  {
    id: 'ssrf-internal-target',
    name: 'Server Side Request Forgery Toward Internal Targets',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'ssrf_target_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 3 },
      { field: 'level', operator: '>=', value: 8 },
    ],
    basis: 'Cutting Edge chained Ivanti SSRF CVE-2024-21893, the Anthropic AI-orchestrated Campaign targeted an SSRF flaw, and the page names the Cloud Instance Metadata API as a follow-up (T1190).',
  },
  {
    id: 'vulnerability-scanner-trace',
    name: 'Known Vulnerability Scanner Or Checking Tool Trace',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'scanner_signature_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 10 },
      { field: 'level', operator: '>=', value: 6 },
    ],
    basis: 'sqlmap and Havij are listed as automated SQL injection tools and Volatile Cedar used automatic vulnerability discovery against public web servers (T1190).',
  },
  {
    id: 'exploit-request-then-web-shell',
    name: 'Known Exploit Endpoint Followed By Web Shell Or Command Execution',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'exploit_endpoint_count', operator: '>=', value: 1 },
      { field: 'webshell_marker_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 2 },
    ],
    basis: 'SharePoint ToolShell Exploitation used crafted POST requests to ToolPane.aspx (CVE-2025-49704), the Mexico breach planted a web shell, and BlackByte and APT41 used ProxyLogon and ProxyShell (T1190).',
  },
];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const TAG_WEIGHT = 0.4;
const PATTERN_WEIGHT = 0.35;
const REPEAT_WEIGHT = 0.15;
const LEVEL_WEIGHT = 0.1;
const REPEAT_FULL = 8;
const LEVEL_FLOOR = 4;
const LEVEL_RANGE = 6;
const NO_SIGNATURE_REASON = 'Repeated T1190 web request without a specific pattern signature';
const NO_MATCH_REASON = 'No known web-injection pattern matched';

const SQL_WORDS = new Set([
  'select', 'insert', 'update', 'delete', 'union', 'drop', 'where', 'from', 'having',
  'sleep', 'benchmark', 'waitfor', 'sql', 'or', 'and',
]);
const SQL_METACHARS = ["'", '"', '--', ';', '/*', '*/'];
const SCRIPT_MARKERS = ['<script', '</script', 'javascript:', 'onerror=', 'onload=', '<svg', '<iframe'];
const COMMAND_WORDS = new Set(['cmd', 'command', 'exec', 'bash', 'powershell', 'wget', 'curl', 'whoami', 'netcat']);
const SHELL_METACHARS = [';', '|', '&&', '`', '$('];
const LOOKUP_PATTERN = /\$\{(?:jndi|\$\{|[a-z]+:-|lower:|upper:|env:|::-)/g;
const LOOKUP_SCHEMES = ['ldap:', 'ldaps:', 'rmi:', 'dns:', 'iiop:'];
const SERIALIZED_MARKERS = [
  'ro0ab', 'aced0005', 'aaeaaad/////', 'ysoserial', '__viewstate', 'objectinputstream',
  'binaryformatter', 'typeconfusedelegate', 'objectdataprovider',
];
const EXPRESSION_MARKERS = ['#{', '%{', 'ognl', 'getruntime', 'java.lang.', 'processbuilder', '.getclass('];
const SSRF_TARGETS = [
  '169.254.169.254', 'metadata.google.internal', '127.0.0.1', 'localhost', '[::1]',
  'file://', 'gopher://', 'dict://',
];
const SCANNER_SIGNATURES = [
  'sqlmap', 'havij', 'nikto', 'nmap', 'masscan', 'nuclei', 'acunetix', 'zgrab',
  'dirbuster', 'wpscan', 'nessus', 'openvas',
];
const EXPLOIT_ENDPOINTS = [
  '/_layouts/15/toolpane.aspx', '/autodiscover/autodiscover.json', '/vpns/portal/scripts', '/vpn/../vpns/',
  '/api/v1/totp/user-backup-code', '/remote/fgt_lang', '/dana-na/', '/tmui/login.jsp', '/ecp/',
  '/global-protect/', '/rest/tinymce/1/macro/preview', '/mgmt/tm/util/bash',
];
const WEBSHELL_MARKERS = [
  'webshell', 'web shell', 'china chopper', 'shell.aspx', 'shell.jsp', 'shell.php',
  'cmd.aspx', 'cmd.jsp', 'whoami', 'powershell', 'aspxspy', 'b374k',
];

function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

function decodeRepeatedly(text) {
  let current = text;
  for (let pass = 0; pass < 3; pass += 1) {
    let next;
    try {
      next = decodeURIComponent(current.replace(/\+/gu, ' '));
    } catch {
      return current;
    }
    if (next === current) return current;
    current = next;
  }
  return current;
}

function textOf(alert) {
  const source = alert && typeof alert === 'object' ? alert : {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const rule = source.rule && typeof source.rule === 'object' ? source.rule : {};
  const parts = [data.url, data.useragent, rule.description]
    .map((part) => (typeof part === 'string' ? part : ''));
  return decodeRepeatedly(parts.join(' ')).toLowerCase();
}

function countDistinct(text, markers) {
  let count = 0;
  for (const marker of markers) if (text.includes(marker)) count += 1;
  return count;
}

function countOccurrences(text, word) {
  let count = 0;
  let index = text.indexOf(word);
  while (index !== -1) {
    count += 1;
    index = text.indexOf(word, index + word.length);
  }
  return count;
}

function countWords(tokens, words) {
  let count = 0;
  for (const word of words) if (tokens.has(word)) count += 1;
  return count;
}

function extractFeatures(alert) {
  const source = alert && typeof alert === 'object' ? alert : {};
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  const rule = source.rule && typeof source.rule === 'object' ? source.rule : {};
  const text = textOf(alert);
  const tokens = new Set(text.split(/[^a-z0-9]+/u).filter(Boolean));
  const count = Number(data.count);
  const level = Number(rule.level);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : [];

  const lookupMatches = text.match(LOOKUP_PATTERN);
  const remoteLookupCount = lookupMatches ? lookupMatches.length : 0;
  const hasPlainExpression = text.includes('${') && remoteLookupCount === 0;

  return {
    level: Number.isFinite(level) ? level : 0,
    repeat_count: Number.isFinite(count) && count >= 1 ? count : 1,
    t1190_tag: mitre.some((id) => typeof id === 'string' && id.toUpperCase() === 'T1190') ? 1 : 0,
    sql_keyword_count: countWords(tokens, SQL_WORDS),
    sql_metachar_count: countDistinct(text, SQL_METACHARS),
    script_tag_count: countDistinct(text, SCRIPT_MARKERS),
    command_marker_count: countWords(tokens, COMMAND_WORDS) + countDistinct(text, SHELL_METACHARS),
    traversal_sequence_count: (text.match(/\.\.[/\\]/gu) || []).length,
    remote_lookup_count: remoteLookupCount,
    lookup_scheme_count: countDistinct(text, LOOKUP_SCHEMES),
    serialized_marker_count: countDistinct(text, SERIALIZED_MARKERS),
    expression_marker_count: countDistinct(text, EXPRESSION_MARKERS) + (hasPlainExpression ? 1 : 0),
    ssrf_target_count: countDistinct(text, SSRF_TARGETS),
    scanner_signature_count: countDistinct(text, SCANNER_SIGNATURES),
    exploit_endpoint_count: countDistinct(text, EXPLOIT_ENDPOINTS),
    webshell_marker_count: countDistinct(text, WEBSHELL_MARKERS),
  };
}

function conditionScore(value, condition) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  if (condition.operator === '>=') {
    if (value >= condition.value) return 1;
    return condition.value > 0 ? value / condition.value : 0;
  }
  if (condition.operator === '<=') {
    if (value <= condition.value) return 1;
    return value > 0 ? condition.value / value : 0;
  }
  return 0;
}

function scorePattern(pattern, features) {
  const scores = pattern.conditions.map((condition) => conditionScore(features[condition.field], condition));
  const total = scores.reduce((sum, score) => sum + score, 0);
  return { score: total / scores.length, specific: scores[0] };
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
    let bestSpecificScore = 0;
    let strongest = 0;
    for (const pattern of PATTERNS) {
      const { score, specific } = scorePattern(pattern, features);
      if (score > strongest) strongest = score;
      if (specific > 0 && score > bestSpecificScore) {
        best = pattern;
        bestSpecificScore = score;
      }
    }

    const repeatScore = clamp((features.repeat_count - 1) / (REPEAT_FULL - 1), 0, 1);
    const levelScore = clamp((features.level - LEVEL_FLOOR) / LEVEL_RANGE, 0, 1);
    const confidence = round2(clamp(
      TAG_WEIGHT * features.t1190_tag
        + PATTERN_WEIGHT * strongest
        + REPEAT_WEIGHT * repeatScore
        + LEVEL_WEIGHT * levelScore,
      0,
      1,
    ));
    const action = pickAction(confidence);
    let reason = NO_MATCH_REASON;
    if (best) reason = best.name;
    else if (action !== 'record') reason = NO_SIGNATURE_REASON;
    return { action, confidence, reason };
  } catch {
    return { action: 'record', confidence: 0, reason: 'Alert could not be evaluated' };
  }
}
