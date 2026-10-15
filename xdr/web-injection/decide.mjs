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
  {
    id: 'jndi-lookup-injection',
    name: 'JNDI Lookup Injection (Log4Shell Style)',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'jndi_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'C0018 and Magic Hound exploited Log4Shell (CVE-2021-44228) in VMware Horizon and Log4j; APT41 did so during C0017 (T1190).',
  },
  {
    id: 'expression-language-injection',
    name: 'OGNL / Expression Language Injection',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'expression_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Rocke exploited Apache Struts, FIN13 exploited Primefaces EL injection (CVE-2017-1000486), and Ember Bear exploited Confluence OGNL (CVE-2021-26084) (T1190).',
  },
  {
    id: 'unsafe-deserialization',
    name: 'Unsafe Object Deserialization Payload',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'deserialization_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'APT41 exploited Zoho ManageEngine unsafe deserialization (CVE-2020-10189) and .NET deserialization; FIN13 abused WebSphere SOAP deserialization (CVE-2015-7450); Blue Mockingbird exploited Telerik (CVE-2019-18935) (T1190).',
  },
  {
    id: 'command-injection',
    name: 'OS Command Injection In Request Parameters',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'command_marker_count', operator: '>=', value: 2 },
      { field: 'shell_metachar_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Cutting Edge threat actors used Ivanti Connect Secure command injection (CVE-2024-21887); Rocke and Quad7 achieved remote code execution via exposed services and SOHO routers (T1190).',
  },
  {
    id: 'ssrf-internal-fetch',
    name: 'Server-Side Request Forgery To Internal Resources',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'ssrf_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Anthropic AI-orchestrated Campaign used a custom exploit for an SSRF vulnerability, and ProxyLogon (CVE-2021-26855) is an SSRF used by Threat Group-3390, HAFNIUM, ToddyCat and BlackByte (T1190).',
  },
  {
    id: 'exchange-proxy-exploit',
    name: 'Microsoft Exchange ProxyLogon / ProxyShell Request Paths',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'exchange_path_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'APT28, Threat Group-3390, HAFNIUM, Magic Hound, Play and BlackByte exploited Exchange (CVE-2020-0688, ProxyLogon, ProxyShell, ProxyNotShell) (T1190).',
  },
  {
    id: 'sharepoint-exploit',
    name: 'Microsoft SharePoint Exploit Request Paths',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'sharepoint_path_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Threat Group-3390, VOID MANTICORE, HomeLand Justice and SharePoint ToolShell Exploitation exploited SharePoint (CVE-2019-0604, CVE-2025-49706, CVE-2025-49704) (T1190).',
  },
  {
    id: 'edge-vpn-appliance-exploit',
    name: 'VPN / Edge Appliance Exploit Request Paths',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'edge_path_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'APT29, APT5, Volt Typhoon, Fox Kitten, UNC3886, Operation MidnightEclipse and Salt Typhoon exploited Citrix, Pulse/Ivanti, FortiOS, Palo Alto GlobalProtect and Cisco devices (T1190).',
  },
  {
    id: 'auth-bypass-path-confusion',
    name: 'Authentication Bypass By Path Confusion',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'auth_bypass_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Cutting Edge used Ivanti authentication bypass (CVE-2023-46805), SharePoint ToolShell used authentication bypass (CVE-2025-49706), and the Fortinet CVE-2022-40684 style bypass abuses path handling (T1190).',
  },
  {
    id: 'web-shell-upload',
    name: 'Web Shell Upload Or Execution Request',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'webshell_marker_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'Public-facing servers (JBoss, WebLogic, GlassFish, Exchange, Confluence) exploited by Operation Wocao, GOLD SOUTHFIELD, Earth Lusca and Cinnamon Tempest were followed by web shell deployment (T1190).',
  },
  {
    id: 'exposed-service-probe',
    name: 'Probe Of Exposed Network Service Or Management Protocol',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'exposed_service_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 5 },
    ],
    basis: 'T1190 covers databases, SMB, SSH, SNMP and Smart Install exposed to the Internet; Qilin was delivered via exposed Citrix and RDP (T1190).',
  },
  {
    id: 'exposed-admin-misconfiguration',
    name: 'Exposed Admin Interface Or Misconfiguration Probe',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'exposed_admin_count', operator: '>=', value: 2 },
      { field: 'repeat_count', operator: '>=', value: 3 },
    ],
    basis: 'ShadowRay exploited exposed Ray servers (CVE-2023-48022) and TeamPCP abused misconfigured GitHub Actions and cloud services (T1190).',
  },
  {
    id: 'automated-exploit-tool',
    name: 'Automated Exploitation Tool Signature',
    mitreSubTechnique: 'T1190',
    conditions: [
      { field: 'tool_signature_count', operator: '>=', value: 1 },
      { field: 'repeat_count', operator: '>=', value: 5 },
    ],
    basis: 'sqlmap and Havij automate SQL injection, Volatile Cedar used automatic vulnerability discovery, and Anthropic AI-orchestrated Campaign automated exploitation with Claude Code (T1190).',
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
const JNDI_WORDS = ['${jndi:', 'jndi:ldap', 'jndi:rmi', 'jndi:dns', 'ldap://', 'rmi://'];
const EXPRESSION_WORDS = ['%{', '${', '#{', '#_memberaccess', 'ognl', 'java.lang.runtime', 'processbuilder', 'getruntime'];
const DESERIALIZATION_WORDS = ['viewstate', 'ro0ab', 'aced0005', 'objectinputstream', 'ysoserial', '__type', 'soapaction', 'rawprefix'];
const COMMAND_WORDS = ['whoami', 'wget ', 'curl ', '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell', 'nc -e', 'certutil', 'base64 -d'];
const SHELL_METACHARS = ['|', '`', '$(', '&&', '%0a', '%7c', ';'];
const SSRF_WORDS = ['169.254.169.254', 'metadata.google', '127.0.0.1', 'localhost', 'file://', 'gopher://', 'dict://', 'x-beresource'];
const EXCHANGE_WORDS = ['/autodiscover/', '/ecp/', '/owa/', '/mapi/', '/powershell', 'x-beresource', 'x-anonresource', '/aspnet_client/', 'autodiscover.json'];
const SHAREPOINT_WORDS = ['/_layouts/', 'toolpane.aspx', 'listform.aspx', '/_vti_bin/', 'spinstall', 'editmode=true', 'webpartpages'];
const EDGE_WORDS = ['/vpn/', '/vpns/', '/dana-na/', '/remote/logincheck', '/remote/fgt_lang', '/global-protect', '/ssl-vpn/', '/api/v2/cmdb', '/mgmt/tm/', '/tmui/', '/webvpn', '/+cscoe+/', '/api/v1/totp', '/ws/v1/cs/', '/cgi-bin/'];
const AUTH_BYPASS_WORDS = ['..;/', '/;/', '%00', '%2f..', ';jsessionid', 'x-forwarded-for', 'bypass', '%252e'];
const WEBSHELL_WORDS = ['.jsp', '.jspx', '.aspx', '.php', '.war', 'cmd=', 'eval(', 'passthru', 'base64_decode', 'webshell', 'multipart/form-data'];
const SERVICE_WORDS = ['snmp', 'smb', 'ssh', 'rdp', 'smartinstall', ':445', ':3389', ':4786', ':161', ':22', ':6379', ':27017', ':5432', ':3306'];
const ADMIN_WORDS = ['/admin', '/console', '/actuator', '/manager/html', '/.git/', '/.env', '/api/jobs', '/jenkins', '/phpmyadmin', '/solr', '/containers/json'];
const TOOL_WORDS = ['sqlmap', 'havij', 'nuclei', 'nikto', 'masscan', 'zgrab', 'metasploit', 'acunetix'];

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

  const tally = (words) => {
    let found = 0;
    for (const word of words) if (text.includes(word)) found += 1;
    return found;
  };

  return {
    level: Number.isFinite(level) ? level : 0,
    repeat_count: Number.isFinite(count) ? count : 1,
    sql_keyword_count: sqlKeywordCount,
    sql_metachar_count: sqlMetacharCount,
    script_tag_count: scriptTagCount,
    event_handler_count: /on[a-z]+=/u.test(text) ? 1 : 0,
    traversal_sequence_count: traversalSequenceCount,
    decoded_traversal_levels: decodedTraversalLevels,
    jndi_marker_count: tally(JNDI_WORDS),
    expression_marker_count: tally(EXPRESSION_WORDS),
    deserialization_marker_count: tally(DESERIALIZATION_WORDS),
    command_marker_count: tally(COMMAND_WORDS),
    shell_metachar_count: tally(SHELL_METACHARS),
    ssrf_marker_count: tally(SSRF_WORDS),
    exchange_path_count: tally(EXCHANGE_WORDS),
    sharepoint_path_count: tally(SHAREPOINT_WORDS),
    edge_path_count: tally(EDGE_WORDS),
    auth_bypass_marker_count: tally(AUTH_BYPASS_WORDS),
    webshell_marker_count: tally(WEBSHELL_WORDS),
    exposed_service_count: tally(SERVICE_WORDS),
    exposed_admin_count: tally(ADMIN_WORDS),
    tool_signature_count: tally(TOOL_WORDS),
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
