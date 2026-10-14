// xdr/web-injection/respond.mjs
// decide.mjs 의 결과를 받아 조치하는 파일이다. decide.mjs 자체는 판단만 하고 이 파일을 모른다.
// - action 이 block 인 경보만 거부 규칙 후보가 된다.
// - 규칙은 xdr/web-injection/deny-rules.json 에 쌓는다. 규칙마다 만료 시각과 근거 경보 번호가 붙는다.
// - 알림(block, alert)은 xdr/alerts.log 에 한 줄씩 덧붙인다. record 는 남기지 않는다.
// - 요청 주소(url)는 쿼리에 값이 섞일 수 있어 규칙과 로그에 넣지 않는다.
// - src/decider.mjs 의 기존 규칙은 읽지도 고치지도 않는다.
// 실행: node xdr/web-injection/respond.mjs   (xdr/fixtures/web-injection.json 을 다시 흘려 본다)

import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const RULES_PATH = resolve(HERE, 'deny-rules.json');
const LOG_PATH = resolve(HERE, '..', 'alerts.log');
const FIXTURE_PATH = resolve(HERE, '..', 'fixtures', 'web-injection.json');

const MODULE_KEY = 'web-injection';
const RULES_SCHEMA = 'aleph.xdr.deny-rules.v1';
const RULE_TTL_SECONDS = 3600;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;

// 막으면 안 되는 주소: 자기 자신, 지정되지 않은 주소.
function isNeverBlocked(ip) {
  return ip.startsWith('127.') || ip === '0.0.0.0';
}

function srcipOf(alert) {
  const ip = alert?.data?.srcip;
  return typeof ip === 'string' && IPV4.test(ip) ? ip : null;
}

function alertIdOf(alert) {
  return typeof alert?.id === 'string' && alert.id.length > 0 ? alert.id : null;
}

// 로그 한 줄에 들어가는 값에서 줄바꿈과 구분자를 없앤다.
function clean(value) {
  return String(value ?? '').replace(/[\r\n\t|]+/gu, ' ').trim();
}

export async function loadRules(path = RULES_PATH) {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8'));
    if (parsed?.schema === RULES_SCHEMA && Array.isArray(parsed.rules)) return parsed.rules;
  } catch {
    // 파일이 아직 없거나 깨졌으면 빈 목록에서 시작한다.
  }
  return [];
}

// 만료되지 않은 규칙만 돌려준다. 판정기 쪽 연결은 이 목록을 읽는다.
export async function activeRules(now = new Date(), path = RULES_PATH) {
  const rules = await loadRules(path);
  return rules.filter((rule) => Date.parse(rule.expiresAt) > now.getTime());
}

async function saveRules(rules, path = RULES_PATH) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify({ schema: RULES_SCHEMA, moduleKey: MODULE_KEY, rules }, null, 2)}\n`, 'utf8');
}

async function writeLogLine(now, decision, alert, note, logPath = LOG_PATH) {
  const line = [
    now.toISOString(),
    MODULE_KEY,
    clean(decision.action),
    clean(alertIdOf(alert) ?? 'no-id'),
    clean(srcipOf(alert) ?? 'no-ip'),
    clean(decision.confidence),
    clean(note),
  ].join(' | ');
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, `${line}\n`, 'utf8');
}

// 경보 하나를 처리한다. trustedIps 에 든 주소는 정상 활동이 확인된 곳이라 막지 않는다.
export async function respond(alert, { now = new Date(), trustedIps = new Set(), paths = {} } = {}) {
  const decision = decide(alert);
  const rulesPath = paths.rules ?? RULES_PATH;
  const logPath = paths.log ?? LOG_PATH;

  if (decision.action === 'record') return { decision, rule: null };

  if (decision.action === 'alert') {
    await writeLogLine(now, decision, alert, decision.reason, logPath);
    return { decision, rule: null };
  }

  // block 후보: 근거 경보 번호와 올바른 주소가 있고, 정상 활동이 확인된 주소가 아닐 때만 규칙을 만든다.
  const ip = srcipOf(alert);
  const alertId = alertIdOf(alert);
  if (ip === null || alertId === null || isNeverBlocked(ip) || trustedIps.has(ip)) {
    await writeLogLine(now, { ...decision, action: 'alert' }, alert, `block skipped: ${decision.reason}`, logPath);
    return { decision, rule: null };
  }

  const rules = await loadRules(rulesPath);
  const existing = rules.find((rule) => rule.match?.srcip === ip && Date.parse(rule.expiresAt) > now.getTime());
  if (existing) {
    await writeLogLine(now, decision, alert, `rule already active: ${existing.ruleId}`, logPath);
    return { decision, rule: existing };
  }

  const rule = {
    ruleId: `xdr.web-injection.deny.${ip}`,
    effect: 'deny',
    match: { srcip: ip },
    evidenceAlertId: alertId,
    confidence: decision.confidence,
    reason: decision.reason,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + RULE_TTL_SECONDS * 1000).toISOString(),
  };
  // 만료된 규칙은 이때 같이 정리한다.
  const kept = rules.filter((r) => Date.parse(r.expiresAt) > now.getTime());
  await saveRules([...kept, rule], rulesPath);
  await writeLogLine(now, decision, alert, `deny rule added: ${rule.ruleId}`, logPath);
  return { decision, rule };
}

// 경보 묶음을 다시 흘린다. 먼저 모두 판정해 record 로 나온 경보의 주소를 정상 주소로 모은 뒤,
// 그 주소는 block 이 나와도 규칙에서 뺀다.
export async function replay(alerts, options = {}) {
  const trustedIps = new Set();
  for (const alert of alerts) {
    const ip = srcipOf(alert);
    if (ip !== null && decide(alert).action === 'record') trustedIps.add(ip);
  }
  const results = [];
  for (const alert of alerts) {
    const out = await respond(alert, { ...options, trustedIps });
    results.push({
      alertId: alertIdOf(alert),
      action: out.decision.action,
      ruleId: out.rule ? out.rule.ruleId : null,
    });
  }
  return results;
}

async function main() {
  const fixture = JSON.parse(await readFile(FIXTURE_PATH, 'utf8'));
  if (!Array.isArray(fixture?.alerts)) throw new Error('alerts array is missing');
  const results = await replay(fixture.alerts);
  const blocked = results.filter((r) => r.ruleId !== null).length;
  for (const r of results) console.log(`${r.alertId} -> ${r.action}${r.ruleId ? ` (${r.ruleId})` : ''}`);
  console.log(`alerts ${results.length} / deny rules touched ${blocked}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : 'run error');
    process.exitCode = 1;
  });
}
