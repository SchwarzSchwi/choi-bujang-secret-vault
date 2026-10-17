import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id));
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('6단계 device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const missingRegistration = { ...normal, requestId: randomUUID() };
  delete missingRegistration.deviceRegistered;
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow',
      reasonCode: 'approved', ruleId: 'device_registered' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered',
      ruleId: 'device_registered' },
    { name: '등록 여부 누락', request: missingRegistration, decision: 'deny',
      reasonCode: 'device_not_registered', ruleId: 'device_registered' },
    ...[undefined, null, 'true', 'false', 1, 0, {}, []].map((deviceRegistered, index) => ({
      name: `불리언이 아닌 등록 여부 ${index + 1}`,
      request: { ...normal, requestId: randomUUID(), deviceRegistered },
      decision: 'deny', reasonCode: 'device_not_registered', ruleId: 'device_registered',
    })),
    ...[
      { schema: 'invalid' },
      { subjectId: undefined }, { subjectId: null }, { subjectId: '' }, { subjectId: ' ' },
      { subjectId: 1 }, { deviceId: undefined }, { deviceId: null }, { deviceId: '' },
      { deviceId: 'invalid' }, { deviceId: 'A'.repeat(16) }, { deviceId: 1 },
    ].map((fields, index) => ({
      name: `유효하지 않은 주체·기기 문맥 ${index + 1}`,
      request: { ...normal, ...fields, requestId: randomUUID() },
      decision: 'deny', reasonCode: 'device_not_registered', ruleId: 'device_registered',
    })),
    ...[
      { service: 'other' }, { method: 'POST' }, { route: 'GET /other/:id' },
      { path: '/other/demo' }, { path: '/notes' }, { path: '/notes/' },
      { path: '/notes/demo/extra' }, { path: undefined }, { path: null },
      { path: '/notes/demo?query' }, { path: '/notes/demo#fragment' },
    ].map((fields, index) => ({
      name: `지원하지 않는 동작·경로 ${index + 1}`,
      request: { ...normal, ...fields, requestId: randomUUID() },
      decision: 'deny', reasonCode: 'starter_not_ready', ruleId: 'starter.deny',
    })),
  ];
  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow' },
    );
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && (!item.reasonCode || response.reasonCode === item.reasonCode)
      && (!item.ruleId || response.ruleIds.includes(item.ruleId));
    results.push({ name: item.name, passed: valid,
      decision: response?.decision, reasonCode: response?.reasonCode });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(
      `${item.passed ? '통과' : '확인 필요'} · ${item.name}: ${item.decision}/${item.reasonCode}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
