import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

test('등록 기기의 자료 읽기만 device_registered 규칙으로 허용한다', async () => {
  assert.deepEqual(RULE_IDS, ['starter.deny', 'device_registered']);
  assert.ok(Object.isFrozen(RULE_IDS));
  const { normal } = fixtureRequests();
  assert.deepEqual(await decide(normal), {
    schema: 'aleph.decision.v1',
    requestId: normal.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  });
});

test('미등록, 누락, boolean이 아닌 기기 상태는 거부한다', async () => {
  const { normal } = fixtureRequests();
  const missing = { ...normal };
  delete missing.deviceRegistered;
  const requests = [
    missing,
    ...[false, undefined, null, 'true', 'false', 1, 0, {}, []]
      .map(deviceRegistered => ({ ...normal, deviceRegistered })),
  ];
  for (const request of requests) {
    assert.deepEqual(await decide(request), {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    });
  }
});

test('다른 서비스, 메서드, 경로의 기존 시작용 거부는 유지한다', async () => {
  const { normal } = fixtureRequests();
  const requests = [
    ...['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']
      .map(method => ({ ...normal, method })),
    { ...normal, service: 'other' },
    { ...normal, route: 'GET /other/:id' },
    { ...normal, route: undefined },
  ];
  for (const request of requests) {
    assert.deepEqual(await decide(request), {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'starter_not_ready',
      ruleIds: ['starter.deny'],
    });
  }
});
