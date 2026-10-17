// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 기기·주체의 연결은 엔진이 사전 검증하며, 지원하지 않는 요청은 기본 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

export async function decide(request) {
  if (request.service === 'notes' && request.method === 'GET'
      && request.route === 'GET /notes/:id'
      && typeof request.path === 'string' && /^\/notes\/[^/?#]+$/u.test(request.path)) {
    const registered = request.schema === 'aleph.decision.v1'
      && typeof request.subjectId === 'string' && request.subjectId.trim().length > 0
      && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/u.test(request.deviceId)
      && request.deviceRegistered === true;
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: registered ? 'allow' : 'deny',
      reasonCode: registered ? 'approved' : 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [RULE_IDS[0]],
  };
}
