// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 규칙에 해당하지 않으면 기본 응답으로 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

export async function decide(request) {
  if (request.service === 'notes' && request.method === 'GET'
      && request.route === 'GET /notes/:id') {
    const registered = request.deviceRegistered === true;
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
