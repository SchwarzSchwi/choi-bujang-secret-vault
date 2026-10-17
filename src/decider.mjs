// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
const REQUEST_KEYS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
].sort().join(',');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const NOTE_PATH = /^\/notes\/[^/]+$/u;

export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

function response(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  };
}

function hasVerifiedPrincipal(request) {
  return request && typeof request === 'object' && !Array.isArray(request)
    && Object.keys(request).sort().join(',') === REQUEST_KEYS
    && request.schema === 'aleph.decision.v1'
    && typeof request.requestId === 'string' && UUID.test(request.requestId)
    && typeof request.classId === 'string' && request.classId.length > 0
    && typeof request.projectId === 'string' && request.projectId.length > 0
    && typeof request.subjectId === 'string' && request.subjectId.length > 0
    && typeof request.deviceId === 'string' && DEVICE_ID.test(request.deviceId);
}

function isVaultRead(request) {
  return request.service === 'notes'
    && request.method === 'GET'
    && request.route === 'GET /notes/:id'
    && typeof request.path === 'string' && NOTE_PATH.test(request.path);
}

export async function decide(request) {
  if (!hasVerifiedPrincipal(request) || request.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', 'device_registered');
  }
  if (!isVaultRead(request)) {
    return response(request, 'deny', 'starter_not_ready', 'starter.deny');
  }
  return response(request, 'allow', 'approved', 'device_registered');
}
