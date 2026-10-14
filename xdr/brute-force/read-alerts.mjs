// 확인용 읽기 모듈: xdr/fixtures/brute-force.json 의 경보에서
// 시각·출발 주소·계정·규칙 수준·설명만 뽑아 한 경보당 한 줄로 보여 준다.
// - 원본 경보 파일은 읽기만 하고 고치지 않는다.
// - 비밀값처럼 보이는 값(토큰, 키, 비밀번호 값 등)은 [가림]으로 바꿔 출력한다.
// - 이 파일은 확인용이다. decide.mjs 는 이 파일을 import 하지 않는다.
//
// 실행: node xdr/brute-force/read-alerts.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const FIXTURE_URL = new URL('../fixtures/brute-force.json', import.meta.url);
const MASK = '[가림]';

// 비밀값처럼 보이는 형태. 위에서부터 차례로 적용한다.
const SECRET_PATTERNS = [
  /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b/gu,                 // JWT
  /\bBearer\s+[\w.~+/=-]{8,}/giu,                              // Bearer 토큰
  /\b(?:sb|sk|pk|ghp|gho|ghs|github_pat|xox[a-z])[_-][\w-]{8,}/giu, // 서비스 키 접두어
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)\s*[:=]\s*\S+/giu, // 이름=값
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
  /\b[A-Fa-f0-9]{32,}\b/gu,                                    // 긴 16진수
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/gu,                            // 긴 base64/토큰 모양
];

export function mask(value) {
  if (value === undefined || value === null) return '';
  let text = String(value).replace(/[\r\n\t]+/gu, ' ');
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, MASK);
  return text.trim();
}

// 경보 하나에서 필요한 다섯 칸만 뽑는다. 원본 객체는 고치지 않는다.
export function pickFields(alert) {
  return {
    time: mask(alert?.timestamp),
    srcip: mask(alert?.data?.srcip),
    srcuser: mask(alert?.data?.srcuser),
    level: mask(alert?.rule?.level),
    description: mask(alert?.rule?.description),
  };
}

export function readAlerts(url = FIXTURE_URL) {
  const fixture = JSON.parse(readFileSync(url, 'utf8'));
  if (!Array.isArray(fixture?.alerts)) throw new Error('alerts 배열이 없습니다.');
  return { total: fixture.alerts.length, rows: fixture.alerts.map(pickFields) };
}

export function formatRow(row) {
  return [row.time, row.srcip, row.srcuser, `수준 ${row.level}`, row.description].join(' | ');
}

function main() {
  const { total, rows } = readAlerts();
  const lines = rows.map(formatRow);
  for (const line of lines) console.log(line);
  console.log(`경보 ${total}건 / 뽑은 줄 ${lines.length}줄 / ${total === lines.length ? '일치' : '불일치'}`);
  if (total !== lines.length) process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(`읽기 실패: ${error.message}`);
    process.exitCode = 1;
  }
}
