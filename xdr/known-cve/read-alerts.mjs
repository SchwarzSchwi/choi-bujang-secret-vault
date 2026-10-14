// known-cve 경보 읽기 모듈 (확인용).
// xdr/fixtures/known-cve.json 에서 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다.
// 원본 경보는 읽기만 하고 고치지 않습니다. 비밀값처럼 보이는 값은 [가림] 으로 바꿔 출력합니다.
// 이 파일은 확인용입니다. decide.mjs 는 이 파일을 불러오지 않습니다.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MASK = '[가림]';

// 비밀값처럼 보이는 형태: 이름=값, Bearer 토큰, 흔한 키 접두어, 긴 16진수·base64 덩어리, 개인키 블록
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|비밀번호|토큰)\b\s*[:=]\s*\S+/gi,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\b(?:sk|pk|ghp|gho|ghs|github_pat|xox[baprs]|AKIA|eyJ)[A-Za-z0-9_-]{8,}/g,
  /\b[A-Fa-f0-9]{32,}\b/g,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
];

export function maskSecrets(value) {
  let text = String(value ?? '');
  for (const pattern of SECRET_PATTERNS) text = text.replace(pattern, MASK);
  return text;
}

function pick(value) {
  return value === undefined || value === null || value === '' ? '-' : maskSecrets(value);
}

export function extractAlert(alert) {
  return {
    time: pick(alert?.timestamp),
    srcip: pick(alert?.data?.srcip),
    account: pick(alert?.data?.srcuser),
    level: pick(alert?.rule?.level),
    description: pick(alert?.rule?.description),
  };
}

export async function readAlerts(root) {
  const path = join(root, 'xdr', 'fixtures', 'known-cve.json');
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'known-cve' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  return fixture.alerts.map(extractAlert);
}

export function formatLine(row) {
  return [row.time, row.srcip, row.account, `level=${row.level}`, row.description].join(' | ');
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const rows = await readAlerts(root);
    const lines = rows.map(formatLine);
    for (const line of lines) console.log(line);
    const total = rows.length;
    const ok = lines.length === total;
    console.log(`경보 ${total}건 / 뽑은 줄 ${lines.length}줄 → ${ok ? '일치' : '불일치'}`);
    if (!ok) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
