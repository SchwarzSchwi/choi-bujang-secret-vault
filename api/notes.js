// Supabase notes 테이블 읽기
// SUPABASE_URL, SUPABASE_SECRET_KEY 환경변수 사용
// 키를 응답, 로그에 노출하지 않음

import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifier;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

function unauthorized(res) {
  return res.status(401).json({ error: 'Unauthorized' });
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 로그인 토큰 검사: Authorization 헤더만 사용, 통과 전에는 자료를 읽지 않음
  const authorization = req.headers?.authorization;
  if (typeof authorization !== 'string' || !authorization) return unauthorized(res);
  let identity = null;
  try {
    identity = await getVerifier().verifyLoginAuthorization(authorization);
  } catch {
    return unauthorized(res);
  }
  if (!identity) return unauthorized(res);

  // 환경변수 검증 (키 노출 금지)
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }

  // 서버 전용 클라이언트 (환경변수에서만 읽음, 브라우저 전송 안 함)
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false } }
  );

  try {
    // notes 테이블에서 모든 행 읽음
    const { data, error } = await supabase
      .from('notes')
      .select('id, title, content, created_at')
      .order('created_at', { ascending: true });

    if (error) {
      // 에러 상세는 로그만 (클라이언트에는 안 넘김)
      console.error('Database query failed');
      return res.status(500).json({ error: 'Failed to fetch notes' });
    }

    // 응답에는 Supabase URL, 키, 내부 정보 없음
    res.status(200).json({ notes: data || [] });
  } catch (err) {
    console.error('Unexpected server error');
    res.status(500).json({ error: 'Internal server error' });
  }
}
