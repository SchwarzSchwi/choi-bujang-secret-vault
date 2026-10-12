// Supabase notes 테이블 읽기 (로그인 토큰 검사 후에만)
// SUPABASE_URL, SUPABASE_SECRET_KEY 환경변수 사용
// 키를 응답, 로그에 노출하지 않음

import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifier = null;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  // 환경변수 검증 (키 노출 금지)
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }

  // 1) 토큰 검사: 브라우저가 보낸 userId·role 등은 읽지 않고, 검사 결과만 믿는다.
  let login = null;
  try {
    login = await getVerifier()(req.headers.authorization);
  } catch {
    // 설정 오류 등: 자료 없이 거부
    console.error('Login verifier unavailable');
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }
  if (!login) {
    return res.status(401).json({ error: 'Login required' });
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
