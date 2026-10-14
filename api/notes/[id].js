// 메모 한 건 읽기(GET)·수정(PUT)·삭제(DELETE).
// URL·본문의 owner_id는 믿지 않고, 토큰 검사로 확인된 login.userId와 DB owner_id를 비교한다.
// 남의 메모는 존재 여부를 숨기기 위해 404로 응답한다.
// SUPABASE_URL, SUPABASE_SECRET_KEY 환경변수 사용 (키는 응답·로그에 노출 안 함)

import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

let verifier = null;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  }
  return verifier;
}

const METHODS = ['GET', 'PUT', 'DELETE'];

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }
  if (!METHODS.includes(req.method)) {
    res.setHeader('Allow', METHODS.join(', '));
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let login;
  try {
    login = await getVerifier()(req.headers.authorization);
  } catch {
    console.error('Login verifier unavailable');
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }
  if (!login) return res.status(401).json({ error: 'Login required' });

  const id = req.query?.id;
  if (typeof id !== 'string' || !id || id.length > 64) {
    return res.status(400).json({ error: 'invalid id' });
  }

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false } });

  try {
    // 기존 행의 소유자 확인 (읽기·수정·삭제 공통)
    const { data: row, error: findError } = await supabase.from('notes')
      .select('id, title, content, owner_id')
      .eq('id', id)
      .maybeSingle();
    if (findError) {
      console.error('Database query failed');
      return res.status(500).json({ error: 'Failed to fetch note' });
    }
    if (!row || row.owner_id !== login.userId) {
      return res.status(404).json({ error: 'Note not found' });
    }

    if (req.method === 'GET') {
      return res.status(200).json({ id: row.id, title: row.title, body: row.content });
    }

    if (req.method === 'DELETE') {
      const { data: deleted, error } = await supabase.from('notes')
        .delete()
        .eq('id', id)
        .eq('owner_id', login.userId)
        .select('id');
      if (error) {
        console.error('Database delete failed');
        return res.status(500).json({ error: 'Failed to delete note' });
      }
      if (!deleted || deleted.length === 0) return res.status(404).json({ error: 'Note not found' });
      return res.status(200).json({ id });
    }

    // PUT: {title, body}. owner_id가 들어오면 소유자 변경 시도로 보고 거부한다.
    const input = req.body && typeof req.body === 'object' ? req.body : {};
    if ('owner_id' in input || 'ownerId' in input) {
      return res.status(403).json({ error: 'Owner cannot be changed' });
    }
    const { title, body } = input;
    if (typeof title !== 'string' || !title.trim() || typeof body !== 'string') {
      return res.status(400).json({ error: 'title and body are required' });
    }
    // owner_id는 수정 값에 넣지 않고, 조건에 확인된 ID를 다시 건다.
    const { data: updated, error } = await supabase.from('notes')
      .update({ title, content: body })
      .eq('id', id)
      .eq('owner_id', login.userId)
      .select('id, title, content, owner_id');
    if (error) {
      console.error('Database update failed');
      return res.status(500).json({ error: 'Failed to update note' });
    }
    // 새 행의 소유자도 본인인지 확인
    if (!updated || updated.length !== 1 || updated[0].owner_id !== login.userId) {
      return res.status(404).json({ error: 'Note not found' });
    }
    return res.status(200).json({ id: updated[0].id, title: updated[0].title, body: updated[0].content });
  } catch {
    console.error('Unexpected server error');
    return res.status(500).json({ error: 'Internal server error' });
  }
}
