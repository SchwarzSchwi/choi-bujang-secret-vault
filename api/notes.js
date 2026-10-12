// 메모 목록(GET)·추가(POST). 모두 서버가 검사한 로그인 사용자만 가능.
// 브라우저가 보낸 userId·role은 읽지 않고, 토큰 검사 결과의 userId만 사용한다.
// SUPABASE_URL, SUPABASE_SECRET_KEY 환경변수 사용 (키는 응답·로그에 노출 안 함)

import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

let verifier = null;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  }
  return verifier;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Server configuration incomplete' });
  }
  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
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

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false } });

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase.from('notes')
        .select('id, title, content')
        .eq('owner_id', login.userId)
        .order('created_at', { ascending: true });
      if (error) {
        console.error('Database query failed');
        return res.status(500).json({ error: 'Failed to fetch notes' });
      }
      return res.status(200).json((data || []).map(n => ({ id: n.id, title: n.title, body: n.content })));
    }

    // POST: {id?, title, body}
    const input = req.body && typeof req.body === 'object' ? req.body : {};
    const { title, body } = input;
    if (typeof title !== 'string' || !title.trim() || typeof body !== 'string') {
      return res.status(400).json({ error: 'title and body are required' });
    }
    if (input.id !== undefined && (typeof input.id !== 'string' || !UUID.test(input.id))) {
      return res.status(400).json({ error: 'id must be a UUID' });
    }
    const id = input.id ?? randomUUID();
    const { error } = await supabase.from('notes')
      .insert({ id, owner_id: login.userId, title, content: body });
    if (error) {
      console.error('Database insert failed');
      return res.status(error.code === '23505' ? 409 : 500)
        .json({ error: error.code === '23505' ? 'id already exists' : 'Failed to create note' });
    }
    return res.status(201).json({ id });
  } catch {
    console.error('Unexpected server error');
    return res.status(500).json({ error: 'Internal server error' });
  }
}
