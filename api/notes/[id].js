// 메모 한 건 조회(GET)·수정(PUT)·삭제(DELETE): /api/notes/:id
// 로그인 여부만 검사한다. 소유자 검사는 아직 없다 (4단계에서 추가 예정: B가 A의 메모를 고칠 수 있는 허점).

import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

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
  if (!['GET', 'PUT', 'DELETE'].includes(req.method)) {
    res.setHeader('Allow', 'GET, PUT, DELETE');
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
  if (typeof id !== 'string' || !UUID.test(id)) {
    return res.status(404).json({ error: 'Not found' });
  }

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false } });

  try {
    if (req.method === 'GET') {
      const { data, error } = await supabase.from('notes')
        .select('id, title, content').eq('id', id).maybeSingle();
      if (error) {
        console.error('Database query failed');
        return res.status(500).json({ error: 'Failed to fetch note' });
      }
      if (!data) return res.status(404).json({ error: 'Not found' });
      return res.status(200).json({ id: data.id, title: data.title, body: data.content });
    }

    if (req.method === 'PUT') {
      const input = req.body && typeof req.body === 'object' ? req.body : {};
      if (typeof input.title !== 'string' || !input.title.trim() || typeof input.body !== 'string') {
        return res.status(400).json({ error: 'title and body are required' });
      }
      // owner_id는 바꾸지 않는다.
      const { data, error } = await supabase.from('notes')
        .update({ title: input.title, content: input.body, updated_at: new Date().toISOString() })
        .eq('id', id).select('id, title, content');
      if (error) {
        console.error('Database update failed');
        return res.status(500).json({ error: 'Failed to update note' });
      }
      if (!data || data.length === 0) return res.status(404).json({ error: 'Not found' });
      return res.status(200).json({ id: data[0].id, title: data[0].title, body: data[0].content });
    }

    // DELETE
    const { data, error } = await supabase.from('notes').delete().eq('id', id).select('id');
    if (error) {
      console.error('Database delete failed');
      return res.status(500).json({ error: 'Failed to delete note' });
    }
    if (!data || data.length === 0) return res.status(404).json({ error: 'Not found' });
    return res.status(200).json({ id });
  } catch {
    console.error('Unexpected server error');
    return res.status(500).json({ error: 'Internal server error' });
  }
}
