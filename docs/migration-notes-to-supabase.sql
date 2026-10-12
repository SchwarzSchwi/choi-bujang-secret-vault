-- Migration: notes 테이블을 현재 API(api/notes.js, api/notes/[id].js)에 맞춘다.
-- 현재 스키마: id UUID, owner_id UUID NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL
-- 서버 함수는 SUPABASE_SECRET_KEY(service role)로만 접근하므로, 브라우저(anon/authenticated)는
-- notes 테이블을 직접 읽거나 쓰지 못하게 막는다.
-- 여러 번 실행해도 안전하게 작성했다.

-- 0. 옛 구조(id BIGSERIAL, title 없음)가 있으면 지우지 않고 이름만 바꿔 보관한다.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'notes'
      AND column_name = 'id' AND data_type <> 'uuid'
  ) THEN
    ALTER TABLE public.notes RENAME TO notes_legacy_bigint;
  END IF;
END $$;

-- 1. 테이블 생성
CREATE TABLE IF NOT EXISTS public.notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- 2. 목록 조회(owner_id 필터 + created_at 정렬)용 인덱스
CREATE INDEX IF NOT EXISTS notes_owner_created_idx
  ON public.notes (owner_id, created_at);

-- 3. RLS 활성화
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;

-- 4. anon / authenticated 역할은 읽기·쓰기 모두 불가 (서버의 service role 키는 RLS를 우회한다)
DROP POLICY IF EXISTS "no_anon_read" ON public.notes;
DROP POLICY IF EXISTS "no_authenticated_read" ON public.notes;
DROP POLICY IF EXISTS "no_anon_write" ON public.notes;
DROP POLICY IF EXISTS "no_authenticated_write" ON public.notes;

CREATE POLICY "no_anon_read" ON public.notes
  AS PERMISSIVE FOR SELECT TO anon USING (false);

CREATE POLICY "no_authenticated_read" ON public.notes
  AS PERMISSIVE FOR SELECT TO authenticated USING (false);

CREATE POLICY "no_anon_write" ON public.notes
  AS PERMISSIVE FOR ALL TO anon USING (false) WITH CHECK (false);

CREATE POLICY "no_authenticated_write" ON public.notes
  AS PERMISSIVE FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- 5. 가상 메모는 더 이상 SQL로 넣지 않는다.
--    owner_id가 NOT NULL이고 메모는 로그인한 사용자가 화면/API(POST /api/notes)로 추가한다.
--    (4단계에서 소유자 검사를 API에 추가할 예정. 지금은 B가 A의 메모를 고칠 수 있다.)
