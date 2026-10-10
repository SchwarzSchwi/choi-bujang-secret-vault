-- Supabase 학습용 메모 테이블 초기화 (2단계)
-- 가상 메모를 코드 밖 Supabase로 옮깁니다.
-- owner_id uuid 칼럼을 두되 auth.users 외래키 제약은 없습니다.

-- 1. 테이블 생성
CREATE TABLE IF NOT EXISTS notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- 2. RLS 활성화
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;

-- 3. 정책: anon과 authenticated 역할에는 조회 권한 없음 (명시적 거부)
CREATE POLICY "Deny select for anon" ON notes
  FOR SELECT
  USING (FALSE);

CREATE POLICY "Deny select for authenticated" ON notes
  FOR SELECT
  USING (auth.uid() IS NULL);
