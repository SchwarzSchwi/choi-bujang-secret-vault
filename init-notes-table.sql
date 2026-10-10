-- Supabase 학습용 메모 테이블 초기화
-- 1. 테이블 생성: owner_id uuid 칼럼을 두되 auth.users 외래키 제약 없음
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

-- 3. 정책: anon과 authenticated 역할에는 조회 권한 없음
-- 기본 거부 정책 (명시적 허용이 없으면 모두 거부)
CREATE POLICY "No access for anonymous" ON notes
  FOR SELECT
  USING (FALSE);

CREATE POLICY "No access for authenticated" ON notes
  FOR SELECT
  USING (auth.uid() IS NULL);

-- 4. 가상 메모 네 건 삽입 (owner_id는 null로 설정 - 학생이 필요시 채우도록)
INSERT INTO notes (owner_id, title, content) VALUES
  (NULL, '과제', '실습용 가상 과제 기록'),
  (NULL, '포트폴리오', '실습용 가상 포트폴리오 기록'),
  (NULL, '아침 리추얼', '실습용 가상 리추얼 기록'),
  (NULL, '훈련 행정 자료', '실습용 가상 행정 기록')
ON CONFLICT DO NOTHING;
