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

-- 4. 학습용 데이터 (owner_id는 null - 학생이 실제 운영 시 채우기)
INSERT INTO notes (owner_id, title, content) VALUES
  (NULL, '과제', '실습용 가상 과제 기록'),
  (NULL, '포트폴리오', '실습용 가상 포트폴리오 기록'),
  (NULL, '아침 리추얼', '실습용 가상 리추얼 기록'),
  (NULL, '훈련 행정 자료', '실습용 가상 행정 기록')
ON CONFLICT DO NOTHING;
