-- Migration: Move sample notes to Supabase table
-- Purpose: Protect sample notes with RLS and prepare for authenticated access in step 2+

-- Create notes table with RLS
CREATE TABLE IF NOT EXISTS public.notes (
  id BIGSERIAL PRIMARY KEY,
  owner_id UUID,
  content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS on notes table
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;

-- Create RLS policies: anon and authenticated roles have NO read access
-- (Only authenticated users with matching owner_id can read their own notes after policy implementation)
CREATE POLICY "no_anon_read" ON public.notes
  AS PERMISSIVE FOR SELECT
  TO anon
  USING (false);

CREATE POLICY "no_authenticated_read" ON public.notes
  AS PERMISSIVE FOR SELECT
  TO authenticated
  USING (false);

-- Insert sample notes with NULL owner_id (will be assigned later or managed by app logic)
INSERT INTO public.notes (owner_id, content) VALUES
  (NULL, '메모 1: 방어전 출발 자료'),
  (NULL, '메모 2: 방어전 출발 자료'),
  (NULL, '메모 3: 방어전 출발 자료'),
  (NULL, '메모 4: 방어전 출발 자료')
ON CONFLICT DO NOTHING;
