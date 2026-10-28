ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON public.documents USING (auth.uid() = owner_id) WITH CHECK (auth.uid() = owner_id);
