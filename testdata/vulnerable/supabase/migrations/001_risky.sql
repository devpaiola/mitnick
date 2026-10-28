ALTER TABLE public.documents DISABLE ROW LEVEL SECURITY;
CREATE POLICY open_read ON public.documents USING (true);
