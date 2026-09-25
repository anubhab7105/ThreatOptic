-- Phase 0 — Supabase Database Trigger Setup (run ONCE in Supabase → SQL Editor).
-- Replaces the auto-org-creation logic previously in POST /auth/register.
--
-- 1. Creates a personal Organization for every confirmed user
-- 2. Mirrors the Supabase auth user into public.users with default 'Analyst' role

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  new_org_id TEXT;
BEGIN
  -- Create a personal workspace org
  new_org_id := gen_random_uuid()::text;
  INSERT INTO public.organizations (id, name, compliance_policy, created_at)
  VALUES (
    new_org_id,
    NEW.email || '''s workspace',
    '{}',
    NOW()
  );

  -- Mirror the Supabase auth user into our public users table
  INSERT INTO public.users (id, email, role, organization_id, created_at)
  VALUES (
    NEW.id::text,     -- Supabase auth UUID becomes our user ID
    NEW.email,
    'Analyst',        -- default role; can be upgraded later
    new_org_id,
    NOW()
  );

  RETURN NEW;
END;
$$;

-- Fire after Supabase confirms email (email_confirmed_at is set)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE PROCEDURE public.handle_new_user();
