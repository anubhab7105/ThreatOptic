-- Phase 0 — Supabase Database Trigger Setup (run ONCE in Supabase → SQL Editor).
-- Replaces the auto-org-creation logic previously in POST /auth/register.
--
-- 1. Creates a personal Organization for every confirmed user
-- 2. Mirrors the Supabase auth user into public.users with default 'Analyst' role
--
-- FIX (2026-09-25): Two triggers are registered:
--   a) on_auth_user_created  → AFTER INSERT  (handles auto-confirm-off flows)
--   b) on_auth_user_confirmed → AFTER UPDATE  (handles email link confirmation)
-- Both are idempotent (ON CONFLICT DO NOTHING) so duplicate calls are safe.

-- ── Function: insert user + org row (idempotent) ────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  new_org_id TEXT;
  existing_org_id TEXT;
BEGIN
  -- Only proceed if the user is confirmed (email_confirmed_at IS NOT NULL).
  -- On INSERT this may be NULL (pre-confirmation); on UPDATE it will be set.
  IF NEW.email_confirmed_at IS NULL THEN
    RETURN NEW;
  END IF;

  -- Skip if already mirrored (idempotent guard)
  IF EXISTS (SELECT 1 FROM public.users WHERE id = NEW.id::text) THEN
    RETURN NEW;
  END IF;

  -- Reuse existing org if the email already has one (org created by a prior attempt)
  SELECT id INTO existing_org_id FROM public.organizations
  WHERE name = NEW.email || '''s workspace'
  LIMIT 1;

  IF existing_org_id IS NULL THEN
    new_org_id := gen_random_uuid()::text;
    INSERT INTO public.organizations (id, name, compliance_policy, created_at)
    VALUES (
      new_org_id,
      NEW.email || '''s workspace',
      '{}',
      NOW()
    )
    ON CONFLICT DO NOTHING;
  ELSE
    new_org_id := existing_org_id;
  END IF;

  -- Mirror the Supabase auth user into our public users table
  INSERT INTO public.users (id, email, role, organization_id, created_at)
  VALUES (
    NEW.id::text,     -- Supabase auth UUID becomes our user ID
    NEW.email,
    'Analyst',        -- default role; can be upgraded later
    new_org_id,
    NOW()
  )
  ON CONFLICT DO NOTHING;   -- safe to call multiple times

  RETURN NEW;
END;
$$;

-- ── Trigger A: fires on new signup row ──────────────────────────────────────
-- Catches cases where Supabase auto-confirms (e.g., magic link, no email verify).
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE PROCEDURE public.handle_new_user();

-- ── Trigger B: fires when email confirmation link is clicked ─────────────────
-- Catches the normal "verify your email" flow: Supabase does an UPDATE to set
-- email_confirmed_at, which didn't trigger the INSERT trigger above.
DROP TRIGGER IF EXISTS on_auth_user_confirmed ON auth.users;
CREATE TRIGGER on_auth_user_confirmed
  AFTER UPDATE ON auth.users
  FOR EACH ROW
  WHEN (OLD.email_confirmed_at IS NULL AND NEW.email_confirmed_at IS NOT NULL)
  EXECUTE PROCEDURE public.handle_new_user();

-- ── Backfill: create rows for already-confirmed users who have no public.users row ──
-- Safe to run multiple times (ON CONFLICT DO NOTHING).
DO $$
DECLARE
  r RECORD;
  v_org_id TEXT;
BEGIN
  FOR r IN
    SELECT au.id::text AS uid, au.email
    FROM auth.users au
    WHERE au.email_confirmed_at IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM public.users pu WHERE pu.id = au.id::text)
  LOOP
    v_org_id := gen_random_uuid()::text;

    INSERT INTO public.organizations (id, name, compliance_policy, created_at)
    VALUES (v_org_id, r.email || '''s workspace', '{}', NOW())
    ON CONFLICT DO NOTHING;

    INSERT INTO public.users (id, email, role, organization_id, created_at)
    VALUES (r.uid, r.email, 'Analyst', v_org_id, NOW())
    ON CONFLICT DO NOTHING;

    RAISE NOTICE 'Backfilled user %', r.email;
  END LOOP;
END $$;
