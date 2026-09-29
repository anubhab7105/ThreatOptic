











CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  new_org_id TEXT;
  existing_org_id TEXT;
BEGIN


  IF NEW.email_confirmed_at IS NULL THEN
    RETURN NEW;
  END IF;


  IF EXISTS (SELECT 1 FROM public.users WHERE id = NEW.id::text) THEN
    RETURN NEW;
  END IF;


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


  INSERT INTO public.users (id, email, role, organization_id, created_at)
  VALUES (
    NEW.id::text,
    NEW.email,
    'Analyst',
    new_org_id,
    NOW()
  )
  ON CONFLICT DO NOTHING;

  RETURN NEW;
END;
$$;



DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE PROCEDURE public.handle_new_user();




DROP TRIGGER IF EXISTS on_auth_user_confirmed ON auth.users;
CREATE TRIGGER on_auth_user_confirmed
  AFTER UPDATE ON auth.users
  FOR EACH ROW
  WHEN (OLD.email_confirmed_at IS NULL AND NEW.email_confirmed_at IS NOT NULL)
  EXECUTE PROCEDURE public.handle_new_user();



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
