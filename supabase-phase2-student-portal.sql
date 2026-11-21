-- Phase 2 migration: private student request tracking without exposing student names/classes.
-- Run in Supabase SQL Editor before deploying the v3.0.0 front end.
-- Safe to rerun if a previous attempt stopped while resolving pgcrypto.digest.

create extension if not exists pgcrypto;

create table if not exists public.application_tracking_tokens (
  token_hash text primary key check (token_hash ~ '^[0-9a-f]{64}$'),
  application_id uuid not null unique references public.applications(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.application_tracking_tokens enable row level security;
revoke all on public.application_tracking_tokens from anon, authenticated;

create or replace function public.submit_application(
  p_kind text,
  p_target_id text,
  p_target_name text,
  p_full_name text,
  p_class_name text,
  p_participation_type text,
  p_reason text,
  p_tracking_token text
)
returns uuid
language plpgsql
security definer
set search_path = public, extensions, pg_temp
as $$
declare
  v_application_id uuid;
  v_token text := lower(coalesce(p_tracking_token, ''));
begin
  if p_kind is null or p_kind not in ('club', 'activity') then
    raise exception 'invalid application kind' using errcode = '22023';
  end if;
  if length(trim(coalesce(p_full_name, ''))) not between 3 and 120 then
    raise exception 'invalid student name' using errcode = '22023';
  end if;
  if length(trim(coalesce(p_class_name, ''))) not between 1 and 100 then
    raise exception 'invalid class' using errcode = '22023';
  end if;
  if length(trim(coalesce(p_target_id, ''))) not between 1 and 100
     or length(trim(coalesce(p_target_name, ''))) not between 1 and 180 then
    raise exception 'invalid target' using errcode = '22023';
  end if;
  if length(coalesce(p_reason, '')) > 1000 then
    raise exception 'reason is too long' using errcode = '22023';
  end if;
  if length(v_token) <> 64 or v_token !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid tracking token' using errcode = '22023';
  end if;

  insert into public.applications (
    kind, target_id, target_name, full_name, class_name,
    participation_type, reason, status, participation_status
  ) values (
    p_kind, trim(p_target_id), trim(p_target_name), trim(p_full_name), trim(p_class_name),
    left(coalesce(nullif(trim(p_participation_type), ''), 'student'), 60),
    coalesce(p_reason, ''), 'pending', 'interest'
  ) returning id into v_application_id;

  insert into public.application_tracking_tokens (token_hash, application_id)
  values (encode(extensions.digest(convert_to(v_token, 'UTF8'), 'sha256'), 'hex'), v_application_id);

  return v_application_id;
end;
$$;

create or replace function public.get_application_status(p_token text)
returns table (
  request_id uuid,
  kind text,
  target_name text,
  status text,
  participation_status text,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public, extensions, pg_temp
as $$
  select a.id, a.kind, a.target_name, a.status, a.participation_status, a.created_at
  from public.application_tracking_tokens t
  join public.applications a on a.id = t.application_id
  where coalesce(p_token, '') ~* '^[a-f0-9]{64}$'
    and t.token_hash = encode(extensions.digest(convert_to(lower(p_token), 'UTF8'), 'sha256'), 'hex')
  limit 1;
$$;

revoke all on function public.submit_application(text, text, text, text, text, text, text, text) from public, anon, authenticated;
revoke all on function public.get_application_status(text) from public, anon, authenticated;
grant execute on function public.submit_application(text, text, text, text, text, text, text, text) to anon, authenticated;
grant execute on function public.get_application_status(text) to anon, authenticated;

notify pgrst, 'reload schema';
