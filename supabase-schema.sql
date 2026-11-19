-- School Hub shared backend schema (run in Supabase SQL Editor).
-- Public visitors can submit a request, but cannot read student requests.
-- Only users listed as school admins can review requests or access project logs.

create extension if not exists pgcrypto;

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.applications (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('club','activity')),
  target_id text not null check (length(target_id) between 1 and 100),
  target_name text not null check (length(target_name) between 1 and 180),
  full_name text not null check (length(trim(full_name)) between 3 and 120),
  class_name text not null check (length(trim(class_name)) between 1 and 100),
  participation_type text not null default 'student' check (length(participation_type) between 1 and 60),
  reason text not null default '' check (length(reason) <= 1000),
  status text not null default 'pending' check (status in ('pending','reviewing','approved','waitlist','rejected')),
  participation_status text not null default 'interest' check (participation_status in ('interest','attended','contributed','absent','excused')),
  created_at timestamptz not null default now()
);

create unique index if not exists applications_duplicate_guard
  on public.applications (kind, target_id, lower(full_name), class_name);
create index if not exists applications_created_idx on public.applications (created_at desc);

create table if not exists public.school_projects (
  id text primary key,
  code text not null,
  payload jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.activity_logs (
  id text primary key,
  project_id text not null,
  activity_date date not null,
  payload jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists activity_logs_date_idx on public.activity_logs (activity_date desc);

create or replace function public.is_school_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = auth.uid() and role = 'admin'
  );
$$;
revoke all on function public.is_school_admin() from public;
grant execute on function public.is_school_admin() to anon, authenticated;

alter table public.user_roles enable row level security;
alter table public.applications enable row level security;
alter table public.school_projects enable row level security;
alter table public.activity_logs enable row level security;

revoke all on public.user_roles from anon, authenticated;
revoke all on public.applications from anon, authenticated;
revoke all on public.school_projects from anon, authenticated;
revoke all on public.activity_logs from anon, authenticated;

grant select on public.user_roles to authenticated;
grant insert (kind, target_id, target_name, full_name, class_name, participation_type, reason)
  on public.applications to anon, authenticated;
grant select, update, delete on public.applications to authenticated;
grant select, insert, update, delete on public.school_projects to authenticated;
grant select, insert, update, delete on public.activity_logs to authenticated;

create policy "users can read their own role"
  on public.user_roles for select to authenticated
  using (user_id = auth.uid());

create policy "public can submit valid applications"
  on public.applications for insert to anon, authenticated
  with check (
    length(trim(full_name)) between 3 and 120
    and length(trim(class_name)) between 1 and 100
    and length(reason) <= 1000
    and status = 'pending'
    and participation_status = 'interest'
  );
create policy "admins can read applications"
  on public.applications for select to authenticated
  using (public.is_school_admin());
create policy "admins can update applications"
  on public.applications for update to authenticated
  using (public.is_school_admin())
  with check (public.is_school_admin());
create policy "admins can delete applications"
  on public.applications for delete to authenticated
  using (public.is_school_admin());

create policy "admins manage school projects"
  on public.school_projects for all to authenticated
  using (public.is_school_admin())
  with check (public.is_school_admin());
create policy "admins manage activity logs"
  on public.activity_logs for all to authenticated
  using (public.is_school_admin())
  with check (public.is_school_admin());

-- Enable Realtime updates for the admin's shared queues and project tracker.
do $$
declare t text;
begin
  foreach t in array array['applications','school_projects','activity_logs'] loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
