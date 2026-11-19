-- فضاء الثانوية التأهيلية الوفاق: shared content, requests, activity tracking and club coordinators.
-- Safe to rerun: policies and the role constraint are recreated idempotently.

create extension if not exists pgcrypto;

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'admin',
  created_at timestamptz not null default now()
);
alter table public.user_roles drop constraint if exists user_roles_role_check;
alter table public.user_roles add constraint user_roles_role_check
  check (role in ('admin','club_coordinator'));

create table if not exists public.user_club_assignments (
  user_id uuid not null references auth.users(id) on delete cascade,
  club_id text not null,
  display_name text not null default '',
  email text not null default '',
  assigned_at timestamptz not null default now(),
  primary key (user_id, club_id)
);
create index if not exists user_club_assignments_club_idx on public.user_club_assignments (club_id);

create table if not exists public.school_content (
  id text primary key,
  content_type text not null check (content_type in ('news','club','activity','media')),
  payload jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists school_content_type_updated_idx on public.school_content (content_type, updated_at desc);

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
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'admin');
$$;

create or replace function public.is_club_coordinator(target_club_id text)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1
    from public.user_roles r
    join public.user_club_assignments a on a.user_id = r.user_id
    where r.user_id = auth.uid()
      and r.role = 'club_coordinator'
      and a.club_id = target_club_id
  );
$$;
create or replace function public.can_manage_activity_media(target_activity_id text)
returns boolean language sql stable security definer set search_path = public
as $$
  select exists (
    select 1 from public.school_content a
    where a.id = target_activity_id
      and a.content_type = 'activity'
      and public.is_club_coordinator(a.payload->>'clubId')
  );
$$;

create or replace function public.assign_club_coordinator(p_email text, p_display_name text, p_club_id text)
returns uuid language plpgsql security definer set search_path = public, auth
as $$
declare target_user_id uuid;
begin
  if not public.is_school_admin() then raise exception 'administrator_required'; end if;
  select id into target_user_id from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if target_user_id is null then raise exception 'auth_user_not_found'; end if;
  if exists (select 1 from public.user_roles where user_id = target_user_id and role = 'admin') then
    raise exception 'cannot_assign_admin_as_coordinator';
  end if;
  insert into public.user_roles(user_id, role) values (target_user_id, 'club_coordinator')
    on conflict (user_id) do update set role = 'club_coordinator';
  insert into public.user_club_assignments(user_id, club_id, display_name, email)
    values (target_user_id, p_club_id, trim(p_display_name), lower(trim(p_email)))
    on conflict (user_id, club_id) do update
      set display_name = excluded.display_name, email = excluded.email;
  return target_user_id;
end;
$$;

revoke all on function public.is_school_admin() from public;
revoke all on function public.is_club_coordinator(text) from public;
revoke all on function public.assign_club_coordinator(text,text,text) from public;
revoke all on function public.can_manage_activity_media(text) from public;
grant execute on function public.is_school_admin() to anon, authenticated;
grant execute on function public.is_club_coordinator(text) to anon, authenticated;
grant execute on function public.assign_club_coordinator(text,text,text) to authenticated;
grant execute on function public.can_manage_activity_media(text) to anon, authenticated;

alter table public.user_roles enable row level security;
alter table public.user_club_assignments enable row level security;
alter table public.school_content enable row level security;
alter table public.applications enable row level security;
alter table public.school_projects enable row level security;
alter table public.activity_logs enable row level security;

revoke all on public.user_roles from anon, authenticated;
revoke all on public.user_club_assignments from anon, authenticated;
revoke all on public.school_content from anon, authenticated;
revoke all on public.applications from anon, authenticated;
revoke all on public.school_projects from anon, authenticated;
revoke all on public.activity_logs from anon, authenticated;

grant select, insert, update, delete on public.user_roles to authenticated;
grant select, insert, update, delete on public.user_club_assignments to authenticated;
grant select on public.school_content to anon, authenticated;
grant insert, update, delete on public.school_content to authenticated;
grant insert (kind, target_id, target_name, full_name, class_name, participation_type, reason)
  on public.applications to anon, authenticated;
grant select, update, delete on public.applications to authenticated;
grant select, insert, update, delete on public.school_projects to authenticated;
grant select, insert, update, delete on public.activity_logs to authenticated;

-- Recreate policies safely on repeat runs.
drop policy if exists "users can read their own role" on public.user_roles;
drop policy if exists "admins manage user roles" on public.user_roles;
drop policy if exists "users can read their own club assignments" on public.user_club_assignments;
drop policy if exists "admins manage club assignments" on public.user_club_assignments;
drop policy if exists "public can read school content" on public.school_content;
drop policy if exists "admins and assigned coordinators manage school content" on public.school_content;
drop policy if exists "public can submit valid applications" on public.applications;
drop policy if exists "admins can read applications" on public.applications;
drop policy if exists "admins can update applications" on public.applications;
drop policy if exists "admins can delete applications" on public.applications;
drop policy if exists "admins manage school projects" on public.school_projects;
drop policy if exists "admins manage activity logs" on public.activity_logs;

create policy "users can read their own role"
  on public.user_roles for select to authenticated
  using (user_id = auth.uid() or public.is_school_admin());
create policy "admins manage user roles"
  on public.user_roles for all to authenticated
  using (public.is_school_admin()) with check (public.is_school_admin());

create policy "users can read their own club assignments"
  on public.user_club_assignments for select to authenticated
  using (user_id = auth.uid() or public.is_school_admin());
create policy "admins manage club assignments"
  on public.user_club_assignments for all to authenticated
  using (public.is_school_admin()) with check (public.is_school_admin());

create policy "public can read school content"
  on public.school_content for select to anon, authenticated
  using (true);
create policy "admins and assigned coordinators manage school content"
  on public.school_content for all to authenticated
  using (
    public.is_school_admin()
    or (content_type = 'club' and public.is_club_coordinator(id))
    or (content_type = 'activity' and public.is_club_coordinator(payload->>'clubId'))
    or (
      content_type = 'media'
      and (
        (payload->>'scopeType' = 'club' and public.is_club_coordinator(payload->>'scopeId'))
        or (
          payload->>'scopeType' = 'activity'
          and public.can_manage_activity_media(payload->>'scopeId')
        )
      )
    )
  )
  with check (
    public.is_school_admin()
    or (content_type = 'club' and public.is_club_coordinator(id))
    or (content_type = 'activity' and public.is_club_coordinator(payload->>'clubId'))
    or (
      content_type = 'media'
      and (
        (payload->>'scopeType' = 'club' and public.is_club_coordinator(payload->>'scopeId'))
        or (
          payload->>'scopeType' = 'activity'
          and public.can_manage_activity_media(payload->>'scopeId')
        )
      )
    )
  );

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
  using (public.is_school_admin()) with check (public.is_school_admin());
create policy "admins can delete applications"
  on public.applications for delete to authenticated
  using (public.is_school_admin());

create policy "admins manage school projects"
  on public.school_projects for all to authenticated
  using (public.is_school_admin()) with check (public.is_school_admin());
create policy "admins manage activity logs"
  on public.activity_logs for all to authenticated
  using (public.is_school_admin()) with check (public.is_school_admin());

-- Enable Realtime for the shared content and administrative queues.
do $$
declare t text;
begin
  foreach t in array array['school_content','applications','school_projects','activity_logs'] loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
