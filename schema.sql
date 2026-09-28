-- Lettersoxd database setup
-- Run this once in the Supabase dashboard: SQL Editor > New query > paste > Run.
-- It is safe to re-run.

-- ============================================================
-- 1. The socks table
-- ============================================================
create table if not exists public.socks (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null default auth.uid() references auth.users (id) on delete cascade,
  name        text not null check (char_length(name) between 1 and 120),
  brand       text check (brand is null or char_length(brand) <= 60),
  notes       text check (notes is null or char_length(notes) <= 1000),
  rating      smallint not null default 0 check (rating between 0 and 10),  -- half-stars: 0-10 = 0-5 stars
  photo_path  text,   -- path inside the sock-photos bucket (detail image)
  thumb_path  text,   -- path inside the sock-photos bucket (grid thumbnail)
  created_at  timestamptz not null default now()
);

create index if not exists socks_user_created_idx on public.socks (user_id, created_at desc);

-- ============================================================
-- 2. Row-level security: each person can only touch their own rows
-- ============================================================
-- Newer Supabase projects don't automatically give the API roles access to
-- new tables, so grant it explicitly. Signed-in users only; anonymous visitors get nothing.
-- (The row-level policies below still limit each user to their own rows.)
grant select, insert, update, delete on public.socks to authenticated;

alter table public.socks enable row level security;

drop policy if exists "socks: select own" on public.socks;
drop policy if exists "socks: insert own" on public.socks;
drop policy if exists "socks: update own" on public.socks;
drop policy if exists "socks: delete own" on public.socks;

create policy "socks: select own" on public.socks
  for select to authenticated
  using (user_id = (select auth.uid()));

create policy "socks: insert own" on public.socks
  for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "socks: update own" on public.socks
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "socks: delete own" on public.socks
  for delete to authenticated
  using (user_id = (select auth.uid()));

-- ============================================================
-- 3. Photo storage: a PRIVATE bucket, 1 MB per file, images only
--    Files live under <user id>/<file name>, and policies only allow
--    access to your own folder.
-- ============================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('sock-photos', 'sock-photos', false, 1048576, array['image/webp', 'image/jpeg'])
on conflict (id) do update
  set public = false,
      file_size_limit = 1048576,
      allowed_mime_types = array['image/webp', 'image/jpeg'];

drop policy if exists "sock-photos: read own"   on storage.objects;
drop policy if exists "sock-photos: upload own" on storage.objects;
drop policy if exists "sock-photos: update own" on storage.objects;
drop policy if exists "sock-photos: delete own" on storage.objects;

create policy "sock-photos: read own" on storage.objects
  for select to authenticated
  using (bucket_id = 'sock-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "sock-photos: upload own" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'sock-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "sock-photos: update own" on storage.objects
  for update to authenticated
  using (bucket_id = 'sock-photos' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'sock-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "sock-photos: delete own" on storage.objects
  for delete to authenticated
  using (bucket_id = 'sock-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- ============================================================
-- 4. "Delete my account"
--    The browser can't delete an auth user directly, so this function does it
--    for the signed-in caller only. Their socks rows are removed by the
--    ON DELETE CASCADE above. (The app deletes their photo files first.)
-- ============================================================
create or replace function public.delete_my_account()
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null then
    raise exception 'Not signed in';
  end if;
  delete from auth.users where id = auth.uid();
end;
$$;

revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;
