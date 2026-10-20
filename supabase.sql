-- Erscript online backend.
-- Supabase > SQL Editor > New query > paste this whole file > Run (once).

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.accounts (
  u text primary key check (u ~ '^[a-z0-9_]{3,20}$'),
  name text not null check (char_length(name) between 1 and 30),
  name_key text not null unique,
  photo text not null default '' check (char_length(photo) <= 100000),
  salt text not null,
  hash2 text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.scripts (
  id bigint primary key,
  title text not null check (char_length(title) between 3 and 60),
  game text not null check (char_length(game) <= 60),
  cat text not null,
  descr text not null check (char_length(descr) <= 500),
  code text not null check (char_length(code) <= 5000),
  creator text not null references public.accounts(u) on delete cascade,
  ts bigint not null,
  img text not null default '' check (char_length(img) <= 200000),
  key_req boolean not null default false,
  uni boolean not null default false,
  mob boolean not null default false,
  patched boolean not null default false,
  views int not null default 0,
  favs int not null default 0
);

create table if not exists public.verified (
  u text primary key references public.accounts(u) on delete cascade,
  ts bigint not null default (extract(epoch from now()) * 1000)::bigint
);

create table if not exists public.applications (
  u text primary key references public.accounts(u) on delete cascade,
  name text not null,
  why text not null,
  link text not null default '',
  ts bigint not null,
  status text not null default 'pending',
  ts2 bigint
);

create table if not exists public.reports (
  id bigserial primary key,
  sid bigint not null,
  by_u text not null check (char_length(by_u) <= 30),
  ts bigint not null
);

-- ---------- row level security ----------
alter table public.accounts     enable row level security;
alter table public.scripts      enable row level security;
alter table public.verified     enable row level security;
alter table public.applications enable row level security;
alter table public.reports      enable row level security;

revoke all on public.accounts, public.scripts, public.verified, public.applications, public.reports from anon, authenticated;
-- the password hash column is NOT readable from the website
grant select (u, name, photo, salt) on public.accounts to anon, authenticated;
grant select on public.scripts, public.verified to anon, authenticated;
grant insert on public.reports to anon, authenticated;
grant usage on sequence public.reports_id_seq to anon, authenticated;

drop policy if exists "read accounts" on public.accounts;
create policy "read accounts" on public.accounts for select using (true);
drop policy if exists "read scripts" on public.scripts;
create policy "read scripts" on public.scripts for select using (true);
drop policy if exists "read verified" on public.verified;
create policy "read verified" on public.verified for select using (true);
drop policy if exists "insert reports" on public.reports;
create policy "insert reports" on public.reports for insert with check (true);
-- applications: no policy = nobody can read or write directly (only the functions below)

-- ---------- helpers ----------
create or replace function public._ers_auth(p_u text, p_hash text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select exists (
    select 1 from public.accounts
    where u = p_u and hash2 = encode(digest(p_hash, 'sha256'), 'hex')
  );
$$;
revoke execute on function public._ers_auth(text, text) from public, anon, authenticated;

create or replace function public._ers_owner(p_u text, p_hash text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_u <> 'devexploiter' or not public._ers_auth(p_u, p_hash) then
    raise exception 'not_owner';
  end if;
end $$;
revoke execute on function public._ers_owner(text, text) from public, anon, authenticated;

-- ---------- accounts ----------
create or replace function public.login_ok(p_u text, p_hash text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select public._ers_auth(p_u, p_hash);
$$;

create or replace function public.signup(p_u text, p_name text, p_key text, p_salt text, p_hash text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_name text := btrim(p_name);
  v_key  text := p_key;
  v_nk   text := regexp_replace(translate(lower(btrim(p_name)), '0i1', 'oll'), '[^a-z0-9]', '', 'g');
  v_uk   text := regexp_replace(translate(p_u, '0i1', 'oll'), '[^a-z0-9]', '', 'g');
begin
  if p_u !~ '^[a-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  if char_length(coalesce(p_hash, '')) < 20 then raise exception 'bad_password'; end if;
  if p_u = 'devexploiter' then
    v_name := 'Devexploiter';
    v_key  := 'devexplolter';
  else
    if v_key = 'devexplolter' or v_nk = 'devexplolter' or v_uk = 'devexplolter' then
      raise exception 'reserved';
    end if;
  end if;
  if char_length(v_name) not between 1 and 30 then raise exception 'bad_name'; end if;
  if v_key !~ '^[a-z0-9]+$' then raise exception 'bad_name'; end if;
  if exists (select 1 from public.accounts where u = p_u) then raise exception 'username_taken'; end if;
  if exists (select 1 from public.accounts where name_key = v_key) then raise exception 'name_taken'; end if;
  insert into public.accounts (u, name, name_key, salt, hash2)
  values (p_u, v_name, v_key, p_salt, encode(digest(p_hash, 'sha256'), 'hex'));
end $$;

create or replace function public.update_account(
  p_u text, p_hash text, p_name text, p_key text, p_photo text, p_newsalt text, p_newhash text
) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_nk text;
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  if p_name is not null and p_u <> 'devexploiter' then
    v_nk := regexp_replace(translate(lower(btrim(p_name)), '0i1', 'oll'), '[^a-z0-9]', '', 'g');
    if char_length(btrim(p_name)) not between 1 and 30 then raise exception 'bad_name'; end if;
    if p_key is null or p_key !~ '^[a-z0-9]+$' then raise exception 'bad_name'; end if;
    if p_key = 'devexplolter' or v_nk = 'devexplolter' then raise exception 'reserved'; end if;
    if exists (select 1 from public.accounts where name_key = p_key and u <> p_u) then raise exception 'name_taken'; end if;
    update public.accounts set name = btrim(p_name), name_key = p_key where u = p_u;
  end if;
  if p_photo is not null then
    if char_length(p_photo) > 100000 then raise exception 'photo_too_big'; end if;
    update public.accounts set photo = p_photo where u = p_u;
  end if;
  if p_newsalt is not null and p_newhash is not null then
    if char_length(p_newhash) < 20 then raise exception 'bad_password'; end if;
    update public.accounts set salt = p_newsalt, hash2 = encode(digest(p_newhash, 'sha256'), 'hex') where u = p_u;
  end if;
end $$;

create or replace function public.delete_account(p_u text, p_hash text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  delete from public.accounts where u = p_u;
end $$;

-- ---------- scripts ----------
create or replace function public.publish_script(
  p_u text, p_hash text, p_id bigint, p_title text, p_game text, p_cat text, p_descr text,
  p_code text, p_ts bigint, p_img text, p_key boolean, p_uni boolean, p_mob boolean
) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  insert into public.scripts (id, title, game, cat, descr, code, creator, ts, img, key_req, uni, mob)
  values (p_id, btrim(p_title), btrim(p_game), p_cat, btrim(p_descr), p_code, p_u, p_ts,
          coalesce(p_img, ''), coalesce(p_key, false), coalesce(p_uni, false), coalesce(p_mob, false));
end $$;

create or replace function public.delete_script(p_u text, p_hash text, p_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  delete from public.scripts where id = p_id and creator = p_u;
end $$;

create or replace function public.patch_script(p_u text, p_hash text, p_id bigint, p_patched boolean) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  update public.scripts set patched = p_patched where id = p_id and creator = p_u;
end $$;

create or replace function public.bump(p_id bigint, p_col text, p_n int) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare n int := greatest(-1, least(1, p_n));
begin
  if p_col = 'views' then
    update public.scripts set views = greatest(0, views + n) where id = p_id;
  elsif p_col = 'favs' then
    update public.scripts set favs = greatest(0, favs + n) where id = p_id;
  else
    raise exception 'bad_column';
  end if;
end $$;

-- ---------- verification ----------
create or replace function public.apply_verification(p_u text, p_hash text, p_why text, p_link text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_name text;
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  if p_u = 'devexploiter' or exists (select 1 from public.verified where u = p_u) then raise exception 'already_verified'; end if;
  if char_length(btrim(coalesce(p_why, ''))) < 20 or char_length(p_why) > 500 or char_length(coalesce(p_link, '')) > 120 then
    raise exception 'bad_request';
  end if;
  select name into v_name from public.accounts where u = p_u;
  insert into public.applications (u, name, why, link, ts, status, ts2)
  values (p_u, v_name, btrim(p_why), coalesce(p_link, ''), (extract(epoch from now()) * 1000)::bigint, 'pending', null)
  on conflict (u) do update
    set name = excluded.name, why = excluded.why, link = excluded.link, ts = excluded.ts, status = 'pending', ts2 = null;
end $$;

create or replace function public.my_application(p_u text, p_hash text) returns setof public.applications
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  return query select * from public.applications where u = p_u;
end $$;

create or replace function public.list_applications(p_u text, p_hash text) returns setof public.applications
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform public._ers_owner(p_u, p_hash);
  return query select * from public.applications order by ts desc;
end $$;

create or replace function public.decide_application(p_u text, p_hash text, p_target text, p_status text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare now_ms bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  perform public._ers_owner(p_u, p_hash);
  if p_status not in ('approved', 'rejected', 'revoked') then raise exception 'bad_status'; end if;
  update public.applications set status = p_status, ts2 = now_ms where u = p_target;
  if not found then raise exception 'no_application'; end if;
  if p_status = 'approved' then
    insert into public.verified (u) values (p_target) on conflict do nothing;
  else
    delete from public.verified where u = p_target;
  end if;
end $$;

create or replace function public.set_verified(p_u text, p_hash text, p_target text, p_on boolean) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare now_ms bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  perform public._ers_owner(p_u, p_hash);
  if not exists (select 1 from public.accounts where u = p_target) then raise exception 'no_account'; end if;
  if p_on then
    insert into public.verified (u) values (p_target) on conflict do nothing;
    update public.applications set status = 'approved', ts2 = now_ms where u = p_target and status = 'pending';
  else
    delete from public.verified where u = p_target;
    update public.applications set status = 'revoked', ts2 = now_ms where u = p_target and status = 'approved';
  end if;
end $$;

-- ---------- let the website call the functions ----------
grant execute on function
  public.login_ok(text, text),
  public.signup(text, text, text, text, text),
  public.update_account(text, text, text, text, text, text, text),
  public.delete_account(text, text),
  public.publish_script(text, text, bigint, text, text, text, text, text, bigint, text, boolean, boolean, boolean),
  public.delete_script(text, text, bigint),
  public.patch_script(text, text, bigint, boolean),
  public.bump(bigint, text, int),
  public.apply_verification(text, text, text, text),
  public.my_application(text, text),
  public.list_applications(text, text),
  public.decide_application(text, text, text, text),
  public.set_verified(text, text, text, boolean)
to anon, authenticated;

-- =====================================================================
-- COMMENTS + NOTIFICATIONS (safe to run again; run this whole file once more)
-- =====================================================================
create table if not exists public.comments (
  id bigserial primary key,
  sid bigint not null references public.scripts(id) on delete cascade,
  u text not null references public.accounts(u) on delete cascade,
  t text not null check (char_length(t) between 2 and 200),
  r int not null check (r between 1 and 5),
  ts bigint not null default (extract(epoch from now()) * 1000)::bigint
);
create index if not exists comments_sid_ts_idx on public.comments (sid, ts);

create table if not exists public.notifications (
  id bigserial primary key,
  to_u text not null references public.accounts(u) on delete cascade,
  kind text not null default 'comment',
  sid bigint references public.scripts(id) on delete cascade,
  cid bigint references public.comments(id) on delete cascade,
  from_u text not null,
  ts bigint not null default (extract(epoch from now()) * 1000)::bigint,
  seen boolean not null default false
);
create index if not exists notifications_to_idx on public.notifications (to_u, ts desc);

alter table public.comments      enable row level security;
alter table public.notifications enable row level security;
revoke all on public.comments, public.notifications from anon, authenticated;
grant select on public.comments to anon, authenticated;
drop policy if exists "read comments" on public.comments;
create policy "read comments" on public.comments for select using (true);
-- notifications: no policy = only readable through my_notifications() below

create or replace function public.post_comment(p_u text, p_hash text, p_sid bigint, p_t text, p_r int) returns bigint
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_creator text;
  v_id bigint;
  v_t text := btrim(coalesce(p_t, ''));
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  if char_length(v_t) not between 2 and 200 then raise exception 'bad_comment'; end if;
  if p_r is null or p_r not between 1 and 5 then raise exception 'bad_rating'; end if;
  select creator into v_creator from public.scripts where id = p_sid;
  if not found then raise exception 'no_script'; end if;
  if exists (select 1 from public.comments where u = p_u and ts > (extract(epoch from now()) * 1000)::bigint - 3000) then
    raise exception 'too_fast';
  end if;
  insert into public.comments (sid, u, t, r) values (p_sid, p_u, v_t, p_r) returning id into v_id;
  if v_creator <> p_u then
    insert into public.notifications (to_u, kind, sid, cid, from_u) values (v_creator, 'comment', p_sid, v_id, p_u);
  end if;
  return v_id;
end $$;

create or replace function public.delete_comment(p_u text, p_hash text, p_id bigint) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  delete from public.comments c
  where c.id = p_id
    and (c.u = p_u or p_u = 'devexploiter'
         or exists (select 1 from public.scripts s where s.id = c.sid and s.creator = p_u));
end $$;

create or replace function public.my_notifications(p_u text, p_hash text)
returns table (n_id bigint, n_kind text, n_sid bigint, n_from text, n_ts bigint, n_seen boolean, n_title text, n_text text)
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  return query
    select n.id, n.kind, n.sid, n.from_u, n.ts, n.seen, s.title, c.t
    from public.notifications n
    left join public.scripts  s on s.id = n.sid
    left join public.comments c on c.id = n.cid
    where n.to_u = p_u
    order by n.ts desc
    limit 30;
end $$;

create or replace function public.mark_notifications_seen(p_u text, p_hash text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._ers_auth(p_u, p_hash) then raise exception 'auth'; end if;
  update public.notifications set seen = true where to_u = p_u and not seen;
end $$;

grant execute on function
  public.post_comment(text, text, bigint, text, int),
  public.delete_comment(text, text, bigint),
  public.my_notifications(text, text),
  public.mark_notifications_seen(text, text)
to anon, authenticated;
