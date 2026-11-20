-- Nhà Mèo Méo: toàn bộ schema (bảng, index, hàm, quyền) - bản dùng cho project zeipzqkqfekccdrrovvg (20/11/2026).
-- Mọi truy cập đi qua hàm meo_* (security definer). Bảng bật RLS, không có policy.

create table if not exists public.meo_players (
  id uuid primary key default gen_random_uuid(),
  username text not null unique check (username ~ '^[a-z0-9_]{3,16}$'),
  pass_hash text not null,
  recovery_hash text,
  recovery_at timestamptz,
  failed int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.meo_sessions (
  token uuid primary key default gen_random_uuid(),
  player_id uuid not null references public.meo_players (id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '180 days')
);
create index if not exists meo_sessions_player_idx on public.meo_sessions (player_id);
create index if not exists meo_sessions_exp_idx on public.meo_sessions (player_id, created_at desc);

create table if not exists public.meo_saves (
  player_id uuid primary key references public.meo_players (id) on delete cascade,
  state jsonb not null,
  updated_at timestamptz not null default now(),
  cats int not null default 0
);
create index if not exists meo_saves_updated_idx on public.meo_saves (updated_at desc);

create table if not exists public.meo_friends (
  player_id uuid not null references public.meo_players (id) on delete cascade,
  friend_id uuid not null references public.meo_players (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (player_id, friend_id),
  check (player_id <> friend_id)
);
create index if not exists meo_friends_friend_idx on public.meo_friends (friend_id);
create index if not exists meo_friends_created_idx on public.meo_friends (friend_id, created_at desc);

create table if not exists public.meo_visits (
  visitor_id uuid not null references public.meo_players (id) on delete cascade,
  host_id uuid not null references public.meo_players (id) on delete cascade,
  day date not null default (now() at time zone 'Asia/Ho_Chi_Minh')::date,
  pets int not null default 0,
  heart boolean not null default false,
  xu int not null default 0,
  claimed boolean not null default false,
  updated_at timestamptz not null default now(),
  fed boolean not null default false,
  cleaned boolean not null default false,
  applied boolean not null default false,
  claimed_xu int not null default 0,
  primary key (visitor_id, host_id, day),
  check (visitor_id <> host_id)
);
create index if not exists meo_visits_host_idx on public.meo_visits (host_id, updated_at desc);
create index if not exists meo_visits_host_day_idx on public.meo_visits (host_id, day);

alter table public.meo_players enable row level security;
alter table public.meo_sessions enable row level security;
alter table public.meo_saves enable row level security;
alter table public.meo_friends enable row level security;
alter table public.meo_visits enable row level security;

-- ===== Nội bộ =====
create or replace function public.meo_player(p_token uuid)
returns uuid language sql stable security definer set search_path = '' as $$
  select s.player_id from public.meo_sessions s where s.token = p_token and s.expires_at > now();
$$;

create or replace function public.meo_pid(p_username text)
returns uuid language sql stable security definer set search_path = '' as $$
  select id from public.meo_players where username = lower(trim(p_username));
$$;

create or replace function public.meo_session_new(p_player uuid)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_token uuid;
begin
  delete from public.meo_sessions where player_id = p_player and (expires_at < now()
    or token in (select token from public.meo_sessions where player_id = p_player order by created_at desc offset 9));
  insert into public.meo_sessions (player_id) values (p_player) returning token into v_token;
  return v_token;
end; $$;

-- ===== Tài khoản =====
create or replace function public.meo_register(p_username text, p_password text)
returns json language plpgsql security definer set search_path = '' as $$
declare v_user text := lower(trim(p_username)); v_id uuid; v_token uuid;
begin
  if v_user !~ '^[a-z0-9_]{3,16}$' then raise exception 'USERNAME_INVALID'; end if;
  if char_length(p_password) < 3 or char_length(p_password) > 6 then raise exception 'PASSWORD_INVALID'; end if;
  if exists (select 1 from public.meo_players where username = v_user) then raise exception 'USERNAME_TAKEN'; end if;
  insert into public.meo_players (username, pass_hash)
    values (v_user, extensions.crypt(p_password, extensions.gen_salt('bf'))) returning id into v_id;
  insert into public.meo_sessions (player_id) values (v_id) returning token into v_token;
  return json_build_object('token', v_token, 'username', v_user);
end; $$;

create or replace function public.meo_login(p_username text, p_password text)
returns json language plpgsql security definer set search_path = '' as $$
declare v_user text := lower(trim(p_username)); p public.meo_players; v_token uuid;
begin
  select * into p from public.meo_players where username = v_user;
  if not found then raise exception 'LOGIN_FAILED'; end if;
  if p.locked_until is not null and p.locked_until > now() then raise exception 'LOCKED'; end if;
  if p.pass_hash <> extensions.crypt(p_password, p.pass_hash) then
    update public.meo_players set failed = failed + 1,
      locked_until = case when failed + 1 >= 8 then now() + interval '5 minutes' else null end where id = p.id;
    raise exception 'LOGIN_FAILED';
  end if;
  update public.meo_players set failed = 0, locked_until = null where id = p.id and (failed <> 0 or locked_until is not null);
  v_token := public.meo_session_new(p.id);
  return json_build_object('token', v_token, 'username', p.username);
end; $$;

create or replace function public.meo_logout(p_token uuid)
returns void language sql security definer set search_path = '' as $$
  update public.meo_sessions set expires_at = now() where token = p_token;
$$;

create or replace function public.meo_recovery_create(p_token uuid)
returns json language plpgsql security definer set search_path = '' as $$
declare v_id uuid := public.meo_player(p_token); v_raw text; v_code text;
begin
  if v_id is null then raise exception 'SESSION'; end if;
  v_raw := upper(translate(encode(extensions.gen_random_bytes(6), 'base64'), '+/=0O1IL', 'XYZ2Q3JK'));
  v_code := substr(v_raw, 1, 4) || '-' || substr(v_raw, 5, 4);
  update public.meo_players set recovery_hash = extensions.crypt(v_code, extensions.gen_salt('bf')), recovery_at = now() where id = v_id;
  return json_build_object('code', v_code);
end; $$;

create or replace function public.meo_security_status(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_id uuid := public.meo_player(p_token); p public.meo_players;
begin
  if v_id is null then raise exception 'SESSION'; end if;
  select * into p from public.meo_players where id = v_id;
  return json_build_object('recovery', p.recovery_hash is not null, 'recovery_at', p.recovery_at);
end; $$;

create or replace function public.meo_recover(p_username text, p_code text, p_new_password text)
returns json language plpgsql security definer set search_path = '' as $$
declare v_user text := lower(trim(p_username)); v_code text := upper(trim(p_code)); p public.meo_players; v_token uuid;
begin
  if char_length(p_new_password) < 3 or char_length(p_new_password) > 6 then raise exception 'PASSWORD_INVALID'; end if;
  select * into p from public.meo_players where username = v_user;
  if not found or p.recovery_hash is null then raise exception 'RECOVER_FAILED'; end if;
  if p.locked_until is not null and p.locked_until > now() then raise exception 'LOCKED'; end if;
  if v_code !~ '-' and char_length(v_code) = 8 then v_code := substr(v_code, 1, 4) || '-' || substr(v_code, 5, 4); end if;
  if p.recovery_hash <> extensions.crypt(v_code, p.recovery_hash) then
    update public.meo_players set failed = failed + 1,
      locked_until = case when failed + 1 >= 8 then now() + interval '5 minutes' else null end where id = p.id;
    raise exception 'RECOVER_FAILED';
  end if;
  update public.meo_players set pass_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf')),
    recovery_hash = null, recovery_at = null, failed = 0, locked_until = null where id = p.id;
  update public.meo_sessions set expires_at = now() where player_id = p.id and expires_at > now();
  insert into public.meo_sessions (player_id) values (p.id) returning token into v_token;
  return json_build_object('token', v_token, 'username', p.username);
end; $$;

create or replace function public.meo_change_password(p_token uuid, p_old text, p_new text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_id uuid := public.meo_player(p_token); p public.meo_players;
begin
  if v_id is null then raise exception 'SESSION'; end if;
  if char_length(p_new) < 3 or char_length(p_new) > 6 then raise exception 'PASSWORD_INVALID'; end if;
  select * into p from public.meo_players where id = v_id;
  if p.pass_hash <> extensions.crypt(p_old, p.pass_hash) then raise exception 'OLD_WRONG'; end if;
  update public.meo_players set pass_hash = extensions.crypt(p_new, extensions.gen_salt('bf')) where id = v_id;
end; $$;

-- ===== Lưu game =====
create or replace function public.meo_load(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_id uuid := public.meo_player(p_token); v_state jsonb; v_at timestamptz;
begin
  if v_id is null then raise exception 'SESSION'; end if;
  select state, updated_at into v_state, v_at from public.meo_saves where player_id = v_id;
  return json_build_object('state', v_state, 'updated_at', v_at);
end; $$;

create or replace function public.meo_save(p_token uuid, p_state jsonb)
returns void language plpgsql security definer set search_path = '' as $$
declare v_id uuid := public.meo_player(p_token);
begin
  if v_id is null then raise exception 'SESSION'; end if;
  if pg_column_size(p_state) > 400000 then raise exception 'TOO_BIG'; end if;
  insert into public.meo_saves (player_id, state, cats, updated_at)
    values (v_id, p_state, coalesce(jsonb_array_length(p_state->'cats'), 0), now())
  on conflict (player_id) do update set state = excluded.state, cats = excluded.cats, updated_at = now();
end; $$;

-- ===== Bạn bè, ghé thăm =====
create or replace function public.meo_view(p_token uuid, p_username text)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_id uuid := public.meo_pid(p_username); v_s jsonb; v_at timestamptz;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  if v_id is null then raise exception 'NOT_FOUND'; end if;
  select state, updated_at into v_s, v_at from public.meo_saves where player_id = v_id;
  if v_s is null then raise exception 'NOT_FOUND'; end if;
  return json_build_object('username', lower(trim(p_username)), 'updated_at', v_at, 'me', v_id = v_me,
    'friend', exists (select 1 from public.meo_friends where player_id = v_me and friend_id = v_id),
    'state', jsonb_build_object('v', v_s->'v', 'houses', v_s->'houses', 'cats', v_s->'cats', 'lots', v_s->'lots', 'cur', 0, 'ch', 0));
end; $$;

create or replace function public.meo_friend_add(p_token uuid, p_username text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_id uuid := public.meo_pid(p_username);
begin
  if v_me is null then raise exception 'SESSION'; end if;
  if v_id is null then raise exception 'NOT_FOUND'; end if;
  if v_id = v_me then raise exception 'SELF'; end if;
  if (select count(*) from public.meo_friends where player_id = v_me) >= 100 then raise exception 'TOO_MANY'; end if;
  insert into public.meo_friends (player_id, friend_id) values (v_me, v_id) on conflict do nothing;
end; $$;

create or replace function public.meo_friend_remove(p_token uuid, p_username text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token);
begin
  if v_me is null then raise exception 'SESSION'; end if;
  delete from public.meo_friends where player_id = v_me and friend_id = public.meo_pid(p_username);
end; $$;

create or replace function public.meo_social(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_today date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  return json_build_object(
    'friends', coalesce((select json_agg(x order by x.active desc nulls last) from (
      select p.username, s.updated_at as active, coalesce(s.cats, 0) as cats,
        exists (select 1 from public.meo_friends b where b.player_id = f.friend_id and b.friend_id = v_me) as mutual,
        coalesce((select v.pets from public.meo_visits v where v.visitor_id = v_me and v.host_id = f.friend_id and v.day = v_today), -1) as pets_today
      from public.meo_friends f join public.meo_players p on p.id = f.friend_id
      left join public.meo_saves s on s.player_id = f.friend_id
      where f.player_id = v_me limit 100) x), '[]'::json),
    'suggest', coalesce((select json_agg(x) from (
      select * from (
        (select p.username, s.updated_at as active, coalesce(s.cats, 0) as cats, true as added_me, 0 as k
         from public.meo_friends b join public.meo_players p on p.id = b.player_id
         left join public.meo_saves s on s.player_id = b.player_id
         where b.friend_id = v_me
           and not exists (select 1 from public.meo_friends f where f.player_id = v_me and f.friend_id = b.player_id)
         order by b.created_at desc limit 6)
        union all
        (select p.username, r.updated_at, r.cats, false, 1
         from (select player_id, updated_at, cats from public.meo_saves order by updated_at desc limit 40) r
         join public.meo_players p on p.id = r.player_id
         where r.player_id <> v_me
           and not exists (select 1 from public.meo_friends f where f.player_id = v_me and f.friend_id = r.player_id)
           and not exists (select 1 from public.meo_friends b where b.player_id = r.player_id and b.friend_id = v_me))
      ) u order by k, active desc nulls last limit 12) x), '[]'::json));
end; $$;

create or replace function public.meo_visit(p_token uuid, p_username text, p_pet boolean default false, p_heart boolean default false, p_help text default null)
returns json language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_id uuid := public.meo_pid(p_username); v_today date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
  v_new boolean := false; r public.meo_visits; v_petted boolean := false; v_helped boolean := false;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  if v_id is null or v_id = v_me then raise exception 'NOT_FOUND'; end if;
  insert into public.meo_visits (visitor_id, host_id, day, xu) values (v_me, v_id, v_today, 5)
    on conflict do nothing returning true into v_new;
  select * into r from public.meo_visits where visitor_id = v_me and host_id = v_id and day = v_today;
  if p_pet and r.pets < 3 then
    update public.meo_visits set pets = pets + 1, xu = xu + 2, claimed = false, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
    v_petted := true;
  end if;
  if p_heart and not r.heart then
    update public.meo_visits set heart = true, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
  end if;
  if p_help = 'feed' and not r.fed then
    update public.meo_visits set fed = true, applied = false, xu = xu + 5, claimed = false, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
    v_helped := true;
  elsif p_help = 'clean' and not r.cleaned then
    update public.meo_visits set cleaned = true, applied = false, xu = xu + 5, claimed = false, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
    v_helped := true;
  end if;
  return json_build_object('first', coalesce(v_new, false), 'pets', r.pets, 'petted', v_petted, 'heart', r.heart, 'fed', r.fed, 'cleaned', r.cleaned, 'helped', v_helped);
end; $$;

create or replace function public.meo_guests(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token);
begin
  if v_me is null then raise exception 'SESSION'; end if;
  return json_build_object(
    'xu', coalesce((select sum(xu - claimed_xu) from public.meo_visits where host_id = v_me), 0),
    'list', coalesce((select json_agg(x) from (
      select p.username, v.day, v.pets, v.heart, v.fed, v.cleaned, v.updated_at
      from public.meo_visits v join public.meo_players p on p.id = v.visitor_id
      where v.host_id = v_me and v.day > (now() at time zone 'Asia/Ho_Chi_Minh')::date - 7
      order by v.updated_at desc limit 30) x), '[]'::json));
end; $$;

create or replace function public.meo_guests_claim(p_token uuid)
returns int language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_xu int;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  with c as (update public.meo_visits v set claimed = true, claimed_xu = v.xu
             from public.meo_visits o
             where o.visitor_id = v.visitor_id and o.host_id = v.host_id and o.day = v.day
               and v.host_id = v_me and v.xu > v.claimed_xu
             returning o.xu - o.claimed_xu as d)
  select coalesce(sum(d), 0) into v_xu from c;
  return v_xu;
end; $$;

create or replace function public.meo_help_take(p_token uuid)
returns json language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_feed int; v_clean int; v_names text;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  with c as (update public.meo_visits set applied = true where host_id = v_me and not applied and (fed or cleaned) returning visitor_id, fed, cleaned)
  select count(*) filter (where fed), count(*) filter (where cleaned), string_agg(distinct p.username, ', ')
    into v_feed, v_clean, v_names from c join public.meo_players p on p.id = c.visitor_id;
  return json_build_object('feed', coalesce(v_feed,0), 'clean', coalesce(v_clean,0), 'names', v_names);
end; $$;

create or replace function public.meo_inbox(p_token uuid)
returns json language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_feed int; v_clean int; v_names text;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  delete from public.meo_visits where host_id = v_me and day < (now() at time zone 'Asia/Ho_Chi_Minh')::date - 30 and claimed_xu >= xu;
  with c as (update public.meo_visits set applied = true where host_id = v_me and not applied and (fed or cleaned) returning visitor_id, fed, cleaned)
  select count(*) filter (where fed), count(*) filter (where cleaned), string_agg(distinct p.username, ', ')
    into v_feed, v_clean, v_names from c join public.meo_players p on p.id = c.visitor_id;
  return json_build_object(
    'help', json_build_object('feed', coalesce(v_feed,0), 'clean', coalesce(v_clean,0), 'names', v_names),
    'xu', coalesce((select sum(xu - claimed_xu) from public.meo_visits where host_id = v_me), 0),
    'list', coalesce((select json_agg(x) from (
      select p.username, v.day, v.pets, v.heart, v.fed, v.cleaned, v.updated_at
      from public.meo_visits v join public.meo_players p on p.id = v.visitor_id
      where v.host_id = v_me and v.day > (now() at time zone 'Asia/Ho_Chi_Minh')::date - 7
      order by v.updated_at desc limit 30) x), '[]'::json));
end; $$;

-- ===== Quyền =====
revoke all on public.meo_players, public.meo_sessions, public.meo_saves, public.meo_friends, public.meo_visits from anon, authenticated;
revoke all on function public.meo_player(uuid) from public, anon, authenticated;
revoke all on function public.meo_pid(text) from public, anon, authenticated;
revoke all on function public.meo_session_new(uuid) from public, anon, authenticated;
grant execute on function public.meo_register(text, text) to anon, authenticated;
grant execute on function public.meo_login(text, text) to anon, authenticated;
grant execute on function public.meo_logout(uuid) to anon, authenticated;
grant execute on function public.meo_recovery_create(uuid) to anon, authenticated;
grant execute on function public.meo_security_status(uuid) to anon, authenticated;
grant execute on function public.meo_recover(text, text, text) to anon, authenticated;
grant execute on function public.meo_change_password(uuid, text, text) to anon, authenticated;
grant execute on function public.meo_load(uuid) to anon, authenticated;
grant execute on function public.meo_save(uuid, jsonb) to anon, authenticated;
grant execute on function public.meo_view(uuid, text) to anon, authenticated;
grant execute on function public.meo_friend_add(uuid, text) to anon, authenticated;
grant execute on function public.meo_friend_remove(uuid, text) to anon, authenticated;
grant execute on function public.meo_social(uuid) to anon, authenticated;
grant execute on function public.meo_visit(uuid, text, boolean, boolean, text) to anon, authenticated;
grant execute on function public.meo_guests(uuid) to anon, authenticated;
grant execute on function public.meo_guests_claim(uuid) to anon, authenticated;
grant execute on function public.meo_help_take(uuid) to anon, authenticated;
grant execute on function public.meo_inbox(uuid) to anon, authenticated;
