-- Nhà Mèo Méo: tài khoản riêng của game và bản lưu trên mây.
-- Tên đăng nhập + mật khẩu 3-6 ký tự (bcrypt), mã khôi phục khi quên mật khẩu, đổi mật khẩu.
-- Bảng có tiền tố meo_. Trình duyệt không đọc/ghi bảng trực tiếp, chỉ gọi các hàm meo_* bên dưới.
create extension if not exists pgcrypto with schema extensions;

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
  expires_at timestamptz not null default now() + interval '180 days'
);
create index if not exists meo_sessions_player_idx on public.meo_sessions (player_id);
create table if not exists public.meo_saves (
  player_id uuid primary key references public.meo_players (id) on delete cascade,
  state jsonb not null,
  updated_at timestamptz not null default now()
);
-- Bật RLS, không có policy: anon không đọc/ghi bảng được, chỉ qua hàm security definer
alter table public.meo_players enable row level security;
alter table public.meo_sessions enable row level security;
alter table public.meo_saves enable row level security;

create or replace function public.meo_player(p_token uuid)
returns uuid language sql stable security definer set search_path = '' as $$
  select s.player_id from public.meo_sessions s where s.token = p_token and s.expires_at > now();
$$;

-- Đăng ký
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

-- Đăng nhập (khóa 5 phút sau 8 lần sai)
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
  update public.meo_players set failed = 0, locked_until = null where id = p.id;
  insert into public.meo_sessions (player_id) values (p.id) returning token into v_token;
  return json_build_object('token', v_token, 'username', p.username);
end; $$;

create or replace function public.meo_logout(p_token uuid)
returns void language sql security definer set search_path = '' as $$
  update public.meo_sessions set expires_at = now() where token = p_token;
$$;

-- Mã khôi phục: tạo mã mới (mã cũ hết hiệu lực), trả mã gốc đúng một lần
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

-- Quên mật khẩu: đúng tên + mã thì đặt mật khẩu mới, mã hết hiệu lực, cấp phiên mới
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

-- Đổi mật khẩu khi đang đăng nhập
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

-- Bản lưu trên mây
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
  insert into public.meo_saves (player_id, state, updated_at) values (v_id, p_state, now())
  on conflict (player_id) do update set state = excluded.state, updated_at = now();
end; $$;

revoke all on function public.meo_player(uuid) from public, anon, authenticated;
grant execute on function public.meo_register(text, text) to anon, authenticated;
grant execute on function public.meo_login(text, text) to anon, authenticated;
grant execute on function public.meo_logout(uuid) to anon, authenticated;
grant execute on function public.meo_recovery_create(uuid) to anon, authenticated;
grant execute on function public.meo_security_status(uuid) to anon, authenticated;
grant execute on function public.meo_recover(text, text, text) to anon, authenticated;
grant execute on function public.meo_change_password(uuid, text, text) to anon, authenticated;
grant execute on function public.meo_load(uuid) to anon, authenticated;
grant execute on function public.meo_save(uuid, jsonb) to anon, authenticated;
