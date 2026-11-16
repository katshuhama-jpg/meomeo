-- Nhà Mèo Méo: bạn bè, gợi ý kết bạn, ghé thăm nhà nhau.
-- Chỉ gọi qua các hàm meo_* (security definer). Bảng bật RLS, không có policy.

create table if not exists public.meo_friends (
  player_id uuid not null references public.meo_players (id) on delete cascade,
  friend_id uuid not null references public.meo_players (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (player_id, friend_id),
  check (player_id <> friend_id)
);
create index if not exists meo_friends_friend_idx on public.meo_friends (friend_id);

-- Mỗi khách, mỗi nhà, mỗi ngày một dòng: số lần vuốt (tối đa 3), tim, xu chủ nhà được nhận
create table if not exists public.meo_visits (
  visitor_id uuid not null references public.meo_players (id) on delete cascade,
  host_id uuid not null references public.meo_players (id) on delete cascade,
  day date not null default (now() at time zone 'Asia/Ho_Chi_Minh')::date,
  pets int not null default 0,
  heart boolean not null default false,
  xu int not null default 0,
  claimed boolean not null default false,
  updated_at timestamptz not null default now(),
  primary key (visitor_id, host_id, day),
  check (visitor_id <> host_id)
);
create index if not exists meo_visits_host_idx on public.meo_visits (host_id, updated_at desc);
create index if not exists meo_saves_updated_idx on public.meo_saves (updated_at desc);

alter table public.meo_friends enable row level security;
alter table public.meo_visits enable row level security;

create or replace function public.meo_pid(p_username text)
returns uuid language sql stable security definer set search_path = '' as $$
  select id from public.meo_players where username = lower(trim(p_username));
$$;

-- Xem nhà người khác: chỉ trả phần cần vẽ nhà (nhà, phòng, đồ, mèo), không có thông tin tài khoản
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

-- Danh sách bạn + gợi ý (người đã thêm mình trước, rồi người mới chơi gần đây)
create or replace function public.meo_social(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_today date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  return json_build_object(
    'friends', coalesce((select json_agg(x order by x.active desc nulls last) from (
      select p.username, s.updated_at as active, coalesce(jsonb_array_length(s.state->'cats'), 0) as cats,
        exists (select 1 from public.meo_friends b where b.player_id = f.friend_id and b.friend_id = v_me) as mutual,
        coalesce((select v.pets from public.meo_visits v where v.visitor_id = v_me and v.host_id = f.friend_id and v.day = v_today), -1) as pets_today
      from public.meo_friends f join public.meo_players p on p.id = f.friend_id
      left join public.meo_saves s on s.player_id = f.friend_id
      where f.player_id = v_me) x), '[]'::json),
    'suggest', coalesce((select json_agg(x) from (
      select p.username, s.updated_at as active, coalesce(jsonb_array_length(s.state->'cats'), 0) as cats,
        exists (select 1 from public.meo_friends b where b.player_id = p.id and b.friend_id = v_me) as added_me
      from public.meo_saves s join public.meo_players p on p.id = s.player_id
      where s.player_id <> v_me
        and not exists (select 1 from public.meo_friends f where f.player_id = v_me and f.friend_id = s.player_id)
      order by exists (select 1 from public.meo_friends b where b.player_id = s.player_id and b.friend_id = v_me) desc, s.updated_at desc
      limit 12) x), '[]'::json));
end; $$;

-- Ghé thăm: p_pet = vuốt 1 lần (tối đa 3/nhà/ngày), p_heart = thả tim. Trả về số lần đã vuốt hôm nay.
-- Chủ nhà được 5 xu lần đầu ghé trong ngày, 2 xu mỗi lần vuốt.
create or replace function public.meo_visit(p_token uuid, p_username text, p_pet boolean default false, p_heart boolean default false)
returns json language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_id uuid := public.meo_pid(p_username); v_today date := (now() at time zone 'Asia/Ho_Chi_Minh')::date;
  v_new boolean := false; r public.meo_visits; v_petted boolean := false;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  if v_id is null or v_id = v_me then raise exception 'NOT_FOUND'; end if;
  insert into public.meo_visits (visitor_id, host_id, day, xu) values (v_me, v_id, v_today, 5)
    on conflict do nothing returning true into v_new;
  select * into r from public.meo_visits where visitor_id = v_me and host_id = v_id and day = v_today;
  if p_pet and r.pets < 3 then
    update public.meo_visits set pets = pets + 1, xu = xu + 2, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
    v_petted := true;
  end if;
  if p_heart and not r.heart then
    update public.meo_visits set heart = true, updated_at = now() where visitor_id = v_me and host_id = v_id and day = v_today returning * into r;
  end if;
  return json_build_object('first', coalesce(v_new, false), 'pets', r.pets, 'petted', v_petted, 'heart', r.heart);
end; $$;

-- Khách đã ghé nhà mình 7 ngày gần đây + xu chưa nhận
create or replace function public.meo_guests(p_token uuid)
returns json language plpgsql stable security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token);
begin
  if v_me is null then raise exception 'SESSION'; end if;
  return json_build_object(
    'xu', coalesce((select sum(xu) from public.meo_visits where host_id = v_me and not claimed), 0),
    'list', coalesce((select json_agg(x) from (
      select p.username, v.day, v.pets, v.heart, v.updated_at
      from public.meo_visits v join public.meo_players p on p.id = v.visitor_id
      where v.host_id = v_me and v.day > (now() at time zone 'Asia/Ho_Chi_Minh')::date - 7
      order by v.updated_at desc limit 30) x), '[]'::json));
end; $$;

create or replace function public.meo_guests_claim(p_token uuid)
returns int language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.meo_player(p_token); v_xu int;
begin
  if v_me is null then raise exception 'SESSION'; end if;
  with c as (update public.meo_visits set claimed = true where host_id = v_me and not claimed returning xu)
  select coalesce(sum(xu), 0) into v_xu from c;
  return v_xu;
end; $$;

revoke all on function public.meo_pid(text) from public, anon, authenticated;
grant execute on function public.meo_view(uuid, text) to anon, authenticated;
grant execute on function public.meo_friend_add(uuid, text) to anon, authenticated;
grant execute on function public.meo_friend_remove(uuid, text) to anon, authenticated;
grant execute on function public.meo_social(uuid) to anon, authenticated;
grant execute on function public.meo_visit(uuid, text, boolean, boolean) to anon, authenticated;
grant execute on function public.meo_guests(uuid) to anon, authenticated;
grant execute on function public.meo_guests_claim(uuid) to anon, authenticated;
