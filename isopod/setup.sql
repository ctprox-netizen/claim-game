-- 우리집 등각류 기록지 · Supabase 설정 (SQL Editor에 붙여 넣고 Run 한 번)
-- 누구나 볼 수 있고, 기록·수정·삭제는 등록된 계정(iso_editor)만 할 수 있어요.
create table if not exists iso_log(
  cid text primary key,
  fam text not null,
  tub text not null,
  who text,
  kind text not null,
  val jsonb,
  note text,
  at timestamptz not null default now(),
  del boolean not null default false,
  upd timestamptz not null default now()
);
create index if not exists iso_log_fam_upd on iso_log(fam, upd);

create table if not exists iso_photo(
  cid text primary key,
  fam text not null,
  tub text not null,
  who text,
  note text,
  thumb text not null,
  data text not null,
  at timestamptz not null default now(),
  del boolean not null default false,
  upd timestamptz not null default now()
);
create index if not exists iso_photo_fam_upd on iso_photo(fam, upd);

-- 공개할 기록지(지금까지 쓰던 기록지)와 기록할 수 있는 사람 목록
create table if not exists iso_cfg(id int primary key default 1 check (id = 1), fam text not null);
create table if not exists iso_editor(email text primary key, name text not null);

-- 표에 직접 접근은 막고, 아래 함수로만 읽고 쓰게 해요
alter table iso_log enable row level security;
alter table iso_photo enable row level security;
alter table iso_cfg enable row level security;
alter table iso_editor enable row level security;

-- 지금까지 쓰던 기록지(기록이 가장 많은 것)를 공개 기록지로 정해요
insert into iso_cfg(id, fam)
select 1, fam from (
  select fam, count(*) n from iso_log group by fam
  union all
  select fam, count(*) n from iso_photo group by fam
) t group by fam order by sum(n) desc limit 1
on conflict (id) do nothing;
insert into iso_cfg(id, fam) values (1, 'home') on conflict (id) do nothing;

create or replace function iso_fam() returns text
language sql stable security definer set search_path = public as $$
  select fam from iso_cfg where id = 1;
$$;

-- 로그인한 계정이 기록 권한이 있으면 이름(나/아빠)을, 없으면 null을 돌려줘요
create or replace function iso_me() returns text
language sql stable security definer set search_path = public as $$
  select name from iso_editor
  where coalesce(auth.jwt()->>'role', '') = 'authenticated'
    and lower(email) = lower(coalesce(auth.jwt()->>'email', ''));
$$;

create or replace function iso_whoami() returns text
language sql stable security definer set search_path = public as $$
  select iso_me();
$$;

-- 보기 (누구나)
create or replace function iso_view(since timestamptz default '1970-01-01')
returns json language plpgsql stable security definer set search_path = public as $$
declare f text := iso_fam();
begin
  return json_build_object(
    'logs', (select coalesce(json_agg(l order by l.upd), '[]'::json) from
             (select cid, tub, who, kind, val, note, at, del, upd from iso_log where fam = f and upd > since) l),
    'photos', (select coalesce(json_agg(p order by p.upd), '[]'::json) from
             (select cid, tub, who, note, thumb, at, del, upd from iso_photo where fam = f and upd > since) p),
    'now', now());
end $$;

create or replace function iso_view_photo(id text) returns text
language sql stable security definer set search_path = public as $$
  select data from iso_photo where fam = iso_fam() and cid = id and not del;
$$;

-- 기록·사진·삭제 (등록된 계정만)
create or replace function iso_write(items json) returns int
language plpgsql security definer set search_path = public as $$
declare x json; n int := 0; me text := iso_me(); f text := iso_fam();
begin
  if me is null then raise exception 'not allowed' using errcode = '42501'; end if;
  for x in select * from json_array_elements(items) loop
    insert into iso_log(cid, fam, tub, who, kind, val, note, at)
    values (x->>'cid', f, x->>'tub', me, x->>'kind', x->'val', left(x->>'note', 2000),
            coalesce((x->>'at')::timestamptz, now()))
    on conflict (cid) do nothing;
    n := n + 1;
  end loop;
  return n;
end $$;

create or replace function iso_write_photo(p json) returns void
language plpgsql security definer set search_path = public as $$
declare me text := iso_me();
begin
  if me is null then raise exception 'not allowed' using errcode = '42501'; end if;
  if length(p->>'data') > 1500000 then raise exception 'photo too large'; end if;
  insert into iso_photo(cid, fam, tub, who, note, thumb, data, at)
  values (p->>'cid', iso_fam(), p->>'tub', me, left(p->>'note', 2000), p->>'thumb', p->>'data',
          coalesce((p->>'at')::timestamptz, now()))
  on conflict (cid) do nothing;
end $$;

create or replace function iso_remove(id text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if iso_me() is null then raise exception 'not allowed' using errcode = '42501'; end if;
  update iso_log set del = true, upd = now() where fam = iso_fam() and cid = id;
  update iso_photo set del = true, upd = now() where fam = iso_fam() and cid = id;
end $$;

-- 예전 '비밀 링크' 함수는 막아요 (링크를 아는 사람도 더는 못 써요)
do $$ begin
  revoke execute on function iso_pull(text, timestamptz) from public, anon, authenticated;
  revoke execute on function iso_push(text, json) from public, anon, authenticated;
  revoke execute on function iso_photo_add(text, json) from public, anon, authenticated;
  revoke execute on function iso_photo_get(text, text) from public, anon, authenticated;
  revoke execute on function iso_del(text, text) from public, anon, authenticated;
exception when undefined_function then null; end $$;

revoke execute on function iso_fam() from public, anon, authenticated;
revoke execute on function iso_me() from public, anon, authenticated;
revoke execute on function iso_write(json) from public, anon;
revoke execute on function iso_write_photo(json) from public, anon;
revoke execute on function iso_remove(text) from public, anon;
grant execute on function iso_view(timestamptz) to anon, authenticated;
grant execute on function iso_view_photo(text) to anon, authenticated;
grant execute on function iso_whoami() to anon, authenticated;
grant execute on function iso_write(json) to authenticated;
grant execute on function iso_write_photo(json) to authenticated;
grant execute on function iso_remove(text) to authenticated;

-- ===== 대표 사진 · 앨범 9칸 · 메모장 (v4) =====
-- 0번 칸 = 대표 사진, 1~9번 칸 = 앨범. 교체하면 예전 사진은 서버에서 지워져요.
create table if not exists iso_gal(
  fam text not null,
  tub text not null check (length(tub) <= 8),
  slot int not null check (slot between -1 and 9),
  thumb text not null,
  data text not null,
  who text,
  upd timestamptz not null default now(),
  primary key (fam, tub, slot)
);
alter table iso_gal enable row level security;
alter table iso_gal drop constraint if exists iso_gal_slot_check;
alter table iso_gal add constraint iso_gal_slot_check check (slot between -1 and 9);
drop function if exists iso_gal_swap(text, int, int);

-- 목록 (누구나): 대표(0)와 앨범(1~9) 칸의 위치·시각, 미리보기는 since 이후 바뀐 칸만
create or replace function iso_gal_list(since timestamptz default '1970-01-01')
returns json language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object('tub', tub, 'slot', slot, 'who', who, 'upd', upd,
           'thumb', case when upd > since then thumb end) order by tub, slot), '[]'::json)
  from iso_gal where fam = iso_fam() and slot between 0 and 9;
$$;

-- 원본 사진 (누구나)
create or replace function iso_gal_get(t text, s int) returns text
language sql stable security definer set search_path = public as $$
  select data from iso_gal where fam = iso_fam() and tub = t and slot = s;
$$;

-- 올리기·교체 (등록된 계정만)
create or replace function iso_gal_set(t text, s int, th text, d text) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare me text := iso_me(); u timestamptz := clock_timestamp();
begin
  if me is null then raise exception 'not allowed' using errcode = '42501'; end if;
  if s < 0 or s > 9 then raise exception 'bad slot'; end if;
  if length(d) > 1000000 or length(th) > 120000 then raise exception 'photo too large'; end if;
  insert into iso_gal(fam, tub, slot, thumb, data, who, upd) values (iso_fam(), t, s, th, d, me, u)
  on conflict (fam, tub, slot) do update set thumb = excluded.thumb, data = excluded.data, who = excluded.who, upd = excluded.upd;
  return u;
end $$;

-- 지우기 (등록된 계정만) — 서버에서 실제로 지워요
create or replace function iso_gal_del(t text, s int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if iso_me() is null then raise exception 'not allowed' using errcode = '42501'; end if;
  delete from iso_gal where fam = iso_fam() and tub = t and slot = s;
end $$;

-- 앨범 사진을 대표 사진(0번)으로 복사
create or replace function iso_gal_cover(t text, s int) returns void
language plpgsql security definer set search_path = public as $$
declare me text := iso_me(); f text := iso_fam();
begin
  if me is null then raise exception 'not allowed' using errcode = '42501'; end if;
  insert into iso_gal(fam, tub, slot, thumb, data, who, upd)
  select fam, tub, 0, thumb, data, me, clock_timestamp() from iso_gal where fam = f and tub = t and slot = s
  on conflict (fam, tub, slot) do update set thumb = excluded.thumb, data = excluded.data, who = excluded.who, upd = excluded.upd;
end $$;

-- 사육통마다 메모장 하나
create table if not exists iso_memo(
  fam text not null,
  tub text not null check (length(tub) <= 8),
  body text not null default '',
  who text,
  upd timestamptz not null default now(),
  primary key (fam, tub)
);
alter table iso_memo enable row level security;

create or replace function iso_memo_list(since timestamptz default '1970-01-01')
returns json language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(json_build_object('tub', tub, 'body', body, 'who', who, 'upd', upd)), '[]'::json)
  from iso_memo where fam = iso_fam() and upd > since;
$$;

create or replace function iso_memo_set(t text, b text) returns timestamptz
language plpgsql security definer set search_path = public as $$
declare me text := iso_me(); u timestamptz := clock_timestamp();
begin
  if me is null then raise exception 'not allowed' using errcode = '42501'; end if;
  if length(b) > 20000 then raise exception 'memo too long'; end if;
  insert into iso_memo(fam, tub, body, who, upd) values (iso_fam(), t, coalesce(b, ''), me, u)
  on conflict (fam, tub) do update set body = excluded.body, who = excluded.who, upd = excluded.upd;
  return u;
end $$;

revoke execute on function iso_gal_set(text, int, text, text) from public, anon;
revoke execute on function iso_gal_del(text, int) from public, anon;
revoke execute on function iso_gal_cover(text, int) from public, anon;
revoke execute on function iso_memo_set(text, text) from public, anon;
grant execute on function iso_gal_list(timestamptz) to anon, authenticated;
grant execute on function iso_gal_get(text, int) to anon, authenticated;
grant execute on function iso_gal_set(text, int, text, text) to authenticated;
grant execute on function iso_gal_del(text, int) to authenticated;
grant execute on function iso_gal_cover(text, int) to authenticated;
grant execute on function iso_memo_list(timestamptz) to anon, authenticated;
grant execute on function iso_memo_set(text, text) to authenticated;

-- ===== 남은 용량 보기 (v5) =====
create or replace function iso_usage() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object(
    'db', pg_database_size(current_database()),
    'gal', pg_total_relation_size('iso_gal'),
    'log', pg_total_relation_size('iso_log') + pg_total_relation_size('iso_photo'),
    'memo', pg_total_relation_size('iso_memo'),
    'nphoto', (select count(*) from iso_gal),
    'ndiary', (select count(*) from iso_log where kind = 'diary' and not del),
    'nlog', (select count(*) from iso_log where kind <> 'diary' and not del));
$$;
grant execute on function iso_usage() to anon, authenticated;
