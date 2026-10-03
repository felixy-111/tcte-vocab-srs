-- ============================================================
-- 統測單字（SRS App）— 雲端同步  001_srs.sql
--
-- 用法：Supabase（跟「統測字彙練習 app」同一個專案）→ SQL Editor →
--       貼上整份 → Run。整份包在一個交易裡：中途出錯就全部不生效。
--       重複執行是安全的（建表用 if not exists、函式用 create or replace）。
--
-- 前提（沿用既有專案設定，請確認仍成立）：
--   Authentication → Providers → Email →「Allow new users to sign up」是關的。
--
-- 設計摘要（細節見同資料夾 SECURITY.md）：
--   srs_teachers     老師名單（auth 帳號 uid）。執行本檔時，自動把「目前所有有 email 的帳號」加進來；
--                    檔尾最後一個查詢會列出名單，請確認只有你自己。
--   srs_students     學生（暱稱＋連結代碼的 SHA-256 雜湊；代碼本身不存）
--   srs_state        每位學生一整包進度（jsonb）＋版本號 rev（防兩台同時寫互蓋）
--   srs_state_backup 每位學生每天第一次上傳前的舊進度快照，保留 14 天（救援用，只能從 SQL Editor 讀）
--
--   學生（anon，沒登入）：完全不能直接讀寫任何表；只能呼叫
--     srs_load(代碼) / srs_save(代碼, 變更, 版本號)，函式內部用代碼雜湊找到「自己那一列」。
--   老師（authenticated 且在 srs_teachers 裡）：可讀 srs_students（不含雜湊欄）與 srs_state；
--     建學生、重設連結只能透過 srs_create_student / srs_reset_link。
-- ============================================================

begin;

-- ---------- 表 ----------
create table if not exists public.srs_teachers (
  user_id  uuid primary key references auth.users (id) on delete cascade,
  added_at timestamptz not null default now()
);

create table if not exists public.srs_students (
  id            uuid primary key default gen_random_uuid(),
  name          text not null check (char_length(name) between 1 and 40),
  token_hash    bytea not null unique,          -- sha256(連結代碼)；代碼只在建立/重設時回傳一次
  created_at    timestamptz not null default now(),
  link_reset_at timestamptz
);

create table if not exists public.srs_state (
  student_id uuid primary key references public.srs_students (id) on delete cascade,
  state      jsonb not null default '{"v":2,"cards":{},"intro":{},"days":{},"log":[]}'::jsonb,
  rev        bigint not null default 0,
  bytes      integer not null default 0,
  updated_at timestamptz not null default now()
);

create table if not exists public.srs_state_backup (
  student_id uuid not null references public.srs_students (id) on delete cascade,
  day        date not null,                     -- 台北日期
  rev        bigint not null,
  state      jsonb not null,
  saved_at   timestamptz not null default now(),
  primary key (student_id, day)
);

-- ---------- RLS＋權限：預設全部收回，再只開必要的 ----------
alter table public.srs_teachers     enable row level security;
alter table public.srs_students     enable row level security;
alter table public.srs_state        enable row level security;
alter table public.srs_state_backup enable row level security;

revoke all on table public.srs_teachers, public.srs_students, public.srs_state, public.srs_state_backup
  from public, anon, authenticated;

-- 老師只需要「讀」；欄位級授權：不給 token_hash
grant select (id, name, created_at, link_reset_at) on public.srs_students to authenticated;
grant select (student_id, state, rev, bytes, updated_at) on public.srs_state to authenticated;

-- ---------- 老師判定 ----------
create or replace function public.srs_is_teacher()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (select 1 from public.srs_teachers t where t.user_id = (select auth.uid()));
$$;

drop policy if exists srs_students_teacher_read on public.srs_students;
create policy srs_students_teacher_read on public.srs_students
  for select to authenticated using ((select public.srs_is_teacher()));

drop policy if exists srs_state_teacher_read on public.srs_state;
create policy srs_state_teacher_read on public.srs_state
  for select to authenticated using ((select public.srs_is_teacher()));
-- srs_teachers、srs_state_backup：沒有任何 policy＋沒有授權 → API 完全碰不到

-- ---------- 學生：讀進度 ----------
-- 回傳 {ok, sid, name, rev, state}；p_rev 跟雲端一樣時不回 state（省流量）
create or replace function public.srs_load(p_token text, p_rev bigint default null)
returns jsonb
language plpgsql stable security definer
set search_path = ''
as $$
declare
  v_id uuid; v_name text; v_rev bigint; v_state jsonb;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  select s.id, s.name into v_id, v_name
    from public.srs_students s
   where s.token_hash = sha256(convert_to(p_token, 'UTF8'));
  if v_id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  select st.rev, st.state into v_rev, v_state from public.srs_state st where st.student_id = v_id;
  if v_rev is null then
    return jsonb_build_object('ok', false, 'error', 'no_state');
  end if;
  if p_rev is not null and p_rev = v_rev then
    return jsonb_build_object('ok', true, 'sid', v_id, 'name', v_name, 'rev', v_rev, 'unchanged', true);
  end if;
  return jsonb_build_object('ok', true, 'sid', v_id, 'name', v_name, 'rev', v_rev, 'state', v_state);
end
$$;

-- ---------- 學生：上傳變更 ----------
-- p_patch 只含「這台改過的部分」：{cards:{字:卡}, intro:{字:時間}, days:{日期:當日紀錄}, log:[作答]}
-- p_base_rev 必須等於雲端目前的 rev（＝這台上次同步後雲端沒被別台改過），否則回 conflict＋雲端整包，
-- 由 App 合併後重送。合併規則在 App（index.html 的 mergeState）。
create or replace function public.srs_save(p_token text, p_patch jsonb, p_base_rev bigint)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  c_max_patch constant integer := 2000000;   -- 單次上傳上限（約 2 MB）
  c_max_state constant integer := 4000000;   -- 整包進度上限（約 4 MB；一年的量估計 < 1 MB）
  c_log_cap   constant integer := 5000;
  v_id uuid; v_rev bigint; v_state jsonb; v_upd timestamptz; v_new jsonb; v_log jsonb; v_bytes integer;
  v_today date := (now() at time zone 'Asia/Taipei')::date;
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;
  select s.id into v_id from public.srs_students s
   where s.token_hash = sha256(convert_to(p_token, 'UTF8'));
  if v_id is null then
    return jsonb_build_object('ok', false, 'error', 'invalid_link');
  end if;

  -- 形狀與大小檢查（不合格整筆拒收）
  if p_patch is null or jsonb_typeof(p_patch) <> 'object' then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;
  if octet_length(p_patch::text) > c_max_patch then
    return jsonb_build_object('ok', false, 'error', 'too_large');
  end if;
  if exists (select 1 from jsonb_object_keys(p_patch) k where k not in ('cards', 'intro', 'days', 'log')) then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;
  if p_patch ? 'cards' and (jsonb_typeof(p_patch -> 'cards') <> 'object' or exists (
       select 1 from jsonb_each(p_patch -> 'cards') e
        where jsonb_typeof(e.value) <> 'object' or char_length(e.key) > 100)) then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;
  if p_patch ? 'intro' and (jsonb_typeof(p_patch -> 'intro') <> 'object' or exists (
       select 1 from jsonb_each(p_patch -> 'intro') e
        where jsonb_typeof(e.value) <> 'number' or char_length(e.key) > 100)) then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;
  if p_patch ? 'days' and (jsonb_typeof(p_patch -> 'days') <> 'object' or exists (
       select 1 from jsonb_each(p_patch -> 'days') e
        where jsonb_typeof(e.value) <> 'object' or e.key !~ '^\d{4}-\d{2}-\d{2}$')) then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;
  if p_patch ? 'log' and (jsonb_typeof(p_patch -> 'log') <> 'array' or exists (
       select 1 from jsonb_array_elements(p_patch -> 'log') a(e)
        where jsonb_typeof(a.e) <> 'object'
           or jsonb_typeof(a.e -> 't') is distinct from 'number'
           or jsonb_typeof(a.e -> 'id') is distinct from 'string'
           or char_length(a.e ->> 'id') > 100)) then
    return jsonb_build_object('ok', false, 'error', 'bad_patch');
  end if;

  -- 版本檢查（鎖住這一列，兩台同時送只會有一台成功）
  select st.rev, st.state, st.updated_at into v_rev, v_state, v_upd
    from public.srs_state st where st.student_id = v_id for update;
  if v_rev is null then
    return jsonb_build_object('ok', false, 'error', 'no_state');
  end if;
  if p_base_rev is null or p_base_rev <> v_rev then
    return jsonb_build_object('ok', false, 'error', 'conflict', 'rev', v_rev, 'state', v_state);
  end if;
  if p_patch = '{}'::jsonb then
    return jsonb_build_object('ok', true, 'rev', v_rev);
  end if;
  -- 簡單節流：同一位學生 2 秒內只收一次寫入（App 本身每 5 秒以上才送一次）
  if v_rev > 0 and v_upd > now() - interval '2 seconds' then
    return jsonb_build_object('ok', false, 'error', 'too_fast');
  end if;

  v_new := v_state;
  if p_patch ? 'cards' then
    v_new := jsonb_set(v_new, '{cards}', coalesce(v_new -> 'cards', '{}'::jsonb) || (p_patch -> 'cards'));
  end if;
  if p_patch ? 'intro' then
    v_new := jsonb_set(v_new, '{intro}', coalesce(v_new -> 'intro', '{}'::jsonb) || (p_patch -> 'intro'));
  end if;
  if p_patch ? 'days' then
    v_new := jsonb_set(v_new, '{days}', coalesce(v_new -> 'days', '{}'::jsonb) || (p_patch -> 'days'));
  end if;
  if p_patch ? 'log' then
    -- 合併、以 (時間, 字) 去重、依時間排序、只留最新 5000 筆
    select coalesce(jsonb_agg(x.e order by x.t, x.id), '[]'::jsonb) into v_log
      from (select d.e, d.t, d.id
              from (select distinct on (u.t, u.id) u.e, u.t, u.id
                      from (select a.e, (a.e ->> 't')::numeric as t, a.e ->> 'id' as id
                              from jsonb_array_elements(coalesce(v_new -> 'log', '[]'::jsonb) || (p_patch -> 'log')) a(e)) u
                     order by u.t, u.id) d
             order by d.t desc, d.id desc
             limit c_log_cap) x;
    v_new := jsonb_set(v_new, '{log}', v_log);
  end if;

  v_bytes := octet_length(v_new::text);
  if v_bytes > c_max_state then
    return jsonb_build_object('ok', false, 'error', 'too_large');
  end if;

  -- 每天第一次寫入前，先把舊的整包存一份（保留 14 天）
  insert into public.srs_state_backup (student_id, day, rev, state)
       values (v_id, v_today, v_rev, v_state)
  on conflict (student_id, day) do nothing;
  delete from public.srs_state_backup b where b.student_id = v_id and b.day < v_today - 14;

  update public.srs_state
     set state = v_new, rev = v_rev + 1, bytes = v_bytes, updated_at = now()
   where student_id = v_id;
  return jsonb_build_object('ok', true, 'rev', v_rev + 1);
end
$$;

-- ---------- 老師：建學生（回傳連結代碼，只出現這一次） ----------
create or replace function public.srs_create_student(p_name text)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  v_name text := btrim(coalesce(p_name, ''));
  v_token text; v_id uuid;
begin
  if not public.srs_is_teacher() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if char_length(v_name) not between 1 and 40 then
    return jsonb_build_object('ok', false, 'error', 'bad_name');
  end if;
  -- gen_random_uuid() 用的是資料庫的強亂數；去掉 - 後 32 個十六進位字＝122 bits 隨機
  v_token := replace(gen_random_uuid()::text, '-', '');
  insert into public.srs_students (name, token_hash)
       values (v_name, sha256(convert_to(v_token, 'UTF8')))
    returning id into v_id;
  insert into public.srs_state (student_id) values (v_id);
  return jsonb_build_object('ok', true, 'id', v_id, 'name', v_name, 'token', v_token);
end
$$;

-- ---------- 老師：重設學生連結（舊連結立刻失效；雲端進度不受影響） ----------
create or replace function public.srs_reset_link(p_student uuid)
returns jsonb
language plpgsql volatile security definer
set search_path = ''
as $$
declare
  v_token text;
begin
  if not public.srs_is_teacher() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  v_token := replace(gen_random_uuid()::text, '-', '');
  update public.srs_students
     set token_hash = sha256(convert_to(v_token, 'UTF8')), link_reset_at = now()
   where id = p_student;
  if not found then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  return jsonb_build_object('ok', true, 'token', v_token);
end
$$;

-- ---------- 函式執行權限：先全部收回，再逐一開放 ----------
revoke all on function public.srs_is_teacher()                    from public, anon, authenticated;
revoke all on function public.srs_load(text, bigint)              from public, anon, authenticated;
revoke all on function public.srs_save(text, jsonb, bigint)       from public, anon, authenticated;
revoke all on function public.srs_create_student(text)            from public, anon, authenticated;
revoke all on function public.srs_reset_link(uuid)                from public, anon, authenticated;

grant execute on function public.srs_is_teacher()              to authenticated;
grant execute on function public.srs_load(text, bigint)        to anon, authenticated;
grant execute on function public.srs_save(text, jsonb, bigint) to anon, authenticated;
grant execute on function public.srs_create_student(text)      to authenticated;
grant execute on function public.srs_reset_link(uuid)          to authenticated;

-- ---------- 老師名單：目前專案裡有 email 的帳號（自助註冊已關 → 應該只有你） ----------
insert into public.srs_teachers (user_id)
select u.id from auth.users u where u.email is not null
on conflict (user_id) do nothing;

notify pgrst, 'reload schema';

commit;

-- 執行完請看下面這張表：只應該出現你自己的 email。多出來的帳號請刪掉：
--   delete from public.srs_teachers where user_id = (select id from auth.users where email = '多出來的email');
select u.email as "有老師權限的帳號" from public.srs_teachers t join auth.users u on u.id = t.user_id;
