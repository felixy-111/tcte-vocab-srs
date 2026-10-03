-- ============================================================
-- 統測單字（SRS App）— 權限驗證  002_verify.sql
--
-- 什麼時候跑：001_srs.sql 執行成功之後，在同一個 SQL Editor 貼上這整份 → Run。
--
-- 它會做什麼：假扮「學生（沒登入）」「老師」「登入但不是老師的人」三種身分，
--   實際去讀表、建一個測試學生、上傳進度、重設連結……逐項確認權限擋得住。
--
-- 會不會弄髒資料庫：不會。整份是「一個區塊」，最後一行「故意丟出錯誤」，
--   資料庫碰到錯誤會把這個區塊做過的所有事全部復原（測試學生、測試進度都不會留下）。
--
-- 怎麼看結果：
--   ✔ 成功：畫面出現紅色錯誤，但訊息開頭是「驗證全部通過」→ 這是正常的（見上一段）。
--   ✘ 失敗：訊息開頭是「FAIL」或其他任何錯誤 → 把整段訊息截圖給 Claude 看。
-- ============================================================

do $verify$
declare
  v_teacher uuid; v_tok text; v_tok2 text; v_sid uuid; v_r jsonb; v_n integer;
  v_log text[] := '{}';
  v_card jsonb := '{"st":3,"df":5,"reps":1,"lapses":0,"last":1,"due":2}';
  c_fake constant text := '0123456789abcdef0123456789abcdef';
begin
  select t.user_id into v_teacher from public.srs_teachers t limit 1;
  if v_teacher is null then raise exception 'FAIL 0：srs_teachers 是空的（沒有老師帳號）'; end if;

  -- ===== 1. 學生端（anon，沒登入）：不能直接碰任何表、不能用老師功能 =====
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  begin perform 1 from public.srs_state; raise exception 'FAIL 1a：anon 讀得到 srs_state';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1a 學生端不能直接讀 srs_state'::text; end;
  begin perform 1 from public.srs_students; raise exception 'FAIL 1b：anon 讀得到 srs_students';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1b 學生端不能直接讀 srs_students'::text; end;
  begin perform 1 from public.srs_teachers; raise exception 'FAIL 1c：anon 讀得到 srs_teachers';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1c 學生端不能讀老師名單'::text; end;
  begin perform 1 from public.srs_state_backup; raise exception 'FAIL 1d：anon 讀得到 srs_state_backup';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1d 學生端不能讀備份'::text; end;
  begin insert into public.srs_students (name, token_hash) values ('x', '\x00'); raise exception 'FAIL 1e：anon 能新增學生列';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1e 學生端不能直接寫表'::text; end;
  begin perform public.srs_create_student('x'); raise exception 'FAIL 1f：anon 能建學生';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1f 學生端不能呼叫「建學生」'::text; end;
  begin perform public.srs_is_teacher(); raise exception 'FAIL 1g：anon 能呼叫 srs_is_teacher';
  exception when insufficient_privilege then v_log := v_log || 'PASS 1g 學生端不能呼叫老師判定'::text; end;
  if public.srs_load(c_fake) ->> 'error' is distinct from 'invalid_link'
     or public.srs_load('<script>') ->> 'error' is distinct from 'invalid_link'
     or public.srs_load(null) ->> 'error' is distinct from 'invalid_link'
     or public.srs_save(c_fake, '{}'::jsonb, 0) ->> 'error' is distinct from 'invalid_link' then
    raise exception 'FAIL 1h：錯的代碼沒有被拒';
  end if;
  v_log := v_log || 'PASS 1h 錯的／亂打的代碼讀不到也寫不了'::text;
  reset role;

  -- ===== 2. 老師 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  if not public.srs_is_teacher() then raise exception 'FAIL 2a：老師帳號不被認成老師'; end if;
  v_r := public.srs_create_student('驗證用學生');
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'token') !~ '^[0-9a-f]{32}$' then raise exception 'FAIL 2b：建學生失敗 %', v_r; end if;
  v_tok := v_r ->> 'token'; v_sid := (v_r ->> 'id')::uuid;
  select count(*) into v_n from public.srs_students s where s.id = v_sid;
  if v_n <> 1 then raise exception 'FAIL 2c：老師讀不到學生'; end if;
  begin perform s.token_hash from public.srs_students s; raise exception 'FAIL 2d：老師讀得到 token_hash 欄';
  exception when insufficient_privilege then null; end;
  begin insert into public.srs_state (student_id) values (gen_random_uuid()); raise exception 'FAIL 2e：老師能直接寫 srs_state';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 2 老師：被認得、能建學生、讀得到名單、讀不到代碼指紋、不能直接改表'::text;
  reset role;

  -- ===== 3. 學生用自己的代碼 =====
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  v_r := public.srs_load(v_tok);
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'rev')::bigint <> 0 or (v_r ->> 'sid')::uuid <> v_sid then
    raise exception 'FAIL 3a：用正確代碼讀不到 %', v_r;
  end if;
  v_r := public.srs_save(v_tok, jsonb_build_object(
           'cards', jsonb_build_object('w', v_card),
           'days', jsonb_build_object('2026-10-07', '{"ans":1}'::jsonb),
           'log', '[{"t":1,"id":"w","g":3},{"t":1,"id":"w","g":3},{"t":2,"id":"w","g":1}]'::jsonb), 0);
  if (v_r ->> 'rev')::bigint is distinct from 1 then raise exception 'FAIL 3b：上傳失敗 %', v_r; end if;
  v_r := public.srs_save(v_tok, jsonb_build_object('cards', jsonb_build_object('w', v_card)), 0);
  if v_r ->> 'error' is distinct from 'conflict' or v_r -> 'state' -> 'cards' -> 'w' is null then
    raise exception 'FAIL 3c：舊版本號沒有回 conflict %', v_r;
  end if;
  v_r := public.srs_save(v_tok, jsonb_build_object('cards', jsonb_build_object('w2', v_card)), 1);
  if v_r ->> 'error' is distinct from 'too_fast' then raise exception 'FAIL 3d：節流沒作用 %', v_r; end if;
  if public.srs_save(v_tok, '{"evil":1}'::jsonb, 1) ->> 'error' is distinct from 'bad_patch'
     or public.srs_save(v_tok, '{"cards":{"w":5}}'::jsonb, 1) ->> 'error' is distinct from 'bad_patch'
     or public.srs_save(v_tok, '{"days":{"<img>":{}}}'::jsonb, 1) ->> 'error' is distinct from 'bad_patch'
     or public.srs_save(v_tok, '{"log":[{"t":"x","id":"w"}]}'::jsonb, 1) ->> 'error' is distinct from 'bad_patch'
     or public.srs_save(v_tok, '[1,2]'::jsonb, 1) ->> 'error' is distinct from 'bad_patch' then
    raise exception 'FAIL 3e：格式不對的上傳沒有被拒';
  end if;
  v_r := public.srs_save(v_tok, jsonb_build_object('cards', jsonb_build_object('w', jsonb_build_object('pad', repeat('x', 2100000)))), 1);
  if v_r ->> 'error' is distinct from 'too_large' then raise exception 'FAIL 3f：超大上傳沒有被拒 %', left(v_r::text, 200); end if;
  v_r := public.srs_load(v_tok);
  if (v_r ->> 'rev')::bigint <> 1 or jsonb_array_length(v_r -> 'state' -> 'log') <> 2 or v_r -> 'state' -> 'cards' -> 'w2' is not null then
    raise exception 'FAIL 3g：雲端內容不對 %', left(v_r::text, 300);
  end if;
  v_r := public.srs_load(v_tok, 1);
  if (v_r ->> 'unchanged')::boolean is not true or v_r ? 'state' then raise exception 'FAIL 3h：版本沒變時不該回整包'; end if;
  v_log := v_log || 'PASS 3 學生：讀寫自己的、舊版本被擋、2 秒節流、格式/大小檢查、作答紀錄去重'::text;
  reset role;

  -- ===== 4. 登入了但不是老師（例如萬一自助註冊被打開） =====
  perform set_config('request.jwt.claims', json_build_object('sub', gen_random_uuid(), 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into v_n from public.srs_state;
  if v_n <> 0 then raise exception 'FAIL 4a：非老師帳號讀得到進度'; end if;
  select count(*) into v_n from public.srs_students;
  if v_n <> 0 then raise exception 'FAIL 4b：非老師帳號讀得到學生名單'; end if;
  begin perform public.srs_create_student('x'); raise exception 'FAIL 4c：非老師帳號能建學生';
  exception when insufficient_privilege then null; end;
  begin perform public.srs_reset_link(v_sid); raise exception 'FAIL 4d：非老師帳號能重設連結';
  exception when insufficient_privilege then null; end;
  v_log := v_log || 'PASS 4 登入但不是老師：什麼都讀不到、不能建學生、不能重設連結'::text;
  reset role;

  -- ===== 5. 備份 =====
  select count(*) into v_n from public.srs_state_backup b where b.student_id = v_sid;
  if v_n <> 1 then raise exception 'FAIL 5：每日備份沒寫入（%）', v_n; end if;
  v_log := v_log || 'PASS 5 第一次上傳前有存備份'::text;

  -- ===== 6. 重設連結：舊的立刻失效、新的可用、進度還在 =====
  perform set_config('request.jwt.claims', json_build_object('sub', v_teacher, 'role', 'authenticated')::text, true);
  set local role authenticated;
  v_tok2 := public.srs_reset_link(v_sid) ->> 'token';
  reset role;
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  if public.srs_load(v_tok) ->> 'error' is distinct from 'invalid_link' then raise exception 'FAIL 6a：舊連結還能用'; end if;
  v_r := public.srs_load(v_tok2);
  if (v_r ->> 'ok')::boolean is not true or (v_r ->> 'rev')::bigint <> 1 then raise exception 'FAIL 6b：新連結讀不到原本進度 %', v_r; end if;
  v_log := v_log || 'PASS 6 重設連結：舊的失效、新的可用、進度還在'::text;
  reset role;

  raise exception using errcode = 'P0001', message =
    '驗證全部通過（' || array_length(v_log, 1) || ' 組）。這行紅字是刻意的：讓剛才的測試學生與測試資料全部自動復原。' || E'\n' ||
    array_to_string(v_log, E'\n');
end
$verify$;
