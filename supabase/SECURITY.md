# 統測單字（SRS）雲端同步：安全自審

範圍：`srs/index.html`（學生端同步、老師端儀表板）＋`supabase/001_srs.sql`（表、RLS、RPC）。
Supabase 專案沿用「統測字彙練習 app」那一個（`knsdpvmhloobfduhfwyk`）。

## 一句話
學生沒有帳號：老師給的連結裡有一串 122 bits 的隨機代碼，雲端只存它的 SHA-256 指紋。
學生端（anon）**碰不到任何一張表**，只能呼叫 `srs_load` / `srs_save` 兩個函式，函式用代碼找到「自己那一列」才動作。
老師用既有的 Supabase 帳號登入，而且必須在 `srs_teachers` 名單上才讀得到東西。

## 角色與權限

| 身分 | 能做 | 不能做 |
|---|---|---|
| anon（學生端、或任何拿到網頁裡 anon key 的人） | `srs_load(代碼)`、`srs_save(代碼, 變更, 版本號)`：只對「代碼對得上的那位學生」有效 | 讀寫任何表（四張表都 `revoke all`，也沒有 anon policy）；建學生、重設連結、`srs_is_teacher` 都沒有 EXECUTE 權限 |
| authenticated 且在 `srs_teachers` | 讀 `srs_students`（只有 id/name/created_at/link_reset_at 欄，**不含** token_hash）、讀 `srs_state`；`srs_create_student`、`srs_reset_link` | 直接寫任何表；讀 `srs_teachers`、`srs_state_backup` |
| authenticated 但不在名單（例：自助註冊萬一被打開、匿名登入） | 什麼都讀不到（RLS 回 0 列）；呼叫老師 RPC 會被 `42501` 擋 | — |
| service_role / SQL Editor | 全部（Supabase 管理者） | — |

所有函式都是 `security definer` ＋ `set search_path = ''`，表名全部寫成 `public.xxx`，避免被同名物件劫持。

## 威脅模型

### T1 學生連結外流（例：學生把連結貼到群組）
- 後果：拿到連結的人可以讀、改**這一位**學生的進度（看得到作答紀錄、可以亂寫）。讀不到其他學生、讀不到老師資料。
- 降低方法：
  - 老師端「重新產生連結」→ 舊代碼立刻失效（指紋換掉），雲端進度不受影響；學生用新連結開一次就接回。
  - 被亂寫也救得回：`srs_save` 每天第一次寫入前，把舊的整包存進 `srs_state_backup`（保留 14 天，只能從 SQL Editor 讀）。救援 SQL 見文末。
  - 上傳只能「新增／取代某張卡、某一天、追加紀錄」，不能刪掉卡片或日期；格式不對整筆拒收。
  - App 開啟時會把 `?s=代碼` 從網址列拿掉（`history.replaceState`），降低截圖、分享網址時外流。
- 剩餘風險：連結本身就是密碼，沒有第二道驗證（設計上就是免登入）。學生名字請用暱稱。

### T2 anon key 公開（GitHub Pages 原始碼看得到）
- anon key 本來就設計成公開的；它只代表「anon 身分」。上表 anon 能做的事，全部都要先有正確代碼。
- 不使用 service_role key（程式碼裡沒有、本次工作也沒用到）。

### T3 猜代碼
- 代碼＝`gen_random_uuid()` 去掉橫線（資料庫的強亂數，122 bits）。就算每秒猜一百萬次，猜中一位學生的期望時間遠超過宇宙年齡。
- 代碼格式先用 `^[0-9a-f]{32}$` 檢查，格式不對直接回 `invalid_link`，不做查詢。
- 只存 SHA-256 指紋：就算資料庫內容外洩，也反推不出可用的連結。對高熵隨機代碼，快速雜湊就足夠（不需要 bcrypt 那類慢雜湊）。

### T4 惡意或超大 jsonb
- `srs_save` 檢查：最外層只能有 `cards/intro/days/log`；cards 每個值必須是物件、key ≤ 100 字；days 的 key 必須是 `YYYY-MM-DD`；intro 的值必須是數字；log 每筆要有數字 `t`、字串 `id`。
- 大小：單次上傳 ≤ 2,000,000 bytes、整包進度 ≤ 4,000,000 bytes（超過回 `too_large`，不寫入）。
  實測估計：30 天約 200 KB、200 天約 530 KB，離上限很遠。
- 作答紀錄（log）在伺服器端依 (時間, 字) 去重、只留最新 5000 筆，不會無限長大。
- 學生端收到雲端資料時再清洗一次（`cleanState`）：形狀不對的卡／日期／紀錄直接丟掉，`__proto__` 之類的 key 不收。

### T5 洗版、頻率
- 同一位學生 2 秒內只收一次寫入（`too_fast`），App 本身是「作答後 5 秒、最晚 30 秒」才送一次，而且只送改過的部分（實測一題約 2～4 KB）。
- 沒有代碼的人只能打 `srs_load/srs_save` 拿到 `invalid_link`：成本是一次雜湊＋一次唯一索引查詢。
- 剩餘風險：Postgres 層沒有「每個 IP 幾次」的限流；大量亂打請求只能靠 Supabase 平台本身的防護。對一位學生的家教 App 可接受。

### T6 學生端資料顯示在老師畫面（stored XSS）
- 進度是學生端寫的（較不可信），而老師畫面有老師的登入憑證。所以：
  - 老師畫面所有字串都經 `esc()`；字卡只顯示題庫（`cards.json`）裡有的 id；日期 key 先過格式檢查。selftest 有一項專測「怪字串不會變成 HTML」。
  - 加了 CSP（`<meta http-equiv="Content-Security-Policy">`）：`connect-src` 只准本站＋這個 Supabase 專案，萬一被注入程式也送不出老師的登入資訊到別的網站。（因為是單檔 App，`script-src` 仍需 `'unsafe-inline'`，所以 CSP 是第二道防線，第一道仍是 `esc()`。）
  - 換 Supabase 專案時，CSP 那行也要一起改（index.html 的註解有寫）。

### T7 資料遺失：空裝置覆蓋、兩台互蓋
- **沒成功下載過雲端進度之前，絕不上傳**（`M.pulled` 閘門）。新手機打開連結 → 先拿雲端 → 合併 → 才會上傳「多出來的部分」（通常是空的）。
- 伺服器端用版本號（`rev`）做「先比對再寫入」：上傳時附上次看到的版本；被別台搶先 → 回 `conflict`＋雲端整包 → App 合併後重送（最多 3 次）。兩台同時送，資料庫的 `for update` 鎖保證只有一台成功。
- 伺服器的合併是「整張卡／整天直接取代」，所以「不倒退」由 App 保證：每次開網頁第一次同步一定整包下載（不信任本機存檔跟同步紀錄是同一版），合併後記住「雲端那包」（只放記憶體）；每次上傳前跟它照合併規則比，只送「最後作答較新」的卡、「進度較多（過關＞作答次數＞分鐘）」的那天。本機存檔倒退（存檔失敗、從備份還原）或作答中保留了進度較少的那天，都不會蓋掉雲端較新的資料。
- 合併規則：每張卡留最後作答時間較新的；同一天留進度較多的（過關 > 作答次數 > 分鐘）；作答紀錄聯集；作答中的那天一律留這台（作答中的隊伍不能被換掉）。
- 這台已經有練習紀錄、第一次接上雲端 → 先問「合併」還是「以雲端為準」。換成另一位學生的連結 → 先問，取消就維持原本的學生（避免把 A 的進度灌進 B）。
- `?today=` 測試日期模式在雲端模式下**另存一份、不同步**，假日期的紀錄不會混進學生真的進度。

### T8 老師帳號
- 前提：專案的 Email 自助註冊是關的（沿用既有 app 的設定）。
- 額外一道：本 App 不是「任何登入的人都是老師」，而是 `srs_teachers` 名單。001 執行時會把「目前所有有 email 的帳號」放進名單，並在最後列出來給你確認。
  ⚠️ 如果名單裡出現不是你的 email，請照 001 檔尾的指令刪掉。
- 老師登入狀態存在瀏覽器 localStorage（key `tsvt-srs-teacher`），和學生進度分開。共用裝置用完請按「登出」。

## 驗證了什麼、怎麼驗的

| 項目 | 方法 | 結果 |
|---|---|---|
| 合併規則（卡、天、紀錄、清洗） | `?selftest=1` 純函式測試 | 通過 |
| 兩台分岔再收斂、空裝置不覆蓋、沒下載過不上傳、換學生、錯代碼、太大被拒、作答中不換隊伍 | `?selftest=1` 用假伺服器（照 001 的 `srs_load/srs_save` 規則用 JS 重寫）模擬多台裝置 | 通過（全部 65 項，含「本機存檔倒退」「作答中那天進度較少」兩個不倒退情境） |
| 測試本身有沒有用 | 故意改壞 `newerCard` / `moreDay` / `cleanState`，確認對應測試會變 FAIL | 會 FAIL（3 / 2 / 1 項） |
| 真的 supabase-js 呼叫路徑（RPC 參數名、錯誤碼→離線、老師登入、建學生、儀表板、重設連結後舊連結失效、貼新連結接回） | Playwright 390×844 對本機假 Supabase（Python，只聽 127.0.0.1） | 通過 |
| CONFIG 留空時行為不變 | Playwright：首頁→任務→作答→重整進度還在→總複習→閱讀；console 0 錯誤；SDK 不載入 | 通過 |
| **SQL 本身（語法、RLS、grant）** | **沒有在任何 Postgres 上跑過**：這台電腦沒有 postgres/psql/docker/supabase CLI，也不該碰正式專案 | **未驗證** → 請在 001 之後跑 `002_verify.sql`（見下） |

## 上線後必做：`002_verify.sql`
001 跑完後，在 SQL Editor 貼上 `002_verify.sql` 執行。它會在資料庫裡假扮學生／老師／非老師三種身分實際測權限，
最後**故意丟出錯誤讓所有測試資料自動復原**。看到「驗證全部通過」開頭的紅字＝成功；看到「FAIL」或其他錯誤＝把訊息截圖回報。

## 救援：把某位學生的進度退回某天的備份（SQL Editor）
```sql
-- 1. 看有哪些備份
select s.name, b.day, b.rev, pg_size_pretty(octet_length(b.state::text)::bigint)
from public.srs_state_backup b join public.srs_students s on s.id = b.student_id order by b.day desc;
-- 2. 退回（把 '暱稱' 和日期換掉）；rev 要 +1，讓所有裝置下次同步時重新下載
update public.srs_state st set state = b.state, rev = st.rev + 1, updated_at = now()
from public.srs_state_backup b join public.srs_students s on s.id = b.student_id
where st.student_id = b.student_id and s.name = '暱稱' and b.day = date '2026-10-10';
```
注意：退回後，學生手機上「比備份新」的紀錄在下次同步時會依合併規則再併回去（每張卡留較新的）。
如果是被亂寫成「時間在未來」的垃圾資料，要先重設連結、再請學生在手機上清除網站資料後重新開連結。

## 需要人工確認的假設
1. 專案的 Email 自助註冊仍是關閉的；匿名登入（Anonymous sign-ins）沒有打開。就算打開，`srs_teachers` 名單也會擋住，但既有的統測字彙 app 會受影響。
2. 執行 001 時，`auth.users` 裡有 email 的帳號都是老師本人（檔尾會列出）。
3. Supabase 專案是 Postgres 13 以上（`gen_random_uuid()`、`sha256()` 是內建函式，不依賴擴充套件）。
4. `gen_random_uuid()` 使用 Postgres 的強亂數來源（`pg_strong_random`）。
