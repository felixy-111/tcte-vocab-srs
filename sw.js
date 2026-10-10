// 快取優先：先用快取，沒有才上網抓並存起來（離線可用）。
// ⚠️ 改了 index.html、data/、audio/、img/ 任何東西都要把 CACHE 版本號 +1，否則手機會一直用舊版。
const CACHE = "tsvt-srs-v10";
const CORE = ["./", "./index.html", "./manifest.json", "./data/cards.json", "./icon-192.png", "./icon-512.png", "./vendor/supabase.js"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(CORE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== location.origin) return;
  // 音檔的 Range 請求（iOS Safari）直接走網路：快取只存完整 200 回應，拿 200 回 Range 會讓播放器出錯
  if (req.headers.has("range")) return;
  e.respondWith(
    caches.match(req, { ignoreSearch: true }).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok && res.status === 200) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }))
  );
});
