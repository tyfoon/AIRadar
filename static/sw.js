// AI-Radar service worker.
//
// Bump CACHE_NAME on every deploy that ships new shell assets — the
// activate handler below deletes any cache whose key doesn't match,
// so a name bump is enough to flush stale app.js / style.css / i18n.js
// out of the user's browser.
//
// Strategy: NETWORK-FIRST for shell assets so a fresh deploy is picked
// up on the next reload without users having to manually clear the SW.
// We still cache the response so the dashboard keeps loading when the
// network is down. The old "cache-first" strategy meant new deploys
// were invisible until the cache key changed, which caused users to
// run on stale frontends for days.
const CACHE_NAME = 'airadar-shell-v37';
const SHELL_URLS = ['/', '/static/style.css', '/static/app.js', '/static/i18n.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(SHELL_URLS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/')) {
    // Network-first for API calls, fall back to stale cache if offline
    e.respondWith(
      fetch(e.request)
        .then(r => {
          const clone = r.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          return r;
        })
        .catch(() => caches.match(e.request))
    );
  } else {
    // Network-first for shell assets so deploys are picked up immediately.
    // Falls back to the cached copy when offline so the dashboard still
    // boots. Successful responses overwrite the cache entry.
    e.respondWith(
      fetch(e.request)
        .then(r => {
          if (r && r.ok) {
            const clone = r.clone();
            caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
          }
          return r;
        })
        .catch(() => caches.match(e.request))
    );
  }
});
