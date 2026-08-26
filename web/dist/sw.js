const CACHE = 'zentcontainer-static';
const ASSETS = ['/app.css','/app.js','/logo.png','/favicon.ico','/favicon-32.png','/favicon-64.png','/apple-touch-icon.png','/icon-192.png','/icon-512.png','/manifest.webmanifest'];
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE && key.startsWith('zentcontainer-static')).map((key) => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/') || req.mode === 'navigate') return;
  if (!ASSETS.includes(url.pathname)) return;
  event.respondWith(caches.match(req).then((cached) => {
    const fresh = fetch(req).then((res) => { if (res.ok) caches.open(CACHE).then((cache) => cache.put(req, res.clone())); return res; }).catch(() => cached);
    return cached || fresh;
  }));
});
