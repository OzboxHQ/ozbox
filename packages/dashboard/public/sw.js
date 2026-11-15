// Oz Box dashboard service worker.
// It makes the app installable and quick to open. It NEVER touches /v1: API data (boxes, usage, plans) is always live,
// never stored. A new version waits until the person chooses Refresh; it never reloads the page on its own.
const CACHE = 'ozbox-shell-v1';

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/manifest.webmanifest', '/icon.svg'])));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))),
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

// Push: the server sends an encrypted payload {title, body, tag, urgent}; the browser decrypts it. A notification must be
// shown for every push, so a payload that cannot be read still shows a plain one. Nothing here caches or reads /v1.
self.addEventListener('push', (event) => {
  const read = () => {
    try {
      return (event.data && event.data.json()) || {};
    } catch {
      return {};
    }
  };
  const d = read();
  const text = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');
  const title = text(d.title, 120) || 'Oz Box';
  const options = { body: text(d.body, 400), icon: '/icon.svg', badge: '/icon.svg', data: { url: '/activity' } };
  if (typeof d.tag === 'string' && d.tag) options.tag = d.tag.slice(0, 100);
  if (d.urgent === true) options.requireInteraction = true;
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if ('focus' in c) return c.focus();
      return self.clients.openWindow('/');
    }),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname === '/v1' || url.pathname.startsWith('/v1/')) return; // live data: straight to the network
  if (url.pathname === '/sw.js') return;
  if (url.pathname.startsWith('/assets/')) {
    // Hashed build files never change under the same name.
    event.respondWith(
      caches.match(req).then(
        (hit) =>
          hit ||
          fetch(req).then((res) => {
            if (res.ok) {
              const copy = res.clone();
              caches.open(CACHE).then((c) => c.put(req, copy));
            }
            return res;
          }),
      ),
    );
  }
});
