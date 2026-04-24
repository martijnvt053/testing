const CACHE = 'seminar-v4';
const CONFIG = 'seminar-config';

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll([
      '/testing/seminar.html',
      '/testing/manifest.json',
      '/testing/icon.svg',
    ]))
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE && k !== CONFIG).map(k => caches.delete(k)))
    ).then(() => clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});

// ─── Push notification ────────────────────────────────────────────────────
self.addEventListener('push', e => {
  const message = e.data?.text() || 'Nieuw bericht van de trainer';
  e.waitUntil(
    self.registration.showNotification('📓 Seminar', {
      body: message,
      icon: '/testing/icon.svg',
      badge: '/testing/icon.svg',
      vibrate: [200, 100, 200],
      tag: 'seminar-msg',
      renotify: true,
      data: { url: '/testing/seminar.html' },
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window' }).then(list => {
      for (const c of list) if (c.url.includes('seminar') && 'focus' in c) return c.focus();
      return clients.openWindow(e.notification.data?.url || '/testing/seminar.html');
    })
  );
});

// ─── Store worker URL from main page ─────────────────────────────────────
self.addEventListener('message', async e => {
  if (e.data?.type === 'SET_WORKER_URL') {
    const cfg = await caches.open(CONFIG);
    await cfg.put('/worker-url', new Response(e.data.url));
  }
});
