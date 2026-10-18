// Samar Cloud Service Worker (v1.0.0)
const CACHE_NAME = 'samar-cloud-v1';
const STATIC_ASSETS = [
    '/',
    '/static/index.html',
    '/static/icon.svg',
    '/static/manifest.json'
];

self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
        .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (e) => {
    const url = new URL(e.request.url);
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/oauth/')) {
        return; // Always live network for cloud files & APIs
    }

    if (e.request.mode === 'navigate') {
        e.respondWith(
            fetch(e.request).catch(() => caches.match('/') || caches.match('/static/index.html'))
        );
        return;
    }

    e.respondWith(
        caches.match(e.request).then((res) => res || fetch(e.request))
    );
});
