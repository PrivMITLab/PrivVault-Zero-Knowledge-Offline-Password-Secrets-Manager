/**
 * PrivVault – sw.js
 * Service Worker for PWA / Offline Support
 * PrivMITLab
 */

'use strict';

const CACHE_NAME    = 'privvault-v1.0.0';
const OFFLINE_URL   = 'index.html';

// Files to cache for offline use
const CACHE_FILES = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/crypto.js',
  '/storage.js',
  '/ui.js',
  '/utils.js',
  '/manifest.json',
  '/assets/icon.svg'
];

// ── Install Event ─────────────────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.info('[SW] Caching app shell');
        return cache.addAll(CACHE_FILES.map(url => {
          return new Request(url, { cache: 'reload' });
        }));
      })
      .then(() => self.skipWaiting())
      .catch(err => {
        console.warn('[SW] Cache install failed:', err);
        return self.skipWaiting();
      })
  );
});

// ── Activate Event ────────────────────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME)
          .map(name => {
            console.info('[SW] Removing old cache:', name);
            return caches.delete(name);
          })
      );
    }).then(() => self.clients.claim())
  );
});

// ── Fetch Event ───────────────────────────────────────────────
self.addEventListener('fetch', (event) => {
  // Only handle GET requests for same-origin resources
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Skip non-same-origin requests
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then(cachedResponse => {
      if (cachedResponse) {
        return cachedResponse;
      }

      // Network fallback
      return fetch(event.request)
        .then(response => {
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }

          // Cache new responses
          const cloned = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, cloned);
          });

          return response;
        })
        .catch(() => {
          // Offline fallback
          if (event.request.mode === 'navigate') {
            return caches.match(OFFLINE_URL);
          }
          return new Response('Offline', { status: 503 });
        });
    })
  );
});