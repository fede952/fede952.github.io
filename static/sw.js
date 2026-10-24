// Kill switch for the service worker this site used to register.
// The old worker served /js, /vendor and CSS cache-first from unversioned
// URLs, so returning visitors kept running stale scripts. Browsers re-check
// this file on navigation; this version wipes every cache, unregisters
// itself and reloads open tabs once so they fetch fresh assets.
// Nothing registers a service worker any more; keep this file deployed
// for a few months, then it can be deleted.
self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) { return Promise.all(keys.map(function (k) { return caches.delete(k); })); })
      .then(function () { return self.registration.unregister(); })
      .then(function () { return self.clients.matchAll({ type: 'window' }); })
      .then(function (clients) { clients.forEach(function (c) { c.navigate(c.url); }); })
  );
});
