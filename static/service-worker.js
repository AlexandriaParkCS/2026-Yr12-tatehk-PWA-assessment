const CACHE_NAME = "coffee-loyalty-v3";
const ASSETS = [
  "/",
  "/manifest.json"
];

// Cache only safe public assets
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

// Network-first so auth pages don’t get served stale from cache
self.addEventListener("fetch", (event) => {
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
