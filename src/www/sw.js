/* Dentrado IS service worker: the frontend "lives its own life" —
 * the shell is cached, the app opens offline; API paths and every
 * non-GET always hit the network. The cache version = the build stage:
 * bump vN when the statics change. */
const CACHE = "is-shell-v21";
const SHELL = ["/", "/app.js", "/style.css", "/icons.svg", "/logo.svg"];
const API = [
  /^\/webauthn\//,
  /^\/connect/,
  /^\/cred\//,
  /^\/authorize$/,
  /^\/account$/,
  /^\/logout$/,
  /^\/keys$/,
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return; // foreign origin — skip
  if (e.request.method !== "GET" || API.some((re) => re.test(url.pathname))) return; // network
  e.respondWith(
    caches.match(e.request).then(
      (hit) =>
        hit ||
        fetch(e.request).then((resp) => {
          if (resp.ok) {
            const copy = resp.clone();
            caches.open(CACHE).then((c) => c.put(e.request, copy));
          }
          return resp;
        }),
    ),
  );
});
