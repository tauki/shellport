// Shellport deliberately keeps shells, credentials and API responses out of caches.
// Registering this worker provides the home-screen lifecycle without offline shell claims.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
