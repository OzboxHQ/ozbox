/** Register the service worker. A waiting update is announced (never applied by itself); `apply` activates it. */
export function registerServiceWorker(onUpdate: (apply: () => void) => void): void {
  if (!('serviceWorker' in navigator)) return;
  let reloading = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloading) return;
    reloading = true;
    window.location.reload();
  });
  navigator.serviceWorker
    .register('/sw.js')
    .then((reg) => {
      const announce = (w: ServiceWorker) => onUpdate(() => w.postMessage({ type: 'SKIP_WAITING' }));
      if (reg.waiting && navigator.serviceWorker.controller) announce(reg.waiting);
      reg.addEventListener('updatefound', () => {
        const w = reg.installing;
        w?.addEventListener('statechange', () => {
          if (w.state === 'installed' && navigator.serviceWorker.controller) announce(w);
        });
      });
    })
    .catch(() => {
      // The app works without it.
    });
}
