import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import type { Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ScreenTime from './ScreenTime';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
});

// Island injector: observe the data-mac attribute on the mount point.
// When app.js sets data-mac="AA:BB:CC", React re-renders with the new MAC.

const MOUNT_ID = 'react-screentime-root';
let root: Root | null = null;
let currentMac = '';

function render(mac: string) {
  const el = document.getElementById(MOUNT_ID);
  if (!el) return;

  if (!root) {
    root = createRoot(el);
  }

  currentMac = mac;
  root.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ScreenTime macAddress={mac} />
      </QueryClientProvider>
    </StrictMode>,
  );
}

// Watch for data-mac changes via MutationObserver
function init() {
  const el = document.getElementById(MOUNT_ID);
  if (!el) {
    // Element not in DOM yet — wait for it
    const bodyObserver = new MutationObserver(() => {
      if (document.getElementById(MOUNT_ID)) {
        bodyObserver.disconnect();
        init();
      }
    });
    bodyObserver.observe(document.body, { childList: true, subtree: true });
    return;
  }

  // Initial render if data-mac is already set
  const mac = el.getAttribute('data-mac');
  if (mac) render(mac);

  // Observe attribute changes
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type === 'attributes' && m.attributeName === 'data-mac') {
        const newMac = el.getAttribute('data-mac') || '';
        if (newMac && newMac !== currentMac) {
          render(newMac);
        }
      }
    }
  });

  observer.observe(el, { attributes: true, attributeFilter: ['data-mac'] });
}

// Start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
