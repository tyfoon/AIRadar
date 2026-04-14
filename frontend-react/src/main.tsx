import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import type { Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ScreenTime from './ScreenTime';
import GeoMap from './geo/GeoMap';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
});

// ---------------------------------------------------------------------------
// Generic island helper: observe a data attribute and (re-)render on change
// ---------------------------------------------------------------------------

function mountIsland(
  elementId: string,
  attrName: string,
  renderFn: (el: HTMLElement, value: string) => void,
) {
  function tryMount() {
    const el = document.getElementById(elementId);
    if (!el) {
      // Wait for element to appear in DOM
      const obs = new MutationObserver(() => {
        if (document.getElementById(elementId)) {
          obs.disconnect();
          tryMount();
        }
      });
      obs.observe(document.body, { childList: true, subtree: true });
      return;
    }

    // Initial render if attribute is already set
    const val = el.getAttribute(attrName);
    if (val) renderFn(el, val);

    // Observe attribute changes
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type === 'attributes' && m.attributeName === attrName) {
          const newVal = el.getAttribute(attrName) || '';
          if (newVal) renderFn(el, newVal);
        }
      }
    });
    observer.observe(el, { attributes: true, attributeFilter: [attrName] });
  }

  tryMount();
}

function renderInto(el: HTMLElement, component: React.ReactNode) {
  // Reuse or create root
  let root = (el as any).__reactRoot as Root | undefined;
  if (!root) {
    root = createRoot(el);
    (el as any).__reactRoot = root;
  }
  root.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        {component}
      </QueryClientProvider>
    </StrictMode>,
  );
}

// ---------------------------------------------------------------------------
// Island: ScreenTime (device drawer Sessions tab)
// ---------------------------------------------------------------------------
mountIsland('react-screentime-root', 'data-mac', (el, mac) => {
  renderInto(el, <ScreenTime macAddress={mac} />);
});

// ---------------------------------------------------------------------------
// Island: GeoMap (geo page)
// ---------------------------------------------------------------------------
mountIsland('react-geo-root', 'data-active', (el, _active) => {
  renderInto(el, <GeoMap />);
});
