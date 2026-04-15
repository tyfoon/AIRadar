import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppShell from './shell/AppShell';
import VanillaPage from './shell/VanillaPage';
import Dashboard from './dashboard/Dashboard';
import GeoMap from './geo/GeoMap';
import IotOverview from './iot/IotOverview';
import DevicesPage from './devices/DevicesPage';
import AiPage from './category/AiPage';
import CloudPage from './category/CloudPage';
import PrivacyPage from './privacy/PrivacyPage';
import ContentPage from './content/ContentPage';
import SummaryPage from './summary/SummaryPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
});

// ---------------------------------------------------------------------------
// Mount the entire app into #react-app-root
// ---------------------------------------------------------------------------
function waitForElement(id: string, cb: (el: HTMLElement) => void) {
  const el = document.getElementById(id);
  if (el) { cb(el); return; }
  const obs = new MutationObserver(() => {
    const found = document.getElementById(id);
    if (found) { obs.disconnect(); cb(found); }
  });
  obs.observe(document.body, { childList: true, subtree: true });
}

waitForElement('react-app-root', (el) => {
  createRoot(el).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <HashRouter>
          <Routes>
            <Route element={<AppShell />}>
              {/* React pages */}
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/geo" element={<GeoMap />} />
              <Route path="/iot" element={<IotOverview />} />
              <Route path="/ai" element={<AiPage />} />
              <Route path="/cloud" element={<CloudPage />} />
              <Route path="/privacy" element={<PrivacyPage />} />

              <Route path="/content" element={<ContentPage />} />
              <Route path="/family" element={<ContentPage />} />
              <Route path="/other" element={<ContentPage />} />

              <Route path="/summary" element={<SummaryPage />} />

              {/* Vanilla JS pages — wrapper shows/hides existing <section> elements */}
              <Route path="/ips" element={<VanillaPage pageId="ips" />} />
              <Route path="/rules" element={<VanillaPage pageId="rules" />} />
              <Route path="/settings" element={<VanillaPage pageId="settings" />} />
              <Route path="/settings/:tab" element={<VanillaPage pageId="settings" />} />

              {/* Default redirect */}
              <Route path="/" element={<Navigate to="/summary" replace />} />
              <Route path="*" element={<Navigate to="/summary" replace />} />
            </Route>
          </Routes>
        </HashRouter>
      </QueryClientProvider>
    </StrictMode>,
  );

  // Disable the vanilla JS router — React Router now owns navigation
  (window as any)._reactRouterActive = true;
});
