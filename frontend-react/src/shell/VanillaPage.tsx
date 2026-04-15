import { useEffect } from 'react';
import { useParams } from 'react-router-dom';

declare global {
  interface Window {
    loadSummaryDashboard?: () => Promise<void>;
    refreshAI?: () => Promise<void>;
    refreshCloud?: () => Promise<void>;
    refreshPrivacy?: () => Promise<void>;
    refreshFamily?: () => Promise<void>;
    refreshIps?: () => Promise<void>;
    refreshRules?: () => Promise<void>;
    loadDevices?: () => Promise<void>;
    loadKillswitchState?: () => Promise<void>;
    _initThemeSelect?: () => void;
    loadSystemPerformance?: () => void;
    switchSettingsTab?: (tab: string) => void;
  }
}

interface Props {
  pageId: string;
}

/**
 * Bridges a vanilla JS page into the React Router.
 * Shows the existing <section id="page-{pageId}"> element and calls
 * the vanilla refresh function. Hides it on unmount.
 */
export default function VanillaPage({ pageId }: Props) {
  const params = useParams<{ tab?: string }>();

  useEffect(() => {
    // Hide all pages first, then show this one
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    const el = document.getElementById(`page-${pageId}`);
    if (el) el.classList.add('active');

    // Call the vanilla refresh function
    callVanillaRefresh(pageId);

    // Settings sub-tab handling
    if (pageId === 'settings' && params.tab) {
      window.switchSettingsTab?.(params.tab);
    }

    return () => {
      if (el) el.classList.remove('active');
    };
  }, [pageId, params.tab]);

  // The vanilla page renders into its own <section> in index.html,
  // so we don't render anything here — just an empty placeholder that
  // controls visibility.
  return null;
}

function callVanillaRefresh(pageId: string) {
  try {
    switch (pageId) {
      case 'summary': window.loadSummaryDashboard?.(); break;
      case 'ai': window.refreshAI?.(); break;
      case 'cloud': window.refreshCloud?.(); break;
      case 'privacy': window.refreshPrivacy?.(); break;
      case 'family': window.refreshFamily?.(); break;
      case 'ips': window.refreshIps?.(); break;
      case 'rules': window.refreshRules?.(); break;
      case 'settings':
        window.loadKillswitchState?.();
        window._initThemeSelect?.();
        window.loadSystemPerformance?.();
        break;
    }
  } catch (err) {
    console.error(`VanillaPage refresh error for ${pageId}:`, err);
  }
}
