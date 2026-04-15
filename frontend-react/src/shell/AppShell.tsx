import { useState, useEffect, useCallback } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { ROUTES } from './routes';
import Sidebar from './Sidebar';
import Header from './Header';

declare global {
  interface Window {
    updateChartsTheme?: () => void;
    loadDevices?: () => Promise<void>;
    _reactRouterActive?: boolean;
  }
}

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('airadar-sidebar') === 'collapsed');
  const [badges, setBadges] = useState<Record<string, number | boolean>>({});
  const location = useLocation();
  const nav = useNavigate();

  // Expose navigate for vanilla JS code
  useEffect(() => {
    (window as any).navigate = (page: string) => {
      const path = page === 'other' || page === 'content' ? '/content'
        : page === 'family' ? '/content'
        : `/${page}`;
      nav(path);
    };
  }, [nav]);

  // On first mount: hide old sidebar/header/mobile-nav
  useEffect(() => {
    const hide = (id: string) => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    };
    hide('sidebar');
    hide('mobile-nav');
    hide('sidebar-backdrop');
    // Hide old header inside the old main wrapper
    const oldMain = document.getElementById('main');
    if (oldMain) {
      const oldHeader = oldMain.querySelector('header');
      if (oldHeader) (oldHeader as HTMLElement).style.display = 'none';
    }
    // Load devices for pages that depend on window.deviceMap
    window.loadDevices?.();
  }, []);

  // Keep old <div id="main"> margin in sync with sidebar collapse
  const marginLeft = collapsed ? 64 : 240;
  useEffect(() => {
    const oldMain = document.getElementById('main');
    if (oldMain) oldMain.style.marginLeft = `${marginLeft}px`;
  }, [marginLeft]);

  // Determine if current route is a React page or vanilla
  const currentPath = location.pathname.replace(/^\//, '') || 'summary';
  const route = ROUTES.find(r => r.path === currentPath || r.pageId === currentPath);
  const isReactPage = route?.type === 'react';

  // Persist sidebar collapse state
  const toggleCollapse = useCallback(() => {
    setCollapsed(prev => {
      const next = !prev;
      localStorage.setItem('airadar-sidebar', next ? 'collapsed' : 'expanded');
      setTimeout(() => { window.updateChartsTheme?.(); }, 300);
      return next;
    });
  }, []);

  // Theme toggle
  const toggleTheme = useCallback(() => {
    document.documentElement.classList.toggle('dark');
    const isDark = document.documentElement.classList.contains('dark');
    localStorage.setItem('airadar-theme', isDark ? 'dark' : 'light');
    window.updateChartsTheme?.();
  }, []);

  // Mobile sidebar
  const [mobileOpen, setMobileOpen] = useState(false);
  const toggleMobileSidebar = useCallback(() => {
    setMobileOpen(prev => {
      document.body.classList.toggle('overflow-hidden', !prev);
      return !prev;
    });
  }, []);

  useEffect(() => {
    setMobileOpen(false);
    document.body.classList.remove('overflow-hidden');
  }, [location.pathname]);

  // Poll for badge updates
  useEffect(() => {
    const update = () => {
      const w = window as Record<string, unknown>;
      const ipsCount = (w._navIpsCount as number) || 0;
      const killswitch = (w._killswitchActive as boolean) || false;
      setBadges(prev => {
        if (prev.ips === ipsCount && prev.settings === killswitch) return prev;
        return { ips: ipsCount, settings: killswitch };
      });
    };
    update();
    const interval = setInterval(update, 5000);
    return () => clearInterval(interval);
  }, []);

  // Hide all vanilla page sections on route change
  useEffect(() => {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  }, [location.pathname]);

  return (
    <>
      <Sidebar
        collapsed={collapsed}
        onToggleCollapse={toggleCollapse}
        onToggleTheme={toggleTheme}
        badges={badges}
      />

      {mobileOpen && (
        <div className="fixed inset-0 bg-black/50 z-30 md:hidden" onClick={toggleMobileSidebar} />
      )}

      {/* Header — always rendered by React */}
      <div style={{ marginLeft }} className="transition-all duration-300">
        <Header onToggleMobileSidebar={toggleMobileSidebar} />
      </div>

      {/* React pages render in their own container with correct margin */}
      {isReactPage && (
        <div
          className="transition-all duration-300 min-h-screen pb-16 md:pb-0"
          style={{ marginLeft }}
        >
          <main className="p-4 sm:p-6 max-w-[1600px] mx-auto">
            <Outlet />
          </main>
        </div>
      )}

      {/* Vanilla pages: Outlet renders VanillaPage (returns null) which
          shows/hides the <section> in the old <div id="main"> */}
      {!isReactPage && <Outlet />}
    </>
  );
}
