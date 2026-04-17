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

  // Reset scroll to top whenever the route changes. React Router preserves
  // the window scroll position by default, which means navigating from
  // "bottom of /geo" to /content leaves you at the bottom of the new page.
  // Use 'auto' (not 'smooth') so the jump is instant — a smooth scroll on
  // a long page would animate through unrelated content during navigation.
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [location.pathname]);

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

  // Keep old <div id="main"> margin in sync with sidebar collapse (desktop only)
  const marginLeft = collapsed ? 64 : 240;
  useEffect(() => {
    const oldMain = document.getElementById('main');
    if (oldMain) {
      const mq = window.matchMedia('(min-width: 768px)');
      const apply = () => { oldMain.style.marginLeft = mq.matches ? `${marginLeft}px` : '0'; };
      apply();
      mq.addEventListener('change', apply);
      return () => mq.removeEventListener('change', apply);
    }
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

  // When navigating to a React page, hide all vanilla page sections
  useEffect(() => {
    if (isReactPage) {
      document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    }
  }, [location.pathname, isReactPage]);

  return (
    <>
      <Sidebar
        collapsed={collapsed}
        onToggleCollapse={toggleCollapse}
        onToggleTheme={toggleTheme}
        badges={badges}
        mobileOpen={mobileOpen}
        onToggleMobile={toggleMobileSidebar}
        onCloseMobile={() => { setMobileOpen(false); document.body.classList.remove('overflow-hidden'); }}
      />

      {/* Header — always rendered by React */}
      <div className="transition-all duration-300 desktop-margin">
        <Header onToggleMobileSidebar={toggleMobileSidebar} />
      </div>

      {/* All pages are React now; isReactPage is always true in practice.
          The guard stays as a safety net in case a future route is added
          before its React component is wired. */}
      {isReactPage && (
        <div className="transition-all duration-300 min-h-screen pb-16 md:pb-0 desktop-margin">
          <main className="p-4 sm:p-6 max-w-[1600px] mx-auto">
            <Outlet />
          </main>
        </div>
      )}
      {!isReactPage && <Outlet />}

      {/* Inject responsive margin — 0 on mobile, sidebar width on desktop */}
      <style>{`
        .desktop-margin { margin-left: 0; }
        @media (min-width: 768px) {
          .desktop-margin { margin-left: ${marginLeft}px; }
        }
      `}</style>
    </>
  );
}
