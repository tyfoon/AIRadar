import { useState, useEffect, useCallback } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
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

  // Expose navigate for vanilla JS code (e.g. GroupsTab calling window.navigate('rules'))
  useEffect(() => {
    (window as any).navigate = (page: string) => {
      const path = page === 'other' || page === 'content' ? '/content' : `/${page}`;
      nav(path);
    };
  }, [nav]);

  // On first mount: hide the old vanilla sidebar/header/mobile-nav,
  // reset the old main wrapper margin so it doesn't conflict.
  useEffect(() => {
    // Hide old sidebar
    const oldSidebar = document.getElementById('sidebar');
    if (oldSidebar) oldSidebar.style.display = 'none';
    // Hide old mobile nav
    const oldMobileNav = document.getElementById('mobile-nav');
    if (oldMobileNav) oldMobileNav.style.display = 'none';
    // Hide old sidebar backdrop
    const oldBackdrop = document.getElementById('sidebar-backdrop');
    if (oldBackdrop) oldBackdrop.style.display = 'none';
    // Reset old main wrapper — remove margin-left and let React control layout
    const oldMain = document.getElementById('main');
    if (oldMain) {
      oldMain.style.marginLeft = '0';
      oldMain.style.paddingBottom = '0';
    }

    // Load devices for pages that depend on window.deviceMap
    window.loadDevices?.();
  }, []);

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

  // Close mobile on route change
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

  const marginLeft = collapsed ? 64 : 240;

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

      {/* Main content area */}
      <div
        className="transition-all duration-300 min-h-screen pb-16 md:pb-0"
        style={{ marginLeft }}
      >
        <Header onToggleMobileSidebar={toggleMobileSidebar} />

        {/* Killswitch banner — keep using the existing DOM element */}

        {/* Page content */}
        <main className="p-4 sm:p-6 max-w-[1600px] mx-auto">
          <Outlet />
        </main>
      </div>
    </>
  );
}
