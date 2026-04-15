import { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ROUTES, MOBILE_NAV, GROUP_LABELS } from './routes';
import { t } from '../utils/i18n';

interface Props {
  collapsed: boolean;
  onToggleCollapse: () => void;
  onToggleTheme: () => void;
  badges: Record<string, number | boolean>;
}

export default function Sidebar({ collapsed, onToggleCollapse, onToggleTheme, badges }: Props) {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  const currentPath = location.pathname.replace(/^\//, '') || 'summary';

  const closeMobile = () => {
    setMobileOpen(false);
    document.body.classList.remove('overflow-hidden');
  };

  const handleNav = (path: string) => {
    navigate(`/${path}`);
    closeMobile();
  };

  const toggleMobile = () => {
    const next = !mobileOpen;
    setMobileOpen(next);
    document.body.classList.toggle('overflow-hidden', next);
  };

  // Close mobile sidebar on route change
  useEffect(() => { closeMobile(); }, [location.pathname]);

  const groups: ('monitor' | 'protect' | 'manage')[] = ['monitor', 'protect', 'manage'];

  const navCls = (path: string, pageId: string) => {
    const active = currentPath === path || currentPath === pageId;
    // Compact rows: py-1.5 instead of py-2. With 12 nav items that's 12px
    // saved vertically, enough to fit everything on a 720p laptop without
    // scrolling.
    const base = 'nav-item relative group flex items-center gap-3 px-3 py-1.5 rounded-lg text-[13px] font-medium transition-colors cursor-pointer';
    if (active) return `${base} bg-indigo-50 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400`;
    return `${base} text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-white/[0.04]`;
  };

  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={`fixed left-0 top-0 h-full bg-white dark:bg-[#0f1117] border-r border-slate-200 dark:border-white/[0.04] z-40 flex flex-col transition-all duration-300 ${collapsed ? 'w-16' : 'w-60'} ${mobileOpen ? 'mobile-open' : ''}`}
        style={{ width: collapsed ? 64 : 240 }}
      >
        {/* Logo — h-14 (was h-16) to reclaim 8px for the nav list */}
        <div className="flex items-center gap-3 px-5 h-14 border-b border-slate-200 dark:border-white/[0.04] flex-shrink-0">
          <div className="h-8 w-8 rounded-lg bg-indigo-600 flex items-center justify-center text-white font-bold text-xs flex-shrink-0">AR</div>
          {!collapsed && <span className="logo-text font-semibold text-sm tracking-tight text-slate-800 dark:text-white">AI-Radar</span>}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-1 px-3 overflow-y-auto">
          {groups.map((group, gi) => (
            <div key={group}>
              {gi > 0 && <div className="my-1 border-t border-slate-200 dark:border-slate-700/50" />}
              {!collapsed && (
                <p className="nav-group-label text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-500 px-3 mt-1.5 mb-0.5">
                  {t(GROUP_LABELS[group].key) || GROUP_LABELS[group].label}
                </p>
              )}
              {ROUTES.filter(r => r.group === group).map(route => (
                <a
                  key={route.path}
                  className={navCls(route.path, route.pageId)}
                  onClick={() => handleNav(route.path)}
                  title={collapsed ? (t(route.labelKey) || route.label) : undefined}
                >
                  <i className={`ph-duotone ${route.icon} text-base flex-shrink-0`} />
                  {!collapsed && <span className="nav-label">{t(route.labelKey) || route.label}</span>}
                  {collapsed && (
                    <span className="nav-tooltip">{t(route.labelKey) || route.label}</span>
                  )}
                  {/* Badge */}
                  {route.badgeId && <NavBadge id={route.badgeId} badges={badges} collapsed={collapsed} />}
                </a>
              ))}
            </div>
          ))}
        </nav>

        {/* Bottom utility row — tighter padding + smaller buttons */}
        <div className="flex items-center justify-center gap-2 py-1.5 border-t border-slate-200 dark:border-slate-700/50 flex-shrink-0">
          <button onClick={onToggleTheme} title="Toggle Theme" className="sidebar-util-btn w-9 h-9 rounded-lg flex items-center justify-center text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
            <i className="ph-duotone ph-sun text-base hidden dark:inline-block" />
            <i className="ph-duotone ph-moon text-base block dark:hidden" />
          </button>
          <button onClick={onToggleCollapse} title="Collapse" className="sidebar-util-btn w-9 h-9 rounded-lg flex items-center justify-center text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
            <i className={`ph-duotone ph-caret-double-left text-base transition-transform ${collapsed ? 'rotate-180' : ''}`} />
          </button>
        </div>
      </aside>

      {/* Mobile backdrop */}
      {mobileOpen && (
        <div className="fixed inset-0 bg-black/50 z-30" onClick={closeMobile} />
      )}

      {/* Mobile bottom nav */}
      <nav className="fixed bottom-0 left-0 right-0 bg-white dark:bg-[#0f1117] border-t border-slate-200 dark:border-white/[0.04] z-40 md:hidden">
        <div className="h-16 flex items-stretch">
          {MOBILE_NAV.map(item => {
            const active = currentPath === item.path;
            return (
              <a
                key={item.path}
                className={`mob-nav flex-1 flex flex-col items-center justify-center gap-0.5 text-xs relative ${active ? 'text-indigo-600 dark:text-indigo-400' : 'text-slate-400 dark:text-slate-500'}`}
                onClick={() => handleNav(item.path)}
              >
                <i className={`ph-duotone ${item.icon} text-xl`} />
                <span>{t(item.labelKey) || item.label}</span>
                {item.badgeId && <MobileBadge id={item.badgeId} badges={badges} />}
              </a>
            );
          })}
          <button
            onClick={toggleMobile}
            className="mob-nav flex-1 flex flex-col items-center justify-center gap-0.5 text-slate-400 dark:text-slate-500 text-xs"
          >
            <i className="ph-duotone ph-list text-xl" />
            <span>{t('mob.menu') || 'Menu'}</span>
          </button>
        </div>
      </nav>
    </>
  );
}

function NavBadge({ id, badges, collapsed }: { id: string; badges: Record<string, number | boolean>; collapsed: boolean }) {
  const val = badges[id];
  if (!val) return null;

  if (id === 'settings') {
    // Red dot for settings
    return <span className={`absolute ${collapsed ? 'top-0.5 right-0.5' : 'top-1.5 right-2.5'} w-2 h-2 rounded-full bg-red-500`} />;
  }

  // Numeric badge
  const display = typeof val === 'number' ? (val > 99 ? '99+' : String(val)) : '';
  return (
    <span className={`absolute ${collapsed ? 'top-0 right-0' : 'top-1 right-2'} min-w-[18px] h-[18px] rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center px-1`}>
      {display}
    </span>
  );
}

function MobileBadge({ id, badges }: { id: string; badges: Record<string, number | boolean> }) {
  const val = badges[id];
  if (!val) return null;

  if (id === 'settings') {
    return <span className="absolute top-1 right-1/4 w-2 h-2 rounded-full bg-red-500" />;
  }

  const display = typeof val === 'number' ? (val > 99 ? '99+' : String(val)) : '';
  return (
    <span className="absolute top-1 right-1/4 min-w-[16px] h-[16px] rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center px-0.5">
      {display}
    </span>
  );
}
