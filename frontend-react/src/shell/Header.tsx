import { useLocation } from 'react-router-dom';
import { ROUTES } from './routes';
import { t } from '../utils/i18n';

declare global {
  interface Window {
    manualRefresh?: () => void;
  }
}

interface Props {
  onToggleMobileSidebar: () => void;
}

export default function Header({ onToggleMobileSidebar }: Props) {
  const location = useLocation();
  const currentPath = location.pathname.replace(/^\//, '') || 'summary';
  const route = ROUTES.find(r => r.path === currentPath || r.pageId === currentPath);
  const title = route ? (t('page.' + route.pageId) || route.label) : 'AI-Radar';

  const handleRefresh = () => {
    if (typeof window.manualRefresh === 'function') {
      window.manualRefresh();
    }
  };

  return (
    <header className="sticky top-0 z-30 h-14 bg-white/80 dark:bg-[#0B0C10]/85 backdrop-blur-md border-b border-slate-200 dark:border-white/[0.04] flex items-center justify-between px-6">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobileSidebar}
          className="md:hidden w-12 h-12 -ml-2 rounded-lg flex items-center justify-center hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <i className="ph-duotone ph-list text-xl" />
        </button>
        <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{title}</h2>
      </div>
      <div className="flex items-center gap-4">
        <a href="#/settings" id="system-status" className="hidden sm:flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 cursor-pointer hover:underline transition-colors">
          <span id="status-dot" className="w-2 h-2 rounded-full bg-slate-400" />
          <span id="status-text">{t('topbar.checking') || 'Checking...'}</span>
        </a>
        <span id="last-refresh" className="text-[11px] text-slate-400 dark:text-slate-500 hidden sm:inline tabular-nums" />
        <button
          onClick={handleRefresh}
          id="refresh-btn"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-slate-200 dark:hover:bg-white/[0.1] text-xs text-slate-600 dark:text-slate-300 transition-all active:scale-95 font-medium"
        >
          <i id="refresh-icon" className="ph-duotone ph-arrows-clockwise text-sm" />
          <span className="hidden sm:inline">{t('topbar.refresh') || 'Refresh'}</span>
        </button>
      </div>
    </header>
  );
}
