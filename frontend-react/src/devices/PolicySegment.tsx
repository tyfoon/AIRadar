import { useState } from 'react';
import { setServicePolicy } from './api';
import { t } from '../utils/i18n';

declare global {
  interface Window {
    showToast?: (msg: string, type?: string) => void;
  }
}

type Action = 'allow' | 'alert' | 'block';

interface Props {
  serviceName: string;
  currentAction: Action | null;
  onPolicyChanged?: (service: string, action: Action) => void;
}

const styles = {
  allow: {
    active: 'bg-emerald-500 text-white shadow-sm',
    inactive: 'text-slate-500 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/20',
    icon: 'ph-check',
  },
  alert: {
    active: 'bg-amber-500 text-white shadow-sm',
    inactive: 'text-slate-500 dark:text-slate-400 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20',
    icon: 'ph-warning',
  },
  block: {
    active: 'bg-red-500 text-white shadow-sm',
    inactive: 'text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20',
    icon: 'ph-x',
  },
} as const;

const labels: Record<Action, string> = {
  allow: 'Allow',
  alert: 'Alert',
  block: 'Block',
};

export default function PolicySegment({ serviceName, currentAction, onPolicyChanged }: Props) {
  const [pending, setPending] = useState(false);
  const [local, setLocal] = useState<Action | null>(null);

  const active = local ?? currentAction;

  const handleClick = async (action: Action) => {
    if (pending || action === active) return;
    setPending(true);
    try {
      await setServicePolicy(serviceName, action);
      setLocal(action);
      onPolicyChanged?.(serviceName, action);
      const label = t(`rules.${action}`) || labels[action];
      window.showToast?.(`${serviceName}: ${label}`, 'success');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  };

  const base = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors';

  return (
    <div className="flex gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1">
      {(['allow', 'alert', 'block'] as const).map(action => {
        const s = styles[action];
        const isActive = active === action;
        return (
          <button
            key={action}
            disabled={pending}
            onClick={e => { e.stopPropagation(); handleClick(action); }}
            className={`${base} ${isActive ? `font-semibold ${s.active}` : s.inactive} ${pending ? 'opacity-50 cursor-wait' : ''}`}
          >
            <i className={`ph-duotone ${s.icon} text-xs`} />
            <span>{t(`rules.${action}`) || labels[action]}</span>
          </button>
        );
      })}
    </div>
  );
}
