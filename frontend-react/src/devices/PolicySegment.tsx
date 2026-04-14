import { useState, useRef } from 'react';
import { setServicePolicy } from './api';
import { svcDisplayName } from '../utils/services';
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
  expiresAt?: string | null;
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

export default function PolicySegment({ serviceName, currentAction, expiresAt, onPolicyChanged }: Props) {
  const [pending, setPending] = useState(false);
  const [local, setLocal] = useState<Action | null>(null);
  const [localExpires, setLocalExpires] = useState<string | null | undefined>(undefined);
  const [showTimer, setShowTimer] = useState(false);

  const active = local ?? currentAction;
  const expires = localExpires !== undefined ? localExpires : expiresAt;

  const handleClick = async (action: Action) => {
    if (pending || action === active) return;
    setPending(true);
    try {
      await setServicePolicy(serviceName, action);
      setLocal(action);
      setLocalExpires(null); // new action clears timer
      onPolicyChanged?.(serviceName, action);
      const label = t(`rules.${action}`) || labels[action];
      window.showToast?.(`${svcDisplayName(serviceName)}: ${label}`, 'success');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  };

  const handleTimer = async (hours: number | null) => {
    const action = active || 'alert';
    const expiresIso = hours ? new Date(Date.now() + hours * 3600 * 1000).toISOString() : null;
    setPending(true);
    setShowTimer(false);
    try {
      await setServicePolicy(serviceName, action);
      // Re-POST with expires_at
      if (expiresIso) {
        const res = await fetch('/api/policies', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scope: 'global',
            service_name: serviceName,
            category: null,
            action,
            expires_at: expiresIso,
          }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      }
      setLocal(action);
      setLocalExpires(expiresIso);
      const label = hours ? `${hours}h` : (t('timer.forever') || 'permanent');
      window.showToast?.(`${svcDisplayName(serviceName)}: ${label}`, 'success');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  };

  const handleTimerAt = async (timeValue: string) => {
    if (!timeValue) return;
    const [hh, mm] = timeValue.split(':').map(Number);
    const target = new Date();
    target.setHours(hh, mm, 0, 0);
    if (target <= new Date()) target.setDate(target.getDate() + 1);

    const action = active || 'alert';
    setPending(true);
    setShowTimer(false);
    try {
      const res = await fetch('/api/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope: 'global',
          service_name: serviceName,
          category: null,
          action,
          expires_at: target.toISOString(),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setLocal(action);
      setLocalExpires(target.toISOString());
      const timeStr = target.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      window.showToast?.(`${svcDisplayName(serviceName)}: ${t('timer.until') || 'until'} ${timeStr}`, 'success');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  };

  // Timer display
  const expiresTime = expires ? new Date(expires).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : null;
  const isExpired = expires ? new Date(expires) <= new Date() : false;

  const base = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors';

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        {/* 3-way segment */}
        <div className="flex gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 flex-1">
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

        {/* Timer button */}
        <button
          onClick={e => { e.stopPropagation(); setShowTimer(!showTimer); }}
          className="flex-shrink-0 p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors"
          title={t('timer.setTimer') || 'Set timer'}
        >
          {expiresTime && !isExpired ? (
            <span className="flex flex-col items-center gap-0">
              <i className="ph-duotone ph-clock-countdown text-base text-blue-500" />
              <span className="text-[9px] tabular-nums text-blue-500 font-medium leading-none">{expiresTime}</span>
            </span>
          ) : (
            <i className="ph-duotone ph-clock text-base text-slate-400" />
          )}
        </button>
      </div>

      {/* Timer dropdown */}
      {showTimer && (
        <TimerDropdown
          onDuration={handleTimer}
          onTimeAt={handleTimerAt}
          onClose={() => setShowTimer(false)}
          pending={pending}
        />
      )}
    </div>
  );
}

function TimerDropdown({ onDuration, onTimeAt, onClose, pending }: {
  onDuration: (hours: number | null) => void;
  onTimeAt: (time: string) => void;
  onClose: () => void;
  pending: boolean;
}) {
  const timeRef = useRef<HTMLInputElement>(null);

  const chipCls = 'px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-blue-100 dark:hover:bg-blue-900/30 text-xs font-medium text-slate-600 dark:text-slate-300 transition-colors disabled:opacity-50';

  return (
    <div className="bg-white dark:bg-[#0f1117] border border-slate-200 dark:border-white/[0.08] rounded-xl shadow-lg p-3 space-y-3" onClick={e => e.stopPropagation()}>
      {/* Quick durations */}
      <div>
        <p className="text-[10px] text-slate-500 dark:text-slate-400 mb-1.5 uppercase tracking-wider font-medium">{t('timer.quickDuration') || 'Duration'}</p>
        <div className="flex flex-wrap gap-1.5">
          {[1, 2, 4, 8, 24].map(h => (
            <button key={h} disabled={pending} onClick={() => onDuration(h)} className={chipCls}>{h}h</button>
          ))}
        </div>
      </div>
      {/* Custom time */}
      <div>
        <p className="text-[10px] text-slate-500 dark:text-slate-400 mb-1.5 uppercase tracking-wider font-medium">{t('timer.untilTime') || 'Until specific time'}</p>
        <div className="flex items-center gap-2">
          <input
            ref={timeRef}
            type="time"
            className="flex-1 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200"
          />
          <button
            disabled={pending}
            onClick={() => timeRef.current?.value && onTimeAt(timeRef.current.value)}
            className="px-3 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-semibold transition-colors disabled:opacity-50"
          >
            {t('timer.set') || 'Set'}
          </button>
        </div>
      </div>
      {/* Footer */}
      <div className="flex items-center justify-between pt-1.5 border-t border-slate-100 dark:border-white/[0.06]">
        <button disabled={pending} onClick={() => onDuration(null)} className="text-[11px] text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
          {t('timer.forever') || 'Permanent (no timer)'}
        </button>
        <button onClick={onClose} className="px-2 py-1 rounded text-[11px] text-slate-400 hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors">
          {t('confirm.cancel') || 'Cancel'}
        </button>
      </div>
    </div>
  );
}
