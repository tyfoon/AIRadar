/**
 * Shared IoT fleet components — used by both IotOverview and Dashboard.
 */
import { useQuery } from '@tanstack/react-query';
import { AreaChart, Area, Tooltip as RTooltip, ResponsiveContainer } from 'recharts';
import { fetchTrafficHistory } from './api';
import type { FleetDevice } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
export function fmtBytes(b: number): string {
  if (b >= 1099511627776) return (b / 1099511627776).toFixed(2) + ' TB';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

export function deviceName(d: { display_name?: string | null; hostname?: string | null; mac_address?: string; ips?: string[] }): string {
  return d.display_name || d.hostname || d.ips?.[0] || d.mac_address || '?';
}

export const HEALTH_RING: Record<string, string> = {
  green: 'ring-emerald-500/40',
  orange: 'ring-amber-500/50',
  red: 'ring-red-500/50',
};

export function FlagIcon({ cc, size = '1em' }: { cc: string; size?: string }) {
  if (!cc || cc.length !== 2) return null;
  return <span className={`fi fi-${cc.toLowerCase()} rounded-sm shadow-sm inline-block`} style={{ fontSize: size }} />;
}

// ---------------------------------------------------------------------------
// BaselineBadge
// ---------------------------------------------------------------------------
export function BaselineBadge({ status, days }: { status: string; days: number }) {
  if (status === 'ready') return null;
  const label = status === 'learning' ? 'Learning' : `Building ${days}/7d`;
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 font-medium whitespace-nowrap">
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Sparkline — Recharts area chart per device
// ---------------------------------------------------------------------------
export function Sparkline({ mac }: { mac: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['iot-sparkline', mac],
    queryFn: () => fetchTrafficHistory(mac, 7),
    staleTime: 120_000,
  });

  if (isLoading) {
    return <div className="h-12 bg-slate-100 dark:bg-white/[0.03] rounded animate-pulse" />;
  }

  const points = data?.data || [];
  if (points.length < 2) {
    return (
      <div className="h-12 flex items-center justify-center text-[10px] text-slate-400">
        Collecting data...
      </div>
    );
  }

  const step = Math.max(1, Math.floor(points.length / 168));
  const sampled = points.filter((_, i) => i % step === 0).map(p => ({
    t: new Date(p.hour).getTime(),
    tx: p.tx,
    rx: p.rx,
  }));

  return (
    <div className="h-12">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={sampled} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`rx-${mac}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`tx-${mac}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.25} />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <RTooltip
            contentStyle={{ background: 'rgba(0,0,0,.85)', border: 'none', borderRadius: 6, fontSize: 11, padding: '4px 8px' }}
            labelStyle={{ display: 'none' }}
            formatter={(v: any, name: any) => [fmtBytes(v ?? 0), name === 'rx' ? '↓ RX' : '↑ TX']}
          />
          <Area type="monotone" dataKey="rx" stroke="#3b82f6" strokeWidth={1.5} fill={`url(#rx-${mac})`} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="tx" stroke="#f59e0b" strokeWidth={1} fill={`url(#tx-${mac})`} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FleetCard — full device card with sparkline, baseline, flags, stats
// ---------------------------------------------------------------------------
export function FleetCard({ device: d }: { device: FleetDevice }) {
  const name = deviceName(d);
  const healthRing = HEALTH_RING[d.health] || HEALTH_RING.green;

  const ratio = d.baseline_avg_bytes_24h && d.baseline_avg_bytes_24h > 0
    ? d.bytes_24h / d.baseline_avg_bytes_24h
    : null;
  const barPct = ratio ? Math.min(ratio * 100, 300) / 3 : null;
  const barColor = ratio && ratio > 3 ? 'bg-red-500' : ratio && ratio > 2 ? 'bg-amber-500' : 'bg-blue-500';

  return (
    <div
      className={`bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 ring-2 ${healthRing} cursor-pointer hover:shadow-md transition-all`}
      onClick={() => {
        if (typeof (window as any).openDeviceDrawer === 'function') {
          (window as any).openDeviceDrawer(d.mac_address, null, null);
        }
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="relative">
            <i className="ph-duotone ph-cpu text-lg text-slate-500 dark:text-slate-400" />
            {d.online && (
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-500 ring-2 ring-white dark:ring-slate-900" />
            )}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-semibold text-slate-700 dark:text-slate-200 truncate">{name}</p>
            <p className="text-[10px] text-slate-400 truncate">{d.vendor || d.device_type}</p>
          </div>
        </div>
        <BaselineBadge status={d.baseline_status} days={d.baseline_days} />
      </div>

      {/* Sparkline */}
      <Sparkline mac={d.mac_address} />

      {/* Stats row */}
      <div className="flex items-center justify-between mt-2 text-[10px] text-slate-500 dark:text-slate-400">
        <span className="tabular-nums">{fmtBytes(d.bytes_24h)}</span>
        <span className="flex items-center gap-1">
          <span className="text-amber-500">↑{fmtBytes(d.orig_bytes_24h)}</span>
          <span className="text-blue-500">↓{fmtBytes(d.resp_bytes_24h)}</span>
        </span>
      </div>

      {/* Throughput bar */}
      {barPct !== null && (
        <div className="mt-1.5">
          <div className="w-full h-1 bg-slate-100 dark:bg-white/[0.04] rounded-full overflow-hidden">
            <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${Math.max(2, barPct)}%` }} />
          </div>
          <p className="text-[9px] text-slate-400 mt-0.5 tabular-nums">{(ratio! * 100).toFixed(0)}% of baseline</p>
        </div>
      )}

      {/* Footer: countries + destinations + anomalies */}
      <div className="flex items-center justify-between mt-2">
        <div className="flex gap-0.5">
          {d.top_countries.slice(0, 3).map(c => (
            <span key={c.cc} title={`${c.cc}: ${fmtBytes(c.bytes)}`}><FlagIcon cc={c.cc} size="1.1em" /></span>
          ))}
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <span title="Unique destinations"><i className="ph-duotone ph-map-pin text-xs" /> {d.destinations}</span>
          {d.anomalies > 0 && (
            <span className="text-red-500" title={`${d.anomalies} anomalies`}>
              <i className="ph-duotone ph-warning text-xs" /> {d.anomalies}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
