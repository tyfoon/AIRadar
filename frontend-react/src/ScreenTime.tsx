import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchActivity } from './api';
import { categoryColor, categoryName, serviceColor, formatDuration, formatBytes, serviceName } from './colors';
import type { Session } from './types';

// Get today in YYYY-MM-DD local time
function todayStr(): string {
  return new Date().toISOString().slice(0, 10);
}

function shiftDate(date: string, days: number): string {
  const d = new Date(date + 'T12:00:00');
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

function formatDate(date: string): string {
  const d = new Date(date + 'T12:00:00');
  return d.toLocaleDateString(undefined, {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
  });
}

// Convert ISO timestamp to fractional hour (0-24) in local time
function toHour(iso: string): number {
  const d = new Date(iso);
  return d.getHours() + d.getMinutes() / 60;
}

interface Props {
  macAddress: string;
}

export default function ScreenTime({ macAddress }: Props) {
  const [date, setDate] = useState(todayStr);
  const [expanded, setExpanded] = useState(true);
  const isToday = date === todayStr();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['activity', macAddress, date],
    queryFn: () => fetchActivity(macAddress, date),
    staleTime: 30_000,
    enabled: !!macAddress,
  });

  if (!macAddress) {
    return <div className="p-5 text-sm text-slate-400">No device selected</div>;
  }

  return (
    <div className="p-5 space-y-4">
      {/* Date navigation */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => setDate(d => shiftDate(d, -1))}
          className="px-2.5 py-1 text-xs rounded-lg bg-slate-100 dark:bg-white/[0.06] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/[0.1] transition-colors"
        >
          &#9664;
        </button>
        <span className="text-sm font-medium text-slate-700 dark:text-slate-200">
          {formatDate(date)}
        </span>
        <div className="flex items-center gap-2">
          {!isToday && (
            <button
              onClick={() => setDate(todayStr())}
              className="px-2.5 py-1 text-[11px] rounded-lg bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 transition-colors"
            >
              Today
            </button>
          )}
          <button
            onClick={() => setDate(d => shiftDate(d, 1))}
            disabled={isToday}
            className="px-2.5 py-1 text-xs rounded-lg bg-slate-100 dark:bg-white/[0.06] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/[0.1] transition-colors disabled:opacity-30"
          >
            &#9654;
          </button>
        </div>
      </div>

      {/* Loading state */}
      {isLoading && (
        <div className="py-10 text-center text-sm text-slate-400">
          <div className="inline-block w-5 h-5 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin mb-2" />
          <p>Loading sessions...</p>
        </div>
      )}

      {/* Error state */}
      {isError && (
        <div className="py-8 text-center text-sm text-red-500 dark:text-red-400">
          Failed to load: {(error as Error)?.message || 'Unknown error'}
        </div>
      )}

      {/* Data loaded */}
      {data && !isLoading && (
        <>
          {/* Grand total */}
          <div className="flex items-baseline gap-3">
            <span className="text-2xl font-bold tabular-nums text-slate-700 dark:text-slate-100">
              {formatDuration(data.grand_total_seconds)}
            </span>
            <span className="text-xs text-slate-400">
              {data.sessions.length} {data.sessions.length === 1 ? 'session' : 'sessions'}
            </span>
          </div>

          {/* Timeline strip (0-24h) */}
          {data.sessions.length > 0 && <TimelineStrip sessions={data.sessions} />}

          {/* Service chips */}
          {data.totals_by_service.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {data.totals_by_service.map(t => {
                const color = serviceColor(t.service, t.category);
                return (
                  <div
                    key={t.service}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium"
                    style={{
                      backgroundColor: color + '20',
                      color: color,
                    }}
                  >
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: color }}
                    />
                    {serviceName(t.service)}
                    <span className="opacity-60">{formatDuration(t.duration_seconds)}</span>
                  </div>
                );
              })}
            </div>
          )}

          {/* Session list */}
          {data.sessions.length > 0 ? (
            <div>
              <button
                onClick={() => setExpanded(e => !e)}
                className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors mb-2"
              >
                {expanded ? '▾ Sessions' : '▸ Sessions'} ({data.sessions.length})
              </button>
              {expanded && <SessionList sessions={data.sessions} />}
            </div>
          ) : (
            <div className="py-8 text-center text-sm text-slate-400 dark:text-slate-500">
              No activity on this day.
            </div>
          )}
        </>
      )}
    </div>
  );
}

// --- Timeline Strip (24h horizontal bar) ---
function TimelineStrip({ sessions }: { sessions: Session[] }) {
  const categories = [...new Set(sessions.map(s => s.category))];

  return (
    <div className="space-y-1.5">
      {categories.map(cat => {
        const catSessions = sessions.filter(s => s.category === cat);
        return (
          <div key={cat}>
            {/* Category label */}
            <div className="flex items-center gap-1.5 mb-0.5">
              <span
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ backgroundColor: categoryColor(cat) }}
              />
              <span className="text-[10px] font-medium text-slate-500 dark:text-slate-400">
                {categoryName(cat)}
              </span>
            </div>
            {/* Timeline bar */}
            <div className="relative h-6 rounded bg-slate-100 dark:bg-white/[0.04]">
              {/* Hour markers */}
              {[6, 12, 18].map(h => (
                <div
                  key={h}
                  className="absolute top-0 bottom-0 border-l border-slate-200 dark:border-white/[0.08]"
                  style={{ left: `${(h / 24) * 100}%` }}
                />
              ))}
              {/* Session blocks — per-service color */}
              {catSessions.map((s, i) => {
                const startH = toHour(s.start);
                const endH = toHour(s.end);
                const left = (startH / 24) * 100;
                const width = Math.max(0.8, ((endH - startH) / 24) * 100);
                const color = serviceColor(s.service, s.category);
                return (
                  <div
                    key={i}
                    className="absolute top-0.5 bottom-0.5 rounded-sm flex items-center justify-center overflow-hidden"
                    style={{
                      left: `${left}%`,
                      width: `${width}%`,
                      backgroundColor: color,
                    }}
                    title={`${serviceName(s.service)} · ${new Date(s.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}–${new Date(s.end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · ${formatDuration(s.duration_seconds)} · ${formatBytes(s.bytes)}`}
                  >
                    {/* Show service name if block is wide enough */}
                    {width > 4 && (
                      <span className="text-[8px] text-white font-medium truncate px-0.5">
                        {serviceName(s.service)}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
      {/* Hour labels */}
      <div className="flex justify-between text-[9px] text-slate-400 px-0.5">
        <span>0:00</span>
        <span>6:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>24:00</span>
      </div>
    </div>
  );
}

// --- Session List ---
function SessionList({ sessions }: { sessions: Session[] }) {
  // Sort by start time
  const sorted = [...sessions].sort(
    (a, b) => new Date(a.start).getTime() - new Date(b.start).getTime(),
  );

  return (
    <div className="space-y-1.5">
      {sorted.map((s, i) => (
        <div
          key={i}
          className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-50 dark:bg-white/[0.03] text-sm"
        >
          <span
            className="w-2 h-2 rounded-full flex-shrink-0"
            style={{ backgroundColor: serviceColor(s.service, s.category) }}
          />
          <span className="font-medium text-slate-700 dark:text-slate-200 min-w-[100px]">
            {serviceName(s.service)}
          </span>
          <span className="text-xs text-slate-400 tabular-nums">
            {new Date(s.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            –
            {new Date(s.end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
          <span className="text-xs font-medium text-slate-600 dark:text-slate-300 tabular-nums ml-auto">
            {formatDuration(s.duration_seconds)}
          </span>
          <span className="text-[11px] text-slate-400 tabular-nums w-16 text-right">
            {formatBytes(s.bytes)}
          </span>
        </div>
      ))}
    </div>
  );
}
