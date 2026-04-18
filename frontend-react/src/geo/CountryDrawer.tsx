import { useState, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchCountryDetail } from './api';
import { formatBytes, formatNumber, countryName, flagClass } from './utils';
import { fetchReputationBulk, type ReputationResult } from '../shared/reputationApi';
import ReputationBadge from '../shared/ReputationBadge';
import ReputationModal from '../shared/ReputationModal';
import SvcLogo from '../devices/SvcLogo';
import { svcDisplayName } from '../utils/services';
import type { Direction, CountryDetailIP } from './types';

interface CountryDrawerProps {
  cc: string | null;  // country code, null = closed
  direction: Direction;
  onClose: () => void;
  onDirectionChange: (dir: Direction) => void;
}

export default function CountryDrawer({ cc, direction, onClose, onDirectionChange }: CountryDrawerProps) {
  const [repCache, setRepCache] = useState<Record<string, ReputationResult>>({});
  const [repTarget, setRepTarget] = useState<string | null>(null);

  // Fetch country detail data
  const { data, isLoading, isError } = useQuery({
    queryKey: ['country-detail', cc, direction],
    queryFn: () => fetchCountryDetail(cc!, direction),
    enabled: !!cc,
    staleTime: 30_000,
  });

  // Bulk-fetch reputation for all IPs when data arrives
  useEffect(() => {
    if (!data?.top_ips?.length) return;
    const ips = data.top_ips.map(ip => ip.ip);
    fetchReputationBulk(ips).then(results => {
      setRepCache(prev => ({ ...prev, ...results }));
    });
  }, [data?.top_ips]);

  // Close on Escape
  useEffect(() => {
    if (!cc) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [cc, onClose]);

  // When the user clicks a device inside this drawer we want to swap to
  // the DeviceDrawer without the two briefly stacking (both share
  // drawer-panel's z-index:51 and slide from the right). Strategy: set a
  // class that disables the slide-out transition for this one close so
  // the CountryDrawer vanishes instantly, then fire openDeviceDrawer so
  // the DeviceDrawer slides in cleanly into the now-empty slot. The flag
  // resets whenever `cc` changes so the next normal open/close path gets
  // its default animation back — we used to mutate inline style.transition
  // directly, which persisted on the DOM node and broke the slide-in
  // when the user clicked the back button to reopen this drawer.
  const [skipAnim, setSkipAnim] = useState(false);
  useEffect(() => { setSkipAnim(false); }, [cc]);
  const handleDeviceClick = useCallback((mac: string) => {
    setSkipAnim(true);
    onClose();
    // Pass a "back to <country>" context so the DeviceDrawer can render
    // a back button that reopens this drawer with the same (cc, direction)
    // state when the user is done exploring the device.
    if (typeof (window as any).openDeviceDrawer === 'function' && cc) {
      (window as any).openDeviceDrawer(mac, {
        back: {
          type: 'country',
          cc,
          direction,
          label: `Back to ${countryName(cc)}`,
        },
      });
    }
  }, [onClose, cc, direction]);

  const dirLabel = direction === 'outbound' ? 'Outbound' : 'Inbound';

  return (
    <>
      {/* Backdrop */}
      <div
        className={`drawer-backdrop ${cc ? 'open' : ''} ${skipAnim ? 'drawer-no-anim' : ''}`}
        onClick={onClose}
      />

      {/* Panel */}
      <div className={`drawer-panel ${cc ? 'open' : ''} ${skipAnim ? 'drawer-no-anim' : ''}`}>
        {cc && (
          <>
            {/* Header */}
            <div className="flex-shrink-0 border-b border-slate-200 dark:border-white/[0.05] px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 min-w-0">
                  <span className={`${flagClass(cc)} text-2xl flex-shrink-0`} />
                  <div className="min-w-0">
                    <h2 className="text-base font-semibold truncate">
                      {countryName(cc)} ({cc})
                    </h2>
                    <p className="text-xs text-slate-400 dark:text-slate-500 truncate mt-0.5">
                      {isLoading && 'Loading\u2026'}
                      {isError && 'Failed to load country data'}
                      {data && (
                        <>
                          {dirLabel} &middot; {formatBytes(data.total_bytes)} &middot; {formatNumber(data.total_hits)} conn.
                        </>
                      )}
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors text-lg"
                >
                  &times;
                </button>
              </div>
            </div>

            {/* Body */}
            <div className="flex-1 overflow-y-auto p-5 space-y-6">
              {/* Direction toggle */}
              <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
                <DirBtn
                  active={direction === 'outbound'}
                  onClick={() => onDirectionChange('outbound')}
                  label={<><span>&#8593;</span> Outbound</>}
                />
                <DirBtn
                  active={direction === 'inbound'}
                  onClick={() => onDirectionChange('inbound')}
                  label={<><span>&#8595;</span> Inbound</>}
                />
              </div>

              {/* Top devices */}
              <Section title="Top devices">
                {!data && isLoading && <Placeholder />}
                {data && data.top_devices.length === 0 && (
                  <EmptyMsg>No devices recorded.</EmptyMsg>
                )}
                {data && data.top_devices.length > 0 && (
                  <DeviceList
                    devices={data.top_devices}
                    onClick={handleDeviceClick}
                  />
                )}
              </Section>

              {/* Top services */}
              <Section title="Top services">
                {!data && isLoading && <Placeholder />}
                {data && data.top_services.length === 0 && (
                  <EmptyMsg>No services recorded.</EmptyMsg>
                )}
                {data && data.top_services.length > 0 && (
                  <ServiceList services={data.top_services} />
                )}
              </Section>

              {/* Top IPs */}
              <Section title="Top remote IPs">
                {!data && isLoading && <Placeholder />}
                {data && data.top_ips.length === 0 && (
                  <EmptyMsg>No remote IPs recorded.</EmptyMsg>
                )}
                {data && data.top_ips.length > 0 && (
                  <IPList
                    ips={data.top_ips}
                    repCache={repCache}
                    onIPClick={setRepTarget}
                  />
                )}
              </Section>
            </div>
          </>
        )}
      </div>

      {/* Reputation modal */}
      <ReputationModal target={repTarget} onClose={() => setRepTarget(null)} />
    </>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DirBtn({ active, onClick, label }: { active: boolean; onClick: () => void; label: React.ReactNode }) {
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const cls = active
    ? `${base} bg-blue-700 text-white shadow-sm`
    : `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  return <button className={cls} onClick={onClick}>{label}</button>;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
        {title}
      </h3>
      {children}
    </div>
  );
}

function EmptyMsg({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-xs text-slate-400 dark:text-slate-500 py-3">{children}</div>
  );
}

function Placeholder() {
  return (
    <div className="py-4 flex justify-center">
      <div className="w-4 h-4 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
    </div>
  );
}

// --- Devices ---

function DeviceList({ devices, onClick }: {
  devices: { mac: string; name: string; vendor?: string; bytes: number }[];
  onClick: (mac: string) => void;
}) {
  const maxB = devices[0]?.bytes || 1;
  return (
    <div>
      {devices.map((d) => {
        const w = Math.max(2, (d.bytes / maxB) * 100);
        return (
          <div
            key={d.mac || d.name}
            className={`flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] ${d.mac ? 'cursor-pointer' : ''}`}
            onClick={() => d.mac && onClick(d.mac)}
          >
            <div className="flex-shrink-0">
              <i className="ph-duotone ph-desktop text-lg text-slate-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">
                  {d.name}
                  {d.vendor && (
                    <span className="text-[10px] text-slate-400 dark:text-slate-500 ml-1">{d.vendor}</span>
                  )}
                </span>
                <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">
                  {formatBytes(d.bytes)}
                </span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-blue-700"
                  style={{ width: `${w}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// --- Services ---

function ServiceList({ services }: {
  services: { service: string; bytes: number; hits: number }[];
}) {
  const maxB = services[0]?.bytes || 1;
  return (
    <div>
      {services.map((s) => {
        const w = Math.max(2, (s.bytes / maxB) * 100);
        return (
          <div
            key={s.service}
            className="flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03]"
          >
            <div className="flex-shrink-0">
              <SvcLogo service={s.service} size={20} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">
                  {svcDisplayName(s.service)}
                </span>
                <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">
                  {formatBytes(s.bytes)}
                </span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-emerald-500 to-teal-500"
                  style={{ width: `${w}%` }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// --- IPs ---

function IPList({ ips, repCache, onIPClick }: {
  ips: CountryDetailIP[];
  repCache: Record<string, ReputationResult>;
  onIPClick: (ip: string) => void;
}) {
  return (
    <div>
      {ips.map((ip) => (
        <IPRow key={ip.ip} ip={ip} repCache={repCache} onClick={() => onIPClick(ip.ip)} />
      ))}
    </div>
  );
}

function IPRow({ ip, repCache, onClick }: {
  ip: CountryDetailIP;
  repCache: Record<string, ReputationResult>;
  onClick: () => void;
}) {
  let primary: React.ReactNode = null;
  let secondary: React.ReactNode = null;

  if (ip.asn_org) {
    primary = (
      <div className="text-xs text-slate-700 dark:text-slate-200 truncate">
        AS{ip.asn || '?'} &middot; {ip.asn_org}
      </div>
    );
    if (ip.ptr) {
      secondary = (
        <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 truncate">
          {ip.ptr}
        </div>
      );
    }
  } else if (ip.ptr) {
    primary = (
      <div className="text-xs text-slate-700 dark:text-slate-200 font-mono truncate">
        {ip.ptr}
      </div>
    );
  } else if (ip.enriched) {
    primary = (
      <div className="text-xs text-slate-400 dark:text-slate-600 italic">
        (no reverse DNS / ASN)
      </div>
    );
  } else {
    primary = (
      <div className="text-xs text-slate-400 dark:text-slate-600 italic">
        enriching&hellip;
      </div>
    );
  }

  return (
    <div
      className="flex items-center justify-between py-2 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] border-b border-slate-100 dark:border-white/[0.04] last:border-0 cursor-pointer"
      onClick={onClick}
    >
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[10px] text-slate-400 dark:text-slate-500 truncate flex items-center gap-1 flex-wrap">
          {ip.ip}
          <ReputationBadge ip={ip.ip} cache={repCache} />
        </div>
        {primary}
        {secondary}
      </div>
      <div className="flex-shrink-0 text-right ml-3">
        <div className="text-xs tabular-nums font-medium text-slate-700 dark:text-slate-200">
          {formatBytes(ip.bytes)}
        </div>
        <div className="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">
          {formatNumber(ip.hits)} conn.
        </div>
      </div>
    </div>
  );
}
