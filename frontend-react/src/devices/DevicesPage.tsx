import { useState, useCallback, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useDeviceMatrix } from './useDeviceMatrix';
import DeviceMatrix from './DeviceMatrix';
import GroupsTab from './GroupsTab';
import AskNetwork from './AskNetwork';
import { refreshDeviceMetadata } from './api';
import { t } from '../utils/i18n';

declare global {
  interface Window {
    navigate?: (page: string) => void;
    showToast?: (msg: string, type?: string) => void;
    openDeviceDrawer?: (mac: string) => void;
    // Expose deviceMap for other vanilla JS pages that still need it
    deviceMap?: Record<string, unknown>;
    ipToMac?: Record<string, string>;
  }
}

const PERIOD_OPTIONS = [
  { value: 60, label: '1h' },
  { value: 1440, label: '24h' },
  { value: 10080, label: '7d' },
  { value: 43200, label: '30d' },
];

export default function DevicesPage() {
  const [activeTab, setActiveTab] = useState<'devices' | 'groups'>('devices');
  const [period, setPeriod] = useState(1440);
  const queryClient = useQueryClient();

  const { deviceMap, ipToMac, matrix, policyByService, isLoading, isError, refetch } = useDeviceMatrix(period);

  // Expose deviceMap/ipToMac to vanilla JS pages that still need it
  useEffect(() => {
    window.deviceMap = deviceMap as Record<string, unknown>;
    window.ipToMac = ipToMac;
  }, [deviceMap, ipToMac]);

  // Open the drawer via the global AppShell bridge so the same overlay is
  // reused whether the user clicks from here, Geo, IoT, or anywhere else.
  const openDrawer = useCallback((mac: string) => {
    window.openDeviceDrawer?.(mac);
  }, []);

  const handleRename = useCallback((mac: string) => {
    // Open drawer which has inline rename
    window.openDeviceDrawer?.(mac);
  }, []);

  const handleRefresh = useCallback(async (mac: string) => {
    try {
      await refreshDeviceMetadata(mac);
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      window.showToast?.('Device info refreshed', 'success');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  }, [queryClient]);

  const handleNavigateRules = useCallback((_mac: string) => {
    window.navigate?.('rules');
    window.showToast?.(t('rules.manageRules') || 'Navigate to Rules to manage device rules', 'info');
  }, []);

  const handleGenerateReport = useCallback((mac: string) => {
    window.openDeviceDrawer?.(mac);
    // Report tab is default, so drawer opens to it
  }, []);

  const tabBase = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const tabActive = `${tabBase} bg-blue-700 text-white shadow-sm`;
  const tabInactive = `${tabBase} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;

  return (
    <div className="space-y-6">
      {/* Tab switch: Devices / Groups */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] p-1 rounded-lg">
          <button className={activeTab === 'devices' ? tabActive : tabInactive} onClick={() => setActiveTab('devices')}>
            {t('dev.tabDevices')}
          </button>
          <button className={activeTab === 'groups' ? tabActive : tabInactive} onClick={() => setActiveTab('groups')}>
            {t('dev.tabGroups')}
          </button>
        </div>
        {activeTab === 'devices' && (
          <select
            value={period}
            onChange={e => setPeriod(Number(e.target.value))}
            className="text-xs px-3 py-1.5 rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-600 dark:text-slate-300"
          >
            {PERIOD_OPTIONS.map(o => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        )}
      </div>

      {activeTab === 'devices' && (
        <>
          <AskNetwork />

          {isLoading && (
            <div className="py-12 text-center text-sm text-slate-400">
              <div className="inline-block w-6 h-6 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin mb-2" />
              <p>Loading devices...</p>
            </div>
          )}

          {isError && (
            <div className="py-8 text-center text-sm text-red-500">
              Failed to load device data.
              <button onClick={refetch} className="ml-2 underline">Retry</button>
            </div>
          )}

          {!isLoading && !isError && (
            <DeviceMatrix
              matrix={matrix}
              deviceMap={deviceMap}
              policyByService={policyByService}
              onOpenDrawer={openDrawer}
              onRename={handleRename}
              onRefresh={handleRefresh}
              onNavigateRules={handleNavigateRules}
              onGenerateReport={handleGenerateReport}
            />
          )}
        </>
      )}

      {activeTab === 'groups' && (
        <GroupsTab deviceMap={deviceMap} />
      )}
    </div>
  );
}
