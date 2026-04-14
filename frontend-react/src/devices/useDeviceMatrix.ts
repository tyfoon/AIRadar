import { useQuery } from '@tanstack/react-query';
import { fetchDevices, fetchEvents, fetchPolicies } from './api';
import type { Device, DeviceEvent, DeviceMatrix, DeviceMap, IpToMac, Policy } from './types';
import { bestDeviceName } from '../utils/devices';

interface MatrixResult {
  deviceMap: DeviceMap;
  ipToMac: IpToMac;
  matrix: DeviceMatrix;
  allEvents: DeviceEvent[];
  policyByService: Record<string, string>;
  policyExpiresByService: Record<string, string>;
  isLoading: boolean;
  isError: boolean;
  refetch: () => void;
}

export function useDeviceMatrix(periodMinutes: number): MatrixResult {
  const startIso = new Date(Date.now() - periodMinutes * 60000).toISOString();

  const devicesQuery = useQuery({
    queryKey: ['devices'],
    queryFn: fetchDevices,
    staleTime: 30_000,
  });

  const eventsQuery = useQuery({
    queryKey: ['deviceEvents', periodMinutes],
    queryFn: async () => {
      const [ai, cloud, track, other, policies] = await Promise.all([
        fetchEvents('ai', startIso),
        fetchEvents('cloud', startIso),
        fetchEvents('tracking', startIso),
        fetchEvents('other', startIso),
        fetchPolicies(),
      ]);
      ai.forEach(e => e._cat = 'ai');
      cloud.forEach(e => e._cat = 'cloud');
      track.forEach(e => e._cat = 'tracking');
      other.forEach(e => e._cat = 'other');
      return { events: [...ai, ...cloud, ...track, ...other], policies };
    },
    staleTime: 30_000,
  });

  const devices = devicesQuery.data || [];
  const allEvents = eventsQuery.data?.events || [];
  const policies: Policy[] = eventsQuery.data?.policies || [];

  // Build deviceMap and ipToMac
  const deviceMap: DeviceMap = {};
  const ipToMac: IpToMac = {};
  devices.forEach((d: Device) => {
    deviceMap[d.mac_address] = d;
    if (d.ips) d.ips.forEach(ip => { ipToMac[ip.ip] = d.mac_address; });
  });

  // Build policy lookup
  const policyByService: Record<string, string> = {};
  const policyExpiresByService: Record<string, string> = {};
  policies.forEach(p => {
    if (p.scope === 'global' && p.service_name && !p.category) {
      policyByService[p.service_name] = p.action;
      if (p.expires_at) policyExpiresByService[p.service_name] = p.expires_at;
    }
  });

  // Build matrix
  const matrixData: Record<string, Record<string, { count: number; uploads: number }>> = {};
  const allServices = new Set<string>();
  const svcCategoryMap: Record<string, string> = {};

  allEvents.forEach(e => {
    svcCategoryMap[e.ai_service] = e._cat;
    const mac = ipToMac[e.source_ip] || `_ip_${e.source_ip}`;
    if (!matrixData[mac]) matrixData[mac] = {};
    const row = matrixData[mac];
    if (!row[e.ai_service]) row[e.ai_service] = { count: 0, uploads: 0 };
    row[e.ai_service].count++;
    if (e.possible_upload) row[e.ai_service].uploads++;
    allServices.add(e.ai_service);
  });

  // Include all known devices
  const allKnownMacs = new Set([...Object.keys(matrixData), ...Object.keys(deviceMap)]);
  const deviceMacs = [...allKnownMacs].sort((a, b) => {
    const totalA = Object.values(matrixData[a] || {}).reduce((s, v) => s + v.count, 0);
    const totalB = Object.values(matrixData[b] || {}).reduce((s, v) => s + v.count, 0);
    if (totalA === 0 && totalB === 0) {
      return bestDeviceName(a, deviceMap[a] || null).localeCompare(bestDeviceName(b, deviceMap[b] || null));
    }
    return totalB - totalA;
  });

  let globalMax = 1;
  deviceMacs.forEach(mac => {
    Object.values(matrixData[mac] || {}).forEach(v => { if (v.count > globalMax) globalMax = v.count; });
  });

  const matrix: DeviceMatrix = { matrix: matrixData, svcCategoryMap, allServices, deviceMacs, globalMax };

  return {
    deviceMap,
    ipToMac,
    matrix,
    allEvents,
    policyByService,
    policyExpiresByService,
    isLoading: devicesQuery.isLoading || eventsQuery.isLoading,
    isError: devicesQuery.isError || eventsQuery.isError,
    refetch: () => { devicesQuery.refetch(); eventsQuery.refetch(); },
  };
}
