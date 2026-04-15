// Shared IP → friendly device name lookup.
//
// Fetches /api/devices once (React Query caches it under ['devices'], so
// the Devices page and every insight page share the same request) and
// returns helpers to resolve an IP to the best device name we know —
// localStorage friendly name > display_name > hostname > vendor fallback >
// IP. See bestDeviceName() in utils/devices.ts for the precedence rules.
//
// Why this hook exists: the AI / Cloud / Privacy pages used to show raw
// IPs everywhere because window.deviceMap is keyed by MAC (so a bare
// dm[ip] lookup always missed) and was only populated after the user
// visited the Devices page. This hook makes the lookup work regardless
// of navigation order and keys by IP directly.
import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { fetchDevices } from '../devices/api';
import { bestDeviceName, type Device } from './devices';

export interface DeviceLookup {
  /** Friendly name for the IP, or the IP itself if unknown. */
  nameByIp: (ip: string) => string;
  /** Full device record for the IP, or null if unknown. */
  deviceByIp: (ip: string) => Device | null;
  /** True once devices have loaded — otherwise nameByIp just echoes the IP. */
  ready: boolean;
}

export function useDeviceLookup(): DeviceLookup {
  const { data: devices = [], isSuccess } = useQuery({
    queryKey: ['devices'],
    queryFn: fetchDevices,
    staleTime: 60_000,
  });

  return useMemo(() => {
    const ipMap: Record<string, Device> = {};
    devices.forEach((d: Device) => {
      (d.ips || []).forEach(ipRec => { ipMap[ipRec.ip] = d; });
    });
    return {
      nameByIp: (ip: string) => {
        if (!ip) return ip;
        const d = ipMap[ip];
        if (!d) return ip;
        return bestDeviceName(d.mac_address, d);
      },
      deviceByIp: (ip: string) => ipMap[ip] || null,
      ready: isSuccess,
    };
  }, [devices, isSuccess]);
}
