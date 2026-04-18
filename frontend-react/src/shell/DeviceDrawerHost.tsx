// ---------------------------------------------------------------------------
// DeviceDrawerHost — global mount point for the React DeviceDrawer.
//
// Mounted once in AppShell so that `window.openDeviceDrawer(mac)` can open
// the drawer from ANY page (GeoMap's country drawer, IoT FleetCard, Geo
// inbound attacks, …) without navigating away from the user's current
// context.
//
// Why not run useDeviceMatrix at the AppShell level and always pass data in?
// The matrix fetches devices + four event categories + all policies; that's
// expensive and pointless when no drawer is open. By gating the hook on
// `mac !== null` we only pay the cost when the drawer is actually shown.
// Subsequent opens use the React Query cache from DevicesPage if that
// page was visited, so they're instant.
// ---------------------------------------------------------------------------

import DeviceDrawer from '../devices/DeviceDrawer';
import { useDeviceMatrix } from '../devices/useDeviceMatrix';
import type { DeviceDrawerBack } from './AppShell';

interface Props {
  mac: string | null;
  back: DeviceDrawerBack | null;
  onClose: () => void;
}

const DEFAULT_PERIOD_MINUTES = 1440; // 24h — matches DevicesPage default

export default function DeviceDrawerHost({ mac, back, onClose }: Props) {
  // When mac is null the drawer isn't open — don't pay for the hook at all.
  if (!mac) return null;
  return <LoadedDrawer mac={mac} back={back} onClose={onClose} />;
}

function LoadedDrawer({ mac, back, onClose }: { mac: string; back: DeviceDrawerBack | null; onClose: () => void }) {
  const {
    deviceMap,
    allEvents,
    matrix,
    policyByService,
    policyExpiresByService,
    refetch,
  } = useDeviceMatrix(DEFAULT_PERIOD_MINUTES);

  return (
    <DeviceDrawer
      mac={mac}
      deviceMap={deviceMap}
      allEvents={allEvents}
      svcCategoryMap={matrix.svcCategoryMap}
      policyByService={policyByService}
      policyExpiresByService={policyExpiresByService}
      back={back}
      onClose={onClose}
      onDevicesRefetch={refetch}
    />
  );
}
