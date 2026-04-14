// Device type detection and naming — ported from app.js

export interface DeviceType {
  type: string;
  icon: string; // Phosphor icon class (e.g. 'ph-device-mobile')
}

export interface Device {
  mac_address: string;
  hostname?: string;
  vendor?: string;
  display_name?: string;
  last_seen?: string;
  os_name?: string;
  os_version?: string;
  device_class?: string;
  network_distance?: number;
  dhcp_vendor_class?: string;
  ja4_label?: string;
  ips: { ip: string }[];
}

// Phosphor icon names (without ph-duotone prefix)
const ICON = {
  phone: 'ph-device-mobile',
  tablet: 'ph-device-tablet',
  laptop: 'ph-laptop',
  desktop: 'ph-desktop',
  tv: 'ph-television',
  speaker: 'ph-speaker-hifi',
  printer: 'ph-printer',
  router: 'ph-router',
  netswitch: 'ph-swap',
  ap: 'ph-wifi-high',
  console: 'ph-game-controller',
  camera: 'ph-video-camera',
  watch: 'ph-watch',
  nas: 'ph-hard-drives',
  server: 'ph-hard-drives',
  home: 'ph-house-line',
  doorbell: 'ph-bell-ringing',
  smoke: 'ph-fire',
  vacuum: 'ph-broom',
  washer: 'ph-washing-machine',
  dryer: 'ph-wind',
  airco: 'ph-thermometer',
  blinds: 'ph-blinds',
  light: 'ph-lightbulb',
  energy: 'ph-lightning',
  water: 'ph-drop',
  ereader: 'ph-book-open',
  avr: 'ph-speaker-simple-high',
  alarm: 'ph-alarm',
  remote: 'ph-remote',
  led: 'ph-palette',
  zigbee: 'ph-bluetooth',
  sensor: 'ph-thermometer',
  health: 'ph-heartbeat',
  iot: 'ph-robot',
  unknown: 'ph-question',
  device: 'ph-circuitry',
} as const;

const DEVICE_TYPES: { match: RegExp; icon: string; type: string }[] = [
  { match: /macbook/i, icon: ICON.laptop, type: 'MacBook' },
  { match: /imac/i, icon: ICON.desktop, type: 'iMac' },
  { match: /mac[\s-]?pro/i, icon: ICON.desktop, type: 'Mac Pro' },
  { match: /mac[\s-]?mini/i, icon: ICON.desktop, type: 'Mac mini' },
  { match: /mac[\s-]?studio/i, icon: ICON.desktop, type: 'Mac Studio' },
  { match: /iphone/i, icon: ICON.phone, type: 'iPhone' },
  { match: /ipad/i, icon: ICON.tablet, type: 'iPad' },
  { match: /apple[\s-]?tv/i, icon: ICON.tv, type: 'Apple TV' },
  { match: /homepod/i, icon: ICON.speaker, type: 'HomePod' },
  { match: /apple[\s-]?watch/i, icon: ICON.watch, type: 'Apple Watch' },
  { match: /pixel[\s-]?\d/i, icon: ICON.phone, type: 'Pixel' },
  { match: /galaxy|samsung/i, icon: ICON.phone, type: 'Samsung' },
  { match: /honor[\s-]?magic[\s-]?pad/i, icon: ICON.tablet, type: 'HONOR Tablet' },
  { match: /honor/i, icon: ICON.phone, type: 'HONOR' },
  { match: /huawei|hw\d{2}/i, icon: ICON.phone, type: 'Huawei' },
  { match: /google[\s-]?home[\s-]?mini/i, icon: ICON.speaker, type: 'Google Home Mini' },
  { match: /google[\s-]?home/i, icon: ICON.speaker, type: 'Google Home' },
  { match: /nest[\s-]?hello/i, icon: ICON.doorbell, type: 'Nest Doorbell' },
  { match: /nest[\s-]?protect/i, icon: ICON.smoke, type: 'Nest Protect' },
  { match: /nest[\s-]?hub/i, icon: ICON.tv, type: 'Nest Hub' },
  { match: /nest[\s-]?cam/i, icon: ICON.camera, type: 'Nest Cam' },
  { match: /fuchsia-/i, icon: ICON.tv, type: 'Nest Hub' },
  { match: /nest/i, icon: ICON.home, type: 'Nest' },
  { match: /chromecast/i, icon: ICON.tv, type: 'Chromecast' },
  { match: /lgwebostv/i, icon: ICON.tv, type: 'LG Smart TV' },
  { match: /bravia|sony[\s-]?tv/i, icon: ICON.tv, type: 'Sony TV' },
  { match: /samsung[\s-]?tv|tizen/i, icon: ICON.tv, type: 'Samsung TV' },
  { match: /roku/i, icon: ICON.tv, type: 'Roku' },
  { match: /fire[\s-]?stick/i, icon: ICON.tv, type: 'Fire TV Stick' },
  { match: /sonos|SonosZP/i, icon: ICON.speaker, type: 'Sonos Speaker' },
  { match: /denon[\s-]?avr/i, icon: ICON.avr, type: 'Denon AV Receiver' },
  { match: /marantz/i, icon: ICON.avr, type: 'Marantz AV Receiver' },
  { match: /hue[\s-]?sync[\s-]?box/i, icon: ICON.light, type: 'Hue Sync Box' },
  { match: /harmony[\s-]?hub/i, icon: ICON.remote, type: 'Harmony Hub' },
  { match: /airthings/i, icon: ICON.sensor, type: 'Air Quality Monitor' },
  { match: /dreame[\s_]?vacuum|roborock/i, icon: ICON.vacuum, type: 'Robot Vacuum' },
  { match: /roomba|irobot/i, icon: ICON.vacuum, type: 'Robot Vacuum' },
  { match: /bosch[\s-]?dryer/i, icon: ICON.dryer, type: 'Smart Dryer' },
  { match: /bosch[\s-]?wash/i, icon: ICON.washer, type: 'Smart Washer' },
  { match: /disp[\s-]?dish/i, icon: ICON.washer, type: 'Smart Dishwasher' },
  { match: /disp[\s-]?wash/i, icon: ICON.washer, type: 'Smart Washer' },
  { match: /SC07-WX|XS01-WX|XC0C-iR/i, icon: ICON.blinds, type: 'Somfy Blinds' },
  { match: /slide[\s_]/i, icon: ICON.blinds, type: 'Slide Curtains' },
  { match: /myenergi/i, icon: ICON.energy, type: 'Energy Monitor' },
  { match: /P1[\s-]?Eport|p1[\s-]?meter/i, icon: ICON.energy, type: 'P1 Energy Meter' },
  { match: /SmartGateways[\s-]?Watermeter/i, icon: ICON.water, type: 'Water Meter' },
  { match: /home[\s-]?assistant/i, icon: ICON.home, type: 'Home Assistant' },
  { match: /wled[\s-]/i, icon: ICON.led, type: 'WLED LED' },
  { match: /awtrix/i, icon: ICON.led, type: 'Awtrix Pixel Clock' },
  { match: /nspanel/i, icon: ICON.home, type: 'Sonoff NSPanel' },
  { match: /loftie/i, icon: ICON.alarm, type: 'Smart Alarm Clock' },
  { match: /withings/i, icon: ICON.health, type: 'Health Monitor' },
  { match: /presence[\s-]?sensor/i, icon: ICON.sensor, type: 'Presence Sensor' },
  { match: /camera[\s-]?hub/i, icon: ICON.camera, type: 'Camera Hub' },
  { match: /SLZB|zigbee[\s-]?coord/i, icon: ICON.zigbee, type: 'Zigbee Coordinator' },
  { match: /_ac$|[\s-]ac$/i, icon: ICON.airco, type: 'Smart Airco' },
  { match: /USW[\s-]/i, icon: ICON.netswitch, type: 'Ubiquiti Switch' },
  { match: /U7[\s-]|UAP[\s-]/i, icon: ICON.ap, type: 'Ubiquiti AP' },
  { match: /Switch\d+p|switch.*beneden|switch.*boven/i, icon: ICON.netswitch, type: 'Network Switch' },
  { match: /ubiquiti|unifi/i, icon: ICON.router, type: 'Ubiquiti' },
  { match: /frigate/i, icon: ICON.camera, type: 'Frigate NVR' },
  { match: /caddy|pihole|server/i, icon: ICON.server, type: 'Home Server' },
  { match: /raspberry[\s-]?pi/i, icon: ICON.server, type: 'Raspberry Pi' },
  { match: /surface/i, icon: ICON.laptop, type: 'Surface' },
  { match: /kobo/i, icon: ICON.ereader, type: 'E-reader' },
  { match: /BRN[A-F0-9]|brother/i, icon: ICON.printer, type: 'Printer' },
  { match: /printer|epson|hp[\s-]?print|canon/i, icon: ICON.printer, type: 'Printer' },
  { match: /ds[\s-]?2cd|hikvision/i, icon: ICON.camera, type: 'IP Camera' },
  { match: /camera|cam\b/i, icon: ICON.camera, type: 'IP Camera' },
  { match: /tv\b|television/i, icon: ICON.tv, type: 'TV/Media' },
  { match: /playstation|ps[45]/i, icon: ICON.console, type: 'PlayStation' },
  { match: /xbox/i, icon: ICON.console, type: 'Xbox' },
  { match: /nintendo/i, icon: ICON.console, type: 'Nintendo' },
  { match: /nas|synology|qnap/i, icon: ICON.nas, type: 'NAS' },
  { match: /router|gateway/i, icon: ICON.router, type: 'Router' },
  { match: /access[\s-]?point|ap\b/i, icon: ICON.ap, type: 'Access Point' },
  { match: /hue|signify|philips[\s-]?light/i, icon: ICON.light, type: 'Smart Lighting' },
  { match: /smart[\s-]?home|iot/i, icon: ICON.home, type: 'Smart Home' },
  { match: /thermostat/i, icon: ICON.airco, type: 'Thermostat' },
  { match: /ESP[\s_][A-F0-9]|espressif/i, icon: ICON.iot, type: 'IoT Device' },
  { match: /android/i, icon: ICON.phone, type: 'Android' },
  { match: /windows|desktop[\s-]?[a-z]/i, icon: ICON.desktop, type: 'PC' },
  { match: /laptop|notebook/i, icon: ICON.laptop, type: 'Laptop' },
];

export function detectDeviceType(device: Device | null): DeviceType {
  if (!device) return { icon: ICON.unknown, type: 'Unknown' };
  const haystack = [device.hostname, device.vendor, device.display_name].filter(Boolean).join(' ');
  for (const dt of DEVICE_TYPES) {
    if (dt.match.test(haystack)) return dt;
  }
  const dvc = (device.dhcp_vendor_class || '').toLowerCase();
  if (dvc.startsWith('android-dhcp')) return { icon: ICON.phone, type: 'Android' };
  if (dvc === 'ubnt') return { icon: ICON.router, type: 'Ubiquiti' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('marvell')) return { icon: ICON.speaker, type: 'Google Home' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('bcm2835')) return { icon: ICON.server, type: 'Raspberry Pi' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('freescale')) return { icon: ICON.ereader, type: 'E-reader' };
  if (dvc.startsWith('udhcp')) return { icon: ICON.iot, type: 'IoT Device' };
  if (device.device_class) {
    const dc = device.device_class.toLowerCase();
    if (dc === 'phone') return { icon: ICON.phone, type: 'Phone' };
    if (dc === 'tablet') return { icon: ICON.tablet, type: 'Tablet' };
    if (dc === 'laptop') return { icon: ICON.laptop, type: 'Laptop' };
    if (dc === 'computer') return { icon: ICON.desktop, type: 'Computer' };
    if (dc === 'server') return { icon: ICON.server, type: 'Server' };
    if (dc === 'iot') return { icon: ICON.iot, type: 'IoT Device' };
  }
  if (device.vendor) {
    const v = device.vendor.toLowerCase();
    if (v.includes('espressif')) return { icon: ICON.iot, type: 'IoT Device' };
    if (v.includes('hikvision')) return { icon: ICON.camera, type: 'IP Camera' };
    if (v.includes('nest')) return { icon: ICON.home, type: 'Nest' };
    if (v.includes('sonos')) return { icon: ICON.speaker, type: 'Sonos Speaker' };
    if (v.includes('signify') || v.includes('philips lighting')) return { icon: ICON.light, type: 'Smart Lighting' };
    if (v.includes('lumi')) return { icon: ICON.home, type: 'Aqara Smart Home' };
    if (v.includes('withings')) return { icon: ICON.health, type: 'Health Monitor' };
    if (v.includes('xiaomi')) return { icon: ICON.home, type: 'Xiaomi Smart Home' };
    if (v.includes('myenergi')) return { icon: ICON.energy, type: 'Energy Monitor' };
    if (v.includes('resideo') || v.includes('honeywell')) return { icon: ICON.airco, type: 'Thermostat' };
    if (v.includes('brother')) return { icon: ICON.printer, type: 'Printer' };
    if (v.includes('d&m') || v.includes('denon') || v.includes('marantz')) return { icon: ICON.avr, type: 'AV Receiver' };
    if (v.includes('logitech')) return { icon: ICON.remote, type: 'Logitech' };
    if (v.includes('kobo')) return { icon: ICON.ereader, type: 'E-reader' };
    if (v.includes('apple')) return { icon: ICON.laptop, type: 'Apple Device' };
    if (v.includes('samsung')) return { icon: ICON.phone, type: 'Samsung' };
    if (v.includes('google')) return { icon: ICON.home, type: 'Google Device' };
    if (v.includes('microsoft')) return { icon: ICON.laptop, type: 'Microsoft' };
    if (v.includes('ring')) return { icon: ICON.doorbell, type: 'Doorbell' };
    if (v.includes('ubiquiti')) return { icon: ICON.router, type: 'Ubiquiti' };
    if (v.includes('sercomm')) return { icon: ICON.router, type: 'Gateway' };
    if (v.includes('tp-link') || v.includes('tplink')) return { icon: ICON.router, type: 'Network' };
    if (v.includes('texas instruments') || v.includes('shanghai high')) return { icon: ICON.iot, type: 'IoT Device' };
    if (v.includes('raspberry')) return { icon: ICON.server, type: 'Raspberry Pi' };
    if (v.includes('intel') || v.includes('dell') || v.includes('lenovo') || v.includes('hp ') || v.includes('asrock') || v.includes('elitegroup'))
      return { icon: ICON.desktop, type: 'Computer' };
  }
  return { icon: ICON.device, type: 'Device' };
}

export function isDeviceOnline(device: Device | null): boolean {
  if (!device?.last_seen) return false;
  const ts = device.last_seen.endsWith('Z') ? device.last_seen : device.last_seen + 'Z';
  return (Date.now() - new Date(ts).getTime()) < 5 * 60 * 1000;
}

export function latestIp(device: Device): string {
  if (!device.ips || device.ips.length === 0) return device.mac_address;
  const ipv4 = device.ips.find(i => !i.ip.includes(':'));
  if (ipv4) return ipv4.ip;
  return device.ips[0].ip;
}

export function ipSummary(device: Device): { primary: string; extra: number } {
  if (!device.ips || device.ips.length === 0) return { primary: '', extra: 0 };
  return { primary: device.ips[0].ip, extra: device.ips.length - 1 };
}

// Junk hostname detection
const JUNK_LITERALS = new Set([
  '', '(empty)', '(null)', 'null', 'none', 'unknown',
  'localhost', 'localhost.localdomain',
  'espressif', 'esp32', 'esp8266', 'esp-device',
]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX_ID_RE = /^[0-9a-f]{16,}$/;

function isJunkHostname(name: string | undefined): boolean {
  if (!name) return true;
  const s = name.trim().toLowerCase();
  if (JUNK_LITERALS.has(s)) return true;
  if (s.endsWith('.in-addr.arpa') || s.endsWith('.ip6.arpa')) return true;
  if (UUID_RE.test(s)) return true;
  if (HEX_ID_RE.test(s)) return true;
  return false;
}

function shortVendor(vendor: string | undefined): string | null {
  if (!vendor) return null;
  return vendor
    .replace(/,?\s*(inc\.?|ltd\.?|corp\.?|corporation|limited|co\.?|llc|b\.v\.?|ag|gmbh)$/i, '')
    .trim();
}

function vendorFallbackName(device: Device): string | null {
  const macTail = (device.mac_address || '').split(':').slice(-2).join(':') || '??';
  if (device.ja4_label) return `${device.ja4_label} (${macTail})`;
  const vendor = shortVendor(device.vendor);
  if (vendor) return `${vendor} device`;
  const ip = latestIp(device);
  if (ip) return ip;
  return device.mac_address || `Device ${macTail}`;
}

// Friendly names stored in localStorage
const FRIENDLY_NAMES_KEY = 'airadar-friendly-names';

function loadFriendlyNames(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(FRIENDLY_NAMES_KEY) || '{}'); } catch { return {}; }
}

export function saveFriendlyName(mac: string, name: string | null): void {
  const names = loadFriendlyNames();
  if (name) { names[mac] = name; } else { delete names[mac]; }
  localStorage.setItem(FRIENDLY_NAMES_KEY, JSON.stringify(names));
}

export function getFriendlyName(mac: string): string | null {
  return loadFriendlyNames()[mac] || null;
}

export function bestDeviceName(mac: string, device: Device | null): string {
  const friendly = loadFriendlyNames()[mac];
  if (friendly) return friendly;
  if (device?.display_name) return device.display_name;
  if (device?.hostname && !isJunkHostname(device.hostname)) return device.hostname;
  if (device) {
    const fallback = vendorFallbackName(device);
    if (fallback) return fallback;
    return latestIp(device);
  }
  return typeof mac === 'string' ? mac.replace('_ip_', '') : '';
}

export function originalDeviceName(device: Device | null): string {
  if (!device) return '';
  return device.hostname || latestIp(device);
}

// Device type → filter group mapping
export const TYPE_TO_GROUP: Record<string, string> = {
  'MacBook': 'Computers', 'iMac': 'Computers', 'Mac Pro': 'Computers', 'Mac mini': 'Computers',
  'Mac Studio': 'Computers', 'PC': 'Computers', 'Surface': 'Computers', 'Laptop': 'Computers',
  'Computer': 'Computers', 'Microsoft': 'Computers', 'Apple Device': 'Computers',
  'Home Server': 'Computers', 'Raspberry Pi': 'Computers', 'Frigate NVR': 'Computers',
  'iPhone': 'Phones', 'iPad': 'Phones', 'Pixel': 'Phones', 'Samsung': 'Phones',
  'Android': 'Phones', 'Phone': 'Phones', 'Tablet': 'Phones', 'HONOR': 'Phones',
  'HONOR Tablet': 'Phones', 'Huawei': 'Phones', 'Google Device': 'Phones',
  'Air Quality Monitor': 'Smart Home', 'Robot Vacuum': 'Smart Home',
  'Smart Dryer': 'Smart Home', 'Smart Washer': 'Smart Home', 'Smart Dishwasher': 'Smart Home',
  'Smart Airco': 'Smart Home', 'Thermostat': 'Smart Home',
  'Smart Lighting': 'Smart Home', 'Hue Sync Box': 'Smart Home',
  'Somfy Blinds': 'Smart Home', 'Slide Curtains': 'Smart Home',
  'Energy Monitor': 'Smart Home', 'P1 Energy Meter': 'Smart Home', 'Water Meter': 'Smart Home',
  'Presence Sensor': 'Smart Home', 'Smart Alarm Clock': 'Smart Home',
  'IoT Device': 'Smart Home', 'Smart Home': 'Smart Home',
  'Sonoff NSPanel': 'Smart Home', 'WLED LED': 'Smart Home', 'Awtrix Pixel Clock': 'Smart Home',
  'Zigbee Coordinator': 'Smart Home', 'Home Assistant': 'Smart Home',
  'Health Monitor': 'Smart Home', 'Doorbell': 'Smart Home',
  'Sonos Speaker': 'Media', 'Speaker': 'Media', 'HomePod': 'Media',
  'Google Home': 'Media', 'Google Home Mini': 'Media',
  'Denon AV Receiver': 'Media', 'AV Receiver': 'Media', 'Harmony Hub': 'Media',
  'Apple TV': 'Media', 'Chromecast': 'Media', 'TV/Media': 'Media',
  'LG Smart TV': 'Media', 'E-reader': 'Media',
  'Nest': 'Nest', 'Nest Doorbell': 'Nest', 'Nest Protect': 'Nest',
  'Nest Hub': 'Nest', 'Nest Cam': 'Nest',
  'IP Camera': 'Cameras', 'Camera Hub': 'Cameras',
  'Router': 'Network', 'Ubiquiti': 'Network', 'Ubiquiti AP': 'Network',
  'Ubiquiti Switch': 'Network', 'Network Switch': 'Network',
  'Access Point': 'Network', 'Printer': 'Network',
  'PlayStation': 'Gaming', 'Xbox': 'Gaming', 'Nintendo': 'Gaming',
};
