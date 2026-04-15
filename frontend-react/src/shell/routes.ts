// Route definitions — single source of truth for navigation
export interface RouteConfig {
  path: string;       // hash path (e.g. 'summary')
  pageId: string;     // internal page id (matches page-{id} in HTML)
  icon: string;       // Phosphor icon class
  labelKey: string;   // i18n key for nav label
  label: string;      // fallback English label
  group: 'monitor' | 'protect' | 'manage';
  type: 'react' | 'vanilla';
  // Badge config (optional)
  badgeId?: string;
}

export const ROUTES: RouteConfig[] = [
  // Monitor
  { path: 'summary',   pageId: 'summary',   icon: 'ph-tray',                   labelKey: 'nav.summary',   label: 'Summary',       group: 'monitor', type: 'vanilla' },
  { path: 'dashboard', pageId: 'dashboard', icon: 'ph-squares-four',           labelKey: 'nav.dashboard', label: 'Dashboard',     group: 'monitor', type: 'react' },
  { path: 'ai',        pageId: 'ai',        icon: 'ph-brain',                  labelKey: 'nav.ai',        label: 'AI Radar',      group: 'monitor', type: 'react' },
  { path: 'cloud',     pageId: 'cloud',     icon: 'ph-cloud',                  labelKey: 'nav.cloud',     label: 'Cloud Storage', group: 'monitor', type: 'react' },
  { path: 'privacy',   pageId: 'privacy',   icon: 'ph-shield-check',           labelKey: 'nav.privacy',   label: 'Privacy',       group: 'monitor', type: 'react' },
  { path: 'iot',       pageId: 'iot',       icon: 'ph-cpu',                    labelKey: 'nav.iot',        label: 'IoT Overview',  group: 'monitor', type: 'react' },
  { path: 'content',   pageId: 'family',    icon: 'ph-squares-four',           labelKey: 'nav.family',    label: 'Content',       group: 'monitor', type: 'react' },
  { path: 'geo',       pageId: 'geo',       icon: 'ph-globe-hemisphere-west',  labelKey: 'nav.geo',       label: 'Geo Traffic',   group: 'monitor', type: 'react' },
  // Protect
  { path: 'ips',       pageId: 'ips',       icon: 'ph-warning-octagon',        labelKey: 'nav.attacks',   label: 'Attacks',       group: 'protect', type: 'vanilla', badgeId: 'ips' },
  { path: 'rules',     pageId: 'rules',     icon: 'ph-faders',                 labelKey: 'nav.rules',     label: 'Rules',         group: 'protect', type: 'vanilla' },
  // Manage
  { path: 'devices',   pageId: 'devices',   icon: 'ph-devices',                labelKey: 'nav.devices',   label: 'Devices',       group: 'manage',  type: 'react' },
  { path: 'settings',  pageId: 'settings',  icon: 'ph-gear',                   labelKey: 'nav.settings',  label: 'Settings',      group: 'manage',  type: 'vanilla', badgeId: 'settings' },
];

export const MOBILE_NAV: { path: string; icon: string; labelKey: string; label: string; badgeId?: string }[] = [
  { path: 'summary',  icon: 'ph-tray',             labelKey: 'mob.home',     label: 'Home' },
  { path: 'devices',  icon: 'ph-devices',           labelKey: 'mob.devices',  label: 'Devices' },
  { path: 'ips',      icon: 'ph-warning-octagon',   labelKey: 'mob.attacks',  label: 'Attacks', badgeId: 'ips' },
  { path: 'settings', icon: 'ph-gear',              labelKey: 'mob.settings', label: 'Settings', badgeId: 'settings' },
];

export const GROUP_LABELS: Record<string, { key: string; label: string }> = {
  monitor: { key: 'nav.groupMonitor', label: 'Monitor' },
  protect: { key: 'nav.groupProtect', label: 'Protect' },
  manage:  { key: 'nav.groupManage',  label: 'Manage' },
};
