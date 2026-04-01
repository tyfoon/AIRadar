/* ================================================================
   AI-Radar — Dashboard Application (app.js)
   Single-file JS for the premium UniFi-style frontend.
   ================================================================ */

'use strict';

// ================================================================
// THEME
// ================================================================
function isDark() { return document.documentElement.classList.contains('dark'); }

function toggleTheme() {
  document.documentElement.classList.toggle('dark');
  localStorage.setItem('airadar-theme', isDark() ? 'dark' : 'light');
  updateChartsTheme();
}

function initTheme() {
  const saved = localStorage.getItem('airadar-theme');
  if (saved === 'light') document.documentElement.classList.remove('dark');
  else document.documentElement.classList.add('dark');
}

// ================================================================
// CHART THEME COLORS
// ================================================================
const TC = {
  get grid()    { return isDark() ? 'rgba(255,255,255,0.04)' : '#e2e8f0'; },
  get tick()    { return isDark() ? '#475569' : '#94a3b8'; },
  get legend()  { return isDark() ? '#64748b' : '#475569'; },
};

// ================================================================
// SIDEBAR
// ================================================================
let sidebarCollapsed = false;

function toggleSidebar() {
  sidebarCollapsed = !sidebarCollapsed;
  const sb = document.getElementById('sidebar');
  const main = document.getElementById('main');
  const icon = document.getElementById('collapse-icon');
  if (sidebarCollapsed) {
    sb.classList.add('collapsed');
    sb.style.width = '64px';
    main.style.marginLeft = '64px';
    icon.style.transform = 'rotate(180deg)';
  } else {
    sb.classList.remove('collapsed');
    sb.style.width = '240px';
    main.style.marginLeft = '240px';
    icon.style.transform = '';
  }
  localStorage.setItem('airadar-sidebar', sidebarCollapsed ? 'collapsed' : 'expanded');
}

function initSidebar() {
  if (localStorage.getItem('airadar-sidebar') === 'collapsed') toggleSidebar();
}

function toggleMobileSidebar() {
  // For mobile, we could show the sidebar as an overlay — for now, just navigate
}

// ================================================================
// NAVIGATION / ROUTING
// ================================================================
const VALID_PAGES = ['dashboard','ai','cloud','privacy','devices','ips','rules','settings'];

let currentPage = 'dashboard';

function navigate(page) {
  if (!VALID_PAGES.includes(page)) page = 'dashboard';
  currentPage = page;

  // Update page visibility
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const el = document.getElementById('page-' + page);
  if (el) el.classList.add('active');

  // Update page title
  const titleEl = document.getElementById('page-title');
  if (titleEl) titleEl.textContent = t('page.' + page);

  // Highlight sidebar
  document.querySelectorAll('.nav-item').forEach(a => {
    const isActive = a.dataset.page === page;
    a.classList.toggle('bg-indigo-50', isActive && !isDark());
    a.classList.toggle('dark:bg-indigo-950/40', isActive);
    a.classList.toggle('text-indigo-600', isActive && !isDark());
    a.classList.toggle('dark:text-indigo-400', isActive);
    a.classList.toggle('text-slate-500', !isActive && !isDark());
    a.classList.toggle('dark:text-slate-400', !isActive);
  });

  // Highlight mobile nav
  document.querySelectorAll('.mob-nav').forEach(a => {
    const isActive = a.dataset.page === page;
    a.classList.toggle('text-indigo-600', isActive && !isDark());
    a.classList.toggle('dark:text-indigo-400', isActive);
    a.classList.toggle('text-slate-400', !isActive && !isDark());
    a.classList.toggle('dark:text-slate-500', !isActive);
  });

  // Load data for this page
  refreshPage(page);
}

function initRouter() {
  window.addEventListener('hashchange', () => {
    const page = location.hash.replace('#/', '') || 'dashboard';
    navigate(page);
  });
  const initial = location.hash.replace('#/', '') || 'dashboard';
  navigate(initial);
}

// ================================================================
// SERVICE & COLOR CONSTANTS
// ================================================================
const ACCENT_COLORS = ['#6366f1','#22d3ee','#f59e0b','#ef4444','#10b981','#ec4899','#8b5cf6','#f97316','#14b8a6','#e11d48'];

const SERVICE_COLORS = {
  google_gemini:'#f59e0b', openai:'#10b981', anthropic_claude:'#6366f1',
  microsoft_copilot:'#3b82f6', perplexity:'#22d3ee', huggingface:'#f97316',
  mistral:'#8b5cf6', dropbox:'#3b82f6', wetransfer:'#14b8a6',
  google_drive:'#22c55e', onedrive:'#0ea5e9', icloud:'#6b7280',
  box:'#60a5fa', mega:'#ef4444',
  // VPN
  vpn_active:'#f97316', vpn_nordvpn:'#4687ff', vpn_expressvpn:'#da3940',
  vpn_surfshark:'#1cbdb4', vpn_protonvpn:'#6d4aff', vpn_pia:'#4bb543',
  vpn_cyberghost:'#ffd400', vpn_mullvad:'#294d73', vpn_ipvanish:'#70bb44',
  vpn_tunnelbear:'#ffc600', vpn_windscribe:'#1a5276', vpn_cloudflare_warp:'#f48120',
};

const SERVICE_NAMES = {
  // AI
  openai:'OpenAI', anthropic_claude:'Claude', google_gemini:'Gemini',
  microsoft_copilot:'Copilot', perplexity:'Perplexity', huggingface:'Hugging Face',
  mistral:'Mistral',
  // Cloud
  dropbox:'Dropbox', wetransfer:'WeTransfer', google_drive:'Google Drive',
  onedrive:'OneDrive', icloud:'iCloud', box:'Box', mega:'MEGA',
  // Trackers
  google_ads:'Google Ads', google_analytics:'Google Analytics',
  google_telemetry:'Google Telemetry', meta_tracking:'Meta Tracking',
  apple_ads:'Apple Ads', microsoft_ads:'Microsoft Ads',
  hotjar:'Hotjar', datadog:'Datadog',
  // VPN services
  vpn_active:'VPN Tunnel', vpn_nordvpn:'NordVPN', vpn_expressvpn:'ExpressVPN',
  vpn_surfshark:'Surfshark', vpn_protonvpn:'ProtonVPN', vpn_pia:'Private Internet Access',
  vpn_cyberghost:'CyberGhost', vpn_mullvad:'Mullvad', vpn_ipvanish:'IPVanish',
  vpn_tunnelbear:'TunnelBear', vpn_windscribe:'Windscribe', vpn_cloudflare_warp:'Cloudflare WARP',
  // Social / Gaming (for Rules page)
  facebook:'Facebook', instagram:'Instagram', tiktok:'TikTok',
  twitter:'X (Twitter)', snapchat:'Snapchat', pinterest:'Pinterest',
  linkedin:'LinkedIn', reddit:'Reddit', tumblr:'Tumblr',
  steam:'Steam', epic_games:'Epic Games', roblox:'Roblox',
  twitch:'Twitch', discord:'Discord', nintendo:'Nintendo',
  playstation:'PlayStation', xbox_live:'Xbox Live',
};

// Domain mapping for Clearbit logos
const SERVICE_LOGO_DOMAIN = {
  // AI services
  openai:'openai.com', anthropic_claude:'anthropic.com', google_gemini:'google.com',
  microsoft_copilot:'microsoft.com', perplexity:'perplexity.ai', huggingface:'huggingface.co',
  mistral:'mistral.ai',
  // Cloud services
  dropbox:'dropbox.com', wetransfer:'wetransfer.com', google_drive:'google.com',
  onedrive:'microsoft.com', icloud:'apple.com', box:'box.com', mega:'mega.nz',
  // Trackers
  google_ads:'google.com', google_analytics:'google.com', google_telemetry:'google.com',
  meta_tracking:'meta.com', apple_ads:'apple.com', microsoft_ads:'microsoft.com',
  hotjar:'hotjar.com', datadog:'datadoghq.com', facebook:'facebook.com',
  instagram:'instagram.com', tiktok:'tiktok.com', twitter:'x.com',
  snapchat:'snapchat.com', pinterest:'pinterest.com', linkedin:'linkedin.com',
  reddit:'reddit.com', tumblr:'tumblr.com', steam:'steampowered.com',
  epic_games:'epicgames.com', roblox:'roblox.com', twitch:'twitch.tv',
  discord:'discord.com', nintendo:'nintendo.com', playstation:'playstation.com',
  xbox_live:'xbox.com', signal:'signal.org', whatsapp:'whatsapp.com',
  // VPN services
  vpn_active:'nordvpn.com', vpn_nordvpn:'nordvpn.com', vpn_expressvpn:'expressvpn.com',
  vpn_surfshark:'surfshark.com', vpn_protonvpn:'protonvpn.com', vpn_pia:'privateinternetaccess.com',
  vpn_cyberghost:'cyberghostvpn.com', vpn_mullvad:'mullvad.net', vpn_ipvanish:'ipvanish.com',
  vpn_tunnelbear:'tunnelbear.com', vpn_windscribe:'windscribe.com', vpn_cloudflare_warp:'cloudflare.com',
};

const SVC_BADGE_CLS = {
  // AI
  openai:'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300',
  anthropic_claude:'bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700 dark:text-indigo-300',
  google_gemini:'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-300',
  microsoft_copilot:'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300',
  perplexity:'bg-cyan-100 dark:bg-cyan-900/40 text-cyan-700 dark:text-cyan-300',
  huggingface:'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300',
  mistral:'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300',
  // Cloud
  dropbox:'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300',
  wetransfer:'bg-teal-100 dark:bg-teal-900/40 text-teal-700 dark:text-teal-300',
  google_drive:'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300',
  onedrive:'bg-sky-100 dark:bg-sky-900/40 text-sky-700 dark:text-sky-300',
  icloud:'bg-slate-100 dark:bg-slate-700/40 text-slate-600 dark:text-slate-300',
  box:'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300',
  mega:'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300',
  // VPN
  vpn_active:'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300',
  vpn_nordvpn:'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300',
  vpn_expressvpn:'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300',
  vpn_surfshark:'bg-teal-100 dark:bg-teal-900/40 text-teal-700 dark:text-teal-300',
  vpn_protonvpn:'bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300',
  vpn_pia:'bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300',
  vpn_cyberghost:'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-300',
  vpn_mullvad:'bg-slate-100 dark:bg-slate-700/40 text-slate-600 dark:text-slate-300',
  vpn_cloudflare_warp:'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300',
  // Trackers
  google_ads:'bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300',
  google_analytics:'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300',
  google_telemetry:'bg-yellow-100 dark:bg-yellow-900/40 text-yellow-700 dark:text-yellow-300',
  meta_tracking:'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300',
  apple_ads:'bg-slate-100 dark:bg-slate-700/40 text-slate-600 dark:text-slate-300',
  microsoft_ads:'bg-cyan-100 dark:bg-cyan-900/40 text-cyan-700 dark:text-cyan-300',
  hotjar:'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300',
  datadog:'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300',
};

let _fallbackIdx = 0;
function svcColor(s) {
  if (!SERVICE_COLORS[s]) SERVICE_COLORS[s] = ACCENT_COLORS[_fallbackIdx++ % ACCENT_COLORS.length];
  return SERVICE_COLORS[s];
}

function svcDisplayName(s) {
  return SERVICE_NAMES[s] || s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function svcLogo(s) {
  const domain = SERVICE_LOGO_DOMAIN[s] || s.replace(/_/g, '') + '.com';
  const color = svcColor(s);
  const letter = svcDisplayName(s).charAt(0);
  return `<img src="https://www.google.com/s2/favicons?domain=${domain}&sz=64" alt="${s}" class="svc-logo"
    onerror="this.outerHTML='<span class=\\'svc-logo-fallback\\' style=\\'background:${color}\\'>${letter}</span>'"/>`;
}

function svcLogoName(s) {
  return `<span class="inline-flex items-center gap-1.5">${svcLogo(s)} <span>${svcDisplayName(s)}</span></span>`;
}

function badge(s) {
  const cls = SVC_BADGE_CLS[s] || 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300';
  return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium ${cls}">${svcLogo(s)} ${svcDisplayName(s)}</span>`;
}

// ================================================================
// DEVICE MAP  (keyed by MAC, with IP→MAC lookup)
// ================================================================
let deviceMap = {};   // mac_address → device object
let ipToMac = {};     // ip → mac_address (reverse lookup)

function _deviceByIp(ip) {
  const mac = ipToMac[ip];
  return mac ? deviceMap[mac] : null;
}

function deviceName(ip) {
  const d = _deviceByIp(ip);
  if (!d) return ip;
  return d.display_name || d.hostname || _latestIp(d);
}

function deviceLabel(ip) {
  const d = _deviceByIp(ip);
  if (!d) return ip;
  const name = d.display_name || d.hostname || _latestIp(d);
  const vendor = d.vendor ? `<span class="text-[10px] text-slate-400 dark:text-slate-500 ml-1">(${d.vendor})</span>` : '';
  return name + vendor;
}

function _latestIp(device) {
  if (!device.ips || device.ips.length === 0) return device.mac_address;
  return device.ips[0].ip;  // sorted by last_seen desc from API
}

function _ipSummary(device) {
  if (!device.ips || device.ips.length === 0) return '';
  const latest = device.ips[0].ip;
  if (device.ips.length === 1) return latest;
  return `${latest} <span class="text-[10px] text-slate-400 dark:text-slate-500">(+${device.ips.length - 1} other${device.ips.length > 2 ? 's' : ''})</span>`;
}

// Device type detection from hostname + vendor
const DEVICE_TYPES = [
  { match: /macbook/i,            icon: '💻', type: 'MacBook' },
  { match: /imac/i,               icon: '🖥️', type: 'iMac' },
  { match: /mac[\s-]?pro/i,       icon: '🖥️', type: 'Mac Pro' },
  { match: /mac[\s-]?mini/i,      icon: '🖥️', type: 'Mac mini' },
  { match: /mac[\s-]?studio/i,    icon: '🖥️', type: 'Mac Studio' },
  { match: /iphone/i,             icon: '📱', type: 'iPhone' },
  { match: /ipad/i,               icon: '📱', type: 'iPad' },
  { match: /apple[\s-]?tv/i,      icon: '📺', type: 'Apple TV' },
  { match: /homepod/i,            icon: '🔊', type: 'HomePod' },
  { match: /apple[\s-]?watch/i,   icon: '⌚', type: 'Apple Watch' },
  { match: /galaxy|samsung/i,     icon: '📱', type: 'Samsung' },
  { match: /pixel/i,              icon: '📱', type: 'Pixel' },
  { match: /android/i,            icon: '📱', type: 'Android' },
  { match: /surface/i,            icon: '💻', type: 'Surface' },
  { match: /windows|desktop|pc/i, icon: '🖥️', type: 'PC' },
  { match: /laptop|notebook/i,    icon: '💻', type: 'Laptop' },
  { match: /ubiquiti|unifi|router|gateway/i, icon: '📡', type: 'Router' },
  { match: /switch/i,             icon: '🔌', type: 'Switch' },
  { match: /access[\s-]?point|ap\b/i, icon: '📶', type: 'Access Point' },
  { match: /printer|epson|hp[\s-]?print|canon/i, icon: '🖨️', type: 'Printer' },
  { match: /nest|thermostat|hue|smart[\s-]?home|iot/i, icon: '🏠', type: 'Smart Home' },
  { match: /sonos|speaker/i,      icon: '🔊', type: 'Speaker' },
  { match: /tv|television|chromecast|roku|fire[\s-]?stick/i, icon: '📺', type: 'TV/Media' },
  { match: /playstation|ps[45]/i, icon: '🎮', type: 'PlayStation' },
  { match: /xbox/i,               icon: '🎮', type: 'Xbox' },
  { match: /nintendo|switch/i,    icon: '🎮', type: 'Nintendo' },
  { match: /nas|synology|qnap/i,  icon: '💾', type: 'NAS' },
  { match: /server/i,             icon: '🖥️', type: 'Server' },
  { match: /camera|cam\b|hikvision|ds-2cd/i, icon: '📹', type: 'IP Camera' },
  { match: /espressif/i,          icon: '🔌', type: 'IoT Device' },
];

function _detectDeviceType(device) {
  if (!device) return { icon: '❓', type: 'Unknown' };
  const haystack = [device.hostname, device.vendor, device.display_name].filter(Boolean).join(' ');
  for (const dt of DEVICE_TYPES) {
    if (dt.match.test(haystack)) return dt;
  }
  // p0f device_class fallback
  if (device.device_class) {
    const dc = device.device_class.toLowerCase();
    if (dc === 'phone')    return { icon: '📱', type: 'Phone' };
    if (dc === 'tablet')   return { icon: '📱', type: 'Tablet' };
    if (dc === 'laptop')   return { icon: '💻', type: 'Laptop' };
    if (dc === 'computer') return { icon: '💻', type: 'Computer' };
    if (dc === 'server')   return { icon: '🖥️', type: 'Server' };
    if (dc === 'iot')      return { icon: '🔌', type: 'IoT Device' };
  }
  // Vendor-based fallback
  if (device.vendor) {
    const v = device.vendor.toLowerCase();
    if (v.includes('espressif'))  return { icon: '🔌', type: 'IoT Device' };
    if (v.includes('hikvision'))  return { icon: '📹', type: 'IP Camera' };
    if (v.includes('apple'))      return { icon: '🍎', type: 'Apple Device' };
    if (v.includes('samsung'))    return { icon: '📱', type: 'Samsung' };
    if (v.includes('google'))     return { icon: '📱', type: 'Google Device' };
    if (v.includes('microsoft'))  return { icon: '💻', type: 'Microsoft' };
    if (v.includes('sonos'))      return { icon: '🔊', type: 'Speaker' };
    if (v.includes('ring'))       return { icon: '🔔', type: 'Doorbell' };
    if (v.includes('tp-link') || v.includes('tplink'))  return { icon: '📡', type: 'Network' };
    if (v.includes('intel') || v.includes('dell') || v.includes('lenovo') || v.includes('hp '))
      return { icon: '💻', type: 'Computer' };
  }
  return { icon: '📟', type: 'Device' };
}

function deviceTypeTag(device) {
  const dt = _detectDeviceType(device);
  const vendorText = device?.vendor ? ` · ${device.vendor}` : '';

  // p0f OS fingerprint badge
  let osBadge = '';
  if (device?.os_name) {
    const osIcons = {
      'macOS': '🍎', 'iOS': '📱', 'iPadOS': '📱',
      'Windows': '🪟', 'Linux': '🐧', 'Android': '🤖',
      'FreeBSD': '😈', 'OpenBSD': '🐡',
    };
    const osIcon = osIcons[device.os_name] || '💻';
    const osLabel = device.os_version ? `${device.os_name} ${device.os_version}` : device.os_name;
    const distText = device.network_distance != null ? ` · ${device.network_distance} hop${device.network_distance !== 1 ? 's' : ''}` : '';
    osBadge = `<span class="ml-1 px-1.5 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 text-[9px] font-medium">${osIcon} ${osLabel}${distText}</span>`;
  }

  return `<span class="inline-flex items-center gap-1 text-[10px] text-slate-400 dark:text-slate-500">${dt.icon} ${dt.type}${vendorText}</span>${osBadge}`;
}

async function loadDevices() {
  try {
    const res = await fetch('/api/devices');
    if (!res.ok) return;
    const devices = await res.json();
    deviceMap = {};
    ipToMac = {};
    devices.forEach(d => {
      deviceMap[d.mac_address] = d;
      (d.ips || []).forEach(ipRec => { ipToMac[ipRec.ip] = d.mac_address; });
    });
    // Populate device filter dropdowns (AI + Cloud)
    // Filter value = comma-separated IPs so backend source_ip filter still works
    ['ai-filter-device', 'cloud-filter-device'].forEach(id => {
      const sel = document.getElementById(id);
      if (sel) {
        const cur = sel.value;
        sel.innerHTML = `<option value="">${t('ai.allDevices')}</option>`;
        devices.forEach(d => {
          const allIps = (d.ips || []).map(i => i.ip).join(',');
          const label = d.display_name || d.hostname || _latestIp(d);
          sel.innerHTML += `<option value="${allIps}">${label}</option>`;
        });
        sel.value = cur;
      }
    });
  } catch(e) { console.error('loadDevices:', e); }
}

// Device rename handler (now uses MAC address)
document.addEventListener('click', async (e) => {
  const el = e.target.closest('.device-name');
  if (!el) return;
  const mac = el.dataset.mac;
  if (!mac) return;
  const d = deviceMap[mac];
  const cur = d?.display_name || d?.hostname || mac;
  const n = prompt(t('dev.renameDevice'), cur);
  if (n && n !== cur) {
    await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({display_name: n}),
    });
    await loadDevices();
    refreshPage(currentPage);
  }
});

// ================================================================
// HELPERS
// ================================================================
function fmtTime(iso) {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

function fmtBucket(iso) {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}

function getFilterParams(cat) {
  const p = new URLSearchParams();
  p.set('category', cat);
  // All insight pages share the same filter pattern: service, device, period
  const prefix = (cat === 'ai') ? 'ai' : (cat === 'cloud') ? 'cloud' : (cat === 'tracking') ? 'priv' : null;
  if (prefix) {
    const svc = document.getElementById(prefix + '-filter-service')?.value;
    const dev = document.getElementById(prefix + '-filter-device')?.value;
    const per = document.getElementById(prefix + '-filter-period')?.value;
    if (svc) p.set('service', svc);
    if (dev) p.set('source_ip', dev);
    if (per) p.set('start', new Date(Date.now() - parseInt(per) * 60000).toISOString());
  }
  return p;
}

function getBucketSize(cat) {
  const prefix = (cat === 'cloud') ? 'cloud' : (cat === 'tracking') ? 'priv' : 'ai';
  const per = document.getElementById(prefix + '-filter-period')?.value;
  if (!per) return 'hour';
  const m = parseInt(per);
  if (m <= 60) return 'minute';
  if (m <= 1440) return 'hour';
  return 'day';
}

function exportCSV(cat) {
  const p = getFilterParams(cat);
  window.location.href = '/api/events/export?' + p.toString();
}

// ================================================================
// CHART MANAGEMENT
// ================================================================
const charts = {};

function getOrCreateChart(id, config) {
  if (charts[id]) return charts[id];
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  charts[id] = new Chart(canvas.getContext('2d'), config);
  return charts[id];
}

// Custom HTML legend using same badge() style as tables
function renderHtmlLegend(containerId, chart, serviceKeys) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const items = chart.data.labels.map((label, i) => {
    const key = serviceKeys ? serviceKeys[i] : null;
    if (key) return badge(key);
    // Fallback for non-service labels (e.g. domain names)
    const color = chart.data.datasets[0].backgroundColor[i] || ACCENT_COLORS[i % ACCENT_COLORS.length];
    return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"><span class="w-2 h-2 rounded-full flex-shrink-0" style="background:${color}"></span>${label}</span>`;
  });
  container.innerHTML = items.join(' ');
}

function renderTimelineHtmlLegend(containerId, chart, serviceKeys) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const items = chart.data.datasets.map((ds, i) => {
    if (ds._isUpload) return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300"><span class="w-2 h-2 rounded-full bg-red-500 flex-shrink-0"></span>${t('ai.uploadsLegend')}</span>`;
    const key = serviceKeys ? serviceKeys[i] : null;
    if (key) return badge(key);
    return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"><span class="w-3 h-3 rounded inline-block" style="background:${ds.backgroundColor}"></span>${ds.label}</span>`;
  });
  container.innerHTML = items.join(' ');
}

function makeDoughnutConfig() {
  return {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: ACCENT_COLORS, borderWidth: 0 }] },
    options: {
      cutout: '60%',
      plugins: {
        legend: { display: false },
      },
      responsive: true,
      maintainAspectRatio: true,
    }
  };
}

function makeTimelineConfig() {
  return {
    type: 'bar',
    data: { labels: [], datasets: [] },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
      },
      scales: {
        x: { stacked: true, ticks: { color: TC.tick, maxRotation: 45, font: { size: 10 } }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: TC.tick, precision: 0 }, grid: { color: TC.grid } },
        y2: { position: 'right', beginAtZero: true, display: false, ticks: { color: '#ef4444', precision: 0, font: { size: 10 } }, grid: { display: false } },
      }
    }
  };
}

function makeBarConfig() {
  return {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Blocked', data: [], backgroundColor: '#ef4444', borderRadius: 4 }] },
    options: {
      indexAxis: 'y', responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: TC.tick }, grid: { color: TC.grid } },
        y: { ticks: { color: TC.legend, font: { size: 11 } }, grid: { display: false } },
      }
    }
  };
}

function updateChartsTheme() {
  Object.values(charts).forEach(chart => {
    if (chart.options.plugins?.legend?.labels) chart.options.plugins.legend.labels.color = TC.legend;
    if (chart.options.scales?.x) {
      if (chart.options.scales.x.ticks) chart.options.scales.x.ticks.color = TC.tick;
      if (chart.options.scales.x.grid) chart.options.scales.x.grid.color = TC.grid;
    }
    if (chart.options.scales?.y) {
      if (chart.options.scales.y.ticks) chart.options.scales.y.ticks.color = TC.tick;
      if (chart.options.scales.y.grid) chart.options.scales.y.grid.color = TC.grid;
    }
    chart.update();
  });
}

// ================================================================
// RENDER HELPERS
// ================================================================
function renderEventsTable(events, tbodyId, emptyId) {
  const tbody = document.getElementById(tbodyId);
  const empty = document.getElementById(emptyId);
  if (!tbody) return;
  if (!events.length) {
    tbody.innerHTML = '';
    if (empty) empty.classList.remove('hidden');
    return;
  }
  if (empty) empty.classList.add('hidden');
  tbody.innerHTML = events.map(e => {
    const up = e.possible_upload;
    const rc = up
      ? 'border-b border-orange-200 dark:border-orange-700/30 bg-orange-50 dark:bg-orange-900/10'
      : 'border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20';
    const ub = up ? `<span class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-orange-100 dark:bg-orange-800/50 text-orange-600 dark:text-orange-300">${t('ai.upload')}</span>` : '';
    const dn = deviceName(e.source_ip);
    const dev = _deviceByIp(e.source_ip);
    const dt = _detectDeviceType(dev);
    const macAttr = dev ? `data-mac="${dev.mac_address}"` : '';
    const dc = `<span class="device-name cursor-pointer hover:text-indigo-500 transition-colors" ${macAttr} title="${e.source_ip}">${dt.icon} ${dn}</span>`;
    return `<tr class="${rc} transition-colors">
      <td class="py-2 pr-4 tabular-nums text-slate-400 dark:text-slate-500 text-xs">${fmtTime(e.timestamp)}</td>
      <td class="py-2 pr-4">${badge(e.ai_service)}</td>
      <td class="py-2 pr-4 font-mono text-xs text-slate-600 dark:text-slate-300">${e.detection_type}${ub}</td>
      <td class="py-2 pr-4 text-xs">${dc}</td>
      <td class="py-2 text-right tabular-nums text-xs">${formatNumber(e.bytes_transferred)}</td>
    </tr>`;
  }).join('');
}

function updateCategoryCharts(events, timeline, doughnutId, timelineId) {
  // Doughnut
  const dChart = getOrCreateChart(doughnutId, makeDoughnutConfig());
  if (dChart) {
    const counts = {};
    events.forEach(e => { counts[e.ai_service] = (counts[e.ai_service] || 0) + 1; });
    const dKeys = Object.keys(counts);
    dChart.data.labels = dKeys.map(s => svcDisplayName(s));
    dChart.data.datasets[0].data = Object.values(counts);
    dChart.data.datasets[0].backgroundColor = dKeys.map(s => svcColor(s));
    dChart.update();
    renderHtmlLegend(doughnutId + '-legend', dChart, dKeys);
  }

  // Timeline
  const tChart = getOrCreateChart(timelineId, makeTimelineConfig());
  if (tChart) {
    const labels = timeline.map(p => fmtBucket(p.bucket));
    const svcs = new Set();
    timeline.forEach(p => Object.keys(p.services).forEach(s => svcs.add(s)));
    const svcKeys = [...svcs].sort();
    const ds = svcKeys.map(s => ({
      label: svcDisplayName(s),
      data: timeline.map(p => p.services[s] || 0),
      backgroundColor: svcColor(s),
      borderRadius: 3, stack: 's', yAxisID: 'y',
    }));
    const ul = timeline.map(p => p.uploads || 0);
    if (ul.some(v => v > 0)) {
      ds.push({
        label: t('ai.uploadsLegend'), data: ul, type: 'line', borderColor: '#ef4444', backgroundColor: '#ef4444',
        pointBackgroundColor: '#ef4444', pointRadius: ul.map(v => v > 0 ? 5 : 0), pointStyle: 'circle',
        borderWidth: 0, showLine: false, yAxisID: 'y2', _isUpload: true,
      });
      tChart.options.scales.y2.display = true;
    } else {
      tChart.options.scales.y2.display = false;
    }
    tChart.data.labels = labels;
    tChart.data.datasets = ds;
    tChart.update();
    renderTimelineHtmlLegend(timelineId + '-legend', tChart, svcKeys);
  }
}

// ================================================================
// PAGE REFRESH LOGIC
// ================================================================
async function refreshPage(page) {
  try {
    if (page === 'dashboard') await refreshDashboard();
    else if (page === 'ai') await refreshAI();
    else if (page === 'cloud') await refreshCloud();
    else if (page === 'privacy') await refreshPrivacy();
    else if (page === 'devices') await refreshDevices();
    else if (page === 'ips') await refreshIps();
    else if (page === 'rules') await refreshRules();
    else if (page === 'settings') await loadKillswitchState();
  } catch(err) { console.error('Page refresh error:', err); }
}

// --- DASHBOARD HEALTH DETAIL ---
let _lastHealthData = null;

function toggleDashHealthDetail() {
  const panel = document.getElementById('dash-health-panel');
  if (!panel) return;
  const hidden = panel.classList.contains('hidden');
  if (hidden) {
    panel.classList.remove('hidden');
    renderDashHealthServices();
  } else {
    panel.classList.add('hidden');
  }
}

function renderDashHealthServices() {
  const container = document.getElementById('dash-health-services');
  if (!container || !_lastHealthData?.services) {
    if (container) container.innerHTML = `<p class="col-span-full text-center text-sm text-slate-400 py-4">${t('dash.noHealthData')}</p>`;
    return;
  }
  container.innerHTML = _lastHealthData.services.map(s => {
    const isOk = s.status === 'ok';
    const borderCls = isOk
      ? 'border-emerald-500/20 dark:border-emerald-500/15'
      : 'border-amber-500/30 dark:border-amber-500/20';
    const dotCls = isOk
      ? 'bg-emerald-500'
      : 'bg-amber-500 animate-pulse';
    const statusText = isOk
      ? `<span class="text-emerald-600 dark:text-emerald-400">${t('dash.ok')}</span>`
      : `<span class="text-amber-600 dark:text-amber-400">${t('dash.issue')}</span>`;
    const respTime = s.response_ms > 0
      ? `<span class="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">${s.response_ms.toFixed(0)}ms</span>`
      : '';
    return `<div class="bg-slate-50 dark:bg-white/[0.02] border ${borderCls} rounded-lg px-4 py-3">
      <div class="flex items-center justify-between mb-1">
        <div class="flex items-center gap-2">
          <span class="text-sm">${s.icon}</span>
          <span class="text-xs font-medium text-slate-700 dark:text-slate-200">${s.service}</span>
        </div>
        <div class="flex items-center gap-2">
          ${respTime}
          <span class="w-2 h-2 rounded-full ${dotCls}"></span>
        </div>
      </div>
      <p class="text-[10px] text-slate-400 dark:text-slate-500 leading-snug">${s.details || ''}</p>
      ${(!isOk && s.service === 'Zeek (Packet Capture)')
        ? `<button onclick="restartService('zeek', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-indigo-600 hover:bg-indigo-500 text-white transition-colors">${t('dash.restartZeek')}</button>` : ''}
      ${(!isOk && s.service === 'Zeek Tailer')
        ? `<button onclick="restartService('tailer', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-indigo-600 hover:bg-indigo-500 text-white transition-colors">${t('dash.restartTailer')}</button>` : ''}
      ${(!isOk && s.service.startsWith('Zeek ') && s.service.endsWith('.log'))
        ? `<button onclick="restartService('zeek', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-amber-600 hover:bg-amber-500 text-white transition-colors">${t('dash.restartZeek')}</button>` : ''}
    </div>`;
  }).join('');
}

// --- DASHBOARD ---
async function refreshDashboard() {
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const [aiEvt, cloudEvt, privRes, healthRes, sankeyAi, sankeyCloud, ksState] = await Promise.all([
    fetch('/api/events?category=ai&limit=200&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/events?category=cloud&limit=200&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/privacy/stats').then(r => r.json()).catch(() => null),
    fetch('/api/health').then(r => r.json()).catch(() => null),
    fetch('/api/events?category=ai&limit=500&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/events?category=cloud&limit=500&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/killswitch').then(r => r.json()).catch(() => ({ active: false })),
  ]);

  // Killswitch dashboard banner
  const ksBanner = document.getElementById('ks-dashboard-banner');
  if (ksBanner) {
    if (ksState.active) {
      ksBanner.classList.remove('hidden');
      const since = ksState.activated_at ? new Date(ksState.activated_at + 'Z').toLocaleTimeString() : '';
      const sinceEl = document.getElementById('ks-banner-since');
      if (sinceEl) sinceEl.textContent = since ? t('dash.since', { time: since }) : '';
    } else {
      ksBanner.classList.add('hidden');
    }
  }

  // Metrics
  document.getElementById('dash-devices').textContent = Object.keys(deviceMap).length || 0;
  document.getElementById('dash-events-today').textContent = formatNumber(aiEvt.length + cloudEvt.length);

  const ag = privRes?.adguard || {};
  document.getElementById('dash-blocked').textContent = formatNumber(ag.blocked_queries || 0);

  // Health status
  if (healthRes) {
    const ok = healthRes.summary?.all_ok;
    const dot = document.getElementById('dash-health-dot');
    const txt = document.getElementById('dash-health');
    const topDot = document.getElementById('status-dot');
    const topTxt = document.getElementById('status-text');
    if (ok) {
      dot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500';
      txt.textContent = t('dash.allOk');
      txt.className = 'text-lg font-semibold text-emerald-600 dark:text-emerald-400';
      topDot.className = 'w-2 h-2 rounded-full bg-emerald-500';
      topTxt.textContent = t('topbar.allOk');
    } else {
      const issues = healthRes.summary.total - healthRes.summary.ok;
      dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-500';
      txt.textContent = t('dash.issuesDetected', { n: issues, s: issues > 1 ? 's' : '' });
      txt.className = 'text-lg font-semibold text-amber-600 dark:text-amber-400';
      topDot.className = 'w-2 h-2 rounded-full bg-amber-500';
      topTxt.textContent = t('topbar.issues', { n: issues, s: issues > 1 ? 's' : '' });
    }
    // Store health data for detail panel
    _lastHealthData = healthRes;
    // Auto-update panel if already open
    const hp = document.getElementById('dash-health-panel');
    if (hp && !hp.classList.contains('hidden')) renderDashHealthServices();
  }

  // Mini donuts
  const aiDonut = getOrCreateChart('dash-ai-donut', makeDoughnutConfig());
  if (aiDonut) {
    const ac = {}; aiEvt.forEach(e => { ac[e.ai_service] = (ac[e.ai_service] || 0) + 1; });
    const aiKeys = Object.keys(ac);
    aiDonut.data.labels = aiKeys.map(k => svcDisplayName(k));
    aiDonut.data.datasets[0].data = Object.values(ac);
    aiDonut.data.datasets[0].backgroundColor = aiKeys.map(k => svcColor(k));
    aiDonut.update();
    renderHtmlLegend('dash-ai-donut-legend', aiDonut, aiKeys);
  }

  const cloudDonut = getOrCreateChart('dash-cloud-donut', makeDoughnutConfig());
  if (cloudDonut) {
    const cc = {}; cloudEvt.forEach(e => { cc[e.ai_service] = (cc[e.ai_service] || 0) + 1; });
    const cloudKeys = Object.keys(cc);
    cloudDonut.data.labels = cloudKeys.map(k => svcDisplayName(k));
    cloudDonut.data.datasets[0].data = Object.values(cc);
    cloudDonut.data.datasets[0].backgroundColor = cloudKeys.map(k => svcColor(k));
    cloudDonut.update();
    renderHtmlLegend('dash-cloud-donut-legend', cloudDonut, cloudKeys);
  }

  const privDonut = getOrCreateChart('dash-priv-donut', makeDoughnutConfig());
  if (privDonut && ag.top_blocked?.length) {
    const top5 = ag.top_blocked.slice(0, 5);
    privDonut.data.labels = top5.map(d => d.domain?.length > 20 ? d.domain.slice(0, 18) + '...' : d.domain);
    privDonut.data.datasets[0].data = top5.map(d => d.count);
    privDonut.update();
    renderHtmlLegend('dash-priv-donut-legend', privDonut, null);
  }

  // Alarms
  const allEvt = [...aiEvt, ...cloudEvt].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const alarms = allEvt.filter(e => e.possible_upload || e.bytes_transferred > 100000).slice(0, 15);

  const alarmsBody = document.getElementById('dash-alarms-body');
  if (alarmsBody) {
    if (alarms.length === 0) {
      alarmsBody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">${t('dash.noAlarms')}</td></tr>`;
    } else {
      alarmsBody.innerHTML = alarms.map(e => {
        const isUpload = e.possible_upload;
        const severity = isUpload
          ? '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">HIGH</span>'
          : '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">MED</span>';
        const desc = isUpload
          ? t('dash.uploadDetected', { kb: (e.bytes_transferred / 1024).toFixed(0) })
          : t('dash.highVolume', { kb: (e.bytes_transferred / 1024).toFixed(0) });
        return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors">
          <td class="py-2.5 pr-4 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(e.timestamp)}</td>
          <td class="py-2.5 pr-4">${severity}</td>
          <td class="py-2.5 pr-4 text-xs text-slate-600 dark:text-slate-300">${desc}</td>
          <td class="py-2.5 pr-4">${badge(e.ai_service)}</td>
          <td class="py-2.5 text-xs">${_detectDeviceType(_deviceByIp(e.source_ip)).icon} ${deviceName(e.source_ip)}</td>
        </tr>`;
      }).join('');
    }
  }

  // Sankey Data Flow Diagram
  renderSankey([...sankeyAi, ...sankeyCloud]);
}

// --- SANKEY DIAGRAM ---
let sankeyInstance = null;

function renderSankey(events) {
  const container = document.getElementById('sankey-chart');
  const emptyMsg = document.getElementById('sankey-empty');
  if (!container) return;

  if (!events.length) {
    container.style.display = 'none';
    if (emptyMsg) emptyMsg.classList.remove('hidden');
    return;
  }
  container.style.display = '';
  if (emptyMsg) emptyMsg.classList.add('hidden');

  // Build flows: device → AI-Radar → service, weighted by bytes_transferred
  const deviceFlows = {};  // device → total bytes
  const serviceFlows = {}; // service → total bytes

  events.forEach(e => {
    const dev = deviceName(e.source_ip);
    const svc = svcDisplayName(e.ai_service);
    deviceFlows[dev] = (deviceFlows[dev] || 0) + (e.bytes_transferred || 1);
    serviceFlows[svc] = (serviceFlows[svc] || 0) + (e.bytes_transferred || 1);
  });

  // Build per-link flows: device → service
  const linkMap = {};
  events.forEach(e => {
    const dev = deviceName(e.source_ip);
    const svc = svcDisplayName(e.ai_service);
    const key = dev + '→' + svc;
    linkMap[key] = (linkMap[key] || 0) + (e.bytes_transferred || 1);
  });

  // Nodes
  const nodes = [];
  const nodeSet = new Set();
  Object.keys(deviceFlows).forEach(d => { if (!nodeSet.has(d)) { nodeSet.add(d); nodes.push({ name: d }); } });
  nodes.push({ name: 'AI-Radar' });
  Object.keys(serviceFlows).forEach(s => { if (!nodeSet.has(s)) { nodeSet.add(s); nodes.push({ name: s }); } });

  // Links: device → AI-Radar, AI-Radar → service
  const links = [];
  Object.entries(deviceFlows).forEach(([dev, bytes]) => {
    links.push({ source: dev, target: 'AI-Radar', value: bytes });
  });
  Object.entries(serviceFlows).forEach(([svc, bytes]) => {
    links.push({ source: 'AI-Radar', target: svc, value: bytes });
  });

  const dark = isDark();
  const textColor = dark ? '#94a3b8' : '#475569';

  if (sankeyInstance) sankeyInstance.dispose();
  sankeyInstance = echarts.init(container, null, { renderer: 'canvas' });

  const option = {
    tooltip: {
      trigger: 'item',
      triggerOn: 'mousemove',
      backgroundColor: dark ? '#1e293b' : '#fff',
      borderColor: dark ? 'rgba(255,255,255,0.08)' : '#e2e8f0',
      textStyle: { color: dark ? '#e2e8f0' : '#1e293b', fontSize: 12, fontFamily: 'Inter' },
      formatter: (params) => {
        if (params.dataType === 'edge') {
          const kb = (params.value / 1024).toFixed(1);
          return `${params.data.source} → ${params.data.target}<br/><b>${kb} KB</b>`;
        }
        return params.name;
      }
    },
    series: [{
      type: 'sankey',
      layout: 'none',
      emphasis: { focus: 'adjacency' },
      nodeAlign: 'justify',
      layoutIterations: 32,
      nodeGap: 12,
      nodeWidth: 20,
      data: nodes.map(n => ({
        name: n.name,
        itemStyle: {
          color: n.name === 'AI-Radar' ? '#6366f1'
            : serviceFlows[n.name] ? (SERVICE_COLORS[Object.keys(SERVICE_NAMES).find(k => SERVICE_NAMES[k] === n.name)] || '#6366f1')
            : '#3b82f6',
          borderColor: 'transparent',
        },
        label: {
          color: textColor,
          fontSize: 11,
          fontFamily: 'Inter',
        }
      })),
      links: links,
      lineStyle: {
        color: 'gradient',
        curveness: 0.5,
        opacity: dark ? 0.25 : 0.35,
      },
      label: {
        position: 'right',
        color: textColor,
        fontSize: 11,
        fontFamily: 'Inter',
      },
      left: 40, right: 120, top: 10, bottom: 10,
    }]
  };

  sankeyInstance.setOption(option);

  // Resize observer
  const resizeObserver = new ResizeObserver(() => { sankeyInstance?.resize(); });
  resizeObserver.observe(container);
}

// --- AI RADAR ---
async function refreshAI() {
  const p = getFilterParams('ai');
  const [events, timeline] = await Promise.all([
    fetch('/api/events?' + p).then(r => r.json()),
    fetch('/api/timeline?bucket_size=' + getBucketSize('ai') + '&' + p).then(r => r.json()),
  ]);

  document.getElementById('ai-stat-total').textContent = events.length;
  document.getElementById('ai-stat-services').textContent = new Set(events.map(e => e.ai_service)).size;
  document.getElementById('ai-stat-sources').textContent = Object.keys(deviceMap).length || new Set(events.map(e => e.source_ip)).size || 0;
  document.getElementById('ai-stat-uploads').textContent = events.filter(e => e.possible_upload).length;

  // Populate service filter
  const svcSel = document.getElementById('ai-filter-service');
  if (svcSel) {
    const cur = svcSel.value;
    const allSvcs = [...new Set(events.map(e => e.ai_service))].sort();
    svcSel.innerHTML = `<option value="">${t('ai.allServices')}</option>`;
    allSvcs.forEach(s => { svcSel.innerHTML += `<option value="${s}">${svcDisplayName(s)}</option>`; });
    svcSel.value = cur;
  }

  renderEventsTable(events, 'ai-tbody', 'ai-empty');
  updateCategoryCharts(events, timeline, 'ai-service-chart', 'ai-timeline-chart');
  _lastAiEvents = events;
  renderAiAdoption(events);
}

let _lastAiEvents = [];
let _currentAiTab = 'radar';

function switchAiTab(tab) {
  _currentAiTab = tab;
  const radarDiv = document.getElementById('ai-tab-radar');
  const adoptDiv = document.getElementById('ai-tab-adoption');
  const btnRadar = document.getElementById('ai-tab-btn-radar');
  const btnAdopt = document.getElementById('ai-tab-btn-adoption');

  const activeClass = 'bg-white dark:bg-white/[0.08] text-slate-800 dark:text-white shadow-sm';
  const inactiveClass = 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300';

  if (tab === 'radar') {
    radarDiv.classList.remove('hidden');
    adoptDiv.classList.add('hidden');
    btnRadar.className = `ai-tab-btn px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${activeClass}`;
    btnAdopt.className = `ai-tab-btn px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${inactiveClass}`;
  } else {
    radarDiv.classList.add('hidden');
    adoptDiv.classList.remove('hidden');
    btnRadar.className = `ai-tab-btn px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${inactiveClass}`;
    btnAdopt.className = `ai-tab-btn px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${activeClass}`;
    // Re-render adoption with latest data
    renderAiAdoption(_lastAiEvents);
  }
}

function renderAiAdoption(events) {
  const totalDevices = Object.keys(deviceMap).length || 1;

  // Group events by MAC (physical device)
  const deviceEvents = {};  // mac → [events]
  events.forEach(e => {
    const mac = ipToMac[e.source_ip] || `_ip_${e.source_ip}`;
    if (!deviceEvents[mac]) deviceEvents[mac] = [];
    deviceEvents[mac].push(e);
  });

  const aiDeviceCount = Object.keys(deviceEvents).length;

  // Adoption rate
  const adoptionPct = totalDevices > 0 ? Math.round((aiDeviceCount / totalDevices) * 100) : 0;
  document.getElementById('ai-adopt-rate').textContent = adoptionPct + '%';
  document.getElementById('ai-adopt-rate-detail').textContent = t('adopt.rateDetail', { ai: aiDeviceCount, total: totalDevices });
  document.getElementById('ai-adopt-bar').style.width = adoptionPct + '%';
  document.getElementById('ai-adopt-bar-label').textContent = adoptionPct + '%';

  // Determine time span in days from event data
  let spanDays = 1;
  if (events.length > 1) {
    const times = events.map(e => new Date(e.timestamp).getTime());
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    spanDays = Math.max(1, (maxT - minT) / (1000 * 60 * 60 * 24));
  }

  // Avg queries per device per day
  const avgPerDevDay = aiDeviceCount > 0 ? (events.length / aiDeviceCount / spanDays) : 0;
  document.getElementById('ai-adopt-avg-queries').textContent = avgPerDevDay < 10 ? avgPerDevDay.toFixed(1) : Math.round(avgPerDevDay);

  // Active today
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const todayMacs = new Set();
  events.forEach(e => {
    if (new Date(e.timestamp) >= todayStart) {
      todayMacs.add(ipToMac[e.source_ip] || `_ip_${e.source_ip}`);
    }
  });
  document.getElementById('ai-adopt-active-today').textContent = todayMacs.size;

  // Avg services per user
  const svcPerDevice = Object.values(deviceEvents).map(evts => new Set(evts.map(e => e.ai_service)).size);
  const avgSvc = svcPerDevice.length > 0 ? (svcPerDevice.reduce((a,b) => a+b, 0) / svcPerDevice.length) : 0;
  document.getElementById('ai-adopt-svc-per-user').textContent = avgSvc.toFixed(1);

  // Power users (>50 queries per day)
  const powerThreshold = 50;
  let powerCount = 0;
  Object.values(deviceEvents).forEach(evts => {
    if ((evts.length / spanDays) > powerThreshold) powerCount++;
  });
  document.getElementById('ai-adopt-power').textContent = powerCount;

  // Top service
  const svcCounts = {};
  events.forEach(e => { svcCounts[e.ai_service] = (svcCounts[e.ai_service] || 0) + 1; });
  const topSvc = Object.entries(svcCounts).sort((a,b) => b[1] - a[1])[0];
  const topEl = document.getElementById('ai-adopt-top-svc');
  if (topSvc) {
    topEl.innerHTML = svcLogoName(topSvc[0]);
  } else {
    topEl.textContent = '—';
  }

  // Per-device breakdown bars
  const container = document.getElementById('ai-adopt-devices');
  if (!container) return;

  const deviceRows = Object.entries(deviceEvents).map(([mac, evts]) => {
    const dev = deviceMap[mac];
    const name = dev ? (dev.display_name || dev.hostname || _latestIp(dev)) : mac.replace('_ip_', '');
    const dt = _detectDeviceType(dev);
    const count = evts.length;
    const svcs = [...new Set(evts.map(e => e.ai_service))];
    const uploads = evts.filter(e => e.possible_upload).length;
    return { mac, name, dt, count, svcs, uploads };
  }).sort((a,b) => b.count - a.count);

  const maxCount = deviceRows[0]?.count || 1;

  container.innerHTML = deviceRows.map(d => {
    const pct = Math.round((d.count / maxCount) * 100);
    const svcLogos = d.svcs.slice(0, 5).map(s => svcLogo(s)).join('');
    const uploadBadge = d.uploads > 0 ? ` <span class="text-[9px] px-1 py-0.5 rounded bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">${d.uploads}▲</span>` : '';
    return `<div class="flex items-center gap-2 text-[11px]">
      <span class="w-[140px] truncate flex-shrink-0 text-slate-600 dark:text-slate-300" title="${d.name}">${d.dt.icon} ${d.name}</span>
      <div class="flex-1 h-4 rounded bg-slate-100 dark:bg-slate-800 overflow-hidden relative">
        <div class="h-full rounded bg-gradient-to-r from-indigo-500/80 to-purple-500/80 transition-all duration-500" style="width:${pct}%"></div>
        <span class="absolute inset-0 flex items-center px-2 text-[9px] font-medium tabular-nums ${pct > 40 ? 'text-white' : 'text-slate-500 dark:text-slate-400'}">${d.count}</span>
      </div>
      <span class="flex items-center gap-0.5 flex-shrink-0">${svcLogos}</span>
      ${uploadBadge}
    </div>`;
  }).join('');

  // Service popularity breakdown
  const svcBreakdown = document.getElementById('ai-adopt-svc-breakdown');
  if (!svcBreakdown) return;
  const svcEntries = Object.entries(svcCounts).sort((a,b) => b[1] - a[1]);
  const maxSvcCount = svcEntries[0]?.[1] || 1;
  const totalEvents = events.length || 1;

  svcBreakdown.innerHTML = svcEntries.map(([svc, count]) => {
    const pct = Math.round((count / maxSvcCount) * 100);
    const share = Math.round((count / totalEvents) * 100);
    const usersCount = Object.values(deviceEvents).filter(evts => evts.some(e => e.ai_service === svc)).length;
    return `<div class="flex items-center gap-3 text-[11px]">
      <span class="w-[120px] flex-shrink-0">${svcLogoName(svc)}</span>
      <div class="flex-1 h-5 rounded bg-slate-100 dark:bg-slate-800 overflow-hidden relative">
        <div class="h-full rounded bg-gradient-to-r from-indigo-500/70 to-purple-500/70" style="width:${pct}%"></div>
        <span class="absolute inset-0 flex items-center px-2 text-[9px] font-medium tabular-nums ${pct > 30 ? 'text-white' : 'text-slate-500 dark:text-slate-400'}">${count} ${t('adopt.queries')} · ${share}% ${t('adopt.share')} · ${usersCount} ${usersCount !== 1 ? t('adopt.users') : t('adopt.user')}</span>
      </div>
    </div>`;
  }).join('');
}

// --- CLOUD ---
async function refreshCloud() {
  const p = getFilterParams('cloud');
  const [events, timeline] = await Promise.all([
    fetch('/api/events?' + p).then(r => r.json()),
    fetch('/api/timeline?bucket_size=' + getBucketSize('cloud') + '&' + p).then(r => r.json()),
  ]);

  document.getElementById('cloud-stat-total').textContent = events.length;
  document.getElementById('cloud-stat-services').textContent = new Set(events.map(e => e.ai_service)).size;
  document.getElementById('cloud-stat-sources').textContent = Object.keys(deviceMap).length || new Set(events.map(e => e.source_ip)).size || 0;
  document.getElementById('cloud-stat-uploads').textContent = events.filter(e => e.possible_upload).length;

  // Populate service filter
  const svcSel = document.getElementById('cloud-filter-service');
  if (svcSel) {
    const cur = svcSel.value;
    const allSvcs = [...new Set(events.map(e => e.ai_service))].sort();
    svcSel.innerHTML = `<option value="">${t('cloud.allServices')}</option>`;
    allSvcs.forEach(s => { svcSel.innerHTML += `<option value="${s}">${svcDisplayName(s)}</option>`; });
    svcSel.value = cur;
  }

  renderEventsTable(events, 'cloud-tbody', 'cloud-empty');
  updateCategoryCharts(events, timeline, 'cloud-service-chart', 'cloud-timeline-chart');
}

// --- PRIVACY ---
let _cachedTopBlocked = [];

async function refreshPrivacy() {
  // Build filter params for tracker events
  const fp = getFilterParams('tracking');
  const privRes = await fetch('/api/privacy/stats?' + fp).then(r => r.json());

  // AdGuard section
  const ag = privRes.adguard || {};
  document.getElementById('priv-total').textContent = formatNumber(ag.total_queries || 0);
  document.getElementById('priv-blocked').textContent = formatNumber(ag.blocked_queries || 0);
  document.getElementById('priv-pct').textContent = (ag.block_percentage || 0) + '%';

  const statusEl = document.getElementById('priv-status');
  const unavail = document.getElementById('priv-unavailable');
  const chartC = document.getElementById('priv-chart-container');

  if (ag.status === 'ok') {
    statusEl.textContent = '● ' + t('priv.connected');
    statusEl.className = 'text-base font-semibold mt-2 text-emerald-600 dark:text-emerald-400';
    if (unavail) unavail.classList.add('hidden');
    if (chartC) chartC.classList.remove('hidden');

    const topD = (ag.top_blocked || []).slice(0, 10);
    _cachedTopBlocked = ag.top_blocked || [];

    const bChart = getOrCreateChart('priv-chart', makeBarConfig());
    if (bChart) {
      bChart.data.labels = topD.map(d => d.domain.length > 30 ? d.domain.slice(0, 27) + '...' : d.domain);
      bChart.data.datasets[0].data = topD.map(d => d.count);
      bChart.update();
    }

    // Update blocked domains panel if visible
    const panel = document.getElementById('blocked-domains-panel');
    if (panel && !panel.classList.contains('hidden')) renderBlockedDomainsList();
  } else {
    statusEl.textContent = '● ' + t('priv.offline');
    statusEl.className = 'text-base font-semibold mt-2 text-red-500 dark:text-red-400';
    if (chartC) chartC.classList.add('hidden');
    if (unavail) unavail.classList.remove('hidden');
  }

  // Zeek tracker section
  const tk = privRes.trackers || {};
  _cachedTopTrackers = tk.top_trackers || [];
  document.getElementById('tracker-total').textContent = formatNumber(tk.total_detected || 0);
  document.getElementById('tracker-unique').textContent = _cachedTopTrackers.length;

  // Update tracker details panel if already open
  const tPanel = document.getElementById('tracker-details-panel');
  if (tPanel && !tPanel.classList.contains('hidden')) renderTrackerDetailsList();

  const tChart = getOrCreateChart('tracker-chart', makeDoughnutConfig());
  if (tChart) {
    const topT = _cachedTopTrackers.slice(0, 10);
    const trackerKeys = topT.map(t => t.service);
    tChart.data.labels = topT.map(t => svcDisplayName(t.service));
    tChart.data.datasets[0].data = topT.map(t => t.hits);
    tChart.data.datasets[0].backgroundColor = trackerKeys.map(s => svcColor(s));
    tChart.update();
    renderHtmlLegend('tracker-chart-legend', tChart, trackerKeys);
  }

  // Tracker table
  const tbody = document.getElementById('tracker-table-body');
  const recent = tk.recent || [];
  if (tbody) {
    if (recent.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">${t('priv.noTrackers')}</td></tr>`;
    } else {
      tbody.innerHTML = recent.map(e => {
        return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20">
          <td class="py-2 px-3 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(e.timestamp)}</td>
          <td class="py-2 px-3">${badge(e.service)}</td>
          <td class="py-2 px-3 text-xs text-slate-500 dark:text-slate-400">${e.detection_type}</td>
          <td class="py-2 px-3 text-xs font-mono text-slate-500 dark:text-slate-400">${e.source_ip}</td>
        </tr>`;
      }).join('');
    }
  }

  // Populate tracker filter dropdowns
  const privSvcSel = document.getElementById('priv-filter-service');
  if (privSvcSel) {
    const cur = privSvcSel.value;
    const allSvcs = [...new Set((tk.top_trackers || []).map(t => t.service))].sort();
    privSvcSel.innerHTML = `<option value="">${t('priv.allTrackers')}</option>`;
    allSvcs.forEach(s => { privSvcSel.innerHTML += `<option value="${s}">${svcDisplayName(s)}</option>`; });
    privSvcSel.value = cur;
  }
  const privDevSel = document.getElementById('priv-filter-device');
  if (privDevSel) {
    const cur = privDevSel.value;
    const allDevs = [...new Set(recent.map(e => e.source_ip))].sort();
    privDevSel.innerHTML = `<option value="">${t('priv.allDevices')}</option>`;
    allDevs.forEach(ip => {
      const name = deviceName(ip);
      privDevSel.innerHTML += `<option value="${ip}">${name !== ip ? name + ' (' + ip + ')' : ip}</option>`;
    });
    privDevSel.value = cur;
  }

  // VPN stat card + expandable panel
  renderVpnAlerts(privRes.vpn_alerts || []);
}

// VPN toggle + rendering
function toggleVpnDetail() {
  const panel = document.getElementById('vpn-detail-panel');
  if (!panel) return;
  const hidden = panel.classList.contains('hidden');
  if (hidden) { panel.classList.remove('hidden'); }
  else panel.classList.add('hidden');
}

function renderVpnAlerts(alerts) {
  const statCount = document.getElementById('vpn-stat-count');
  const statLabel = document.getElementById('vpn-stat-label');
  const statCard = document.getElementById('vpn-stat-card');
  const body = document.getElementById('vpn-alerts-body');
  if (!statCount) return;

  const count = alerts?.length || 0;
  statCount.textContent = count;

  if (count === 0) {
    statLabel.textContent = t('priv.noTunnels');
    statLabel.className = 'text-emerald-500 dark:text-emerald-400';
    statCard.className = statCard.className.replace(/border-orange-\S+/g, '').replace(/dark:border-orange-\S+/g, '');
    if (!statCard.className.includes('border-slate-200')) statCard.className += ' border-slate-200 dark:border-white/[0.05]';
    if (body) body.innerHTML = `
      <div class="flex flex-col items-center justify-center py-6 text-center">
        <div class="w-10 h-10 rounded-full bg-emerald-500/10 dark:bg-emerald-500/15 flex items-center justify-center mb-2">
          <svg class="w-5 h-5 text-emerald-500 dark:text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
        </div>
        <p class="text-sm text-slate-500 dark:text-slate-400">No active VPN tunnels detected</p>
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-1">Monitoring OpenVPN, WireGuard, IPsec &amp; more</p>
      </div>`;
    return;
  }

  // Active alerts — orange warning
  statLabel.textContent = count === 1 ? '1 device using VPN' : `${count} devices using VPN`;
  statLabel.className = 'text-orange-500 dark:text-orange-400';
  statCard.className = statCard.className
    .replace(/border-slate-200\s*/g, '').replace(/dark:border-white\/\[0\.05\]/g, '');
  if (!statCard.className.includes('border-orange')) {
    statCard.className += ' border-orange-500/40 dark:border-orange-500/30';
  }

  if (body) body.innerHTML = `
    <div class="overflow-x-auto max-h-64 overflow-y-auto">
      <table class="w-full text-sm text-left">
        <thead class="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-slate-200 dark:border-white/[0.05] sticky top-0 bg-white dark:bg-[#0B0C10]">
          <tr>
            <th class="pb-2 px-3 font-medium">Device</th>
            <th class="pb-2 px-3 font-medium">VPN Service</th>
            <th class="pb-2 px-3 font-medium">Data</th>
            <th class="pb-2 px-3 font-medium">Events</th>
            <th class="pb-2 px-3 font-medium">Last Seen</th>
          </tr>
        </thead>
        <tbody class="text-slate-600 dark:text-slate-300">
          ${alerts.map(a => {
            const name = a.display_name || a.hostname || a.source_ip;
            const dtTag = typeof deviceTypeTag === 'function' ? deviceTypeTag(a) : '';
            const bytes = a.total_bytes >= 1048576
              ? (a.total_bytes / 1048576).toFixed(1) + ' MB'
              : (a.total_bytes / 1024).toFixed(0) + ' KB';
            return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-orange-50/50 dark:hover:bg-orange-900/10">
              <td class="py-2 px-3">
                <div class="font-medium text-xs">${name}</div>
                ${dtTag}
                <span class="text-[10px] font-mono text-slate-400 dark:text-slate-500 ml-1">${a.source_ip}</span>
              </td>
              <td class="py-2 px-3">
                ${a.vpn_service && a.vpn_service.startsWith('vpn_') && a.vpn_service !== 'vpn_active'
                  ? badge(a.vpn_service)
                  : `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-orange-500/10 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400">🔒 Encrypted Tunnel</span>`
                }
              </td>
              <td class="py-2 px-3 text-xs tabular-nums font-medium text-orange-600 dark:text-orange-400">${bytes}</td>
              <td class="py-2 px-3 text-xs tabular-nums">${a.hits}</td>
              <td class="py-2 px-3 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(a.last_seen)}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>`;
}

// Blocked domains panel
function toggleBlockedDomains() {
  const panel = document.getElementById('blocked-domains-panel');
  if (!panel) return;
  const hidden = panel.classList.contains('hidden');
  if (hidden) { panel.classList.remove('hidden'); renderBlockedDomainsList(); }
  else panel.classList.add('hidden');
}

function renderBlockedDomainsList() {
  const container = document.getElementById('blocked-domains-list');
  if (!container) return;
  if (!_cachedTopBlocked?.length) {
    container.innerHTML = '<p class="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-4">No blocked domains data available.</p>';
    return;
  }
  const maxCount = _cachedTopBlocked[0]?.count || 1;
  container.innerHTML = _cachedTopBlocked.map((d, i) => {
    const pct = Math.max(5, (d.count / maxCount) * 100);
    return `<div class="flex items-center gap-3 bg-slate-50 dark:bg-white/[0.03] rounded-lg px-3 py-2 border border-slate-200 dark:border-white/[0.04]">
      <span class="text-[10px] text-slate-400 w-4 text-right tabular-nums">${i + 1}</span>
      <div class="flex-1 min-w-0">
        <p class="text-[11px] font-mono text-slate-700 dark:text-slate-200 truncate" title="${d.domain}">${d.domain}</p>
        <div class="mt-1 h-1 rounded-full bg-slate-200 dark:bg-slate-700/50 overflow-hidden">
          <div class="h-full rounded-full bg-red-500/70" style="width:${pct}%"></div>
        </div>
      </div>
      <span class="text-[11px] tabular-nums text-red-500 dark:text-red-400 font-medium">${formatNumber(d.count)}</span>
    </div>`;
  }).join('');
}

// Tracker details panel
let _cachedTopTrackers = [];

function toggleTrackerDetails() {
  const panel = document.getElementById('tracker-details-panel');
  if (!panel) return;
  const hidden = panel.classList.contains('hidden');
  if (hidden) { panel.classList.remove('hidden'); renderTrackerDetailsList(); }
  else panel.classList.add('hidden');
}

function renderTrackerDetailsList() {
  const container = document.getElementById('tracker-details-list');
  if (!container) return;
  if (!_cachedTopTrackers?.length) {
    container.innerHTML = '<p class="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-4">No tracker data available.</p>';
    return;
  }
  const maxHits = _cachedTopTrackers[0]?.hits || 1;
  container.innerHTML = _cachedTopTrackers.map((t, i) => {
    const pct = Math.max(5, (t.hits / maxHits) * 100);
    const name = svcDisplayName(t.service);
    return `<div class="flex items-center gap-3 bg-slate-50 dark:bg-white/[0.03] rounded-lg px-3 py-2 border border-slate-200 dark:border-white/[0.04]">
      <span class="text-[10px] text-slate-400 w-4 text-right tabular-nums">${i + 1}</span>
      <div class="flex-1 min-w-0">
        <p class="text-[11px] font-medium text-slate-700 dark:text-slate-200 truncate inline-flex items-center gap-1.5" title="${name}">${svcLogo(t.service)} ${name}</p>
        <div class="mt-1 h-1 rounded-full bg-slate-200 dark:bg-slate-700/50 overflow-hidden">
          <div class="h-full rounded-full bg-amber-500/70" style="width:${pct}%"></div>
        </div>
      </div>
      <span class="text-[11px] tabular-nums text-amber-500 dark:text-amber-400 font-medium">${formatNumber(t.hits)}</span>
    </div>`;
  }).join('');
}

// --- DEVICES ---
// Store events globally for drill-down
let _devAllEvents = [];
let _devMatrix = {};
let _devExpandedGroups = new Set();

function getCategoryGroups() {
  return [
    { key: 'ai',       label: t('cat.aiServices'),   icon: '🤖', color: 'indigo' },
    { key: 'cloud',    label: t('cat.cloudStorage'),  icon: '☁️',  color: 'sky' },
    { key: 'tracking', label: t('cat.privacyTrackers'), icon: '🛡️', color: 'amber' },
  ];
}

function _categorizeService(svc, svcCategoryMap) {
  return svcCategoryMap[svc] || 'tracking';
}

function _heatCell(count, uploads, globalMax) {
  if (!count) return `<span class="inline-block w-full py-1 rounded text-[10px] text-slate-300 dark:text-slate-600">—</span>`;
  const intensity = count / globalMax;
  let bg, text;
  if (intensity < 0.15)      { bg = 'bg-blue-100 dark:bg-blue-900/40'; text = 'text-blue-700 dark:text-blue-300'; }
  else if (intensity < 0.4)  { bg = 'bg-amber-200 dark:bg-amber-800/50'; text = 'text-amber-800 dark:text-amber-200'; }
  else if (intensity < 0.7)  { bg = 'bg-orange-300 dark:bg-orange-700/60'; text = 'text-orange-900 dark:text-orange-100'; }
  else                       { bg = 'bg-red-400 dark:bg-red-600/70'; text = 'text-white dark:text-red-100'; }
  const uploadIcon = uploads > 0 ? ` <span class="text-orange-500" title="${uploads} upload(s)">▲</span>` : '';
  return `<span class="inline-block w-full py-1 rounded text-[11px] font-medium tabular-nums ${bg} ${text}">${count}${uploadIcon}</span>`;
}

function _toggleDevGroup(groupKey) {
  if (_devExpandedGroups.has(groupKey)) _devExpandedGroups.delete(groupKey);
  else _devExpandedGroups.add(groupKey);
  _renderDeviceMatrix();
}

function _showCellEvents(mac, service, category) {
  const panel = document.getElementById('dev-event-detail');
  const title = document.getElementById('dev-event-detail-title');
  const tbody = document.getElementById('dev-event-detail-body');

  // Find matching device IPs
  const dev = deviceMap[mac];
  const devIps = new Set();
  if (dev && dev.ips) dev.ips.forEach(ip => devIps.add(ip.ip));
  else devIps.add(mac.replace('_ip_', ''));

  // Filter events
  let events;
  if (service) {
    events = _devAllEvents.filter(e => devIps.has(e.source_ip) && e.ai_service === service);
  } else if (category) {
    events = _devAllEvents.filter(e => devIps.has(e.source_ip) && e._cat === category);
  } else {
    events = _devAllEvents.filter(e => devIps.has(e.source_ip));
  }
  events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const dn = dev ? (dev.display_name || dev.hostname || _latestIp(dev)) : mac.replace('_ip_', '');
  const catGroup = category ? getCategoryGroups().find(g => g.key === category) : null;
  const svcLabel = service ? svcLogoName(service) : catGroup ? `${catGroup.icon} ${catGroup.label}` : 'All Services';
  // OS fingerprint info line
  let osLine = '';
  if (dev?.os_name) {
    const osLabel = dev.os_version ? `${dev.os_name} ${dev.os_version}` : dev.os_name;
    const distText = dev.network_distance != null ? ` · ${dev.network_distance} hop${dev.network_distance !== 1 ? 's' : ''}` : '';
    const dcText = dev.device_class ? ` · ${dev.device_class}` : '';
    osLine = `<div class="text-[10px] text-indigo-500 dark:text-indigo-400 mt-0.5">🔍 p0f: ${osLabel}${dcText}${distText}</div>`;
  }
  title.innerHTML = `${_detectDeviceType(dev).icon} ${dn} — ${svcLabel} <span class="text-slate-400 dark:text-slate-500 font-normal">(${events.length} events)</span>${osLine}`;

  tbody.innerHTML = events.slice(0, 100).map(e => {
    const up = e.possible_upload;
    const upBadge = up ? ' <span class="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-orange-100 dark:bg-orange-800/50 text-orange-600 dark:text-orange-300">UPLOAD</span>' : '';
    return `<tr class="border-b border-slate-100 dark:border-white/[0.04] ${up ? 'bg-orange-50/50 dark:bg-orange-900/10' : ''}">
      <td class="py-2 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500 whitespace-nowrap">${fmtTime(e.timestamp)}</td>
      <td class="py-2 px-4">${badge(e.ai_service)}</td>
      <td class="py-2 px-4 text-xs">${e.detection_type}${upBadge}</td>
      <td class="py-2 px-4 text-xs font-mono text-slate-400 dark:text-slate-500">${e.source_ip}</td>
      <td class="py-2 px-4 text-xs text-right tabular-nums">${e.bytes_transferred ? formatNumber(e.bytes_transferred) : '0'}</td>
    </tr>`;
  }).join('');

  if (events.length > 100) {
    tbody.innerHTML += `<tr><td colspan="5" class="py-3 text-center text-slate-400 dark:text-slate-500 text-xs">Showing first 100 of ${events.length} events</td></tr>`;
  }

  // Store current MAC for the AI report button
  panel.dataset.mac = mac;

  // Hide any previous report
  document.getElementById('dev-ai-report').classList.add('hidden');

  panel.classList.remove('hidden');
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ---------------------------------------------------------------------------
// AI Recap — generate device report via Gemini
// ---------------------------------------------------------------------------
let _reportAbort = null;

async function generateDeviceReport(macParam) {
  // MAC can come from parameter (matrix button) or from the detail panel
  const panel = document.getElementById('dev-event-detail');
  const mac = macParam || panel?.dataset?.mac;
  if (!mac) return;

  // If called from matrix row, open the detail panel first so the report has a place to render
  if (macParam && panel.classList.contains('hidden')) {
    _showCellEvents(mac, null, null);
  }
  // Ensure panel stores the MAC
  panel.dataset.mac = mac;

  const btn = document.getElementById('btn-ai-report');
  const reportBox = document.getElementById('dev-ai-report');
  const reportContent = document.getElementById('dev-ai-report-content');

  // Loading state
  btn.disabled = true;
  btn.innerHTML = '<span class="inline-block animate-pulse">&#10024;</span> Generating AI report\u2026';
  btn.classList.add('opacity-70', 'cursor-wait');
  reportBox.classList.remove('hidden');
  reportContent.innerHTML = `
    <div class="flex items-center gap-3 text-indigo-500 dark:text-indigo-400 py-4">
      <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path></svg>
      <span>Gemini is analyzing the past 24 hours of network activity\u2026</span>
    </div>`;

  // Scroll the report into view
  reportBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const resp = await fetch(`/api/devices/${encodeURIComponent(mac)}/report`);
    const data = await resp.json();

    if (!resp.ok) {
      reportContent.innerHTML = `<div class="text-red-500 dark:text-red-400 text-sm">${data.detail || 'Fout bij het genereren van het rapport.'}</div>`;
      return;
    }

    // Render markdown (simple parser for bold, italic, headers, lists, code)
    let html = renderSimpleMarkdown(data.report);

    // Token usage footer
    if (data.tokens) {
      const tok = data.tokens;
      const costIn = (tok.prompt_tokens || 0) * 0.15 / 1e6;
      const costOut = (tok.response_tokens || 0) * 0.60 / 1e6;
      const costThink = (tok.thinking_tokens || 0) * 3.50 / 1e6;
      const totalCost = costIn + costOut + costThink;
      const cents = (totalCost * 100).toFixed(2);
      html += `<div class="mt-4 pt-3 border-t border-indigo-200/30 dark:border-indigo-700/20 flex items-center justify-between text-[10px] text-indigo-400/70 dark:text-indigo-500/50">
        <span>Gemini 2.5 Flash &middot; ${formatNumber(tok.total_tokens || 0)} tokens</span>
        <span>${cents}&cent; per report</span>
      </div>`;
    }

    reportContent.innerHTML = html;

  } catch (err) {
    reportContent.innerHTML = `<div class="text-red-500 dark:text-red-400 text-sm">Netwerk-fout: ${err.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="text-sm">&#10024;</span> Genereer AI Rapport (24u)';
    btn.classList.remove('opacity-70', 'cursor-wait');
  }
}

function renderSimpleMarkdown(md) {
  if (!md) return '';
  let html = md
    // Escape HTML entities
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // Headers (### → h4, ## → h3, # → h2)
    .replace(/^### (.+)$/gm, '<h4 class="text-sm font-semibold mt-4 mb-1 text-slate-800 dark:text-slate-200">$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 class="text-base font-semibold mt-5 mb-2 text-slate-800 dark:text-slate-200">$1</h3>')
    .replace(/^# (.+)$/gm, '<h2 class="text-lg font-bold mt-5 mb-2 text-slate-800 dark:text-slate-200">$1</h2>')
    // Bold + italic
    .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-800 dark:text-slate-100">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-slate-200/70 dark:bg-slate-700/50 text-xs font-mono">$1</code>')
    // Unordered lists
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-[13px] leading-relaxed">$1</li>')
    .replace(/^\* (.+)$/gm, '<li class="ml-4 list-disc text-[13px] leading-relaxed">$1</li>')
    // Horizontal rule
    .replace(/^---$/gm, '<hr class="my-3 border-indigo-200/50 dark:border-indigo-700/30">')
    // Paragraphs (double newline)
    .replace(/\n\n/g, '</p><p class="mb-2">')
    // Single newlines within text
    .replace(/\n/g, '<br>');

  // Wrap consecutive <li> items in <ul>
  html = html.replace(/(<li[^>]*>.*?<\/li>(?:\s*<br>?\s*<li[^>]*>.*?<\/li>)*)/gs, '<ul class="my-2 space-y-0.5">$1</ul>');
  // Clean up stray <br> inside <ul>
  html = html.replace(/<ul([^>]*)>([\s\S]*?)<\/ul>/g, (m, attrs, inner) => {
    return `<ul${attrs}>${inner.replace(/<br>/g, '')}</ul>`;
  });

  return `<p class="mb-2">${html}</p>`;
}

window.generateDeviceReport = generateDeviceReport;

// Expose for onclick
window._toggleDevGroup = _toggleDevGroup;
window._showCellEvents = _showCellEvents;

function _renderDeviceMatrix() {
  const matrix = _devMatrix.matrix;
  const svcCategoryMap = _devMatrix.svcCategoryMap;
  const allServices = _devMatrix.allServices;
  const deviceMacs = _devMatrix.deviceMacs;
  const globalMax = _devMatrix.globalMax;

  // Group services by category
  const groups = getCategoryGroups().map(g => {
    const svcs = [...allServices].filter(s => _categorizeService(s, svcCategoryMap) === g.key).sort();
    // Compute group total per device
    return { ...g, services: svcs };
  }).filter(g => g.services.length > 0);

  // Build header
  const thead = document.getElementById('devices-matrix-head');
  const expanded = _devExpandedGroups;

  let headerCells = `<th class="py-3 px-4 font-medium sticky left-0 bg-slate-50 dark:bg-[#0B0C10] z-10 min-w-[180px]">Device</th>
    <th class="py-3 px-3 font-medium text-right min-w-[60px]">Total</th>`;

  groups.forEach(g => {
    const isExpanded = expanded.has(g.key);
    const chevron = isExpanded ? '▾' : '▸';
    headerCells += `<th class="py-3 px-3 font-medium text-center min-w-[90px] cursor-pointer select-none hover:text-indigo-400 transition-colors border-l border-slate-200 dark:border-white/[0.06]"
      onclick="_toggleDevGroup('${g.key}')" title="Click to ${isExpanded ? 'collapse' : 'expand'} ${g.label}">
      <span class="inline-flex items-center gap-1 justify-center">${g.icon} ${g.label} <span class="text-[10px] opacity-60">${chevron}</span></span>
    </th>`;
    if (isExpanded) {
      g.services.forEach(s => {
        headerCells += `<th class="py-3 px-2 font-medium text-center min-w-[70px]" title="${s}">
          <span class="inline-flex items-center gap-1 justify-center">${svcLogo(s)} <span class="truncate max-w-[60px]">${svcDisplayName(s)}</span></span>
        </th>`;
      });
    }
  });

  thead.innerHTML = `<tr>${headerCells}</tr>`;

  // Render body
  const tbody = document.getElementById('devices-matrix-body');
  const colCount = 2 + groups.reduce((s, g) => s + 1 + (expanded.has(g.key) ? g.services.length : 0), 0);

  if (deviceMacs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${colCount}" class="py-12 text-center text-slate-400 dark:text-slate-500 text-sm">No device activity detected in this period.</td></tr>`;
    return;
  }

  tbody.innerHTML = deviceMacs.map(mac => {
    const row = matrix[mac] || {};
    const total = Object.values(row).reduce((s, v) => s + v.count, 0);
    const totalUploads = Object.values(row).reduce((s, v) => s + v.uploads, 0);
    const dev = deviceMap[mac] || null;
    const dn = dev ? (dev.display_name || dev.hostname || _latestIp(dev)) : mac.replace('_ip_', '');
    const ipInfo = dev ? _ipSummary(dev) : mac.replace('_ip_', '');
    const dtTag = deviceTypeTag(dev);

    let cells = '';
    groups.forEach(g => {
      // Group total cell
      const groupCount = g.services.reduce((s, svc) => s + (row[svc]?.count || 0), 0);
      const groupUploads = g.services.reduce((s, svc) => s + (row[svc]?.uploads || 0), 0);
      cells += `<td class="py-2.5 px-2 text-center border-l border-slate-100 dark:border-white/[0.04] cursor-pointer" onclick="_showCellEvents('${mac}', null, '${g.key}')">
        ${_heatCell(groupCount, groupUploads, globalMax)}
      </td>`;

      if (expanded.has(g.key)) {
        g.services.forEach(s => {
          const v = row[s];
          cells += `<td class="py-2.5 px-2 text-center cursor-pointer" onclick="_showCellEvents('${mac}', '${s}')">
            ${_heatCell(v?.count || 0, v?.uploads || 0, globalMax)}
          </td>`;
        });
      }
    });

    const uploadBadge = totalUploads > 0
      ? `<span class="ml-1 text-[10px] px-1 py-0.5 rounded bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">${totalUploads}▲</span>`
      : '';

    const isQuiet = total === 0;
    const rowOpacity = isQuiet ? 'opacity-60' : '';
    const totalDisplay = isQuiet
      ? `<span class="text-xs text-slate-300 dark:text-slate-600">—</span>`
      : `<span class="cursor-pointer" onclick="_showCellEvents('${mac}', null, null)">${total}${uploadBadge}</span>`;

    const reportBtn = dev ? `<button onclick="event.stopPropagation();generateDeviceReport('${mac}')" class="ml-2 px-1.5 py-0.5 text-[9px] font-semibold rounded bg-gradient-to-r from-indigo-500/80 to-purple-500/80 text-white hover:from-indigo-500 hover:to-purple-500 transition-all leading-none whitespace-nowrap" title="Generate AI Network Recap">&#10024; AI</button>` : '';

    return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors ${rowOpacity}">
      <td class="py-2.5 px-4 sticky left-0 bg-white dark:bg-[#0B0C10] z-10">
        <div class="flex items-center gap-1">
          <span class="device-name cursor-pointer hover:text-indigo-500 transition-colors text-sm font-medium" data-mac="${dev ? dev.mac_address : ''}" title="${dn}">${dn}</span>
          ${reportBtn}
        </div>
        <p class="text-[10px] text-slate-400 dark:text-slate-500 font-mono">${ipInfo}</p>
        ${dtTag}
      </td>
      <td class="py-2.5 px-3 text-right tabular-nums text-sm font-semibold">${totalDisplay}</td>
      ${cells}
    </tr>`;
  }).join('');
}

async function refreshDevices() {
  const per = document.getElementById('dev-filter-period')?.value;
  const params = new URLSearchParams();
  params.set('limit', '1000');
  if (per) params.set('start', new Date(Date.now() - parseInt(per) * 60000).toISOString());

  // Fetch all categories in parallel
  const [aiEvt, cloudEvt, trackEvt] = await Promise.all([
    fetch('/api/events?category=ai&' + params).then(r => r.json()),
    fetch('/api/events?category=cloud&' + params).then(r => r.json()),
    fetch('/api/events?category=tracking&' + params).then(r => r.json()),
  ]);

  // Tag events with their category
  aiEvt.forEach(e => e._cat = 'ai');
  cloudEvt.forEach(e => e._cat = 'cloud');
  trackEvt.forEach(e => e._cat = 'tracking');

  const allEvents = [...aiEvt, ...cloudEvt, ...trackEvt];
  _devAllEvents = allEvents;

  // Build service → category map from event data
  const svcCategoryMap = {};
  allEvents.forEach(e => { svcCategoryMap[e.ai_service] = e._cat; });

  // Build device → service → {count, uploads} map
  const matrix = {};
  const allServices = new Set();

  allEvents.forEach(e => {
    const mac = ipToMac[e.source_ip] || `_ip_${e.source_ip}`;
    if (!matrix[mac]) matrix[mac] = {};
    const row = matrix[mac];
    if (!row[e.ai_service]) row[e.ai_service] = { count: 0, uploads: 0 };
    row[e.ai_service].count++;
    if (e.possible_upload) row[e.ai_service].uploads++;
    allServices.add(e.ai_service);
  });

  // Include ALL known devices (even those with 0 events)
  const allKnownMacs = new Set(Object.keys(matrix));
  Object.keys(deviceMap).forEach(mac => allKnownMacs.add(mac));

  const deviceMacs = [...allKnownMacs];
  deviceMacs.sort((a, b) => {
    const totalA = Object.values(matrix[a] || {}).reduce((s, v) => s + v.count, 0);
    const totalB = Object.values(matrix[b] || {}).reduce((s, v) => s + v.count, 0);
    // Devices with events first (sorted by count desc), then devices without events (sorted by name)
    if (totalA === 0 && totalB === 0) {
      const nameA = deviceMap[a]?.display_name || deviceMap[a]?.hostname || a;
      const nameB = deviceMap[b]?.display_name || deviceMap[b]?.hostname || b;
      return nameA.localeCompare(nameB);
    }
    return totalB - totalA;
  });

  const activeMacs = Object.keys(matrix).length;

  // Stats
  const totalUploads = allEvents.filter(e => e.possible_upload).length;
  document.getElementById('dev-stat-total').textContent = deviceMacs.length;
  document.getElementById('dev-stat-violators').textContent = activeMacs;
  document.getElementById('dev-stat-events').textContent = formatNumber(allEvents.length);
  document.getElementById('dev-stat-uploads').textContent = totalUploads;

  // Find global max for heat intensity
  let globalMax = 1;
  deviceMacs.forEach(mac => {
    Object.values(matrix[mac] || {}).forEach(v => { if (v.count > globalMax) globalMax = v.count; });
  });

  // Store for rendering
  _devMatrix = { matrix, svcCategoryMap, allServices, deviceMacs, globalMax };

  // Hide event detail panel on refresh
  document.getElementById('dev-event-detail')?.classList.add('hidden');

  _renderDeviceMatrix();
}

// --- RULES ---
let _currentRulesTab = 'outbound';

function switchRulesTab(tab) {
  _currentRulesTab = tab;
  const outDiv = document.getElementById('rules-tab-outbound');
  const inDiv  = document.getElementById('rules-tab-inbound');
  const btnOut = document.getElementById('rules-tab-btn-outbound');
  const btnIn  = document.getElementById('rules-tab-btn-inbound');

  const activeClass = 'bg-white dark:bg-white/[0.08] text-slate-800 dark:text-white shadow-sm';
  const inactiveClass = 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300';

  if (tab === 'outbound') {
    outDiv.classList.remove('hidden');
    inDiv.classList.add('hidden');
    btnOut.className = `px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${activeClass}`;
    btnIn.className  = `px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${inactiveClass}`;
  } else {
    outDiv.classList.add('hidden');
    inDiv.classList.remove('hidden');
    btnOut.className = `px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${inactiveClass}`;
    btnIn.className  = `px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${activeClass}`;
  }
}

async function refreshRules() {
  await Promise.all([loadGlobalFilterStatus(), loadIpsStatus(), loadAccessControl()]);
}

async function loadGlobalFilterStatus() {
  try {
    const res = await fetch('/api/filters/status');
    const data = await res.json();
    document.getElementById('toggle-parental').checked = data.parental_enabled;
    document.getElementById('toggle-social').checked = data.social_media_blocked;
    document.getElementById('toggle-gaming').checked = data.gaming_blocked;
    styleFilterCard('filter-parental-card', data.parental_enabled);
    styleFilterCard('filter-social-card', data.social_media_blocked);
    styleFilterCard('filter-gaming-card', data.gaming_blocked);
  } catch(e) { console.error('loadGlobalFilterStatus:', e); }
}

function styleFilterCard(id, active) {
  const card = document.getElementById(id);
  if (!card) return;
  if (active) {
    card.classList.add('border-red-300', 'dark:border-red-700/40', 'bg-red-50', 'dark:bg-red-900/10');
    card.classList.remove('border-slate-200', 'dark:border-white/[0.05]', 'bg-white', 'dark:bg-white/[0.03]');
  } else {
    card.classList.remove('border-red-300', 'dark:border-red-700/40', 'bg-red-50', 'dark:bg-red-900/10');
    card.classList.add('border-slate-200', 'dark:border-white/[0.05]', 'bg-white', 'dark:bg-white/[0.03]');
  }
}

async function toggleGlobalFilter(type, checkbox) {
  checkbox.disabled = true;
  const enabled = checkbox.checked;
  const endpoints = { parental: '/api/filters/parental', social: '/api/filters/social', gaming: '/api/filters/gaming' };
  const cards = { parental: 'filter-parental-card', social: 'filter-social-card', gaming: 'filter-gaming-card' };
  try {
    const res = await fetch(endpoints[type], {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
    styleFilterCard(cards[type], enabled);
  } catch(err) {
    console.error('toggleGlobalFilter:', err);
    checkbox.checked = !checkbox.checked;
    alert('Failed to update filter: ' + err.message);
  } finally { checkbox.disabled = false; }
}

// --- Active Protect (IPS) ---
async function refreshIps() {
  await loadIpsStatus();
}

async function loadIpsStatus() {
  try {
    const res = await fetch('/api/ips/status');
    const data = await res.json();

    // Sync both toggles (rules card + IPS page)
    ['toggle-ips', 'toggle-ips-page'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.checked = data.enabled;
    });
    styleIpsCard(data.enabled);
    _updateIpsBanner(data);
    _updateIpsStats(data);
  } catch(e) { console.error('loadIpsStatus:', e); }
}

function _updateIpsBanner(data) {
  const banner = document.getElementById('ips-banner');
  const statusText = document.getElementById('ips-banner-status');
  const shield = document.getElementById('ips-shield-icon');
  if (!banner) return;

  if (data.enabled && data.crowdsec_running) {
    statusText.textContent = 'Active — protecting your network';
    statusText.className = 'text-sm text-emerald-500 dark:text-emerald-400';
    banner.classList.remove('border-slate-200', 'dark:border-white/[0.05]');
    banner.classList.add('border-emerald-300', 'dark:border-emerald-700/40');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center text-2xl';
  } else if (data.enabled) {
    statusText.textContent = 'Enabled — CrowdSec engine not reachable';
    statusText.className = 'text-sm text-amber-500 dark:text-amber-400';
    banner.classList.remove('border-slate-200', 'dark:border-white/[0.05]');
    banner.classList.add('border-amber-300', 'dark:border-amber-700/40');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center text-2xl';
  } else {
    statusText.textContent = 'Disabled — network is not protected';
    statusText.className = 'text-sm text-slate-400 dark:text-slate-500';
    banner.classList.remove('border-emerald-300', 'dark:border-emerald-700/40', 'border-amber-300', 'dark:border-amber-700/40');
    banner.classList.add('border-slate-200', 'dark:border-white/[0.05]');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-2xl';
  }
}

function _updateIpsStats(data) {
  // Threats blocked count
  const blockedEl = document.getElementById('ips-stat-blocked');
  if (blockedEl) blockedEl.textContent = formatNumber(data.active_threats_blocked);

  // Decisions count
  const decisionsEl = document.getElementById('ips-stat-decisions');
  if (decisionsEl) decisionsEl.textContent = formatNumber(data.active_threats_blocked);

  // Rules card badge
  const countEl = document.getElementById('ips-threats-count');
  if (countEl) countEl.textContent = formatNumber(data.active_threats_blocked);

  // Engine status
  const engineEl = document.getElementById('ips-engine-status');
  if (engineEl) {
    if (data.crowdsec_running) {
      engineEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400 dark:bg-emerald-500 inline-block"></span> Online';
      engineEl.className = 'inline-flex items-center gap-1.5 text-sm font-medium text-emerald-500 dark:text-emerald-400';
    } else {
      engineEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600 inline-block"></span> Offline';
      engineEl.className = 'inline-flex items-center gap-1.5 text-sm font-medium text-slate-400 dark:text-slate-500';
    }
  }

  // Status dot on rules card
  const dot = document.getElementById('ips-status-dot');
  if (dot) {
    dot.classList.remove('bg-emerald-400', 'dark:bg-emerald-500', 'bg-amber-400', 'dark:bg-amber-500', 'bg-slate-300', 'dark:bg-slate-600');
    if (data.crowdsec_running) {
      dot.classList.add('bg-emerald-400', 'dark:bg-emerald-500');
      dot.title = 'CrowdSec online';
    } else if (data.enabled) {
      dot.classList.add('bg-amber-400', 'dark:bg-amber-500');
      dot.title = 'CrowdSec not reachable';
    } else {
      dot.classList.add('bg-slate-300', 'dark:bg-slate-600');
      dot.title = 'CrowdSec offline';
    }
  }

  // Show/hide setup guide
  const guide = document.getElementById('ips-setup-guide');
  if (guide) guide.classList.toggle('hidden', data.crowdsec_running);
}

function styleIpsCard(active) {
  const card = document.getElementById('filter-ips-card');
  if (!card) return;
  if (active) {
    card.classList.add('border-emerald-300', 'dark:border-emerald-700/40', 'bg-emerald-50', 'dark:bg-emerald-900/10');
    card.classList.remove('border-slate-200', 'dark:border-white/[0.05]', 'bg-white', 'dark:bg-white/[0.03]');
  } else {
    card.classList.remove('border-emerald-300', 'dark:border-emerald-700/40', 'bg-emerald-50', 'dark:bg-emerald-900/10');
    card.classList.add('border-slate-200', 'dark:border-white/[0.05]', 'bg-white', 'dark:bg-white/[0.03]');
  }
}

async function toggleIps(checkbox) {
  checkbox.disabled = true;
  const enabled = checkbox.checked;
  try {
    const res = await fetch('/api/ips/toggle', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
    // Sync both toggles
    ['toggle-ips', 'toggle-ips-page'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.checked = enabled;
    });
    styleIpsCard(enabled);
    // Re-fetch full status to update banner/stats
    await loadIpsStatus();
  } catch(err) {
    console.error('toggleIps:', err);
    checkbox.checked = !checkbox.checked;
    alert('Failed to toggle Active Protect: ' + err.message);
  } finally { checkbox.disabled = false; }
}

// --- GRANULAR SERVICE CARDS ---
async function loadAccessControl() {
  try {
    const res = await fetch('/api/rules/services');
    const services = await res.json();
    const aiContainer = document.getElementById('access-control-ai');
    const cloudContainer = document.getElementById('access-control-cloud');
    const aiSvcs = services.filter(s => s.category === 'ai');
    const cloudSvcs = services.filter(s => s.category === 'cloud');
    aiContainer.innerHTML = aiSvcs.length
      ? aiSvcs.map(renderServiceCard).join('')
      : '<p class="text-slate-400 dark:text-slate-500 text-sm col-span-full text-center py-4">No AI services configured</p>';
    cloudContainer.innerHTML = cloudSvcs.length
      ? cloudSvcs.map(renderServiceCard).join('')
      : '<p class="text-slate-400 dark:text-slate-500 text-sm col-span-full text-center py-4">No Cloud services configured</p>';
  } catch(e) { console.error('loadAccessControl:', e); }
}

function remainingTime(expiresAt) {
  if (!expiresAt) return null;
  const exp = new Date(expiresAt.endsWith('Z') ? expiresAt : expiresAt + 'Z');
  const diff = exp - new Date();
  if (diff <= 0) return 'expiring...';
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m left`;
  const hrs = Math.floor(mins / 60);
  return `${hrs}h ${mins % 60}m left`;
}

function renderServiceCard(svc) {
  const name = SERVICE_NAMES[svc.service_name] || svc.service_name;
  const badgeCls = SVC_BADGE_CLS[svc.service_name] || 'bg-slate-100 dark:bg-slate-700/40 text-slate-600 dark:text-slate-300';
  const isAllowed = !svc.is_blocked;
  const blockedClass = svc.is_blocked ? 'blocked' : '';
  const remaining = svc.is_blocked && !svc.is_permanent ? remainingTime(svc.expires_at) : null;
  const permLabel = svc.is_blocked ? (svc.is_permanent ? 'Permanent' : remaining || 'Temporary') : '';
  const logo = svcLogo(svc.service_name);

  const seenTag = svc.seen
    ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400" title="${svc.hit_count} events">● ${t('svc.active')} (${formatNumber(svc.hit_count)})</span>`
    : `<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700/40 text-slate-400 dark:text-slate-500" title="No traffic detected">○ Preventive</span>`;

  const lastSeenText = svc.seen && svc.last_seen ? `Last: ${fmtTime(svc.last_seen)}` : 'No traffic detected';

  return `
    <div class="svc-card bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 ${blockedClass}">
      <div class="flex items-center justify-between mb-2">
        <div class="flex items-center gap-2">
          ${logo}
          <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${name}</span>
        </div>
        <label class="toggle" title="${isAllowed ? 'Allowed — click to block' : 'Blocked — click to allow'}">
          <input type="checkbox" ${isAllowed ? 'checked' : ''}
                 onchange="toggleService('${svc.service_name}','${svc.domains[0]}','${svc.category}',this)"/>
          <span class="slider"></span>
        </label>
      </div>
      <div class="mb-2">${seenTag}</div>
      <div class="flex items-center gap-2">
        <select id="dur-${svc.service_name}" class="text-xs flex-1" ${svc.is_blocked ? 'disabled' : ''}>
          <option value="0">Always</option>
          <option value="60">1 Hour</option>
          <option value="120">2 Hours</option>
          <option value="240">4 Hours</option>
          <option value="360">6 Hours</option>
          <option value="480">8 Hours</option>
          <option value="custom">Custom...</option>
        </select>
        ${svc.is_blocked
          ? `<span class="text-[10px] px-2 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 font-medium">${permLabel}</span>`
          : '<span class="text-[10px] text-emerald-600 dark:text-emerald-400 font-medium">✓ Allowed</span>'}
      </div>
      <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-2">${lastSeenText}</p>
    </div>`;
}

// Track pending custom block
let _pendingCustomBlock = null;

async function toggleService(serviceName, domain, category, checkbox) {
  checkbox.disabled = true;
  const isNowAllowed = checkbox.checked;
  try {
    if (isNowAllowed) {
      await fetch('/api/rules/unblock', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ service_name: serviceName, domain }),
      });
    } else {
      const durSelect = document.getElementById('dur-' + serviceName);
      const durVal = durSelect?.value || '0';

      if (durVal === 'custom') {
        // Open modal
        _pendingCustomBlock = { serviceName, domain, category, checkbox };
        document.getElementById('modal-backdrop').classList.remove('hidden');
        const input = document.getElementById('modal-block-until');
        // Default to 4 hours from now
        const def = new Date(Date.now() + 4 * 3600000);
        input.value = def.toISOString().slice(0, 16);
        return; // Don't finalize yet
      }

      const dur = parseInt(durVal);
      await fetch('/api/rules/block', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          service_name: serviceName, domain, category,
          duration_minutes: dur || null,
        }),
      });
    }
    await loadAccessControl();
  } catch(err) {
    console.error('toggleService:', err);
    checkbox.checked = !checkbox.checked;
  } finally {
    checkbox.disabled = false;
  }
}

function closeModal() {
  document.getElementById('modal-backdrop').classList.add('hidden');
  if (_pendingCustomBlock) {
    _pendingCustomBlock.checkbox.checked = true; // revert
    _pendingCustomBlock.checkbox.disabled = false;
    _pendingCustomBlock = null;
  }
}

async function confirmCustomBlock() {
  if (!_pendingCustomBlock) return;
  const { serviceName, domain, category, checkbox } = _pendingCustomBlock;
  const until = document.getElementById('modal-block-until').value;
  if (!until) { alert('Please select a date/time.'); return; }

  const untilDate = new Date(until);
  const now = new Date();
  const durationMin = Math.max(1, Math.round((untilDate - now) / 60000));

  try {
    await fetch('/api/rules/block', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        service_name: serviceName, domain, category,
        duration_minutes: durationMin,
      }),
    });
    await loadAccessControl();
  } catch(err) {
    console.error('confirmCustomBlock:', err);
    checkbox.checked = true; // revert
  } finally {
    checkbox.disabled = false;
    _pendingCustomBlock = null;
    document.getElementById('modal-backdrop').classList.add('hidden');
  }
}

// ================================================================
// ABOUT & LEGAL
// ================================================================

const LEGAL_COMPONENTS = [
  {
    name: 'AI-Radar',
    version: '1.0.0',
    license: 'Proprietary',
    description: 'Network intelligence appliance for AI & Cloud monitoring, privacy protection, and intrusion prevention.',
    url: null,
    icon: 'AR',
    iconBg: 'bg-indigo-100 dark:bg-indigo-900/30',
    iconColor: 'text-indigo-600 dark:text-indigo-400',
  },
  {
    name: 'FastAPI',
    version: null,
    license: 'MIT License',
    description: 'Modern, high-performance Python web framework for building APIs.',
    url: 'https://fastapi.tiangolo.com',
    icon: '⚡',
    iconBg: 'bg-emerald-100 dark:bg-emerald-900/30',
    iconColor: '',
  },
  {
    name: 'Zeek Network Security Monitor',
    version: null,
    license: 'BSD License',
    description: 'Passive network traffic analysis framework for security monitoring.',
    url: 'https://zeek.org',
    icon: '🔍',
    iconBg: 'bg-sky-100 dark:bg-sky-900/30',
    iconColor: '',
  },
  {
    name: 'CrowdSec',
    version: null,
    license: 'MIT License',
    description: 'Collaborative intrusion prevention system using crowd-sourced threat intelligence.',
    url: 'https://crowdsec.net',
    icon: '🛡️',
    iconBg: 'bg-purple-100 dark:bg-purple-900/30',
    iconColor: '',
  },
  {
    name: 'AdGuard Home',
    version: null,
    license: 'GNU GPLv3',
    description: 'Network-wide DNS-level ad and tracker blocking. AI-Radar communicates with an unmodified, independent instance via its official REST API.',
    url: 'https://adguard.com/adguard-home.html',
    icon: '🟢',
    iconBg: 'bg-green-100 dark:bg-green-900/30',
    iconColor: '',
  },
  {
    name: 'Chart.js',
    version: null,
    license: 'MIT License',
    description: 'Simple yet flexible JavaScript charting library for data visualization.',
    url: 'https://www.chartjs.org',
    icon: '📊',
    iconBg: 'bg-amber-100 dark:bg-amber-900/30',
    iconColor: '',
  },
  {
    name: 'Apache ECharts',
    version: null,
    license: 'Apache License 2.0',
    description: 'Powerful interactive charting and data visualization library.',
    url: 'https://echarts.apache.org',
    icon: '📈',
    iconBg: 'bg-red-100 dark:bg-red-900/30',
    iconColor: '',
  },
];

function renderLegalComponents() {
  const container = document.getElementById('legal-components');
  if (!container) return;

  container.innerHTML = LEGAL_COMPONENTS.map(c => {
    const versionBadge = c.version ? `<span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700/50 text-slate-500 dark:text-slate-400 font-mono">v${c.version}</span>` : '';
    const licenseBadge = `<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400">${c.license}</span>`;
    const link = c.url ? `<a href="${c.url}" target="_blank" rel="noopener" class="text-[10px] text-indigo-500 hover:underline ml-auto flex-shrink-0">${c.url.replace('https://', '')}</a>` : '';
    const iconContent = c.icon.length <= 3 ? `<span class="font-bold text-xs ${c.iconColor}">${c.icon}</span>` : `<span class="text-sm">${c.icon}</span>`;

    return `<div class="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/30 border border-slate-100 dark:border-white/[0.03]">
      <div class="w-8 h-8 rounded-lg ${c.iconBg} flex items-center justify-center flex-shrink-0">${iconContent}</div>
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${c.name}</span>
          ${versionBadge}
          ${licenseBadge}
          ${link}
        </div>
        <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">${c.description}</p>
      </div>
    </div>`;
  }).join('');
}

// Render on page load
document.addEventListener('DOMContentLoaded', renderLegalComponents);

// ================================================================
// KILLSWITCH
// ================================================================
let _killswitchActive = false;

async function loadKillswitchState() {
  try {
    const res = await fetch('/api/killswitch');
    if (!res.ok) return;
    const data = await res.json();
    _killswitchActive = data.active;
    renderKillswitchUI(data);
  } catch (e) {
    console.warn('[killswitch] Could not load state:', e);
  }
}

function renderKillswitchUI(data) {
  const card = document.getElementById('killswitch-card');
  const btn = document.getElementById('ks-toggle-btn');
  const icon = document.getElementById('ks-icon');
  const subtitle = document.getElementById('ks-subtitle');
  const failsafeInfo = document.getElementById('ks-failsafe-info');
  if (!card || !btn) return;

  const active = data.active;
  _killswitchActive = active;

  if (active) {
    // KILLSWITCH IS ON — red danger state
    card.className = card.className
      .replace('border-slate-200 dark:border-white/[0.05]', '')
      .replace('border-emerald-400 dark:border-emerald-600', '');
    card.classList.add('border-red-400', 'dark:border-red-600');
    card.style.background = ''; // reset
    card.classList.add('bg-red-50', 'dark:bg-red-950/20');

    icon.className = 'w-10 h-10 rounded-xl bg-red-100 dark:bg-red-900/30 flex items-center justify-center transition-colors';
    icon.innerHTML = '<span class="text-xl">⚠️</span>';

    const since = data.activated_at ? new Date(data.activated_at + 'Z').toLocaleTimeString() : '?';
    const by = data.activated_by === 'auto_failsafe' ? 'auto-failsafe' : 'manual';
    subtitle.textContent = `Active since ${since} (${by})`;
    subtitle.classList.remove('text-slate-400', 'dark:text-slate-500');
    subtitle.classList.add('text-red-500', 'dark:text-red-400');

    btn.textContent = 'Deactivate Killswitch';
    btn.className = 'relative px-5 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 active:scale-95 bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20';

    // Status dots → red
    setKsDot('adguard', 'red', 'passthrough');
    setKsDot('ips', 'red', 'disabled');
    setKsDot('rules', 'red', 'suspended');

    // Show failsafe banner if auto-activated
    if (data.activated_by === 'auto_failsafe') {
      failsafeInfo.classList.remove('hidden');
    } else {
      failsafeInfo.classList.add('hidden');
    }

  } else {
    // KILLSWITCH IS OFF — normal green state
    card.classList.remove('bg-red-50', 'dark:bg-red-950/20', 'border-red-400', 'dark:border-red-600');
    card.classList.add('border-slate-200', 'dark:border-white/[0.05]');
    card.style.background = '';

    icon.className = 'w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center transition-colors';
    icon.innerHTML = '<span class="text-xl">🛡️</span>';

    subtitle.textContent = 'All systems operational';
    subtitle.classList.remove('text-red-500', 'dark:text-red-400');
    subtitle.classList.add('text-slate-400', 'dark:text-slate-500');

    btn.textContent = 'Activate Killswitch';
    btn.className = 'relative px-5 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 active:scale-95 bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/20';

    setKsDot('adguard', 'green', 'filtering');
    setKsDot('ips', 'green', 'active');
    setKsDot('rules', 'green', 'enforced');

    failsafeInfo.classList.add('hidden');
  }
}

function setKsDot(name, color, label) {
  const dot = document.getElementById(`ks-dot-${name}`);
  const lbl = document.getElementById(`ks-label-${name}`);
  if (dot) {
    dot.classList.remove('bg-emerald-500', 'bg-red-500', 'bg-amber-500');
    dot.classList.add(color === 'green' ? 'bg-emerald-500' : color === 'red' ? 'bg-red-500' : 'bg-amber-500');
  }
  if (lbl) {
    lbl.textContent = label;
    lbl.classList.remove('text-emerald-600', 'dark:text-emerald-400', 'text-red-600', 'dark:text-red-400');
    if (color === 'green') {
      lbl.classList.add('text-emerald-600', 'dark:text-emerald-400');
    } else {
      lbl.classList.add('text-red-600', 'dark:text-red-400');
    }
  }
}

async function toggleKillswitch() {
  const newState = !_killswitchActive;
  const action = newState ? 'ACTIVATE' : 'DEACTIVATE';

  // Confirm before activating
  if (newState) {
    if (!confirm(
      '⚠️ ACTIVATE KILLSWITCH?\n\n' +
      'This will:\n' +
      '• Disable AdGuard DNS filtering\n' +
      '• Suspend all block rules\n' +
      '• Disable intrusion prevention\n\n' +
      'Internet traffic will flow unfiltered.\n' +
      'Use this only in emergencies.'
    )) return;
  }

  const btn = document.getElementById('ks-toggle-btn');
  const log = document.getElementById('ks-log');
  btn.disabled = true;
  btn.textContent = newState ? 'Activating…' : 'Deactivating…';

  // Show log
  log.classList.remove('hidden');
  log.innerHTML = `<div class="text-amber-400">▸ ${action} killswitch…</div>`;

  try {
    const res = await fetch('/api/killswitch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({active: newState}),
    });
    const data = await res.json();

    // Render action log
    let logHtml = '';
    for (const a of (data.actions || [])) {
      const icon = a.success ? '<span class="text-emerald-400">✓</span>' : '<span class="text-red-400">✗</span>';
      logHtml += `<div>${icon} ${a.service}: ${a.detail}</div>`;
    }
    log.innerHTML = logHtml;

    // Update UI state
    renderKillswitchUI(data.killswitch || {active: newState});

  } catch (e) {
    log.innerHTML = `<div class="text-red-400">✗ Error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
  }
}

// ================================================================
// HEALTH CHECK
// ================================================================
async function runHealthCheck() {
  const btn = document.getElementById('health-run-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Checking...'; }

  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const services = data.services || [];
    const summary = data.summary || {};

    const statusMap = {
      ok:      { bg: 'bg-emerald-50 dark:bg-emerald-900/20', border: 'border-emerald-200 dark:border-emerald-700/40', text: 'text-emerald-600 dark:text-emerald-400', label: '● Online' },
      warning: { bg: 'bg-amber-50 dark:bg-amber-900/20', border: 'border-amber-200 dark:border-amber-700/40', text: 'text-amber-600 dark:text-amber-400', label: '⚠ Warning' },
      error:   { bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-200 dark:border-red-700/40', text: 'text-red-600 dark:text-red-400', label: '✗ Offline' },
    };

    const cards = document.getElementById('health-cards');
    const allOk = summary.all_ok;
    const bannerBg = allOk ? 'bg-emerald-50 dark:bg-emerald-900/15 border-emerald-200 dark:border-emerald-700/40' : 'bg-amber-50 dark:bg-amber-900/15 border-amber-200 dark:border-amber-700/40';
    const bannerText = allOk
      ? `<span class="text-emerald-600 dark:text-emerald-400 font-medium">All ${summary.total} services healthy</span>`
      : `<span class="text-amber-600 dark:text-amber-400 font-medium">${summary.ok}/${summary.total} healthy</span>`;
    const banner = `<div class="col-span-full ${bannerBg} border rounded-xl p-3 text-center text-sm">${bannerText} — ${new Date().toLocaleTimeString()}</div>`;

    cards.innerHTML = banner + services.map(s => {
      const c = statusMap[s.status] || statusMap.error;
      // Determine if this service can be restarted
      let restartBtn = '';
      if (s.service === 'Zeek (Packet Capture)') {
        restartBtn = `<button onclick="restartService('zeek', this)" class="mt-2 w-full px-2 py-1 rounded-lg text-[10px] font-medium transition-colors
          ${s.status !== 'ok' ? 'bg-indigo-600 hover:bg-indigo-500 text-white' : 'bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300'}">
          ${s.status !== 'ok' ? '⚡ Restart Zeek' : '↻ Restart'}</button>`;
      } else if (s.service === 'Zeek Tailer') {
        restartBtn = `<button onclick="restartService('tailer', this)" class="mt-2 w-full px-2 py-1 rounded-lg text-[10px] font-medium transition-colors
          ${s.status !== 'ok' ? 'bg-indigo-600 hover:bg-indigo-500 text-white' : 'bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300'}">
          ${s.status !== 'ok' ? '⚡ Restart Tailer' : '↻ Restart'}</button>`;
      } else if (s.service.startsWith('Zeek ') && s.service.endsWith('.log') && s.status !== 'ok') {
        restartBtn = `<button onclick="restartService('zeek', this)" class="mt-2 w-full px-2 py-1 rounded-lg text-[10px] font-medium bg-amber-600 hover:bg-amber-500 text-white transition-colors">⚡ Restart Zeek</button>`;
      }
      return `<div class="${c.bg} border ${c.border} rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-lg">${s.icon}</span>
          <span class="text-[10px] px-2 py-0.5 rounded ${c.bg} ${c.text} font-semibold">${c.label}</span>
        </div>
        <p class="text-sm font-medium text-slate-700 dark:text-slate-200">${s.service}</p>
        <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-1">${s.details}</p>
        ${s.response_ms > 0 ? `<p class="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">${s.response_ms}ms</p>` : ''}
        ${restartBtn}
      </div>`;
    }).join('');

    // Details table
    const details = document.getElementById('health-details');
    details.classList.remove('hidden');
    const tbody = document.getElementById('health-tbody');
    tbody.innerHTML = services.map(s => {
      const c = statusMap[s.status] || statusMap.error;
      return `<tr class="border-b border-slate-100 dark:border-white/[0.04]">
        <td class="py-2.5 px-3 text-sm"><span class="mr-2">${s.icon}</span>${s.service}</td>
        <td class="py-2.5 px-3"><span class="text-[10px] px-2 py-0.5 rounded ${c.bg} ${c.text} font-semibold">${c.label}</span></td>
        <td class="py-2.5 px-3 text-xs tabular-nums text-slate-400">${s.response_ms > 0 ? s.response_ms + ' ms' : '—'}</td>
        <td class="py-2.5 px-3 text-xs text-slate-500 dark:text-slate-400">${s.details}</td>
      </tr>`;
    }).join('');

  } catch(err) {
    const cards = document.getElementById('health-cards');
    cards.innerHTML = `<div class="col-span-full bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 rounded-xl p-6 text-center">
      <p class="text-red-600 dark:text-red-400 font-medium">Health check failed</p>
      <p class="text-sm text-slate-500 mt-1">${err.message}</p>
    </div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Check'; }
  }
}

// ================================================================
// SERVICE RESTART
// ================================================================
async function restartService(service, btn) {
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Restarting...';
  btn.className = btn.className.replace(/bg-\S+/g, 'bg-slate-500').replace(/hover:\S+/g, '');

  try {
    const res = await fetch(`/api/services/${service}/restart`, { method: 'POST' });
    const data = await res.json();

    if (data.status === 'ok') {
      btn.textContent = '✓ ' + data.message;
      btn.className = btn.className.replace(/bg-slate-500/g, 'bg-emerald-600');
      // Re-run health check after a moment
      setTimeout(() => runHealthCheck(), 2000);
    } else {
      btn.textContent = '✗ ' + data.message;
      btn.className = btn.className.replace(/bg-slate-500/g, 'bg-red-600');
      btn.disabled = false;
    }
  } catch (err) {
    btn.textContent = '✗ Failed: ' + err.message;
    btn.className = btn.className.replace(/bg-slate-500/g, 'bg-red-600');
    btn.disabled = false;
  }
}

// ================================================================
// MANUAL REFRESH
// ================================================================
function updateRefreshTimestamp() {
  const el = document.getElementById('last-refresh');
  if (el) el.textContent = new Date().toLocaleTimeString();
}

async function manualRefresh() {
  const btn = document.getElementById('refresh-btn');
  const icon = document.getElementById('refresh-icon');
  if (btn) { btn.disabled = true; btn.classList.add('opacity-60'); }
  if (icon) icon.classList.add('animate-spin');

  try {
    await loadDevices();
    await refreshPage(currentPage);
    updateRefreshTimestamp();
  } catch(err) { console.error('Refresh error:', err); }
  finally {
    if (btn) { btn.disabled = false; btn.classList.remove('opacity-60'); }
    if (icon) icon.classList.remove('animate-spin');
  }
}

// ================================================================
// INIT
// ================================================================
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  initSidebar();
  await loadDevices();
  initRouter();
  updateRefreshTimestamp();

  // Quick health check for top bar
  try {
    const h = await fetch('/api/health').then(r => r.json());
    const dot = document.getElementById('status-dot');
    const txt = document.getElementById('status-text');
    if (h.summary?.all_ok) {
      dot.className = 'w-2 h-2 rounded-full bg-emerald-500';
      txt.textContent = 'All Systems Operational';
    } else {
      const issues = h.summary.total - h.summary.ok;
      dot.className = 'w-2 h-2 rounded-full bg-amber-500';
      txt.textContent = `${issues} Issue${issues > 1 ? 's' : ''}`;
    }
  } catch(e) {
    document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-red-500';
    document.getElementById('status-text').textContent = 'Connection Error';
  }
});
