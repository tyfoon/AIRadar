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

  // Resize all charts after sidebar transition completes (250ms CSS transition)
  setTimeout(() => {
    Object.values(charts).forEach(c => c.resize());
    if (sankeyInstance) sankeyInstance.resize();
  }, 300);
}

function initSidebar() {
  if (localStorage.getItem('airadar-sidebar') === 'collapsed') toggleSidebar();
}

function toggleMobileSidebar() {
  // For mobile, we could show the sidebar as an overlay — for now, just navigate
}

// ================================================================
// MOBILE NAV — Overflow panel + badges
// ================================================================
function toggleMobOverflow() {
  const panel = document.getElementById('mob-overflow');
  if (panel) panel.classList.toggle('hidden');
}

function closeMobOverflow() {
  const panel = document.getElementById('mob-overflow');
  if (panel) panel.classList.add('hidden');
}

function _updateMobileBadges() {
  // IPS badge in overflow
  const mobIps = document.getElementById('mob-badge-ips');
  if (mobIps) {
    if (_navIpsCount > 0) {
      mobIps.textContent = _navIpsCount > 99 ? '99+' : String(_navIpsCount);
      mobIps.classList.remove('hidden');
    } else {
      mobIps.classList.add('hidden');
    }
  }

  // Settings badge in overflow
  const mobSettings = document.getElementById('mob-badge-settings');
  if (mobSettings) {
    if (_killswitchActive) {
      mobSettings.classList.remove('hidden');
    } else {
      mobSettings.classList.add('hidden');
    }
  }

  // "More" button dot: show if any overflow item has a badge
  const mobMore = document.getElementById('mob-badge-more');
  if (mobMore) {
    const hasAny = _navIpsCount > 0 || _killswitchActive;
    mobMore.classList.toggle('hidden', !hasAny);
  }
}

// ================================================================
// TREND INDICATOR — ready for backend comparison data
// ================================================================
// TODO: The backend does not yet provide historical comparison data.
// When available (e.g. via /api/stats/comparison returning { devices_yesterday,
// events_yesterday, blocked_yesterday }), call renderTrend() to populate
// the trend indicator divs on the dashboard stat cards.
//
// Parameters:
//   elementId      – the ID of the trend <div> container (e.g. 'dash-devices-trend')
//   current        – today's value
//   previous       – yesterday's value (null/undefined to skip)
//   higherIsBetter – true if an increase is positive (e.g. blocked threats),
//                    false if an increase is concerning (e.g. events/attacks)
function renderTrend(elementId, current, previous, higherIsBetter) {
  const el = document.getElementById(elementId);
  if (!el || previous == null || previous === undefined) return;

  const diff = current - previous;
  if (diff === 0) {
    el.innerHTML = `<span class="text-[11px] text-slate-400 dark:text-slate-500">${t('dash.trendFlat')}</span>`;
    el.classList.remove('hidden');
    return;
  }

  const pct = previous > 0 ? Math.abs((diff / previous) * 100).toFixed(1) : 0;
  const isUp = diff > 0;
  const isPositive = (isUp && higherIsBetter) || (!isUp && !higherIsBetter);
  const colorClass = isPositive
    ? 'text-emerald-600 dark:text-emerald-400'
    : 'text-red-600 dark:text-red-400';
  const key = isUp ? 'dash.trendUp' : 'dash.trendDown';

  el.innerHTML = `<span class="text-[11px] font-medium ${colorClass}">${t(key, { pct })}</span>`;
  el.classList.remove('hidden');
}

// Scroll to the Latest Alarms section on the dashboard
function scrollToAlarms() {
  const section = document.getElementById('dash-alarms-section');
  if (section) {
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    // Brief highlight flash
    section.classList.add('ring-2', 'ring-indigo-400/50');
    setTimeout(() => section.classList.remove('ring-2', 'ring-indigo-400/50'), 1500);
  }
}

// ================================================================
// NAV BADGES
// ================================================================
let _navIpsCount = 0;

function updateNavBadges() {
  // Attacks badge: show count when threats blocked > 0
  const ipsBadge = document.getElementById('nav-badge-ips');
  if (ipsBadge) {
    if (_navIpsCount > 0) {
      ipsBadge.textContent = _navIpsCount > 99 ? '99+' : String(_navIpsCount);
      ipsBadge.classList.remove('hidden');
    } else {
      ipsBadge.classList.add('hidden');
    }
  }

  // Settings badge: red dot when killswitch is active
  const settingsBadge = document.getElementById('nav-badge-settings');
  if (settingsBadge) {
    if (_killswitchActive) {
      settingsBadge.classList.remove('hidden');
    } else {
      settingsBadge.classList.add('hidden');
    }
  }

  // Mobile nav badges
  _updateMobileBadges();
}

// ================================================================
// NAVIGATION / ROUTING
// ================================================================
const VALID_PAGES = ['summary','dashboard','ai','cloud','privacy','iot','other','geo','devices','ips','rules','settings'];

let currentPage = 'summary';

function navigate(page) {
  if (!VALID_PAGES.includes(page)) page = 'summary';
  currentPage = page;

  // Close mobile overflow panel if open
  closeMobOverflow();

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
    const raw = location.hash.replace('#/', '') || 'summary';
    _routeFromHash(raw);
  });
  const initial = location.hash.replace('#/', '') || 'summary';
  _routeFromHash(initial);
}

function _routeFromHash(raw) {
  // Handle settings sub-tabs: settings/system, settings/about, settings/protection
  if (raw.startsWith('settings')) {
    const parts = raw.split('/');
    navigate('settings');
    const subTab = parts[1] || 'protection';
    switchSettingsTab(subTab);
    _initThemeSelect();
  } else {
    navigate(raw);
  }
}

// ================================================================
// SERVICE & COLOR CONSTANTS
// ================================================================
const ACCENT_COLORS = ['#6366f1','#22d3ee','#f59e0b','#ef4444','#10b981','#ec4899','#8b5cf6','#f97316','#14b8a6','#e11d48'];

const SERVICE_COLORS = {
  google_gemini:'#f59e0b', openai:'#10b981', anthropic_claude:'#6366f1',
  microsoft_copilot:'#3b82f6', perplexity:'#22d3ee', huggingface:'#f97316',
  mistral:'#8b5cf6', dropbox:'#3b82f6', wetransfer:'#14b8a6',
  google_drive:'#22c55e', google_device_sync:'#14b8a6', google_generic_cdn:'#94a3b8',
  onedrive:'#0ea5e9', icloud:'#6b7280',
  box:'#60a5fa', mega:'#ef4444',
  // VPN
  vpn_active:'#f97316', vpn_nordvpn:'#4687ff', vpn_expressvpn:'#da3940',
  vpn_surfshark:'#1cbdb4', vpn_protonvpn:'#6d4aff', vpn_pia:'#4bb543',
  vpn_cyberghost:'#ffd400', vpn_mullvad:'#294d73', vpn_ipvanish:'#70bb44',
  vpn_tunnelbear:'#ffc600', vpn_windscribe:'#1a5276', vpn_cloudflare_warp:'#f48120',
  // Social
  facebook:'#1877f2', instagram:'#e4405f', tiktok:'#010101', snapchat:'#fffc00',
  twitter:'#1da1f2', pinterest:'#e60023', linkedin:'#0a66c2', reddit:'#ff4500',
  tumblr:'#35465c', whatsapp:'#25d366', signal:'#3a76f0',
  // Gaming
  steam:'#1b2838', epic_games:'#2f2d2e', roblox:'#e2231a', ea_games:'#000000',
  xbox_live:'#107c10', playstation:'#003791', nintendo:'#e60012',
  twitch:'#9146ff', discord:'#5865f2',
  // Streaming
  netflix:'#e50914', youtube:'#ff0000', spotify:'#1db954', disney_plus:'#113ccf',
  hbo_max:'#5822b4', prime_video:'#00a8e1', apple_tv:'#000000',
};

const SERVICE_NAMES = {
  // AI
  openai:'OpenAI', anthropic_claude:'Claude', google_gemini:'Gemini',
  microsoft_copilot:'Copilot', perplexity:'Perplexity', huggingface:'Hugging Face',
  mistral:'Mistral',
  // Cloud
  dropbox:'Dropbox', wetransfer:'WeTransfer', google_drive:'Google Drive',
  google_device_sync:'Google Device Sync', google_generic_cdn:'Google Cloud (CDN)',
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
  // Social
  facebook:'Facebook', instagram:'Instagram', tiktok:'TikTok',
  twitter:'X (Twitter)', snapchat:'Snapchat', pinterest:'Pinterest',
  linkedin:'LinkedIn', reddit:'Reddit', tumblr:'Tumblr',
  whatsapp:'WhatsApp', signal:'Signal',
  // Gaming
  steam:'Steam', epic_games:'Epic Games', roblox:'Roblox', ea_games:'EA Games',
  xbox_live:'Xbox Live', playstation:'PlayStation', nintendo:'Nintendo',
  twitch:'Twitch', discord:'Discord',
  // Streaming
  netflix:'Netflix', youtube:'YouTube', spotify:'Spotify', disney_plus:'Disney+',
  hbo_max:'HBO Max', prime_video:'Prime Video', apple_tv:'Apple TV+',
};

// Domain mapping for Clearbit logos
const SERVICE_LOGO_DOMAIN = {
  // AI services
  openai:'openai.com', anthropic_claude:'anthropic.com', google_gemini:'google.com',
  microsoft_copilot:'microsoft.com', perplexity:'perplexity.ai', huggingface:'huggingface.co',
  mistral:'mistral.ai',
  // Cloud services
  dropbox:'dropbox.com', wetransfer:'wetransfer.com', google_drive:'google.com',
  google_device_sync:'google.com', google_generic_cdn:'google.com',
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
  // Social
  whatsapp:'whatsapp.com', signal:'signal.org', tumblr:'tumblr.com',
  // Gaming
  ea_games:'ea.com',
  // Streaming
  netflix:'netflix.com', youtube:'youtube.com', spotify:'spotify.com',
  disney_plus:'disneyplus.com', hbo_max:'max.com', prime_video:'primevideo.com', apple_tv:'apple.com',
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

// ---------------------------------------------------------------------------
// Junk hostname filter — mirrors _is_junk_hostname in api.py / zeek_tailer.py.
// Catches UUIDs, long hex IDs (Spotify/Lumi), reverse-DNS PTRs, placeholders.
// ---------------------------------------------------------------------------
const _JUNK_HOSTNAME_LITERALS = new Set([
  '', '(empty)', '(null)', 'null', 'none', 'unknown',
  'localhost', 'localhost.localdomain',
  'espressif', 'esp32', 'esp8266', 'esp-device',
]);
const _UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const _HEX_ID_RE = /^[0-9a-f]{16,}$/;

function _isJunkHostname(name) {
  if (!name || typeof name !== 'string') return true;
  const s = name.trim().toLowerCase();
  if (_JUNK_HOSTNAME_LITERALS.has(s)) return true;
  if (s.endsWith('.in-addr.arpa') || s.endsWith('.ip6.arpa')) return true;
  if (_UUID_RE.test(s)) return true;
  if (_HEX_ID_RE.test(s)) return true;
  return false;
}

function _shortVendor(vendor) {
  if (!vendor) return null;
  return vendor
    .replace(/,?\s*(inc\.?|ltd\.?|corp\.?|corporation|limited|co\.?|llc|b\.v\.?|ag|gmbh)$/i, '')
    .trim();
}

function _vendorFallbackName(device) {
  // Build a friendly "Vendor device (xx:yy)" label from MAC + vendor.
  // When a JA4 TLS fingerprint label is available, prefer that over the
  // generic "device" wording (e.g. "Apple Safari (a2:3e)").
  if (!device) return null;
  const macTail = (device.mac_address || '').split(':').slice(-2).join(':') || '??';
  const vendor = _shortVendor(device.vendor);
  if (device.ja4_label) {
    return `${device.ja4_label} (${macTail})`;
  }
  if (vendor) {
    return `${vendor} device (${macTail})`;
  }
  return `Device ${macTail}`;
}

function deviceName(ip) {
  const d = _deviceByIp(ip);
  if (!d) return ip;
  return _bestDeviceName(d.mac_address, d);
}

function deviceLabel(ip) {
  const d = _deviceByIp(ip);
  if (!d) return ip;
  const name = _bestDeviceName(d.mac_address, d);
  const vendor = d.vendor ? `<span class="text-[10px] text-slate-400 dark:text-slate-500 ml-1">(${d.vendor})</span>` : '';
  return name + vendor;
}

function _latestIp(device) {
  if (!device.ips || device.ips.length === 0) return device.mac_address;
  // Prefer IPv4 over IPv6 for display (IPv6 is unreadable as a label)
  const ipv4 = device.ips.find(i => !i.ip.includes(':'));
  if (ipv4) return ipv4.ip;
  return device.ips[0].ip;
}

function _ipSummary(device) {
  if (!device.ips || device.ips.length === 0) return '';
  const latest = device.ips[0].ip;
  if (device.ips.length === 1) return latest;
  return `${latest} <span class="text-[10px] text-slate-400 dark:text-slate-500">(+${device.ips.length - 1} other${device.ips.length > 2 ? 's' : ''})</span>`;
}

// Device type detection from hostname + vendor
// -----------------------------------------------------------------------
// Device type icons — Phosphor Icons (duotone weight).
// Each icon is an HTML string that must be injected via innerHTML
// (NOT textContent) because <i class="ph-duotone ph-..."> is an HTML tag.
// The `type` field remains a plain string (used in titles / tooltips).
// -----------------------------------------------------------------------
const PH_ICON = {
  phone:    '<i class="ph-duotone ph-device-mobile text-xl"></i>',
  tablet:   '<i class="ph-duotone ph-device-tablet text-xl"></i>',
  laptop:   '<i class="ph-duotone ph-laptop text-xl"></i>',
  desktop:  '<i class="ph-duotone ph-desktop text-xl"></i>',
  tv:       '<i class="ph-duotone ph-television text-xl"></i>',
  speaker:  '<i class="ph-duotone ph-speaker-hifi text-xl"></i>',
  printer:  '<i class="ph-duotone ph-printer text-xl"></i>',
  router:   '<i class="ph-duotone ph-router text-xl"></i>',
  netswitch:'<i class="ph-duotone ph-swap text-xl"></i>',
  ap:       '<i class="ph-duotone ph-wifi-high text-xl"></i>',
  console:  '<i class="ph-duotone ph-game-controller text-xl"></i>',
  camera:   '<i class="ph-duotone ph-video-camera text-xl"></i>',
  watch:    '<i class="ph-duotone ph-watch text-xl"></i>',
  nas:      '<i class="ph-duotone ph-hard-drives text-xl"></i>',
  server:   '<i class="ph-duotone ph-hard-drives text-xl"></i>',
  home:     '<i class="ph-duotone ph-house-line text-xl"></i>',
  doorbell: '<i class="ph-duotone ph-bell-ringing text-xl"></i>',
  smoke:    '<i class="ph-duotone ph-fire text-xl"></i>',
  vacuum:   '<i class="ph-duotone ph-broom text-xl"></i>',
  washer:   '<i class="ph-duotone ph-washing-machine text-xl"></i>',
  dryer:    '<i class="ph-duotone ph-wind text-xl"></i>',
  airco:    '<i class="ph-duotone ph-thermometer text-xl"></i>',
  blinds:   '<i class="ph-duotone ph-blinds text-xl"></i>',
  light:    '<i class="ph-duotone ph-lightbulb text-xl"></i>',
  energy:   '<i class="ph-duotone ph-lightning text-xl"></i>',
  water:    '<i class="ph-duotone ph-drop text-xl"></i>',
  ereader:  '<i class="ph-duotone ph-book-open text-xl"></i>',
  avr:      '<i class="ph-duotone ph-speaker-simple-high text-xl"></i>',
  alarm:    '<i class="ph-duotone ph-alarm text-xl"></i>',
  remote:   '<i class="ph-duotone ph-remote text-xl"></i>',
  led:      '<i class="ph-duotone ph-palette text-xl"></i>',
  zigbee:   '<i class="ph-duotone ph-bluetooth text-xl"></i>',
  sensor:   '<i class="ph-duotone ph-thermometer text-xl"></i>',
  health:   '<i class="ph-duotone ph-heartbeat text-xl"></i>',
  iot:      '<i class="ph-duotone ph-robot text-xl"></i>',
  unknown:  '<i class="ph-duotone ph-question text-xl"></i>',
  device:   '<i class="ph-duotone ph-circuitry text-xl"></i>',
};

// Device classification by hostname / vendor / display_name.
// Rules are evaluated top-to-bottom; first match wins. Put specific
// patterns (brand+model) above generic ones (category keywords).
const DEVICE_TYPES = [
  // ── Apple ──────────────────────────────────────────────
  { match: /macbook/i,                         icon: PH_ICON.laptop,  type: 'MacBook' },
  { match: /imac/i,                            icon: PH_ICON.desktop, type: 'iMac' },
  { match: /mac[\s-]?pro/i,                    icon: PH_ICON.desktop, type: 'Mac Pro' },
  { match: /mac[\s-]?mini/i,                   icon: PH_ICON.desktop, type: 'Mac mini' },
  { match: /mac[\s-]?studio/i,                 icon: PH_ICON.desktop, type: 'Mac Studio' },
  { match: /iphone/i,                          icon: PH_ICON.phone,   type: 'iPhone' },
  { match: /ipad/i,                            icon: PH_ICON.tablet,  type: 'iPad' },
  { match: /apple[\s-]?tv/i,                   icon: PH_ICON.tv,      type: 'Apple TV' },
  { match: /homepod/i,                         icon: PH_ICON.speaker, type: 'HomePod' },
  { match: /apple[\s-]?watch/i,                icon: PH_ICON.watch,   type: 'Apple Watch' },
  // ── Android / Google phones ────────────────────────────
  { match: /pixel[\s-]?\d/i,                   icon: PH_ICON.phone,   type: 'Pixel' },
  { match: /galaxy|samsung/i,                  icon: PH_ICON.phone,   type: 'Samsung' },
  { match: /honor[\s-]?magic[\s-]?pad/i,       icon: PH_ICON.tablet,  type: 'HONOR Tablet' },
  { match: /honor/i,                           icon: PH_ICON.phone,   type: 'HONOR' },
  { match: /huawei|hw\d{2}/i,                  icon: PH_ICON.phone,   type: 'Huawei' },
  // ── Google Smart Home ──────────────────────────────────
  { match: /google[\s-]?home[\s-]?mini/i,      icon: PH_ICON.speaker, type: 'Google Home Mini' },
  { match: /google[\s-]?home/i,                icon: PH_ICON.speaker, type: 'Google Home' },
  { match: /nest[\s-]?hello/i,                 icon: PH_ICON.doorbell,type: 'Nest Doorbell' },
  { match: /nest[\s-]?protect/i,               icon: PH_ICON.smoke,   type: 'Nest Protect' },
  { match: /nest[\s-]?hub/i,                   icon: PH_ICON.tv,      type: 'Nest Hub' },
  { match: /nest[\s-]?cam/i,                   icon: PH_ICON.camera,  type: 'Nest Cam' },
  { match: /fuchsia-/i,                        icon: PH_ICON.tv,      type: 'Nest Hub' },
  { match: /nest/i,                            icon: PH_ICON.home,    type: 'Nest' },
  { match: /chromecast/i,                      icon: PH_ICON.tv,      type: 'Chromecast' },
  // ── Smart TVs ──────────────────────────────────────────
  { match: /lgwebostv/i,                       icon: PH_ICON.tv,      type: 'LG Smart TV' },
  { match: /bravia|sony[\s-]?tv/i,             icon: PH_ICON.tv,      type: 'Sony TV' },
  { match: /samsung[\s-]?tv|tizen/i,           icon: PH_ICON.tv,      type: 'Samsung TV' },
  { match: /roku/i,                            icon: PH_ICON.tv,      type: 'Roku' },
  { match: /fire[\s-]?stick/i,                 icon: PH_ICON.tv,      type: 'Fire TV Stick' },
  // ── Audio / AV ─────────────────────────────────────────
  { match: /sonos|SonosZP/i,                   icon: PH_ICON.speaker, type: 'Sonos Speaker' },
  { match: /denon[\s-]?avr/i,                  icon: PH_ICON.avr,     type: 'Denon AV Receiver' },
  { match: /marantz/i,                         icon: PH_ICON.avr,     type: 'Marantz AV Receiver' },
  { match: /hue[\s-]?sync[\s-]?box/i,          icon: PH_ICON.light,   type: 'Hue Sync Box' },
  { match: /harmony[\s-]?hub/i,                icon: PH_ICON.remote,  type: 'Harmony Hub' },
  // ── Smart Home / IoT — specific brands ─────────────────
  { match: /airthings/i,                       icon: PH_ICON.sensor,  type: 'Air Quality Monitor' },
  { match: /dreame[\s_]?vacuum|roborock/i,     icon: PH_ICON.vacuum,  type: 'Robot Vacuum' },
  { match: /roomba|irobot/i,                   icon: PH_ICON.vacuum,  type: 'Robot Vacuum' },
  { match: /bosch[\s-]?dryer/i,                icon: PH_ICON.dryer,   type: 'Smart Dryer' },
  { match: /bosch[\s-]?wash/i,                 icon: PH_ICON.washer,  type: 'Smart Washer' },
  { match: /disp[\s-]?dish/i,                  icon: PH_ICON.washer,  type: 'Smart Dishwasher' },
  { match: /disp[\s-]?wash/i,                  icon: PH_ICON.washer,  type: 'Smart Washer' },
  { match: /SC07-WX|XS01-WX|XC0C-iR/i,        icon: PH_ICON.blinds,  type: 'Somfy Blinds' },
  { match: /slide[\s_]/i,                      icon: PH_ICON.blinds,  type: 'Slide Curtains' },
  { match: /myenergi/i,                        icon: PH_ICON.energy,  type: 'Energy Monitor' },
  { match: /P1[\s-]?Eport|p1[\s-]?meter/i,    icon: PH_ICON.energy,  type: 'P1 Energy Meter' },
  { match: /SmartGateways[\s-]?Watermeter/i,   icon: PH_ICON.water,   type: 'Water Meter' },
  { match: /home[\s-]?assistant/i,             icon: PH_ICON.home,    type: 'Home Assistant' },
  { match: /wled[\s-]/i,                       icon: PH_ICON.led,     type: 'WLED LED' },
  { match: /awtrix/i,                          icon: PH_ICON.led,     type: 'Awtrix Pixel Clock' },
  { match: /nspanel/i,                         icon: PH_ICON.home,    type: 'Sonoff NSPanel' },
  { match: /loftie/i,                          icon: PH_ICON.alarm,   type: 'Smart Alarm Clock' },
  { match: /withings/i,                        icon: PH_ICON.health,  type: 'Health Monitor' },
  { match: /presence[\s-]?sensor/i,            icon: PH_ICON.sensor,  type: 'Presence Sensor' },
  { match: /camera[\s-]?hub/i,                 icon: PH_ICON.camera,  type: 'Camera Hub' },
  { match: /SLZB|zigbee[\s-]?coord/i,          icon: PH_ICON.zigbee,  type: 'Zigbee Coordinator' },
  { match: /_ac$|[\s-]ac$/i,                   icon: PH_ICON.airco,   type: 'Smart Airco' },
  // ── Networking ─────────────────────────────────────────
  { match: /USW[\s-]/i,                        icon: PH_ICON.netswitch, type: 'Ubiquiti Switch' },
  { match: /U7[\s-]|UAP[\s-]/i,               icon: PH_ICON.ap,      type: 'Ubiquiti AP' },
  { match: /Switch\d+p|switch.*beneden|switch.*boven/i, icon: PH_ICON.netswitch, type: 'Network Switch' },
  { match: /ubiquiti|unifi/i,                  icon: PH_ICON.router,  type: 'Ubiquiti' },
  // ── Generic patterns (AFTER specific brands) ───────────
  { match: /frigate/i,                         icon: PH_ICON.camera,  type: 'Frigate NVR' },
  { match: /caddy|pihole|server/i,             icon: PH_ICON.server,  type: 'Home Server' },
  { match: /raspberry[\s-]?pi/i,               icon: PH_ICON.server,  type: 'Raspberry Pi' },
  { match: /surface/i,                         icon: PH_ICON.laptop,  type: 'Surface' },
  { match: /kobo/i,                            icon: PH_ICON.ereader, type: 'E-reader' },
  { match: /BRN[A-F0-9]|brother/i,            icon: PH_ICON.printer, type: 'Printer' },
  { match: /printer|epson|hp[\s-]?print|canon/i, icon: PH_ICON.printer, type: 'Printer' },
  { match: /ds[\s-]?2cd|hikvision/i,           icon: PH_ICON.camera,  type: 'IP Camera' },
  { match: /camera|cam\b/i,                    icon: PH_ICON.camera,  type: 'IP Camera' },
  { match: /tv\b|television/i,                 icon: PH_ICON.tv,      type: 'TV/Media' },
  { match: /playstation|ps[45]/i,              icon: PH_ICON.console, type: 'PlayStation' },
  { match: /xbox/i,                            icon: PH_ICON.console, type: 'Xbox' },
  { match: /nintendo/i,                        icon: PH_ICON.console, type: 'Nintendo' },
  { match: /nas|synology|qnap/i,               icon: PH_ICON.nas,     type: 'NAS' },
  { match: /router|gateway/i,                  icon: PH_ICON.router,  type: 'Router' },
  { match: /access[\s-]?point|ap\b/i,          icon: PH_ICON.ap,      type: 'Access Point' },
  { match: /hue|signify|philips[\s-]?light/i,  icon: PH_ICON.light,   type: 'Smart Lighting' },
  { match: /smart[\s-]?home|iot/i,             icon: PH_ICON.home,    type: 'Smart Home' },
  { match: /thermostat/i,                      icon: PH_ICON.airco,   type: 'Thermostat' },
  { match: /ESP[\s_][A-F0-9]|espressif/i,      icon: PH_ICON.iot,     type: 'IoT Device' },
  { match: /android/i,                         icon: PH_ICON.phone,   type: 'Android' },
  { match: /windows|desktop[\s-]?[a-z]/i,      icon: PH_ICON.desktop, type: 'PC' },
  { match: /laptop|notebook/i,                 icon: PH_ICON.laptop,  type: 'Laptop' },
];

function _detectDeviceType(device) {
  if (!device) return { icon: PH_ICON.unknown, type: 'Unknown' };
  const haystack = [device.hostname, device.vendor, device.display_name].filter(Boolean).join(' ');
  for (const dt of DEVICE_TYPES) {
    if (dt.match.test(haystack)) return dt;
  }
  // DHCP vendor_class — strongest IoT signal (set by the device's own
  // DHCP client, can't be faked by hostname spoofing)
  const dvc = (device.dhcp_vendor_class || '').toLowerCase();
  if (dvc.startsWith('android-dhcp'))   return { icon: PH_ICON.phone,   type: 'Android' };
  if (dvc === 'ubnt')                    return { icon: PH_ICON.router,  type: 'Ubiquiti' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('marvell'))
                                          return { icon: PH_ICON.speaker, type: 'Google Home' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('bcm2835'))
                                          return { icon: PH_ICON.server,  type: 'Raspberry Pi' };
  if (dvc.startsWith('dhcpcd') && dvc.includes('freescale'))
                                          return { icon: PH_ICON.ereader, type: 'E-reader' };
  if (dvc.startsWith('udhcp'))           return { icon: PH_ICON.iot,     type: 'IoT Device' };

  // p0f device_class fallback
  if (device.device_class) {
    const dc = device.device_class.toLowerCase();
    if (dc === 'phone')    return { icon: PH_ICON.phone,   type: 'Phone' };
    if (dc === 'tablet')   return { icon: PH_ICON.tablet,  type: 'Tablet' };
    if (dc === 'laptop')   return { icon: PH_ICON.laptop,  type: 'Laptop' };
    if (dc === 'computer') return { icon: PH_ICON.desktop, type: 'Computer' };
    if (dc === 'server')   return { icon: PH_ICON.server,  type: 'Server' };
    if (dc === 'iot')      return { icon: PH_ICON.iot,     type: 'IoT Device' };
  }
  // Vendor-based fallback — broadest net, least specific
  if (device.vendor) {
    const v = device.vendor.toLowerCase();
    if (v.includes('espressif'))  return { icon: PH_ICON.iot,      type: 'IoT Device' };
    if (v.includes('hikvision'))  return { icon: PH_ICON.camera,   type: 'IP Camera' };
    if (v.includes('nest'))       return { icon: PH_ICON.home,     type: 'Nest' };
    if (v.includes('sonos'))      return { icon: PH_ICON.speaker,  type: 'Sonos Speaker' };
    if (v.includes('signify') || v.includes('philips lighting'))
                                   return { icon: PH_ICON.light,   type: 'Smart Lighting' };
    if (v.includes('lumi'))       return { icon: PH_ICON.home,     type: 'Aqara Smart Home' };
    if (v.includes('withings'))   return { icon: PH_ICON.health,   type: 'Health Monitor' };
    if (v.includes('xiaomi'))     return { icon: PH_ICON.home,     type: 'Xiaomi Smart Home' };
    if (v.includes('myenergi'))   return { icon: PH_ICON.energy,   type: 'Energy Monitor' };
    if (v.includes('resideo') || v.includes('honeywell'))
                                   return { icon: PH_ICON.airco,   type: 'Thermostat' };
    if (v.includes('brother'))    return { icon: PH_ICON.printer,  type: 'Printer' };
    if (v.includes('d&m') || v.includes('denon') || v.includes('marantz'))
                                   return { icon: PH_ICON.avr,     type: 'AV Receiver' };
    if (v.includes('logitech'))   return { icon: PH_ICON.remote,   type: 'Logitech' };
    if (v.includes('kobo'))       return { icon: PH_ICON.ereader,  type: 'E-reader' };
    if (v.includes('apple'))      return { icon: PH_ICON.laptop,   type: 'Apple Device' };
    if (v.includes('samsung'))    return { icon: PH_ICON.phone,    type: 'Samsung' };
    if (v.includes('google'))     return { icon: PH_ICON.home,     type: 'Google Device' };
    if (v.includes('microsoft'))  return { icon: PH_ICON.laptop,   type: 'Microsoft' };
    if (v.includes('ring'))       return { icon: PH_ICON.doorbell, type: 'Doorbell' };
    if (v.includes('ubiquiti'))   return { icon: PH_ICON.router,   type: 'Ubiquiti' };
    if (v.includes('sercomm'))    return { icon: PH_ICON.router,   type: 'Gateway' };
    if (v.includes('tp-link') || v.includes('tplink'))
                                   return { icon: PH_ICON.router,  type: 'Network' };
    if (v.includes('texas instruments') || v.includes('shanghai high'))
                                   return { icon: PH_ICON.iot,     type: 'IoT Device' };
    if (v.includes('raspberry'))  return { icon: PH_ICON.server,   type: 'Raspberry Pi' };
    if (v.includes('intel') || v.includes('dell') || v.includes('lenovo') || v.includes('hp ') || v.includes('asrock') || v.includes('elitegroup'))
                                   return { icon: PH_ICON.desktop,  type: 'Computer' };
  }
  return { icon: PH_ICON.device, type: 'Device' };
}

// Large device type icon (20x20) for device matrix
function _deviceTypeIcon20(dt) {
  return `<span class="inline-flex items-center justify-center w-5 h-5 text-base leading-none flex-shrink-0" title="${dt.type}">${dt.icon}</span>`;
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
    const distText = device.network_distance != null ? ` · ${device.network_distance} ${device.network_distance !== 1 ? t('dev.hops') : t('dev.hop')}` : '';
    osBadge = `<span class="ml-1 px-1.5 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 text-[9px] font-medium">${osIcon} ${osLabel}${distText}</span>`;
  }

  return `<span class="inline-flex items-center gap-1.5 text-[10px] text-slate-400 dark:text-slate-500">${_deviceTypeIcon20(dt)} ${dt.type}${vendorText}</span>${osBadge}`;
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
    // Populate device filter dropdowns — shared helper ensures consistent
    // names and comma-separated IP values across all insight pages.
    ['ai-filter-device', 'cloud-filter-device'].forEach(_populateDeviceFilter);
  } catch(e) { console.error('loadDevices:', e); }
}

// Inline device rename — opens an input field in-place
function _startDeviceRename(mac) {
  const safeMac = mac.replace(/[^a-zA-Z0-9]/g, '_');
  const container = document.getElementById('dev-name-row-' + safeMac);
  if (!container) return;
  const dev = deviceMap[mac] || null;
  const currentName = _bestDeviceName(mac, dev);

  // Replace content with inline edit form
  container.innerHTML = `
    <form onsubmit="event.preventDefault();_saveDeviceRename('${mac}')" class="flex items-center gap-1.5 w-full">
      <input type="text" id="dev-rename-input-${safeMac}" value="${currentName.replace(/"/g, '&quot;')}" class="flex-1 min-w-0 text-sm py-0.5 px-1.5 rounded border border-indigo-300 dark:border-indigo-600 focus:ring-2 focus:ring-indigo-400 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200" autofocus>
      <button type="submit" class="px-2 py-0.5 text-[10px] font-semibold rounded bg-blue-700 hover:bg-blue-600 text-white transition-colors">${t('dev.saveName')}</button>
      <button type="button" onclick="_cancelDeviceRename()" class="px-2 py-0.5 text-[10px] font-semibold rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors">${t('dev.cancelEdit')}</button>
    </form>`;

  // Focus and select all text
  const input = document.getElementById('dev-rename-input-' + safeMac);
  if (input) { input.focus(); input.select(); }
}

async function _saveDeviceRename(mac) {
  const safeMac = mac.replace(/[^a-zA-Z0-9]/g, '_');
  const input = document.getElementById('dev-rename-input-' + safeMac);
  if (!input) return;
  const newName = input.value.trim();
  if (!newName) { _cancelDeviceRename(); return; }

  // Save to localStorage
  _saveFriendlyName(mac, newName);

  // Also try to save to API
  try {
    await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({display_name: newName}),
    });
    await loadDevices();
  } catch (e) {
    console.warn('[devices] API rename failed, using localStorage only:', e);
  }

  _renderDeviceMatrix();
}

function _cancelDeviceRename() {
  _renderDeviceMatrix();
}

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

    // Heartbeat toggle: by default hide zero-byte SNI pings on insight
    // pages so the event table reflects real activity, not presence.
    // Active usage = bytes > 0 OR possible_upload. Users can tick the
    // checkbox to re-include pings (e.g. when debugging).
    const hbToggle = document.getElementById(prefix + '-show-heartbeats');
    const includeHb = hbToggle ? hbToggle.checked : false;
    if (!includeHb) p.set('include_heartbeats', 'false');
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

// Chart.js plugin: draw total count + label in doughnut center
const doughnutCenterTextPlugin = {
  id: 'doughnutCenterText',
  afterDraw(chart) {
    if (chart.config.type !== 'doughnut') return;
    const meta = chart.options.plugins.doughnutCenterText;
    if (!meta || !meta.text) return;

    const { ctx, chartArea: { left, right, top, bottom } } = chart;
    const cx = (left + right) / 2;
    const cy = (top + bottom) / 2;

    ctx.save();
    // Main number
    ctx.font = `700 20px Inter, system-ui, sans-serif`;
    ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#f1f5f9' : '#0f172a';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(meta.text, cx, cy - 8);
    // Sub-label
    ctx.font = `400 11px Inter, system-ui, sans-serif`;
    ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#64748b' : '#94a3b8';
    ctx.fillText(meta.subText || '', cx, cy + 10);
    ctx.restore();
  }
};
// Register plugin globally
if (typeof Chart !== 'undefined') Chart.register(doughnutCenterTextPlugin);

// ---------------------------------------------------------------------------
// Tracker Knowledge Base — domain patterns → company + category
// ---------------------------------------------------------------------------
const TRACKER_KB = [
  // Google
  { patterns: ['doubleclick', 'googleads', 'googlesyndication', 'googleadservices', 'googletag', 'googletagmanager', 'adservice.google', 'pagead'], company: 'Google', category: 'Advertising' },
  { patterns: ['google-analytics', 'googleanalytics', 'analytics.google'], company: 'Google', category: 'Analytics' },
  { patterns: ['crashlytics', 'firebase', 'firebaseio', 'gstatic.com/firebasejs'], company: 'Google', category: 'App Analytics' },
  // Meta
  { patterns: ['facebook.com', 'facebook.net', 'fbcdn', 'fbsbx', 'connect.facebook'], company: 'Meta', category: 'Social Tracking' },
  { patterns: ['instagram.com', 'cdninstagram'], company: 'Meta (Instagram)', category: 'Social Tracking' },
  { patterns: ['whatsapp.net', 'whatsapp.com'], company: 'Meta (WhatsApp)', category: 'Messaging Analytics' },
  // Microsoft
  { patterns: ['msads', 'bing.com/ads', 'bingads'], company: 'Microsoft', category: 'Advertising' },
  { patterns: ['clarity.ms'], company: 'Microsoft', category: 'Analytics' },
  { patterns: ['appcenter.ms', 'in.appcenter'], company: 'Microsoft', category: 'App Analytics' },
  // Apple
  { patterns: ['iadsdk.apple.com', 'iads.apple.com', 'searchads.apple.com'], company: 'Apple', category: 'Advertising' },
  { patterns: ['metrics.apple.com', 'xp.apple.com', 'idiagnostics.apple.com'], company: 'Apple', category: 'Analytics' },
  // Amazon
  { patterns: ['amazon-adsystem', 'aax.amazon', 'assoc-amazon'], company: 'Amazon', category: 'Advertising' },
  // TikTok / ByteDance
  { patterns: ['tiktok', 'bytedance', 'musical.ly', 'tiktokv.com', 'byteoversea'], company: 'TikTok', category: 'Social Tracking' },
  // X (Twitter)
  { patterns: ['twitter.com/i/ads', 'ads-twitter', 'ads.twitter', 'analytics.twitter'], company: 'X (Twitter)', category: 'Advertising' },
  { patterns: ['twitter', 'twimg', 't.co'], company: 'X (Twitter)', category: 'Social Tracking' },
  // Reddit
  { patterns: ['reddit.com', 'redditmedia', 'redditstatic'], company: 'Reddit', category: 'Social Tracking' },
  { patterns: ['events.reddit', 'alb.reddit'], company: 'Reddit', category: 'Analytics' },
  // Snap
  { patterns: ['snapchat', 'snap.com', 'sc-static', 'snapkit'], company: 'Snapchat', category: 'Social Tracking' },
  // LinkedIn
  { patterns: ['linkedin', 'licdn.com'], company: 'LinkedIn', category: 'Social Tracking' },
  // Analytics platforms
  { patterns: ['datadoghq', 'datadog-'], company: 'Datadog', category: 'App Monitoring' },
  { patterns: ['sentry.io', 'sentry-cdn'], company: 'Sentry', category: 'Error Tracking' },
  { patterns: ['hotjar'], company: 'Hotjar', category: 'Analytics' },
  { patterns: ['amplitude'], company: 'Amplitude', category: 'Analytics' },
  { patterns: ['mixpanel'], company: 'Mixpanel', category: 'Analytics' },
  { patterns: ['segment.com', 'segment.io'], company: 'Segment', category: 'Analytics' },
  { patterns: ['heap.io', 'heapanalytics'], company: 'Heap', category: 'Analytics' },
  { patterns: ['fullstory', 'fullstory.com'], company: 'FullStory', category: 'Analytics' },
  { patterns: ['applytics'], company: 'Applytics', category: 'App Analytics' },
  { patterns: ['newrelic', 'nr-data'], company: 'New Relic', category: 'App Monitoring' },
  { patterns: ['bugsnag'], company: 'Bugsnag', category: 'Error Tracking' },
  { patterns: ['rollbar.com'], company: 'Rollbar', category: 'Error Tracking' },
  // Ad networks
  { patterns: ['criteo', 'criteo.com'], company: 'Criteo', category: 'Advertising' },
  { patterns: ['taboola'], company: 'Taboola', category: 'Advertising' },
  { patterns: ['outbrain'], company: 'Outbrain', category: 'Advertising' },
  { patterns: ['adnxs', 'appnexus'], company: 'Xandr', category: 'Advertising' },
  { patterns: ['rubiconproject', 'rubicon'], company: 'Rubicon', category: 'Advertising' },
  { patterns: ['pubmatic'], company: 'PubMatic', category: 'Advertising' },
  { patterns: ['openx.net'], company: 'OpenX', category: 'Advertising' },
  { patterns: ['moat.com', 'moatads'], company: 'Oracle (Moat)', category: 'Ad Verification' },
  { patterns: ['chartbeat'], company: 'Chartbeat', category: 'Analytics' },
  { patterns: ['quantserve', 'quantcast'], company: 'Quantcast', category: 'Advertising' },
  { patterns: ['scorecardresearch', 'comscore'], company: 'Comscore', category: 'Analytics' },
  // Privacy / consent
  { patterns: ['onetrust', 'cookielaw'], company: 'OneTrust', category: 'Consent Management' },
  { patterns: ['cookiebot'], company: 'Cookiebot', category: 'Consent Management' },
  // Misc
  { patterns: ['adjust.com', 'adjust.io'], company: 'Adjust', category: 'Mobile Attribution' },
  { patterns: ['branch.io'], company: 'Branch', category: 'Mobile Attribution' },
  { patterns: ['appsflyer'], company: 'AppsFlyer', category: 'Mobile Attribution' },
  { patterns: ['intercom.io', 'intercom.com'], company: 'Intercom', category: 'Customer Support' },
  { patterns: ['zendesk'], company: 'Zendesk', category: 'Customer Support' },
  { patterns: ['hubspot'], company: 'HubSpot', category: 'Marketing' },
  { patterns: ['marketo'], company: 'Marketo', category: 'Marketing' },
  { patterns: ['salesforce', 'force.com', 'exacttarget'], company: 'Salesforce', category: 'Marketing' },
  { patterns: ['optimizely'], company: 'Optimizely', category: 'A/B Testing' },
  { patterns: ['crazyegg'], company: 'Crazy Egg', category: 'Analytics' },
  { patterns: ['mouseflow'], company: 'Mouseflow', category: 'Analytics' },
];

/**
 * Resolve a domain to tracker info: { company, category } or null.
 */
function resolveTracker(domain) {
  const lower = (domain || '').toLowerCase();
  for (const entry of TRACKER_KB) {
    if (entry.patterns.some(p => lower.includes(p))) {
      return { company: entry.company, category: entry.category };
    }
  }
  return null;
}

/**
 * Legacy alias for dashboard donut grouping — returns category string.
 */
function classifyTrackerDomain(domain) {
  const info = resolveTracker(domain);
  return info ? `${info.company} ${info.category}` : null;
}

/**
 * Extract a readable name from an unknown domain.
 * "browser-intake-us5-datadoghq.com" → "Datadoghq"
 * "applytics.os4work.com" → "Os4work"
 */
function _readableDomain(domain) {
  if (!domain) return domain;
  const parts = domain.replace(/\.$/, '').split('.');
  // Get the main domain (second to last part, or first if only two parts)
  if (parts.length >= 2) {
    const main = parts[parts.length - 2];
    return main.charAt(0).toUpperCase() + main.slice(1);
  }
  return domain;
}

/**
 * Get a display label for a blocked domain: "Google (Advertising)" or "Os4work" for unknowns.
 */
function trackerDisplayLabel(domain) {
  const info = resolveTracker(domain);
  if (info) return `${info.company} (${info.category})`;
  return _readableDomain(domain);
}

// Group blocked domains by company + category for bar chart aggregation
function groupBlockedByCompany(topBlocked) {
  const grouped = {}; // "Company (Category)" → { count, domains[] }
  const unknown = [];

  for (const item of topBlocked) {
    const info = resolveTracker(item.domain);
    if (info) {
      const key = `${info.company} (${info.category})`;
      if (!grouped[key]) grouped[key] = { count: 0, domains: [] };
      grouped[key].count += item.count;
      grouped[key].domains.push(item.domain);
    } else {
      unknown.push(item);
    }
  }

  const result = [];
  for (const [label, data] of Object.entries(grouped)) {
    result.push({ label, count: data.count, domains: data.domains, isCompany: true });
  }
  // Group unknown domains by readable name (e.g. ads.vungle.com + api.vungle.com → "Vungle")
  const unknownGrouped = {};
  for (const item of unknown) {
    const label = _readableDomain(item.domain);
    if (!unknownGrouped[label]) unknownGrouped[label] = { count: 0, domains: [] };
    unknownGrouped[label].count += item.count;
    unknownGrouped[label].domains.push(item.domain);
  }
  for (const [label, data] of Object.entries(unknownGrouped)) {
    result.push({ label, count: data.count, domains: data.domains, isCompany: false });
  }
  result.sort((a, b) => b.count - a.count);
  return result;
}

// Legacy alias used by dashboard donut
function groupBlockedByCategory(topBlocked) {
  return groupBlockedByCompany(topBlocked);
}

function getOrCreateChart(id, config) {
  if (charts[id]) return charts[id];
  const canvas = document.getElementById(id);
  if (!canvas) return null;
  charts[id] = new Chart(canvas.getContext('2d'), config);
  return charts[id];
}

// Custom HTML legend using same badge() style as tables
// maxItems: limit legend to N items + a "+X more" overflow badge (0 = unlimited)
function renderHtmlLegend(containerId, chart, serviceKeys, maxItems) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const limit = maxItems || 0;
  const labels = chart.data.labels || [];
  const total = labels.length;
  const showLabels = limit > 0 ? labels.slice(0, limit) : labels;

  const items = showLabels.map((label, i) => {
    const key = serviceKeys ? serviceKeys[i] : null;
    if (key) return badge(key);
    // Fallback for non-service labels (e.g. domain names, category names)
    const color = chart.data.datasets[0].backgroundColor[i] || ACCENT_COLORS[i % ACCENT_COLORS.length];
    // Use title attr for full text on truncated labels
    const displayLabel = label.length > 22 ? label.slice(0, 20) + '...' : label;
    const titleAttr = label.length > 22 ? ` title="${label}"` : '';
    return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300"${titleAttr}><span class="w-2 h-2 rounded-full flex-shrink-0" style="background:${color}"></span>${displayLabel}</span>`;
  });

  // "+N more" overflow
  if (limit > 0 && total > limit) {
    items.push(`<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-50 dark:bg-white/[0.04] text-slate-400 dark:text-slate-500">${t('dash.nMore', { n: total - limit })}</span>`);
  }

  container.innerHTML = items.join('');
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
      cutout: '65%',
      plugins: {
        legend: { display: false },
        doughnutCenterText: { text: '', subText: '' },
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
// ---------------------------------------------------------------------------
// Collapse consecutive events — shared helper used by every events table
// ---------------------------------------------------------------------------
// Problem: a single SNI heartbeat stream (Spotify, Discord, WhatsApp, etc.)
// emits a steady drip of identical 0-byte sni_hello rows every few seconds,
// plus duplicate rows when a device talks over both IPv4 and IPv6. Rendered
// raw, a 24h window for one device can be hundreds of visually-identical
// lines. We group adjacent events that share the same key within a short
// time window and collapse them into one row that carries a ×N badge and
// summed bytes. Caller supplies the key function so each table can pick
// what "same event" means for its scope:
//   drawer (device-scoped)     → (ai_service, detection_type)
//   multi-device tables        → (ai_service, detection_type, source_ip)
const COLLAPSE_WINDOW_SEC = 60;

function _collapseConsecutiveEvents(events, keyFn, windowSec = COLLAPSE_WINDOW_SEC) {
  if (!events || events.length === 0) return [];
  // Work on a desc-sorted copy — that's the display order too.
  const sorted = [...events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const out = [];
  let cur = null;
  for (const e of sorted) {
    const k = keyFn(e);
    const ts = new Date(e.timestamp).getTime();
    // Groups grow backward in time; compare against the oldest event
    // already in the group so a continuous stream collapses fully.
    if (cur && cur._key === k && (cur._oldest_ms - ts) <= windowSec * 1000) {
      cur._count += 1;
      cur.bytes_transferred = (cur.bytes_transferred || 0) + (e.bytes_transferred || 0);
      cur.possible_upload = cur.possible_upload || !!e.possible_upload;
      cur._oldest_ts = e.timestamp;
      cur._oldest_ms = ts;
    } else {
      cur = {
        ...e,
        _key: k,
        _count: 1,
        _newest_ts: e.timestamp,
        _oldest_ts: e.timestamp,
        _newest_ms: ts,
        _oldest_ms: ts,
      };
      out.push(cur);
    }
  }
  return out;
}

// Render helper: when a collapsed row has _count > 1, append a ×N badge
// and a time-range so the user sees "Spotify · 19:29:24 ×12 (over 45s)".
function _countBadge(e) {
  if (!e || !e._count || e._count <= 1) return '';
  return ` <span class="ml-1 px-1.5 py-0.5 rounded text-[9px] font-semibold tabular-nums bg-slate-200/70 dark:bg-white/[0.08] text-slate-600 dark:text-slate-300" title="${e._count} events between ${fmtTime(e._oldest_ts)} and ${fmtTime(e._newest_ts)}">×${e._count}</span>`;
}

function _eventDescription(e) {
  const type = e.detection_type;
  if (type === 'sni_hello') return t('ev.connection');
  if (type === 'upload_detected' || e.possible_upload) {
    const size = e.bytes_transferred ? _fmtBytes(e.bytes_transferred) : '';
    return '<span class="text-orange-500 dark:text-orange-400">↑</span> ' + t('ev.upload', { size });
  }
  if (type === 'dns_query') return t('ev.dnsLookup');
  // Unknown type → code badge
  return `<span class="px-1.5 py-0.5 rounded font-mono text-[10px] bg-slate-100 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400">${type}</span>`;
}

function _fmtSize(bytes) {
  if (!bytes || bytes === 0) return '<span class="text-slate-300 dark:text-slate-600">—</span>';
  return _fmtBytes(bytes);
}

function _styleUploadCard(prefix, count) {
  const card = document.getElementById(prefix + '-upload-card');
  const label = document.getElementById(prefix + '-upload-label');
  const value = document.getElementById(prefix + '-stat-uploads');
  if (!card) return;

  // Reset classes
  const neutralBorder = 'border-slate-200 dark:border-white/[0.05]';
  const greenBorder = 'border-emerald-300 dark:border-emerald-700/40';
  const orangeBorder = 'border-orange-300 dark:border-orange-700/40';
  const redBorder = 'border-red-300 dark:border-red-700/40';
  const allBorders = [neutralBorder, greenBorder, orangeBorder, redBorder].join(' ').split(' ');

  allBorders.forEach(c => card.classList.remove(c));

  if (count === 0) {
    // Neutral/green — no uploads
    greenBorder.split(' ').forEach(c => card.classList.add(c));
    if (label) { label.className = 'text-xs text-emerald-500 dark:text-emerald-400 font-medium'; }
    if (value) { value.className = 'text-2xl font-bold mt-2 tabular-nums text-emerald-500 dark:text-emerald-400'; }
  } else if (count > 10) {
    // Red — high upload activity
    redBorder.split(' ').forEach(c => card.classList.add(c));
    if (label) { label.className = 'text-xs text-red-500 dark:text-red-400 font-medium'; }
    if (value) { value.className = 'text-2xl font-bold mt-2 tabular-nums text-red-500 dark:text-red-400'; }
  } else {
    // Orange — some uploads
    orangeBorder.split(' ').forEach(c => card.classList.add(c));
    if (label) { label.className = 'text-xs text-orange-500 dark:text-orange-400 font-medium'; }
    if (value) { value.className = 'text-2xl font-bold mt-2 tabular-nums text-orange-500 dark:text-orange-400'; }
  }
}

function renderEventsTable(events, tbodyId, emptyId, lowActivityId) {
  const tbody = document.getElementById(tbodyId);
  const empty = document.getElementById(emptyId);
  const lowAct = lowActivityId ? document.getElementById(lowActivityId) : null;
  if (!tbody) return;

  // Low-activity callout based on raw event count (before collapse so
  // the "3+ events" threshold still reflects true activity volume).
  if (lowAct) lowAct.classList.toggle('hidden', events.length === 0 || events.length >= 3);

  if (!events.length) {
    tbody.innerHTML = '';
    if (empty) empty.classList.remove('hidden');
    return;
  }
  if (empty) empty.classList.add('hidden');

  // Multi-device table: include source_ip in the key so two devices
  // hitting the same service at the same second don't merge.
  const collapsed = _collapseConsecutiveEvents(
    events,
    e => `${e.ai_service}|${e.detection_type}|${e.source_ip}`,
  );

  tbody.innerHTML = collapsed.map(e => {
    const up = e.possible_upload;
    const rc = up
      ? 'border-b border-orange-200 dark:border-orange-700/30 bg-orange-50/30 dark:bg-orange-900/10 border-l-[3px] border-l-orange-400'
      : 'border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20';
    const dn = deviceName(e.source_ip);
    const dev = _deviceByIp(e.source_ip);
    const dt = _detectDeviceType(dev);
    const macAttr = dev ? `data-mac="${dev.mac_address}"` : '';
    const dc = `<span class="device-name cursor-pointer hover:text-indigo-500 transition-colors" ${macAttr} title="${e.source_ip}">${dt.icon} ${dn}</span>`;
    const timeCell = e._count > 1
      ? `${fmtTime(e._newest_ts)} <span class="text-[10px] text-slate-400 dark:text-slate-500">– ${fmtTime(e._oldest_ts)}</span>`
      : fmtTime(e.timestamp);
    return `<tr class="${rc} transition-colors">
      <td class="py-3 px-4 tabular-nums text-slate-400 dark:text-slate-500 text-xs">${timeCell}</td>
      <td class="py-3 px-4">${badge(e.ai_service)}${_countBadge(e)}</td>
      <td class="py-3 px-4 text-xs text-slate-600 dark:text-slate-300">${_eventDescription(e)}</td>
      <td class="py-3 px-4 text-xs hidden sm:table-cell">${dc}</td>
      <td class="py-3 px-4 text-right tabular-nums text-xs hidden sm:table-cell">${_fmtSize(e.bytes_transferred)}</td>
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
// LOADING SKELETONS
// ================================================================
const _skeletonLine = '<div class="h-3 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>';
const _skeletonBlock = '<div class="h-8 w-16 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>';

function _showStatSkeletons(prefix) {
  // Show pulsing placeholders in stat cards while loading
  const ids = [`${prefix}-stat-total`, `${prefix}-stat-services`, `${prefix}-stat-sources`, `${prefix}-stat-uploads`];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = _skeletonBlock;
  });
}

function _showTableSkeleton(tbodyId, cols) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const n = cols || 5;
  const rows = Array.from({ length: 5 }, () =>
    `<tr class="border-b border-slate-100 dark:border-white/[0.04]">` +
    Array.from({ length: n }, () => `<td class="py-3 px-4">${_skeletonLine}</td>`).join('') +
    `</tr>`
  ).join('');
  tbody.innerHTML = rows;
}

// ================================================================
// PAGE REFRESH LOGIC
// ================================================================
async function refreshPage(page) {
  // Show skeletons before async load
  if (page === 'ai') { _showStatSkeletons('ai'); _showTableSkeleton('ai-tbody', 5); }
  else if (page === 'cloud') { _showStatSkeletons('cloud'); _showTableSkeleton('cloud-tbody', 5); }

  try {
    if (page === 'summary') await loadSummaryDashboard();
    else if (page === 'dashboard') await refreshDashboard();
    else if (page === 'ai') await refreshAI();
    else if (page === 'cloud') await refreshCloud();
    else if (page === 'privacy') await refreshPrivacy();
    else if (page === 'devices') await refreshDevices();
    else if (page === 'ips') await refreshIps();
    else if (page === 'rules') await refreshRules();
    else if (page === 'iot') await refreshIot();
    else if (page === 'other') await refreshOther();
    else if (page === 'geo') await refreshGeo();
    else if (page === 'settings') { await loadKillswitchState(); _initThemeSelect(); loadSystemPerformance(); }
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
        ? `<button onclick="restartService('zeek', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-blue-700 hover:bg-blue-600 text-white transition-colors">${t('dash.restartZeek')}</button>` : ''}
      ${(!isOk && s.service === 'Zeek Tailer')
        ? `<button onclick="restartService('tailer', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-blue-700 hover:bg-blue-600 text-white transition-colors">${t('dash.restartTailer')}</button>` : ''}
      ${(!isOk && s.service.startsWith('Zeek ') && s.service.endsWith('.log'))
        ? `<button onclick="restartService('zeek', this)" class="mt-1.5 w-full px-2 py-1 rounded text-[10px] font-medium bg-amber-600 hover:bg-amber-500 text-white transition-colors">${t('dash.restartZeek')}</button>` : ''}
    </div>`;
  }).join('');
}

// ================================================================
// SUMMARY / ACTION INBOX — the new default landing view
// ================================================================
// Architecture:
//   - loadSummaryDashboard()  fetches /api/alerts/active and renders
//     each group as a card with device name, alert type, hit count,
//     and a "Beoordeel" button.
//   - Clicking the button opens #alert-action-modal with the alert
//     context stored in _currentAlertContext.
//   - submitAlertAction() translates button presses into POSTs to
//     /api/policies (allow/block) or /api/exceptions (snooze/ignore).
//   - generateSummaryAI() calls /api/alerts/ai-summary for a Gemini-
//     generated non-technical summary.
// ================================================================

let _currentAlertContext = null;
let _summaryAlerts = [];

const _ANOMALY_ALERT_TYPES = new Set(['beaconing_threat', 'vpn_tunnel', 'stealth_vpn_tunnel', 'new_device', 'iot_lateral_movement', 'iot_suspicious_port', 'inbound_threat', 'inbound_port_scan']);

function _alertTypeLabel(type) {
  // Icons are HTML strings (Phosphor duotone). Callers must inject
  // them via innerHTML, never textContent.
  const map = {
    'beaconing_threat':  { icon: '<i class="ph-duotone ph-siren text-xl"></i>',           label: 'Malware beacon', color: 'red' },
    'vpn_tunnel':        { icon: '<i class="ph-duotone ph-lock-key text-xl"></i>',         label: 'VPN tunnel',     color: 'orange' },
    'stealth_vpn_tunnel':{ icon: '<i class="ph-duotone ph-mask-sad text-xl"></i>',         label: 'Stealth tunnel', color: 'red' },
    'upload':            { icon: '<i class="ph-duotone ph-upload-simple text-xl"></i>',    label: 'Data upload',    color: 'amber' },
    'service_access':    { icon: '<i class="ph-duotone ph-globe text-xl"></i>',            label: 'Service access', color: 'indigo' },
    'new_device':        { icon: '<i class="ph-duotone ph-wifi-high text-xl"></i>',        label: t('alert.newDevice') || 'New device', color: 'blue' },
    'iot_lateral_movement':{ icon: '<i class="ph-duotone ph-arrows-left-right text-xl"></i>', label: 'Lateral movement', color: 'red' },
    'iot_suspicious_port': { icon: '<i class="ph-duotone ph-warning text-xl"></i>',        label: 'Suspicious port',  color: 'red' },
    'inbound_threat':      { icon: '<i class="ph-duotone ph-shield-warning text-xl"></i>', label: 'Inbound threat',   color: 'red' },
    'inbound_port_scan':   { icon: '<i class="ph-duotone ph-scan text-xl"></i>',           label: 'Port scan',        color: 'orange' },
  };
  return map[type] || { icon: '<i class="ph-duotone ph-question text-xl"></i>', label: type, color: 'slate' };
}

function _updateNavBadge(count) {
  const badge = document.getElementById('nav-badge-summary');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count > 99 ? '99+' : String(count);
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

async function loadSummaryDashboard() {
  const container = document.getElementById('summary-alerts-container');
  if (!container) return;

  // Skeleton
  container.innerHTML = `
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
      <div class="inline-block w-6 h-6 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin"></div>
      <p class="text-sm text-slate-400 dark:text-slate-500 mt-3">${t('summary.loading') || 'Meldingen ophalen...'}</p>
    </div>`;

  try {
    const res = await fetch('/api/alerts/active');
    const data = await res.json();
    _summaryAlerts = data.alerts || [];
    _updateNavBadge(_summaryAlerts.length);

    // Show/hide the "Clear all" button
    const clearBtn = document.getElementById('btn-clear-all-alerts');
    if (clearBtn) clearBtn.classList.toggle('hidden', _summaryAlerts.length === 0);

    if (_summaryAlerts.length === 0) {
      container.innerHTML = `
        <div class="bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-700/30 rounded-xl p-8 text-center">
          <div class="inline-flex items-center justify-center w-14 h-14 rounded-full bg-emerald-100 dark:bg-emerald-900/30 mb-3">
            <i class="ph-duotone ph-shield-check text-3xl text-emerald-600 dark:text-emerald-400"></i>
          </div>
          <h3 class="text-lg font-semibold text-emerald-700 dark:text-emerald-300">${t('summary.allClear') || 'Alles is veilig'}</h3>
          <p class="text-sm text-emerald-600/80 dark:text-emerald-400/70 mt-1">${t('summary.allClearSub') || 'Geen actie vereist.'}</p>
        </div>`;
      return;
    }

    container.innerHTML = _summaryAlerts.map((a, idx) => {
      const meta = _alertTypeLabel(a.alert_type);
      const devName = a.display_name || (a.hostname && !_isJunkHostname(a.hostname) ? a.hostname : null)
                    || (a.vendor ? `${_shortVendor(a.vendor)} device` : null)
                    || a.mac_address;
      const macTag = a.mac_address && a.mac_address !== devName
        ? `<span class="text-[10px] font-mono text-slate-400 dark:text-slate-500 ml-1.5">${a.mac_address}</span>`
        : '';
      const lastSeen = a.timestamp ? fmtTime(a.timestamp) : '';
      const firstSeen = a.first_seen ? fmtTime(a.first_seen) : '';
      const isAnomaly = _ANOMALY_ALERT_TYPES.has(a.alert_type);
      const borderClass = isAnomaly
        ? 'border-red-200 dark:border-red-700/40 bg-red-50/40 dark:bg-red-900/10'
        : 'border-slate-200 dark:border-white/[0.05] bg-white dark:bg-white/[0.03]';
      // Icon priority: for service-scoped alerts (AI/cloud/tracker/etc.)
      // show the product's own logo via Google's favicon service — same
      // brand-icon source used throughout the UI (svcLogo()), but sized
      // up to fit the 40×40 card slot. Anomaly alerts (beaconing, VPN,
      // stealth tunnel) aren't tied to a product, so those keep the
      // alert-type emoji.
      const isAnomalyIcon = isAnomaly || !a.service_or_dest;
      let iconHtml;
      if (isAnomalyIcon) {
        iconHtml = `<div class="w-10 h-10 rounded-lg bg-${meta.color}-100 dark:bg-${meta.color}-900/30 flex items-center justify-center flex-shrink-0 text-xl">${meta.icon}</div>`;
      } else {
        const svc = a.service_or_dest;
        const logoDomain = (SERVICE_LOGO_DOMAIN[svc] || svc.replace(/_/g, '') + '.com');
        const fallbackColor = svcColor(svc);
        const fallbackLetter = (svcDisplayName(svc) || '?').charAt(0).toUpperCase();
        // 28px icon inside a 40px white tile with subtle border, so the
        // logo reads clearly against both light and dark card backgrounds.
        iconHtml = `<div class="w-10 h-10 rounded-lg bg-white dark:bg-white/[0.08] border border-slate-200 dark:border-white/[0.08] flex items-center justify-center flex-shrink-0 overflow-hidden">
          <img src="https://www.google.com/s2/favicons?domain=${logoDomain}&sz=64" alt="${svc}"
            style="width:28px;height:28px;object-fit:contain;"
            onerror="this.outerHTML='<span style=\\'width:28px;height:28px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;background:${fallbackColor};color:white;font-weight:700;font-size:14px;\\'>${fallbackLetter}</span>'"/>
        </div>`;
      }
      return `
        <div class="${borderClass} border rounded-xl p-5 card-hover transition-all">
          <div class="flex items-start justify-between gap-4">
            <div class="flex items-start gap-3 min-w-0 flex-1">
              ${iconHtml}
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="text-sm font-semibold text-slate-800 dark:text-white truncate">${devName}</span>
                  ${macTag}
                  <span class="text-[10px] px-2 py-0.5 rounded-full bg-${meta.color}-100 dark:bg-${meta.color}-900/30 text-${meta.color}-600 dark:text-${meta.color}-400 font-medium">${meta.label}</span>
                </div>
                <p class="text-xs text-slate-600 dark:text-slate-300 mt-1">
                  <span class="font-medium">${svcDisplayName(a.service_or_dest) || a.service_or_dest}</span>
                  ${a.category ? `<span class="text-slate-400 dark:text-slate-500 ml-1">· ${a.category}</span>` : ''}
                </p>
                <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-1.5 tabular-nums">
                  ${a.hits} hits · ${t('summary.firstSeen') || 'eerst'} ${firstSeen} · ${t('summary.lastSeen') || 'laatst'} ${lastSeen}
                </p>
              </div>
            </div>
            <button onclick="openAlertActionModal(${idx})"
                    class="flex-shrink-0 px-4 py-2 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-semibold shadow-sm transition-colors active:scale-95">
              ${t('summary.review') || 'Beoordeel'}
            </button>
          </div>
        </div>`;
    }).join('');
  } catch (err) {
    console.error('loadSummaryDashboard:', err);
    container.innerHTML = `
      <div class="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-700/30 rounded-xl p-6 text-center">
        <p class="text-sm text-red-600 dark:text-red-400">${t('summary.error') || 'Kon meldingen niet laden'}: ${err.message}</p>
      </div>`;
  }
}

// ---------------------------------------------------------------------------
// Alert action modal
// ---------------------------------------------------------------------------
let _alertModalScope = 'device'; // 'device' or 'global'
let _alertModalAction = 'allow'; // currently selected action in the 3-way toggle

function openAlertActionModal(idx) {
  const alert = _summaryAlerts[idx];
  if (!alert) return;
  _currentAlertContext = alert;
  _alertModalScope = 'device'; // default to device-specific
  _alertModalAction = 'allow';

  const modal = document.getElementById('alert-action-modal');
  const title = document.getElementById('alert-modal-title');
  const subtitle = document.getElementById('alert-modal-subtitle');
  const logoEl = document.getElementById('alert-modal-logo');
  const policyGroup = document.getElementById('alert-modal-policy-group');
  const snoozeGroup = document.getElementById('alert-modal-snooze-group');
  const scopeSection = document.getElementById('alert-modal-scope-section');
  const status = document.getElementById('alert-modal-status');

  const devName = alert.display_name || (alert.hostname && !_isJunkHostname(alert.hostname) ? alert.hostname : null)
                || (alert.vendor ? `${_shortVendor(alert.vendor)} device` : null)
                || alert.mac_address;
  const svcName = svcDisplayName(alert.service_or_dest) || alert.service_or_dest;
  const meta = _alertTypeLabel(alert.alert_type);

  if (title) title.textContent = svcName;
  if (subtitle) subtitle.innerHTML = `${meta.icon} <span>${meta.label} · ${devName} · ${alert.hits} hits</span>`;
  if (status) status.textContent = '';

  // Service logo (same 28px style as Action Inbox cards)
  if (logoEl) {
    const isAnomaly = _ANOMALY_ALERT_TYPES.has(alert.alert_type);
    if (isAnomaly || !alert.service_or_dest) {
      logoEl.innerHTML = `<div class="w-7 h-7 rounded bg-${meta.color}-100 dark:bg-${meta.color}-900/30 flex items-center justify-center">${meta.icon}</div>`;
    } else {
      const svc = alert.service_or_dest;
      const logoDomain = SERVICE_LOGO_DOMAIN[svc] || svc.replace(/_/g, '') + '.com';
      const fc = svcColor(svc);
      const fl = (svcDisplayName(svc) || '?').charAt(0).toUpperCase();
      logoEl.innerHTML = `<img src="https://www.google.com/s2/favicons?domain=${logoDomain}&sz=64" alt="" style="width:28px;height:28px;object-fit:contain" onerror="this.outerHTML='<span style=\\'width:28px;height:28px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;background:${fc};color:white;font-weight:700;font-size:14px\\'>${fl}</span>'"/>`;
    }
  }

  // Device name in scope button
  const devLabel = document.getElementById('alert-scope-device-label');
  if (devLabel) devLabel.textContent = devName;

  // Reset scope pills
  setAlertScope('device');

  const isAnomaly = _ANOMALY_ALERT_TYPES.has(alert.alert_type);
  // Always show snooze/dismiss group so any alert can be dismissed
  if (snoozeGroup) snoozeGroup.classList.remove('hidden');
  if (isAnomaly) {
    if (policyGroup) policyGroup.classList.add('hidden');
    if (scopeSection) scopeSection.classList.add('hidden');
  } else {
    if (policyGroup) policyGroup.classList.remove('hidden');
    if (scopeSection) scopeSection.classList.remove('hidden');
    // Render the 3-way toggle inside the modal
    _renderAlertPolicyToggle(alert.service_or_dest);
  }

  if (modal) modal.classList.remove('hidden');
}

function _renderAlertPolicyToggle(serviceName) {
  const container = document.getElementById('alert-modal-policy-segment');
  if (!container) return;
  // Reuse the same visual pattern as renderPolicySegment on the Rules page
  const allowActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-semibold transition-colors bg-emerald-500 text-white shadow-sm';
  const allowInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/20';
  const alertActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-semibold transition-colors bg-amber-500 text-white shadow-sm';
  const alertInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20';
  const blockActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-semibold transition-colors bg-red-500 text-white shadow-sm';
  const blockInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-2 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20';

  const cur = _alertModalAction;
  container.innerHTML = `<div class="flex gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1">
    <button type="button" onclick="setAlertAction('allow')" class="${cur === 'allow' ? allowActive : allowInactive}"><i class="ph-duotone ph-check text-xs"></i><span>${t('rules.allow') || 'Allow'}</span></button>
    <button type="button" onclick="setAlertAction('alert')" class="${cur === 'alert' ? alertActive : alertInactive}"><i class="ph-duotone ph-warning text-xs"></i><span>${t('rules.alert') || 'Alert'}</span></button>
    <button type="button" onclick="setAlertAction('block')" class="${cur === 'block' ? blockActive : blockInactive}"><i class="ph-duotone ph-x text-xs"></i><span>${t('rules.block') || 'Block'}</span></button>
  </div>`;
}

function setAlertAction(action) {
  _alertModalAction = action;
  if (_currentAlertContext) _renderAlertPolicyToggle(_currentAlertContext.service_or_dest);
}

function setAlertScope(scope) {
  _alertModalScope = scope;
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  const btnD = document.getElementById('alert-scope-btn-device');
  const btnG = document.getElementById('alert-scope-btn-global');
  if (btnD) btnD.className = scope === 'device' ? active : inactive;
  if (btnG) btnG.className = scope === 'global' ? active : inactive;
}

// Submit the 3-way policy with optional timer from the alert modal
async function submitAlertPolicy(hours) {
  if (!_currentAlertContext) return;
  const alert = _currentAlertContext;
  const status = document.getElementById('alert-modal-status');
  if (status) status.textContent = t('alertModal.submitting') || 'Submitting...';

  const isGlobal = _alertModalScope === 'global';
  const expires = hours ? new Date(Date.now() + hours * 3600 * 1000).toISOString() : null;

  try {
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: isGlobal ? 'global' : 'device',
        mac_address: isGlobal ? null : alert.mac_address,
        service_name: alert.service_or_dest,
        category: alert.category,
        action: _alertModalAction,
        expires_at: expires,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    closeAlertActionModal();
    const scopeLabel = isGlobal ? (t('rules.scopeGlobal') || 'Global') : (t('rules.scopePerDevice') || 'Device');
    const actionLabel = _alertModalAction === 'allow' ? (t('rules.allow') || 'Allow')
                      : _alertModalAction === 'alert' ? (t('rules.alert') || 'Alert')
                      : (t('rules.block') || 'Block');
    const timerLabel = hours ? ` (${hours}h)` : '';
    showToast(`${svcDisplayName(alert.service_or_dest)}: ${actionLabel} · ${scopeLabel}${timerLabel}`, 'success');
    await loadSummaryDashboard();
  } catch (err) {
    console.error('submitAlertPolicy:', err);
    if (status) status.textContent = `${t('alertModal.failed') || 'Failed'}: ${err.message}`;
  }
}

// Keep submitAlertAction for snooze/whitelist (anomaly path)
async function submitAlertAction(action) {
  if (!_currentAlertContext) return;
  const alert = _currentAlertContext;
  const status = document.getElementById('alert-modal-status');
  if (status) status.textContent = t('alertModal.submitting') || 'Submitting...';

  try {
    let body;
    if (action === 'dismiss') {
      // Dismiss = exception that expires immediately.  All current events
      // are marked as "handled"; only NEW detections will re-trigger.
      body = {
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest,
        expires_at: new Date(Date.now() + 1000).toISOString(),
      };
    } else if (action.startsWith('snooze_')) {
      const hours = parseInt(action.split('_')[1], 10);
      body = {
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest,
        expires_at: new Date(Date.now() + hours * 3600 * 1000).toISOString(),
      };
    } else if (action === 'whitelist_forever') {
      body = {
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest,
        expires_at: null,
      };
    } else {
      throw new Error('Unknown action: ' + action);
    }
    const res = await fetch('/api/exceptions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    closeAlertActionModal();
    showToast(t('alertModal.success') || 'Alert processed', 'success');
    await loadSummaryDashboard();
  } catch (err) {
    console.error('submitAlertAction:', err);
    if (status) status.textContent = `${t('alertModal.failed') || 'Failed'}: ${err.message}`;
  }
}

function closeAlertActionModal() {
  const modal = document.getElementById('alert-action-modal');
  if (modal) modal.classList.add('hidden');
  _currentAlertContext = null;
}

window.openAlertActionModal = openAlertActionModal;
window.closeAlertActionModal = closeAlertActionModal;
window.submitAlertAction = submitAlertAction;
window.submitAlertPolicy = submitAlertPolicy;
window.setAlertAction = setAlertAction;
window.setAlertScope = setAlertScope;

// ---------------------------------------------------------------------------
// "Clear all alerts" — dismiss every visible alert
// ---------------------------------------------------------------------------
// Creates one AlertException per (mac_address, alert_type, service_or_dest)
// with expires_at = now (immediately expired).  This marks all current events
// as "handled".  Alerts only return if NEW detections occur after this point.
async function clearAllAlerts() {
  if (!_summaryAlerts || _summaryAlerts.length === 0) {
    showToast(t('summary.noAlertsToClear') || 'No alerts to clear.', 'info');
    return;
  }

  const n = _summaryAlerts.length;
  const confirmed = await styledConfirm(
    t('summary.clearAllTitle') || 'Clear all alerts',
    (t('summary.clearConfirm') || 'This will dismiss all {n} alerts. They will only return if new activity is detected.')
      .replace('{n}', String(n))
  );
  if (!confirmed) return;

  const btn = document.getElementById('btn-clear-all-alerts');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('opacity-60', 'cursor-wait');
  }

  const expires = new Date(Date.now() + 1000).toISOString();
  let okCount = 0;
  let fail = 0;

  for (const a of _summaryAlerts) {
    try {
      const res = await fetch('/api/exceptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mac_address: a.mac_address,
          alert_type: a.alert_type,
          destination: a.service_or_dest,
          expires_at: expires,
        }),
      });
      if (res.ok) okCount++;
      else fail++;
    } catch (e) {
      fail++;
    }
  }

  if (btn) {
    btn.disabled = false;
    btn.classList.remove('opacity-60', 'cursor-wait');
  }

  if (fail === 0) {
    showToast(t('summary.clearSuccess', { n: String(okCount) }) || `${okCount} alerts dismissed`, 'success');
  } else {
    showToast(`${okCount} dismissed, ${fail} failed`, 'warning');
  }

  await loadSummaryDashboard();
}
window.clearAllAlerts = clearAllAlerts;

// ---------------------------------------------------------------------------
// Styled confirm modal — async replacement for window.confirm()
// ---------------------------------------------------------------------------
// Returns a Promise<boolean>. Usage: if (await styledConfirm('Title', 'Msg')) { ... }
let _confirmResolve = () => {};

function styledConfirm(title, message) {
  return new Promise(resolve => {
    const modal = document.getElementById('confirm-modal');
    document.getElementById('confirm-modal-title').textContent = title;
    document.getElementById('confirm-modal-message').textContent = message;
    modal.classList.remove('hidden');
    _confirmResolve = (result) => {
      modal.classList.add('hidden');
      resolve(result);
    };
  });
}
window._confirmResolve = (result) => _confirmResolve(result);
window.styledConfirm = styledConfirm;

// ---------------------------------------------------------------------------
// AI summary button
// ---------------------------------------------------------------------------
async function generateSummaryAI() {
  const btn = document.getElementById('summary-ai-btn');
  const responseBox = document.getElementById('summary-ai-response');
  if (!btn || !responseBox) return;

  const origHTML = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="inline-flex items-center gap-1.5"><i class="ph-duotone ph-circle-notch animate-spin text-sm"></i><span>${t('summary.aiGenerating') || 'Bezig met analyseren...'}</span></span>`;

  responseBox.classList.remove('hidden');
  responseBox.innerHTML = `
    <div class="space-y-2">
      <div class="h-3 rounded bg-slate-200 dark:bg-white/[0.06] animate-pulse"></div>
      <div class="h-3 rounded bg-slate-200 dark:bg-white/[0.06] animate-pulse w-11/12"></div>
      <div class="h-3 rounded bg-slate-200 dark:bg-white/[0.06] animate-pulse w-9/12"></div>
    </div>`;

  try {
    const res = await fetch('/api/alerts/ai-summary');
    const data = await res.json();
    const summary = data.summary || '';
    const count = data.alert_count || 0;
    const html = renderSimpleMarkdown(summary);
    const meta = data.tokens
      ? `<div class="mt-3 pt-3 border-t border-indigo-200/30 dark:border-indigo-700/20 text-[10px] text-indigo-400/70 dark:text-indigo-500/50 flex items-center justify-between">
           <span>Gemini 2.5 Flash · ${formatNumber(data.tokens.total || 0)} tokens</span>
           <span>${count} ${count === 1 ? 'melding' : 'meldingen'}</span>
         </div>`
      : '';
    responseBox.innerHTML = `<div class="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">${html}</div>${meta}`;
  } catch (err) {
    responseBox.innerHTML = `<div class="text-sm text-red-500 dark:text-red-400">${t('summary.aiFailed') || 'AI-samenvatting mislukt'}: ${err.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = origHTML;
  }
}
window.generateSummaryAI = generateSummaryAI;

// ---------------------------------------------------------------------------
// Simple toast notification
// ---------------------------------------------------------------------------
function showToast(message, type = 'info') {
  const host = document.getElementById('toast-host');
  if (!host) return;
  const colors = {
    success: 'bg-emerald-500 text-white',
    error:   'bg-red-500 text-white',
    info:    'bg-slate-800 text-white dark:bg-white dark:text-slate-800',
  };
  const cls = colors[type] || colors.info;
  const toast = document.createElement('div');
  toast.className = `pointer-events-auto px-4 py-3 rounded-lg shadow-lg text-sm font-medium ${cls} transform transition-all duration-300 translate-y-2 opacity-0`;
  toast.textContent = message;
  host.appendChild(toast);
  // Trigger in animation
  requestAnimationFrame(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  });
  // Remove after 3s
  setTimeout(() => {
    toast.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}
window.showToast = showToast;


// --- DASHBOARD ---
async function refreshDashboard() {
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const [aiEvt, cloudEvt, privRes, healthRes, sankeyAi, sankeyCloud, ksState, policiesRes] = await Promise.all([
    // Counter: meaningful activity only (heartbeats excluded). Users see
    // a realistic "real events today" number, not thousands of 0-byte pings.
    fetch('/api/events?category=ai&limit=200&include_heartbeats=false&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/events?category=cloud&limit=200&include_heartbeats=false&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/privacy/stats').then(r => r.json()).catch(() => null),
    fetch('/api/health').then(r => r.json()).catch(() => null),
    // Sankey: include heartbeats so service adoption (e.g. "my iPhone uses iCloud")
    // is represented even when the device only pings and never transfers data.
    fetch('/api/events?category=ai&limit=500&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/events?category=cloud&limit=500&start=' + todayStart.toISOString()).then(r => r.json()),
    fetch('/api/killswitch').then(r => r.json()).catch(() => ({ active: false })),
    // Policies — needed for the "Services Blocked" stat card + list.
    fetch('/api/policies?scope=global').then(r => r.json()).catch(() => []),
  ]);

  // Build policy lookup so the dashboard knows which services are blocked.
  _policyByService = {};
  _policyExpiresByService = {};
  (Array.isArray(policiesRes) ? policiesRes : []).forEach(p => {
    if (p.scope === 'global' && p.service_name && !p.category) {
      _policyByService[p.service_name] = p.action;
      if (p.expires_at) _policyExpiresByService[p.service_name] = p.expires_at;
    }
  });

  // Update global killswitch banner
  updateGlobalKsBanner(ksState);

  // Metrics
  const deviceCount = Object.keys(deviceMap).length || 0;
  document.getElementById('dash-devices').textContent = formatNumber(deviceCount);
  const devSub = document.getElementById('dash-devices-subtitle');
  if (devSub) devSub.textContent = t('dash.onNetwork', { count: formatNumber(deviceCount) });

  const evtCount = aiEvt.length + cloudEvt.length;
  document.getElementById('dash-events-today').textContent = formatNumber(evtCount);

  // Services Blocked stat card — shows count of YOUR active block rules,
  // not AdGuard's raw blocked_queries (which was misleading).
  const blockedSvcCount = Object.values(_policyByService).filter(a => a === 'block').length;
  document.getElementById('dash-blocked').textContent = blockedSvcCount;

  // Security stat card (beaconing threats + any security-category events)
  renderSecurityStats(privRes?.security || {}, 'dash-security', 'dash-security-7d', 'dash-security-spark');

  // TODO: Trend indicators — render when API provides yesterday's comparison data.
  // The API would need to return e.g. { devices_yesterday, events_yesterday, blocked_yesterday }
  // in the /api/privacy/stats or a new /api/stats/comparison endpoint.
  // Example usage:
  //   renderTrend('dash-devices-trend', deviceCount, data.devices_yesterday, false);
  //   renderTrend('dash-events-trend', evtCount, data.events_yesterday, false);
  //   renderTrend('dash-blocked-trend', ag.blocked_queries, data.blocked_yesterday, true);

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
      txt.textContent = t('dash.issuesDetected', { n: issues, problem: getLocale() === 'nl' ? (issues > 1 ? 'problemen' : 'probleem') : (issues > 1 ? 'Issues' : 'Issue') });
      txt.className = 'text-lg font-semibold text-amber-600 dark:text-amber-400';
      topDot.className = 'w-2 h-2 rounded-full bg-amber-500';
      topTxt.textContent = t('topbar.issues', { n: issues, problem: getLocale() === 'nl' ? (issues > 1 ? 'problemen' : 'probleem') : (issues > 1 ? 'Issues' : 'Issue') });
    }
    // Store health data for detail panel
    _lastHealthData = healthRes;
    // Auto-update panel if already open
    const hp = document.getElementById('dash-health-panel');
    if (hp && !hp.classList.contains('hidden')) renderDashHealthServices();
  }

  // Mini donuts with center text
  const aiDonut = getOrCreateChart('dash-ai-donut', makeDoughnutConfig());
  if (aiDonut) {
    const ac = {}; aiEvt.forEach(e => { ac[e.ai_service] = (ac[e.ai_service] || 0) + 1; });
    const aiKeys = Object.keys(ac);
    const aiTotal = Object.values(ac).reduce((s, v) => s + v, 0);
    aiDonut.data.labels = aiKeys.map(k => svcDisplayName(k));
    aiDonut.data.datasets[0].data = Object.values(ac);
    aiDonut.data.datasets[0].backgroundColor = aiKeys.map(k => svcColor(k));
    aiDonut.options.plugins.doughnutCenterText = { text: formatNumber(aiTotal), subText: t('dash.events') };
    aiDonut.update();
    renderHtmlLegend('dash-ai-donut-legend', aiDonut, aiKeys, 4);
  }

  const cloudDonut = getOrCreateChart('dash-cloud-donut', makeDoughnutConfig());
  if (cloudDonut) {
    const cc = {}; cloudEvt.forEach(e => { cc[e.ai_service] = (cc[e.ai_service] || 0) + 1; });
    const cloudKeys = Object.keys(cc);
    const cloudTotal = Object.values(cc).reduce((s, v) => s + v, 0);
    cloudDonut.data.labels = cloudKeys.map(k => svcDisplayName(k));
    cloudDonut.data.datasets[0].data = Object.values(cc);
    cloudDonut.data.datasets[0].backgroundColor = cloudKeys.map(k => svcColor(k));
    cloudDonut.options.plugins.doughnutCenterText = { text: formatNumber(cloudTotal), subText: t('dash.events') };
    cloudDonut.update();
    renderHtmlLegend('dash-cloud-donut-legend', cloudDonut, cloudKeys, 4);
  }

  // Services Blocked panel — show actual blocked services with logos
  const blockedListEl = document.getElementById('dash-blocked-services-list');
  if (blockedListEl) {
    const blockedSvcs = Object.entries(_policyByService)
      .filter(([, action]) => action === 'block')
      .map(([svc]) => svc)
      .sort((a, b) => svcDisplayName(a).localeCompare(svcDisplayName(b)));
    if (blockedSvcs.length === 0) {
      blockedListEl.innerHTML = `
        <div class="text-center py-6">
          <i class="ph-duotone ph-shield-check text-3xl text-emerald-500 mb-2"></i>
          <p class="text-xs text-emerald-600 dark:text-emerald-400">${t('rules.allServicesAllowed') || 'All services are currently allowed.'}</p>
        </div>`;
    } else {
      blockedListEl.innerHTML = blockedSvcs.map(svc => {
        const name = svcDisplayName(svc);
        const logo = svcLogo(svc);
        const exp = _policyExpiresByService?.[svc];
        const timerLabel = exp
          ? `<span class="text-[9px] text-blue-500"><i class="ph-duotone ph-clock-countdown"></i> ${new Date(exp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>`
          : '';
        return `<div class="flex items-center gap-2 py-1.5">
          <div class="flex-shrink-0">${logo}</div>
          <span class="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">${name}</span>
          ${timerLabel}
          <i class="ph-duotone ph-prohibit text-xs text-red-500 flex-shrink-0 ml-auto"></i>
        </div>`;
      }).join('');
    }
  }

  // Alarms — grouping, pagination, severity filter
  const allEvt = [...aiEvt, ...cloudEvt].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const alarms = allEvt.filter(e => e.possible_upload || e.bytes_transferred > 100000);
  _dashAlarms = alarms;
  _dashAlarmsVisible = 10;
  _dashAlarmsSevFilter = 'all';
  renderDashAlarms();

  // Sankey Data Flow Diagram
  renderSankey([...sankeyAi, ...sankeyCloud]);
}

// --- DASHBOARD ALARMS: grouping, pagination, severity filter, interactivity ---
let _dashAlarms = [];
let _dashAlarmsVisible = 10;
let _dashAlarmsSevFilter = 'all';

function _alarmSeverity(e) {
  return e.possible_upload ? 'high' : 'medium';
}

function _severityBadge(sev) {
  if (sev === 'critical') return '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400">CRITICAL</span>';
  if (sev === 'high')     return '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">HIGH</span>';
  if (sev === 'low')      return '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400">LOW</span>';
  return '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">MED</span>';
}

function _fmtBytes(bytes) {
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(0) + ' KB';
  return bytes + ' B';
}

function _groupAlarms(alarms) {
  // Group consecutive alarms with same type + service + device
  const groups = [];
  let cur = null;

  for (const e of alarms) {
    const key = _alarmSeverity(e) + '|' + (e.ai_service || '') + '|' + (e.source_ip || '');
    if (cur && cur.key === key) {
      cur.events.push(e);
      cur.totalBytes += (e.bytes_transferred || 0);
    } else {
      cur = { key, events: [e], totalBytes: (e.bytes_transferred || 0) };
      groups.push(cur);
    }
  }
  return groups;
}

function _navigateToDevice(ip) {
  // Navigate to the Devices page — the device detail view
  const mac = ipToMac[ip];
  navigate('devices');
  // If there's a device detail function, trigger it after navigation
  if (mac && typeof showDeviceDetail === 'function') {
    setTimeout(() => showDeviceDetail(mac), 100);
  }
}

function showMoreAlarms() {
  _dashAlarmsVisible += 10;
  renderDashAlarms();
}

function setAlarmSevFilter(sev) {
  _dashAlarmsSevFilter = sev;
  _dashAlarmsVisible = 10;
  renderDashAlarms();
}

function toggleAlarmGroup(groupIdx) {
  const rows = document.querySelectorAll(`.alarm-group-${groupIdx}-child`);
  const chevron = document.getElementById(`alarm-chevron-${groupIdx}`);
  if (!rows.length) return;
  const isHidden = rows[0].classList.contains('hidden');
  rows.forEach(r => r.classList.toggle('hidden', !isHidden));
  if (chevron) chevron.style.transform = isHidden ? 'rotate(90deg)' : '';
}

function renderDashAlarms() {
  const body = document.getElementById('dash-alarms-body');
  const countEl = document.getElementById('dash-alarms-count');
  const moreWrap = document.getElementById('dash-alarms-more-wrap');
  const filtersEl = document.getElementById('dash-alarms-filters');
  const sevTh = document.getElementById('dash-alarms-sev-th');
  if (!body) return;

  const colSpan = 6; // time + sev + event + service + device + arrow

  // --- Empty state ---
  if (_dashAlarms.length === 0) {
    body.innerHTML = `<tr><td colspan="${colSpan}" class="py-12 text-center">
      <div class="flex flex-col items-center gap-2">
        <i class="ph-duotone ph-shield-check text-4xl text-emerald-400 dark:text-emerald-500"></i>
        <span class="text-sm text-slate-400 dark:text-slate-500">${t('dash.noAlarms')}</span>
      </div>
    </td></tr>`;
    if (countEl) countEl.textContent = '';
    if (moreWrap) moreWrap.classList.add('hidden');
    if (filtersEl) filtersEl.classList.add('hidden');
    return;
  }

  // --- Determine if all severities are the same ---
  const sevSet = new Set(_dashAlarms.map(e => _alarmSeverity(e)));
  const allSameSev = sevSet.size <= 1;
  const showSevCol = !allSameSev;

  // Hide/show severity column header
  if (sevTh) sevTh.classList.toggle('hidden', !showSevCol);

  // --- Severity filter chips ---
  if (filtersEl) {
    if (showSevCol) {
      const sevList = ['all', ...Array.from(sevSet).sort()];
      const labelMap = { all: 'dash.filterAll', critical: 'dash.filterCritical', high: 'dash.filterHigh', medium: 'dash.filterMedium', low: 'dash.filterLow' };
      filtersEl.innerHTML = sevList.map(s => {
        const active = _dashAlarmsSevFilter === s;
        const cls = active
          ? 'bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700 dark:text-indigo-300 border-indigo-300 dark:border-indigo-600'
          : 'bg-slate-50 dark:bg-white/[0.04] text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/[0.06] hover:bg-slate-100 dark:hover:bg-white/[0.08]';
        return `<button onclick="setAlarmSevFilter('${s}')" class="px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors ${cls}">${t(labelMap[s] || 'dash.filterAll')}</button>`;
      }).join('');
      filtersEl.classList.remove('hidden');
      filtersEl.classList.add('flex');
    } else {
      filtersEl.classList.add('hidden');
      filtersEl.classList.remove('flex');
    }
  }

  // --- Filter by severity ---
  let filtered = _dashAlarms;
  if (_dashAlarmsSevFilter !== 'all') {
    filtered = _dashAlarms.filter(e => _alarmSeverity(e) === _dashAlarmsSevFilter);
  }

  const totalCount = filtered.length;

  // --- Group consecutive alarms ---
  const groups = _groupAlarms(filtered);

  // --- Pagination: count groups (each group counts as 1 visible item) ---
  let visibleCount = 0;
  let renderedGroups = [];
  for (const g of groups) {
    if (visibleCount >= _dashAlarmsVisible) break;
    renderedGroups.push(g);
    visibleCount++;
  }

  // Count total individual alarms shown (for the "Showing X of Y" label)
  const totalIndividualShown = renderedGroups.reduce((sum, g) => sum + g.events.length, 0);

  // --- Update count label ---
  if (countEl) {
    countEl.textContent = t('dash.showingOf', {
      visible: Math.min(totalIndividualShown, totalCount),
      total: totalCount
    });
  }

  // --- Show/hide "Show more" button ---
  if (moreWrap) {
    moreWrap.classList.toggle('hidden', renderedGroups.length >= groups.length);
  }

  // --- Render rows ---
  const adjustedColSpan = showSevCol ? colSpan : colSpan - 1;
  let html = '';

  renderedGroups.forEach((group, gi) => {
    const e0 = group.events[0]; // representative event (most recent in group)
    const isGrouped = group.events.length > 1;
    const sev = _alarmSeverity(e0);
    const isUpload = e0.possible_upload;

    if (isGrouped) {
      // --- Grouped row ---
      const firstTime = fmtTime(group.events[group.events.length - 1].timestamp);
      const lastTime = fmtTime(e0.timestamp);
      const timeRange = firstTime + ' — ' + lastTime;
      const desc = isUpload
        ? t('dash.groupUploads', { n: group.events.length, size: _fmtBytes(group.totalBytes) })
        : t('dash.groupHighVol', { n: group.events.length, size: _fmtBytes(group.totalBytes) });

      html += `<tr class="border-b border-slate-100 dark:border-white/[0.04] border-l-2 border-l-orange-400 bg-orange-50/40 dark:bg-orange-950/10 hover:bg-orange-50 dark:hover:bg-orange-950/20 transition-colors cursor-pointer" onclick="toggleAlarmGroup(${gi})">
        <td class="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500">
          <span class="inline-flex items-center gap-1.5">
            <i id="alarm-chevron-${gi}" class="ph-duotone ph-caret-right text-xs text-slate-400 transition-transform duration-200 inline-block"></i>
            ${timeRange}
          </span>
        </td>
        ${showSevCol ? `<td class="py-3 px-4">${_severityBadge(sev)}</td>` : ''}
        <td class="py-3 px-4 text-xs text-slate-600 dark:text-slate-300 font-medium">${desc}</td>
        <td class="py-3 px-4">${badge(e0.ai_service)}</td>
        <td class="py-3 px-4 text-xs">${_detectDeviceType(_deviceByIp(e0.source_ip)).icon} ${deviceName(e0.source_ip)}</td>
        <td class="w-8"></td>
      </tr>`;

      // --- Child rows (hidden by default) ---
      group.events.forEach(ce => {
        const cDesc = ce.possible_upload
          ? t('dash.uploadDetected', { kb: (ce.bytes_transferred / 1024).toFixed(0) })
          : t('dash.highVolume', { kb: (ce.bytes_transferred / 1024).toFixed(0) });
        html += `<tr class="alarm-group-${gi}-child hidden border-b border-slate-100 dark:border-white/[0.04] bg-slate-50/50 dark:bg-white/[0.01] hover:bg-slate-100 dark:hover:bg-slate-700/20 transition-colors cursor-pointer group" onclick="_navigateToDevice('${ce.source_ip}')">
          <td class="py-2.5 px-4 pl-10 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(ce.timestamp)}</td>
          ${showSevCol ? `<td class="py-2.5 px-4">${_severityBadge(_alarmSeverity(ce))}</td>` : ''}
          <td class="py-2.5 px-4 text-xs text-slate-500 dark:text-slate-400">${cDesc}</td>
          <td class="py-2.5 px-4">${badge(ce.ai_service)}</td>
          <td class="py-2.5 px-4 text-xs">${_detectDeviceType(_deviceByIp(ce.source_ip)).icon} ${deviceName(ce.source_ip)}</td>
          <td class="w-8 text-right pr-3"><span class="opacity-0 group-hover:opacity-100 text-slate-400 dark:text-slate-500 transition-opacity text-xs">→</span></td>
        </tr>`;
      });

    } else {
      // --- Single row ---
      const desc = isUpload
        ? t('dash.uploadDetected', { kb: (e0.bytes_transferred / 1024).toFixed(0) })
        : t('dash.highVolume', { kb: (e0.bytes_transferred / 1024).toFixed(0) });

      html += `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors cursor-pointer group" onclick="_navigateToDevice('${e0.source_ip}')">
        <td class="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(e0.timestamp)}</td>
        ${showSevCol ? `<td class="py-3 px-4">${_severityBadge(sev)}</td>` : ''}
        <td class="py-3 px-4 text-xs text-slate-600 dark:text-slate-300">${desc}</td>
        <td class="py-3 px-4">${badge(e0.ai_service)}</td>
        <td class="py-3 px-4 text-xs">${_detectDeviceType(_deviceByIp(e0.source_ip)).icon} ${deviceName(e0.source_ip)}</td>
        <td class="w-8 text-right pr-3"><span class="opacity-0 group-hover:opacity-100 text-slate-400 dark:text-slate-500 transition-opacity text-xs">→</span></td>
      </tr>`;
    }
  });

  body.innerHTML = html;
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

  // Limit to top 10 devices by traffic volume to keep the chart readable.
  const top10Devices = new Set(
    Object.entries(deviceFlows)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([dev]) => dev)
  );

  // Rebuild device flows with only top 10
  const filteredDeviceFlows = {};
  Object.entries(deviceFlows).forEach(([dev, bytes]) => {
    if (top10Devices.has(dev)) filteredDeviceFlows[dev] = bytes;
  });

  // Rebuild service flows from events of top 10 devices only
  const filteredServiceFlows = {};
  events.forEach(e => {
    const dev = deviceName(e.source_ip);
    if (!top10Devices.has(dev)) return;
    const svc = svcDisplayName(e.ai_service);
    filteredServiceFlows[svc] = (filteredServiceFlows[svc] || 0) + (e.bytes_transferred || 1);
  });

  // Nodes
  const nodes = [];
  const nodeSet = new Set();
  Object.keys(filteredDeviceFlows).forEach(d => { if (!nodeSet.has(d)) { nodeSet.add(d); nodes.push({ name: d }); } });
  nodes.push({ name: 'AI-Radar' });
  Object.keys(filteredServiceFlows).forEach(s => { if (!nodeSet.has(s)) { nodeSet.add(s); nodes.push({ name: s }); } });

  // Links: device → AI-Radar, AI-Radar → service
  const links = [];
  Object.entries(filteredDeviceFlows).forEach(([dev, bytes]) => {
    links.push({ source: dev, target: 'AI-Radar', value: bytes });
  });
  Object.entries(filteredServiceFlows).forEach(([svc, bytes]) => {
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
          return `${params.data.source} → ${params.data.target}<br/><b>${_fmtBytes(params.value)}</b>`;
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
          fontSize: 12,
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
        fontSize: 12,
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
  const aiUploadCount = events.filter(e => e.possible_upload).length;
  document.getElementById('ai-stat-uploads').textContent = aiUploadCount;
  _styleUploadCard('ai', aiUploadCount);

  // Populate service filter
  const svcSel = document.getElementById('ai-filter-service');
  if (svcSel) {
    const cur = svcSel.value;
    const allSvcs = [...new Set(events.map(e => e.ai_service))].sort();
    svcSel.innerHTML = `<option value="">${t('ai.allServices')}</option>`;
    allSvcs.forEach(s => { svcSel.innerHTML += `<option value="${s}">${svcDisplayName(s)}</option>`; });
    svcSel.value = cur;
  }

  renderEventsTable(events, 'ai-tbody', 'ai-empty', 'ai-low-activity');
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

  const activeClass = 'bg-blue-700 text-white shadow-sm';
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
    const name = dev ? _bestDeviceName(mac, dev) : mac.replace('_ip_', '');
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
        <div class="h-full rounded bg-gradient-to-r from-blue-500/80 to-blue-700/80 transition-all duration-500" style="width:${pct}%"></div>
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
        <div class="h-full rounded bg-gradient-to-r from-blue-500/70 to-blue-700/70" style="width:${pct}%"></div>
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
  const cloudUploadCount = events.filter(e => e.possible_upload).length;
  document.getElementById('cloud-stat-uploads').textContent = cloudUploadCount;
  _styleUploadCard('cloud', cloudUploadCount);

  // Populate service filter
  const svcSel = document.getElementById('cloud-filter-service');
  if (svcSel) {
    const cur = svcSel.value;
    const allSvcs = [...new Set(events.map(e => e.ai_service))].sort();
    svcSel.innerHTML = `<option value="">${t('cloud.allServices')}</option>`;
    allSvcs.forEach(s => { svcSel.innerHTML += `<option value="${s}">${svcDisplayName(s)}</option>`; });
    svcSel.value = cur;
  }

  renderEventsTable(events, 'cloud-tbody', 'cloud-empty', 'cloud-low-activity');
  updateCategoryCharts(events, timeline, 'cloud-service-chart', 'cloud-timeline-chart');
  renderTopUploaders(events);
}

// ---------------------------------------------------------------------------
// Top Data Exporters — rank devices by total upload bytes in the current view
// ---------------------------------------------------------------------------
function _fmtBytesShort(b) {
  if (!b || b <= 0) return '0 B';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

function renderTopUploaders(events) {
  const container = document.getElementById('cloud-top-uploaders');
  const totalEl = document.getElementById('cloud-uploaders-total');
  if (!container) return;

  // Aggregate only events flagged as possible upload
  const byIp = {};
  let grandTotal = 0;
  events.forEach(e => {
    if (!e.possible_upload || !e.bytes_transferred) return;
    const ip = e.source_ip;
    if (!byIp[ip]) byIp[ip] = { bytes: 0, events: 0, services: new Set() };
    byIp[ip].bytes += e.bytes_transferred;
    byIp[ip].events += 1;
    byIp[ip].services.add(e.ai_service);
    grandTotal += e.bytes_transferred;
  });

  const ranked = Object.entries(byIp)
    .map(([ip, agg]) => ({ ip, ...agg, services: [...agg.services] }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  if (ranked.length === 0) {
    container.innerHTML = `<p class="text-sm text-slate-400 dark:text-slate-500 italic text-center py-4">${t('cloud.noUploaders') || 'No uploads detected in this time window.'}</p>`;
    if (totalEl) totalEl.textContent = '';
    return;
  }

  if (totalEl) {
    totalEl.textContent = `${t('cloud.totalUploaded') || 'Total'}: ${_fmtBytesShort(grandTotal)}`;
  }

  const max = ranked[0].bytes;
  container.innerHTML = ranked.map((r, i) => {
    const pct = Math.max(3, (r.bytes / max) * 100);
    const dev = _deviceByIp(r.ip);
    const name = dev ? _bestDeviceName(dev.mac_address, dev) : r.ip;
    const macTag = dev && dev.mac_address
      ? `<span class="text-[10px] font-mono text-slate-400 dark:text-slate-500 ml-1.5">${dev.mac_address}</span>`
      : '';
    const svcList = r.services.slice(0, 3).map(s => svcDisplayName(s)).join(', ')
                   + (r.services.length > 3 ? ` +${r.services.length - 3}` : '');
    const barColor = i === 0 ? 'from-red-500 to-orange-500'
                  : i < 3 ? 'from-orange-500 to-amber-500'
                  : 'from-blue-500 to-blue-700';
    return `<div class="group">
      <div class="flex items-center justify-between gap-3 mb-1">
        <div class="flex items-center gap-2 min-w-0 flex-1">
          <span class="text-[11px] tabular-nums text-slate-400 dark:text-slate-500 w-5 text-right flex-shrink-0">#${i + 1}</span>
          <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${name}</span>
          ${macTag}
        </div>
        <span class="text-xs tabular-nums font-semibold text-slate-800 dark:text-slate-100 flex-shrink-0">${_fmtBytesShort(r.bytes)}</span>
      </div>
      <div class="flex items-center gap-2">
        <div class="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.04] overflow-hidden">
          <div class="h-full rounded-full bg-gradient-to-r ${barColor} transition-all duration-500" style="width:${pct}%"></div>
        </div>
        <span class="text-[10px] text-slate-400 dark:text-slate-500 tabular-nums w-16 text-right flex-shrink-0">${r.events} ev &middot; ${svcList}</span>
      </div>
    </div>`;
  }).join('');
}

// --- PRIVACY ---
let _cachedTopBlocked = [];
let _cachedAggregatedBlocked = [];

async function refreshPrivacy() {
  // Build filter params for tracker events
  const fp = getFilterParams('tracking');
  const privRes = await fetch('/api/privacy/stats?' + fp).then(r => r.json());

  // AdGuard section
  const ag = privRes.adguard || {};
  document.getElementById('priv-total').textContent = formatNumber(ag.total_queries || 0);
  document.getElementById('priv-blocked').textContent = formatNumber(ag.blocked_queries || 0);
  document.getElementById('priv-pct').textContent = (ag.block_percentage || 0) + '%';

  const unavail = document.getElementById('priv-unavailable');
  const chartC = document.getElementById('priv-chart-container');

  if (ag.status === 'ok') {
    if (unavail) unavail.classList.add('hidden');
    if (chartC) chartC.classList.remove('hidden');

    _cachedTopBlocked = ag.top_blocked || [];

    // Aggregate blocked domains by company+category for the bar chart
    const aggregated = groupBlockedByCompany(_cachedTopBlocked).slice(0, 10);
    _cachedAggregatedBlocked = aggregated;

    const bChart = getOrCreateChart('priv-chart', makeBarConfig());
    if (bChart) {
      bChart.data.labels = aggregated.map(d => d.label.length > 35 ? d.label.slice(0, 32) + '...' : d.label);
      bChart.data.datasets[0].data = aggregated.map(d => d.count);
      // Store domain lists for tooltip
      bChart._domainMap = aggregated.map(d => d.domains);
      bChart.options.plugins.tooltip = {
        callbacks: {
          afterBody: function(items) {
            const idx = items[0]?.dataIndex;
            const domains = bChart._domainMap?.[idx];
            if (domains && domains.length > 1) {
              return domains.slice(0, 5).map(d => '  ' + d).join('\n') +
                (domains.length > 5 ? `\n  +${domains.length - 5} more` : '');
            }
            if (domains?.length === 1) return '  ' + domains[0];
            return '';
          }
        }
      };
      bChart.update();
    }

    // Update blocked domains panel if visible
    const panel = document.getElementById('blocked-domains-panel');
    if (panel && !panel.classList.contains('hidden')) renderBlockedDomainsList();
  } else {
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

  // Tracker table — with company badges, category subtitles, device names, translated types
  const tbody = document.getElementById('tracker-table-body');
  const recent = tk.recent || [];
  if (tbody) {
    if (recent.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">${t('priv.noTrackers')}</td></tr>`;
    } else {
      // Collapse consecutive events per (tracker, type, device) within
      // 60s so a burst of identical tracker pings appears as one row
      // with a ×N badge instead of 50 visually-identical lines.
      const collapsed = _collapseConsecutiveEvents(
        recent,
        e => `${e.service}|${e.detection_type}|${e.source_ip}`,
      );
      tbody.innerHTML = collapsed.map(e => {
        // Resolve tracker company from service key or domain (if available)
        const trackerInfo = resolveTracker(e.service) || resolveTracker(e.domain || '');
        const trackerBadge = badge(e.service);
        const categoryLine = trackerInfo
          ? `<div class="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">${trackerInfo.category}</div>`
          : '';

        // Resolve source IP to device name
        const srcName = deviceName(e.source_ip);
        const srcDisplay = srcName !== e.source_ip
          ? `<span class="text-slate-700 dark:text-slate-200">${srcName}</span><div class="text-[10px] font-mono text-slate-400 dark:text-slate-500 mt-0.5">${e.source_ip}</div>`
          : `<span class="font-mono">${e.source_ip}</span>`;

        // Translate detection type
        const typeLabel = e.detection_type === 'sni_hello' ? t('priv.dnsQuery') : e.detection_type;
        const timeCell = e._count > 1
          ? `${fmtTime(e._newest_ts)} <span class="text-[10px] text-slate-400 dark:text-slate-500">– ${fmtTime(e._oldest_ts)}</span>`
          : fmtTime(e.timestamp);

        return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20">
          <td class="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500 whitespace-nowrap">${timeCell}</td>
          <td class="py-3 px-4"><div>${trackerBadge}${_countBadge(e)}</div>${categoryLine}</td>
          <td class="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">${typeLabel}</td>
          <td class="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">${srcDisplay}</td>
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
  _populateDeviceFilter('priv-filter-device');

  // VPN stat card + expandable panel
  renderVpnAlerts(privRes.vpn_alerts || []);

  // Security stat card (beaconing + future security category events)
  renderSecurityStats(privRes.security || {}, 'security-stat-count', 'security-stat-7d', 'security-spark');

  // Beaconing / C2 threat intelligence card
  renderBeaconAlerts(privRes.beaconing_alerts || [], privRes.beaconing_status || null);
}

// ---------------------------------------------------------------------------
// Security stats — stat card with 24h count + 7-day sparkline
// ---------------------------------------------------------------------------
function renderSecurityStats(stats, countId, weekId, sparkId) {
  const countEl = document.getElementById(countId);
  const weekEl = document.getElementById(weekId);
  const sparkEl = document.getElementById(sparkId);
  if (!countEl) return;

  const total24h = stats.total_24h || 0;
  const total7d = stats.total_7d || 0;
  const spark = Array.isArray(stats.sparkline_7d) ? stats.sparkline_7d : [0,0,0,0,0,0,0];

  countEl.textContent = total24h;
  if (weekEl) weekEl.textContent = total7d;

  // Sparkline: 7 bars, width 64px (viewBox 0..64), height 20
  if (sparkEl) {
    const max = Math.max(1, ...spark);
    const barW = 64 / spark.length;
    const gap = 1.5;
    const barInner = barW - gap;
    // Choose colour based on whether there are any hits at all
    const color = total7d > 0 ? '#ef4444' : '#94a3b8';
    sparkEl.innerHTML = spark.map((v, i) => {
      const h = Math.max(2, (v / max) * 18);
      const x = i * barW + gap / 2;
      const y = 20 - h;
      return `<rect x="${x.toFixed(2)}" y="${y.toFixed(2)}" width="${barInner.toFixed(2)}" height="${h.toFixed(2)}" rx="0.5" fill="${color}" opacity="${v > 0 ? 0.9 : 0.35}"/>`;
    }).join('');
  }
}

// ---------------------------------------------------------------------------
// Beaconing (malware C2) alert rendering
// ---------------------------------------------------------------------------
// Build the small scanner-status footer shown under the beacon panel.
// Makes "zero threats found" distinguishable from "scan hasn't run yet"
// or "scan is in progress". Without this, a clean home network looks
// identical to a broken feature.
function _beaconStatusFooter(status) {
  if (!status) return '';
  const running = !!status.running;
  const scansDone = status.scans_completed || 0;
  const lastAt = status.last_scan_at;
  const findings = status.last_findings || 0;
  const lastErr = status.last_error;

  let line;
  let cls = 'text-slate-400 dark:text-slate-500';
  if (lastErr) {
    line = `${t('beacon.scanError') || 'Scanner error'}: ${lastErr}`;
    cls = 'text-red-500 dark:text-red-400';
  } else if (running && scansDone === 0) {
    line = t('beacon.firstScanRunning') || 'First scan in progress…';
  } else if (scansDone === 0) {
    line = t('beacon.warmingUp') || 'Warming up — first scan starts ~90s after restart.';
  } else {
    const when = lastAt ? fmtTime(lastAt) : '—';
    const patternsLabel = findings === 1
      ? (t('beacon.onePattern') || '1 pattern found')
      : `${findings} ${t('beacon.patternsFound') || 'patterns found'}`;
    line = `${t('beacon.lastScan') || 'Last scan'}: ${when} · ${patternsLabel}`;
  }
  return `<div class="mt-3 pt-2 border-t border-slate-100 dark:border-white/[0.04] text-[11px] ${cls} flex items-center gap-1.5">
    <i class="ph-duotone ph-clock text-xs flex-shrink-0"></i>
    <span>${line}</span>
  </div>`;
}

function renderBeaconAlerts(alerts, status) {
  const body = document.getElementById('beacon-body');
  const badge = document.getElementById('beacon-badge');
  if (!body || !badge) return;

  if (!alerts || alerts.length === 0) {
    badge.textContent = t('beacon.clear') || 'All clear';
    badge.className = 'text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-medium';
    body.innerHTML = `
      <div class="flex items-center gap-2.5 text-emerald-600 dark:text-emerald-400">
        <i class="ph-duotone ph-shield-check text-xl flex-shrink-0"></i>
        <span class="text-sm font-medium">${t('beacon.noThreats') || 'Geen verdachte malware-beacons gedetecteerd.'}</span>
      </div>
      ${_beaconStatusFooter(status)}`;
    return;
  }

  // Threats found — show a prominent red alert list
  badge.textContent = `${alerts.length} ${t('beacon.detected') || 'threats'}`;
  badge.className = 'text-[10px] px-2 py-0.5 rounded-full bg-red-500 text-white font-bold animate-pulse';

  body.innerHTML = `
    <div class="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 flex items-start gap-2">
      <i class="ph-duotone ph-warning text-base mt-0.5 text-red-500 flex-shrink-0"></i>
      <p class="text-xs text-red-700 dark:text-red-300">
        <span class="font-semibold">${t('beacon.warning') || 'Warning'}:</span>
        ${t('beacon.warningText') || 'One or more devices are exhibiting highly periodic outbound connection patterns consistent with malware command &amp; control traffic.'}
      </p>
    </div>
    <div class="space-y-2">
      ${alerts.map(a => {
        const devName = a.display_name || (a.hostname && !_isJunkHostname(a.hostname) ? a.hostname : null)
                      || (a.vendor ? `${_shortVendor(a.vendor)} device` : null)
                      || a.mac_address
                      || a.source_ip;
        const macTag = a.mac_address
          ? `<span class="text-[10px] font-mono text-slate-400 dark:text-slate-500 ml-1">${a.mac_address}</span>`
          : '';
        const lastSeen = a.last_seen ? fmtTime(a.last_seen) : '';
        return `<div class="flex items-center justify-between px-3 py-2 rounded-lg bg-red-50/50 dark:bg-red-900/10 border border-red-200 dark:border-red-700/30 hover:bg-red-100/60 dark:hover:bg-red-900/20 transition-colors">
          <div class="flex items-center gap-3 min-w-0 flex-1">
            <span class="text-lg flex-shrink-0">🚨</span>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-sm font-semibold text-slate-800 dark:text-slate-100 truncate">${devName}</span>
                ${macTag}
              </div>
              <div class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                <span class="font-mono text-red-600 dark:text-red-400">${a.source_ip}</span>
                <span class="mx-1">→</span>
                <span class="font-mono text-red-600 dark:text-red-400">${a.dest_ip}</span>
              </div>
            </div>
          </div>
          <div class="text-right flex-shrink-0 ml-3">
            <div class="text-[10px] text-slate-400 dark:text-slate-500">${t('beacon.lastSeen') || 'Last seen'}</div>
            <div class="text-[11px] tabular-nums text-slate-600 dark:text-slate-300">${lastSeen}</div>
          </div>
        </div>`;
      }).join('')}
    </div>
    ${_beaconStatusFooter(status)}`;
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
          <i class="ph-duotone ph-shield-check text-xl text-emerald-500 dark:text-emerald-400"></i>
        </div>
        <p class="text-sm text-slate-500 dark:text-slate-400">${t('priv.noVpnTunnels')}</p>
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-1">${t('priv.vpnMonitoring')}</p>
      </div>`;
    return;
  }

  // Active alerts — orange warning
  const deviceWord = getLocale() === 'nl' ? (count === 1 ? 'apparaat' : 'apparaten') : (count === 1 ? 'device' : 'devices');
  statLabel.textContent = t('priv.deviceUsingVpn', { n: count, device: deviceWord });
  statLabel.className = 'text-orange-500 dark:text-orange-400';
  statCard.className = statCard.className
    .replace(/border-slate-200\s*/g, '').replace(/dark:border-white\/\[0\.05\]/g, '');
  if (!statCard.className.includes('border-orange')) {
    statCard.className += ' border-orange-500/40 dark:border-orange-500/30';
  }

  if (body) body.innerHTML = `
    <div class="overflow-x-auto max-h-64 overflow-y-auto">
      <table class="w-full text-sm text-left">
        <thead class="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium border-b border-slate-200 dark:border-white/[0.05] sticky top-0 bg-white dark:bg-[#0B0C10]">
          <tr>
            <th class="py-3 px-4 font-medium">${t('priv.thDevice')}</th>
            <th class="py-3 px-4 font-medium">${t('priv.thVpnService')}</th>
            <th class="py-3 px-4 font-medium">${t('priv.thData')}</th>
            <th class="py-3 px-4 font-medium">${t('priv.thEvents')}</th>
            <th class="py-3 px-4 font-medium">${t('priv.thLastSeen')}</th>
          </tr>
        </thead>
        <tbody class="text-slate-600 dark:text-slate-300">
          ${alerts.map(a => {
            const name = a.display_name || (a.hostname && !_isJunkHostname(a.hostname) ? a.hostname : null) || a.source_ip;
            const dtTag = typeof deviceTypeTag === 'function' ? deviceTypeTag(a) : '';
            const bytes = a.total_bytes >= 1048576
              ? (a.total_bytes / 1048576).toFixed(1) + ' MB'
              : (a.total_bytes / 1024).toFixed(0) + ' KB';
            // Stealth detection: if the aggregator saw stealth_vpn_tunnel events,
            // show a distinct red badge. Mixed traffic shows both badges.
            let serviceBadges = '';
            if (a.is_stealth) {
              serviceBadges = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-500/15 text-red-600 dark:bg-red-500/25 dark:text-red-300 border border-red-500/30" title="${t('priv.stealthVpnHint') || 'Tunneling protocol that evades normal VPN detection (AYIYA, Teredo, GRE, DPD heuristic)'}">🥷 ${t('priv.stealthVpn') || 'Stealth tunnel'}</span>`;
              if (a.regular_hits > 0) {
                serviceBadges += ` <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-orange-500/10 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400">🔒 ${t('priv.encryptedTunnel')}</span>`;
              }
            } else if (a.vpn_service && a.vpn_service.startsWith('vpn_') && a.vpn_service !== 'vpn_active') {
              serviceBadges = badge(a.vpn_service);
            } else {
              serviceBadges = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-orange-500/10 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400">🔒 ${t('priv.encryptedTunnel')}</span>`;
            }
            const rowClass = a.is_stealth
              ? 'border-b border-slate-100 dark:border-white/[0.04] hover:bg-red-50/50 dark:hover:bg-red-900/10 bg-red-50/30 dark:bg-red-900/5'
              : 'border-b border-slate-100 dark:border-white/[0.04] hover:bg-orange-50/50 dark:hover:bg-orange-900/10';
            return `<tr class="${rowClass}">
              <td class="py-3 px-4">
                <div class="font-medium text-xs">${name}</div>
                ${dtTag}
                <span class="text-[10px] font-mono text-slate-400 dark:text-slate-500 ml-1">${a.source_ip}</span>
              </td>
              <td class="py-3 px-4">${serviceBadges}</td>
              <td class="py-3 px-4 text-xs tabular-nums font-medium text-orange-600 dark:text-orange-400">${bytes}</td>
              <td class="py-3 px-4 text-xs tabular-nums">${a.hits}</td>
              <td class="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500">${fmtTime(a.last_seen)}</td>
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
    container.innerHTML = `<p class="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-4">${t('priv.noBlockedData')}</p>`;
    return;
  }
  const maxCount = _cachedTopBlocked[0]?.count || 1;
  container.innerHTML = _cachedTopBlocked.map((d, i) => {
    const pct = Math.max(5, (d.count / maxCount) * 100);
    const info = resolveTracker(d.domain);
    const displayName = info ? `${info.company}` : _readableDomain(d.domain);
    const catTag = info ? `<span class="text-[9px] text-slate-400 dark:text-slate-500 ml-1">${info.category}</span>` : '';
    return `<div class="flex items-center gap-3 bg-slate-50 dark:bg-white/[0.03] rounded-lg px-3 py-2 border border-slate-200 dark:border-white/[0.04]">
      <span class="text-[10px] text-slate-400 w-4 text-right tabular-nums">${i + 1}</span>
      <div class="flex-1 min-w-0">
        <p class="text-[11px] font-medium text-slate-700 dark:text-slate-200 truncate" title="${d.domain}">${displayName}${catTag}</p>
        <p class="text-[9px] font-mono text-slate-400 dark:text-slate-500 truncate">${d.domain}</p>
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
    container.innerHTML = `<p class="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-4">${t('priv.noTrackerData')}</p>`;
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

// ================================================================
// IoT DEVICES — fleet overview + anomaly alerts
// ================================================================

async function refreshIot() {
  try {
    const [fleet, anomalies] = await Promise.all([
      fetch('/api/iot/fleet').then(r => r.json()),
      fetch('/api/iot/anomalies').then(r => r.json()),
    ]);
    _renderIotStats(fleet);
    _renderIotAnomalies(anomalies);
    _renderIotFleet(fleet);
  } catch (err) {
    console.error('refreshIot:', err);
  }
}

function _renderIotStats(data) {
  const el = document.getElementById('iot-stats');
  if (!el) return;
  const healthCounts = { green: 0, orange: 0, red: 0 };
  (data.devices || []).forEach(d => { healthCounts[d.health] = (healthCounts[d.health] || 0) + 1; });

  el.innerHTML = `
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('iot.totalDevices') || 'IoT Devices'}</p>
      <p class="text-2xl font-bold mt-2 tabular-nums">${data.total_devices || 0}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('iot.dataToday') || 'Data Today'}</p>
      <p class="text-2xl font-bold mt-2 tabular-nums">${_fmtBytes(data.total_bytes_24h || 0)}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border ${data.anomaly_devices > 0 ? 'border-red-300 dark:border-red-700/40' : 'border-slate-200 dark:border-white/[0.05]'} rounded-xl p-5 card-hover">
      <p class="text-xs ${data.anomaly_devices > 0 ? 'text-red-500 dark:text-red-400' : 'text-slate-500 dark:text-slate-400'} font-medium">${t('iot.anomalies') || 'Anomalies'}</p>
      <p class="text-2xl font-bold mt-2 tabular-nums ${data.anomaly_devices > 0 ? 'text-red-500' : ''}">${data.anomaly_devices || 0}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('iot.topTalker') || 'Top Talker'}</p>
      <p class="text-lg font-bold mt-2 truncate">${data.top_talker || '—'}</p>
    </div>
  `;
}

function _renderIotAnomalies(data) {
  const el = document.getElementById('iot-anomalies-section');
  if (!el) return;
  const anomalies = data.anomalies || [];
  if (anomalies.length === 0) {
    el.innerHTML = '';
    return;
  }
  el.innerHTML = `
    <div class="bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-700/30 rounded-xl p-5">
      <h3 class="text-lg font-semibold text-red-600 dark:text-red-400 mb-3 flex items-center gap-2">
        <i class="ph-duotone ph-siren text-xl"></i> ${t('iot.anomalyTitle') || 'Security Anomalies'}
      </h3>
      <div class="space-y-2">
        ${anomalies.map(a => {
          const devName = a.display_name || a.hostname || a.mac || a.source_ip;
          const typeLabel = a.detection_type === 'iot_lateral_movement'
            ? `<span class="text-red-600 dark:text-red-400 font-semibold">${t('iot.lateralMovement') || 'Lateral Movement'}</span>`
            : `<span class="text-orange-600 dark:text-orange-400 font-semibold">${t('iot.suspiciousPort') || 'Suspicious Port'}</span>`;
          return `<div class="flex items-center justify-between p-3 rounded-lg bg-white dark:bg-white/[0.03] border border-red-100 dark:border-red-800/30">
            <div class="flex items-center gap-3 min-w-0">
              <i class="ph-duotone ph-warning text-lg text-red-500 flex-shrink-0"></i>
              <div class="min-w-0">
                <div class="text-sm font-medium text-slate-800 dark:text-white truncate">${devName}</div>
                <div class="text-xs text-slate-500 dark:text-slate-400">${typeLabel} · ${a.detail} · ${a.hits} hits</div>
              </div>
            </div>
            <span class="text-[10px] text-slate-400 tabular-nums flex-shrink-0">${fmtTime(a.last_seen)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>`;
}

function _renderIotFleet(data) {
  const el = document.getElementById('iot-fleet-grid');
  if (!el) return;
  const devices = data.devices || [];
  if (devices.length === 0) {
    el.innerHTML = `<p class="text-slate-400 dark:text-slate-500 text-sm col-span-full text-center py-8">${t('iot.noDevices') || 'No IoT devices detected on your network.'}</p>`;
    return;
  }

  el.innerHTML = devices.map(d => {
    const name = d.display_name || d.hostname || d.mac_address;
    const healthColor = d.health === 'red' ? 'border-red-300 dark:border-red-700/50 bg-red-50/30 dark:bg-red-900/5'
                      : d.health === 'orange' ? 'border-amber-300 dark:border-amber-700/50 bg-amber-50/30 dark:bg-amber-900/5'
                      : 'border-slate-200 dark:border-white/[0.05]';
    const healthDot = d.health === 'red' ? 'bg-red-500'
                    : d.health === 'orange' ? 'bg-amber-500'
                    : 'bg-emerald-500';
    const dt = _detectDeviceType(d);

    return `<div class="border ${healthColor} rounded-xl p-4 bg-white dark:bg-white/[0.03] transition-colors cursor-pointer hover:shadow-md" onclick="openDeviceDrawer('${d.mac_address}', null, null)">
      <div class="flex items-center gap-2 mb-2">
        <span class="flex-shrink-0">${dt.icon}</span>
        <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${name}</span>
        <span class="w-2 h-2 rounded-full ${healthDot} flex-shrink-0 ml-auto"></span>
      </div>
      <p class="text-[10px] text-slate-400 dark:text-slate-500 mb-2">${d.device_type || dt.type}</p>
      <div class="flex items-center justify-between text-[10px] tabular-nums">
        <span class="text-slate-500 dark:text-slate-400">${_fmtBytes(d.bytes_24h)}/day</span>
        <span class="text-slate-400 dark:text-slate-500">${d.destinations} dest.</span>
        ${d.anomalies > 0 ? `<span class="text-red-500 font-semibold">${d.anomalies} <i class="ph-duotone ph-warning text-[9px]"></i></span>` : ''}
      </div>
    </div>`;
  }).join('');
}


let _otherFiltersPopulated = false;

// ================================================================
// OTHER USAGE — category tree accordion
// ================================================================

const CATEGORY_META = {
  gaming:    { icon: '<i class="ph-duotone ph-game-controller text-xl"></i>', color: 'indigo' },
  social:    { icon: '<i class="ph-duotone ph-chat-circle-text text-xl"></i>', color: 'pink' },
  streaming: { icon: '<i class="ph-duotone ph-play-circle text-xl"></i>', color: 'purple' },
  shopping:  { icon: '<i class="ph-duotone ph-shopping-bag text-xl"></i>', color: 'amber' },
  gambling:  { icon: '<i class="ph-duotone ph-dice-five text-xl"></i>', color: 'rose' },
};

function _fmtBytes(b) {
  if (!b || b <= 0) return '0 B';
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

async function refreshOther() {
  const filters = _buildInsightFilters('other');
  const [tree, devices] = await Promise.all([
    fetch(`/api/analytics/category-tree?${filters}`).then(r => r.json()),
    fetch('/api/devices').then(r => r.json()),
  ]);

  // Populate filter dropdowns on first render from the device list
  // and the services surfaced in the tree response itself.
  if (!_otherFiltersPopulated) {
    _otherFiltersPopulated = true;
    _populateDeviceFilter('other-filter-device');
    // Services from the current tree response — everything under
    // every category.
    const svcList = [];
    (tree || []).forEach(cat => (cat.services || []).forEach(s => svcList.push(s.service_name)));
    _populateFilterSelect('other-filter-service', svcList,
      t('ai.allServices') || 'All services', svc => svcDisplayName(svc));
  }

  // Build IP → device name map
  const ipName = {};
  (devices || []).forEach(d => {
    const name = _bestDeviceName(d.mac_address, d);
    (d.ips || []).forEach(ipRec => { ipName[ipRec.ip] = name; });
  });

  // Stats cards
  const statsEl = document.getElementById('other-stats');
  if (statsEl) {
    statsEl.innerHTML = (tree || []).map(cat => {
      const m = CATEGORY_META[cat.category] || { icon: '<i class="ph-duotone ph-chart-bar text-xl"></i>', color: 'slate' };
      const totalHits = cat.services.reduce((s, svc) => s + svc.devices.reduce((a, d) => a + d.hits, 0), 0);
      const uniqueDevices = new Set(cat.services.flatMap(svc => svc.devices.map(d => d.ip))).size;
      return `<div class="bg-white dark:bg-${m.color}-900/10 border border-slate-200 dark:border-${m.color}-700/30 rounded-xl p-5 card-hover">
        <p class="text-xs text-${m.color}-500 dark:text-${m.color}-400 font-medium">${m.icon} ${t('other.cat.' + cat.category) || cat.category}</p>
        <p class="text-2xl font-bold mt-2 tabular-nums text-${m.color}-600 dark:text-${m.color}-400">${totalHits}</p>
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-1">${cat.services.length} services · ${uniqueDevices} ${t('other.devices')}</p>
      </div>`;
    }).join('');
  }

  // Tree accordion
  const container = document.getElementById('other-usage-tree-container');
  if (!container) return;

  if (!tree || tree.length === 0) {
    container.innerHTML = `<div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
      <p class="text-slate-400 dark:text-slate-500 text-sm">${t('other.noData')}</p>
    </div>`;
    return;
  }

  container.innerHTML = tree.map((cat, ci) => {
    const m = CATEGORY_META[cat.category] || { icon: '<i class="ph-duotone ph-chart-bar text-xl"></i>', color: 'slate' };
    const catLabel = t('other.cat.' + cat.category) || cat.category;
    const totalHits = cat.services.reduce((s, svc) => s + svc.devices.reduce((a, d) => a + d.hits, 0), 0);

    const servicesHtml = cat.services.map((svc, si) => {
      const svcName = SERVICE_NAMES[svc.service_name] || svc.service_name;
      // Use the shared favicon-based svcLogo helper — same source as
      // badges, device drawer Summary, and Action Inbox. The old code
      // used logo.clearbit.com which has been dead since Dec 2023.
      const logoImg = svcLogo(svc.service_name);
      const svcHits = svc.devices.reduce((a, d) => a + d.hits, 0);

      const devicesHtml = svc.devices.map(d => {
        const dName = ipName[d.ip] || d.ip;
        return `<div class="flex items-center justify-between py-2 px-4 text-xs border-b border-slate-100 dark:border-white/[0.03] last:border-0">
          <span class="text-slate-600 dark:text-slate-300">${dName} <span class="text-slate-400 dark:text-slate-500 font-mono text-[10px] ml-1">${d.ip}</span></span>
          <span class="flex items-center gap-3">
            <span class="tabular-nums font-medium text-slate-700 dark:text-slate-200">${_fmtBytes(d.bytes)}</span>
            <span class="tabular-nums text-slate-400 dark:text-slate-500 w-12 text-right">${d.hits} ${t('other.hits')}</span>
          </span>
        </div>`;
      }).join('');

      return `<div class="border-b border-slate-100 dark:border-white/[0.04] last:border-0">
        <button onclick="this.nextElementSibling.classList.toggle('hidden');this.querySelector('.other-chevron').classList.toggle('rotate-90')"
                class="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors group">
          <span class="flex items-center gap-2.5">
            ${logoImg}
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${svcName}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400">${svc.devices.length} ${t('other.devices')}</span>
          </span>
          <span class="flex items-center gap-3">
            <span class="text-xs tabular-nums font-medium text-slate-600 dark:text-slate-300">${_fmtBytes(svc.total_bytes)}</span>
            <span class="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">${svcHits} ${t('other.hits')}</span>
            <i class="other-chevron ph-duotone ph-caret-right text-base text-slate-400 transition-transform duration-200 inline-block"></i>
          </span>
        </button>
        <div class="hidden bg-slate-50/50 dark:bg-white/[0.01]">
          ${devicesHtml}
        </div>
      </div>`;
    }).join('');

    return `<div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
      <button onclick="this.nextElementSibling.classList.toggle('hidden');this.querySelector('.other-chevron').classList.toggle('rotate-90')"
              class="w-full flex items-center justify-between px-5 py-4 hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors">
        <span class="flex items-center gap-3">
          <span class="text-xl">${m.icon}</span>
          <span class="text-base font-semibold text-slate-800 dark:text-white">${catLabel}</span>
          <span class="text-[10px] px-2 py-0.5 rounded-full bg-${m.color}-100 dark:bg-${m.color}-900/30 text-${m.color}-600 dark:text-${m.color}-400 font-medium">${cat.services.length} services</span>
        </span>
        <span class="flex items-center gap-3">
          <span class="text-sm tabular-nums font-semibold text-slate-700 dark:text-slate-200">${_fmtBytes(cat.total_bytes)}</span>
          <span class="text-xs tabular-nums text-slate-400 dark:text-slate-500">${totalHits} ${t('other.hits')}</span>
          <i class="other-chevron ph-duotone ph-caret-right text-lg text-slate-400 transition-transform duration-200 rotate-90 inline-block"></i>
        </span>
      </button>
      <div class="border-t border-slate-200 dark:border-white/[0.05]">
        ${servicesHtml}
      </div>
    </div>`;
  }).join('');
}


// ================================================================
// GEO TRAFFIC — world map + country table with inbound/outbound tabs
// ================================================================
let _geoDirection = 'outbound';
let _geoMap = null;
let _geoData = null;

// Convert a 2-letter ISO country code to a flag emoji using Unicode
// regional indicator symbols (0x1F1E6 + letter offset).
function _flagEmoji(cc) {
  // Returns an HTML string using the flag-icons CSS library for
  // consistent rectangular SVG flags across all platforms (replaces
  // OS-native Unicode emoji flags which look different on every OS).
  if (!cc || cc.length !== 2) return '<i class="ph-duotone ph-globe text-slate-400"></i>';
  const code = cc.toLowerCase();
  return `<span class="fi fi-${code} rounded-sm shadow-sm inline-block" style="font-size:1.1em"></span>`;
}

function _geoFmtBytes(b) {
  if (!b || b <= 0) return '0 B';
  if (b >= 1099511627776) return (b / 1099511627776).toFixed(2) + ' TB';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

async function refreshGeo() {
  return loadGeoTraffic(_geoDirection);
}

// Build filter params for the Geo and Other pages. Mirrors the AI
// page pattern (service/device/period) so all three insight pages
// behave the same way.
function _buildInsightFilters(prefix) {
  const p = new URLSearchParams();
  const svc = document.getElementById(`${prefix}-filter-service`)?.value;
  const dev = document.getElementById(`${prefix}-filter-device`)?.value;
  const per = document.getElementById(`${prefix}-filter-period`)?.value;
  if (svc) p.set('service', svc);
  if (dev) p.set('source_ip', dev);
  if (per) p.set('start', new Date(Date.now() - parseInt(per) * 60000).toISOString());
  return p;
}

// Populate a <select> with an "All X" option and a sorted list of
// values. Preserves the current selection where possible.
function _populateFilterSelect(id, values, allLabel, displayFn) {
  const sel = document.getElementById(id);
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${allLabel}</option>`;
  [...new Set(values)].filter(Boolean).sort().forEach(v => {
    const label = displayFn ? displayFn(v) : v;
    sel.innerHTML += `<option value="${v}">${label}</option>`;
  });
  sel.value = cur;
}

// Populate a device filter <select> from the global deviceMap.
// Uses comma-separated IPs as value so backend source_ip filters
// catch both IPv4 and IPv6 traffic from the same physical device.
// This is the SINGLE source of truth for all device dropdowns —
// use it everywhere instead of ad-hoc IP-from-events approaches.
function _populateDeviceFilter(selectId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${t('ai.allDevices') || 'All devices'}</option>`;
  const entries = Object.entries(deviceMap)
    .map(([mac, d]) => ({
      label: _bestDeviceName(mac, d),
      value: (d.ips || []).map(i => i.ip).join(','),
    }))
    .filter(e => e.value)
    .sort((a, b) => a.label.localeCompare(b.label));
  entries.forEach(e => {
    sel.innerHTML += `<option value="${e.value}">${e.label}</option>`;
  });
  sel.value = cur;
}

async function loadGeoTraffic(direction) {
  _geoDirection = direction;
  try {
    const filters = _buildInsightFilters('geo');
    filters.set('direction', direction);
    const res = await fetch(`/api/analytics/geo?${filters}`);
    const data = await res.json();
    _geoData = data;
    _renderGeoStats(data);
    _renderGeoMap(data);
    _renderGeoTable(data);

    // Populate filter dropdowns from the device list + the services
    // we see in the conversations table (via a second lightweight
    // request the first time). Only runs once per page visit.
    if (!_geoFiltersPopulated) {
      _geoFiltersPopulated = true;
      _populateDeviceFilter('geo-filter-device');

      // Services list: pull from a quick /api/events scan (any category)
      try {
        const evs = await fetch('/api/events?limit=1000').then(r => r.json());
        _populateFilterSelect('geo-filter-service',
          (evs || []).map(e => e.ai_service),
          t('ai.allServices') || 'All services',
          svc => svcDisplayName(svc));
      } catch (e) { console.warn('geo service filter:', e); }
    }
  } catch (err) {
    console.error('loadGeoTraffic:', err);
  }
}
let _geoFiltersPopulated = false;

function switchGeoTab(direction) {
  const outBtn = document.getElementById('geo-tab-outbound');
  const inBtn  = document.getElementById('geo-tab-inbound');
  // Shared tab classes — match the Rules / AI / Settings style
  // so every sub-tab in the app looks identical.
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  // Preserve the icon+label markup by only rewriting className.
  if (direction === 'outbound') {
    if (outBtn) outBtn.className = active;
    if (inBtn) inBtn.className = inactive;
  } else {
    if (outBtn) outBtn.className = inactive;
    if (inBtn) inBtn.className = active;
  }
  loadGeoTraffic(direction);
}
window.switchGeoTab = switchGeoTab;

function _renderGeoStats(data) {
  const container = document.getElementById('geo-stats');
  if (!container) return;
  const countries = data.countries || [];
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0);
  const totalHits = countries.reduce((s, c) => s + c.hits, 0);
  const top = countries[0];
  const topLabel = top ? `${_flagEmoji(top.country_code)} ${top.country_code}` : '—';
  const dirLabel = data.direction === 'outbound'
    ? (t('geo.outboundShort') || 'Outbound')
    : (t('geo.inboundShort') || 'Inbound');

  container.innerHTML = `
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('geo.statCountries') || 'Countries'}</p>
      <p class="text-2xl font-bold mt-2 tabular-nums">${countries.length}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('geo.statBandwidth') || 'Total bandwidth'} (${dirLabel})</p>
      <p class="text-2xl font-bold mt-2 tabular-nums">${_geoFmtBytes(totalBytes)}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('geo.statConnections') || 'Connections'}</p>
      <p class="text-2xl font-bold mt-2 tabular-nums">${formatNumber(totalHits)}</p>
    </div>
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <p class="text-xs text-slate-500 dark:text-slate-400 font-medium">${t('geo.statTop') || 'Top destination'}</p>
      <p class="text-2xl font-bold mt-2">${topLabel}</p>
      <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-1">${top ? _geoFmtBytes(top.bytes) : ''}</p>
    </div>
  `;
}

function _renderGeoMap(data) {
  const wrap = document.getElementById('geo-map-wrap');
  const empty = document.getElementById('geo-map-empty');
  if (!wrap || !empty) return;

  const countries = data.countries || [];
  if (countries.length === 0) {
    wrap.classList.add('hidden');
    empty.classList.remove('hidden');
    return;
  }
  wrap.classList.remove('hidden');
  empty.classList.add('hidden');

  // Build country → bytes map for jsVectorMap. jsVectorMap uses uppercase
  // ISO-3166-1 alpha-2 codes to identify countries on the world map.
  const values = {};
  countries.forEach(c => { values[c.country_code] = c.bytes; });

  // Legend
  const max = countries[0]?.bytes || 0;
  const legend = document.getElementById('geo-map-legend');
  if (legend) legend.textContent = `${t('geo.scaleMax') || 'Darker = more traffic'} (max ${_geoFmtBytes(max)})`;

  // Tear down previous map if present (jsVectorMap doesn't support data swap)
  const container = document.getElementById('geo-map');
  if (!container) return;
  if (_geoMap) {
    try { _geoMap.destroy(); } catch (e) { /* ignore */ }
    _geoMap = null;
  }
  container.innerHTML = '';

  const dark = isDark();
  const bg = dark ? '#0B0C10' : '#f8fafc';
  const scaleColors = dark ? ['#334155', '#7c3aed', '#ef4444'] : ['#e2e8f0', '#a78bfa', '#dc2626'];

  // jsVectorMap v1.x uses jsVectorMap global. Some builds expose it as
  // window.jsVectorMap or as a default export.
  const JVM = window.jsVectorMap || window.jsvectormap;
  if (!JVM) {
    console.warn('jsVectorMap not loaded');
    return;
  }

  try {
    _geoMap = new JVM({
      selector: '#geo-map',
      map: 'world',
      backgroundColor: bg,
      zoomOnScroll: false,
      zoomButtons: true,
      regionStyle: {
        initial: {
          fill: dark ? '#1e293b' : '#e2e8f0',
          stroke: dark ? '#0f172a' : '#cbd5e1',
          strokeWidth: 0.4,
        },
        hover: {
          fill: dark ? '#6366f1' : '#818cf8',
          cursor: 'pointer',
        },
      },
      visualizeData: {
        scale: scaleColors,
        values: values,
      },
      onRegionTooltipShow(event, tooltip, code) {
        const bytes = values[code] || 0;
        const entry = countries.find(c => c.country_code === code);
        const hits = entry ? entry.hits : 0;
        const name = tooltip.text();
        if (bytes > 0) {
          tooltip.text(
            `<div class="font-semibold">${_flagEmoji(code)} ${name}</div>` +
            `<div class="text-xs">${_geoFmtBytes(bytes)} &middot; ${formatNumber(hits)} conn.</div>` +
            `<div class="text-[10px] opacity-70 mt-0.5">${t('geo.clickForDetails') || 'Click for details'}</div>`,
            true
          );
        } else {
          tooltip.text(`${_flagEmoji(code)} ${name}`, true);
        }
      },
      onRegionClick(event, code) {
        if (!code) return;
        // Only drill into countries we actually have data for.
        if (!values[code] || values[code] <= 0) return;
        openCountryDrawer(code);
      },
    });
  } catch (err) {
    console.error('jsVectorMap init failed:', err);
    container.innerHTML = `<p class="text-center text-sm text-red-500 py-12">Map error: ${err.message}</p>`;
  }
}

// Classify a country row by its inbound/outbound ratio into one of
// three buckets used for left-border coloring on the geo table.
//   outbound >> inbound (>3x) → orange  (upload / push / sync heavy)
//   inbound  >> outbound (>3x) → blue    (streaming / download heavy)
//   otherwise                  → slate   (balanced)
// Called with the row's bytes (matches the currently-selected
// direction) and opposite_bytes from the API.
function _geoRatioClass(bytes, opposite, direction) {
  const a = bytes || 0;
  const b = opposite || 0;
  if (a === 0 && b === 0) return 'border-l-2 border-slate-200 dark:border-white/[0.04]';
  const outBytes = direction === 'outbound' ? a : b;
  const inBytes  = direction === 'outbound' ? b : a;
  if (outBytes > inBytes * 3) return 'border-l-2 border-orange-400';
  if (inBytes  > outBytes * 3) return 'border-l-2 border-sky-400';
  return 'border-l-2 border-slate-300 dark:border-slate-600';
}

function _renderGeoTable(data) {
  const tbody = document.getElementById('geo-table-body');
  if (!tbody) return;
  const countries = data.countries || [];
  if (countries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-xs text-slate-400 dark:text-slate-500">${t('geo.noData') || 'No geo traffic data yet.'}</td></tr>`;
    return;
  }
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0) || 1;
  tbody.innerHTML = countries.map((c, i) => {
    const pct = (c.bytes / totalBytes) * 100;
    const pctLabel = pct.toFixed(1);
    const barColor = i === 0 ? 'from-red-500 to-orange-500'
                   : i < 3 ? 'from-orange-500 to-amber-500'
                   : 'from-blue-500 to-blue-700';
    const ratioCls = _geoRatioClass(c.bytes, c.opposite_bytes, data.direction);
    // Top-3 devices line — stacked chips with truncation
    const devChips = (c.top_devices || []).slice(0, 3).map(d => {
      const name = (d.name || d.mac || '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
      return `<span class="inline-block px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.05] text-[10px] text-slate-600 dark:text-slate-300 truncate max-w-[120px]" title="${name}">${name}</span>`;
    }).join(' ');
    const devCell = devChips || `<span class="text-[10px] text-slate-400 dark:text-slate-600">—</span>`;
    return `<tr class="${ratioCls} border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50/60 dark:hover:bg-white/[0.02] transition-colors cursor-pointer" onclick="openCountryDrawer('${c.country_code}')">
      <td class="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500">#${i + 1}</td>
      <td class="py-3 px-4">
        <span class="inline-flex items-center gap-2">
          <span class="text-lg leading-none">${_flagEmoji(c.country_code)}</span>
          <span class="font-mono font-semibold text-slate-700 dark:text-slate-200">${c.country_code}</span>
        </span>
      </td>
      <td class="py-3 px-4 text-xs tabular-nums font-medium text-slate-700 dark:text-slate-200">${_geoFmtBytes(c.bytes)}</td>
      <td class="py-3 px-4 text-xs tabular-nums text-slate-500 dark:text-slate-400">${formatNumber(c.hits)}</td>
      <td class="py-3 px-4 hidden md:table-cell"><div class="flex flex-wrap gap-1">${devCell}</div></td>
      <td class="py-3 px-4 min-w-[140px]">
        <div class="flex items-center gap-2">
          <div class="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.04] overflow-hidden">
            <div class="h-full rounded-full bg-gradient-to-r ${barColor}" style="width:${Math.max(2, pct).toFixed(1)}%"></div>
          </div>
          <span class="text-[10px] tabular-nums text-slate-500 dark:text-slate-400 w-10 text-right">${pctLabel}%</span>
        </div>
      </td>
    </tr>`;
  }).join('');
}

// ---------------------------------------------------------------------------
// Country Drawer — drilldown for a single country from the Geo page
// ---------------------------------------------------------------------------
// Mirrors the device drawer UX but focused on a country. Reachable from:
//   1. Clicking a country on the vector map (onRegionClick)
//   2. Clicking a row in the geo table
// Reuses the existing .drawer-panel CSS for the slide-in animation.

let _countryDrawerCC = null;
let _countryDrawerDirection = 'outbound';

// Full country name lookup via the browser's built-in Intl API. Falls
// back to the raw ISO code if the runtime doesn't support it.
function _countryName(cc) {
  try {
    const dn = new Intl.DisplayNames([getLocale ? getLocale() : 'en'], { type: 'region' });
    return dn.of(cc) || cc;
  } catch (e) {
    return cc;
  }
}

async function openCountryDrawer(cc) {
  if (!cc) return;
  _countryDrawerCC = cc;
  _countryDrawerDirection = _geoDirection || 'outbound';

  // _flagEmoji returns HTML (not a text char), so use innerHTML.
  document.getElementById('country-drawer-flag').innerHTML = _flagEmoji(cc);
  document.getElementById('country-drawer-name').textContent = `${_countryName(cc)} (${cc})`;
  document.getElementById('country-drawer-meta').textContent = t('country.loading') || 'Loading…';

  // Mark the direction toggle visually
  _syncCountryDirButtons();

  document.getElementById('country-drawer-backdrop').classList.add('open');
  const panel = document.getElementById('country-drawer-panel');
  panel.style.transform = '';
  panel.classList.add('open');
  document.body.classList.add('overflow-hidden');

  await _loadCountryDrawer();
}

function _syncCountryDirButtons() {
  const out = document.getElementById('country-dir-out');
  const inb = document.getElementById('country-dir-in');
  // Shared tab classes — match Rules / AI / Settings / Geo.
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  if (!out || !inb) return;
  if (_countryDrawerDirection === 'outbound') { out.className = active; inb.className = inactive; }
  else                                         { inb.className = active; out.className = inactive; }
}

function setCountryDrawerDirection(dir) {
  if (dir !== 'outbound' && dir !== 'inbound') return;
  _countryDrawerDirection = dir;
  _syncCountryDirButtons();
  _loadCountryDrawer();
}

async function _loadCountryDrawer() {
  const cc = _countryDrawerCC;
  const dir = _countryDrawerDirection;
  if (!cc) return;
  try {
    const res = await fetch(`/api/analytics/geo/country/${encodeURIComponent(cc)}?direction=${encodeURIComponent(dir)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (_countryDrawerCC !== cc) return; // user navigated away
    _renderCountryDrawer(data);
  } catch (err) {
    console.error('loadCountryDrawer:', err);
    document.getElementById('country-drawer-meta').textContent = t('country.loadError') || 'Failed to load country data';
  }
}

function _renderCountryDrawer(data) {
  const dirLabel = data.direction === 'outbound'
    ? (t('geo.outbound') || 'Outbound')
    : (t('geo.inbound') || 'Inbound');
  document.getElementById('country-drawer-meta').textContent =
    `${dirLabel} · ${_geoFmtBytes(data.total_bytes)} · ${formatNumber(data.total_hits)} ${t('geo.connectionsShort') || 'conn.'}`;

  // --- Top devices ---
  const devEl = document.getElementById('country-top-devices');
  const devs = data.top_devices || [];
  if (devs.length === 0) {
    devEl.innerHTML = `<div class="text-xs text-slate-400 dark:text-slate-500 py-3">${t('country.noDevices') || 'No devices recorded.'}</div>`;
  } else {
    const maxB = devs[0].bytes || 1;
    devEl.innerHTML = devs.map(d => {
      const w = Math.max(2, (d.bytes / maxB * 100));
      const vendor = d.vendor ? `<span class="text-[10px] text-slate-400 dark:text-slate-500 ml-1">${d.vendor}</span>` : '';
      const onClick = d.mac ? `onclick="closeCountryDrawer();openDeviceDrawer('${d.mac}', null, null)"` : '';
      return `<div class="flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] ${d.mac ? 'cursor-pointer' : ''}" ${onClick}>
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline justify-between gap-2">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${d.name}${vendor}</span>
            <span class="text-xs tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">${_geoFmtBytes(d.bytes)}</span>
          </div>
          <div class="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
            <div class="h-full bg-gradient-to-r from-blue-500 to-blue-700" style="width:${w}%"></div>
          </div>
        </div>
      </div>`;
    }).join('');
  }

  // --- Top services ---
  const svcEl = document.getElementById('country-top-services');
  const svcs = data.top_services || [];
  if (svcs.length === 0) {
    svcEl.innerHTML = `<div class="text-xs text-slate-400 dark:text-slate-500 py-3">${t('country.noServices') || 'No services recorded.'}</div>`;
  } else {
    const maxB = svcs[0].bytes || 1;
    svcEl.innerHTML = svcs.map(s => {
      const w = Math.max(2, (s.bytes / maxB * 100));
      return `<div class="flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03]">
        <div class="flex-shrink-0">${svcLogo(s.service)}</div>
        <div class="flex-1 min-w-0">
          <div class="flex items-baseline justify-between gap-2">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${svcDisplayName(s.service)}</span>
            <span class="text-xs tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">${_geoFmtBytes(s.bytes)}</span>
          </div>
          <div class="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
            <div class="h-full bg-gradient-to-r from-emerald-500 to-teal-500" style="width:${w}%"></div>
          </div>
        </div>
      </div>`;
    }).join('');
  }

  // --- Top IPs with ASN / PTR ---
  // Label priority per row, from most to least informative:
  //   1. ASN + org available → "AS15169 · Google LLC"
  //   2. Only PTR available   → "server-...cloudfront.net"
  //   3. Enrichment completed but empty → "(no reverse DNS / ASN)"
  //   4. Enrichment not yet run         → "enriching…"
  const ipEl = document.getElementById('country-top-ips');
  const ips = data.top_ips || [];
  if (ips.length === 0) {
    ipEl.innerHTML = `<div class="text-xs text-slate-400 dark:text-slate-500 py-3">${t('country.noIps') || 'No remote IPs recorded.'}</div>`;
  } else {
    ipEl.innerHTML = ips.map(ip => {
      let primary = '';   // big label line
      let secondary = ''; // small detail line

      if (ip.asn_org) {
        primary = `<div class="text-xs text-slate-700 dark:text-slate-200 truncate">AS${ip.asn || '?'} · ${ip.asn_org}</div>`;
        if (ip.ptr) {
          secondary = `<div class="text-[10px] font-mono text-slate-400 dark:text-slate-500 truncate">${ip.ptr}</div>`;
        }
      } else if (ip.ptr) {
        primary = `<div class="text-xs text-slate-700 dark:text-slate-200 font-mono truncate">${ip.ptr}</div>`;
      } else if (ip.enriched) {
        primary = `<div class="text-xs text-slate-400 dark:text-slate-600 italic">${t('country.ipNoRdns') || '(no reverse DNS / ASN)'}</div>`;
      } else {
        primary = `<div class="text-xs text-slate-400 dark:text-slate-600 italic">${t('country.ipEnriching') || 'enriching…'}</div>`;
      }

      return `<div class="flex items-center justify-between py-2 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] border-b border-slate-100 dark:border-white/[0.04] last:border-0">
        <div class="min-w-0 flex-1">
          <div class="font-mono text-[10px] text-slate-400 dark:text-slate-500 truncate">${ip.ip}</div>
          ${primary}
          ${secondary}
        </div>
        <div class="flex-shrink-0 text-right ml-3">
          <div class="text-xs tabular-nums font-medium text-slate-700 dark:text-slate-200">${_geoFmtBytes(ip.bytes)}</div>
          <div class="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">${formatNumber(ip.hits)} ${t('geo.connectionsShort') || 'conn.'}</div>
        </div>
      </div>`;
    }).join('');
  }
}

function closeCountryDrawer() {
  document.getElementById('country-drawer-backdrop').classList.remove('open');
  document.getElementById('country-drawer-panel').classList.remove('open');
  if (!document.getElementById('drawer-panel').classList.contains('open')) {
    document.body.classList.remove('overflow-hidden');
  }
  _countryDrawerCC = null;
}
window.openCountryDrawer = openCountryDrawer;
window.closeCountryDrawer = closeCountryDrawer;
window.setCountryDrawerDirection = setCountryDrawerDirection;

// Close country drawer on Escape
window.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && document.getElementById('country-drawer-panel').classList.contains('open')) {
    closeCountryDrawer();
  }
});


// --- DEVICES ---
// Store events globally for drill-down
let _devAllEvents = [];
let _devMatrix = {};
let _devExpandedGroups = new Set();
let _devSearchQuery = '';
let _devTypeFilter = 'all';
let _devHideInactive = false;

// --- Friendly device names (localStorage fallback) ---
const _FRIENDLY_NAMES_KEY = 'airadar-friendly-names';

function _loadFriendlyNames() {
  try { return JSON.parse(localStorage.getItem(_FRIENDLY_NAMES_KEY) || '{}'); } catch { return {}; }
}

function _saveFriendlyName(mac, name) {
  const names = _loadFriendlyNames();
  if (name) { names[mac] = name; } else { delete names[mac]; }
  localStorage.setItem(_FRIENDLY_NAMES_KEY, JSON.stringify(names));
}

function _getFriendlyName(mac) {
  return _loadFriendlyNames()[mac] || null;
}

// Get the best display name for a device.
// Priority:
//   1. User-set friendly name (localStorage, legacy)
//   2. User-set display_name (from /api/devices PUT)
//   3. Clean hostname from DHCP/mDNS (junk hostnames like UUIDs/PTRs are skipped)
//   4. Vendor + JA4 label + MAC tail fallback (e.g. "Apple Safari (a2:3e)")
//   5. Latest IP
function _bestDeviceName(mac, device) {
  const friendly = _getFriendlyName(mac);
  if (friendly) return friendly;
  if (device?.display_name) return device.display_name;
  if (device?.hostname && !_isJunkHostname(device.hostname)) return device.hostname;
  const fallback = _vendorFallbackName(device);
  if (fallback) return fallback;
  return device ? _latestIp(device) : (typeof mac === 'string' ? mac.replace('_ip_', '') : '');
}

function _originalDeviceName(device) {
  return device?.hostname || (device ? _latestIp(device) : '');
}

// --- Device search/filter ---
function onDevSearchInput() {
  const input = document.getElementById('dev-search');
  const clearBtn = document.getElementById('dev-search-clear');
  _devSearchQuery = (input?.value || '').toLowerCase().trim();
  if (clearBtn) clearBtn.classList.toggle('hidden', !_devSearchQuery);
  _renderDeviceMatrix();
}

function clearDevSearch() {
  const input = document.getElementById('dev-search');
  if (input) input.value = '';
  _devSearchQuery = '';
  document.getElementById('dev-search-clear')?.classList.add('hidden');
  _renderDeviceMatrix();
}

function setDevTypeFilter(type) {
  _devTypeFilter = type;
  _renderDeviceMatrix();
}

function onDevFilterChange() {
  _devHideInactive = document.getElementById('dev-hide-inactive')?.checked || false;
  _renderDeviceMatrix();
}

function getCategoryGroups() {
  return [
    { key: 'ai',       label: t('cat.aiServices'),     icon: '<i class="ph-duotone ph-sparkle text-base"></i>', color: 'indigo' },
    { key: 'cloud',    label: t('cat.cloudStorage'),   icon: '<i class="ph-duotone ph-cloud text-base"></i>',   color: 'sky' },
    { key: 'tracking', label: t('cat.privacyTrackers'),icon: '<i class="ph-duotone ph-shield-check text-base"></i>', color: 'amber' },
    { key: 'other',    label: t('cat.other'),          icon: '<i class="ph-duotone ph-chart-bar text-base"></i>', color: 'slate' },
  ];
}

function _categorizeService(svc, svcCategoryMap) {
  // Unknown services fall into "other" so they still surface somewhere
  // on the devices page instead of being silently dropped or mis-filed
  // under trackers.
  return svcCategoryMap[svc] || 'other';
}

// Policy-aware heatmap cell. Color is driven by the active policy
// action, not by volume alone:
//   block  → red    (always, regardless of count)
//   alert  → amber  (always)
//   allow  → blue   (neutral, volume sets intensity shade)
//   none   → blue   (same as allow)
// Volume (count / globalMax) determines the shade darkness WITHIN
// the policy color so high-traffic services are visually heavier.
// policyAction: 'block'|'alert'|'allow'|null (for per-service cells)
//   or for group cells: the "worst" policy among all services in the group.
function _heatCell(count, uploads, globalMax, policyAction) {
  if (!count) return `<span class="inline-block w-full py-1 rounded text-[10px] text-slate-300 dark:text-slate-600">—</span>`;
  const intensity = Math.min(count / (globalMax || 1), 1);
  let bg, text, icon = '';

  if (policyAction === 'block') {
    // Red — always, with intensity shade
    if (intensity < 0.3) { bg = 'bg-red-100 dark:bg-red-900/30'; text = 'text-red-700 dark:text-red-300'; }
    else if (intensity < 0.6) { bg = 'bg-red-300 dark:bg-red-700/50'; text = 'text-red-900 dark:text-red-100'; }
    else { bg = 'bg-red-400 dark:bg-red-600/70'; text = 'text-white dark:text-red-100'; }
    icon = ' <i class="ph-duotone ph-prohibit text-[9px]"></i>';
  } else if (policyAction === 'alert') {
    // Amber — always
    if (intensity < 0.3) { bg = 'bg-amber-100 dark:bg-amber-900/30'; text = 'text-amber-700 dark:text-amber-300'; }
    else if (intensity < 0.6) { bg = 'bg-amber-200 dark:bg-amber-800/50'; text = 'text-amber-800 dark:text-amber-200'; }
    else { bg = 'bg-amber-300 dark:bg-amber-700/60'; text = 'text-amber-900 dark:text-amber-100'; }
    icon = ' <i class="ph-duotone ph-warning text-[9px]"></i>';
  } else {
    // Blue — neutral (allow or no policy)
    if (intensity < 0.15) { bg = 'bg-blue-100 dark:bg-blue-900/40'; text = 'text-blue-700 dark:text-blue-300'; }
    else if (intensity < 0.4) { bg = 'bg-blue-200 dark:bg-blue-800/50'; text = 'text-blue-800 dark:text-blue-200'; }
    else if (intensity < 0.7) { bg = 'bg-blue-300 dark:bg-blue-700/60'; text = 'text-blue-900 dark:text-blue-100'; }
    else { bg = 'bg-blue-400 dark:bg-blue-600/70'; text = 'text-white dark:text-blue-100'; }
  }
  const uploadIcon = uploads > 0 ? ` <span class="text-orange-500" title="${uploads} upload(s)">▲</span>` : '';
  return `<span class="inline-block w-full py-1 rounded text-[11px] font-medium tabular-nums ${bg} ${text}">${count}${icon}${uploadIcon}</span>`;
}

function _toggleDevGroup(groupKey) {
  if (_devExpandedGroups.has(groupKey)) _devExpandedGroups.delete(groupKey);
  else _devExpandedGroups.add(groupKey);
  _renderDeviceMatrix();
}

// ---------------------------------------------------------------------------
// Device detail drawer state
// ---------------------------------------------------------------------------
let _drawerMac = null;
let _drawerEvents = [];       // all events for current device
let _drawerFiltered = [];     // events filtered by active tab
let _drawerVisible = 0;       // how many rows currently rendered
let _drawerActiveTab = 'all'; // current tab key
const DRAWER_PAGE_SIZE = 50;

function _showCellEvents(mac, service, category) {
  openDeviceDrawer(mac, service, category);
}

function openDeviceDrawer(mac, service, category) {
  _drawerMac = mac;
  const dev = deviceMap[mac];
  const devIps = new Set();
  if (dev && dev.ips) dev.ips.forEach(ip => devIps.add(ip.ip));
  else devIps.add(mac.replace('_ip_', ''));

  // Collect ALL events for this device
  _drawerEvents = _devAllEvents.filter(e => devIps.has(e.source_ip));
  _drawerEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // --- Populate header ---
  const dt = _detectDeviceType(dev);
  const dn = _bestDeviceName(mac, dev);
  // dt.icon is a Phosphor HTML string — innerHTML, not textContent.
  document.getElementById('drawer-dev-icon').innerHTML = dt.icon;
  document.getElementById('drawer-dev-name').textContent = dn;

  // Meta line: type · IP · vendor
  const parts = [dt.type];
  if (dev) {
    const ip = _latestIp(dev);
    if (ip) parts.push(ip);
    if (dev.vendor) parts.push(dev.vendor);
  }
  document.getElementById('drawer-dev-meta').textContent = parts.join(' · ');

  // OS fingerprint
  const osEl = document.getElementById('drawer-dev-os');
  if (dev?.os_name) {
    const osLabel = dev.os_version ? `${dev.os_name} ${dev.os_version}` : dev.os_name;
    const distText = dev.network_distance != null ? ` · ${dev.network_distance} ${dev.network_distance !== 1 ? t('dev.hops') : t('dev.hop')}` : '';
    const dcText = dev.device_class ? ` · ${dev.device_class}` : '';
    osEl.innerHTML = `🔍 p0f: ${osLabel}${dcText}${distText}`;
    osEl.classList.remove('hidden');
  } else {
    osEl.classList.add('hidden');
  }

  // --- Build tab bar ---
  const cats = getCategoryGroups();
  const tabCounts = {};
  cats.forEach(c => {
    tabCounts[c.key] = _drawerEvents.filter(e => e._cat === c.key).length;
  });

  // Determine initial active tab. Clicking a specific service or
  // category cell still jumps straight to that filtered view;
  // opening the drawer from the device name lands on Summary.
  if (service) {
    const matchCat = cats.find(c => _drawerEvents.some(e => e.ai_service === service && e._cat === c.key));
    _drawerActiveTab = matchCat ? matchCat.key : 'summary';
  } else if (category) {
    _drawerActiveTab = category;
  } else {
    _drawerActiveTab = 'summary';
  }

  // Tabs: Summary · Connections · AI Recap · (category tabs).
  const tabBase = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap';
  const tabActive = `${tabBase} bg-blue-700 text-white shadow-sm`;
  const tabInactive = `${tabBase} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  const tabCls = (key) => (_drawerActiveTab === key ? tabActive : tabInactive);

  const tabsHtml = [
    `<button class="${tabCls('summary')}" data-tab="summary" onclick="setDrawerTab('summary')">${t('dev.drawerSummaryTab')}</button>`,
    `<button class="${tabCls('connections')}" data-tab="connections" onclick="setDrawerTab('connections')"><i class="ph-duotone ph-swap text-xs"></i> ${t('dev.drawerConnectionsTab') || 'Connections'}</button>`,
    `<button class="${tabCls('report')}" data-tab="report" onclick="setDrawerTab('report')">&#10024; ${t('dev.drawerReportTab')}</button>`,
  ];
  cats.forEach(c => {
    if (tabCounts[c.key] > 0) {
      tabsHtml.push(`<button class="${tabCls(c.key)}" data-tab="${c.key}" onclick="setDrawerTab('${c.key}')">${c.icon} ${c.label} <span class="ml-1 text-[10px] opacity-60">${tabCounts[c.key]}</span></button>`);
    }
  });
  document.getElementById('drawer-tabs').innerHTML = tabsHtml.join('');

  // --- Reset report tab state for this device ---
  // Wipe any previously-rendered report so the empty-state CTA shows
  // again until we either load a cache for this MAC or the user hits
  // Generate. Hide the regenerate button until a report is present.
  _resetReportView();
  // Fire-and-forget the cache fetch so the tab is instant when clicked.
  _loadCachedDeviceReport(mac);

  // --- Filter events for active tab and optional service ---
  _applyDrawerFilter(service);

  // --- Open drawer ---
  document.getElementById('drawer-backdrop').classList.add('open');
  const drawerEl = document.getElementById('drawer-panel');
  drawerEl.style.transform = '';  // Reset any swipe transform
  drawerEl.classList.add('open');
  document.body.classList.add('overflow-hidden');

  // Push history state for back-button support
  if (!history.state || history.state.drawer !== mac) {
    history.pushState({ drawer: mac }, '', location.href);
  }
}

function _applyDrawerFilter(serviceFilter) {
  const summaryView = document.getElementById('drawer-summary-view');
  const reportView  = document.getElementById('drawer-report-view');
  const eventsView  = document.getElementById('drawer-events-view');
  const countEl = document.getElementById('drawer-event-count');

  const hideAll = () => {
    if (summaryView) summaryView.classList.add('hidden');
    if (reportView)  reportView.classList.add('hidden');
    if (eventsView)  eventsView.classList.add('hidden');
  };

  if (_drawerActiveTab === 'summary') {
    hideAll();
    if (summaryView) summaryView.classList.remove('hidden');
    _renderDrawerSummary();
    if (countEl) countEl.textContent = '';
    return;
  }

  if (_drawerActiveTab === 'report') {
    hideAll();
    if (reportView) reportView.classList.remove('hidden');
    if (countEl) countEl.textContent = '';
    return;
  }

  if (_drawerActiveTab === 'connections') {
    hideAll();
    if (summaryView) summaryView.classList.remove('hidden');
    if (countEl) countEl.textContent = '';
    _loadDrawerConnections();
    return;
  }

  // Category tab: show event table filtered to that category.
  hideAll();
  if (eventsView) eventsView.classList.remove('hidden');

  let filtered = _drawerEvents.filter(e => e._cat === _drawerActiveTab);
  if (serviceFilter) {
    filtered = filtered.filter(e => e.ai_service === serviceFilter);
  }
  // Drawer is already scoped to one device, so collapsing by
  // (service, detection_type) folds both IPv4/IPv6 duplicates and
  // rapid heartbeat drips of the same service into a single row.
  _drawerFiltered = _collapseConsecutiveEvents(
    filtered,
    e => `${e.ai_service}|${e.detection_type}`,
  );
  _drawerVisible = 0;
  _renderDrawerEvents(true);
}

// ---------------------------------------------------------------------------
// Drawer Summary view — top services by bytes for the current device
// across the time window already applied to _drawerEvents (so it follows
// the period selector on the devices page).
// ---------------------------------------------------------------------------
const DRAWER_SUMMARY_TOP_N = 15;

// ---------------------------------------------------------------------------
// Session time estimator
// ---------------------------------------------------------------------------
// Given a sorted array of timestamps (ISO strings or Date objects),
// group them into sessions where consecutive events are within
// SESSION_GAP_MS of each other. Return total estimated active time
// in milliseconds.
const SESSION_GAP_MS = 5 * 60 * 1000; // 5 minutes
const MIN_SESSION_MS = 60 * 1000;      // 1 minute minimum per session

function _estimateActiveTime(timestamps) {
  if (!timestamps || timestamps.length === 0) return 0;
  const sorted = timestamps.map(t => new Date(t).getTime()).sort((a, b) => a - b);
  let total = 0;
  let sessionStart = sorted[0];
  let sessionEnd = sorted[0];
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] - sessionEnd <= SESSION_GAP_MS) {
      sessionEnd = sorted[i];
    } else {
      total += Math.max(sessionEnd - sessionStart, MIN_SESSION_MS);
      sessionStart = sorted[i];
      sessionEnd = sorted[i];
    }
  }
  total += Math.max(sessionEnd - sessionStart, MIN_SESSION_MS);
  return total;
}

function _fmtDuration(ms) {
  if (ms <= 0) return '0m';
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}


function _renderDrawerSummary() {
  const el = document.getElementById('drawer-summary-view');
  if (!el) return;

  if (!_drawerEvents || _drawerEvents.length === 0) {
    el.innerHTML = `<div class="py-12 text-center text-sm text-slate-400 dark:text-slate-500">${t('dev.noActivity')}</div>`;
    return;
  }

  // Aggregate bytes + hits + timestamps per service across the whole window.
  const svcAgg = {};
  _drawerEvents.forEach(e => {
    const svc = e.ai_service;
    if (!svcAgg[svc]) svcAgg[svc] = { bytes: 0, hits: 0, cat: e._cat, timestamps: [] };
    svcAgg[svc].bytes += e.bytes_transferred || 0;
    svcAgg[svc].hits += 1;
    svcAgg[svc].timestamps.push(e.timestamp);
  });

  // Compute estimated active time per service.
  for (const info of Object.values(svcAgg)) {
    info.activeMs = _estimateActiveTime(info.timestamps);
  }

  const total = Object.values(svcAgg).reduce((s, v) => s + v.bytes, 0);
  const totalTime = Object.values(svcAgg).reduce((s, v) => s + v.activeMs, 0);

  // Sort by active time desc, then bytes, then hits.
  const rows = Object.entries(svcAgg)
    .sort((a, b) => (b[1].activeMs - a[1].activeMs) || (b[1].bytes - a[1].bytes) || (b[1].hits - a[1].hits))
    .slice(0, DRAWER_SUMMARY_TOP_N);

  const maxTime = rows.length ? rows[0][1].activeMs : 0;

  // Header: small title + window hint read from the devices filter
  const per = document.getElementById('dev-filter-period')?.value;
  const windowLabel = per ? (document.querySelector(`#dev-filter-period option[value="${per}"]`)?.textContent || '') : '';

  let html = `<div class="mb-4 flex items-baseline justify-between gap-3">
    <h3 class="text-sm font-semibold text-slate-700 dark:text-slate-200">${t('dev.summaryTitle')}</h3>
    <span class="text-[11px] text-slate-400 dark:text-slate-500">${windowLabel}</span>
  </div>`;

  if (rows.length === 0) {
    html += `<div class="py-8 text-center text-xs text-slate-400 dark:text-slate-500">${t('dev.summaryNoBytes')}</div>`;
    el.innerHTML = html;
    return;
  }

  html += '<div class="space-y-1.5">';
  rows.forEach(([svc, info]) => {
    const barPct = maxTime > 0 ? (info.activeMs / maxTime * 100) : 0;
    const name = svcDisplayName(svc);
    const logo = svcLogo(svc);
    const timeLabel = _fmtDuration(info.activeMs);
    const bytesLabel = info.bytes > 0 ? _fmtBytes(info.bytes) : '';
    html += `<div class="flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] transition-colors">
      <div class="flex-shrink-0">${logo}</div>
      <div class="flex-1 min-w-0">
        <div class="flex items-baseline justify-between gap-2">
          <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${name}</span>
          <span class="text-xs tabular-nums flex-shrink-0 flex items-center gap-2">
            <span class="text-blue-600 dark:text-blue-400 font-semibold"><i class="ph-duotone ph-clock text-[10px]"></i> ${timeLabel}</span>
            ${bytesLabel ? `<span class="text-slate-400 dark:text-slate-500">${bytesLabel}</span>` : ''}
          </span>
        </div>
        <div class="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
          <div class="h-full bg-gradient-to-r from-blue-500 to-blue-700" style="width: ${barPct}%"></div>
        </div>
      </div>
    </div>`;
  });
  html += '</div>';

  // Footer: totals line
  html += `<div class="mt-4 pt-3 border-t border-slate-100 dark:border-white/[0.05] flex items-center justify-between text-[11px] text-slate-400 dark:text-slate-500">
    <span>${t('dev.summaryServicesCount', { n: Object.keys(svcAgg).length })}</span>
    <span class="tabular-nums flex items-center gap-2">
      <span><i class="ph-duotone ph-clock text-[10px]"></i> ${_fmtDuration(totalTime)}</span>
      ${total > 0 ? `<span>${_fmtBytes(total)}</span>` : ''}
    </span>
  </div>`;

  el.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Drawer Connections tab — raw IP-level connections from geo_conversations
// ---------------------------------------------------------------------------
async function _loadDrawerConnections() {
  const el = document.getElementById('drawer-summary-view');
  if (!el || !_drawerMac) return;

  el.innerHTML = `<div class="flex items-center gap-2 text-slate-400 py-6 justify-center">
    <i class="ph-duotone ph-circle-notch animate-spin text-lg"></i>
    <span class="text-sm">${t('dev.loadingConnections') || 'Loading connections...'}</span>
  </div>`;

  try {
    const res = await fetch(`/api/devices/${encodeURIComponent(_drawerMac)}/connections`);
    const data = await res.json();
    const conns = data.connections || [];

    if (conns.length === 0) {
      el.innerHTML = `<div class="py-8 text-center text-xs text-slate-400 dark:text-slate-500">${t('dev.noConnections') || 'No connections recorded.'}</div>`;
      return;
    }

    const totalBytes = conns.reduce((s, c) => s + (c.bytes || 0), 0);
    const totalHits = conns.reduce((s, c) => s + (c.hits || 0), 0);

    let html = `<div class="mb-3 flex items-center justify-between">
      <h3 class="text-sm font-semibold text-slate-700 dark:text-slate-200">${t('dev.connectionsTitle') || 'Network Connections'}</h3>
      <span class="text-[11px] text-slate-400 dark:text-slate-500 tabular-nums">${conns.length} dest. · ${_fmtBytes(totalBytes)} · ${formatNumber(totalHits)} conn.</span>
    </div>`;

    html += '<div class="space-y-1">';
    conns.forEach(c => {
      const dirIcon = c.direction === 'outbound'
        ? '<i class="ph-duotone ph-arrow-up-right text-xs text-blue-500" title="Outbound"></i>'
        : '<i class="ph-duotone ph-arrow-down-left text-xs text-emerald-500" title="Inbound"></i>';
      const flag = _flagEmoji(c.country_code);

      // Best label: PTR > ASN org > service > raw IP
      let primary;
      if (c.ptr) {
        primary = `<span class="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">${c.ptr}</span>`;
      } else if (c.asn_org) {
        primary = `<span class="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">AS${c.asn} · ${c.asn_org}</span>`;
      } else if (c.service && c.service !== 'unknown') {
        primary = `<span class="text-xs font-medium text-slate-700 dark:text-slate-200">${svcDisplayName(c.service)}</span>`;
      } else {
        primary = `<span class="text-xs font-mono text-slate-500 dark:text-slate-400">${c.resp_ip}</span>`;
      }

      const ipLine = c.ptr || c.asn_org
        ? `<div class="text-[10px] font-mono text-slate-400 dark:text-slate-500 truncate">${c.resp_ip}</div>`
        : '';

      html += `<div class="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03]">
        <span class="flex-shrink-0">${dirIcon}</span>
        <span class="flex-shrink-0 text-sm">${flag}</span>
        <div class="flex-1 min-w-0">
          ${primary}
          ${ipLine}
        </div>
        <div class="flex-shrink-0 text-right">
          <div class="text-xs tabular-nums font-medium text-slate-700 dark:text-slate-200">${_fmtBytes(c.bytes)}</div>
          <div class="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">${c.hits} conn.</div>
        </div>
      </div>`;
    });
    html += '</div>';

    el.innerHTML = html;
  } catch (err) {
    el.innerHTML = `<p class="text-sm text-red-500 text-center py-4">${err.message}</p>`;
  }
}


function _renderDrawerEvents(reset) {
  const tbody = document.getElementById('drawer-event-body');
  const loadMoreWrap = document.getElementById('drawer-load-more');
  const countEl = document.getElementById('drawer-event-count');

  if (reset) {
    tbody.innerHTML = '';
    _drawerVisible = 0;
    document.getElementById('drawer-scroll').scrollTop = 0;
  }

  const nextBatch = _drawerFiltered.slice(_drawerVisible, _drawerVisible + DRAWER_PAGE_SIZE);
  _drawerVisible += nextBatch.length;

  const rows = nextBatch.map(e => {
    const up = e.possible_upload;
    const upBadge = up ? ' <span class="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-orange-100 dark:bg-orange-800/50 text-orange-600 dark:text-orange-300">UPLOAD</span>' : '';
    const typeLabel = e.detection_type === 'sni_hello' ? t('dev.connection') : e.detection_type;
    const bytesStr = e.bytes_transferred ? _fmtBytes(e.bytes_transferred) : '0 B';
    const timeCell = e._count > 1
      ? `${fmtTime(e._newest_ts)} <span class="text-[10px] text-slate-400 dark:text-slate-500">– ${fmtTime(e._oldest_ts)}</span>`
      : fmtTime(e.timestamp);
    return `<tr class="border-b border-slate-100 dark:border-white/[0.04] ${up ? 'bg-orange-50/50 dark:bg-orange-900/10' : ''}">
      <td class="py-2.5 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500 whitespace-nowrap">${timeCell}</td>
      <td class="py-2.5 px-4">${badge(e.ai_service)}${_countBadge(e)}</td>
      <td class="py-2.5 px-4 text-xs">${typeLabel}${upBadge}</td>
      <td class="py-2.5 px-4 text-xs text-right tabular-nums hidden sm:table-cell">${bytesStr}</td>
    </tr>`;
  }).join('');

  tbody.insertAdjacentHTML('beforeend', rows);

  // Update count label
  countEl.textContent = t('dev.showingOfEvents', { visible: _drawerVisible, total: _drawerFiltered.length });

  // Show/hide load more
  if (_drawerVisible < _drawerFiltered.length) {
    loadMoreWrap.classList.remove('hidden');
  } else {
    loadMoreWrap.classList.add('hidden');
  }
}

function drawerLoadMore() {
  _renderDrawerEvents(false);
}

function setDrawerTab(tabKey) {
  _drawerActiveTab = tabKey;
  // Swap active / inactive Tailwind class strings on every tab button
  // so the visual update matches exactly what openDeviceDrawer() built.
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors whitespace-nowrap';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  document.querySelectorAll('#drawer-tabs button[data-tab]').forEach(btn => {
    btn.className = (btn.getAttribute('data-tab') === tabKey) ? active : inactive;
  });
  _applyDrawerFilter(null); // clear service filter when switching tabs
}

function closeDeviceDrawer() {
  document.getElementById('drawer-backdrop').classList.remove('open');
  document.getElementById('drawer-panel').classList.remove('open');
  document.body.classList.remove('overflow-hidden');
  _drawerMac = null;
  _drawerEvents = [];
  _drawerFiltered = [];
  _drawerVisible = 0;
}

// Back-button support: close drawer on popstate
window.addEventListener('popstate', function(e) {
  if (document.getElementById('drawer-panel').classList.contains('open')) {
    closeDeviceDrawer();
  }
});

// Close drawer on Escape key
window.addEventListener('keydown', function(e) {
  if (e.key === 'Escape' && document.getElementById('drawer-panel').classList.contains('open')) {
    closeDeviceDrawer();
  }
});

// Swipe-to-close: swipe right on the drawer panel to close (mobile)
(function() {
  let _swipeStartX = 0;
  let _swiping = false;
  const panel = document.getElementById('drawer-panel');
  if (!panel) return;
  panel.addEventListener('touchstart', function(e) {
    if (e.touches.length === 1) {
      _swipeStartX = e.touches[0].clientX;
      _swiping = true;
    }
  }, { passive: true });
  panel.addEventListener('touchmove', function(e) {
    if (!_swiping) return;
    const dx = e.touches[0].clientX - _swipeStartX;
    if (dx > 60) {
      // Translate drawer right as user swipes
      panel.style.transform = `translateX(${Math.min(dx - 60, 200)}px)`;
    }
  }, { passive: true });
  panel.addEventListener('touchend', function(e) {
    if (!_swiping) return;
    _swiping = false;
    const dx = (e.changedTouches[0]?.clientX || 0) - _swipeStartX;
    if (dx > 120) {
      closeDeviceDrawer();
    }
    panel.style.transform = '';
  }, { passive: true });
})();

// ---------------------------------------------------------------------------
// AI Recap — generate device report via Gemini
// ---------------------------------------------------------------------------
// The recap lives in its own drawer tab. Empty state = a centered
// CTA button. After a report is rendered the regenerate button at
// the top of the tab becomes visible so refreshing is one click away.

function _renderReportEmpty() {
  return `<div id="drawer-report-empty" class="py-10 text-center">
    <p class="text-xs text-slate-400 dark:text-slate-500 mb-4">${t('dev.reportEmptyHint')}</p>
    <button onclick="generateDeviceReport()" class="px-4 py-2 text-xs font-medium rounded-lg bg-gradient-to-r from-indigo-500 to-purple-500 text-white hover:from-indigo-600 hover:to-purple-600 transition-all shadow-sm hover:shadow-md">
      <span>&#10024;</span> ${t('dev.generateReport')}
    </button>
  </div>`;
}

function _resetReportView() {
  const content = document.getElementById('drawer-ai-report-content');
  const regen = document.getElementById('drawer-btn-regenerate-report');
  if (content) content.innerHTML = _renderReportEmpty();
  if (regen) regen.classList.add('hidden');
}

async function generateDeviceReport(macParam) {
  // MAC can come from parameter or from the drawer
  const mac = macParam || _drawerMac;
  if (!mac) return;

  // If drawer isn't open, open it first so the tab has a place to render
  if (!document.getElementById('drawer-panel').classList.contains('open')) {
    openDeviceDrawer(mac, null, null);
  }
  _drawerMac = mac;

  // Switch to the AI Recap tab so the loading state is visible
  setDrawerTab('report');

  const reportContent = document.getElementById('drawer-ai-report-content');
  const regenBtn = document.getElementById('drawer-btn-regenerate-report');
  if (!reportContent) return;

  // Loading state
  if (regenBtn) regenBtn.classList.add('hidden');
  reportContent.innerHTML = `
    <div class="flex items-center gap-3 text-indigo-500 dark:text-indigo-400 py-6">
      <i class="ph-duotone ph-circle-notch animate-spin text-lg"></i>
      <span class="text-sm">${t('dev.geminiAnalyzing')}</span>
    </div>`;

  try {
    // Explicit click = force regenerate. The cached copy is loaded
    // silently on drawer open by _loadCachedDeviceReport().
    const lang = (typeof getLocale === 'function' ? getLocale() : 'en');
    const resp = await fetch(`/api/devices/${encodeURIComponent(mac)}/report?force=true&lang=${encodeURIComponent(lang)}`);
    const data = await resp.json();

    if (!resp.ok) {
      reportContent.innerHTML = `<div class="text-red-500 dark:text-red-400 text-sm">${data.detail || t('dev.reportError')}</div>`;
      return;
    }

    reportContent.innerHTML = _renderReportHTML(data);
    if (regenBtn) regenBtn.classList.remove('hidden');

  } catch (err) {
    reportContent.innerHTML = `<div class="text-red-500 dark:text-red-400 text-sm">${t('dev.networkError', { msg: err.message })}</div>`;
  }
}

// Silently load the cached AI report (if any) on drawer open so the
// tab is instant when the user clicks it. No spinner, no error toast;
// if there's no cache we leave the empty-state CTA visible.
async function _loadCachedDeviceReport(mac) {
  try {
    const lang = (typeof getLocale === 'function' ? getLocale() : 'en');
    const resp = await fetch(`/api/devices/${encodeURIComponent(mac)}/report?lang=${encodeURIComponent(lang)}`);
    if (!resp.ok) return;  // 400/404 → no cache, leave empty state
    const data = await resp.json();
    if (!data.cached || !data.report) return;

    // Only render if the drawer is still on the same device (user may
    // have navigated away while the request was in flight).
    if (_drawerMac !== mac) return;

    const reportContent = document.getElementById('drawer-ai-report-content');
    const regenBtn = document.getElementById('drawer-btn-regenerate-report');
    if (!reportContent) return;
    reportContent.innerHTML = _renderReportHTML(data);
    if (regenBtn) regenBtn.classList.remove('hidden');
  } catch (err) {
    console.warn('_loadCachedDeviceReport:', err);
  }
}

// Shared renderer — markdown body + pricing footer + generated-at line
function _renderReportHTML(data) {
  let html = renderSimpleMarkdown(data.report);

  // Pricing table per model.
  // Source: https://ai.google.dev/gemini-api/docs/pricing (USD per 1M tokens).
  const pricing = {
    'gemini-2.5-flash-lite':   { input: 0.10, output: 0.40, thinking: 0 },
    'gemini-2.5-flash':        { input: 0.30, output: 2.50, thinking: 3.50 },
    'gemini-2.0-flash':        { input: 0.10, output: 0.40, thinking: 0 },
    'gemini-2.0-flash-lite':   { input: 0.075, output: 0.30, thinking: 0 },
    'gemini-3-flash-preview':  { input: 0.30, output: 2.50, thinking: 0 },
  };
  const modelName = data.model || 'gemini-2.5-flash-lite';
  const p = pricing[modelName] || pricing['gemini-2.5-flash-lite'];
  const tok = data.tokens || {};
  const costIn = (tok.prompt_tokens || 0) * p.input / 1e6;
  const costOut = (tok.response_tokens || 0) * p.output / 1e6;
  const costThink = (tok.thinking_tokens || 0) * p.thinking / 1e6;
  const totalCost = costIn + costOut + costThink;
  const costLabel = totalCost >= 0.01
    ? `${(totalCost * 100).toFixed(2)}\u00A2`
    : `${(totalCost * 1000).toFixed(3)}m\u00A2`;
  const modelLabel = modelName
    .replace('gemini-', 'Gemini ')
    .replace(/-/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());

  // Generated-at line + cached badge
  let generatedLine = '';
  if (data.generated_at) {
    const when = fmtTime(data.generated_at);
    const cachedBadge = data.cached
      ? `<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-200/60 dark:bg-white/[0.05] text-slate-500 dark:text-slate-400 text-[9px] uppercase tracking-wider font-medium">${t('dev.cached') || 'Cached'}</span>`
      : `<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 text-[9px] uppercase tracking-wider font-medium">${t('dev.freshScan') || 'Fresh'}</span>`;
    generatedLine = `<div class="mt-3 flex items-center gap-2 text-[10px] text-slate-400 dark:text-slate-500">
      ${cachedBadge}
      <span>${t('dev.reportGeneratedAt') || 'Gegenereerd op'} ${when}</span>
    </div>`;
  }

  html += generatedLine + `<div class="mt-2 pt-3 border-t border-indigo-200/30 dark:border-indigo-700/20 flex items-center justify-between text-[10px] text-indigo-400/70 dark:text-indigo-500/50">
    <span>${modelLabel} &middot; ${formatNumber(tok.total_tokens || 0)} tokens</span>
    <span>${costLabel} per report</span>
  </div>`;

  return html;
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
window.openDeviceDrawer = openDeviceDrawer;
window.closeDeviceDrawer = closeDeviceDrawer;
window.setDrawerTab = setDrawerTab;
window.drawerLoadMore = drawerLoadMore;

function _renderDeviceMatrix() {
  if (!_devMatrix.deviceMacs) return;
  const matrix = _devMatrix.matrix;
  const svcCategoryMap = _devMatrix.svcCategoryMap;
  const allServices = _devMatrix.allServices;
  const allDeviceMacs = _devMatrix.deviceMacs;
  const globalMax = _devMatrix.globalMax;

  // --- Build device type chip list grouped into parent categories ---
  // Maps the 50+ specific device types into ~8 usable filter categories.
  const _TYPE_TO_GROUP = {
    // Computers & Phones
    'MacBook': 'Computers', 'iMac': 'Computers', 'Mac Pro': 'Computers', 'Mac mini': 'Computers',
    'Mac Studio': 'Computers', 'PC': 'Computers', 'Surface': 'Computers', 'Laptop': 'Computers',
    'Computer': 'Computers', 'Microsoft': 'Computers', 'Apple Device': 'Computers',
    'Home Server': 'Computers', 'Raspberry Pi': 'Computers', 'Frigate NVR': 'Computers',
    // Phones & Tablets
    'iPhone': 'Phones', 'iPad': 'Phones', 'Pixel': 'Phones', 'Samsung': 'Phones',
    'Android': 'Phones', 'Phone': 'Phones', 'Tablet': 'Phones', 'HONOR': 'Phones',
    'HONOR Tablet': 'Phones', 'Huawei': 'Phones', 'Google Device': 'Phones',
    // Smart Home / IoT
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
    // Speakers & Media
    'Sonos Speaker': 'Media', 'Speaker': 'Media', 'HomePod': 'Media',
    'Google Home': 'Media', 'Google Home Mini': 'Media',
    'Denon AV Receiver': 'Media', 'AV Receiver': 'Media', 'Harmony Hub': 'Media',
    'Apple TV': 'Media', 'Chromecast': 'Media', 'TV/Media': 'Media',
    'LG Smart TV': 'Media', 'E-reader': 'Media',
    // Google Nest
    'Nest': 'Nest', 'Nest Doorbell': 'Nest', 'Nest Protect': 'Nest',
    'Nest Hub': 'Nest', 'Nest Cam': 'Nest',
    // Cameras
    'IP Camera': 'Cameras', 'Camera Hub': 'Cameras',
    // Networking
    'Router': 'Network', 'Ubiquiti': 'Network', 'Ubiquiti AP': 'Network',
    'Ubiquiti Switch': 'Network', 'Network Switch': 'Network',
    'Access Point': 'Network', 'Printer': 'Network',
    // Gaming
    'PlayStation': 'Gaming', 'Xbox': 'Gaming', 'Nintendo': 'Gaming',
  };

  const groupCountMap = {}; // parent group → count
  const groupTypes = {};    // parent group → Set of specific types
  allDeviceMacs.forEach(mac => {
    const dev = deviceMap[mac] || null;
    const dt = _detectDeviceType(dev);
    const group = _TYPE_TO_GROUP[dt.type] || 'Other';
    groupCountMap[group] = (groupCountMap[group] || 0) + 1;
    (groupTypes[group] = groupTypes[group] || new Set()).add(dt.type);
  });

  const chipContainer = document.getElementById('dev-type-chips');
  if (chipContainer) {
    const groups = Object.keys(groupCountMap).sort();
    const allActive = _devTypeFilter === 'all';
    const activeCls = 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-600';
    const inactiveCls = 'bg-slate-50 dark:bg-white/[0.04] text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/[0.06] hover:bg-slate-100 dark:hover:bg-white/[0.08]';
    let chips = `<button onclick="setDevTypeFilter('all')" class="px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors ${allActive ? activeCls : inactiveCls}">${t('dev.filterAll')} <span class="ml-0.5 text-[10px] opacity-60">${allDeviceMacs.length}</span></button>`;
    groups.forEach(grp => {
      const active = _devTypeFilter === grp;
      chips += `<button onclick="setDevTypeFilter('${grp.replace(/'/g, "\\'")}')" class="px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors ${active ? activeCls : inactiveCls}">${grp} <span class="ml-0.5 text-[10px] opacity-60">${groupCountMap[grp]}</span></button>`;
    });
    chipContainer.innerHTML = chips;
  }

  // Store the mapping so the filter can match
  window._typeToGroupMap = _TYPE_TO_GROUP;

  // --- Filter devices ---
  let deviceMacs = allDeviceMacs;

  // Type filter — matches the parent group, not the specific subtype
  if (_devTypeFilter !== 'all') {
    deviceMacs = deviceMacs.filter(mac => {
      const dev = deviceMap[mac] || null;
      const dt = _detectDeviceType(dev);
      const group = (window._typeToGroupMap || {})[dt.type] || 'Other';
      return group === _devTypeFilter;
    });
  }

  // Search filter
  if (_devSearchQuery) {
    deviceMacs = deviceMacs.filter(mac => {
      const dev = deviceMap[mac] || null;
      const name = _bestDeviceName(mac, dev).toLowerCase();
      const hostname = (dev?.hostname || '').toLowerCase();
      const ip = dev ? _latestIp(dev).toLowerCase() : mac.replace('_ip_', '');
      const dt = _detectDeviceType(dev);
      const vendor = (dev?.vendor || '').toLowerCase();
      return name.includes(_devSearchQuery) || hostname.includes(_devSearchQuery) ||
             ip.includes(_devSearchQuery) || dt.type.toLowerCase().includes(_devSearchQuery) ||
             vendor.includes(_devSearchQuery);
    });
  }

  // Hide inactive
  if (_devHideInactive) {
    deviceMacs = deviceMacs.filter(mac => {
      const row = matrix[mac] || {};
      return Object.values(row).reduce((s, v) => s + v.count, 0) > 0;
    });
  }

  // Group services by category
  const groups = getCategoryGroups().map(g => {
    const svcs = [...allServices].filter(s => _categorizeService(s, svcCategoryMap) === g.key).sort();
    return { ...g, services: svcs };
  }).filter(g => g.services.length > 0);

  // Build header
  const thead = document.getElementById('devices-matrix-head');
  const expanded = _devExpandedGroups;

  let headerCells = `<th class="py-3 px-4 font-medium sticky left-0 bg-slate-50 dark:bg-[#0B0C10] z-10 min-w-[220px]">${t('dev.device')}</th>
    <th class="py-3 px-3 font-medium text-right min-w-[60px]">${t('dev.total')}</th>`;

  groups.forEach(g => {
    const isExpanded = expanded.has(g.key);
    const chevron = isExpanded ? '▾' : '▸';
    headerCells += `<th class="py-3 px-3 font-medium text-center min-w-[90px] cursor-pointer select-none hover:text-indigo-400 transition-colors border-l border-slate-200 dark:border-white/[0.06] hidden sm:table-cell"
      onclick="_toggleDevGroup('${g.key}')" title="Click to ${isExpanded ? 'collapse' : 'expand'} ${g.label}">
      <span class="inline-flex items-center gap-1 justify-center">${g.icon} ${g.label} <span class="text-[10px] opacity-60">${chevron}</span></span>
    </th>`;
    if (isExpanded) {
      g.services.forEach(s => {
        headerCells += `<th class="py-3 px-2 font-medium text-center min-w-[70px] hidden sm:table-cell" title="${s}">
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
    tbody.innerHTML = `<tr><td colspan="${colCount}" class="py-12 text-center text-slate-400 dark:text-slate-500 text-sm">${t('dev.noActivity')}</td></tr>`;
    return;
  }

  tbody.innerHTML = deviceMacs.map(mac => {
    const row = matrix[mac] || {};
    const total = Object.values(row).reduce((s, v) => s + v.count, 0);
    const totalUploads = Object.values(row).reduce((s, v) => s + v.uploads, 0);
    const dev = deviceMap[mac] || null;
    const bestName = _bestDeviceName(mac, dev);
    const origName = _originalDeviceName(dev);
    const friendlyName = _getFriendlyName(mac);
    const hasFriendly = !!friendlyName || (dev?.display_name && dev.display_name !== origName);
    const ipInfo = dev ? _ipSummary(dev) : mac.replace('_ip_', '');
    const dtTag = deviceTypeTag(dev);

    // Truncated original name for display
    const origTruncated = origName.length > 35 ? origName.slice(0, 33) + '...' : origName;

    let cells = '';
    groups.forEach(g => {
      const groupCount = g.services.reduce((s, svc) => s + (row[svc]?.count || 0), 0);
      const groupUploads = g.services.reduce((s, svc) => s + (row[svc]?.uploads || 0), 0);
      // Group policy = "worst" among all services in the group:
      // block > alert > allow. If ANY service is blocked, group is red.
      let groupPolicy = null;
      g.services.forEach(svc => {
        const p = _policyByService[svc];
        if (p === 'block') groupPolicy = 'block';
        else if (p === 'alert' && groupPolicy !== 'block') groupPolicy = 'alert';
      });
      cells += `<td class="py-2.5 px-2 text-center border-l border-slate-100 dark:border-white/[0.04] cursor-pointer hidden sm:table-cell" onclick="_showCellEvents('${mac}', null, '${g.key}')">
        ${_heatCell(groupCount, groupUploads, globalMax, groupPolicy)}
      </td>`;

      if (expanded.has(g.key)) {
        g.services.forEach(s => {
          const v = row[s];
          const svcPolicy = _policyByService[s] || null;
          cells += `<td class="py-2.5 px-2 text-center cursor-pointer hidden sm:table-cell" onclick="_showCellEvents('${mac}', '${s}')">
            ${_heatCell(v?.count || 0, v?.uploads || 0, globalMax, svcPolicy)}
          </td>`;
        });
      }
    });

    const uploadBadge = totalUploads > 0
      ? `<span class="ml-1 text-[10px] px-1 py-0.5 rounded bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">${totalUploads}▲</span>`
      : '';

    const isQuiet = total === 0;
    const rowOpacity = isQuiet ? 'opacity-50' : '';
    const totalDisplay = isQuiet
      ? `<span class="text-xs text-slate-300 dark:text-slate-600">—</span>`
      : `<span class="cursor-pointer" onclick="_showCellEvents('${mac}', null, null)">${total}${uploadBadge}</span>`;

    const reportBtn = dev ? `<button onclick="event.stopPropagation();generateDeviceReport('${mac}')" class="ml-2 px-1.5 py-0.5 text-[9px] font-semibold rounded bg-gradient-to-r from-indigo-500/80 to-purple-500/80 text-white hover:from-indigo-500 hover:to-purple-500 transition-all leading-none whitespace-nowrap" title="${t('dev.aiRecap')}">&#10024; AI</button>` : '';

    // Edit (pencil) button — appears on row hover via CSS .dev-edit-btn
    const editBtn = `<button onclick="event.stopPropagation();_startDeviceRename('${mac}')" class="dev-edit-btn ml-1 text-slate-400 hover:text-blue-500 transition-colors" title="${t('dev.editName')}"><i class="ph-duotone ph-pencil-simple text-sm"></i></button>`;
    const rulesBtn = dev ? `<button onclick="event.stopPropagation();navigateToDeviceRules('${mac}')" class="dev-edit-btn ml-0.5 text-slate-400 hover:text-blue-500 transition-colors" title="${t('rules.manageRules')}"><i class="ph-duotone ph-shield-check text-sm"></i></button>` : '';

    // Name display: friendly name as primary, original name as secondary
    const nameEscaped = bestName.replace(/"/g, '&quot;');
    const origTitle = origName.replace(/"/g, '&quot;');
    const secondaryName = hasFriendly && origName
      ? `<p class="text-[10px] text-slate-400 dark:text-slate-500 truncate max-w-[200px]" title="${origTitle}">${origTruncated}</p>`
      : '';

    return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors ${rowOpacity}">
      <td class="py-3 px-4 sticky left-0 bg-white dark:bg-[#0B0C10] z-10">
        <div class="flex items-center gap-1" id="dev-name-row-${mac.replace(/[^a-zA-Z0-9]/g, '_')}">
          <span class="device-name cursor-pointer hover:text-indigo-500 transition-colors text-sm font-medium truncate max-w-[180px]" data-mac="${dev ? dev.mac_address : ''}" title="${nameEscaped}">${bestName}</span>
          ${editBtn}
          ${rulesBtn}
          ${reportBtn}
        </div>
        ${secondaryName}
        <p class="text-[10px] text-slate-400 dark:text-slate-500 font-mono">${ipInfo}</p>
        ${dtTag}
      </td>
      <td class="py-3 px-4 text-right tabular-nums text-sm font-semibold">${totalDisplay}</td>
      ${cells}
    </tr>`;
  }).join('');
}

// ---------------------------------------------------------------------------
// "Ask anything" — natural language network queries
// ---------------------------------------------------------------------------
async function askNetwork() {
  const input = document.getElementById('ask-network-input');
  const btn = document.getElementById('ask-network-btn');
  const responseDiv = document.getElementById('ask-network-response');
  const contentDiv = document.getElementById('ask-network-content');
  const question = (input?.value || '').trim();
  if (!question || question.length < 5) {
    showToast(t('ask.tooShort') || 'Question too short — please be more specific.', 'info');
    return;
  }

  // Loading state
  if (btn) { btn.disabled = true; btn.classList.add('opacity-60', 'cursor-wait'); }
  if (responseDiv) responseDiv.classList.remove('hidden');
  if (contentDiv) contentDiv.innerHTML = `<div class="flex items-center gap-2 text-indigo-500 py-2">
    <i class="ph-duotone ph-circle-notch animate-spin text-lg"></i>
    <span class="text-sm">${t('ask.thinking') || 'Analyzing your network...'}</span>
  </div>`;

  try {
    const lang = (typeof getLocale === 'function' ? getLocale() : 'en');
    const res = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, lang }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    // Render markdown answer
    let html = renderSimpleMarkdown(data.answer || '');

    // Cost + timing footer
    const tok = data.tokens || {};
    const totalCost = (tok.prompt_tokens || 0) * 0.10 / 1e6 + (tok.response_tokens || 0) * 0.40 / 1e6;
    const costLabel = totalCost >= 0.01 ? `${(totalCost * 100).toFixed(2)}¢` : `${(totalCost * 1000).toFixed(3)}m¢`;
    html += `<div class="mt-3 pt-2 border-t border-slate-100 dark:border-white/[0.05] flex items-center justify-between text-[10px] text-slate-400 dark:text-slate-500">
      <span>${data.model || ''} · ${formatNumber(tok.total_tokens || 0)} tokens · ${data.elapsed_s || '?'}s</span>
      <span>${costLabel}</span>
    </div>`;

    if (contentDiv) contentDiv.innerHTML = html;
  } catch (err) {
    if (contentDiv) contentDiv.innerHTML = `<p class="text-sm text-red-500">${err.message}</p>`;
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('opacity-60', 'cursor-wait'); }
  }
}
window.askNetwork = askNetwork;


// ---------------------------------------------------------------------------
// Devices page tab switching (Devices / Groups)
// ---------------------------------------------------------------------------
let _currentDevicesTab = 'devices';

function switchDevicesTab(tab) {
  _currentDevicesTab = tab;
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  ['devices', 'groups'].forEach(t => {
    const div = document.getElementById(`dev-tab-${t}`);
    const btn = document.getElementById(`dev-tab-btn-${t}`);
    if (div) div.classList.toggle('hidden', t !== tab);
    if (btn) btn.className = (t === tab) ? active : inactive;
  });
  if (tab === 'groups') loadGroups();
}
window.switchDevicesTab = switchDevicesTab;

// ---------------------------------------------------------------------------
// Groups management
// ---------------------------------------------------------------------------
async function loadGroups() {
  const container = document.getElementById('groups-list');
  if (!container) return;
  try {
    const data = await fetch('/api/groups').then(r => r.json());
    const groups = data.groups || [];
    if (groups.length === 0) {
      container.innerHTML = `<p class="text-slate-400 dark:text-slate-500 text-sm text-center py-8">${t('groups.noGroups') || 'No groups created yet.'}</p>`;
      return;
    }

    // Build parent→children map
    const childrenOf = {};
    const topLevel = [];
    groups.forEach(g => {
      if (g.parent_id) {
        (childrenOf[g.parent_id] = childrenOf[g.parent_id] || []).push(g);
      } else {
        topLevel.push(g);
      }
    });

    container.innerHTML = topLevel.map(g => _renderGroupCard(g, childrenOf, groups)).join('');
  } catch (err) {
    container.innerHTML = `<p class="text-red-500 text-xs text-center py-4">${err.message}</p>`;
  }
}

function _renderGroupCard(group, childrenOf, allGroups) {
  const children = childrenOf[group.id] || [];
  const childrenHtml = children.length
    ? `<div class="ml-6 mt-2 space-y-2 border-l-2 border-slate-200 dark:border-white/[0.06] pl-3">${children.map(c => `
        <div class="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-white/[0.02] border border-slate-100 dark:border-white/[0.03]">
          <div class="flex items-center gap-2">
            <i class="ph-duotone ph-${c.icon || 'users-three'} text-lg text-${c.color || 'blue'}-500"></i>
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${c.name}</span>
            <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.06] text-slate-500">${c.member_count} ${t('groups.members') || 'members'}</span>
          </div>
          <div class="flex items-center gap-1">
            <button onclick="openGroupMembersModal(${c.id}, '${c.name}')" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors" title="${t('groups.manageMembers') || 'Manage members'}"><i class="ph-duotone ph-user-plus text-base"></i></button>
            <button onclick="navigateToGroupRules(${c.id})" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors" title="${t('rules.manageRules') || 'Manage rules'}"><i class="ph-duotone ph-shield-check text-base"></i></button>
            <button onclick="deleteGroup(${c.id})" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-red-500 transition-colors" title="${t('groups.delete') || 'Delete'}"><i class="ph-duotone ph-trash text-base"></i></button>
          </div>
        </div>`).join('')}</div>`
    : '';

  // Parent selector for nesting
  const otherTopLevel = allGroups.filter(g => !g.parent_id && g.id !== group.id);

  return `
    <div class="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg bg-${group.color || 'blue'}-100 dark:bg-${group.color || 'blue'}-900/30 flex items-center justify-center">
            <i class="ph-duotone ph-${group.icon || 'users-three'} text-xl text-${group.color || 'blue'}-600 dark:text-${group.color || 'blue'}-400"></i>
          </div>
          <div>
            <h3 class="text-base font-semibold text-slate-800 dark:text-white">${group.name}</h3>
            <p class="text-[11px] text-slate-400 dark:text-slate-500">${group.member_count} ${t('groups.members') || 'members'}${children.length ? ` · ${children.length} ${t('groups.subgroups') || 'subgroups'}` : ''}</p>
          </div>
        </div>
        <div class="flex items-center gap-1">
          <button onclick="openGroupMembersModal(${group.id}, '${group.name}')" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors" title="${t('groups.manageMembers') || 'Manage members'}"><i class="ph-duotone ph-user-plus text-base"></i></button>
          <button onclick="navigateToGroupRules(${group.id})" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors" title="${t('rules.manageRules') || 'Manage rules'}"><i class="ph-duotone ph-shield-check text-base"></i></button>
          <button onclick="deleteGroup(${group.id})" class="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-red-500 transition-colors" title="${t('groups.delete') || 'Delete'}"><i class="ph-duotone ph-trash text-base"></i></button>
        </div>
      </div>
      ${childrenHtml}
    </div>`;
}

async function createGroup() {
  const input = document.getElementById('new-group-name');
  const name = (input?.value || '').trim();
  if (!name) return;
  try {
    const res = await fetch('/api/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    input.value = '';
    showToast(`${t('groups.created') || 'Group created'}: ${name}`, 'success');
    await loadGroups();
  } catch (err) {
    showToast(`${t('groups.createFailed') || 'Failed'}: ${err.message}`, 'error');
  }
}

async function deleteGroup(groupId) {
  const confirmed = await styledConfirm(
    t('groups.deleteTitle') || 'Delete group',
    t('groups.deleteConfirm') || 'This will remove the group, all memberships, and all group-scoped rules. Continue?'
  );
  if (!confirmed) return;
  try {
    await fetch(`/api/groups/${groupId}`, { method: 'DELETE' });
    showToast(t('groups.deleted') || 'Group deleted', 'success');
    await loadGroups();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

async function openGroupMembersModal(groupId, groupName) {
  // Fetch current members + all devices
  const [membersRes, devicesRes] = await Promise.all([
    fetch(`/api/groups/${groupId}/members`).then(r => r.json()),
    fetch('/api/devices').then(r => r.json()),
  ]);
  const members = new Set((membersRes.members || []).map(m => m.mac_address));

  // Build device list sorted by activity
  const devices = (devicesRes || [])
    .map(d => ({
      mac: d.mac_address,
      name: _bestDeviceName(d.mac_address, d),
      isMember: members.has(d.mac_address),
      lastSeen: d.last_seen ? new Date(d.last_seen).getTime() : 0,
    }))
    .sort((a, b) => {
      if (a.isMember !== b.isMember) return a.isMember ? -1 : 1;
      return b.lastSeen - a.lastSeen;
    });

  const msg = devices.map(d => {
    const checked = d.isMember ? 'checked' : '';
    return `<label class="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-slate-50 dark:hover:bg-white/[0.03] cursor-pointer">
      <input type="checkbox" ${checked} onchange="toggleGroupMember(${groupId}, '${d.mac}', this.checked)" class="rounded border-slate-300 dark:border-slate-600 w-4 h-4">
      <span class="text-sm text-slate-700 dark:text-slate-200">${d.name}</span>
    </label>`;
  }).join('');

  // Reuse the confirm modal structure but with custom content
  const modal = document.getElementById('confirm-modal');
  document.getElementById('confirm-modal-title').textContent = `${groupName} — ${t('groups.manageMembers') || 'Manage Members'}`;
  document.getElementById('confirm-modal-message').innerHTML = `<div class="max-h-[300px] overflow-y-auto space-y-0.5 -mx-2">${msg}</div>`;
  modal.classList.remove('hidden');
  _confirmResolve = () => { modal.classList.add('hidden'); loadGroups(); };
}

async function toggleGroupMember(groupId, mac, add) {
  try {
    if (add) {
      await fetch(`/api/groups/${groupId}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac_address: mac }),
      });
    } else {
      await fetch(`/api/groups/${groupId}/members/${encodeURIComponent(mac)}`, { method: 'DELETE' });
    }
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

function navigateToGroupRules(groupId) {
  // Navigate to Rules page with group scope pre-selected
  // For now, navigate to rules — group scope in Rules page is future work
  navigate('rules');
  showToast(t('groups.rulesHint') || 'Select "Per group" on the Rules page to set group rules', 'info');
}

window.createGroup = createGroup;
window.deleteGroup = deleteGroup;
window.openGroupMembersModal = openGroupMembersModal;
window.toggleGroupMember = toggleGroupMember;
window.navigateToGroupRules = navigateToGroupRules;


async function refreshDevices() {
  const per = document.getElementById('dev-filter-period')?.value;
  const params = new URLSearchParams();
  params.set('limit', '1000');
  if (per) params.set('start', new Date(Date.now() - parseInt(per) * 60000).toISOString());

  // Fetch all categories in parallel. 'other' is a synthetic bucket
  // on the backend (category NOT IN ai/cloud/tracking) that catches
  // gaming, social, streaming, shopping, gambling, and anything else
  // the classifier assigned a non-primary category to.
  const [aiEvt, cloudEvt, trackEvt, otherEvt, policiesRes] = await Promise.all([
    fetch('/api/events?category=ai&' + params).then(r => r.json()),
    fetch('/api/events?category=cloud&' + params).then(r => r.json()),
    fetch('/api/events?category=tracking&' + params).then(r => r.json()),
    fetch('/api/events?category=other&' + params).then(r => r.json()),
    fetch('/api/policies?scope=global').then(r => r.json()).catch(() => []),
  ]);

  // Build policy lookup for heatmap coloring — reuse the same global
  // so the Rules page and Devices page share one source of truth.
  _policyByService = {};
  (Array.isArray(policiesRes) ? policiesRes : []).forEach(p => {
    if (p.scope === 'global' && p.service_name && !p.category) {
      _policyByService[p.service_name] = p.action;
    }
  });

  // Tag events with their category
  aiEvt.forEach(e => e._cat = 'ai');
  cloudEvt.forEach(e => e._cat = 'cloud');
  trackEvt.forEach(e => e._cat = 'tracking');
  otherEvt.forEach(e => e._cat = 'other');

  const allEvents = [...aiEvt, ...cloudEvt, ...trackEvt, ...otherEvt];
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
      const nameA = deviceMap[a] ? _bestDeviceName(a, deviceMap[a]) : a;
      const nameB = deviceMap[b] ? _bestDeviceName(b, deviceMap[b]) : b;
      return nameA.localeCompare(nameB);
    }
    return totalB - totalA;
  });

  const activeMacs = Object.keys(matrix).length;

  // Count devices that actually have events on alert/block policies
  // (not just any device with traffic — that inflates the "violations"
  // count with perfectly normal allowed services).
  let violationMacs = 0;
  Object.entries(matrix).forEach(([mac, svcs]) => {
    const hasViolation = Object.keys(svcs).some(svc => {
      const policy = _policyByService[svc];
      return policy === 'alert' || policy === 'block';
    });
    if (hasViolation) violationMacs++;
  });

  // Stats
  const totalUploads = allEvents.filter(e => e.possible_upload).length;
  document.getElementById('dev-stat-total').textContent = deviceMacs.length;
  document.getElementById('dev-stat-violators').textContent = violationMacs;
  document.getElementById('dev-stat-events').textContent = formatNumber(allEvents.length);
  document.getElementById('dev-stat-uploads').textContent = totalUploads;

  // Find global max for heat intensity
  let globalMax = 1;
  deviceMacs.forEach(mac => {
    Object.values(matrix[mac] || {}).forEach(v => { if (v.count > globalMax) globalMax = v.count; });
  });

  // Store for rendering
  _devMatrix = { matrix, svcCategoryMap, allServices, deviceMacs, globalMax };

  // Close device drawer on data refresh (if open)
  if (document.getElementById('drawer-panel')?.classList.contains('open')) {
    closeDeviceDrawer();
  }

  _renderDeviceMatrix();
}

// --- RULES ---
let _currentRulesTab = 'outbound';
let _rulesScopeMode = 'global';  // 'global' or 'device'
let _rulesScopeMac = null;
let _devicePolicyByService = {};
let _deviceOverrideServices = new Set();
let _policyByCategory = {};
let _policyCatExpires = {};

function switchRulesTab(tab) {
  _currentRulesTab = tab;
  const tabs = ['outbound', 'inbound', 'active'];
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const activeClass = `${base} bg-blue-700 text-white shadow-sm`;
  const inactiveClass = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;

  tabs.forEach(t => {
    const div = document.getElementById(`rules-tab-${t}`);
    const btn = document.getElementById(`rules-tab-btn-${t}`);
    if (div) div.classList.toggle('hidden', t !== tab);
    if (btn) btn.className = (t === tab) ? activeClass : inactiveClass;
  });

  // Lazy-load active blocks when the tab is first selected
  if (tab === 'active') loadActiveBlockRules();
}

async function refreshRules() {
  _populateRulesDeviceFilter();
  await Promise.all([loadGlobalFilterStatus(), loadIpsStatus(), loadAccessControl(), loadAdguardProtectionState(), loadActiveBlockRules()]);
}

// ---------------------------------------------------------------------------
// Rules scope: Global vs Per-device
// ---------------------------------------------------------------------------
let _rulesScopeGroupId = null;

function switchRulesScope(mode) {
  _rulesScopeMode = mode;
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  const btnG = document.getElementById('rules-scope-btn-global');
  const btnD = document.getElementById('rules-scope-btn-device');
  const btnGr = document.getElementById('rules-scope-btn-group');
  const selD = document.getElementById('rules-scope-device-select');
  const selGr = document.getElementById('rules-scope-group-select');
  const lbl = document.getElementById('rules-scope-label');
  const globalSection = document.getElementById('rules-global-filters-section');

  if (btnG) btnG.className = inactive;
  if (btnD) btnD.className = inactive;
  if (btnGr) btnGr.className = inactive;
  if (selD) selD.classList.add('hidden');
  if (selGr) selGr.classList.add('hidden');
  if (lbl) { lbl.classList.add('hidden'); lbl.textContent = ''; }

  if (mode === 'global') {
    if (btnG) btnG.className = active;
    if (globalSection) globalSection.classList.remove('hidden');
    _rulesScopeMac = null;
    _rulesScopeGroupId = null;
    loadAccessControl();
  } else if (mode === 'device') {
    if (btnD) btnD.className = active;
    if (selD) selD.classList.remove('hidden');
    if (globalSection) globalSection.classList.add('hidden');
    _rulesScopeGroupId = null;
    if (selD && selD.value) {
      _rulesScopeMac = selD.value;
      const dev = deviceMap[selD.value];
      if (lbl) { lbl.textContent = dev ? _bestDeviceName(selD.value, dev) : selD.value; lbl.classList.remove('hidden'); }
      loadAccessControl();
    }
  } else if (mode === 'group') {
    if (btnGr) btnGr.className = active;
    if (selGr) selGr.classList.remove('hidden');
    if (globalSection) globalSection.classList.add('hidden');
    _rulesScopeMac = null;
    _populateRulesGroupFilter();
    if (selGr && selGr.value) {
      _rulesScopeGroupId = parseInt(selGr.value);
      if (lbl) { lbl.textContent = selGr.options[selGr.selectedIndex]?.text || ''; lbl.classList.remove('hidden'); }
      loadAccessControl();
    }
  }
}

function onRulesGroupSelected(groupId) {
  _rulesScopeGroupId = groupId ? parseInt(groupId) : null;
  const lbl = document.getElementById('rules-scope-label');
  const sel = document.getElementById('rules-scope-group-select');
  if (groupId && lbl && sel) {
    lbl.textContent = sel.options[sel.selectedIndex]?.text || '';
    lbl.classList.remove('hidden');
  } else if (lbl) {
    lbl.classList.add('hidden');
  }
  if (groupId) loadAccessControl();
}

async function _populateRulesGroupFilter() {
  const sel = document.getElementById('rules-scope-group-select');
  if (!sel) return;
  try {
    const data = await fetch('/api/groups').then(r => r.json());
    const groups = data.groups || [];
    const cur = sel.value;
    sel.innerHTML = `<option value="">${t('rules.selectGroup') || 'Select a group...'}</option>`;
    groups.forEach(g => { sel.innerHTML += `<option value="${g.id}">${g.name} (${g.member_count})</option>`; });
    sel.value = cur;
  } catch (e) { console.warn('populate group filter:', e); }
}

window.onRulesGroupSelected = onRulesGroupSelected;

function onRulesDeviceSelected(mac) {
  _rulesScopeMac = mac || null;
  const lbl = document.getElementById('rules-scope-label');
  if (mac && lbl) {
    const dev = deviceMap[mac];
    lbl.textContent = dev ? _bestDeviceName(mac, dev) : mac;
    lbl.classList.remove('hidden');
  } else if (lbl) {
    lbl.classList.add('hidden');
  }
  if (mac) loadAccessControl();
}

function _populateRulesDeviceFilter() {
  const sel = document.getElementById('rules-scope-device-select');
  if (!sel) return;
  const cur = sel.value;
  sel.innerHTML = `<option value="">${t('rules.selectDevice') || 'Select a device...'}</option>`;
  // Sort by most recently active (last_seen desc) so the device you
  // want to set a rule for is typically at the top of the list.
  Object.entries(deviceMap)
    .map(([mac, d]) => ({
      mac,
      label: _bestDeviceName(mac, d),
      lastSeen: d.last_seen ? new Date(d.last_seen).getTime() : 0,
    }))
    .sort((a, b) => b.lastSeen - a.lastSeen)
    .forEach(e => { sel.innerHTML += `<option value="${e.mac}">${e.label}</option>`; });
  sel.value = cur;
}

function navigateToDeviceRules(mac) {
  if (!mac) return;
  closeDeviceDrawer();
  _rulesScopeMode = 'device';
  _rulesScopeMac = mac;
  navigate('rules');
  // After navigation + render, pre-select the device
  setTimeout(() => {
    const sel = document.getElementById('rules-scope-device-select');
    if (sel) sel.value = mac;
    switchRulesScope('device');
  }, 100);
}

window.switchRulesScope = switchRulesScope;
window.onRulesDeviceSelected = onRulesDeviceSelected;
window.navigateToDeviceRules = navigateToDeviceRules;

// ---------------------------------------------------------------------------
// Active Block Rules — compact overview of all active service blocks
// ---------------------------------------------------------------------------
async function loadActiveBlockRules() {
  const container = document.getElementById('active-blocks-list');
  if (!container) return;

  try {
    const policies = await fetch('/api/policies').then(r => r.json()).catch(() => []);
    const blocked = (Array.isArray(policies) ? policies : [])
      .filter(p => p.action === 'block');

    // Update badge count on the tab button
    const badge = document.getElementById('rules-active-count');
    if (badge) {
      badge.textContent = String(blocked.length);
      badge.classList.toggle('hidden', blocked.length === 0);
    }

    if (blocked.length === 0) {
      container.innerHTML = `
        <div class="bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-700/30 rounded-xl p-8 text-center">
          <i class="ph-duotone ph-shield-check text-3xl text-emerald-500 mb-2"></i>
          <p class="text-sm text-emerald-600 dark:text-emerald-400 font-medium">${t('rules.noActiveBlockRules') || 'No active block rules.'}</p>
          <p class="text-xs text-emerald-500/70 dark:text-emerald-400/50 mt-1">${t('rules.allServicesAllowed') || 'All services are currently allowed.'}</p>
        </div>`;
      return;
    }

    container.innerHTML = blocked.map(p => {
      const svc = p.service_name || p.category || '—';
      const name = p.service_name ? svcDisplayName(p.service_name) : (p.category || '—');
      const logo = p.service_name ? svcLogo(p.service_name) : '<i class="ph-duotone ph-folder text-xl"></i>';

      // Scope badge — visually distinct per scope level
      let scopeBadge;
      if (p.scope === 'device' && p.mac_address) {
        const devName = _bestDeviceName(p.mac_address, deviceMap[p.mac_address]);
        scopeBadge = `<span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 font-medium">
          <i class="ph-duotone ph-device-mobile text-xs"></i> ${devName}
        </span>`;
      } else if (p.scope === 'group' && p.group_name) {
        // Future: group scope
        scopeBadge = `<span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 font-medium">
          <i class="ph-duotone ph-users-three text-xs"></i> ${p.group_name}
        </span>`;
      } else {
        scopeBadge = `<span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-slate-200 dark:bg-white/[0.08] text-slate-600 dark:text-slate-300 font-medium">
          <i class="ph-duotone ph-globe text-xs"></i> ${t('rules.global') || 'Global'}
        </span>`;
      }

      // Timer badge — prominent when temporary, subtle when permanent
      let timerBadge;
      if (p.expires_at) {
        const d = new Date(p.expires_at);
        const now = new Date();
        const remainingMs = d - now;
        const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const dateStr = d.toLocaleDateString([], { month: 'short', day: 'numeric' });
        // Expiring within 1 hour → orange warning, otherwise blue
        const isExpiringSoon = remainingMs > 0 && remainingMs < 3600000;
        const timerColor = isExpiringSoon
          ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400'
          : 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400';
        const remainLabel = remainingMs > 0 ? _fmtDuration(remainingMs) : 'expired';
        timerBadge = `<span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full ${timerColor} font-semibold">
          <i class="ph-duotone ph-clock-countdown text-xs"></i> ${t('timer.until') || 'until'} ${dateStr} ${timeStr} <span class="opacity-70">(${remainLabel})</span>
        </span>`;
      } else {
        timerBadge = `<span class="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.04] text-slate-400 dark:text-slate-500">
          <i class="ph-duotone ph-infinity text-xs"></i> ${t('timer.forever') || 'Permanent'}
        </span>`;
      }

      return `
        <div class="flex items-center gap-3 p-4 bg-white dark:bg-white/[0.03] border border-red-200 dark:border-red-700/40 bg-red-50/30 dark:bg-red-900/5 rounded-xl transition-colors">
          <div class="w-10 h-10 rounded-lg bg-white dark:bg-white/[0.08] border border-slate-200 dark:border-white/[0.08] flex items-center justify-center flex-shrink-0 p-1.5">
            ${logo}
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-sm font-semibold text-slate-800 dark:text-white truncate">${name}</span>
              ${scopeBadge}
            </div>
            <div class="flex items-center gap-2 mt-1.5 flex-wrap">
              ${timerBadge}
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            ${p.service_name ? `<button onclick="openPolicyTimerModal('${p.service_name}')" class="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors" title="${t('timer.setTimer') || 'Set timer'}">
              <i class="ph-duotone ph-clock text-lg text-slate-400"></i>
            </button>` : ''}
            <button onclick="setServicePolicy('${p.service_name || ''}','allow',this)" class="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-600 text-white text-xs font-semibold shadow-sm transition-colors active:scale-95">
              <span class="inline-flex items-center gap-1"><i class="ph-duotone ph-check text-xs"></i> ${t('rules.unblock') || 'Unblock'}</span>
            </button>
          </div>
        </div>`;
    }).join('');

  } catch (err) {
    console.error('loadActiveBlockRules:', err);
    container.innerHTML = `<p class="text-xs text-red-500 text-center py-4">${err.message}</p>`;
  }
}
window.loadActiveBlockRules = loadActiveBlockRules;

async function loadAdguardProtectionState() {
  try {
    const res = await fetch('/api/adguard/protection');
    const data = await res.json();
    const cb = document.getElementById('toggle-adguard-protection');
    const label = document.getElementById('adguard-protection-state');
    if (cb) cb.checked = !!data.enabled;
    if (label) {
      label.textContent = data.enabled ? t('svc.on') : t('svc.off');
      label.className = data.enabled
        ? 'text-xs font-medium text-emerald-500'
        : 'text-xs font-medium text-slate-400';
    }
    // Show which services are actually blocked right now
    const blocksEl = document.getElementById('adguard-active-blocks');
    if (blocksEl) {
      const blocked = Object.entries(_policyByService || {})
        .filter(([, action]) => action === 'block')
        .map(([svc]) => svcDisplayName(svc));
      if (blocked.length > 0) {
        blocksEl.innerHTML = `<span class="text-red-500 font-medium">${blocked.length} ${t('rules.servicesBlocked') || 'service(s) blocked'}:</span> ${blocked.join(', ')}`;
      } else {
        blocksEl.textContent = data.enabled
          ? (t('rules.noActiveBlocks') || 'No services currently blocked.')
          : '';
      }
    }
  } catch (err) {
    console.error('loadAdguardProtectionState:', err);
  }
}

async function toggleAdguardProtection(checkbox) {
  checkbox.disabled = true;
  const enabled = checkbox.checked;
  try {
    const res = await fetch('/api/adguard/protection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const label = document.getElementById('adguard-protection-state');
    if (label) {
      label.textContent = enabled ? t('svc.on') : t('svc.off');
      label.className = enabled
        ? 'text-xs font-medium text-emerald-500'
        : 'text-xs font-medium text-slate-400';
    }
  } catch (err) {
    console.error('toggleAdguardProtection:', err);
    checkbox.checked = !enabled;
    alert(t('rules.adguardToggleFailed', { msg: err.message }) || `Failed: ${err.message}`);
  } finally {
    checkbox.disabled = false;
  }
}
window.toggleAdguardProtection = toggleAdguardProtection;

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
    _renderAllScheduleBadges();
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
  // Update on/off label
  const filterType = id.replace('filter-', '').replace('-card', '');
  const stateEl = document.getElementById(`filter-${filterType}-state`);
  if (stateEl) {
    stateEl.textContent = active ? t('svc.on') : t('svc.off');
    stateEl.className = active
      ? 'text-xs font-medium text-emerald-500'
      : 'text-xs font-medium text-slate-400';
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
    alert(t('rules.filterFailed', { msg: err.message }));
  } finally { checkbox.disabled = false; }
}

// ---------------------------------------------------------------------------
// Scheduling — localStorage-backed schedule for global filters
// ---------------------------------------------------------------------------
const SCHED_STORAGE_KEY = 'airadar-filter-schedules';
let _schedFilterKey = null; // which filter we're editing

function _loadSchedules() {
  try { return JSON.parse(localStorage.getItem(SCHED_STORAGE_KEY)) || {}; }
  catch { return {}; }
}

function _saveSchedules(schedules) {
  localStorage.setItem(SCHED_STORAGE_KEY, JSON.stringify(schedules));
}

const FILTER_NAMES = { parental: 'rules.safeWork', social: 'rules.blockSocial', gaming: 'rules.blockGaming' };
const DAY_KEYS = ['mon','tue','wed','thu','fri','sat','sun'];

function openScheduleModal(filterKey) {
  _schedFilterKey = filterKey;
  const modal = document.getElementById('schedule-modal-backdrop');
  const title = document.getElementById('schedule-modal-title');
  title.textContent = t('sched.title', { name: t(FILTER_NAMES[filterKey]) });

  // Populate time dropdowns
  ['sched-start', 'sched-end'].forEach(id => {
    const sel = document.getElementById(id);
    if (sel.options.length > 0) return; // already populated
    for (let h = 0; h < 24; h++) {
      for (let m = 0; m < 60; m += 30) {
        const val = `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
        const label = new Date(2000, 0, 1, h, m).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        sel.innerHTML += `<option value="${val}">${label}</option>`;
      }
    }
  });

  // Populate day checkboxes
  const daysContainer = document.getElementById('sched-days');
  if (!daysContainer.children.length) {
    daysContainer.innerHTML = DAY_KEYS.map(d =>
      `<label class="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-slate-100 dark:bg-white/[0.04] cursor-pointer hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors">
        <input type="checkbox" value="${d}" class="accent-indigo-500 w-3 h-3" checked>
        <span class="text-[11px] text-slate-600 dark:text-slate-300">${t('sched.' + d)}</span>
      </label>`
    ).join('');
  }

  // Load existing schedule
  const schedules = _loadSchedules();
  const existing = schedules[filterKey];

  if (existing && existing.mode === 'custom') {
    document.querySelector('input[name="sched-mode"][value="custom"]').checked = true;
    document.getElementById('schedule-custom-fields').classList.remove('hidden');
    document.getElementById('sched-start').value = existing.start || '15:00';
    document.getElementById('sched-end').value = existing.end || '18:00';
    // Set day checkboxes
    daysContainer.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.checked = (existing.days || DAY_KEYS.slice(0, 5)).includes(cb.value);
    });
  } else {
    document.querySelector('input[name="sched-mode"][value="always"]').checked = true;
    document.getElementById('schedule-custom-fields').classList.add('hidden');
    document.getElementById('sched-start').value = '15:00';
    document.getElementById('sched-end').value = '18:00';
    daysContainer.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.checked = DAY_KEYS.slice(0, 5).includes(cb.value); // Mon-Fri default
    });
  }

  modal.classList.remove('hidden');
}

function closeScheduleModal() {
  document.getElementById('schedule-modal-backdrop').classList.add('hidden');
  _schedFilterKey = null;
}

function onScheduleModeChange() {
  const mode = document.querySelector('input[name="sched-mode"]:checked')?.value;
  document.getElementById('schedule-custom-fields').classList.toggle('hidden', mode !== 'custom');
}

function saveSchedule() {
  if (!_schedFilterKey) return;
  const mode = document.querySelector('input[name="sched-mode"]:checked')?.value;
  const schedules = _loadSchedules();

  if (mode === 'custom') {
    const start = document.getElementById('sched-start').value;
    const end = document.getElementById('sched-end').value;
    const days = [...document.querySelectorAll('#sched-days input[type="checkbox"]:checked')].map(cb => cb.value);
    schedules[_schedFilterKey] = { mode: 'custom', start, end, days };
  } else {
    delete schedules[_schedFilterKey];
  }

  _saveSchedules(schedules);
  _renderAllScheduleBadges();
  closeScheduleModal();
}

function _renderAllScheduleBadges() {
  const schedules = _loadSchedules();
  ['parental', 'social', 'gaming'].forEach(key => {
    const el = document.getElementById(`filter-${key}-schedule`);
    const textEl = document.getElementById(`filter-${key}-schedule-text`);
    if (!el || !textEl) return;

    const sched = schedules[key];
    if (sched && sched.mode === 'custom') {
      const dayLabels = (sched.days || []).map(d => t('sched.' + d));
      // Compact day range: if Mon-Fri, show "Mon–Fri"
      let dayStr;
      const weekdays = DAY_KEYS.slice(0, 5);
      const weekend = DAY_KEYS.slice(5);
      if (sched.days.length === 7) dayStr = t('sched.mon') + '–' + t('sched.sun');
      else if (JSON.stringify(sched.days.sort()) === JSON.stringify(weekdays)) dayStr = t('sched.mon') + '–' + t('sched.fri');
      else if (JSON.stringify(sched.days.sort()) === JSON.stringify(weekend)) dayStr = t('sched.sat') + '–' + t('sched.sun');
      else dayStr = dayLabels.join(', ');

      // Format times nicely
      const fmtT = (v) => {
        const [h, m] = v.split(':').map(Number);
        return new Date(2000, 0, 1, h, m).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      };
      textEl.textContent = `${dayStr}, ${fmtT(sched.start)} – ${fmtT(sched.end)}`;
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
    }
  });
}

// Expose scheduling functions
window.openScheduleModal = openScheduleModal;
window.closeScheduleModal = closeScheduleModal;
window.onScheduleModeChange = onScheduleModeChange;
window.saveSchedule = saveSchedule;
window.switchSettingsTab = switchSettingsTab;
window.setThemeFromSelect = setThemeFromSelect;
window.toggleMobOverflow = toggleMobOverflow;
window.closeMobOverflow = closeMobOverflow;

// ---------------------------------------------------------------------------
// Settings → "Clean up stale data" button
// ---------------------------------------------------------------------------
// Calls POST /api/admin/cleanup which wipes stale VPN event categories,
// orphan TLS fingerprints, and VACUUMs the database. Confirms first
// so a misclick doesn't nuke the Privacy tab.
async function adminCleanupRun() {
  const confirmMsg = t('settings.cleanupConfirm')
    || 'This will permanently remove all VPN tunnel events and stealth-tunnel events from the database. Continue?';
  if (!window.confirm(confirmMsg)) return;

  const btn = document.getElementById('btn-admin-cleanup');
  const out = document.getElementById('admin-cleanup-result');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('opacity-60', 'cursor-wait');
  }
  if (out) {
    out.classList.remove('hidden', 'text-red-500', 'text-emerald-600');
    out.classList.add('text-slate-400', 'dark:text-slate-500');
    out.textContent = t('settings.cleanupRunning') || 'Running cleanup…';
  }

  try {
    const res = await fetch('/api/admin/cleanup', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const r = data.removed || {};
    const parts = [
      `${r.vpn_tunnel_events || 0} VPN tunnel`,
      `${r.stealth_vpn_events || 0} stealth tunnel`,
      `${r.vpn_sni_events || 0} VPN SNI`,
      `${r.orphaned_tls_fingerprints || 0} orphan TLS`,
    ];
    const vacuumLabel = data.vacuum
      ? (t('settings.cleanupVacuumOk') || 'DB compacted')
      : (t('settings.cleanupVacuumFail') || 'VACUUM failed');
    if (out) {
      out.classList.remove('text-slate-400', 'dark:text-slate-500', 'text-red-500');
      out.classList.add('text-emerald-600', 'dark:text-emerald-400');
      out.textContent = `✓ ${data.total_removed} ${t('settings.cleanupDone') || 'rows removed'} — ${parts.join(' · ')} · ${vacuumLabel}`;
    }

    // Refresh any currently-visible data views so the user sees the
    // effect immediately instead of having to navigate away and back.
    if (typeof refreshPrivacy === 'function') refreshPrivacy();
    if (typeof refreshIps === 'function') refreshIps();
  } catch (err) {
    if (out) {
      out.classList.remove('text-emerald-600', 'dark:text-emerald-400', 'text-slate-400', 'dark:text-slate-500');
      out.classList.add('text-red-500', 'dark:text-red-400');
      out.textContent = `${t('settings.cleanupError') || 'Cleanup failed'}: ${err.message}`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('opacity-60', 'cursor-wait');
    }
  }
}
window.adminCleanupRun = adminCleanupRun;

// ---------------------------------------------------------------------------
// Notification Settings — Home Assistant integration
// ---------------------------------------------------------------------------
async function loadNotificationSettings() {
  try {
    const res = await fetch('/api/settings/notifications');
    const data = await res.json();
    const urlEl = document.getElementById('notify-ha-url');
    const tokenEl = document.getElementById('notify-ha-token');
    const serviceEl = document.getElementById('notify-ha-service');
    const enabledEl = document.getElementById('notify-ha-enabled');
    if (urlEl) urlEl.value = data.url || '';
    if (tokenEl) tokenEl.placeholder = data.token_masked || 'eyJhbGciOiJIUzI1NiIs...';
    if (serviceEl) serviceEl.value = data.notify_service || '';
    if (enabledEl) enabledEl.checked = !!data.is_enabled;
    // Set category checkboxes
    const cats = new Set((data.enabled_categories || '').split(','));
    document.querySelectorAll('#notify-categories input[type="checkbox"]').forEach(cb => {
      cb.checked = cats.has(cb.value);
    });
  } catch (err) {
    console.error('loadNotificationSettings:', err);
  }
}

async function saveNotificationSettings() {
  const url = document.getElementById('notify-ha-url')?.value || '';
  const token = document.getElementById('notify-ha-token')?.value || '';
  const service = document.getElementById('notify-ha-service')?.value || '';
  const enabled = document.getElementById('notify-ha-enabled')?.checked || false;
  const cats = [];
  document.querySelectorAll('#notify-categories input[type="checkbox"]').forEach(cb => {
    if (cb.checked) cats.push(cb.value);
  });
  const statusEl = document.getElementById('notify-status');

  try {
    const res = await fetch('/api/settings/notifications', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        token: token || undefined,
        notify_service: service,
        enabled_categories: cats.join(','),
        is_enabled: enabled,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast(t('notify.saved') || 'Notification settings saved', 'success');
    if (statusEl) statusEl.textContent = '';
    loadNotificationSettings(); // reload to show masked token
  } catch (err) {
    showToast(`${t('notify.saveFailed') || 'Save failed'}: ${err.message}`, 'error');
  }
}

async function testHaNotification() {
  const statusEl = document.getElementById('notify-status');
  if (statusEl) statusEl.textContent = t('notify.testing') || 'Sending test...';
  try {
    // Save first to make sure latest config is used
    await saveNotificationSettings();
    const res = await fetch('/api/settings/notifications/test', { method: 'POST' });
    const data = await res.json();
    if (data.status === 'ok') {
      showToast(t('notify.testOk') || 'Test notification sent!', 'success');
      if (statusEl) statusEl.textContent = '✓ ' + (data.message || 'OK');
      if (statusEl) statusEl.className = 'text-[11px] text-emerald-500';
    } else {
      showToast(`${t('notify.testFailed') || 'Test failed'}: ${data.message}`, 'error');
      if (statusEl) statusEl.textContent = '✗ ' + data.message;
      if (statusEl) statusEl.className = 'text-[11px] text-red-500';
    }
  } catch (err) {
    showToast(`Test failed: ${err.message}`, 'error');
    if (statusEl) { statusEl.textContent = '✗ ' + err.message; statusEl.className = 'text-[11px] text-red-500'; }
  }
}

window.loadNotificationSettings = loadNotificationSettings;
window.saveNotificationSettings = saveNotificationSettings;
window.testHaNotification = testHaNotification;

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
    _renderIpsThreats(data);
  } catch(e) { console.error('loadIpsStatus:', e); }
}

function _renderIpsThreats(data) {
  // --- Alerts tab: real attacks on our network ---
  const alertsBody = document.getElementById('ips-alerts-body');
  if (alertsBody) {
    const rows = [];
    for (const a of (data.alerts || [])) {
      rows.push({
        time: a.created_at,
        ip: a.ip,
        reason: a.scenario.replace(/^crowdsecurity\//, ''),
        source: a.country ? `${a.as_name || ''} (${a.country})`.trim() : (a.as_name || 'local'),
        events: a.events_count || 0,
      });
    }
    for (const d of (data.local_decisions || [])) {
      if (rows.some(r => r.ip === d.ip)) continue;
      rows.push({
        time: d.created_at,
        ip: d.ip,
        reason: d.reason.replace(/^crowdsecurity\//, ''),
        source: d.origin || 'local',
        events: '',
      });
    }
    rows.sort((a, b) => (b.time || '').localeCompare(a.time || ''));

    if (rows.length === 0) {
      alertsBody.innerHTML = `<tr><td colspan="5" class="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
        <div class="flex flex-col items-center gap-2"><span class="text-2xl">🛡️</span><span>No attacks detected on your network yet.</span></div>
      </td></tr>`;
    } else {
      alertsBody.innerHTML = rows.slice(0, 50).map(r => {
        const timeStr = r.time ? new Date(r.time).toLocaleString() : '';
        return `<tr class="border-t border-slate-100 dark:border-white/[0.04]">
          <td class="py-2 px-4 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">${timeStr}</td>
          <td class="py-2 px-4 font-mono text-xs">${r.ip}</td>
          <td class="py-2 px-4 text-xs">${r.reason}</td>
          <td class="py-2 px-4 text-xs text-slate-500 dark:text-slate-400">${r.source}</td>
          <td class="py-2 px-4 text-xs text-slate-500 dark:text-slate-400">${r.events}</td>
        </tr>`;
      }).join('');
    }
  }

  // --- Blocklist tab: community CAPI entries ---
  const blocklistBody = document.getElementById('ips-blocklist-body');
  if (blocklistBody) {
    const bl = data.blocklist || [];
    if (bl.length === 0) {
      blocklistBody.innerHTML = `<tr><td colspan="3" class="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">Community blocklist is empty or still loading.</td></tr>`;
    } else {
      blocklistBody.innerHTML = bl.slice(0, 100).map(d => {
        const reason = d.reason.replace(/^crowdsecurity\//, '').replace(/:/, ' — ');
        return `<tr class="border-t border-slate-100 dark:border-white/[0.04]">
          <td class="py-2 px-4 font-mono text-xs">${d.ip}</td>
          <td class="py-2 px-4 text-xs">${reason}</td>
          <td class="py-2 px-4 text-xs text-slate-500 dark:text-slate-400">${d.duration || ''}</td>
        </tr>`;
      }).join('');
    }
  }
}

function switchIpsTab(tab) {
  const alertsTab = document.getElementById('ips-tab-alerts');
  const blocklistTab = document.getElementById('ips-tab-blocklist');
  const alertsPanel = document.getElementById('ips-panel-alerts');
  const blocklistPanel = document.getElementById('ips-panel-blocklist');
  if (!alertsTab || !blocklistTab) return;

  // Shared tab classes — match the Rules / AI / Settings style.
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const active = `${base} bg-blue-700 text-white shadow-sm`;
  const inactive = `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;

  // Children (the count pills) live inside the <button> via innerHTML,
  // so we must rebuild the markup rather than just rewrite className.
  const alertsCount = document.getElementById('ips-tab-alerts-count')?.textContent || '0';
  const blocklistCount = document.getElementById('ips-tab-blocklist-count')?.textContent || '0';
  const activePill = `<span class="ml-1 px-1.5 py-0.5 text-[9px] rounded-full bg-white/20 text-white">${alertsCount}</span>`;
  const inactivePill = `<span id="ips-tab-alerts-count" class="ml-1 px-1.5 py-0.5 text-[9px] rounded-full bg-slate-200 dark:bg-white/[0.08] text-slate-500 dark:text-slate-400">${alertsCount}</span>`;
  const activeBlocklistPill = `<span id="ips-tab-blocklist-count" class="ml-1 px-1.5 py-0.5 text-[9px] rounded-full bg-white/20 text-white">${blocklistCount}</span>`;
  const inactiveBlocklistPill = `<span id="ips-tab-blocklist-count" class="ml-1 px-1.5 py-0.5 text-[9px] rounded-full bg-slate-200 dark:bg-white/[0.08] text-slate-500 dark:text-slate-400">${blocklistCount}</span>`;

  if (tab === 'alerts') {
    alertsTab.className = active;
    alertsTab.innerHTML = `Attacks on your network <span id="ips-tab-alerts-count" class="ml-1 px-1.5 py-0.5 text-[9px] rounded-full bg-white/20 text-white">${alertsCount}</span>`;
    blocklistTab.className = inactive;
    blocklistTab.innerHTML = `Community Blocklist ${inactiveBlocklistPill}`;
    alertsPanel.classList.remove('hidden');
    blocklistPanel.classList.add('hidden');
  } else {
    alertsTab.className = inactive;
    alertsTab.innerHTML = `Attacks on your network ${inactivePill}`;
    blocklistTab.className = active;
    blocklistTab.innerHTML = `Community Blocklist ${activeBlocklistPill}`;
    alertsPanel.classList.add('hidden');
    blocklistPanel.classList.remove('hidden');
  }
}

function _updateIpsBanner(data) {
  const banner = document.getElementById('ips-banner');
  const statusText = document.getElementById('ips-banner-status');
  const shield = document.getElementById('ips-shield-icon');
  if (!banner) return;

  if (data.enabled && data.crowdsec_running) {
    statusText.textContent = t('ips.active');
    statusText.className = 'text-sm text-emerald-500 dark:text-emerald-400';
    banner.classList.remove('border-slate-200', 'dark:border-white/[0.05]');
    banner.classList.add('border-emerald-300', 'dark:border-emerald-700/40');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center text-2xl';
  } else if (data.enabled) {
    statusText.textContent = t('ips.enabledNoEngine');
    statusText.className = 'text-sm text-amber-500 dark:text-amber-400';
    banner.classList.remove('border-slate-200', 'dark:border-white/[0.05]');
    banner.classList.add('border-amber-300', 'dark:border-amber-700/40');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center text-2xl';
  } else {
    statusText.textContent = t('ips.disabled');
    statusText.className = 'text-sm text-slate-400 dark:text-slate-500';
    banner.classList.remove('border-emerald-300', 'dark:border-emerald-700/40', 'border-amber-300', 'dark:border-amber-700/40');
    banner.classList.add('border-slate-200', 'dark:border-white/[0.05]');
    if (shield) shield.className = 'w-12 h-12 rounded-xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-2xl';
  }
}

function _updateIpsStats(data) {
  // Local alerts count (real attacks on our network)
  const blockedEl = document.getElementById('ips-stat-blocked');
  if (blockedEl) blockedEl.textContent = formatNumber(data.local_alerts_count || 0);

  // Community blocklist count
  const decisionsEl = document.getElementById('ips-stat-decisions');
  if (decisionsEl) decisionsEl.textContent = formatNumber(data.blocklist_count || 0);

  // Tab counts
  const alertsCountEl = document.getElementById('ips-tab-alerts-count');
  if (alertsCountEl) alertsCountEl.textContent = formatNumber(data.local_alerts_count || 0);
  const blocklistCountEl = document.getElementById('ips-tab-blocklist-count');
  if (blocklistCountEl) blocklistCountEl.textContent = formatNumber(data.blocklist_count || 0);

  // Rules card badge — only show local alerts (real attacks)
  const countEl = document.getElementById('ips-threats-count');
  if (countEl) countEl.textContent = formatNumber(data.local_alerts_count || 0);

  // Engine status
  const engineEl = document.getElementById('ips-engine-status');
  if (engineEl) {
    if (data.crowdsec_running) {
      engineEl.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400 dark:bg-emerald-500 inline-block"></span> ${t('ips.online')}`;
      engineEl.className = 'inline-flex items-center gap-1.5 text-sm font-medium text-emerald-500 dark:text-emerald-400';
    } else {
      engineEl.innerHTML = `<span class="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600 inline-block"></span> ${t('ips.offline')}`;
      engineEl.className = 'inline-flex items-center gap-1.5 text-sm font-medium text-slate-400 dark:text-slate-500';
    }
  }

  // Status dot on rules card
  const dot = document.getElementById('ips-status-dot');
  if (dot) {
    dot.classList.remove('bg-emerald-400', 'dark:bg-emerald-500', 'bg-amber-400', 'dark:bg-amber-500', 'bg-slate-300', 'dark:bg-slate-600');
    if (data.crowdsec_running) {
      dot.classList.add('bg-emerald-400', 'dark:bg-emerald-500');
      dot.title = t('ips.crowdsecOnline');
    } else if (data.enabled) {
      dot.classList.add('bg-amber-400', 'dark:bg-amber-500');
      dot.title = t('ips.crowdsecUnreachable');
    } else {
      dot.classList.add('bg-slate-300', 'dark:bg-slate-600');
      dot.title = t('ips.crowdsecOffline');
    }
  }

  // Show/hide setup guide
  const guide = document.getElementById('ips-setup-guide');
  if (guide) guide.classList.toggle('hidden', data.crowdsec_running);

  // Nav badge — only local alerts (real attacks), not blocklist
  _navIpsCount = data.local_alerts_count || 0;
  updateNavBadges();
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
    alert(t('ips.toggleFailed', { msg: err.message }));
  } finally { checkbox.disabled = false; }
}

// --- GRANULAR SERVICE CARDS ---
// ---------------------------------------------------------------------------
// Access Control — 3-way policy segmented control (allow / alert / block)
// ---------------------------------------------------------------------------
// Loads both the list of known services (with traffic stats) AND the
// currently active global ServicePolicy rows. Each service card shows
// a 3-way segmented control wired to POST /api/policies.

let _policyByService = {};  // service_name → action ("allow"|"alert"|"block")

async function loadAccessControl() {
  try {
    // Always fetch global policies. Additionally fetch device-specific
    // policies when a device is selected in the scope bar.
    const fetches = [
      fetch('/api/rules/services').then(r => r.json()),
      fetch('/api/policies?scope=global').then(r => r.json()).catch(() => []),
    ];
    const isDeviceMode = _rulesScopeMode === 'device' && _rulesScopeMac;
    const isGroupMode = _rulesScopeMode === 'group' && _rulesScopeGroupId;
    if (isDeviceMode) {
      fetches.push(
        fetch(`/api/policies?scope=device&mac_address=${encodeURIComponent(_rulesScopeMac)}`)
          .then(r => r.json()).catch(() => [])
      );
    }
    if (isGroupMode) {
      fetches.push(
        fetch(`/api/policies?scope=group&group_id=${_rulesScopeGroupId}`)
          .then(r => r.json()).catch(() => [])
      );
    }
    const results = await Promise.all(fetches);
    const servicesRes = results[0];
    const globalPolicies = results[1];
    const devicePolicies = isDeviceMode ? results[2] : [];
    const groupPolicies = isGroupMode ? results[2] : [];

    // Build global policy map
    const globalByService = {};
    const globalExpByService = {};
    (Array.isArray(globalPolicies) ? globalPolicies : []).forEach(p => {
      if (p.scope === 'global' && p.service_name && !p.category) {
        globalByService[p.service_name] = p.action;
        if (p.expires_at) globalExpByService[p.service_name] = p.expires_at;
      }
    });

    // Build device/group policy map (overrides global when present)
    _devicePolicyByService = {};
    _deviceOverrideServices = new Set();
    if (isDeviceMode && Array.isArray(devicePolicies)) {
      devicePolicies.forEach(p => {
        if (p.scope === 'device' && p.service_name && !p.category) {
          _devicePolicyByService[p.service_name] = p.action;
          _deviceOverrideServices.add(p.service_name);
          if (p.expires_at) globalExpByService[p.service_name] = p.expires_at;
        }
      });
    }
    if (isGroupMode && Array.isArray(groupPolicies)) {
      groupPolicies.forEach(p => {
        if (p.scope === 'group' && p.service_name && !p.category) {
          _devicePolicyByService[p.service_name] = p.action;
          _deviceOverrideServices.add(p.service_name);
          if (p.expires_at) globalExpByService[p.service_name] = p.expires_at;
        }
      });
    }

    // Build category-level policy map (policies where service_name is null)
    _policyByCategory = {};
    _policyCatExpires = {};
    (Array.isArray(globalPolicies) ? globalPolicies : []).forEach(p => {
      if (p.scope === 'global' && !p.service_name && p.category) {
        _policyByCategory[p.category] = p.action;
        if (p.expires_at) _policyCatExpires[p.category] = p.expires_at;
      }
    });
    if (isDeviceMode && Array.isArray(devicePolicies)) {
      devicePolicies.forEach(p => {
        if (p.scope === 'device' && !p.service_name && p.category) {
          _policyByCategory[p.category] = p.action;
          if (p.expires_at) _policyCatExpires[p.category] = p.expires_at;
        }
      });
    }

    // Merged effective policy: device wins over global
    _policyByService = { ...globalByService };
    _policyExpiresByService = { ...globalExpByService };
    if (isDeviceMode) {
      Object.entries(_devicePolicyByService).forEach(([svc, action]) => {
        _policyByService[svc] = action;
      });
    }

    // Render service cards per category into their respective grids.
    // Each category section gets a header with a category-level 3-way
    // toggle so you can block/alert/allow an entire category at once.
    const categories = [
      { key: 'ai',        containerId: 'access-control-ai' },
      { key: 'cloud',     containerId: 'access-control-cloud' },
      { key: 'social',    containerId: 'access-control-social' },
      { key: 'gaming',    containerId: 'access-control-gaming' },
      { key: 'streaming', containerId: 'access-control-streaming' },
    ];
    for (const cat of categories) {
      const el = document.getElementById(cat.containerId);
      if (!el) continue;
      const svcs = servicesRes.filter(s => s.category === cat.key);
      const catToggle = _renderCategoryToggle(cat.key);
      el.innerHTML = catToggle + (svcs.length
        ? svcs.map(renderServiceCard).join('')
        : `<p class="text-slate-400 dark:text-slate-500 text-sm col-span-full text-center py-4">${t('rules.noServices') || 'No services detected.'}</p>`);
    }
  } catch(e) { console.error('loadAccessControl:', e); }
}

function renderServiceCard(svc) {
  const name = SERVICE_NAMES[svc.service_name] || svc.service_name;
  const logo = svcLogo(svc.service_name);

  // Resolve current action. If no explicit policy row exists, fall back
  // to the backend default: "allow" for standard traffic, "alert" for
  // the AI category (high-risk for data exfiltration).
  const defaultAction = svc.category === 'ai' ? 'alert' : 'allow';
  const currentAction = _policyByService[svc.service_name] || defaultAction;

  const lastSeenFmt = svc.last_seen ? fmtTime(svc.last_seen) : '';
  const activeTooltip = svc.seen
    ? t('svc.activeTooltip', { count: formatNumber(svc.hit_count), time: lastSeenFmt })
    : t('svc.preventiveTip');

  const seenTag = svc.seen
    ? `<span class="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400" title="${activeTooltip}"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500 inline-block"></span> ${t('svc.active')} (${formatNumber(svc.hit_count)})</span>`
    : `<span class="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700/40 text-slate-400 dark:text-slate-500" title="${activeTooltip}"><span class="w-1.5 h-1.5 rounded-full bg-slate-300 dark:bg-slate-600 inline-block"></span> ${t('svc.preventive')}</span>`;

  const lastSeenText = svc.seen && svc.last_seen ? `Last: ${lastSeenFmt}` : t('svc.noTraffic');

  // Device mode: distinguish "set on this device" from "inherited from global"
  const isDeviceMode = _rulesScopeMode === 'device' && _rulesScopeMac;
  const isInherited = isDeviceMode && !_deviceOverrideServices.has(svc.service_name);

  // Border tint reflects the current action for visual clarity
  const borderClass =
    currentAction === 'block'  ? 'border-red-300 dark:border-red-700/50 bg-red-50/30 dark:bg-red-900/10' :
    currentAction === 'alert'  ? 'border-amber-300 dark:border-amber-700/50 bg-amber-50/30 dark:bg-amber-900/10' :
                                 'border-slate-200 dark:border-white/[0.05]';

  const inheritedBadge = isInherited
    ? ` <span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.06] text-slate-400 dark:text-slate-500">${t('rules.inherited') || 'Inherited'}</span>`
    : '';
  const cardOpacity = isInherited ? 'opacity-60' : '';
  const cardBorder = isInherited ? 'border-dashed' : '';

  return `
    <div class="svc-card border ${borderClass} ${cardBorder} rounded-xl p-4 bg-white dark:bg-white/[0.03] transition-colors ${cardOpacity}">
      <div class="flex items-center gap-2 mb-2">
        ${logo}
        <span class="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">${name}</span>
        ${inheritedBadge}
      </div>
      <div class="mb-3">${seenTag}</div>
      <div class="flex items-center gap-2">
        <div class="flex-1">${renderPolicySegment(svc.service_name, currentAction)}</div>
        ${renderTimerButton(svc.service_name)}
      </div>
      <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-2">${lastSeenText}</p>
    </div>`;
}

function renderPolicySegment(serviceName, currentAction) {
  // 3-way segmented control — hardcoded class strings (not template
  // interpolation) so Tailwind JIT from the Play CDN picks them up.
  // Active segment has a saturated background, inactive ones use
  // neutral text with a colored hover hint.
  const allowActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-emerald-500 text-white shadow-sm';
  const allowInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-emerald-600 dark:hover:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/20';
  const alertActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-amber-500 text-white shadow-sm';
  const alertInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20';
  const blockActive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-red-500 text-white shadow-sm';
  const blockInactive = 'flex-1 flex items-center justify-center gap-1 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20';

  const checkIcon = '<i class="ph-duotone ph-check text-xs"></i>';
  const alertIcon = '<i class="ph-duotone ph-warning text-xs"></i>';
  const blockIcon = '<i class="ph-duotone ph-x text-xs"></i>';

  const allowLabel = t('rules.allow') || 'Toestaan';
  const alertLabel = t('rules.alert') || 'Waarschuw';
  const blockLabel = t('rules.block') || 'Blokkeer';

  return `<div class="flex gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1" data-svc="${serviceName}">
    <button type="button" onclick="setServicePolicy('${serviceName}','allow',this)" class="${currentAction === 'allow' ? allowActive : allowInactive}">${checkIcon}<span>${allowLabel}</span></button>
    <button type="button" onclick="setServicePolicy('${serviceName}','alert',this)" class="${currentAction === 'alert' ? alertActive : alertInactive}">${alertIcon}<span>${alertLabel}</span></button>
    <button type="button" onclick="setServicePolicy('${serviceName}','block',this)" class="${currentAction === 'block' ? blockActive : blockInactive}">${blockIcon}<span>${blockLabel}</span></button>
  </div>`;
}

async function setServicePolicy(serviceName, action, buttonEl) {
  // Optimistic UI update: disable the segment while the POST is in flight
  const segment = buttonEl?.closest('[data-svc]');
  const buttons = segment ? segment.querySelectorAll('button') : [];
  buttons.forEach(b => { b.disabled = true; });

  try {
    // Send scoped policy based on the active scope selector.
    const scope = _rulesScopeMode === 'device' && _rulesScopeMac ? 'device'
                : _rulesScopeMode === 'group' && _rulesScopeGroupId ? 'group'
                : 'global';
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: scope,
        mac_address: scope === 'device' ? _rulesScopeMac : null,
        group_id: scope === 'group' ? _rulesScopeGroupId : null,
        service_name: serviceName,
        category: null,
        action: action,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    _policyByService[serviceName] = action;
    const actionLabel =
      action === 'allow' ? (t('rules.allow') || 'Toestaan') :
      action === 'alert' ? (t('rules.alert') || 'Waarschuw') :
                           (t('rules.block') || 'Blokkeer');
    const svcLabel = SERVICE_NAMES[serviceName] || serviceName;
    showToast(`${svcLabel}: ${actionLabel}`, 'success');
    // Refresh both the service cards AND the protection toggle —
    // a block action may have auto-enabled AdGuard protection.
    await Promise.all([loadAccessControl(), loadAdguardProtectionState()]);
  } catch (err) {
    console.error('setServicePolicy:', err);
    showToast(`${t('rules.updateFailed') || 'Update mislukt'}: ${err.message}`, 'error');
    buttons.forEach(b => { b.disabled = false; });
  }
}
window.setServicePolicy = setServicePolicy;

// ---------------------------------------------------------------------------
// Category-level policy toggle — block/alert/allow an entire category
// ---------------------------------------------------------------------------
function _renderCategoryToggle(category) {
  const currentAction = _policyByCategory[category] || null;
  const exp = _policyCatExpires[category];

  // Timer indicator
  let timerHtml = '';
  if (exp) {
    const d = new Date(exp);
    const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    timerHtml = `<span class="text-[9px] text-blue-500 tabular-nums"><i class="ph-duotone ph-clock-countdown text-[8px]"></i> ${timeStr}</span>`;
  }

  const allowActive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-emerald-500 text-white shadow-sm';
  const allowInactive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-900/20';
  const alertActive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-amber-500 text-white shadow-sm';
  const alertInactive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-900/20';
  const blockActive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-colors bg-red-500 text-white shadow-sm';
  const blockInactive = 'flex items-center justify-center gap-1 px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20';
  const clearBtn = currentAction
    ? `<button onclick="setCategoryPolicy('${category}', null)" class="text-[10px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors">${t('rules.clearCatRule') || 'Clear'}</button>`
    : '';

  return `<div class="col-span-full mb-2 flex items-center gap-3 px-3 py-2 rounded-xl bg-slate-50 dark:bg-white/[0.02] border border-slate-200 dark:border-white/[0.05]">
    <span class="text-xs font-medium text-slate-600 dark:text-slate-300 flex-shrink-0">${t('rules.entireCategory') || 'Entire category'}:</span>
    <div class="flex gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-0.5">
      <button onclick="setCategoryPolicy('${category}','allow')" class="${currentAction === 'allow' ? allowActive : allowInactive}"><i class="ph-duotone ph-check text-xs"></i> ${t('rules.allow') || 'Allow'}</button>
      <button onclick="setCategoryPolicy('${category}','alert')" class="${currentAction === 'alert' ? alertActive : alertInactive}"><i class="ph-duotone ph-warning text-xs"></i> ${t('rules.alert') || 'Alert'}</button>
      <button onclick="setCategoryPolicy('${category}','block')" class="${currentAction === 'block' ? blockActive : blockInactive}"><i class="ph-duotone ph-x text-xs"></i> ${t('rules.block') || 'Block'}</button>
    </div>
    <button onclick="openCategoryTimerModal('${category}')" class="flex-shrink-0 p-1 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors" title="${t('timer.setTimer') || 'Set timer'}">
      <i class="ph-duotone ph-clock text-base text-slate-400"></i>
    </button>
    ${timerHtml}
    ${clearBtn}
    ${!currentAction ? `<span class="text-[10px] text-slate-400 dark:text-slate-500 italic">${t('rules.noCatRule') || 'No category rule — individual service rules apply'}</span>` : ''}
  </div>`;
}

async function setCategoryPolicy(category, action) {
  const isDeviceScope = _rulesScopeMode === 'device' && _rulesScopeMac;
  try {
    if (action === null) {
      // Remove the category policy — fetch existing and delete
      const policies = await fetch(`/api/policies?scope=${isDeviceScope ? 'device' : 'global'}${isDeviceScope ? '&mac_address=' + encodeURIComponent(_rulesScopeMac) : ''}`).then(r => r.json());
      const catPolicy = (policies || []).find(p => p.category === category && !p.service_name);
      if (catPolicy) {
        await fetch(`/api/policies/${catPolicy.id}`, { method: 'DELETE' });
      }
    } else {
      await fetch('/api/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope: isDeviceScope ? 'device' : 'global',
          mac_address: isDeviceScope ? _rulesScopeMac : null,
          service_name: null,
          category: category,
          action: action,
        }),
      });
    }
    const label = action ? (action === 'allow' ? t('rules.allow') : action === 'alert' ? t('rules.alert') : t('rules.block')) : (t('rules.cleared') || 'Cleared');
    showToast(`${category}: ${label}`, 'success');
    await loadAccessControl();
  } catch (err) {
    showToast(`${t('rules.updateFailed') || 'Failed'}: ${err.message}`, 'error');
  }
}

function openCategoryTimerModal(category) {
  // Reuse the policy timer modal — store category instead of service
  _timerModalService = null;
  _timerModalCategory = category;
  const nameEl = document.getElementById('policy-timer-svc-name');
  if (nameEl) nameEl.textContent = `${t('rules.entireCategory') || 'Entire category'}: ${category}`;
  document.getElementById('policy-timer-modal').classList.remove('hidden');
}

window.setCategoryPolicy = setCategoryPolicy;
window.openCategoryTimerModal = openCategoryTimerModal;

// ---------------------------------------------------------------------------
// Policy Timer — time-limited rules
// ---------------------------------------------------------------------------
let _policyExpiresByService = {};
let _timerModalService = null;
let _timerModalCategory = null;

function renderTimerButton(serviceName) {
  const exp = _policyExpiresByService[serviceName];
  if (exp) {
    const d = new Date(exp);
    const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `<button onclick="openPolicyTimerModal('${serviceName}')" class="flex flex-col items-center gap-0.5 flex-shrink-0" title="${t('timer.activeUntil') || 'Active until'} ${timeStr}">
      <i class="ph-duotone ph-clock-countdown text-lg text-blue-500"></i>
      <span class="text-[9px] tabular-nums text-blue-500 font-medium">${timeStr}</span>
    </button>`;
  }
  return `<button onclick="openPolicyTimerModal('${serviceName}')" class="flex-shrink-0 p-1 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] transition-colors" title="${t('timer.setTimer') || 'Set timer'}">
    <i class="ph-duotone ph-clock text-lg text-slate-400"></i>
  </button>`;
}

function openPolicyTimerModal(serviceName) {
  _timerModalService = serviceName;
  _timerModalCategory = null;
  const nameEl = document.getElementById('policy-timer-svc-name');
  if (nameEl) nameEl.textContent = svcDisplayName(serviceName);
  document.getElementById('policy-timer-modal').classList.remove('hidden');
}

function closePolicyTimerModal() {
  document.getElementById('policy-timer-modal').classList.add('hidden');
  _timerModalService = null;
}

async function setPolicyTimer(hours) {
  // Handle both service-level and category-level timers
  const svc = _timerModalService;
  const cat = _timerModalCategory;
  if (!svc && !cat) return;
  const action = svc ? (_policyByService[svc] || 'alert') : (_policyByCategory[cat] || 'alert');
  const expires = hours ? new Date(Date.now() + hours * 3600 * 1000).toISOString() : null;
  const isDeviceScope = _rulesScopeMode === 'device' && _rulesScopeMac;
  closePolicyTimerModal();
  try {
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: isDeviceScope ? 'device' : 'global',
        mac_address: isDeviceScope ? _rulesScopeMac : null,
        service_name: svc || null,
        category: cat || null,
        action: action,
        expires_at: expires,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const label = hours ? `${hours}h` : (t('timer.forever') || 'permanent');
    const targetName = svc ? svcDisplayName(svc) : cat;
    showToast(`${targetName}: ${label}`, 'success');
    await loadAccessControl();
  } catch (err) {
    showToast(`${t('rules.updateFailed') || 'Update failed'}: ${err.message}`, 'error');
  }
}

async function setPolicyTimerAt() {
  const svc = _timerModalService;
  const cat = _timerModalCategory;
  if (!svc && !cat) return;
  const timeInput = document.getElementById('policy-timer-time');
  if (!timeInput || !timeInput.value) return;
  const [hh, mm] = timeInput.value.split(':').map(Number);
  const target = new Date();
  target.setHours(hh, mm, 0, 0);
  if (target <= new Date()) target.setDate(target.getDate() + 1);

  const action = svc ? (_policyByService[svc] || 'alert') : (_policyByCategory[cat] || 'alert');
  const isDeviceScope = _rulesScopeMode === 'device' && _rulesScopeMac;
  closePolicyTimerModal();
  try {
    const res = await fetch('/api/policies', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope: isDeviceScope ? 'device' : 'global',
        mac_address: isDeviceScope ? _rulesScopeMac : null,
        service_name: svc || null,
        category: cat || null,
        action: action,
        expires_at: target.toISOString(),
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const timeStr = target.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const targetName = svc ? svcDisplayName(svc) : cat;
    showToast(`${targetName}: ${t('timer.until') || 'until'} ${timeStr}`, 'success');
    await loadAccessControl();
  } catch (err) {
    showToast(`${t('rules.updateFailed') || 'Update failed'}: ${err.message}`, 'error');
  }
}

window.openPolicyTimerModal = openPolicyTimerModal;
window.closePolicyTimerModal = closePolicyTimerModal;
window.setPolicyTimer = setPolicyTimer;
window.setPolicyTimerAt = setPolicyTimerAt;

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
    icon: '<i class="ph-duotone ph-lightning"></i>',
    iconBg: 'bg-emerald-100 dark:bg-emerald-900/30',
    iconColor: '',
  },
  {
    name: 'Zeek Network Security Monitor',
    version: null,
    license: 'BSD License',
    description: 'Passive network traffic analysis framework for security monitoring.',
    url: 'https://zeek.org',
    icon: '<i class="ph-duotone ph-magnifying-glass"></i>',
    iconBg: 'bg-sky-100 dark:bg-sky-900/30',
    iconColor: '',
  },
  {
    name: 'CrowdSec',
    version: null,
    license: 'MIT License',
    description: 'Collaborative intrusion prevention system using crowd-sourced threat intelligence.',
    url: 'https://crowdsec.net',
    icon: '<i class="ph-duotone ph-shield-check"></i>',
    iconBg: 'bg-purple-100 dark:bg-purple-900/30',
    iconColor: '',
  },
  {
    name: 'AdGuard Home',
    version: null,
    license: 'GNU GPLv3',
    description: 'Network-wide DNS-level ad and tracker blocking. AI-Radar communicates with an unmodified, independent instance via its official REST API.',
    url: 'https://adguard.com/adguard-home.html',
    icon: '<i class="ph-duotone ph-broadcast"></i>',
    iconBg: 'bg-green-100 dark:bg-green-900/30',
    iconColor: '',
  },
  {
    name: 'Chart.js',
    version: null,
    license: 'MIT License',
    description: 'Simple yet flexible JavaScript charting library for data visualization.',
    url: 'https://www.chartjs.org',
    icon: '<i class="ph-duotone ph-chart-bar"></i>',
    iconBg: 'bg-amber-100 dark:bg-amber-900/30',
    iconColor: '',
  },
  {
    name: 'Apache ECharts',
    version: null,
    license: 'Apache License 2.0',
    description: 'Powerful interactive charting and data visualization library.',
    url: 'https://echarts.apache.org',
    icon: '<i class="ph-duotone ph-chart-line"></i>',
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
    // Two icon variants: a short text badge ("AR" for AI-Radar) or
    // a Phosphor icon HTML string. Length heuristic is no longer
    // reliable now that Phosphor icons are full HTML tags — detect
    // by checking for a leading < instead.
    const iconContent = c.icon.startsWith('<')
      ? `<span class="text-base ${c.iconColor}">${c.icon}</span>`
      : `<span class="font-bold text-xs ${c.iconColor}">${c.icon}</span>`;

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
    updateGlobalKsBanner(data);
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
  updateNavBadges();
  updateGlobalKsBanner(data);

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
    const by = data.activated_by === 'auto_failsafe' ? t('settings.ksAutoFailsafe') : t('settings.ksManual');
    subtitle.textContent = t('settings.ksActiveSince', { time: since, by });
    subtitle.classList.remove('text-slate-400', 'dark:text-slate-500');
    subtitle.classList.add('text-red-500', 'dark:text-red-400');

    btn.textContent = t('settings.ksDeactivate');
    btn.className = 'relative px-5 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 active:scale-95 bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20';

    // Status dots → red
    setKsDot('adguard', 'red', t('settings.ksPassthrough'));
    setKsDot('ips', 'red', t('settings.ksDisabled'));
    setKsDot('rules', 'red', t('settings.ksSuspended'));

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

    subtitle.textContent = t('settings.ksOperational');
    subtitle.classList.remove('text-red-500', 'dark:text-red-400');
    subtitle.classList.add('text-slate-400', 'dark:text-slate-500');

    btn.textContent = t('settings.ksActivate');
    btn.className = 'relative px-5 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 active:scale-95 bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/20';

    setKsDot('adguard', 'green', t('settings.ksFiltering'));
    setKsDot('ips', 'green', t('settings.ksActive'));
    setKsDot('rules', 'green', t('settings.ksEnforced'));

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

function updateGlobalKsBanner(ksState) {
  const banner = document.getElementById('ks-global-banner');
  if (!banner) return;
  if (ksState && ksState.active) {
    banner.classList.remove('hidden');
    banner.classList.add('flex');
    const since = ksState.activated_at ? new Date(ksState.activated_at + 'Z').toLocaleTimeString() : '';
    const sinceEl = document.getElementById('ks-banner-since');
    if (sinceEl) sinceEl.textContent = since ? t('dash.since', { time: since }) : '';
  } else {
    banner.classList.add('hidden');
    banner.classList.remove('flex');
  }
}

async function restoreProtection() {
  // Deactivate the killswitch directly
  try {
    const res = await fetch('/api/killswitch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({active: false}),
    });
    const data = await res.json();
    renderKillswitchUI(data.killswitch || {active: false});
    updateGlobalKsBanner({active: false});
    // Refresh current page to update any page-specific state
    await refreshPage(currentPage);
  } catch (e) {
    console.error('[killswitch] Restore failed:', e);
  }
}

async function toggleKillswitch() {
  const newState = !_killswitchActive;
  const action = newState ? 'ACTIVATE' : 'DEACTIVATE';

  // Confirm before activating
  if (newState) {
    if (!confirm(t('settings.ksConfirm'))) return;
  }

  const btn = document.getElementById('ks-toggle-btn');
  const log = document.getElementById('ks-log');
  btn.disabled = true;
  btn.textContent = newState ? t('settings.ksActivating') : t('settings.ksDeactivating');

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
  if (btn) { btn.disabled = true; btn.textContent = t('settings.checking'); }

  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    const services = data.services || [];
    const summary = data.summary || {};

    const statusMap = {
      ok:      { bg: 'bg-emerald-50 dark:bg-emerald-900/20', border: 'border-emerald-200 dark:border-emerald-700/40', text: 'text-emerald-600 dark:text-emerald-400', label: '● ' + t('settings.online') },
      warning: { bg: 'bg-amber-50 dark:bg-amber-900/20', border: 'border-amber-200 dark:border-amber-700/40', text: 'text-amber-600 dark:text-amber-400', label: '⚠ ' + t('settings.warning') },
      error:   { bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-200 dark:border-red-700/40', text: 'text-red-600 dark:text-red-400', label: '✗ ' + t('settings.hcOffline') },
    };

    const cards = document.getElementById('health-cards');
    const allOk = summary.all_ok;
    const bannerBg = allOk ? 'bg-emerald-50 dark:bg-emerald-900/15 border-emerald-200 dark:border-emerald-700/40' : 'bg-amber-50 dark:bg-amber-900/15 border-amber-200 dark:border-amber-700/40';
    const bannerText = allOk
      ? `<span class="text-emerald-600 dark:text-emerald-400 font-medium">${t('settings.allHealthy', { n: summary.total })}</span>`
      : `<span class="text-amber-600 dark:text-amber-400 font-medium">${t('settings.nHealthy', { ok: summary.ok, total: summary.total })}</span>`;
    const banner = `<div class="col-span-full ${bannerBg} border rounded-xl p-3 text-center text-sm">${bannerText} — ${new Date().toLocaleTimeString()}</div>`;

    cards.innerHTML = banner + services.map(s => {
      const c = statusMap[s.status] || statusMap.error;
      // Determine if this service can be restarted
      let restartBtn = '';
      if (s.service === 'Zeek (Packet Capture)') {
        restartBtn = `<button onclick="restartService('zeek', this)" class="mt-2 w-full px-2 py-1 rounded-lg text-[10px] font-medium transition-colors
          ${s.status !== 'ok' ? 'bg-blue-700 hover:bg-blue-600 text-white' : 'bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300'}">
          ${s.status !== 'ok' ? '⚡ Restart Zeek' : '↻ Restart'}</button>`;
      } else if (s.service === 'Zeek Tailer') {
        restartBtn = `<button onclick="restartService('tailer', this)" class="mt-2 w-full px-2 py-1 rounded-lg text-[10px] font-medium transition-colors
          ${s.status !== 'ok' ? 'bg-blue-700 hover:bg-blue-600 text-white' : 'bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300'}">
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
        <td class="py-3 px-4 text-sm"><span class="mr-2">${s.icon}</span>${s.service}</td>
        <td class="py-3 px-4"><span class="text-[10px] px-2 py-0.5 rounded ${c.bg} ${c.text} font-semibold">${c.label}</span></td>
        <td class="py-3 px-4 text-xs tabular-nums text-slate-400">${s.response_ms > 0 ? s.response_ms + ' ms' : '—'}</td>
        <td class="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">${s.details}</td>
      </tr>`;
    }).join('');

  } catch(err) {
    const cards = document.getElementById('health-cards');
    cards.innerHTML = `<div class="col-span-full bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 rounded-xl p-6 text-center">
      <p class="text-red-600 dark:text-red-400 font-medium">${t('settings.hcFailed')}</p>
      <p class="text-sm text-slate-500 mt-1">${err.message}</p>
    </div>`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = t('settings.runCheck'); }
  }
}

// ================================================================
// SERVICE RESTART
// ================================================================
// ================================================================
// SETTINGS TABS
// ================================================================
let _currentSettingsTab = 'protection';

function switchSettingsTab(tab) {
  const tabs = ['protection', 'system', 'notifications', 'about'];
  if (tab === 'notifications') loadNotificationSettings();
  if (!tabs.includes(tab)) tab = 'protection';
  _currentSettingsTab = tab;

  const activeClass = 'bg-blue-700 text-white shadow-sm';
  const inactiveClass = 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300';

  tabs.forEach(t => {
    const div = document.getElementById('settings-tab-' + t);
    const btn = document.getElementById('settings-tab-btn-' + t);
    if (div) div.classList.toggle('hidden', t !== tab);
    if (btn) btn.className = `px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${t === tab ? activeClass : inactiveClass}`;
  });

  // Update URL hash without triggering full navigate
  const newHash = tab === 'protection' ? '#/settings' : '#/settings/' + tab;
  if (location.hash !== newHash) {
    history.replaceState(null, '', newHash);
  }
}

// ---------------------------------------------------------------------------
// System Performance — host CPU/memory/disk + per-container stats
// ---------------------------------------------------------------------------
let _perfAutoTimer = null;

function _perfBytes(b) {
  if (!b || b <= 0) return '0 B';
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(0) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

function _perfBar(pct, color) {
  const safePct = Math.min(100, Math.max(0, pct || 0));
  return `<div class="w-full h-1.5 rounded-full bg-slate-200 dark:bg-white/[0.06] overflow-hidden">
    <div class="h-full rounded-full bg-${color}-500 transition-all duration-500" style="width:${safePct}%"></div>
  </div>`;
}

function _perfColor(pct) {
  if (pct >= 85) return 'red';
  if (pct >= 65) return 'amber';
  return 'emerald';
}

// ---------------------------------------------------------------------------
// Data Sources info card — shows all external lists/databases used
// ---------------------------------------------------------------------------
async function loadDataSources() {
  const el = document.getElementById('data-sources-list');
  if (!el) return;
  el.innerHTML = `<p class="text-xs text-slate-400 text-center py-2">${t('summary.loading') || 'Loading...'}</p>`;
  try {
    const res = await fetch('/api/system/data-sources');
    const data = await res.json();
    const sources = data.sources || [];
    if (sources.length === 0) {
      el.innerHTML = '<p class="text-xs text-slate-400 text-center py-4">No data sources found.</p>';
      return;
    }
    el.innerHTML = sources.map(s => {
      const entries = typeof s.entries === 'number' ? formatNumber(s.entries) : (s.entries || '—');
      const detail = s.detail ? `<span class="text-slate-400 dark:text-slate-500 ml-1">(${s.detail})</span>` : '';
      const lastUp = s.last_updated ? fmtTime(s.last_updated) : `<span class="text-amber-500">${t('settings.never') || 'never'}</span>`;
      const srcLink = s.source && s.source.startsWith('github.com')
        ? `<a href="https://${s.source}" target="_blank" rel="noopener" class="text-blue-500 hover:underline">${s.source}</a>`
        : (s.source || '—');
      return `<div class="flex items-start gap-3 p-3 rounded-lg bg-slate-50 dark:bg-white/[0.02] border border-slate-100 dark:border-white/[0.03]">
        <div class="w-8 h-8 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center flex-shrink-0">
          <i class="ph-duotone ph-database text-base text-blue-600 dark:text-blue-400"></i>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${s.name}</span>
            <span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400 tabular-nums">${entries} entries${detail}</span>
          </div>
          <p class="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">${s.description}</p>
          <div class="flex items-center gap-3 mt-1.5 text-[10px]">
            <span class="text-slate-400 dark:text-slate-500"><i class="ph-duotone ph-clock text-[9px]"></i> ${t('settings.lastUpdated') || 'Last updated'}: ${lastUp}</span>
            <span class="text-slate-400 dark:text-slate-500"><i class="ph-duotone ph-link text-[9px]"></i> ${srcLink}</span>
          </div>
        </div>
      </div>`;
    }).join('');
  } catch (err) {
    el.innerHTML = `<p class="text-xs text-red-500 text-center py-4">${err.message}</p>`;
  }
}
window.loadDataSources = loadDataSources;


async function loadSystemPerformance() {
  const grid = document.getElementById('perf-host-grid');
  const section = document.getElementById('perf-container-section');
  const tbody = document.getElementById('perf-container-tbody');
  const errP = document.getElementById('perf-docker-error');
  if (!grid) return;

  try {
    const data = await fetch('/api/system/performance').then(r => r.json());
    const host = data.host || {};

    // Host cards
    const cpuColor = _perfColor(host.cpu_percent);
    const memColor = _perfColor(host.memory?.percent);
    const diskColor = _perfColor(host.disk?.percent);
    const load = host.load_avg || [0, 0, 0];

    grid.innerHTML = `
      <div class="bg-slate-50 dark:bg-white/[0.02] rounded-lg p-4 border border-slate-200 dark:border-white/[0.04]">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-slate-500 dark:text-slate-400">${t('settings.cpu') || 'CPU'}</span>
          <span class="text-xs tabular-nums font-semibold text-${cpuColor}-500 dark:text-${cpuColor}-400">${host.cpu_percent ?? 0}%</span>
        </div>
        ${_perfBar(host.cpu_percent, cpuColor)}
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-2 tabular-nums">${host.cpu_count || 0} cores &middot; load ${load[0]} / ${load[1]} / ${load[2]}</p>
      </div>
      <div class="bg-slate-50 dark:bg-white/[0.02] rounded-lg p-4 border border-slate-200 dark:border-white/[0.04]">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-slate-500 dark:text-slate-400">${t('settings.memory') || 'Memory'}</span>
          <span class="text-xs tabular-nums font-semibold text-${memColor}-500 dark:text-${memColor}-400">${host.memory?.percent ?? 0}%</span>
        </div>
        ${_perfBar(host.memory?.percent, memColor)}
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-2 tabular-nums">${_perfBytes(host.memory?.used)} / ${_perfBytes(host.memory?.total)}</p>
      </div>
      <div class="bg-slate-50 dark:bg-white/[0.02] rounded-lg p-4 border border-slate-200 dark:border-white/[0.04]">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-medium text-slate-500 dark:text-slate-400">${t('settings.disk') || 'Disk'}</span>
          <span class="text-xs tabular-nums font-semibold text-${diskColor}-500 dark:text-${diskColor}-400">${host.disk?.percent ?? 0}%</span>
        </div>
        ${_perfBar(host.disk?.percent, diskColor)}
        <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-2 tabular-nums">${_perfBytes(host.disk?.used)} / ${_perfBytes(host.disk?.total)}</p>
      </div>
    `;

    // Container table
    const containers = data.containers || [];
    if (containers.length > 0) {
      section.classList.remove('hidden');
      tbody.innerHTML = containers.map(c => {
        const cpuC = _perfColor(c.cpu_percent);
        const memC = _perfColor(c.memory_percent);
        const stateDot = c.state === 'running'
          ? '<span class="inline-block w-2 h-2 rounded-full bg-emerald-500"></span>'
          : '<span class="inline-block w-2 h-2 rounded-full bg-slate-400"></span>';
        return `<tr class="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50/60 dark:hover:bg-white/[0.02] transition-colors">
          <td class="py-2.5 px-4">
            <span class="text-sm font-medium text-slate-700 dark:text-slate-200">${c.name}</span>
          </td>
          <td class="py-2.5 px-4">
            <span class="inline-flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400">${stateDot} ${c.state}</span>
          </td>
          <td class="py-2.5 px-4 min-w-[140px]">
            <div class="flex items-center gap-2">
              <div class="flex-1">${_perfBar(c.cpu_percent, cpuC)}</div>
              <span class="text-[11px] tabular-nums font-medium text-${cpuC}-500 dark:text-${cpuC}-400 w-12 text-right">${c.cpu_percent}%</span>
            </div>
          </td>
          <td class="py-2.5 px-4 min-w-[180px]">
            <div class="flex items-center gap-2">
              <div class="flex-1">${_perfBar(c.memory_percent, memC)}</div>
              <span class="text-[11px] tabular-nums text-slate-500 dark:text-slate-400 whitespace-nowrap">${_perfBytes(c.memory_used)}</span>
            </div>
          </td>
        </tr>`;
      }).join('');
      errP.classList.add('hidden');
    } else {
      section.classList.remove('hidden');
      tbody.innerHTML = `<tr><td colspan="4" class="py-6 text-center text-xs text-slate-400 dark:text-slate-500">${t('settings.noContainers') || 'No container data available'}</td></tr>`;
    }

    if (data.docker_error) {
      errP.textContent = data.docker_error;
      errP.classList.remove('hidden');
    }
  } catch (err) {
    grid.innerHTML = `<p class="col-span-full text-center text-sm text-red-500 dark:text-red-400 py-6">${t('settings.perfError') || 'Failed to load performance data'}: ${err.message}</p>`;
  }
}

function _togglePerfAutoRefresh() {
  const cb = document.getElementById('perf-autorefresh');
  if (!cb) return;
  if (cb.checked) {
    if (_perfAutoTimer) clearInterval(_perfAutoTimer);
    _perfAutoTimer = setInterval(() => {
      if (currentPage === 'settings' && _currentSettingsTab === 'system') {
        loadSystemPerformance();
      }
    }, 5000);
  } else if (_perfAutoTimer) {
    clearInterval(_perfAutoTimer);
    _perfAutoTimer = null;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const cb = document.getElementById('perf-autorefresh');
  if (cb) cb.addEventListener('change', _togglePerfAutoRefresh);
});

window.loadSystemPerformance = loadSystemPerformance;


function setThemeFromSelect(value) {
  const wantDark = value === 'dark';
  const currentlyDark = isDark();
  if (wantDark !== currentlyDark) toggleTheme();
}

function _initThemeSelect() {
  const sel = document.getElementById('theme-select');
  if (sel) sel.value = isDark() ? 'dark' : 'light';
}

async function restartService(service, btn) {
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ ' + t('settings.restarting');
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
  if (el) el.textContent = t('topbar.lastUpdated') + ' ' + new Date().toLocaleTimeString();
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
    const statusWrap = document.getElementById('system-status');
    if (h.summary?.all_ok) {
      dot.className = 'w-2 h-2 rounded-full bg-emerald-500';
      txt.textContent = t('topbar.allOk');
      txt.className = 'text-emerald-600 dark:text-emerald-400';
      if (statusWrap) statusWrap.className = statusWrap.className.replace(/text-slate-500 dark:text-slate-400/, 'text-emerald-600 dark:text-emerald-400');
    } else {
      const issues = h.summary.total - h.summary.ok;
      dot.className = 'w-2 h-2 rounded-full bg-amber-500';
      txt.textContent = t('topbar.issues', { n: issues, problem: getLocale() === 'nl' ? (issues > 1 ? 'problemen' : 'probleem') : (issues > 1 ? 'Issues' : 'Issue') });
      txt.className = 'text-amber-600 dark:text-amber-400';
      if (statusWrap) statusWrap.className = statusWrap.className.replace(/text-slate-500 dark:text-slate-400/, 'text-amber-600 dark:text-amber-400');
    }
  } catch(e) {
    document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-red-500';
    const errTxt = document.getElementById('status-text');
    errTxt.textContent = t('topbar.connError');
    errTxt.className = 'text-red-600 dark:text-red-400';
    const statusWrap = document.getElementById('system-status');
    if (statusWrap) statusWrap.className = statusWrap.className.replace(/text-slate-500 dark:text-slate-400/, 'text-red-600 dark:text-red-400');
  }

  applyTranslations();

  // Set language selector to current locale
  const localeSel = document.getElementById('locale-select');
  if (localeSel) localeSel.value = getLocale();

  // Load killswitch + IPS state for nav badges
  loadKillswitchState();
  fetch('/api/ips/status').then(r => r.ok ? r.json() : null).then(d => {
    if (d) { _navIpsCount = d.active_threats_blocked || 0; updateNavBadges(); }
  }).catch(() => {});
});
