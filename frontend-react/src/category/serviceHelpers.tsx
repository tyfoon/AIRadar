/**
 * Shared service logo / display-name / color helpers.
 * Extracted from Dashboard.tsx so AI, Cloud, and Dashboard pages can all use them.
 */

// ---------------------------------------------------------------------------
// Service → favicon domain mapping
// ---------------------------------------------------------------------------
const SERVICE_LOGO_DOMAIN: Record<string, string> = {
  openai:'openai.com', anthropic_claude:'claude.ai', google_gemini:'gemini.google.com',
  microsoft_copilot:'copilot.microsoft.com', perplexity:'perplexity.ai', huggingface:'huggingface.co',
  mistral:'mistral.ai', dropbox:'dropbox.com', wetransfer:'wetransfer.com',
  google_drive:'drive.google.com', google_device_sync:'android.com', google_generic_cdn:'cloud.google.com',
  google_api:'developers.google.com', onedrive:'onedrive.live.com', icloud:'icloud.com',
  box:'box.com', mega:'mega.nz', google_ads:'ads.google.com', google_analytics:'analytics.google.com',
  google_telemetry:'firebase.google.com', meta_tracking:'meta.com', apple_ads:'searchads.apple.com',
  microsoft_ads:'ads.microsoft.com', hotjar:'hotjar.com', datadog:'datadoghq.com',
  facebook:'facebook.com', instagram:'instagram.com', tiktok:'tiktok.com', twitter:'x.com',
  snapchat:'snapchat.com', pinterest:'pinterest.com', linkedin:'linkedin.com', reddit:'reddit.com',
  tumblr:'tumblr.com', steam:'steampowered.com', epic_games:'epicgames.com', roblox:'roblox.com',
  twitch:'twitch.tv', discord:'discord.com', nintendo:'nintendo.com', playstation:'playstation.com',
  xbox_live:'xbox.com', signal:'signal.org', whatsapp:'whatsapp.com',
  netflix:'netflix.com', youtube:'youtube.com', spotify:'spotify.com', disney_plus:'disneyplus.com',
  hbo_max:'max.com', prime_video:'primevideo.com', apple_tv:'tv.apple.com',
  amazon:'amazon.com', bol:'bol.com', coolblue:'coolblue.nl', mediamarkt:'mediamarkt.nl',
  zalando:'zalando.com', shein:'shein.com', temu:'temu.com', aliexpress:'aliexpress.com',
  marktplaats:'marktplaats.nl', vinted:'vinted.com', ikea:'ikea.com', ebay:'ebay.com', etsy:'etsy.com',
  nos:'nos.nl', nu_nl:'nu.nl', telegraaf:'telegraaf.nl', ad_nl:'ad.nl', nrc:'nrc.nl',
  volkskrant:'volkskrant.nl', bbc:'bbc.com', nytimes:'nytimes.com', reuters:'reuters.com',
  guardian:'theguardian.com', ea_games:'ea.com',
  pornhub:'pornhub.com', xvideos:'xvideos.com', xhamster:'xhamster.com', onlyfans:'onlyfans.com',
  tinder:'tinder.com', bumble:'bumble.com',
};

const SERVICE_LOGO_URL: Record<string, string> = {
  google_drive: 'https://ssl.gstatic.com/images/branding/product/2x/drive_2020q4_48dp.png',
  google_gemini: 'https://ssl.gstatic.com/images/branding/product/2x/gemini_48dp.png',
  google_device_sync: 'https://ssl.gstatic.com/images/branding/product/2x/android_48dp.png',
};

export function svcLogoUrl(s: string): string {
  if (SERVICE_LOGO_URL[s]) return SERVICE_LOGO_URL[s];
  const domain = SERVICE_LOGO_DOMAIN[s] || s.replace(/_/g, '') + '.com';
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

export function SvcLogo({ svc, size = 14 }: { svc: string; size?: number }) {
  return (
    <img
      src={svcLogoUrl(svc)}
      alt={svc}
      width={size}
      height={size}
      className="rounded-sm"
      style={{ width: size, height: size, objectFit: 'contain' }}
      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
    />
  );
}

// ---------------------------------------------------------------------------
// Service → color mapping
// ---------------------------------------------------------------------------
export const SERVICE_COLORS: Record<string, string> = {
  openai:'#10b981', anthropic_claude:'#6366f1', google_gemini:'#f59e0b',
  google_api:'#4285f4', microsoft_copilot:'#0078d4', perplexity:'#22d3ee',
  huggingface:'#ff6f00', mistral:'#7c3aed',
  dropbox:'#0061fe', wetransfer:'#409fff', google_drive:'#22c55e',
  google_device_sync:'#34a853', google_generic_cdn:'#94a3b8',
  onedrive:'#0ea5e9', icloud:'#6b7280', box:'#0075c9', mega:'#d0021b',
  facebook:'#1877f2', instagram:'#e4405f', tiktok:'#010101', snapchat:'#fffc00',
  twitter:'#1da1f2', pinterest:'#e60023', linkedin:'#0a66c2', reddit:'#ff4500',
  tumblr:'#35465c', whatsapp:'#25d366', signal:'#3a76f0', discord:'#5865f2',
  steam:'#1b2838', epic_games:'#2f2d2e', roblox:'#e2231a', twitch:'#9146ff',
  xbox_live:'#107c10', playstation:'#003791', nintendo:'#e60012', ea_games:'#000',
  netflix:'#e50914', youtube:'#ff0000', spotify:'#1db954', disney_plus:'#113ccf',
  hbo_max:'#5822b4', prime_video:'#00a8e1', apple_tv:'#555',
  amazon:'#ff9900', bol:'#0000a4', coolblue:'#0090e3',
  nos:'#ff6600', nu_nl:'#c30000', bbc:'#bb1919', nytimes:'#111',
  google_ads:'#fbbc04', google_analytics:'#e37400', meta_tracking:'#1877f2',
  hotjar:'#fd3a5c', datadog:'#632ca6',
};

export function svcColor(s: string): string {
  return SERVICE_COLORS[s] || `hsl(${Math.abs([...s].reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0)) % 360}, 55%, 50%)`;
}

export function svcDisplayName(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Service badge — logo + name pill
// ---------------------------------------------------------------------------
export function SvcBadge({ svc }: { svc: string }) {
  const color = svcColor(svc);
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300">
      <SvcLogo svc={svc} size={14} />
      <span style={{ color }}>{svcDisplayName(svc)}</span>
    </span>
  );
}
