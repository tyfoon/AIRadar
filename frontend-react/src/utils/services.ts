// Service metadata — colors, names, logos
// Synced from app.js SERVICE_COLORS / SERVICE_NAMES / SERVICE_LOGO_DOMAIN

const ACCENT_COLORS = ['#6366f1','#22d3ee','#f59e0b','#ef4444','#10b981','#ec4899','#8b5cf6','#f97316','#14b8a6','#e11d48'];

const SERVICE_COLORS: Record<string, string> = {
  google_gemini:'#f59e0b', openai:'#10b981', anthropic_claude:'#6366f1',
  google_api:'#4285f4', microsoft_copilot:'#0078d4', perplexity:'#22d3ee',
  huggingface:'#ff6f00', mistral:'#7c3aed',
  dropbox:'#0061fe', wetransfer:'#409fff', google_drive:'#22c55e',
  google_device_sync:'#34a853', google_generic_cdn:'#94a3b8',
  onedrive:'#0ea5e9', icloud:'#6b7280', box:'#0075c9', mega:'#d0021b',
  vpn_active:'#f97316', vpn_nordvpn:'#4687ff', vpn_expressvpn:'#da3940',
  vpn_surfshark:'#1cbdb4', vpn_protonvpn:'#6d4aff', vpn_pia:'#4bb543',
  vpn_cyberghost:'#ffd400', vpn_mullvad:'#294d73', vpn_ipvanish:'#70bb44',
  vpn_tunnelbear:'#ffc600', vpn_windscribe:'#1a5276', vpn_cloudflare_warp:'#f48120',
  facebook:'#1877f2', instagram:'#e4405f', tiktok:'#010101', snapchat:'#fffc00',
  twitter:'#1da1f2', pinterest:'#e60023', linkedin:'#0a66c2', reddit:'#ff4500',
  tumblr:'#35465c', whatsapp:'#25d366', signal:'#3a76f0',
  steam:'#1b2838', epic_games:'#2f2d2e', roblox:'#e2231a', ea_games:'#000000',
  xbox_live:'#107c10', playstation:'#003791', nintendo:'#e60012',
  twitch:'#9146ff', discord:'#5865f2',
  netflix:'#e50914', youtube:'#ff0000', spotify:'#1db954', disney_plus:'#113ccf',
  hbo_max:'#5822b4', prime_video:'#00a8e1', apple_tv:'#555555',
};

const SERVICE_NAMES: Record<string, string> = {
  openai:'OpenAI', anthropic_claude:'Claude', google_gemini:'Gemini',
  google_api:'Google API', microsoft_copilot:'Copilot', perplexity:'Perplexity',
  huggingface:'Hugging Face', mistral:'Mistral',
  dropbox:'Dropbox', wetransfer:'WeTransfer', google_drive:'Google Drive',
  google_device_sync:'Google Device Sync', google_generic_cdn:'Google Cloud (CDN)',
  onedrive:'OneDrive', icloud:'iCloud', box:'Box', mega:'MEGA',
  google_ads:'Google Ads', google_analytics:'Google Analytics',
  google_telemetry:'Google Telemetry', meta_tracking:'Meta Tracking',
  apple_ads:'Apple Ads', microsoft_ads:'Microsoft Ads',
  hotjar:'Hotjar', datadog:'Datadog',
  vpn_active:'VPN Tunnel', vpn_nordvpn:'NordVPN', vpn_expressvpn:'ExpressVPN',
  vpn_surfshark:'Surfshark', vpn_protonvpn:'ProtonVPN', vpn_pia:'Private Internet Access',
  vpn_cyberghost:'CyberGhost', vpn_mullvad:'Mullvad', vpn_ipvanish:'IPVanish',
  vpn_tunnelbear:'TunnelBear', vpn_windscribe:'Windscribe', vpn_cloudflare_warp:'Cloudflare WARP',
  facebook:'Facebook', instagram:'Instagram', tiktok:'TikTok',
  twitter:'X (Twitter)', snapchat:'Snapchat', pinterest:'Pinterest',
  linkedin:'LinkedIn', reddit:'Reddit', tumblr:'Tumblr',
  whatsapp:'WhatsApp', signal:'Signal',
  steam:'Steam', epic_games:'Epic Games', roblox:'Roblox', ea_games:'EA Games',
  xbox_live:'Xbox Live', playstation:'PlayStation', nintendo:'Nintendo',
  twitch:'Twitch', discord:'Discord',
  netflix:'Netflix', youtube:'YouTube', spotify:'Spotify', disney_plus:'Disney+',
  hbo_max:'HBO Max', prime_video:'Prime Video', apple_tv:'Apple TV+',
  amazon:'Amazon', bol:'bol.com', coolblue:'Coolblue', mediamarkt:'MediaMarkt',
  zalando:'Zalando', shein:'Shein', temu:'Temu', aliexpress:'AliExpress',
  marktplaats:'Marktplaats', vinted:'Vinted', ikea:'IKEA', ebay:'eBay', etsy:'Etsy',
  nos:'NOS', nu_nl:'NU.nl', telegraaf:'De Telegraaf', ad_nl:'AD', nrc:'NRC',
  volkskrant:'Volkskrant', bbc:'BBC', nytimes:'New York Times',
  reuters:'Reuters', guardian:'The Guardian',
  tinder:'Tinder', bumble:'Bumble', hinge:'Hinge', grindr:'Grindr',
  lexa:'Lexa', parship:'Parship', happn:'Happn', okcupid:'OkCupid',
  pornhub:'Pornhub', xvideos:'XVideos', xhamster:'xHamster', youporn:'YouPorn',
  redtube:'RedTube', onlyfans:'OnlyFans', chaturbate:'Chaturbate',
  stripchat:'Stripchat', brazzers:'Brazzers',
};

const SERVICE_LOGO_DOMAIN: Record<string, string> = {
  openai:'openai.com', anthropic_claude:'claude.ai',
  google_gemini:'gemini.google.com', microsoft_copilot:'copilot.microsoft.com',
  perplexity:'perplexity.ai', huggingface:'huggingface.co', mistral:'mistral.ai',
  dropbox:'dropbox.com', wetransfer:'wetransfer.com',
  google_drive:'drive.google.com', google_device_sync:'android.com',
  google_generic_cdn:'cloud.google.com', google_api:'developers.google.com',
  onedrive:'onedrive.live.com', icloud:'icloud.com', box:'box.com', mega:'mega.nz',
  google_ads:'ads.google.com', google_analytics:'analytics.google.com',
  google_telemetry:'firebase.google.com', meta_tracking:'meta.com',
  apple_ads:'searchads.apple.com', microsoft_ads:'ads.microsoft.com',
  hotjar:'hotjar.com', datadog:'datadoghq.com', facebook:'facebook.com',
  instagram:'instagram.com', tiktok:'tiktok.com', twitter:'x.com',
  snapchat:'snapchat.com', pinterest:'pinterest.com', linkedin:'linkedin.com',
  reddit:'reddit.com', tumblr:'tumblr.com', steam:'steampowered.com',
  epic_games:'epicgames.com', roblox:'roblox.com', twitch:'twitch.tv',
  discord:'discord.com', nintendo:'nintendo.com', playstation:'playstation.com',
  xbox_live:'xbox.com', signal:'signal.org', whatsapp:'whatsapp.com',
  vpn_active:'nordvpn.com', vpn_nordvpn:'nordvpn.com', vpn_expressvpn:'expressvpn.com',
  vpn_surfshark:'surfshark.com', vpn_protonvpn:'protonvpn.com',
  vpn_pia:'privateinternetaccess.com', vpn_cyberghost:'cyberghostvpn.com',
  vpn_mullvad:'mullvad.net', vpn_ipvanish:'ipvanish.com',
  vpn_tunnelbear:'tunnelbear.com', vpn_windscribe:'windscribe.com',
  vpn_cloudflare_warp:'cloudflare.com', ea_games:'ea.com',
  netflix:'netflix.com', youtube:'youtube.com', spotify:'spotify.com',
  disney_plus:'disneyplus.com', hbo_max:'max.com', prime_video:'primevideo.com',
  apple_tv:'tv.apple.com',
  amazon:'amazon.com', bol:'bol.com', coolblue:'coolblue.nl', mediamarkt:'mediamarkt.nl',
  zalando:'zalando.com', shein:'shein.com', temu:'temu.com', aliexpress:'aliexpress.com',
  marktplaats:'marktplaats.nl', vinted:'vinted.com', ikea:'ikea.com',
  ebay:'ebay.com', etsy:'etsy.com',
  nos:'nos.nl', nu_nl:'nu.nl', telegraaf:'telegraaf.nl', ad_nl:'ad.nl',
  nrc:'nrc.nl', volkskrant:'volkskrant.nl', bbc:'bbc.com',
  nytimes:'nytimes.com', reuters:'reuters.com', guardian:'theguardian.com',
  tinder:'tinder.com', bumble:'bumble.com', hinge:'hinge.co', grindr:'grindr.com',
  lexa:'lexa.nl', parship:'parship.nl', happn:'happn.com', okcupid:'okcupid.com',
  pornhub:'pornhub.com', xvideos:'xvideos.com', xhamster:'xhamster.com',
  youporn:'youporn.com', redtube:'redtube.com', onlyfans:'onlyfans.com',
  chaturbate:'chaturbate.com', stripchat:'stripchat.com', brazzers:'brazzers.com',
};

const SERVICE_LOGO_URL: Record<string, string> = {
  google_drive: 'https://ssl.gstatic.com/images/branding/product/2x/drive_2020q4_48dp.png',
  google_gemini: 'https://ssl.gstatic.com/images/branding/product/2x/gemini_48dp.png',
  google_device_sync: 'https://ssl.gstatic.com/images/branding/product/2x/android_48dp.png',
};

let _fallbackIdx = 0;

export function svcColor(s: string): string {
  if (!SERVICE_COLORS[s]) SERVICE_COLORS[s] = ACCENT_COLORS[_fallbackIdx++ % ACCENT_COLORS.length];
  return SERVICE_COLORS[s];
}

export function svcDisplayName(s: string): string {
  return SERVICE_NAMES[s] || s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export function svcLogoUrl(s: string): string {
  const direct = SERVICE_LOGO_URL[s];
  if (direct) return direct;
  const domain = SERVICE_LOGO_DOMAIN[s] || s.replace(/_/g, '') + '.com';
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}
