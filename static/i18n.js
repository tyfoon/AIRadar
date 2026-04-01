/* ================================================================
   AI-Radar — Lightweight i18n Module
   ================================================================
   Usage:
     t('nav.dashboard')             → translated string
     t('devices.hopCount', {n: 3})  → "3 hops" (interpolation)
     formatNumber(11530)            → "11,530" (en) or "11.530" (nl)
     setLocale('nl')                → switch language, re-render
   ================================================================ */

'use strict';

// ---------------------------------------------------------------------------
// Translation dictionaries
// ---------------------------------------------------------------------------
const TRANSLATIONS = {

  // ========== ENGLISH ==========
  en: {
    // Navigation
    'nav.dashboard':       'Dashboard',
    'nav.ai':              'AI Radar',
    'nav.cloud':           'Cloud Storage',
    'nav.privacy':         'Privacy',
    'nav.attacks':         'Attacks',
    'nav.devices':         'Devices',
    'nav.rules':           'Rules',
    'nav.settings':        'Settings',
    'nav.toggleTheme':     'Toggle Theme',
    'nav.collapse':        'Collapse',
    'nav.groupMonitor':    'Monitor',
    'nav.groupProtect':    'Protect',
    'nav.groupManage':     'Manage',

    // Mobile nav
    'mob.home':            'Home',
    'mob.ai':              'AI',
    'mob.cloud':           'Cloud',
    'mob.privacy':         'Privacy',
    'mob.devices':         'Devices',
    'mob.rules':           'Rules',
    'mob.settings':        'Settings',

    // Page titles
    'page.dashboard':      'Dashboard',
    'page.ai':             'AI Radar',
    'page.cloud':          'Cloud Storage',
    'page.privacy':        'Privacy',
    'page.devices':        'Devices',
    'page.ips':            'Attacks',
    'page.rules':          'Rules & Access Control',
    'page.settings':       'Settings',

    // Top bar
    'topbar.checking':     'Checking...',
    'topbar.refresh':      'Refresh',
    'topbar.allOk':        'All Systems Operational',
    'topbar.issues':       '{n} {problem}',
    'topbar.connError':    'Connection Error',
    'topbar.lastUpdated':  'Last updated:',

    // Dashboard
    'dash.system':         'System',
    'dash.devices':        'Devices',
    'dash.eventsToday':    'Events Today',
    'dash.dnsBlocked':     'Threats Blocked',
    'dash.checking':       'Checking...',
    'dash.allOk':          'All Systems OK',
    'dash.issuesDetected': '{n} {problem} Detected',
    'dash.healthDetails':  'System Health Details',
    'dash.close':          'Close',
    'dash.noHealthData':   'No health data yet. Wait for next refresh.',
    'dash.ok':             'OK',
    'dash.issue':          'Issue',
    'dash.restartZeek':    'Restart Zeek',
    'dash.restartTailer':  'Restart Tailer',
    'dash.dataFlow':       'Network Data Flow',
    'dash.dataFlowDesc':   'How data flows between your devices and online services',
    'dash.viewAllDevices': 'View all devices',
    'dash.noTraffic':      'No traffic data to visualize yet.',
    'dash.aiTraffic':      'AI Traffic',
    'dash.cloudTraffic':   'Cloud Traffic',
    'dash.privacyBlocks':  'Privacy Blocks',
    'dash.events':         'events',
    'dash.nMore':          '+{n} more',
    'dash.latestAlarms':   'Latest Alarms',
    'dash.alarmTime':      'Time',
    'dash.alarmSeverity':  'Severity',
    'dash.alarmEvent':     'Event',
    'dash.alarmService':   'Service',
    'dash.alarmDevice':    'Device',
    'dash.loadingAlarms':  'Loading alarms...',
    'dash.noAlarms':       'No alarms detected. Your network is running smoothly.',
    'dash.uploadDetected': 'Upload detected ({kb} KB)',
    'dash.highVolume':     'High volume traffic ({kb} KB)',
    'dash.showMore':       'Show more',
    'dash.showingOf':      'Showing {visible} of {total} alarms',
    'dash.groupUploads':   '{n} uploads detected (total: {size})',
    'dash.groupHighVol':   '{n} high-volume events (total: {size})',
    'dash.filterAll':      'All',
    'dash.filterCritical': 'Critical',
    'dash.filterHigh':     'High',
    'dash.filterMedium':   'Medium',
    'dash.filterLow':      'Low',
    'dash.since':          'since {time}',
    'dash.onNetwork':      '{count} on your network',
    'dash.eventsSubtitle': 'network events detected',
    'dash.adsTrackers':    'ads & trackers stopped',
    'dash.blockRate':      '{pct}% of all traffic',
    'dash.trendUp':        '↑ {pct}% from yesterday',
    'dash.trendDown':      '↓ {pct}% from yesterday',
    'dash.trendFlat':      '— no change from yesterday',

    // Killswitch banner
    'ks.bannerTitle':      'Killswitch Active — All Protection Disabled',
    'ks.bannerSubtitle':   'Your network protection is currently paused. All traffic is unfiltered.',
    'ks.restoreBtn':       'Restore Protection',

    // AI Radar page
    'ai.tabRadar':         'AI Radar',
    'ai.tabAdoption':      'AI Adoption',
    'ai.events':           'AI Events',
    'ai.services':         'Services',
    'ai.devices':          'Devices',
    'ai.uploads':          'Uploads',
    'ai.filters':          'Filters',
    'ai.allServices':      'All services',
    'ai.allDevices':       'All devices',
    'ai.allTime':          'All time',
    'ai.lastHour':         'Last hour',
    'ai.last24h':          'Last 24 h',
    'ai.last7d':           'Last 7 days',
    'ai.apply':            'Apply',
    'ai.exportCsv':        'Export CSV',
    'ai.timeline':         'Activity Timeline',
    'ai.byService':        'By Service',
    'ai.latestEvents':     'Latest Events',
    'ai.uploadHint':       'Orange rows indicate possible file uploads (>100 KB outbound).',
    'ai.thTime':           'Time',
    'ai.thService':        'Service',
    'ai.thType':           'Type',
    'ai.thDevice':         'Device',
    'ai.thBytes':          'Bytes',
    'ai.noEvents':         'No AI events captured yet.',
    'ai.upload':           'UPLOAD',
    'ai.uploadsLegend':    'Uploads',

    // AI Adoption
    'adopt.overview':      'AI Adoption Overview',
    'adopt.rate':          'Adoption Rate',
    'adopt.rateDetail':    '{ai} of {total} devices',
    'adopt.avgQueries':    'Avg Queries / Device / Day',
    'adopt.activeToday':   'Active Today',
    'adopt.avgSvcUser':    'Avg Services / User',
    'adopt.powerUsers':    'Power Users',
    'adopt.powerHint':     '>50 queries/day',
    'adopt.mostPopular':   'Most Popular',
    'adopt.orgAdoption':   'Organisation AI Adoption',
    'adopt.perDevice':     'Per-Device AI Usage',
    'adopt.perDeviceHint': 'Queries in selected period. Bars show relative usage intensity.',
    'adopt.svcPopularity': 'Service Popularity',
    'adopt.queries':       'queries',
    'adopt.share':         'share',
    'adopt.user':          'user',
    'adopt.users':         'users',

    // Cloud page
    'cloud.events':        'Cloud Events',
    'cloud.services':      'Services',
    'cloud.devices':       'Devices',
    'cloud.uploads':       'Uploads',
    'cloud.filters':       'Filters',
    'cloud.allServices':   'All services',
    'cloud.allDevices':    'All devices',
    'cloud.timeline':      'Activity Timeline',
    'cloud.byService':     'By Service',
    'cloud.latestEvents':  'Latest Events',
    'cloud.eventsHint':    'Cloud storage events (Dropbox, WeTransfer, Google Drive, etc.).',
    'cloud.noEvents':      'No cloud events captured yet.',

    // Privacy page
    'priv.dnsQueries':     'DNS Lookups',
    'priv.viaAdguard':     'via AdGuard Home',
    'priv.dnsBlocked':     'Threats Blocked',
    'priv.blockRate':      'block rate',
    'priv.trackers':       'Trackers Found',
    'priv.viaZeek':        '',
    'priv.uniqueTrackers': 'Tracker Companies',
    'priv.vpnTunnels':     'VPN Connections',
    'priv.noTunnels':      'No tunnels detected',
    'priv.adguard':        'AdGuard',
    'priv.connected':      'Connected',
    'priv.offline':        'Offline',
    'priv.vpnAlerts':      'VPN & Evasion Alerts',
    'priv.noVpnTunnels':   'No active VPN tunnels detected',
    'priv.vpnMonitoring':  'Monitoring OpenVPN, WireGuard, IPsec & more',
    'priv.deviceUsingVpn': '{n} {device} using VPN',
    'priv.blockedDomains': 'Blocked Domains',
    'priv.detectedTrackers':'Detected Trackers',
    'priv.filters':        'Filters',
    'priv.allTrackers':    'All trackers',
    'priv.allDevices':     'All devices',
    'priv.topBlocked':     'Top Blocked (AdGuard)',
    'priv.adguardInactive':'AdGuard Home not active on DNS yet.',
    'priv.trackerBreakdown':'Tracker Breakdown (Zeek)',
    'priv.recentTrackers': 'Recent Tracker Activity',
    'priv.thTime':         'Time',
    'priv.thTracker':      'Tracker',
    'priv.thType':         'Type',
    'priv.thSource':       'Source',
    'priv.waitingData':    'Waiting for data...',
    'priv.noTrackers':     'No trackers detected yet.',
    'priv.noBlockedData':  'No blocked domains data available.',
    'priv.noTrackerData':  'No tracker data available.',
    'priv.vpnDevice':      'Device',
    'priv.vpnService':     'VPN Service',
    'priv.vpnData':        'Data',
    'priv.vpnEvents':      'Events',
    'priv.vpnLastSeen':    'Last Seen',
    'priv.encryptedTunnel':'Encrypted Tunnel',

    // Devices page
    'dev.totalDevices':    'Total Devices',
    'dev.withViolations':  'With Violations',
    'dev.totalEvents':     'Total Events',
    'dev.uploads':         'Uploads',
    'dev.period':          'Period',
    'dev.allTime':         'All time',
    'dev.lastHour':        'Last hour',
    'dev.last24h':         'Last 24 h',
    'dev.last7d':          'Last 7 days',
    'dev.apply':           'Apply',
    'dev.intensity':       'Intensity',
    'dev.low':             'Low',
    'dev.medium':          'Medium',
    'dev.high':            'High',
    'dev.critical':        'Critical',
    'dev.uploadDetected':  'Upload detected',
    'dev.loading':         'Loading...',
    'dev.loadingData':     'Loading device data...',
    'dev.device':          'Device',
    'dev.total':           'Total',
    'dev.noActivity':      'No device activity detected in this period.',
    'dev.aiRecap':         'AI Network Recap',
    'dev.generateReport':  'Generate AI Report (24h)',
    'dev.generatingReport':'Generating AI report...',
    'dev.geminiAnalyzing': 'Gemini is analyzing the past 24 hours of network activity...',
    'dev.reportError':     'Error generating the report.',
    'dev.networkError':    'Network error: {msg}',
    'dev.events':          'events',
    'dev.showingFirst':    'Showing first 100 of {n} events',
    'dev.allServices':     'All Services',
    'dev.renameDevice':    'Rename device:',
    'dev.hop':             'hop',
    'dev.hops':            'hops',
    'dev.searchPlaceholder': 'Search devices by name, IP, or type...',
    'dev.filterAll':       'All',
    'dev.hideInactive':    'Hide inactive devices',
    'dev.editName':        'Edit device name',
    'dev.saveName':        'Save',
    'dev.cancelEdit':      'Cancel',
    'dev.originalName':    'Original:',

    // Attacks (IPS) page
    'ips.attackPrevention':'Attack Prevention',
    'ips.checkingStatus':  'Checking status...',
    'ips.threatsBlocked':  'Threats Blocked',
    'ips.activeDecisions': 'Active Decisions',
    'ips.crowdsecEngine':  'CrowdSec Engine',
    'ips.bouncer':         'Bouncer',
    'ips.online':          'Online',
    'ips.offline':         'Offline',
    'ips.notConfigured':   'Not configured',
    'ips.threatIntel':     'Threat Intelligence Sources',
    'ips.botnetDetection': 'Botnet Detection',
    'ips.botnetDesc':      'Known C2 servers, zombie networks, and automated attack infrastructure.',
    'ips.bruteForce':      'Brute Force Protection',
    'ips.bruteForceDesc':  'IPs flagged for SSH, HTTP, and credential stuffing attacks.',
    'ips.scannerExploit':  'Scanner & Exploit',
    'ips.scannerDesc':     'Port scanners, vulnerability probers, and exploit attempt sources.',
    'ips.recentThreats':   'Recent Blocked Threats',
    'ips.thTime':          'Time',
    'ips.thIp':            'IP Address',
    'ips.thReason':        'Reason',
    'ips.thOrigin':        'Origin',
    'ips.thDuration':      'Duration',
    'ips.noThreats':       'No threats blocked yet. CrowdSec will populate this table once active.',
    'ips.setupGuide':      'Setup Guide',
    'ips.setupIntro':      'Install CrowdSec to enable Active Protect:',
    'ips.setupNote':       'Once installed, CrowdSec will automatically connect to the community threat intelligence network and begin protecting your network.',
    'ips.active':          'Active — protecting your network',
    'ips.enabledNoEngine': 'Enabled — CrowdSec engine not reachable',
    'ips.disabled':        'Disabled — network is not protected',
    'ips.threatsBlockedBadge': 'threats blocked',
    'ips.crowdsecOnline':  'CrowdSec online',
    'ips.crowdsecOffline': 'CrowdSec offline',
    'ips.crowdsecUnreachable': 'CrowdSec not reachable',
    'ips.toggleFailed':    'Failed to toggle Active Protect: {msg}',

    // Rules page
    'rules.outbound':      'Outbound',
    'rules.inbound':       'Inbound',
    'rules.globalFilters': 'Global Office Filters',
    'rules.safeWork':      'Safe Work Environment',
    'rules.safeWorkDesc':  'NSFW, gambling, SafeSearch',
    'rules.blockSocial':   'Block Social Media',
    'rules.blockSocialDesc':'Meta, TikTok, X, Snapchat & more',
    'rules.blockGaming':   'Block Gaming',
    'rules.blockGamingDesc':'Steam, Epic, Roblox, Twitch, Discord',
    'rules.aiServices':    'AI Services',
    'rules.cloudServices': 'Cloud Services',
    'rules.noAiServices':  'No AI services configured',
    'rules.noCloudServices':'No Cloud services configured',
    'rules.ipsTitle':      'Intrusion Prevention (CrowdSec)',
    'rules.crowdsecEngine':'CrowdSec Engine',
    'rules.crowdsecDesc':  'Community-driven threat intelligence',
    'rules.crowdsecDetail':'Automatically blocks known malicious IPs, botnets, and hackers using CrowdSec\'s real-time threat database.',
    'rules.howItWorks':    'How it works',
    'rules.howStep1':      'CrowdSec analyses Zeek network logs for suspicious patterns',
    'rules.howStep2':      'Detected attackers are matched against a global reputation database',
    'rules.howStep3':      'Confirmed threats are automatically blocked at the network level',
    'rules.howStep4':      'Your network contributes back to the community intelligence',
    'rules.threatSources': 'Threat Intelligence Sources',
    'rules.botnet':        'Botnet Detection',
    'rules.botnetDesc':    'Blocks traffic from known botnets, command-and-control servers, and zombie networks.',
    'rules.bruteForce':    'Brute Force Protection',
    'rules.bruteForceDesc':'Detects and blocks automated password-guessing attacks on SSH, web apps, and other services.',
    'rules.scanner':       'Scanner & Exploit',
    'rules.scannerDesc':   'Identifies port scanners, vulnerability probes, and known exploit attempts targeting your network.',
    'rules.filterFailed':  'Failed to update filter: {msg}',

    // Service card
    'svc.active':          'Active',
    'svc.preventive':      'Preventive',
    'svc.allowed':         'Allowed',
    'svc.permanent':       'Permanent',
    'svc.temporary':       'Temporary',
    'svc.noTraffic':       'No traffic detected',
    'svc.expiring':        'expiring...',
    'svc.minsLeft':        '{m}m left',
    'svc.hrsLeft':         '{h}h {m}m left',
    'svc.always':          'Always',
    'svc.1hour':           '1 Hour',
    'svc.2hours':          '2 Hours',
    'svc.4hours':          '4 Hours',
    'svc.6hours':          '6 Hours',
    'svc.8hours':          '8 Hours',
    'svc.custom':          'Custom...',
    'svc.allowedToBlock':  'Allowed — click to block',
    'svc.blockedToAllow':  'Blocked — click to allow',
    'svc.lastSeen':        'Last: {time}',

    // Settings page — Killswitch
    'settings.killswitch': 'Emergency Killswitch',
    'settings.ksOperational':'All systems operational',
    'settings.ksActivate': 'Activate Killswitch',
    'settings.ksDeactivate':'Deactivate Killswitch',
    'settings.ksActiveSince':'Active since {time} ({by})',
    'settings.ksAutoFailsafe':'auto-failsafe',
    'settings.ksManual':   'manual',
    'settings.ksAdguard':  'AdGuard DNS',
    'settings.ksIps':      'IPS / CrowdSec',
    'settings.ksBlockRules':'Block Rules',
    'settings.ksFiltering':'filtering',
    'settings.ksActive':   'active',
    'settings.ksEnforced': 'enforced',
    'settings.ksPassthrough':'passthrough',
    'settings.ksDisabled': 'disabled',
    'settings.ksSuspended':'suspended',
    'settings.ksAutoText': 'Activated automatically because AdGuard was unreachable.',
    'settings.ksActivating':'Activating...',
    'settings.ksDeactivating':'Deactivating...',
    'settings.ksConfirm':  'ACTIVATE KILLSWITCH?\n\nThis will:\n\u2022 Disable AdGuard DNS filtering\n\u2022 Suspend all block rules\n\u2022 Disable intrusion prevention\n\nInternet traffic will flow unfiltered.\nUse this only in emergencies.',

    // Settings — Health
    'settings.health':     'System Health',
    'settings.runCheck':   'Run Check',
    'settings.pressCheck': 'Press {btn} to test all services.',
    'settings.checking':   'Checking...',
    'settings.online':     'Online',
    'settings.warning':    'Warning',
    'settings.hcOffline':  'Offline',
    'settings.hcFailed':   'Health check failed',
    'settings.allHealthy': 'All {n} services healthy',
    'settings.nHealthy':   '{ok}/{total} healthy',
    'settings.restarting': 'Restarting...',
    'settings.restart':    'Restart',

    // Settings — Network
    'settings.network':    'Network Configuration',
    'settings.dnsServer':  'DNS Server',
    'settings.adguardHome':'AdGuard Home',
    'settings.apiBackend': 'API Backend',
    'settings.sensor':     'Sensor',

    // Settings — Data
    'settings.dataRetention':'Data Retention',
    'settings.retentionPeriod':'Retention Period',
    'settings.maxEvents':  'Max Events',
    'settings.cleanup':    'Cleanup Interval',
    'settings.compaction': 'DB Compaction',
    'settings.7days':      '7 days',
    'settings.50k':        '50,000',
    'settings.every60':    'Every 60 min',
    'settings.autoVacuum': 'Auto VACUUM on cleanup',

    // Settings — About
    'settings.about':      'About & Legal',
    'settings.version':    'Version {v}',
    'settings.appDesc':    'Network intelligence appliance for monitoring AI & Cloud service usage, privacy protection, and intrusion prevention.',
    'settings.legalIntro': 'AI-Radar integrates the following independent open-source components via their official APIs. No source code of these projects has been modified or redistributed.',
    'settings.legalFooter':'All trademarks and registered trademarks are the property of their respective owners. This software is provided "as is" without warranty of any kind.',

    // Settings — Language
    'settings.language':   'Language',
    'settings.langDesc':   'Choose your preferred language',

    // Modal
    'modal.customDuration':'Custom Block Duration',
    'modal.blockUntil':    'Block until',
    'modal.block':         'Block',
    'modal.cancel':        'Cancel',
    'modal.selectDate':    'Please select a date/time.',

    // Device categories
    'cat.aiServices':      'AI Services',
    'cat.cloudStorage':    'Cloud Storage',
    'cat.privacyTrackers': 'Privacy / Trackers',

    // Device types (from p0f / detection)
    'dtype.unknown':       'Unknown',
    'dtype.phone':         'Phone',
    'dtype.tablet':        'Tablet',
    'dtype.laptop':        'Laptop',
    'dtype.computer':      'Computer',
    'dtype.server':        'Server',
    'dtype.iot':           'IoT Device',
    'dtype.device':        'Device',
  },

  // ========== DUTCH ==========
  nl: {
    // Navigatie
    'nav.dashboard':       'Dashboard',
    'nav.ai':              'AI Radar',
    'nav.cloud':           'Cloudopslag',
    'nav.privacy':         'Privacy',
    'nav.attacks':         'Aanvallen',
    'nav.devices':         'Apparaten',
    'nav.rules':           'Regels',
    'nav.settings':        'Instellingen',
    'nav.toggleTheme':     'Thema wisselen',
    'nav.collapse':        'Inklappen',
    'nav.groupMonitor':    'Monitor',
    'nav.groupProtect':    'Bescherm',
    'nav.groupManage':     'Beheer',

    // Mobiel
    'mob.home':            'Home',
    'mob.ai':              'AI',
    'mob.cloud':           'Cloud',
    'mob.privacy':         'Privacy',
    'mob.devices':         'Apparaten',
    'mob.rules':           'Regels',
    'mob.settings':        'Instellingen',

    // Paginatitels
    'page.dashboard':      'Dashboard',
    'page.ai':             'AI Radar',
    'page.cloud':          'Cloudopslag',
    'page.privacy':        'Privacy',
    'page.devices':        'Apparaten',
    'page.ips':            'Aanvallen',
    'page.rules':          'Regels & Toegangsbeheer',
    'page.settings':       'Instellingen',

    // Bovenbalk
    'topbar.checking':     'Controleren...',
    'topbar.refresh':      'Vernieuwen',
    'topbar.allOk':        'Alle systemen operationeel',
    'topbar.issues':       '{n} {problem}',
    'topbar.connError':    'Verbindingsfout',
    'topbar.lastUpdated':  'Laatst bijgewerkt:',

    // Dashboard
    'dash.system':         'Systeem',
    'dash.devices':        'Apparaten',
    'dash.eventsToday':    'Gebeurtenissen vandaag',
    'dash.dnsBlocked':     'Bedreigingen geblokkeerd',
    'dash.checking':       'Controleren...',
    'dash.allOk':          'Alle systemen OK',
    'dash.issuesDetected': '{n} {problem} gedetecteerd',
    'dash.healthDetails':  'Systeemgezondheid details',
    'dash.close':          'Sluiten',
    'dash.noHealthData':   'Nog geen gezondheidsdata. Wacht op de volgende vernieuwing.',
    'dash.ok':             'OK',
    'dash.issue':          'Probleem',
    'dash.restartZeek':    'Herstart Zeek',
    'dash.restartTailer':  'Herstart Tailer',
    'dash.dataFlow':       'Netwerk dataverkeer',
    'dash.dataFlowDesc':   'Hoe data stroomt tussen je apparaten en online diensten',
    'dash.viewAllDevices': 'Bekijk alle apparaten',
    'dash.noTraffic':      'Nog geen verkeersdata beschikbaar.',
    'dash.aiTraffic':      'AI-verkeer',
    'dash.cloudTraffic':   'Cloudverkeer',
    'dash.privacyBlocks':  'Privacyblokkades',
    'dash.events':         'gebeurtenissen',
    'dash.nMore':          '+{n} meer',
    'dash.latestAlarms':   'Laatste alarmen',
    'dash.alarmTime':      'Tijd',
    'dash.alarmSeverity':  'Ernst',
    'dash.alarmEvent':     'Gebeurtenis',
    'dash.alarmService':   'Service',
    'dash.alarmDevice':    'Apparaat',
    'dash.loadingAlarms':  'Alarmen laden...',
    'dash.noAlarms':       'Geen alarmen gedetecteerd. Je netwerk draait soepel.',
    'dash.uploadDetected': 'Upload gedetecteerd ({kb} KB)',
    'dash.highVolume':     'Hoog dataverkeer ({kb} KB)',
    'dash.showMore':       'Meer tonen',
    'dash.showingOf':      '{visible} van {total} alarmen weergegeven',
    'dash.groupUploads':   '{n} uploads gedetecteerd (totaal: {size})',
    'dash.groupHighVol':   '{n} hoog-volume gebeurtenissen (totaal: {size})',
    'dash.filterAll':      'Alle',
    'dash.filterCritical': 'Kritiek',
    'dash.filterHigh':     'Hoog',
    'dash.filterMedium':   'Gemiddeld',
    'dash.filterLow':      'Laag',
    'dash.since':          'sinds {time}',
    'dash.onNetwork':      '{count} op je netwerk',
    'dash.eventsSubtitle': 'netwerkgebeurtenissen gedetecteerd',
    'dash.adsTrackers':    'advertenties & trackers gestopt',
    'dash.blockRate':      '{pct}% van al het verkeer',
    'dash.trendUp':        '↑ {pct}% ten opzichte van gisteren',
    'dash.trendDown':      '↓ {pct}% ten opzichte van gisteren',
    'dash.trendFlat':      '— geen verandering sinds gisteren',

    // Killswitch banner
    'ks.bannerTitle':      'Killswitch actief — Alle bescherming uitgeschakeld',
    'ks.bannerSubtitle':   'Je netwerkbescherming is momenteel gepauzeerd. Al het verkeer is ongefilterd.',
    'ks.restoreBtn':       'Bescherming herstellen',

    // AI Radar pagina
    'ai.tabRadar':         'AI Radar',
    'ai.tabAdoption':      'AI Adoptie',
    'ai.events':           'AI-gebeurtenissen',
    'ai.services':         'Services',
    'ai.devices':          'Apparaten',
    'ai.uploads':          'Uploads',
    'ai.filters':          'Filters',
    'ai.allServices':      'Alle services',
    'ai.allDevices':       'Alle apparaten',
    'ai.allTime':          'Alle tijd',
    'ai.lastHour':         'Laatste uur',
    'ai.last24h':          'Laatste 24 u',
    'ai.last7d':           'Laatste 7 dagen',
    'ai.apply':            'Toepassen',
    'ai.exportCsv':        'Exporteer CSV',
    'ai.timeline':         'Activiteitstijdlijn',
    'ai.byService':        'Per service',
    'ai.latestEvents':     'Laatste gebeurtenissen',
    'ai.uploadHint':       'Oranje rijen duiden op mogelijke bestandsuploads (>100 KB uitgaand).',
    'ai.thTime':           'Tijd',
    'ai.thService':        'Service',
    'ai.thType':           'Type',
    'ai.thDevice':         'Apparaat',
    'ai.thBytes':          'Bytes',
    'ai.noEvents':         'Nog geen AI-gebeurtenissen vastgelegd.',
    'ai.upload':           'UPLOAD',
    'ai.uploadsLegend':    'Uploads',

    // AI Adoptie
    'adopt.overview':      'AI Adoptie overzicht',
    'adopt.rate':          'Adoptiegraad',
    'adopt.rateDetail':    '{ai} van {total} apparaten',
    'adopt.avgQueries':    'Gem. verzoeken / apparaat / dag',
    'adopt.activeToday':   'Actief vandaag',
    'adopt.avgSvcUser':    'Gem. services / gebruiker',
    'adopt.powerUsers':    'Intensieve gebruikers',
    'adopt.powerHint':     '>50 verzoeken/dag',
    'adopt.mostPopular':   'Meest populair',
    'adopt.orgAdoption':   'Organisatie AI-adoptie',
    'adopt.perDevice':     'AI-gebruik per apparaat',
    'adopt.perDeviceHint': 'Verzoeken in geselecteerde periode. Balken tonen relatieve gebruiksintensiteit.',
    'adopt.svcPopularity': 'Service populariteit',
    'adopt.queries':       'verzoeken',
    'adopt.share':         'aandeel',
    'adopt.user':          'gebruiker',
    'adopt.users':         'gebruikers',

    // Cloud pagina
    'cloud.events':        'Cloud-gebeurtenissen',
    'cloud.services':      'Services',
    'cloud.devices':       'Apparaten',
    'cloud.uploads':       'Uploads',
    'cloud.filters':       'Filters',
    'cloud.allServices':   'Alle services',
    'cloud.allDevices':    'Alle apparaten',
    'cloud.timeline':      'Activiteitstijdlijn',
    'cloud.byService':     'Per service',
    'cloud.latestEvents':  'Laatste gebeurtenissen',
    'cloud.eventsHint':    'Cloudopslag-gebeurtenissen (Dropbox, WeTransfer, Google Drive, etc.).',
    'cloud.noEvents':      'Nog geen cloud-gebeurtenissen vastgelegd.',

    // Privacy pagina
    'priv.dnsQueries':     'DNS-lookups',
    'priv.viaAdguard':     'via AdGuard Home',
    'priv.dnsBlocked':     'Bedreigingen geblokkeerd',
    'priv.blockRate':      'blokkeerpercentage',
    'priv.trackers':       'Trackers gevonden',
    'priv.viaZeek':        '',
    'priv.uniqueTrackers': 'Trackerbedrijven',
    'priv.vpnTunnels':     'VPN-verbindingen',
    'priv.noTunnels':      'Geen tunnels gedetecteerd',
    'priv.adguard':        'AdGuard',
    'priv.connected':      'Verbonden',
    'priv.offline':        'Offline',
    'priv.vpnAlerts':      'VPN & ontwijkingswaarschuwingen',
    'priv.noVpnTunnels':   'Geen actieve VPN-tunnels gedetecteerd',
    'priv.vpnMonitoring':  'Bewaakt OpenVPN, WireGuard, IPsec en meer',
    'priv.deviceUsingVpn': '{n} {device} gebruikt VPN',
    'priv.blockedDomains': 'Geblokkeerde domeinen',
    'priv.detectedTrackers':'Gedetecteerde trackers',
    'priv.filters':        'Filters',
    'priv.allTrackers':    'Alle trackers',
    'priv.allDevices':     'Alle apparaten',
    'priv.topBlocked':     'Meest geblokkeerd (AdGuard)',
    'priv.adguardInactive':'AdGuard Home nog niet actief op DNS.',
    'priv.trackerBreakdown':'Tracker uitsplitsing (Zeek)',
    'priv.recentTrackers': 'Recente trackeractiviteit',
    'priv.thTime':         'Tijd',
    'priv.thTracker':      'Tracker',
    'priv.thType':         'Type',
    'priv.thSource':       'Bron',
    'priv.waitingData':    'Wachten op data...',
    'priv.noTrackers':     'Nog geen trackers gedetecteerd.',
    'priv.noBlockedData':  'Geen geblokkeerde domeinen beschikbaar.',
    'priv.noTrackerData':  'Geen trackerdata beschikbaar.',
    'priv.vpnDevice':      'Apparaat',
    'priv.vpnService':     'VPN-service',
    'priv.vpnData':        'Data',
    'priv.vpnEvents':      'Gebeurtenissen',
    'priv.vpnLastSeen':    'Laatst gezien',
    'priv.encryptedTunnel':'Versleutelde tunnel',

    // Apparaten pagina
    'dev.totalDevices':    'Totaal apparaten',
    'dev.withViolations':  'Met overtredingen',
    'dev.totalEvents':     'Totaal gebeurtenissen',
    'dev.uploads':         'Uploads',
    'dev.period':          'Periode',
    'dev.allTime':         'Alle tijd',
    'dev.lastHour':        'Laatste uur',
    'dev.last24h':         'Laatste 24 u',
    'dev.last7d':          'Laatste 7 dagen',
    'dev.apply':           'Toepassen',
    'dev.intensity':       'Intensiteit',
    'dev.low':             'Laag',
    'dev.medium':          'Gemiddeld',
    'dev.high':            'Hoog',
    'dev.critical':        'Kritiek',
    'dev.uploadDetected':  'Upload gedetecteerd',
    'dev.loading':         'Laden...',
    'dev.loadingData':     'Apparaatdata laden...',
    'dev.device':          'Apparaat',
    'dev.total':           'Totaal',
    'dev.noActivity':      'Geen apparaatactiviteit in deze periode.',
    'dev.aiRecap':         'AI Netwerksamenvatting',
    'dev.generateReport':  'Genereer AI Rapport (24u)',
    'dev.generatingReport':'AI-rapport genereren...',
    'dev.geminiAnalyzing': 'Gemini analyseert de afgelopen 24 uur netwerkactiviteit...',
    'dev.reportError':     'Fout bij het genereren van het rapport.',
    'dev.networkError':    'Netwerkfout: {msg}',
    'dev.events':          'gebeurtenissen',
    'dev.showingFirst':    'Eerste 100 van {n} gebeurtenissen',
    'dev.allServices':     'Alle services',
    'dev.renameDevice':    'Apparaat hernoemen:',
    'dev.hop':             'hop',
    'dev.hops':            'hops',
    'dev.searchPlaceholder': 'Zoek apparaten op naam, IP of type...',
    'dev.filterAll':       'Alle',
    'dev.hideInactive':    'Inactieve apparaten verbergen',
    'dev.editName':        'Apparaatnaam bewerken',
    'dev.saveName':        'Opslaan',
    'dev.cancelEdit':      'Annuleren',
    'dev.originalName':    'Origineel:',

    // Aanvallen (IPS) pagina
    'ips.attackPrevention':'Aanvalspreventie',
    'ips.checkingStatus':  'Status controleren...',
    'ips.threatsBlocked':  'Bedreigingen geblokkeerd',
    'ips.activeDecisions': 'Actieve beslissingen',
    'ips.crowdsecEngine':  'CrowdSec Engine',
    'ips.bouncer':         'Bouncer',
    'ips.online':          'Online',
    'ips.offline':         'Offline',
    'ips.notConfigured':   'Niet geconfigureerd',
    'ips.threatIntel':     'Dreigingsinforrnatiebronnen',
    'ips.botnetDetection': 'Botnetdetectie',
    'ips.botnetDesc':      'Bekende C2-servers, zombienetwerken en geautomatiseerde aanvalsinfrastructuur.',
    'ips.bruteForce':      'Brute Force-bescherming',
    'ips.bruteForceDesc':  'IP\'s gemarkeerd voor SSH-, HTTP- en credential stuffing-aanvallen.',
    'ips.scannerExploit':  'Scanner & Exploit',
    'ips.scannerDesc':     'Poortscanners, kwetsbaarheidstesters en exploit-pogingsbronnen.',
    'ips.recentThreats':   'Recent geblokkeerde bedreigingen',
    'ips.thTime':          'Tijd',
    'ips.thIp':            'IP-adres',
    'ips.thReason':        'Reden',
    'ips.thOrigin':        'Herkomst',
    'ips.thDuration':      'Duur',
    'ips.noThreats':       'Nog geen bedreigingen geblokkeerd. CrowdSec vult deze tabel zodra het actief is.',
    'ips.setupGuide':      'Installatiegids',
    'ips.setupIntro':      'Installeer CrowdSec om Active Protect in te schakelen:',
    'ips.setupNote':       'Na installatie maakt CrowdSec automatisch verbinding met het gemeenschappelijke dreigingsinformatienetwerk en begint het uw netwerk te beschermen.',
    'ips.active':          'Actief — beschermt uw netwerk',
    'ips.enabledNoEngine': 'Ingeschakeld — CrowdSec engine niet bereikbaar',
    'ips.disabled':        'Uitgeschakeld — netwerk is niet beschermd',
    'ips.threatsBlockedBadge': 'bedreigingen geblokkeerd',
    'ips.crowdsecOnline':  'CrowdSec online',
    'ips.crowdsecOffline': 'CrowdSec offline',
    'ips.crowdsecUnreachable': 'CrowdSec niet bereikbaar',
    'ips.toggleFailed':    'Kan Active Protect niet schakelen: {msg}',

    // Regels pagina
    'rules.outbound':      'Uitgaand',
    'rules.inbound':       'Inkomend',
    'rules.globalFilters': 'Globale kantoorfilters',
    'rules.safeWork':      'Veilige werkomgeving',
    'rules.safeWorkDesc':  'NSFW, gokken, SafeSearch',
    'rules.blockSocial':   'Sociale media blokkeren',
    'rules.blockSocialDesc':'Meta, TikTok, X, Snapchat en meer',
    'rules.blockGaming':   'Gaming blokkeren',
    'rules.blockGamingDesc':'Steam, Epic, Roblox, Twitch, Discord',
    'rules.aiServices':    'AI-services',
    'rules.cloudServices': 'Cloudservices',
    'rules.noAiServices':  'Geen AI-services geconfigureerd',
    'rules.noCloudServices':'Geen cloudservices geconfigureerd',
    'rules.ipsTitle':      'Inbraakpreventie (CrowdSec)',
    'rules.crowdsecEngine':'CrowdSec Engine',
    'rules.crowdsecDesc':  'Gemeenschapsgestuurde dreigingsinformatie',
    'rules.crowdsecDetail':'Blokkeert automatisch bekende kwaadaardige IP\'s, botnets en hackers met behulp van CrowdSec\'s realtime dreigingsdatabase.',
    'rules.howItWorks':    'Hoe het werkt',
    'rules.howStep1':      'CrowdSec analyseert Zeek-netwerklogboeken op verdachte patronen',
    'rules.howStep2':      'Gedetecteerde aanvallers worden vergeleken met een mondiale reputatiedatabase',
    'rules.howStep3':      'Bevestigde bedreigingen worden automatisch op netwerkniveau geblokkeerd',
    'rules.howStep4':      'Uw netwerk draagt bij aan de gemeenschapsinformatie',
    'rules.threatSources': 'Dreigingsinformatiebronnen',
    'rules.botnet':        'Botnetdetectie',
    'rules.botnetDesc':    'Blokkeert verkeer van bekende botnets, command-and-control servers en zombienetwerken.',
    'rules.bruteForce':    'Brute Force-bescherming',
    'rules.bruteForceDesc':'Detecteert en blokkeert geautomatiseerde wachtwoord-raadaanvallen op SSH, webapps en andere services.',
    'rules.scanner':       'Scanner & Exploit',
    'rules.scannerDesc':   'Identificeert poortscanners, kwetsbaarheidsonderzoeken en bekende exploitpogingen gericht op uw netwerk.',
    'rules.filterFailed':  'Filter bijwerken mislukt: {msg}',

    // Service kaart
    'svc.active':          'Actief',
    'svc.preventive':      'Preventief',
    'svc.allowed':         'Toegestaan',
    'svc.permanent':       'Permanent',
    'svc.temporary':       'Tijdelijk',
    'svc.noTraffic':       'Geen verkeer gedetecteerd',
    'svc.expiring':        'verloopt...',
    'svc.minsLeft':        '{m}m over',
    'svc.hrsLeft':         '{h}u {m}m over',
    'svc.always':          'Altijd',
    'svc.1hour':           '1 uur',
    'svc.2hours':          '2 uur',
    'svc.4hours':          '4 uur',
    'svc.6hours':          '6 uur',
    'svc.8hours':          '8 uur',
    'svc.custom':          'Aangepast...',
    'svc.allowedToBlock':  'Toegestaan — klik om te blokkeren',
    'svc.blockedToAllow':  'Geblokkeerd — klik om toe te staan',
    'svc.lastSeen':        'Laatst: {time}',

    // Instellingen — Killswitch
    'settings.killswitch': 'Noodschakelaar',
    'settings.ksOperational':'Alle systemen operationeel',
    'settings.ksActivate': 'Killswitch activeren',
    'settings.ksDeactivate':'Killswitch deactiveren',
    'settings.ksActiveSince':'Actief sinds {time} ({by})',
    'settings.ksAutoFailsafe':'auto-beveiliging',
    'settings.ksManual':   'handmatig',
    'settings.ksAdguard':  'AdGuard DNS',
    'settings.ksIps':      'IPS / CrowdSec',
    'settings.ksBlockRules':'Blokkeerregels',
    'settings.ksFiltering':'filtering',
    'settings.ksActive':   'actief',
    'settings.ksEnforced': 'actief',
    'settings.ksPassthrough':'doorlaten',
    'settings.ksDisabled': 'uitgeschakeld',
    'settings.ksSuspended':'opgeschort',
    'settings.ksAutoText': 'Automatisch geactiveerd omdat AdGuard onbereikbaar was.',
    'settings.ksActivating':'Activeren...',
    'settings.ksDeactivating':'Deactiveren...',
    'settings.ksConfirm':  'KILLSWITCH ACTIVEREN?\n\nDit zal:\n\u2022 AdGuard DNS-filtering uitschakelen\n\u2022 Alle blokkeerregels opschorten\n\u2022 Inbraakpreventie uitschakelen\n\nInternetverkeer zal ongefilterd stromen.\nGebruik dit alleen in noodgevallen.',

    // Instellingen — Gezondheid
    'settings.health':     'Systeemgezondheid',
    'settings.runCheck':   'Controleren',
    'settings.pressCheck': 'Druk op {btn} om alle services te testen.',
    'settings.checking':   'Controleren...',
    'settings.online':     'Online',
    'settings.warning':    'Waarschuwing',
    'settings.hcOffline':  'Offline',
    'settings.hcFailed':   'Gezondheidscontrole mislukt',
    'settings.allHealthy': 'Alle {n} services gezond',
    'settings.nHealthy':   '{ok}/{total} gezond',
    'settings.restarting': 'Herstarten...',
    'settings.restart':    'Herstarten',

    // Instellingen — Netwerk
    'settings.network':    'Netwerkconfiguratie',
    'settings.dnsServer':  'DNS-server',
    'settings.adguardHome':'AdGuard Home',
    'settings.apiBackend': 'API Backend',
    'settings.sensor':     'Sensor',

    // Instellingen — Data
    'settings.dataRetention':'Gegevensbewaring',
    'settings.retentionPeriod':'Bewaarperiode',
    'settings.maxEvents':  'Max gebeurtenissen',
    'settings.cleanup':    'Opruiminterval',
    'settings.compaction': 'DB-compactie',
    'settings.7days':      '7 dagen',
    'settings.50k':        '50.000',
    'settings.every60':    'Elke 60 min',
    'settings.autoVacuum': 'Auto VACUUM bij opruiming',

    // Instellingen — Over
    'settings.about':      'Over & Juridisch',
    'settings.version':    'Versie {v}',
    'settings.appDesc':    'Netwerkinformatie-apparaat voor het monitoren van AI- en cloudservicegebruik, privacybescherming en inbraakpreventie.',
    'settings.legalIntro': 'AI-Radar integreert de volgende onafhankelijke open-source componenten via hun offici\u00eble API\'s. Geen broncode van deze projecten is gewijzigd of herverdeeld.',
    'settings.legalFooter':'Alle handelsmerken en geregistreerde handelsmerken zijn eigendom van hun respectievelijke eigenaars. Deze software wordt geleverd "zoals het is" zonder enige garantie.',

    // Instellingen — Taal
    'settings.language':   'Taal',
    'settings.langDesc':   'Kies uw voorkeurstaal',

    // Modaal
    'modal.customDuration':'Aangepaste blokkeerduur',
    'modal.blockUntil':    'Blokkeren tot',
    'modal.block':         'Blokkeren',
    'modal.cancel':        'Annuleren',
    'modal.selectDate':    'Selecteer een datum/tijd.',

    // Apparaatcategorie\u00ebn
    'cat.aiServices':      'AI-services',
    'cat.cloudStorage':    'Cloudopslag',
    'cat.privacyTrackers': 'Privacy / Trackers',

    // Apparaattypen
    'dtype.unknown':       'Onbekend',
    'dtype.phone':         'Telefoon',
    'dtype.tablet':        'Tablet',
    'dtype.laptop':        'Laptop',
    'dtype.computer':      'Computer',
    'dtype.server':        'Server',
    'dtype.iot':           'IoT-apparaat',
    'dtype.device':        'Apparaat',
  },
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let _currentLocale = localStorage.getItem('airadar-locale') || 'en';

// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------

/**
 * Get the current locale code ('en' or 'nl').
 */
function getLocale() {
  return _currentLocale;
}

/**
 * Translate a key, with optional interpolation.
 *   t('dash.uploadDetected', { kb: 42 })  →  "Upload detected (42 KB)"
 *   t('topbar.issues', { n: 3, s: 's' })  →  "3 Issues"
 */
function t(key, params) {
  const dict = TRANSLATIONS[_currentLocale] || TRANSLATIONS.en;
  let str = dict[key];
  if (str === undefined) {
    // Fallback to English
    str = TRANSLATIONS.en[key];
    if (str === undefined) return key; // missing key — return raw key
  }
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      str = str.replace(new RegExp(`\\{${k}\\}`, 'g'), v);
    });
  }
  return str;
}

/**
 * Format a number with locale-appropriate thousands separator.
 *   formatNumber(11530)  →  "11,530" (en)  /  "11.530" (nl)
 */
function formatNumber(n) {
  if (n == null || isNaN(n)) return '0';
  const loc = _currentLocale === 'nl' ? 'nl-NL' : 'en-US';
  return Number(n).toLocaleString(loc);
}

/**
 * Apply translations to all elements with a data-i18n attribute.
 *   <span data-i18n="nav.dashboard">Dashboard</span>
 */
function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const translated = t(key);
    if (translated !== key) {
      el.textContent = translated;
    }
  });
  // Also apply placeholder translations
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    const translated = t(key);
    if (translated !== key) el.placeholder = translated;
  });
  // Update page title if currently showing
  const titleEl = document.getElementById('page-title');
  if (titleEl && typeof currentPage !== 'undefined') {
    titleEl.textContent = t('page.' + currentPage);
  }
}

/**
 * Switch locale and re-render the entire page.
 */
function setLocale(locale) {
  if (!TRANSLATIONS[locale]) return;
  _currentLocale = locale;
  localStorage.setItem('airadar-locale', locale);
  document.documentElement.lang = locale;
  applyTranslations();
  // Re-render dynamic content on the current page
  if (typeof refreshPage === 'function' && typeof currentPage !== 'undefined') {
    refreshPage(currentPage);
  }
}
