import { t } from './i18n';

export interface CategoryGroup {
  key: string;
  label: string;
  icon: string; // Phosphor icon class
  color: string;
}

export function getCategoryGroups(): CategoryGroup[] {
  return [
    { key: 'ai', label: t('cat.aiServices') || 'AI Services', icon: 'ph-brain', color: 'indigo' },
    { key: 'cloud', label: t('cat.cloudStorage') || 'Cloud Storage', icon: 'ph-cloud', color: 'sky' },
    { key: 'tracking', label: t('cat.privacyTrackers') || 'Privacy & Trackers', icon: 'ph-shield-check', color: 'amber' },
    { key: 'other', label: t('cat.other') || 'Other', icon: 'ph-squares-four', color: 'slate' },
  ];
}

export function categorizeService(svc: string, svcCategoryMap: Record<string, string>): string {
  return svcCategoryMap[svc] || 'other';
}
