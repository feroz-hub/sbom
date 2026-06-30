import {
  Activity,
  CalendarClock,
  FileText,
  FolderOpen,
  LayoutDashboard,
  Settings as SettingsIcon,
  type LucideIcon,
} from 'lucide-react';

export interface SubNavItem {
  href: string;
  label: string;
  permission?: string;
}

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  children?: SubNavItem[];
  permission?: string;
}

export const navigationItems: NavItem[] = [
  { href: '/', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', icon: FolderOpen },
  { href: '/sboms', label: 'SBOMs', icon: FileText },
  {
    href: '/analysis',
    label: 'Analysis',
    icon: Activity,
    children: [
      { href: '/analysis?tab=runs', label: 'Runs' },
      { href: '/analysis?tab=consolidated', label: 'Consolidated' },
      { href: '/analysis/compare', label: 'Compare' },
    ],
  },
  { href: '/schedules', label: 'Schedules', icon: CalendarClock },
  {
    href: '/settings',
    label: 'Settings',
    icon: SettingsIcon,
    children: [
      { href: '/settings/ai', label: 'AI configuration' },
      { href: '/settings/tenant', label: 'Tenant users' },
      { href: '/admin/ai-usage', label: 'AI usage' },
      { href: '/admin/lifecycle-providers', label: 'Lifecycle providers', permission: 'lifecycle:provider:read' },
      { href: '/admin/lifecycle-vendor-records', label: 'Vendor records', permission: 'lifecycle:vendor-record:read' },
    ],
  },
];
