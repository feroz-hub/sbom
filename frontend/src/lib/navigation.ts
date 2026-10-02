import {
  Activity,
  Building2,
  Cpu,
  UsersRound,
  CalendarClock,
  FileText,
  FolderOpen,
  LayoutDashboard,
  ShieldCheck,
  ShieldQuestion,
  PackageSearch,
  Settings as SettingsIcon,
  type LucideIcon,
} from 'lucide-react';

export interface SubNavItem {
  href: string;
  label: string;
  permission?: string;
  permissionsAny?: string[];
  icon?: LucideIcon;
}

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  children?: SubNavItem[];
  permission?: string;
  permissionsAny?: string[];
  section?: boolean;
  group?: 'Overview' | 'Inventory' | 'Security Operations' | 'Administration';
}

export const navigationItems: NavItem[] = [
  { href: '/platform', label: 'Platform Dashboard', icon: LayoutDashboard, permission: 'platform:tenant:read' },
  { href: '/settings/platform/tenants', label: 'Tenants', icon: Building2, permission: 'platform:tenant:read' },
  {
    href: '/platform/configuration', label: 'Configuration', icon: SettingsIcon, section: true,
    children: [
      { href: '/platform/configuration/ai', label: 'AI Configuration', icon: Cpu, permission: 'platform:ai:read' },
      { href: '/platform/configuration/lifecycle', label: 'Lifecycle Providers', icon: CalendarClock, permission: 'platform:lifecycle-provider:read' },
    ],
  },
  {
    href: '/platform/administration', label: 'Administration', icon: UsersRound, section: true,
    children: [
      { href: '/settings/platform', label: 'Platform Administrators', icon: UsersRound, permission: 'platform:administrator:read' },
      { href: '/settings/iam', label: 'Platform Health', icon: Activity, permission: 'platform:health:read' },
    ],
  },
  { href: '/', label: 'Dashboard', icon: LayoutDashboard, permission: 'dashboard:read', group: 'Overview' },
  { href: '/projects', label: 'Projects', icon: FolderOpen, permission: 'project:read', group: 'Inventory' },
  { href: '/sboms', label: 'SBOMs', icon: FileText, permission: 'sbom:read', group: 'Inventory' },
  {
    href: '/analysis',
    label: 'Analysis',
    group: 'Security Operations',
    icon: Activity,
    permission: 'analysis:read',
    children: [
      { href: '/analysis?tab=runs', label: 'Runs' },
      { href: '/analysis?tab=consolidated', label: 'Consolidated' },
      { href: '/analysis/compare', label: 'Compare' },
    ],
  },
  { href: '/kev', label: 'CISA KEV', icon: ShieldCheck, permission: 'analysis:read', group: 'Security Operations' },
  { href: '/vex-investigation', label: 'VEX Investigation', icon: ShieldQuestion, permission: 'vex:read', group: 'Security Operations' },
  { href: '/component-advisor', label: 'Secure Component Advisor', icon: PackageSearch, permission: 'component_advisor:read', group: 'Security Operations' },
  { href: '/schedules', label: 'Schedules', icon: CalendarClock, permission: 'schedule:read', group: 'Security Operations' },
  {
    href: '/settings',
    label: 'Settings',
    group: 'Administration',
    icon: SettingsIcon,
    children: [
      { href: '/settings/users', label: 'Users & Access', icon: UsersRound, permission: 'tenant:user:read' },
      { href: '/settings/ai', label: 'AI Configuration', icon: Cpu, permission: 'tenant:ai:read' },
      { href: '/admin/lifecycle-providers', label: 'Lifecycle Providers', icon: CalendarClock, permission: 'tenant:lifecycle-provider:read' },
      { href: '/settings/notifications', label: 'Notifications', icon: Activity, permission: 'sbom:read' },
      { href: '/admin/lifecycle-vendor-records', label: 'LifeCycle Vendor Records', icon: Building2, permission: 'lifecycle:vendor-record:read' },
    ],
  },
];
