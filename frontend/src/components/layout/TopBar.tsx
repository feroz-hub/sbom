import type { ReactNode } from 'react';

interface TopBarProps {
  title: string;
  action?: ReactNode;
}

export function TopBar({ title, action }: TopBarProps) {
  return (
    <header className="sticky top-0 z-20 bg-white border-b-2 border-hcl-border shadow-topbar px-6 py-4 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-1 h-6 rounded-full bg-hcl-blue shrink-0" />
        <h1 className="text-xl font-semibold text-hcl-navy tracking-tight">{title}</h1>
      </div>
      {action && <div>{action}</div>}
    </header>
  );
}
