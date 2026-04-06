import type { ReactNode } from 'react';

interface TopBarProps {
  title: string;
  action?: ReactNode;
}

export function TopBar({ title, action }: TopBarProps) {
  return (
    <header className="sticky top-0 z-20 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
      <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
      {action && <div>{action}</div>}
    </header>
  );
}
