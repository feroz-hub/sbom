import { Suspense } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { ReportNotificationsPage } from '@/components/reports/ReportNotificationsPage';

export default function NotificationsRoute() {
  return <div className="flex flex-1 flex-col"><TopBar title="Settings — Notifications" /><main className="mx-auto w-full max-w-6xl p-6"><Suspense fallback={<p>Loading notification settings…</p>}><ReportNotificationsPage /></Suspense></main></div>;
}
