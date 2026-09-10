import Link from 'next/link';
import { Bell } from 'lucide-react';
import type { ReportScope } from '@/types/reports';

export function NotifyMeLink({ scope, targetId }: { scope: ReportScope; targetId: number }) {
  return <Link href={`/settings/notifications?scope=${scope}&target=${targetId}`} className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-xs font-medium text-hcl-blue hover:bg-hcl-light"><Bell className="h-4 w-4" />Notify me</Link>;
}
