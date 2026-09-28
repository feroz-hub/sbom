'use client';
import NativeUserInviteForm from '@/components/admin/NativeUserInviteForm';
import UserLifecycle from '@/components/admin/UserLifecycle';
import { useAuth } from '@/hooks/useAuth';

export default function NativeUsersPage() {
  const { hasPermission } = useAuth();
  const canInvite = hasPermission('platform:user:manage_status') || hasPermission('tenant:user:invite');
  return <main className="p-8 space-y-8"><UserLifecycle />{canInvite && <details><summary>Invite native user</summary><NativeUserInviteForm /></details>}</main>;
}
