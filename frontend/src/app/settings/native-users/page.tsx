'use client';
import NativeUserInviteForm from '@/components/admin/NativeUserInviteForm';
import UserLifecycle from '@/components/admin/UserLifecycle';

export default function NativeUsersPage() {
  return <main className="p-8 space-y-8"><UserLifecycle /><details><summary>Invite native user</summary><NativeUserInviteForm /></details></main>;
}
