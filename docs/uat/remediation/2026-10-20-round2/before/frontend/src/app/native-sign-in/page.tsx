import { NativeAuthForm } from '@/components/auth/NativeAuthForm';
export default async function Page({ searchParams }: { searchParams: Promise<{ email?: string | string[]; activated?: string | string[] }> }) {
  const params = await searchParams;
  return <NativeAuthForm initialEmail={typeof params.email === 'string' ? params.email : ''} activated={params.activated === '1'} />;
}
