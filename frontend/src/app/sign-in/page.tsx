import Link from 'next/link';
import { MicrosoftSignIn } from '@/components/auth/MicrosoftSignIn';

export const dynamic = 'force-dynamic';

export default function SignInPage() {
  return <main className="mx-auto max-w-md space-y-6 px-6 py-16">
    <h1 className="text-2xl font-semibold">Sign in to SBOM Analyzer</h1>
    <p>Use your organization identity or your Native account.</p>
    <MicrosoftSignIn />
    {process.env.NATIVE_AUTH_ENABLED === 'true' && <Link className="block underline" href="/native-sign-in">Native sign in</Link>}
    {process.env.NEXT_PUBLIC_HCL_AUTH_ENABLED !== 'false' && <Link className="block underline" href="/api/auth/login?provider=hcl">Sign in with HCL.CS</Link>}
  </main>;
}
