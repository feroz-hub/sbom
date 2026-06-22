import type { Metadata } from 'next';
import { LoginCallback } from '@/components/auth/LoginCallback';

export const metadata: Metadata = {
  title: 'Sign In — SBOM Analyzer',
  description: 'Completing authentication with HCL IAM.',
};

export default function AuthCallbackPage() {
  return <LoginCallback />;
}
