import { NativeAuthForm } from '@/components/auth/NativeAuthForm';
import { MicrosoftSignIn } from '@/components/auth/MicrosoftSignIn';
export default function Page() { return <><NativeAuthForm /><div className="mx-auto max-w-md px-8 pb-8"><MicrosoftSignIn /></div></>; }
