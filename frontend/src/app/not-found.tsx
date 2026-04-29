import Link from 'next/link';
import { FileQuestion } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-4 p-8 text-center">
      <FileQuestion className="h-14 w-14 text-hcl-muted" aria-hidden />
      <h1 className="text-xl font-semibold text-hcl-navy">Page not found</h1>
      <p className="max-w-md text-sm text-hcl-muted">
        The URL may be mistyped, or the resource was removed.
      </p>
      <Link
        href="/"
        className="mt-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-hcl-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50"
      >
        Back to dashboard
      </Link>
    </div>
  );
}
