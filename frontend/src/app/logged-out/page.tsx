export default function LoggedOutPage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-md space-y-6 rounded-2xl border border-border bg-surface p-8 text-center shadow-elev-3">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-hcl-blue text-sm font-bold text-white" aria-hidden="true">
          HCL
        </div>
        <div className="space-y-2">
          <h1 className="text-xl font-bold text-foreground">Signed out successfully</h1>
          <p className="text-sm text-hcl-muted">Your SBOM Analyzer session has ended.</p>
        </div>
        <a
          href="/api/auth/login?returnTo=%2F"
          className="inline-flex w-full items-center justify-center rounded-lg bg-hcl-blue px-4 py-2.5 text-sm font-semibold text-white shadow-elev-1 transition-colors hover:bg-hcl-blue/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue focus-visible:ring-offset-2"
        >
          Sign in again
        </a>
        <a className="block underline" href="/native-sign-in">Native sign in</a>
      </div>
    </main>
  );
}
