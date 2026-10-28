import { Check, ShieldCheck, Boxes } from 'lucide-react';
import type { ReactNode } from 'react';

export function NativeAuthLayout({ children }: { children: ReactNode }) {
  return <main className="min-h-screen bg-surface lg:grid lg:grid-cols-[55%_45%]">
    <section className="relative overflow-hidden bg-gradient-to-br from-primary-800 via-primary-900 to-hcl-violet p-8 text-white sm:p-12 lg:flex lg:min-h-screen lg:flex-col lg:justify-between lg:p-16">
      <div aria-hidden="true" className="pointer-events-none absolute -right-32 top-1/3 h-[32rem] w-[32rem] rotate-12 rounded-[5rem] border border-white/10"><div className="absolute inset-12 rounded-[4rem] border border-white/10" /><Boxes className="absolute bottom-20 left-20 h-32 w-32 text-white/10" strokeWidth={0.7} /></div>
      <div className="relative"><span className="text-3xl font-bold tracking-tight">HCLTech</span><p className="mt-3 text-xs font-medium tracking-[0.24em] text-white/80">SBOM ANALYZER</p></div>
      <div className="relative my-6 max-w-xl sm:my-12 lg:my-20"><ShieldCheck className="mb-8 hidden h-10 w-10 text-white/80 lg:block" aria-hidden="true" /><h2 className="text-2xl font-semibold leading-tight tracking-tight sm:text-5xl lg:text-6xl">Secure your<br />software supply chain.</h2><p className="mt-5 text-xl text-white/90">Know what&apos;s inside.</p><p className="mt-6 hidden max-w-md text-sm leading-7 text-white/80 sm:block">Discover components, identify vulnerabilities, track lifecycle risk, and manage software supply-chain security from one secure platform.</p><ul className="mt-8 hidden space-y-4 text-sm lg:block">{['SBOM & component visibility', 'Vulnerability intelligence', 'Lifecycle & compliance monitoring'].map(text => <li key={text} className="flex items-center gap-3"><Check className="h-4 w-4" aria-hidden="true" />{text}</li>)}</ul></div>
      <p className="relative hidden text-xs text-white/70 lg:block">SBOM Analyzer • An HCLTech product</p>
    </section>
    <section className="flex items-center justify-center px-6 py-12 sm:px-12 lg:py-16"><div className="w-full max-w-md">{children}</div></section>
  </main>;
}
