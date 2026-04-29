import type { Metadata } from 'next';
import Script from 'next/script';
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';
import { AppShell } from '@/components/layout/AppShell';

/** HCLTech-grade UI: IBM Plex Sans (corporate / tech), Plex Mono for IDs and metrics. */
const plexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
  display: 'swap',
});

const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'SBOM Analyzer',
  description: 'Software Bill of Materials Analysis Dashboard',
};

const themeInitScript = `(function(){try{var t=localStorage.getItem('spectra-theme');if(t==='dark')document.documentElement.classList.add('dark');else document.documentElement.classList.remove('dark');}catch(e){}})();`;

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`} suppressHydrationWarning>
      <body className="bg-background min-h-screen font-sans antialiased text-foreground">
        <Script id="spectra-theme-init" strategy="beforeInteractive">
          {themeInitScript}
        </Script>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
