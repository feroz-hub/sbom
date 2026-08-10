import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: [
    // UI can live in hooks as well as pages/components (the custom toast
    // viewport is implemented in src/hooks/useToast.tsx).  Restricting the
    // scanner to app/components silently omitted its positioning utilities
    // from production CSS even though the portal existed in document.body.
    './src/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: 'var(--color-background)',
        foreground: 'var(--color-foreground)',
        surface: {
          DEFAULT: 'var(--color-surface)',
          muted: 'var(--color-surface-muted)',
        },
        border: {
          DEFAULT: 'var(--color-border)',
          subtle: 'var(--color-border-subtle)',
        },
        // Brand scale — anchored on enterprise blue #1068E6
        primary: {
          DEFAULT: '#1068E6',
          50: '#EBF3FE',
          100: '#D2E4FC',
          200: '#A5C9F9',
          300: '#78AEF6',
          400: '#4B93F3',
          500: '#1068E6',
          600: '#0056D6',
          700: '#0044AA',
          800: '#00337E',
          900: '#002252',
        },
        // Theme-aware HCL tokens (text, borders, subtle fills)
        hcl: {
          navy: 'var(--color-hcl-navy)',
          muted: 'var(--color-hcl-muted)',
          border: 'var(--color-hcl-border)',
          light: 'var(--color-hcl-light)',
          dark: 'var(--color-hcl-dark)',
          blue: 'var(--color-hcl-blue)',
          cyan: 'var(--color-hcl-cyan)',
          violet: 'var(--color-hcl-violet)',
        },
        link: 'var(--color-link)',
        sidebar: {
          DEFAULT: 'var(--color-sidebar)',
          foreground: 'var(--color-sidebar-foreground)',
          muted: 'var(--color-sidebar-muted)',
          accent: 'var(--color-sidebar-accent)',
          hover: 'var(--color-sidebar-hover-bg)',
        },
        'row-alt': 'var(--row-alt-bg)',
        'row-hover': 'var(--row-hover-bg)',
        severity: {
          critical: '#C0392B',
          high: '#D4680A',
          medium: '#B8860B',
          low: '#0067B1',
          unknown: '#6B7A8D',
        },
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'IBM Plex Sans', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'IBM Plex Mono', 'ui-monospace', 'monospace'],
        display: ['var(--font-sans)', 'IBM Plex Sans', 'system-ui', 'sans-serif'],
      },
      letterSpacing: {
        tight: '-0.025em',
        display: '-0.03em',
      },
      fontSize: {
        'display-sm': ['1.125rem', { lineHeight: '1.4', letterSpacing: '-0.02em' }],
        display: ['1.5rem', { lineHeight: '1.25', letterSpacing: '-0.03em' }],
        'display-lg': ['1.875rem', { lineHeight: '1.2', letterSpacing: '-0.035em' }],
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        'card-hover': 'var(--shadow-card-hover)',
        topbar: 'var(--shadow-topbar)',
        'elev-1': 'var(--elev-1)',
        'elev-2': 'var(--elev-2)',
        'elev-3': 'var(--elev-3)',
        'elev-4': 'var(--elev-4)',
        'glow-primary': 'var(--glow-primary)',
        'glow-cyan': 'var(--glow-cyan)',
        'glow-critical': 'var(--glow-critical)',
        'glow-success': 'var(--glow-success)',
      },
      backdropBlur: {
        glass: 'var(--glass-blur)',
      },
      transitionTimingFunction: {
        spring: 'var(--ease-spring)',
        emphasized: 'var(--ease-emphasized)',
        smooth: 'var(--ease-out)',
      },
      transitionDuration: {
        fast: 'var(--duration-fast)',
        base: 'var(--duration-base)',
        slow: 'var(--duration-slow)',
        slower: 'var(--duration-slower)',
      },
    },
  },
  plugins: [],
};

export default config;
