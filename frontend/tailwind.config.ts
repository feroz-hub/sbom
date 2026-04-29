import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
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
        // Brand scale (charts, emphasis) — numeric steps stay fixed
        primary: {
          DEFAULT: '#0067B1',
          50: '#E6F2FA',
          100: '#CCE4F4',
          200: '#99C9E9',
          300: '#66AEDE',
          400: '#3393D3',
          500: '#0067B1',
          600: '#00528E',
          700: '#003E6A',
          800: '#002947',
          900: '#001523',
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
        },
        sidebar: 'var(--color-sidebar)',
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
