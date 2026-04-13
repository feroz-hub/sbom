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
        sans: ['var(--font-sans)', 'Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        'card-hover': 'var(--shadow-card-hover)',
        topbar: 'var(--shadow-topbar)',
      },
    },
  },
  plugins: [],
};

export default config;
