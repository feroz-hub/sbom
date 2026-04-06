import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // ── HCLTech Brand Palette ──────────────────────────
        primary: {
          DEFAULT: '#0067B1',
          50:  '#E6F2FA',
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
        hcl: {
          navy:   '#1A2B4A',  // sidebar
          blue:   '#0067B1',  // primary actions
          cyan:   '#00B2E2',  // secondary accent
          dark:   '#003087',  // hover / pressed
          light:  '#E6F2FA',  // highlight bg
          border: '#C8DCED',  // card / input borders
          muted:  '#5B7083',  // muted text
        },
        sidebar:    '#1A2B4A',
        background: '#F0F4F8',
        severity: {
          critical: '#C0392B',
          high:     '#D4680A',
          medium:   '#B8860B',
          low:      '#0067B1',
          unknown:  '#6B7A8D',
        },
      },
      fontFamily: {
        sans: ['Rubik', 'Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        card:       '0 1px 4px 0 rgba(0,103,177,0.08), 0 1px 2px 0 rgba(26,43,74,0.06)',
        'card-hover':'0 4px 16px 0 rgba(0,103,177,0.14), 0 2px 6px 0 rgba(26,43,74,0.08)',
        topbar:     '0 1px 4px 0 rgba(26,43,74,0.10)',
      },
    },
  },
  plugins: [],
};

export default config;
