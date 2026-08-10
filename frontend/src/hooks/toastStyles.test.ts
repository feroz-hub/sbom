import postcss from 'postcss';
import tailwindcss from 'tailwindcss';
import { describe, expect, it } from 'vitest';
import tailwindConfig from '../../tailwind.config';

describe('toast production styles', () => {
  it('scans hook components and emits the viewport positioning utilities', async () => {
    expect(tailwindConfig.content).toContain('./src/**/*.{js,ts,jsx,tsx,mdx}');

    const result = await postcss([
      tailwindcss(tailwindConfig),
    ]).process('@tailwind utilities;', { from: undefined });

    expect(result.css).toContain('.fixed');
    expect(result.css).toContain('.top-4');
    expect(result.css).toContain('.right-4');
    expect(result.css).toContain('.z-\\[9999\\]');
  }, 15_000);
});
