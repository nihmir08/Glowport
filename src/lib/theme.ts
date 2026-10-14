import type { Mode } from './state.svelte';

/** Luminance according to WCAG, 0 (black) to 1 (white). */
function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const f = (v: number) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f((n >> 16) & 255) + 0.7152 * f((n >> 8) & 255) + 0.0722 * f(n & 255);
}

export const isHexColor = (s: unknown): s is string => typeof s === 'string' && /^#[0-9a-f]{6}$/i.test(s);

export function applyTheme(mode: Mode, accent: string, systemDark: boolean) {
  const root = document.documentElement;
  root.dataset.mode = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;
  root.style.setProperty('--accent', accent);
  // Text on the accent area: dark on light colors, white on dark ones.
  root.style.setProperty('--accent-ink', luminance(accent) > 0.4 ? '#17120a' : '#ffffff');
}
