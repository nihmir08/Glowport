// The terminal's color schemes: the bundled ones and importing foreign ones (Windows Terminal, iTerm2).

/** `ansi` are the 16 base colors in the usual order: black, red, green, yellow, blue, magenta, cyan, white, then the same bright. */
export interface Scheme {
  id: string;
  name: string;
  dark: boolean;
  background: string;
  foreground: string;
  /** Missing = Glowport's accent color. */
  cursor?: string;
  selection?: string;
  ansi: string[];
}

/** Follows the color mode: “Glowport Dark” or “Glowport Light”. */
export const AUTO = 'auto';

const scheme = (id: string, name: string, dark: boolean, background: string, foreground: string, ansi: string, extra: Partial<Scheme> = {}): Scheme => ({
  id,
  name,
  dark,
  background,
  foreground,
  ansi: ansi.split(' ').map((c) => `#${c}`),
  ...extra,
});

export const SCHEMES: Scheme[] = [
  scheme('glowport-dark', 'Glowport Dunkel', true, '#0a0a12', '#e6e6f0', '1a1a26 ff5d7c a6e357 ffb544 5cc8ff c58bff 3fe0e8 d5d5e2 6d6d84 ff5d7c a6e357 ffb544 5cc8ff c58bff 3fe0e8 ffffff', { selection: '#ffffff33' }),
  scheme('glowport-light', 'Glowport Hell', false, '#fbfaf8', '#1d1b26', '17151d d81e4d 3d8b00 b56a00 0b6fd6 7a3fd1 008b96 d9d6e2 77748a d81e4d 3d8b00 b56a00 0b6fd6 7a3fd1 008b96 8a8799', { selection: '#00000026' }),
  scheme('dracula', 'Dracula', true, '#282a36', '#f8f8f2', '21222c ff5555 50fa7b f1fa8c bd93f9 ff79c6 8be9fd f8f8f2 6272a4 ff6e6e 69ff94 ffffa5 d6acff ff92df a4ffff ffffff', { cursor: '#f8f8f2', selection: '#44475a' }),
  scheme('nord', 'Nord', true, '#2e3440', '#d8dee9', '3b4252 bf616a a3be8c ebcb8b 81a1c1 b48ead 88c0d0 e5e9f0 4c566a bf616a a3be8c ebcb8b 81a1c1 b48ead 8fbcbb eceff4', { cursor: '#d8dee9', selection: '#434c5e' }),
  scheme('tokyo-night', 'Tokyo Night', true, '#1a1b26', '#c0caf5', '15161e f7768e 9ece6a e0af68 7aa2f7 bb9af7 7dcfff a9b1d6 414868 f7768e 9ece6a e0af68 7aa2f7 bb9af7 7dcfff c0caf5', { cursor: '#c0caf5', selection: '#283457' }),
  scheme('catppuccin-mocha', 'Catppuccin Mocha', true, '#1e1e2e', '#cdd6f4', '45475a f38ba8 a6e3a1 f9e2af 89b4fa f5c2e7 94e2d5 bac2de 585b70 f38ba8 a6e3a1 f9e2af 89b4fa f5c2e7 94e2d5 a6adc8', { cursor: '#f5e0dc', selection: '#585b70' }),
  scheme('one-dark', 'One Dark', true, '#282c34', '#abb2bf', '282c34 e06c75 98c379 e5c07b 61afef c678dd 56b6c2 abb2bf 5c6370 e06c75 98c379 e5c07b 61afef c678dd 56b6c2 ffffff', { cursor: '#528bff', selection: '#3e4451' }),
  scheme('gruvbox-dark', 'Gruvbox Dunkel', true, '#282828', '#ebdbb2', '282828 cc241d 98971a d79921 458588 b16286 689d6a a89984 928374 fb4934 b8bb26 fabd2f 83a598 d3869b 8ec07c ebdbb2', { cursor: '#ebdbb2', selection: '#504945' }),
  scheme('monokai', 'Monokai', true, '#272822', '#f8f8f2', '272822 f92672 a6e22e f4bf75 66d9ef ae81ff a1efe4 f8f8f2 75715e f92672 a6e22e f4bf75 66d9ef ae81ff a1efe4 f9f8f5', { cursor: '#f8f8f0', selection: '#49483e' }),
  scheme('solarized-dark', 'Solarized Dunkel', true, '#002b36', '#839496', '073642 dc322f 859900 b58900 268bd2 d33682 2aa198 eee8d5 586e75 cb4b16 586e75 657b83 839496 6c71c4 93a1a1 fdf6e3', { cursor: '#93a1a1', selection: '#073642' }),
  scheme('github-dark', 'GitHub Dunkel', true, '#0d1117', '#c9d1d9', '484f58 ff7b72 3fb950 d29922 58a6ff bc8cff 39c5cf b1bac4 6e7681 ffa198 56d364 e3b341 79c0ff d2a8ff 56d4dd f0f6fc', { cursor: '#58a6ff', selection: '#264f78' }),
  scheme('campbell', 'Campbell (Windows Terminal)', true, '#0c0c0c', '#cccccc', '0c0c0c c50f1f 13a10e c19c00 0037da 881798 3a96dd cccccc 767676 e74856 16c60c f9f1a5 3b78ff b4009e 61d6d6 f2f2f2', { cursor: '#ffffff', selection: '#ffffff40' }),
  scheme('solarized-light', 'Solarized Hell', false, '#fdf6e3', '#657b83', '073642 dc322f 859900 b58900 268bd2 d33682 2aa198 eee8d5 586e75 cb4b16 586e75 657b83 839496 6c71c4 93a1a1 fdf6e3', { cursor: '#586e75', selection: '#eee8d5' }),
  scheme('catppuccin-latte', 'Catppuccin Latte', false, '#eff1f5', '#4c4f69', '5c5f77 d20f39 40a02b df8e1d 1e66f5 ea76cb 179299 acb0be 6c6f85 d20f39 40a02b df8e1d 1e66f5 ea76cb 179299 bcc0cc', { cursor: '#dc8a78', selection: '#ccd0da' }),
  scheme('github-light', 'GitHub Hell', false, '#ffffff', '#24292f', '24292f cf222e 116329 4d2d00 0969da 8250df 1b7c83 6e7781 57606a a40e26 1a7f37 633c01 218bff a475f9 3192aa 8c959f', { cursor: '#0969da', selection: '#0969da33' }),
];

const HEX = /^#[0-9a-f]{6}([0-9a-f]{2})?$/i;
const ANSI_NAMES = ['black', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white', 'brightBlack', 'brightRed', 'brightGreen', 'brightYellow', 'brightBlue', 'brightPurple', 'brightCyan', 'brightWhite'];

/** Brightness of a color, 0 to 1. Decides whether an imported scheme counts as dark. */
function brightness(hex: string): number {
  const n = parseInt(hex.slice(1, 7), 16);
  return (0.299 * ((n >> 16) & 255) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
}

const slug = (name: string) =>
  `custom-${name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')}`;

/** Checks whether a value from the settings is a complete scheme. */
export function isScheme(value: unknown): value is Scheme {
  const s = value as Partial<Scheme> | null;
  return (
    !!s &&
    typeof s.id === 'string' &&
    typeof s.name === 'string' &&
    typeof s.dark === 'boolean' &&
    HEX.test(s.background ?? '') &&
    HEX.test(s.foreground ?? '') &&
    Array.isArray(s.ansi) &&
    s.ansi.length === 16 &&
    s.ansi.every((c) => HEX.test(c)) &&
    (s.cursor === undefined || HEX.test(s.cursor)) &&
    (s.selection === undefined || HEX.test(s.selection))
  );
}

/** A scheme in Windows Terminal format: an object with `name`, `background`, `black` … `brightWhite`. */
function fromWindowsTerminal(entry: Record<string, unknown>): Scheme | null {
  const color = (key: string) => (typeof entry[key] === 'string' && HEX.test(entry[key] as string) ? (entry[key] as string) : null);
  const ansi = ANSI_NAMES.map(color);
  const background = color('background');
  const foreground = color('foreground');
  if (typeof entry.name !== 'string' || !entry.name.trim() || !background || !foreground || ansi.some((c) => !c)) return null;
  const name = entry.name.trim();
  return { id: slug(name), name, dark: brightness(background) < 0.5, background, foreground, ansi: ansi as string[], cursor: color('cursorColor') ?? undefined, selection: color('selectionBackground') ?? undefined };
}

/** A scheme in iTerm2 format (`.itermcolors`): a property list with entries like “Ansi 0 Color”. */
function fromIterm(text: string, name: string): Scheme | null {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const root = doc.querySelector('plist > dict');
  if (!root || doc.querySelector('parsererror')) return null;
  const colors = new Map<string, string>();
  const entries = [...root.children];
  for (let i = 0; i + 1 < entries.length; i += 2) {
    if (entries[i].tagName !== 'key' || entries[i + 1].tagName !== 'dict') continue;
    const parts = [...entries[i + 1].children];
    const component = (label: string) => {
      const at = parts.findIndex((p) => p.tagName === 'key' && p.textContent === `${label} Component`);
      const value = at >= 0 ? Number(parts[at + 1]?.textContent) : NaN;
      return Number.isFinite(value) ? Math.round(Math.min(1, Math.max(0, value)) * 255) : null;
    };
    const rgb = [component('Red'), component('Green'), component('Blue')];
    if (rgb.every((c) => c !== null)) colors.set(entries[i].textContent ?? '', `#${rgb.map((c) => c!.toString(16).padStart(2, '0')).join('')}`);
  }
  const ansi = ANSI_NAMES.map((_, i) => colors.get(`Ansi ${i} Color`));
  const background = colors.get('Background Color');
  const foreground = colors.get('Foreground Color');
  if (!background || !foreground || ansi.some((c) => !c)) return null;
  return { id: slug(name), name, dark: brightness(background) < 0.5, background, foreground, ansi: ansi as string[], cursor: colors.get('Cursor Color'), selection: colors.get('Selection Color') };
}

/**
 * Reads schemes from a file's content: a single Windows Terminal scheme, its whole `settings.json`
 * (list `schemes`) or an `.itermcolors` file. Empty list if nothing usable is in it.
 */
export function parseSchemes(text: string, fileName: string): Scheme[] {
  const trimmed = text.trim();
  if (trimmed.startsWith('<')) {
    const found = fromIterm(trimmed, fileName.replace(/\.[^.]+$/, '') || 'iTerm');
    return found ? [found] : [];
  }
  try {
    // Windows Terminal's settings file may contain comments.
    const data: unknown = JSON.parse(trimmed.replace(/^\s*\/\/.*$/gm, ''));
    const list = Array.isArray(data) ? data : Array.isArray((data as { schemes?: unknown })?.schemes) ? (data as { schemes: unknown[] }).schemes : [data];
    return list.map((entry) => (entry && typeof entry === 'object' ? fromWindowsTerminal(entry as Record<string, unknown>) : null)).filter((s): s is Scheme => !!s);
  } catch {
    return [];
  }
}

/** Mixes the opacity into a color: `#rrggbb` becomes `#rrggbbaa`. */
export const withAlpha = (hex: string, alpha: number) => `${hex.slice(0, 7)}${Math.round(Math.min(1, Math.max(0, alpha)) * 255).toString(16).padStart(2, '0')}`;
