import type { ITheme } from '@xterm/xterm';
import { hostById, schemeOf } from './data.svelte';
import { t } from './i18n.svelte';
import { AUTO, SCHEMES, withAlpha, type Scheme } from './schemes';
import { settings } from './state.svelte';
import type { Target } from './types';

/** The terminal's look: which color scheme applies, which font, and how both get to xterm.js. */

/**
 * `dark`: whether the interface is currently dark; set when the color mode is applied (App.svelte).
 * `background`: address of the background image for display, otherwise null. The settings only say which image it is.
 */
export const look = $state({ dark: true, background: null as string | null });

/** The bundled schemes are stored as “… Dunkel” and “… Hell”; the suffix shown follows the interface language. */
const builtIn = (): Scheme[] => SCHEMES.map((s) => ({ ...s, name: s.name.replace(/ (Dunkel|Hell)$/, (_, kind) => ` ${t(kind === 'Dunkel' ? 'scheme.dark' : 'scheme.light')}`) }));

export const allSchemes = (): Scheme[] => [...builtIn(), ...settings.customSchemes];

/** The scheme for an ID. Unknown ones and “automatic” follow the color mode. */
export function schemeById(id: string | undefined): Scheme {
  const found = id && id !== AUTO ? allSchemes().find((s) => s.id === id) : undefined;
  return found ?? SCHEMES[look.dark ? 0 : 1];
}

/** The scheme for a destination: host before group before settings. */
export function schemeFor(target: Target): Scheme {
  const host = target.kind === 'host' ? hostById(target.id) : undefined;
  return schemeById((host && schemeOf(host)) || settings.termScheme);
}

export const schemeName = (id: string) => (id === AUTO ? null : (allSchemes().find((s) => s.id === id)?.name ?? null));

/**
 * Colors for xterm.js. The background itself is transparent: the pane behind the terminal paints it,
 * so opacity and background image come about in one place. The color is kept for inversely displayed text.
 */
export function xtermTheme(scheme: Scheme): ITheme {
  const [black, red, green, yellow, blue, magenta, cyan, white, brightBlack, brightRed, brightGreen, brightYellow, brightBlue, brightMagenta, brightCyan, brightWhite] = scheme.ansi;
  return {
    background: withAlpha(scheme.background, 0),
    foreground: scheme.foreground,
    cursor: scheme.cursor ?? settings.accent,
    cursorAccent: scheme.background,
    selectionBackground: scheme.selection ?? (scheme.dark ? '#ffffff33' : '#00000026'),
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    brightBlack,
    brightRed,
    brightGreen,
    brightYellow,
    brightBlue,
    brightMagenta,
    brightCyan,
    brightWhite,
  };
}

/** Background of a terminal pane: the scheme's color with the configured opacity. */
export const paneBackground = (scheme: Scheme) => withAlpha(scheme.background, settings.termOpacity / 100);

/** Fonts Glowport offers for choice, as far as they are installed on the computer. The first is bundled. */
export const FONT_CHOICES = [
  'Cascadia Code',
  'Cascadia Mono',
  'Consolas',
  'Fira Code',
  'JetBrainsMono Nerd Font',
  'CaskaydiaCove Nerd Font',
  'FiraCode Nerd Font',
  'Hack',
  'Source Code Pro',
  'IBM Plex Mono',
  'Ubuntu Mono',
  'Lucida Console',
  'Courier New',
];

const BUNDLED = "'JetBrains Mono Variable', 'Cascadia Code', Consolas, monospace";
export const fontStack = (name = settings.termFont) => (name ? `'${name.replace(/['\\]/g, '')}', ${BUNDLED}` : BUNDLED);

/** Is a font installed? The width of a text is compared with that in two fallback fonts. */
export function fontInstalled(name: string): boolean {
  const context = document.createElement('canvas').getContext('2d');
  if (!context) return false;
  const width = (family: string) => ((context.font = `32px ${family}`), context.measureText('mmmmMMMMWWWWiiii0000@@@@').width);
  return ['monospace', 'serif'].some((fallback) => width(`'${name}', ${fallback}`) !== width(fallback));
}
