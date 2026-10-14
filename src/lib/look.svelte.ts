import type { ITheme } from '@xterm/xterm';
import { hostById, schemeOf } from './data.svelte';
import { t } from './i18n.svelte';
import { AUTO, SCHEMES, withAlpha, type Scheme } from './schemes';
import { settings } from './state.svelte';
import type { Target } from './types';

/** Aussehen des Terminals: welches Farbschema gilt, welche Schrift, und wie beides an xterm.js geht. */

/**
 * `dark`: ob die Oberfläche gerade dunkel ist; wird beim Anwenden des Farbmodus gesetzt (App.svelte).
 * `background`: Adresse des Hintergrundbilds zum Anzeigen, sonst null. In den Einstellungen steht nur, welches Bild es ist.
 */
export const look = $state({ dark: true, background: null as string | null });

/** Die mitgelieferten Schemata heißen „… Dunkel“ und „… Hell“; der Zusatz folgt der Sprache der Oberfläche. */
const builtIn = (): Scheme[] => SCHEMES.map((s) => ({ ...s, name: s.name.replace(/ (Dunkel|Hell)$/, (_, kind) => ` ${t(kind === 'Dunkel' ? 'scheme.dark' : 'scheme.light')}`) }));

export const allSchemes = (): Scheme[] => [...builtIn(), ...settings.customSchemes];

/** Das Schema zu einer Kennung. Unbekanntes und „automatisch“ folgen dem Farbmodus. */
export function schemeById(id: string | undefined): Scheme {
  const found = id && id !== AUTO ? allSchemes().find((s) => s.id === id) : undefined;
  return found ?? SCHEMES[look.dark ? 0 : 1];
}

/** Das Schema für ein Ziel: Host vor Gruppe vor Einstellungen. */
export function schemeFor(target: Target): Scheme {
  const host = target.kind === 'host' ? hostById(target.id) : undefined;
  return schemeById((host && schemeOf(host)) || settings.termScheme);
}

export const schemeName = (id: string) => (id === AUTO ? null : (allSchemes().find((s) => s.id === id)?.name ?? null));

/**
 * Farben für xterm.js. Der Hintergrund selbst ist durchsichtig: Ihn malt der Bereich hinter dem Terminal,
 * damit Deckkraft und Hintergrundbild an einer Stelle entstehen. Die Farbe bleibt für umgekehrt dargestellten Text erhalten.
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

/** Hintergrund eines Terminal-Bereichs: die Farbe des Schemas mit der eingestellten Deckkraft. */
export const paneBackground = (scheme: Scheme) => withAlpha(scheme.background, settings.termOpacity / 100);

/** Schriften, die Glowport zur Auswahl anbietet, soweit sie auf dem Rechner installiert sind. Die erste liegt bei. */
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

/** Ist eine Schrift installiert? Verglichen wird die Breite eines Textes mit der in zwei Ersatzschriften. */
export function fontInstalled(name: string): boolean {
  const context = document.createElement('canvas').getContext('2d');
  if (!context) return false;
  const width = (family: string) => ((context.font = `32px ${family}`), context.measureText('mmmmMMMMWWWWiiii0000@@@@').width);
  return ['monospace', 'serif'].some((fallback) => width(`'${name}', ${fallback}`) !== width(fallback));
}
