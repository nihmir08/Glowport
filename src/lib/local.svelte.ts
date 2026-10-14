import { localShells } from './backend';
import { siAlmalinux, siAlpinelinux, siArchlinux, siDebian, siFedora, siGit, siKalilinux, siLinux, siOpensuse, siRockylinux, siUbuntu } from 'simple-icons';
import { t } from './i18n.svelte';
import { settings } from './state.svelte';
import type { LocalShell } from './types';

/**
 * Lokales Terminal: die Shells dieses PCs (PowerShell, Eingabeaufforderung, Git Bash, WSL). Welche es gibt, sieht der
 * Kern beim Start einmal nach; gespeichert wird davon nichts.
 */
export const local = $state({ shells: [] as LocalShell[], loaded: false });

export async function loadShells() {
  try {
    local.shells = await localShells();
  } catch (e) {
    console.error('Shells nicht lesbar', e);
  }
  local.loaded = true;
}

export const shellById = (id: string) => local.shells.find((shell) => shell.id === id);

/** Wie eine Shell heißt. Die Eingabeaufforderung trägt in jeder Sprache ihren eigenen Namen; die anderen sind Eigennamen. */
export const shellName = (shell: LocalShell) => (shell.kind === 'cmd' ? t('local.cmd') : shell.name);

/** Die Shell, die ohne weitere Wahl aufgeht: die eingestellte, sonst die erste gefundene. */
export const defaultShell = (): LocalShell | undefined => shellById(settings.localShell) ?? local.shells[0];

/** Zeichen und Farbe einer Shell. `path` ist ein gefülltes Logo im 24er-Raster, `line` ein Liniensymbol. */
export interface ShellLook {
  color: string;
  path?: string;
  line?: string;
}

const PROMPT = '<path d="M5 7l6 5-6 5"/><path d="M13 17h6"/>';

/** WSL-Distributionen bekommen ihr eigenes Logo; der Name kommt von Windows („Ubuntu-24.04“, „kali-linux“). */
const DISTROS: [RegExp, ShellLook][] = [
  [/ubuntu/i, { color: '#E9622E', path: siUbuntu.path }],
  [/debian/i, { color: '#D6336C', path: siDebian.path }],
  [/kali/i, { color: '#6F9AB8', path: siKalilinux.path }],
  [/suse/i, { color: '#73BA25', path: siOpensuse.path }],
  [/alpine/i, { color: '#3B8FD9', path: siAlpinelinux.path }],
  [/arch/i, { color: '#1793D1', path: siArchlinux.path }],
  [/fedora/i, { color: '#51A2DA', path: siFedora.path }],
  [/alma/i, { color: '#4F8FE6', path: siAlmalinux.path }],
  [/rocky/i, { color: '#10B981', path: siRockylinux.path }],
];

export function shellLook(shell: Pick<LocalShell, 'kind' | 'detail'> | undefined): ShellLook {
  switch (shell?.kind) {
    case 'pwsh':
      return { color: '#7C8CFF', line: PROMPT };
    case 'powershell':
      return { color: '#3A96F0', line: PROMPT };
    case 'gitbash':
      return { color: '#F0623E', path: siGit.path };
    case 'wsl':
      return DISTROS.find(([name]) => name.test(shell.detail))?.[1] ?? { color: '#8B90A8', path: siLinux.path };
    default:
      return { color: '#9AA0B4', line: '<path d="M4 6l5 6-5 6"/><path d="M11 18h9"/>' };
  }
}
