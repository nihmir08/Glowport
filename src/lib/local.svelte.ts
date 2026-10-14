import { localShells } from './backend';
import { siAlmalinux, siAlpinelinux, siArchlinux, siDebian, siFedora, siGit, siKalilinux, siLinux, siOpensuse, siRockylinux, siUbuntu } from 'simple-icons';
import { t } from './i18n.svelte';
import { settings } from './state.svelte';
import type { LocalShell } from './types';

/**
 * Local terminal: this PC's shells (PowerShell, Command Prompt, Git Bash, WSL). Which ones exist the
 * core checks once on start; none of it is saved.
 */
export const local = $state({ shells: [] as LocalShell[], loaded: false });

export async function loadShells() {
  try {
    local.shells = await localShells();
  } catch (e) {
    console.error('Shells not readable', e);
  }
  local.loaded = true;
}

export const shellById = (id: string) => local.shells.find((shell) => shell.id === id);

/** What a shell is called. Command Prompt carries its own name in every language; the others are proper names. */
export const shellName = (shell: LocalShell) => (shell.kind === 'cmd' ? t('local.cmd') : shell.name);

/** The shell that opens without further choice: the configured one, otherwise the first one found. */
export const defaultShell = (): LocalShell | undefined => shellById(settings.localShell) ?? local.shells[0];

/** A shell's symbol and color. `path` is a filled logo on a 24 grid, `line` a line icon. */
export interface ShellLook {
  color: string;
  path?: string;
  line?: string;
}

const PROMPT = '<path d="M5 7l6 5-6 5"/><path d="M13 17h6"/>';

/** WSL distributions get their own logo; the name comes from Windows (“Ubuntu-24.04”, “kali-linux”). */
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
