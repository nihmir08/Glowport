import { has, t, type Key } from './i18n.svelte';
import type { Authority, BackendError, FieldKey, Fields, Forward, Group, Host, Identity, KnownHost, Protocol, ProxmoxConnection, SerialSettings, Snapshot, Snippet, SshKey, Status, VaultInfo, VaultState, Workspace, FtpSettings } from './types';

/** State of the vault and, while it is open, its entries. On locking everything is discarded. */
export const vault = $state({
  state: 'loading' as VaultState | 'loading',
  groups: [] as Group[],
  hosts: [] as Host[],
  knownHosts: [] as KnownHost[],
  keys: [] as SshKey[],
  identities: [] as Identity[],
  authorities: [] as Authority[],
  workspaces: [] as Workspace[],
  forwards: [] as Forward[],
  snippets: [] as Snippet[],
  /** All vaults of this device, the personal one first. Without syncing there is only that one. */
  vaults: [] as VaultInfo[],
  proxmox: [] as ProxmoxConnection[],
  damaged: 0,
  error: null as BackendError | null,
  /** Does the vault open on start without a master password? The truth about that lives in the core, not in the settings. */
  startUnlock: false,
});

/** Number of the state shown. */
let shown = 0;

export function applySnapshot(data: Snapshot) {
  // Answers to commands and events overtake each other: a state older than the one shown is ignored.
  // Otherwise the answer to signing in, for example, would empty the list the first sync just filled.
  if (data.seq !== undefined) {
    if (data.seq < shown) return;
    shown = data.seq;
  }
  // The core does not name the vault on every entry but in a list next to them.
  const homes = data.homes ?? {};
  for (const list of [data.groups, data.hosts, data.keys ?? [], data.identities ?? [], data.forwards ?? [], data.snippets ?? []]) {
    for (const entry of list) entry.vault ??= homes[entry.id];
  }
  vault.groups = data.groups;
  vault.hosts = data.hosts;
  vault.damaged = data.damaged;
  vault.knownHosts = data.knownHosts ?? [];
  vault.keys = data.keys ?? [];
  vault.identities = data.identities ?? [];
  vault.authorities = data.authorities ?? [];
  vault.workspaces = data.workspaces ?? [];
  vault.forwards = data.forwards ?? [];
  vault.snippets = data.snippets ?? [];
  vault.vaults = data.vaults ?? [];
  vault.proxmox = data.proxmox ?? [];
}

export function applyStatus(status: Status) {
  vault.state = status.state;
  vault.error = status.error ?? null;
  vault.startUnlock = status.startUnlock ?? false;
  applySnapshot(status.data ?? { groups: [], hosts: [], damaged: 0, knownHosts: [], keys: [], identities: [], authorities: [], workspaces: [], forwards: [], snippets: [] });
}

/** Message for the user from a core error. Unknown ones are not swallowed but shown. */
export function errorText(error: unknown): string {
  const e = error as Partial<BackendError> | null;
  const key = e?.code === 'invalid' ? `err.invalid.${e.reason}` : `err.${e?.code}`;
  if (e?.code && has(key)) return t(key as Key, { message: e.message ?? '' });
  return t('err.internal', { message: e?.message ?? String(error) });
}

export const personalVault = () => vault.vaults.find((v) => v.kind === 'personal');
export const sharedVaults = () => vault.vaults.filter((v) => v.kind === 'shared');
/** An entry's vault. Without one it lives in the personal vault. */
export const vaultOf = (entry: { vault?: string }) => vault.vaults.find((v) => v.id === entry.vault) ?? personalVault();
/** May this entry be changed? Not in a shared vault with read access. */
export const canEdit = (entry: { vault?: string }) => vaultOf(entry)?.role !== 'read';

/**
 * May an entry in vault `home` refer to `entry`? The personal vault (`home` empty) may refer to anything,
 * a shared one only to entries within itself: otherwise the other members would not have them.
 */
export const reachable = (home: string | undefined, entry: { vault?: string }) => !home || home === personalVault()?.id || entry.vault === home;
/** Are two entries in the same vault? For groups: an entry is always in its group's vault. */
export const sameVault = (home: string | undefined, entry: { vault?: string }) => (entry.vault ?? personalVault()?.id) === (home ?? personalVault()?.id);

export const groupById = (id: string | null) => (id ? vault.groups.find((g) => g.id === id) : undefined);
export const hostById = (id: string | null) => (id ? vault.hosts.find((h) => h.id === id) : undefined);
export const keyById = (id: string | null | undefined) => (id ? vault.keys.find((k) => k.id === id) : undefined);
export const identityById = (id: string | null | undefined) => (id ? vault.identities.find((i) => i.id === id) : undefined);
export const forwardById = (id: string | null | undefined) => (id ? vault.forwards.find((f) => f.id === id) : undefined);
export const snippetById = (id: string | null | undefined) => (id ? vault.snippets.find((s) => s.id === id) : undefined);
export const forwardsOf = (host: string) => vault.forwards.filter((f) => f.host === host);
export const childGroups = (parent: string | null) => vault.groups.filter((g) => g.parent === parent);
export const hostsIn = (group: string | null) => vault.hosts.filter((h) => h.group === group);

/** Groups from the root to `id`. Stops at a cycle in damaged data. */
export function groupPath(id: string | null): Group[] {
  const path: Group[] = [];
  for (let g = groupById(id); g && !path.includes(g); g = groupById(g.parent)) path.unshift(g);
  return path;
}

export const pathLabel = (id: string | null) =>
  groupPath(id)
    .map((g) => g.name)
    .join(' › ');

/** All groups below `id`, including `id` itself. */
export function descendants(id: string): string[] {
  const found = [id];
  for (let i = 0; i < found.length; i++) for (const g of vault.groups) if (g.parent === found[i] && !found.includes(g.id)) found.push(g.id);
  return found;
}

export const hostCount = (group: string): number => {
  const inside = descendants(group);
  return vault.hosts.filter((h) => h.group && inside.includes(h.group)).length;
};

export interface Inherited<T> {
  value: T;
  /** Group that sets the value. */
  source: Group;
}

/** Defaults along the group path: deeper groups override higher ones. */
export function inherited(group: string | null): { [K in FieldKey]?: Inherited<NonNullable<Fields[K]>> } {
  const out: Record<string, Inherited<unknown>> = {};
  for (const g of groupPath(group)) for (const [k, v] of Object.entries(g.defs)) if (v !== undefined) out[k] = { value: v, source: g };
  return out as ReturnType<typeof inherited>;
}

/** Does this host's terminal run over Mosh? Its own switch, otherwise that of the nearest group. Only for SSH. */
export const usesMosh = (host: Host): boolean => protocolOf(host) === 'ssh' && (host.own.mosh ?? inherited(host.group).mosh?.value ?? false);

/** UDP port or range for `mosh-server`: `60001` or `60001:60010`. */
export const MOSH_PORT = /^\d{1,5}(:\d{1,5})?$/;

export const DEFAULT_USER = 'root';
export const DEFAULT_PORT = 22;

/** A host's color: its own, otherwise that of the nearest group with a color. */
export function colorOf(host: Host): string | null {
  if (host.color) return host.color;
  return (
    groupPath(host.group)
      .reverse()
      .find((g) => g.color)?.color ?? null
  );
}

export const groupColor = (group: Group): string | null =>
  groupPath(group.id)
    .reverse()
    .find((g) => g.color)?.color ?? null;

/** An effective sign-in value and where it comes from. `group` null = entered on the host itself. */
export interface From<T> {
  value: T;
  group: Group | null;
  /** Set if the value is not entered individually but comes from this identity. */
  identity?: Identity;
}

export interface Auth {
  identity?: From<Identity>;
  user?: From<string>;
  key?: From<SshKey>;
  keyFile?: From<string>;
  /** Does the identity bring a password? A host's own password comes first. */
  identityPassword: boolean;
}

/**
 * Sign-in for a host with its own values `own` in the group `group`.
 * What is closer to the host wins. On the same level the individually entered field wins over the identity.
 * Counterpart in the core: crates/core/src/directory.rs.
 */
export function authFor(group: string | null, own: Fields = {}): Auth {
  const levels: { fields: Fields; group: Group | null }[] = [...groupPath(group).map((g) => ({ fields: g.defs, group: g })), { fields: own, group: null }];
  /** Deepest level at which `read` finds something, or -1. */
  function deepest(read: (f: Fields) => unknown): number {
    for (let i = levels.length - 1; i >= 0; i--) if (read(levels[i].fields) !== undefined) return i;
    return -1;
  }
  // The deepest level that sets an identity (also “none”) determines it.
  const at = deepest((f) => f.identity);
  const chosen = at >= 0 ? identityById(levels[at].fields.identity) : undefined;
  const identity = chosen && { value: chosen, group: levels[at].group };
  // An individually entered value only counts if it is not above the identity.
  function pick<T>(read: (f: Fields) => T | undefined): From<T> | undefined {
    const i = deepest(read);
    return i >= 0 && (!chosen || i >= at) ? { value: read(levels[i].fields)!, group: levels[i].group } : undefined;
  }
  const ownKey = pick((f) => (f.key === undefined ? undefined : (keyById(f.key) ?? null)));
  const identityKey = chosen && keyById(chosen.key);
  return {
    identity,
    user: pick((f) => f.user) ?? (chosen && { value: chosen.user, group: levels[at].group, identity: chosen }),
    key: ownKey ? (ownKey.value ? (ownKey as From<SshKey>) : undefined) : identityKey ? { value: identityKey, group: levels[at].group, identity: chosen } : undefined,
    keyFile: pick((f) => f.keyFile),
    identityPassword: !!chosen?.hasPassword,
  };
}

/** Hosts that sign in with this key, directly or through group and identity. */
export const hostsUsingKey = (key: string) => vault.hosts.filter((h) => authFor(h.group, h.own).key?.value.id === key);
export const hostsUsingIdentity = (identity: string) => vault.hosts.filter((h) => authFor(h.group, h.own).identity?.value.id === identity);

export function userOf(host: Host): string {
  return authFor(host.group, host.own).user?.value ?? DEFAULT_USER;
}

export const DEFAULT_TELNET_PORT = 23;
export const DEFAULT_SERIAL: SerialSettings = { baud: 9600, dataBits: 8, parity: 'none', stopBits: 1, flow: 'none' };

/** A host's protocol. Unknown ones from a newer version count as SSH. */
export const protocolOf = (host: Host): Protocol => (host.protocol === 'telnet' || host.protocol === 'serial' || host.protocol === 'ftp' ? host.protocol : 'ssh');
export const isSsh = (host: Host) => protocolOf(host) === 'ssh';
/** Hosts reached over SSH: only they serve as jump hosts, for port rules, files and running snippets. */
export const sshHosts = () => vault.hosts.filter(isSsh);

export const DEFAULT_FTP_PORT = 21;
/** Implicit FTPS has its own port. */
export const DEFAULT_FTPS_PORT = 990;
export const DEFAULT_FTP: FtpSettings = { security: 'explicit', anonymous: false };
export const isFtp = (host: Host | undefined) => !!host && protocolOf(host) === 'ftp';
export const ftpOf = (host: Host): FtpSettings => host.ftp ?? DEFAULT_FTP;
/** Does this FTP host run unencrypted? Then password and files are readable on the way. */
export const ftpOpen = (host: Host | undefined) => isFtp(host) && ftpOf(host!).security === 'none';
export const ftpPort = (settings: FtpSettings) => (settings.security === 'implicit' ? DEFAULT_FTPS_PORT : DEFAULT_FTP_PORT);
/** Hosts with files: over SFTP (SSH) or FTP. */
export const fileHosts = () => vault.hosts.filter((host) => isSsh(host) || isFtp(host));

/** A serial line's short form: “9600 8N1”. */
export const serialLabel = (s: SerialSettings) => `${s.baud} ${s.dataBits}${s.parity === 'none' ? 'N' : s.parity === 'odd' ? 'O' : 'E'}${s.stopBits}`;

/** A host's port. It is only inherited for SSH; a group's default means the SSH port. */
export function portOf(host: Host): number {
  if (protocolOf(host) === 'telnet') return host.own.port ?? DEFAULT_TELNET_PORT;
  if (protocolOf(host) === 'ftp') return host.own.port ?? ftpPort(ftpOf(host));
  return host.own.port ?? inherited(host.group).port?.value ?? DEFAULT_PORT;
}

/** ID of the color scheme set for a host: on the host itself, otherwise on the nearest group. */
export function schemeOf(host: Host): string | undefined {
  return host.own.scheme ?? inherited(host.group).scheme?.value;
}

/** Effective jump host or undefined. */
export function jumpOf(host: Host): Host | undefined {
  const id = host.own.jump ?? inherited(host.group).jump?.value;
  return id ? hostById(id) : undefined;
}

/** Where a host leads, for display: `user@address`, for Telnet the address, for a serial line port and settings. */
export function addressOf(host: Host): string {
  const port = portOf(host);
  switch (protocolOf(host)) {
    case 'serial':
      return `${host.address} · ${serialLabel(host.serial ?? DEFAULT_SERIAL)}`;
    case 'telnet':
      return `${host.own.user ? `${host.own.user}@` : ''}${host.address}${port === DEFAULT_TELNET_PORT ? '' : `:${port}`}`;
    case 'ftp': {
      const ftp = ftpOf(host);
      return `${ftp.anonymous ? 'anonymous' : (host.own.user ?? '')}${ftp.anonymous || host.own.user ? '@' : ''}${host.address}${port === ftpPort(ftp) ? '' : `:${port}`}`;
    }
    default:
      return `${userOf(host)}@${host.address}${port === DEFAULT_PORT ? '' : `:${port}`}`;
  }
}
