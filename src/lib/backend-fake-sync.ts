// Stand-in for syncing when the interface runs in the browser (development and preview).
// There is no server and no encryption here; the file only shows how the screens behave.
// What counts are crates/sync and docs/sync.md.

import type {
  BackendError,
  SyncAccount,
  SyncCandidate,
  SyncDevice,
  SyncInvitation,
  SyncInviteCode,
  SyncLogin,
  SyncNotice,
  SyncRegister,
  SyncServerInfo,
  SyncState,
  VaultInfo,
  VaultMember,
  VaultRole,
} from './types';

interface Stored {
  server: string;
  username: string;
  admin: boolean;
  syncedAt: number;
  shared: VaultInfo[];
  invitations: SyncInvitation[];
  devices: SyncDevice[];
  notices: SyncNotice[];
  invites: SyncInviteCode[];
  accounts: SyncAccount[];
}

/** What the stand-in vault provides for syncing. */
interface World {
  /** Creates sample hosts in a shared vault. */
  addHosts: (vault: string, hosts: [name: string, address: string, os: string][]) => void;
  /** Removes all entries of a vault. */
  dropVault: (vault: string) => void;
  /** Reports the changed vault to the interface. */
  changed: () => void;
  password: () => string | null;
}

export const PERSONAL = 'persoenlich';
const LS_KEY = 'glowport.fakesync';
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

let stored: Stored | null = JSON.parse(localStorage.getItem(LS_KEY) ?? 'null');
let world: World | null = null;
let emit: (state: SyncState) => void = () => {};
let phase: SyncState['phase'] = 'synced';
let seq = Date.now();

export const registerSync = (w: World) => void (world = w);

const persist = () => (stored ? localStorage.setItem(LS_KEY, JSON.stringify(stored)) : localStorage.removeItem(LS_KEY));
const fail = (code: string, reason?: string): never => {
  throw { code, reason, message: code } satisfies BackendError;
};
const later = <T>(work: () => T, ms = 260): Promise<T> =>
  new Promise((ok, no) =>
    setTimeout(() => {
      try {
        ok(work());
      } catch (e) {
        no(e);
      }
    }, ms),
  );
const need = () => stored ?? fail('not_linked');
const newId = () => (++seq).toString(16).padStart(32, '0');

// Six words per account. In the program they come from a checksum of the keys; here they are made up.
const CODES: Record<string, string> = {
  ich: 'falke · mond · ziegel · hafen · birke · nebel',
  sam: 'kupfer · welle · adler · saite · moos · fackel',
  kai: 'anker · linde · quarz · regen · sattel · dohle',
  mira: 'feder · kiesel · brise · laterne · farn · amboss',
};
const codeOf = (name: string) => CODES[name] ?? 'ginster · tinte · brunnen · lerche · schiefer · wolke';

const member = (name: string, role: VaultRole, me = false, invited = false): VaultMember => ({ account: `konto-${name}`, name, role, me, invited, code: me ? CODES.ich : codeOf(name) });

function state(): SyncState {
  if (!stored) return { linked: false, server: '', username: '', admin: false, phase: 'synced', pending: 0, syncedAt: null, code: '', invitations: [], notices: 0, passwordChanged: false };
  return {
    linked: true,
    server: stored.server,
    username: stored.username,
    admin: stored.admin,
    phase,
    pending: phase === 'offline' ? 2 : 0,
    syncedAt: stored.syncedAt,
    code: CODES.ich,
    invitations: stored.invitations,
    notices: stored.notices.length,
    passwordChanged: false,
  };
}

/** Saves, reports the state and returns it. */
function done(): SyncState {
  persist();
  const now = state();
  emit(now);
  return now;
}

/** Like `done`, if the vault's content changed too. */
function changed(): SyncState {
  const now = done();
  world?.changed();
  return now;
}

function address(server: string): string {
  const text = server.trim().replace(/\/+$/, '');
  if (!text || /\s/.test(text)) fail('address_invalid');
  if (/^http:\/\//i.test(text) && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/i.test(text)) fail('address_invalid');
  return /^https?:\/\//i.test(text) ? text : `https://${text}`;
}

/** What is there after setup, so every screen shows something. */
function demo(server: string, username: string, admin: boolean, device: string): Stored {
  const now = Date.now();
  const team = newId();
  world?.addHosts(team, [
    ['pve-01', '10.20.0.11', 'debian'],
    ['pve-02', '10.20.0.12', 'debian'],
    ['backup-nas', '10.20.0.40', 'linux'],
    ['discord-bot', '10.20.1.15', 'ubuntu'],
  ]);
  return {
    server,
    username,
    admin,
    syncedAt: now,
    shared: [{ id: team, kind: 'shared', name: 'Team Infra', role: 'owner', members: [member(username, 'owner', true), member('sam', 'write'), member('kai', 'read', false, true)] }],
    invitations: [{ vault: newId(), name: 'Sam Homelab', owner: 'sam', role: 'read', code: codeOf('sam'), known: 'same' }],
    devices: [
      { id: newId(), name: device, createdAt: now, seenAt: now, current: true },
      { id: newId(), name: 'Laptop', createdAt: now - 12 * DAY, seenAt: now - 3 * 60 * MINUTE, current: false },
    ],
    notices: [
      { id: 2, at: now - 9 * MINUTE, kind: 'clash', vaultName: 'Team Infra', recordName: 'pve-01', path: 'own.port', mine: false },
      { id: 1, at: now - 2 * DAY, kind: 'restored', vaultName: '', recordName: 'web-02' },
    ],
    invites: admin ? [{ code: 'K7QF-2MXA-9RTD', createdAt: now - DAY, expiresAt: now + 6 * DAY }] : [],
    accounts: admin
      ? [
          { id: 'konto-ich', username, admin: true, disabled: false, createdAt: now - 30 * DAY, seenAt: now, devices: 2, bytes: 184_320 },
          { id: 'konto-sam', username: 'sam', admin: false, disabled: false, createdAt: now - 21 * DAY, seenAt: now - 40 * MINUTE, devices: 3, bytes: 96_256 },
          { id: 'konto-kai', username: 'kai', admin: false, disabled: false, createdAt: now - 2 * DAY, seenAt: now - 2 * DAY, devices: 1, bytes: 4_096 },
        ]
      : [],
  };
}

function checkAccount(username: string, password: string) {
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) fail('bad_request');
  if (password !== world?.password()) fail('wrong_password');
}

const shared = (id: string) => need().shared.find((v) => v.id === id) ?? fail('not_found');
const owned = (id: string) => {
  const vault = shared(id);
  return vault.role === 'owner' ? vault : fail('not_owner');
};
const role = (text: VaultRole) => (text === 'write' || text === 'read' ? text : fail('invalid'));

export const fakeSync = {
  /** The vaults for the stand-in vault's overview: the personal one and all shared ones. */
  vaults: (): VaultInfo[] => [{ id: PERSONAL, kind: 'personal', name: '', role: 'owner', members: [] }, ...(stored?.shared ?? [])],
  onState: (handler: (state: SyncState) => void) => ((emit = handler), () => {}),
  /** When the stand-in vault is deleted, the sign-in goes too. */
  reset: () => ((stored = null), persist()),

  /** For “Sign in with account” on first start: the stand-in vault has just been created and is linked right away. */
  link: (server: string, username: string, device: string) => {
    stored = demo(address(server), username, false, device.trim() || 'PC');
    phase = 'synced';
    persist();
  },
  state: () => later(state, 60),
  probe: (server: string) =>
    later((): SyncServerInfo => {
      const fixed = address(server);
      if (/offline|nirgends/.test(fixed)) fail('offline');
      return { server: fixed, fresh: /new|fresh/.test(fixed) };
    }, 500),
  register: (request: SyncRegister) =>
    later(() => {
      if (stored) fail('already_linked');
      const server = address(request.server);
      checkAccount(request.username, request.password);
      const fresh = /new|fresh/.test(server);
      if (!/^[A-Za-z0-9]{4}(-[A-Za-z0-9]{4}){2}$/.test(request.code.trim())) fail('code_invalid');
      stored = demo(server, request.username, fresh || request.username === 'alex', request.device.trim() || 'PC');
      phase = 'synced';
      return changed();
    }, 900),
  /** On a device with a vault: link to an existing account. */
  connect: (request: SyncLogin) =>
    later(() => {
      if (stored) fail('already_linked');
      const server = address(request.server);
      checkAccount(request.username, request.password);
      // The stand-in vault never belongs to an account: only the choice of what happens to its entries links it.
      if (!request.local) fail('other_account');
      stored = demo(server, request.username, false, request.device.trim() || 'PC');
      phase = 'synced';
      return changed();
    }, 900),
  now: () =>
    later(() => {
      const s = need();
      if (phase !== 'signedOut') phase = 'synced';
      s.syncedAt = Date.now();
      return done();
    }, 700),
  unlink: () =>
    later(() => {
      const s = need();
      for (const vault of s.shared) world?.dropVault(vault.id);
      stored = null;
      return changed();
    }),
  resync: (vault: string) =>
    later(() => {
      const found = need().shared.find((v) => v.id === vault);
      if (found) found.rolledBack = false;
      return changed();
    }, 800),
  /** Only for the preview: simulates a state that otherwise only exists with a real server. */
  pretend: (what: SyncState['phase'] | 'rolledBack') =>
    later(() => {
      const s = need();
      if (what === 'rolledBack') s.shared.forEach((v) => (v.rolledBack = true));
      else phase = what;
      return changed();
    }, 30),

  devices: () => later(() => [...need().devices]),
  deviceRename: (id: string, name: string) =>
    later(() => {
      const device = need().devices.find((d) => d.id === id) ?? fail('not_found');
      device.name = name.trim() || fail('invalid', 'name_required');
      persist();
      return [...need().devices];
    }),
  deviceRemove: (id: string) =>
    later(() => {
      const s = need();
      if (s.devices.find((d) => d.id === id)?.current) fail('invalid');
      s.devices = s.devices.filter((d) => d.id !== id);
      persist();
      return [...s.devices];
    }),

  notices: () => later(() => [...need().notices]),
  noticesClear: () =>
    later(() => {
      need().notices = [];
      done();
    }),

  create: (name: string) =>
    later(() => {
      const s = need();
      const vault: VaultInfo = { id: newId(), kind: 'shared', name: name.trim() || fail('invalid', 'name_required'), role: 'owner', members: [member(s.username, 'owner', true)] };
      s.shared.push(vault);
      changed();
      return vault.id;
    }),
  rename: (id: string, name: string) =>
    later(() => {
      owned(id).name = name.trim() || fail('invalid', 'name_required');
      changed();
    }),
  lookup: (username: string) =>
    later((): SyncCandidate => {
      const name = username.trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(name) || /niemand|unbekannt/.test(name)) fail('not_found');
      return { account: `konto-${name}`, username: name, code: codeOf(name), known: name === 'sam' ? 'same' : name === 'mira' ? 'changed' : 'new' };
    }, 500),
  invite: (id: string, account: string, as: VaultRole) =>
    later(() => {
      const vault = owned(id);
      if (vault.members.some((m) => m.account === account)) fail('invalid', 'already_member');
      vault.members.push(member(account.replace(/^konto-/, ''), role(as), false, true));
      changed();
    }, 500),
  setRole: (id: string, account: string, to: VaultRole) =>
    later(() => {
      const found = owned(id).members.find((m) => m.account === account && !m.me) ?? fail('not_found');
      found.role = role(to);
      changed();
    }, 500),
  remove: (id: string, account: string) =>
    later(() => {
      const vault = owned(id);
      vault.members = vault.members.filter((m) => m.account !== account || m.me);
      changed();
    }, 700),
  transfer: (id: string, account: string) =>
    later(() => {
      const vault = owned(id);
      const next = vault.members.find((m) => m.account === account && !m.me && !m.invited) ?? fail('not_found');
      for (const m of vault.members) if (m.role === 'owner') m.role = 'write';
      next.role = 'owner';
      vault.role = 'write';
      changed();
    }, 500),
  leave: (id: string) =>
    later(() => {
      const s = need();
      if (shared(id).role === 'owner') fail('owner_cannot_leave');
      s.shared = s.shared.filter((v) => v.id !== id);
      world?.dropVault(id);
      changed();
    }),
  remove_vault: (id: string) =>
    later(() => {
      const s = need();
      owned(id);
      s.shared = s.shared.filter((v) => v.id !== id);
      world?.dropVault(id);
      changed();
    }),
  accept: (id: string) =>
    later(() => {
      const s = need();
      const invitation = s.invitations.find((i) => i.vault === id) ?? fail('not_found');
      s.invitations = s.invitations.filter((i) => i !== invitation);
      s.shared.push({ id, kind: 'shared', name: invitation.name ?? '', role: invitation.role, members: [member(invitation.owner, 'owner'), member(s.username, invitation.role, true), member('mira', 'write')] });
      world?.addHosts(id, [
        ['homelab-gw', '192.168.50.1', 'linux'],
        ['media-01', '192.168.50.20', 'ubuntu'],
      ]);
      changed();
    }, 600),
  decline: (id: string) =>
    later(() => {
      const s = need();
      s.invitations = s.invitations.filter((i) => i.vault !== id);
      return done();
    }),

  adminInvites: () => later(() => [...need().invites]),
  adminInviteCreate: () =>
    later(() => {
      const s = need();
      const block = () => Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 32]).join('');
      s.invites = [...s.invites, { code: `${block()}-${block()}-${block()}`, createdAt: Date.now(), expiresAt: Date.now() + 7 * DAY }];
      persist();
      return [...s.invites];
    }),
  adminInviteRevoke: (code: string) =>
    later(() => {
      const s = need();
      s.invites = s.invites.filter((i) => i.code !== code);
      persist();
      return [...s.invites];
    }),
  adminAccounts: () => later(() => [...need().accounts]),
  adminAccountDisable: (id: string, disabled: boolean) =>
    later(() => {
      const account = need().accounts.find((a) => a.id === id && !a.admin) ?? fail('own_account');
      account.disabled = disabled;
      persist();
      return [...need().accounts];
    }),
  adminAccountDelete: (id: string) =>
    later(() => {
      const s = need();
      if (s.accounts.find((a) => a.id === id)?.admin) fail('own_account');
      s.accounts = s.accounts.filter((a) => a.id !== id);
      persist();
      return [...s.accounts];
    }),
};
