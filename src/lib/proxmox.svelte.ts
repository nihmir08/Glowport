import { proxmoxAction, proxmoxOverview, proxmoxReachable } from './backend';
import { errorText, hostById, identityById, vault } from './data.svelte';
import { t } from './i18n.svelte';
import { openTab } from './sessions.svelte';
import { toast } from './state.svelte';
import type { Host, ProxmoxConnection, ProxmoxGuest, ProxmoxOverview } from './types';

/** State of a connection to Proxmox, as it was last read. */
export interface PveState {
  overview?: ProxmoxOverview;
  /** Message if reading failed. */
  error: string;
  /** When it was last read. */
  at: number;
}

const states = $state<Record<string, PveState>>({});
let watchers = 0;
let timer: ReturnType<typeof setInterval> | undefined;

/** How often it is re-read while a page is watching. */
const INTERVAL = 10_000;

export const pveOf = (connection: string): PveState | undefined => states[connection];

/** Re-reads a connection. `fresh`: also ask anew what the core remembers about the machines for a while. */
export async function refreshPve(connection: string, fresh = false) {
  const state = (states[connection] ??= { error: '', at: 0 });
  try {
    state.overview = await proxmoxOverview(connection, fresh);
    state.error = '';
  } catch (e) {
    state.error = errorText(e);
  }
  state.at = Date.now();
}

const refreshAll = () => Promise.all(vault.proxmox.map((connection) => refreshPve(connection.id)));

/**
 * Re-reads all connections as long as someone is watching (the Proxmox page or the hosts overview).
 * Returns a function that ends watching. Nothing is queried in the background.
 */
export function watchPve(): () => void {
  if (++watchers === 1) {
    void refreshAll();
    timer = setInterval(() => void refreshAll(), INTERVAL);
  }
  return () => {
    if (--watchers > 0) return;
    clearInterval(timer);
    timer = undefined;
  };
}

/** The machine a host belongs to, as far as its state is known. */
export function guestOf(host: Host): ProxmoxGuest | undefined {
  const link = host.proxmox;
  return link ? states[link.connection]?.overview?.guests.find((guest) => guest.node === link.node && guest.vmid === link.vmid) : undefined;
}

/** The host is linked, but the machine no longer exists in Proxmox. */
export const guestGone = (host: Host): boolean => !!host.proxmox && !!states[host.proxmox.connection]?.overview && !guestOf(host);

/** What Glowport signs in to a machine with: user, plus a key or an identity from the vault. */
export interface GuestLogin {
  user?: string;
  /** ID and name of the key Cloud-Init stored for the machine. */
  key?: string;
  keyName?: string;
  /** ID and name of the identity the connection sets for its machines. */
  identity?: string;
  identityName?: string;
}

/**
 * If Cloud-Init names a key from the vault, Cloud-Init applies (user and key). Otherwise the
 * connection's identity applies as a whole, and without it only the user Proxmox names. The core applies
 * the same rule when creating hosts (`add_proxmox_hosts`).
 */
export function loginOf(connection: ProxmoxConnection, guest: ProxmoxGuest): GuestLogin {
  if (guest.key) return { user: guest.user, key: guest.key, keyName: guest.keyName };
  const identity = identityById(connection.identity);
  return identity ? { user: identity.user, identity: identity.id, identityName: identity.name } : { user: guest.user };
}

export type Power = 'start' | 'shutdown' | 'stop' | 'reboot';

/** Machines currently being switched, as `connection/number`. The Proxmox page and the hosts see the same state. */
const switching = $state<Record<string, boolean>>({});
export const isSwitching = (connection: string, vmid: number): boolean => !!switching[`${connection}/${vmid}`];

/** Switches a machine and says how it went. Returns when Proxmox has carried out the task. */
export async function powerGuest(connection: string, guest: Pick<ProxmoxGuest, 'node' | 'vmid' | 'kind' | 'name'>, action: Power): Promise<boolean> {
  const key = `${connection}/${guest.vmid}`;
  switching[key] = true;
  let done = false;
  try {
    await proxmoxAction(connection, { node: guest.node, vmid: guest.vmid, kind: guest.kind }, action);
    toast(t(`pve.done.${action}`, { name: guest.name }), 'ok');
    done = true;
  } catch (e) {
    toast(errorText(e), 'err');
  }
  delete switching[key];
  void refreshPve(connection);
  return done;
}

/** Hosts waiting for their machine that was just started. */
const waiting = $state<Record<string, boolean>>({});
export const isWaiting = (host: string): boolean => !!waiting[host];
/** Cancels waiting; the machine keeps running. */
export const stopWaiting = (host: string) => void delete waiting[host];

/** This long “Start and connect” waits for the machine to accept connections. */
const BOOT_PATIENCE = 120_000;

/**
 * Starts a host's machine and connects as soon as it accepts connections. While waiting it re-reads;
 * that way a host without a fixed address gets the one its machine reports after starting.
 */
export async function startAndConnect(host: Host) {
  const link = host.proxmox;
  const guest = guestOf(host);
  if (!link || !guest || waiting[host.id]) return;
  if (!(await powerGuest(link.connection, guest, 'start'))) return;
  waiting[host.id] = true;
  const end = Date.now() + BOOT_PATIENCE;
  while (waiting[host.id] && Date.now() < end) {
    await refreshPve(link.connection);
    if (await proxmoxReachable(host.id).catch(() => false)) break;
    await new Promise((ok) => setTimeout(ok, 2000));
  }
  // Cancelled: do not connect. After the time runs out, yes; the tab then says what the cause is.
  if (!waiting[host.id]) return;
  delete waiting[host.id];
  if (hostById(host.id)) openTab({ kind: 'host', id: host.id });
}

export const statusText = (status: ProxmoxGuest['status']) => t(`pve.status.${status}`);
export const statusTone = (status: ProxmoxGuest['status']) => (status === 'running' ? 'ok' : status === 'paused' ? 'warn' : 'idle');
