import { proxmoxAction, proxmoxOverview, proxmoxReachable } from './backend';
import { errorText, hostById, identityById, vault } from './data.svelte';
import { t } from './i18n.svelte';
import { openTab } from './sessions.svelte';
import { toast } from './state.svelte';
import type { Host, ProxmoxConnection, ProxmoxGuest, ProxmoxOverview } from './types';

/** Stand einer Verbindung zu Proxmox, wie er zuletzt gelesen wurde. */
export interface PveState {
  overview?: ProxmoxOverview;
  /** Meldung, wenn das Lesen scheiterte. */
  error: string;
  /** Wann zuletzt gelesen wurde. */
  at: number;
}

const states = $state<Record<string, PveState>>({});
let watchers = 0;
let timer: ReturnType<typeof setInterval> | undefined;

/** Wie oft nachgelesen wird, solange eine Seite zusieht. */
const INTERVAL = 10_000;

export const pveOf = (connection: string): PveState | undefined => states[connection];

/** Liest eine Verbindung nach. `fresh`: auch das neu fragen, was der Kern sich über die Maschinen eine Weile merkt. */
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
 * Liest alle Verbindungen nach, solange jemand zusieht (die Seite „Proxmox“ oder die Host-Übersicht).
 * Liefert eine Funktion, die das Zusehen beendet. Im Hintergrund wird nichts abgefragt.
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

/** Die Maschine, zu der ein Host gehört, soweit ihr Stand bekannt ist. */
export function guestOf(host: Host): ProxmoxGuest | undefined {
  const link = host.proxmox;
  return link ? states[link.connection]?.overview?.guests.find((guest) => guest.node === link.node && guest.vmid === link.vmid) : undefined;
}

/** Der Host ist verknüpft, die Maschine gibt es in Proxmox aber nicht mehr. */
export const guestGone = (host: Host): boolean => !!host.proxmox && !!states[host.proxmox.connection]?.overview && !guestOf(host);

/** Womit sich Glowport an einer Maschine anmeldet: Benutzer, dazu ein Schlüssel oder eine Identität aus dem Tresor. */
export interface GuestLogin {
  user?: string;
  /** Kennung und Name des Schlüssels, den Cloud-Init für die Maschine hinterlegt hat. */
  key?: string;
  keyName?: string;
  /** Kennung und Name der Identität, die die Verbindung für ihre Maschinen vorgibt. */
  identity?: string;
  identityName?: string;
}

/**
 * Nennt Cloud-Init einen Schlüssel aus dem Tresor, gilt Cloud-Init (Benutzer und Schlüssel). Sonst gilt die
 * Identität der Verbindung als Ganzes, und ohne sie nur der Benutzer, den Proxmox nennt. Dieselbe Regel wendet
 * der Kern beim Anlegen von Hosts an (`add_proxmox_hosts`).
 */
export function loginOf(connection: ProxmoxConnection, guest: ProxmoxGuest): GuestLogin {
  if (guest.key) return { user: guest.user, key: guest.key, keyName: guest.keyName };
  const identity = identityById(connection.identity);
  return identity ? { user: identity.user, identity: identity.id, identityName: identity.name } : { user: guest.user };
}

export type Power = 'start' | 'shutdown' | 'stop' | 'reboot';

/** Maschinen, die gerade geschaltet werden, als `Verbindung/Nummer`. Die Seite „Proxmox“ und die Hosts sehen denselben Stand. */
const switching = $state<Record<string, boolean>>({});
export const isSwitching = (connection: string, vmid: number): boolean => !!switching[`${connection}/${vmid}`];

/** Schaltet eine Maschine und sagt, wie es ausging. Kehrt zurück, wenn Proxmox den Auftrag ausgeführt hat. */
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

/** Hosts, die auf ihre eben gestartete Maschine warten. */
const waiting = $state<Record<string, boolean>>({});
export const isWaiting = (host: string): boolean => !!waiting[host];
/** Bricht das Warten ab; die Maschine läuft weiter. */
export const stopWaiting = (host: string) => void delete waiting[host];

/** So lange wartet „Starten und verbinden“ darauf, dass die Maschine Verbindungen annimmt. */
const BOOT_PATIENCE = 120_000;

/**
 * Startet die Maschine eines Hosts und verbindet, sobald sie Verbindungen annimmt. Beim Warten wird nachgelesen;
 * so bekommt ein Host ohne feste Adresse die, die seine Maschine nach dem Start meldet.
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
  // Abgebrochen: nicht verbinden. Nach Ablauf der Zeit schon; der Tab sagt dann, woran es liegt.
  if (!waiting[host.id]) return;
  delete waiting[host.id];
  if (hostById(host.id)) openTab({ kind: 'host', id: host.id });
}

export const statusText = (status: ProxmoxGuest['status']) => t(`pve.status.${status}`);
export const statusTone = (status: ProxmoxGuest['status']) => (status === 'running' ? 'ok' : status === 'paused' ? 'warn' : 'idle');
