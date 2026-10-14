// Beispieldaten für die Proxmox-Anbindung, nur für die Vorschau im Browser.
import type { Changed, HostInput, ProxmoxConnection, ProxmoxGuest, ProxmoxInput, ProxmoxLink, ProxmoxOverview, ProxmoxProbe } from './types';

const fail = (code: string, message = ''): never => {
  throw { code, message };
};
const later = <T>(work: () => T | Promise<T>, ms = 180): Promise<T> => new Promise((ok, no) => setTimeout(() => (async () => work())().then(ok, no), ms));

const GIB = 1024 ** 3;
const FINGERPRINT = '5F:1A:9C:42:D7:0B:E3:68:AA:14:7C:90:3D:E2:56:B1:08:F4:6D:2A:C9:71:35:EE:80:4B:1D:97:A6:53:CF:02';

/** Was die Vorschau vom übrigen Ersatz-Kern braucht. */
interface World {
  hosts: () => { id: string; name: string }[];
  keyNamed: (name: string) => string | undefined;
  identityNamed: (name: string) => string | undefined;
  save: (input: HostInput) => Promise<Changed>;
  changed: () => Changed;
}
let world: World | null = null;
export const registerProxmox = (w: World) => (world = w);

let connections: (ProxmoxConnection & { secret: string })[] = [];
/** Verknüpfte Hosts: Kennung des Hosts → Maschine. */
const links = new Map<string, ProxmoxLink>();
let seeded = false;

type Guest = Omit<ProxmoxGuest, 'host'>;
const GUESTS: Guest[] = [
  { node: 'pve', vmid: 101, kind: 'qemu', name: 'web-01', status: 'running', template: false, cpu: 0.18, cores: 4, memory: { used: 2.9 * GIB, total: 8 * GIB }, uptime: 1_209_600, tags: ['prod', 'web'], address: '10.0.10.11', source: 'cloudinit', user: 'deploy', keyName: 'deploy@laptop', os: 'Ub' },
  { node: 'pve', vmid: 102, kind: 'qemu', name: 'db-01', status: 'running', template: false, cpu: 0.42, cores: 8, memory: { used: 11.2 * GIB, total: 16 * GIB }, uptime: 1_209_540, tags: ['prod', 'db'], address: '10.0.20.21', source: 'cloudinit', user: 'deploy', keyName: 'deploy@laptop', os: 'De' },
  { node: 'pve', vmid: 110, kind: 'lxc', name: 'mail', status: 'running', template: false, cpu: 0.03, cores: 2, memory: { used: 0.7 * GIB, total: 2 * GIB }, uptime: 432_000, tags: ['prod'], address: '10.0.10.25', source: 'config', user: 'root', os: 'De' },
  { node: 'pve', vmid: 111, kind: 'lxc', name: 'pihole', status: 'running', template: false, cpu: 0.01, cores: 1, memory: { used: 0.2 * GIB, total: 0.5 * GIB }, uptime: 2_592_000, tags: ['netz'], address: '10.0.0.53', source: 'config', user: 'root', os: 'De' },
  { node: 'pve', vmid: 112, kind: 'lxc', name: 'gitea', status: 'running', template: false, cpu: 0.06, cores: 2, memory: { used: 0.9 * GIB, total: 2 * GIB }, uptime: 86_400, tags: [], address: '10.0.10.74', source: 'guest', user: 'root', os: 'Al' },
  { node: 'pve', vmid: 120, kind: 'qemu', name: 'monitoring', status: 'running', template: false, cpu: 0.09, cores: 2, memory: { used: 1.6 * GIB, total: 4 * GIB }, uptime: 600_000, tags: ['intern'], address: '10.0.10.90', source: 'agent', user: undefined, os: 'De' },
  { node: 'pve', vmid: 130, kind: 'qemu', name: 'spielwiese', status: 'stopped', template: false, cores: 2, memory: { used: 0, total: 4 * GIB }, tags: ['test'], os: 'Ub' },
  { node: 'pve', vmid: 131, kind: 'qemu', name: 'win-test', status: 'stopped', template: false, cores: 4, memory: { used: 0, total: 8 * GIB }, tags: ['test'], os: 'Win' },
  { node: 'pve', vmid: 9000, kind: 'qemu', name: 'debian-13-vorlage', status: 'stopped', template: true, cores: 2, memory: { used: 0, total: 2 * GIB }, tags: [], os: 'De' },
];
const guests = structuredClone(GUESTS);

/** Beim ersten Blick in den Tresor: So sieht ein Gerät aus, das Proxmox schon benutzt. */
function seed() {
  if (seeded || !world) return;
  seeded = true;
  connections = [{ id: 'pve1', name: 'Dedi', address: 'https://pve.example.de:8006', tokenId: 'glowport@pve!glowport', fingerprint: FINGERPRINT, identity: world.identityNamed('Deploy'), secret: 'x' }];
  for (const [name, vmid, kind] of [['web-01', 101, 'qemu'], ['db-01', 102, 'qemu'], ['pihole', 111, 'lxc']] as const) {
    const host = world.hosts().find((h) => h.name === name);
    if (host) links.set(host.id, { connection: 'pve1', node: 'pve', vmid, kind });
  }
}

const sameGuest = (a: { node: string; vmid: number }, b: { node: string; vmid: number }) => a.node === b.node && a.vmid === b.vmid;
const view = ({ secret: _secret, ...connection }: (typeof connections)[number]): ProxmoxConnection => connection;

export const fakeProxmox = {
  /** Für den Stand des Tresors: die Verbindungen und, je Host, seine Maschine. */
  connections: (): ProxmoxConnection[] => (seed(), connections.map(view)),
  linkOf: (host: string): { proxmox?: ProxmoxLink } => (seed(), links.has(host) ? { proxmox: links.get(host) } : {}),
  /** Für die Bilder: ein Gerät, das Proxmox noch nicht kennt. */
  forget: () => {
    seeded = true;
    connections = [];
    links.clear();
  },

  probe: (input: ProxmoxInput): Promise<ProxmoxProbe> =>
    later(() => {
      if (!/^https:\/\/[^/\s]+$/.test(input.address.trim().replace(/\/$/, ''))) fail('address_invalid');
      if (input.address.includes('gibt-es-nicht')) fail('offline');
      if (!/^[^@\s]+@[^!\s]+![^\s]+$/.test(input.tokenId.trim())) fail('proxmox_token');
      // Eine Adresse mit anerkanntem Zertifikat braucht keinen Fingerabdruck. Sonst nennt der erste Schritt nur
      // den Fingerabdruck; erst mit dem bestätigten geht der Token hinaus.
      const trusted = input.address.includes('letsencrypt');
      if (!trusted && input.fingerprint !== FINGERPRINT) return { version: '', trusted, fingerprint: FINGERPRINT, missing: [], changed: !!input.fingerprint };
      return { version: '9.0.11', trusted, fingerprint: FINGERPRINT, missing: input.tokenId.includes('nur-lesen') ? ['power'] : [] };
    }, 500),
  save: (input: ProxmoxInput): Promise<Changed> =>
    later(() => {
      seed();
      const old = connections.find((c) => c.id === input.id);
      const next = { id: old?.id ?? `pve${connections.length + 1}`, name: input.name.trim(), address: input.address.trim().replace(/\/$/, ''), tokenId: input.tokenId.trim(), fingerprint: input.fingerprint, identity: input.identity, secret: input.secret || old?.secret || '' };
      if (!next.name) fail('invalid', 'name_required');
      if (!next.secret) fail('proxmox_token');
      connections = old ? connections.map((c) => (c.id === old.id ? next : c)) : [...connections, next];
      return { ...world!.changed(), id: next.id };
    }),
  remove: (id: string): Promise<Changed> =>
    later(() => {
      connections = connections.filter((c) => c.id !== id);
      for (const [host, link] of links) if (link.connection === id) links.delete(host);
      return world!.changed();
    }),
  overview: (id: string): Promise<ProxmoxOverview> =>
    later(() => {
      seed();
      if (!connections.some((c) => c.id === id)) fail('not_found');
      const hostOf = (guest: Guest) => [...links].find(([, link]) => link.connection === id && sameGuest(link, guest))?.[0];
      return {
        version: '9.0.11',
        nodes: [{ node: 'pve', online: true, cpu: 0.21, cores: 32, memory: { used: 71 * GIB, total: 128 * GIB }, uptime: 5_184_000 }],
        guests: guests.map((guest) => ({ ...guest, key: guest.keyName ? world?.keyNamed(guest.keyName) : undefined, host: hostOf(guest) })),
      };
    }, 250),
  action: (id: string, target: { node: string; vmid: number }, action: 'start' | 'shutdown' | 'stop' | 'reboot'): Promise<void> =>
    later(() => {
      const guest = guests.find((g) => sameGuest(g, target)) ?? fail('not_found');
      if (id && guest.template) fail('proxmox_failed', 'template');
      if (action === 'start' || action === 'reboot') Object.assign(guest, { status: 'running', uptime: 5, cpu: 0.3, memory: { used: 0.6 * GIB, total: guest.memory?.total ?? GIB } });
      else Object.assign(guest, { status: 'stopped', uptime: undefined, cpu: undefined, memory: { used: 0, total: guest.memory?.total ?? GIB } });
    }, 900),
  import: (id: string, picks: { node: string; vmid: number }[], group: string | null): Promise<Changed> =>
    later(async () => {
      for (const pick of picks) {
        const guest = guests.find((g) => sameGuest(g, pick));
        if (!guest) continue;
        // Ohne bekannte Adresse steht vorerst der Name der Maschine da.
        // Wie im Kern: Cloud-Init mit einem Schlüssel aus dem Tresor gilt, sonst die Identität der Verbindung.
        const key = guest.keyName ? world!.keyNamed(guest.keyName) : undefined;
        const identity = connections.find((c) => c.id === id)?.identity;
        const own = key ? { user: guest.user, key } : identity ? { identity } : { user: guest.user };
        const saved = await world!.save({ name: guest.name, address: guest.address ?? guest.name, group, color: null, os: guest.os ?? null, own });
        if (saved.id) links.set(saved.id, { connection: id, node: guest.node, vmid: guest.vmid, kind: guest.kind });
      }
      return world!.changed();
    }, 400),
  unlink: (host: string): Promise<Changed> =>
    later(() => {
      links.delete(host);
      return world!.changed();
    }),
  reachable: (_host: string): Promise<boolean> => later(() => true, 600),
};
