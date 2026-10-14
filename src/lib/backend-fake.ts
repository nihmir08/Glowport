// Ersatz für den Kern, wenn die Oberfläche im Browser läuft (Entwicklung und Vorschau).
// NICHT verschlüsselt und nicht Teil des Programms: Im Programmfenster wird diese Datei nie benutzt.
// Die Regeln hier sind nur so genau, wie es zum Ausprobieren der Oberfläche nötig ist; maßgeblich ist crates/core.

import { FAKE_PORTS, FAKE_SHELLS, startDevice, type Device, type DeviceKind } from './backend-fake-extras';
import { registerPlaces, shellCd, shellHome, shellLs } from './backend-fake-files';
import { sampleDraft, sampleFound } from './backend-fake-import';
import { fakeProxmox, registerProxmox } from './backend-fake-proxmox';
import { PERSONAL, fakeSync, registerSync } from './backend-fake-sync';
import { fakeForwards, registerTools } from './backend-fake-tools';
import { hotkeyProblem } from './snippets';
import type {
  FtpPlace,
  Agent,
  Answer,
  Authority,
  BackendError,
  Changed,
  DeployResult,
  Fields,
  Forward,
  ForwardInput,
  Group,
  GroupInput,
  Host,
  HostInput,
  Identity,
  IdentityInput,
  ImportDraft,
  ImportOptions,
  ImportReport,
  ImportSource,
  ExportRequest,
  KeyFile,
  KeyGenerate,
  KeyImport,
  KeyInfo,
  KeyKind,
  KnownHost,
  Protocol,
  Recording,
  SavedLayout,
  SavedTab,
  SerialSettings,
  SessionEvent,
  Snapshot,
  Snippet,
  SnippetInput,
  SshKey,
  Status,
  SyncLogin,
  Target,
  Workspace,
  WorkspaceInput,
} from './types';

interface Stored {
  password: string;
  startUnlock?: boolean;
  groups: (Group & { proxyPassword?: string })[];
  hosts: (Host & { password?: string; proxyPassword?: string })[];
  knownHosts?: KnownHost[];
  keys?: SshKey[];
  identities?: (Identity & { password?: string })[];
  authorities?: Authority[];
  workspaces?: Workspace[];
  forwards?: Forward[];
  snippets?: Snippet[];
}

const LS_KEY = 'glowport.fakevault';
let store: Stored | null = JSON.parse(localStorage.getItem(LS_KEY) ?? 'null');
// Wie im Kern: Ist das Entsperren beim Start eingeschaltet, ist der Tresor nach dem Laden offen.
// Ein Tab in eigenem Fenster gehört zum selben Programm; dort ist der Tresor so offen wie im Hauptfenster.
let open = !!store?.startUnlock || new URLSearchParams(location.search).has('detached');
let seq = Date.now();

const newId = () => (++seq).toString(16).padStart(32, '0');
const persist = () => localStorage.setItem(LS_KEY, JSON.stringify(store));
const fail = (code: string, reason?: string): never => {
  throw { code, reason, message: `${code}${reason ? `: ${reason}` : ''}` } satisfies BackendError;
};

function snapshot(): Snapshot {
  const byName = <T extends { name: string }>(a: T, b: T) => a.name.localeCompare(b.name);
  return {
    groups: store!.groups.map(({ proxyPassword, ...g }) => ({ ...g, hasProxyPassword: !!proxyPassword })).sort(byName),
    hosts: store!.hosts.map(({ password, proxyPassword, ...h }) => ({ ...h, hasPassword: !!password, hasProxyPassword: !!proxyPassword, ...fakeProxmox.linkOf(h.id) })).sort(byName),
    damaged: 0,
    knownHosts: store!.knownHosts ?? [],
    keys: [...(store!.keys ?? [])].sort(byName),
    identities: (store!.identities ?? []).map(({ password, ...i }) => ({ ...i, hasPassword: !!password })).sort(byName),
    authorities: [...(store!.authorities ?? [])].sort(byName),
    workspaces: [...(store!.workspaces ?? [])].sort(byName),
    forwards: [...(store!.forwards ?? [])].sort(byName),
    snippets: [...(store!.snippets ?? [])].sort(byName),
    vaults: fakeSync.vaults(),
    proxmox: fakeProxmox.connections(),
  };
}

/** Der Tresor für einen neuen Eintrag. Der persönliche wird nicht eigens vermerkt. */
const placed = (vault: string | undefined) => (vault && vault !== PERSONAL ? { vault } : {});

const status = (): Status => {
  const startUnlock = !!store?.startUnlock;
  if (!store) return { state: 'missing', startUnlock };
  return open ? { state: 'open', data: snapshot(), startUnlock } : { state: 'locked', startUnlock };
};
const changed = (id?: string): Changed => (persist(), { id, data: snapshot() });
const need = () => (open && store ? store : fail('locked'));

function cleanFields(f: Fields): Fields {
  const out: Fields = {};
  if (f.user?.trim()) out.user = f.user.trim();
  if (f.port !== undefined) out.port = f.port >= 1 && f.port <= 65535 ? f.port : fail('invalid', 'port_invalid');
  if (f.jump !== undefined) out.jump = f.jump;
  if (f.startcmd?.trim()) out.startcmd = f.startcmd.trim();
  if (f.reconnect) out.reconnect = f.reconnect;
  if (f.keyFile?.trim()) out.keyFile = f.keyFile.trim();
  if (f.agent !== undefined) out.agent = f.agent;
  if (f.agentForward !== undefined) out.agentForward = f.agentForward;
  if (f.proxy !== undefined) out.proxy = !f.proxy || /^(http|socks5h?|socks):\/\/([^\s@/:]+@)?[^\s@/]+$/i.test(f.proxy.trim()) ? f.proxy.trim() : fail('invalid', 'proxy_invalid');
  if (f.keepalive !== undefined) out.keepalive = f.keepalive <= 3600 ? f.keepalive : fail('invalid', 'keepalive_invalid');
  if (f.timeout !== undefined) out.timeout = f.timeout >= 1 && f.timeout <= 300 ? f.timeout : fail('invalid', 'timeout_invalid');
  if (f.term?.trim()) out.term = /^[\w.+-]{1,32}$/.test(f.term.trim()) ? f.term.trim() : fail('invalid', 'term_invalid');
  if (f.charset) out.charset = f.charset;
  if (f.legacy !== undefined) out.legacy = f.legacy;
  if (f.mosh !== undefined) out.mosh = f.mosh;
  if (f.moshPredict) out.moshPredict = ['adaptive', 'always', 'never'].includes(f.moshPredict) ? f.moshPredict : fail('invalid', 'mosh_predict_invalid');
  if (f.moshPort?.trim()) out.moshPort = /^\d{1,5}(:\d{1,5})?$/.test(f.moshPort.trim()) ? f.moshPort.trim() : fail('invalid', 'mosh_port_invalid');
  if (f.moshServer?.trim()) out.moshServer = /^[^\s;&|`$<>]{1,200}$/.test(f.moshServer.trim()) ? f.moshServer.trim() : fail('invalid', 'mosh_server_invalid');
  if (f.scheme) out.scheme = f.scheme;
  if (f.env?.trim()) out.env = /^(\s*[A-Za-z_]\w*=("[^"]*"|\S*))*\s*$/.test(f.env) ? f.env.trim() : fail('invalid', 'env_invalid');
  if (f.identity !== undefined) out.identity = f.identity && !store!.identities?.some((i) => i.id === f.identity) ? fail('invalid', 'identity_missing') : f.identity;
  if (f.key !== undefined) out.key = f.key && !store!.keys?.some((k) => k.id === f.key) ? fail('invalid', 'key_missing') : f.key;
  if (out.user && /^-|\s/.test(out.user)) fail('invalid', 'user_invalid');
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const random = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => B64[b % 64]).join('');

/** Ein Schlüssel, der nur so aussieht: Fingerabdruck und öffentlicher Teil sind Zufall. */
function fakeKey(name: string, kind: KeyKind, bits: number, origin: SshKey['origin'], addedAt = Date.now()): SshKey {
  const [algorithm, body] =
    kind === 'ed25519'
      ? ['ssh-ed25519', `AAAAC3NzaC1lZDI1NTE5AAAAI${random(43)}`]
      : kind === 'rsa'
        ? ['ssh-rsa', `AAAAB3NzaC1yc2EAAAADAQABAAAC${random(bits / 6)}`]
        : [`ecdsa-sha2-nistp${bits}`, `AAAAE2VjZHNhLXNoYTItbmlzdHA${random(bits / 3)}`];
  return { id: newId(), name, kind, bits, fingerprint: `SHA256:${random(43)}`, publicKey: `${algorithm} ${body} ${name}`, origin, addedAt };
}

const ENCRYPTED_SAMPLE = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0 (Beispiel aus der Vorschau)\n-----END OPENSSH PRIVATE KEY-----\n';

function inspect(text: string, passphrase?: string): KeyInfo {
  const format = text.includes('PuTTY-User-Key-File') ? 'ppk' : text.includes('BEGIN OPENSSH PRIVATE KEY') ? 'openssh' : text.includes('PRIVATE KEY-----') ? 'pem' : fail('key_unreadable');
  const encrypted = /ENCRYPTED|FlczI1Ni|Encryption: aes/.test(text);
  if (encrypted && passphrase === 'falsch') fail('wrong_passphrase');
  const kind: KeyKind = /RSA|ssh-rsa/.test(text) ? 'rsa' : /EC PRIVATE|ecdsa/.test(text) ? 'ecdsa' : 'ed25519';
  const open = !encrypted || !!passphrase;
  return { kind, bits: kind === 'rsa' ? 4096 : 256, fingerprint: open ? `SHA256:${random(43)}` : null, encrypted, format, comment: open ? 'ich@laptop' : '' };
}

/** Namen der Beispieldaten für eine englische Oberfläche, etwa für die Bilder der README. */
const ENGLISH: Record<string, string> = {
  Produktiv: 'Production',
  Datenbanken: 'Databases',
  Netzwerk: 'Network',
  'switch-keller': 'switch-basement',
  'switch-buero': 'switch-office',
  'router-konsole': 'router-console',
  'esp32-werkbank': 'esp32-workbench',
  'webspace-kunde': 'webspace-client',
  'ftp.kunde-example.de': 'ftp.client.example.com',
  'scanner-archiv': 'scanner-archive',
  'arbeit-2026': 'work-2026',
  'alt-rsa': 'legacy-rsa',
  'SOCKS über bastion': 'SOCKS via bastion',
  Alltag: 'Daily',
  Plattenplatz: 'Disk usage',
  'Container anzeigen': 'List containers',
  'Dienst neu starten': 'Restart service',
  'Updates einspielen': 'Install updates',
  'Release ausrollen': 'Roll out release',
  'Logs verfolgen': 'Follow logs',
  'Gäste auflisten': 'List guests',
  'Größte Ordner finden': 'Find largest folders',
  'Deploy-Runde': 'Deploy round',
  'Proxmox-Überblick': 'Proxmox overview',
};

/** Die Beispieldaten in der Sprache der Oberfläche: Deutsch, wie sie geschrieben sind, oder übersetzt. */
function seed(): ReturnType<typeof seedData> {
  const data = seedData();
  if (JSON.parse(localStorage.getItem('glowport.settings') ?? '{}')?.lang !== 'en') return data;
  const en = <T extends { name: string }>(item: T): T => ({ ...item, name: ENGLISH[item.name] ?? item.name });
  return {
    ...data,
    groups: data.groups.map(en),
    hosts: data.hosts.map((host) => ({ ...en(host), address: ENGLISH[host.address] ?? host.address })),
    keys: data.keys?.map((key) => ({ ...en(key), publicKey: key.publicKey.replace(key.name, ENGLISH[key.name] ?? key.name) })),
    forwards: data.forwards?.map(en),
    workspaces: data.workspaces?.map(en),
    snippets: data.snippets?.map((s) => ({ ...en(s), package: ENGLISH[s.package] ?? s.package, command: s.command.replaceAll('{{dienst', '{{service').replaceAll('{{zeilen', '{{lines') })),
  };
}

function seedData(): Pick<Stored, 'groups' | 'hosts' | 'keys' | 'identities' | 'workspaces' | 'forwards' | 'snippets'> {
  const g = (name: string, parent: string | null, color: string | null, defs: Fields = {}): Group => ({ id: newId(), name, parent, color, defs });
  const h = (name: string, address: string, os: string | null, group: Group | null, own: Fields = {}): Host => ({
    id: newId(),
    name,
    address,
    group: group?.id ?? null,
    protocol: 'ssh',
    color: null,
    os,
    own,
    hasPassword: false,
  });
  const other = (name: string, address: string, protocol: Protocol, group: Group | null, own: Fields = {}, serial?: SerialSettings): Host => ({ ...h(name, address, null, group, own), protocol, ...(serial ? { serial } : {}) });
  const prod = g('Produktiv', null, '#FF5D6C', { user: 'deploy' });
  const web = g('Web', prod.id, null, { startcmd: 'cd /var/www/app' });
  const db = g('Datenbanken', prod.id, null);
  const pve = g('Proxmox', null, '#F59E0B', { user: 'root' });
  const home = g('Homelab', null, '#22C3A6');
  const gear = g('Netzwerk', null, '#5B9DFF');
  const bastion = h('bastion', '203.0.113.10', 'De', prod, { jump: '' });
  prod.defs.jump = bastion.id;
  const day = 86_400_000;
  const work = fakeKey('arbeit-2026', 'ed25519', 256, 'generated', Date.now() - 40 * day);
  const old = fakeKey('alt-rsa', 'rsa', 4096, 'imported', Date.now() - 400 * day);
  const ci = fakeKey('ci-deploy', 'ecdsa', 256, 'generated', Date.now() - 3 * day);
  const deploy: Identity & { password?: string } = { id: newId(), name: 'Deploy', user: 'deploy', key: work.id, hasPassword: false };
  const root: Identity & { password?: string } = { id: newId(), name: 'Proxmox root', user: 'root', key: null, hasPassword: true, password: 'vorschau' };
  delete prod.defs.user;
  prod.defs.identity = deploy.id;
  delete pve.defs.user;
  pve.defs.identity = root.id;
  home.defs.key = old.id;
  home.defs.scheme = 'nord';
  const web1 = h('web-01', '10.0.10.11', 'Ub', web);
  const web2 = h('web-02', '10.0.10.12', 'Ub', web);
  const db1 = h('db-01', '10.0.20.21', 'De', db);
  const pve1 = h('pve-01', '198.51.100.20', 'PVE', pve, { scheme: 'dracula' });
  const game = h('gameserver', '10.10.0.101', 'Ub', pve);
  const leaf = (host: Host): SavedLayout => ({ pane: { kind: 'host', id: host.id } });
  const rule = (name: string, kind: Forward['kind'], host: Host, bindPort: number, destHost = '', destPort = 0): Forward => ({ id: newId(), name, kind, host: host.id, bindAddress: '127.0.0.1', bindPort, destHost, destPort });
  const snip = (name: string, pack: string, command: string, hotkey: string | null = null): Snippet => ({ id: newId(), name, package: pack, kind: 'command', command, steps: [], hotkey });
  return {
    forwards: [
      rule('Grafana', 'local', web1, 3000, '127.0.0.1', 3000),
      rule('Postgres', 'local', db1, 5433, '127.0.0.1', 5432),
      rule('SOCKS über bastion', 'dynamic', bastion, 1080),
      rule('Webhook-Test', 'remote', web2, 8080, '127.0.0.1', 5173),
    ],
    snippets: [
      snip('Plattenplatz', 'Alltag', 'df -h', 'Alt+1'),
      snip('Container anzeigen', 'Alltag', 'docker ps', 'Alt+2'),
      snip('Dienst neu starten', 'Alltag', 'sudo systemctl restart {{dienst}}'),
      snip('Updates einspielen', 'Alltag', 'sudo apt update && sudo apt upgrade -y'),
      snip('Release ausrollen', 'Deploy', 'cd /var/www/app\ngit pull --ff-only\ndocker compose up -d', 'Ctrl+Alt+R'),
      snip('Logs verfolgen', 'Deploy', 'journalctl -u {{dienst:nginx}} -f -n {{zeilen:50}}'),
      snip('Gäste auflisten', 'Proxmox', 'qm list && pct list'),
      {
        id: newId(),
        name: 'Größte Ordner finden',
        package: '',
        kind: 'macro',
        command: '',
        steps: [
          { wait: 0, keys: 'cd /var\r' },
          { wait: 900, keys: 'sudo du -xh --max-depth=1 | sort -h | tail -n 8\r' },
          { wait: 2600, keys: 'cd -\r' },
        ],
        hotkey: null,
      },
    ],
    keys: [work, old, ci],
    identities: [deploy, root],
    groups: [prod, web, db, pve, home, gear],
    hosts: [
      bastion,
      web1,
      web2,
      h('lb-01', '10.0.10.5', 'De', web),
      db1,
      h('db-02', '10.0.20.22', 'De', db),
      pve1,
      game,
      h('nas', '192.168.1.20', 'Li', home, { user: 'admin', mosh: true }),
      // In der Vorschau fehlt mosh-server auf „pihole“: So lässt sich der Rückfall auf SSH ansehen.
      h('pihole', '192.168.1.2', 'Rp', home, { user: 'pi', mosh: true }),
      h('backup-box', '203.0.113.77', 'De', null, { port: 2222 }),
      other('switch-keller', '192.168.1.250', 'telnet', gear, { user: 'admin' }),
      other('switch-buero', '192.168.1.251', 'telnet', gear),
      other('router-konsole', 'COM3', 'serial', gear, {}, { baud: 115200, dataBits: 8, parity: 'none', stopBits: 1, flow: 'none' }),
      other('esp32-werkbank', 'COM5', 'serial', home, {}, { baud: 9600, dataBits: 8, parity: 'none', stopBits: 1, flow: 'none' }),
      { ...other('webspace-kunde', 'ftp.kunde-example.de', 'ftp', web, { user: 'web123' }), ftp: { security: 'explicit', anonymous: false, dir: '/htdocs' } },
      { ...other('scanner-archiv', '192.168.1.60', 'ftp', gear, { user: 'scan' }), ftp: { security: 'none', anonymous: false } },
    ],
    workspaces: [
      { id: newId(), name: 'Deploy-Runde', multi: true, layout: { dir: 'row', ratio: 0.5, a: leaf(web1), b: { dir: 'col', ratio: 0.5, a: leaf(web2), b: leaf(db1) } } },
      { id: newId(), name: 'Proxmox-Überblick', multi: false, layout: { dir: 'row', ratio: 0.6, a: leaf(pve1), b: leaf(game) } },
    ],
  };
}

function savedHosts(layout: SavedLayout): string[] {
  return 'pane' in layout ? (layout.pane.kind === 'host' ? [layout.pane.id] : []) : [...savedHosts(layout.a), ...savedHosts(layout.b)];
}

/** Entfernt einen Host aus einer Anordnung; null, wenn nichts übrig bleibt. */
function withoutHost(layout: SavedLayout, id: string): SavedLayout | null {
  if ('pane' in layout) return layout.pane.kind === 'host' && layout.pane.id === id ? null : layout;
  const a = withoutHost(layout.a, id);
  const b = withoutHost(layout.b, id);
  return a && b ? { ...layout, a, b } : (a ?? b);
}

// ---------- Ersatz-Mitschnitte: Beispiele, dazu das, was in der Vorschau aufgezeichnet wird ----------

const MINUTE = 60_000;
const LOG_DIR = 'C:\\Users\\ich\\AppData\\Roaming\\Glowport\\logs\\';
const SAMPLE_LOG = `deploy@web-01:~$ cd /var/www/app
deploy@web-01:/var/www/app$ git pull --ff-only
remote: Enumerating objects: 42, done.
remote: Counting objects: 100% (42/42), done.
Unpacking objects: 100% (27/27), 6.31 KiB | 1.05 MiB/s, done.
From git.example.org:shop/app
   9f3c1d2..b71e04a  main       -> origin/main
Updating 9f3c1d2..b71e04a
Fast-forward
 app/Http/Controllers/CartController.php | 18 ++++++++++++------
 resources/views/cart/show.blade.php     |  7 +++++--
 2 files changed, 17 insertions(+), 8 deletions(-)
deploy@web-01:/var/www/app$ php artisan migrate --force

   INFO  Nothing to migrate.

deploy@web-01:/var/www/app$ sudo systemctl reload php8.3-fpm
deploy@web-01:/var/www/app$ systemctl status nginx --no-pager
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: enabled)
     Active: active (running) since Mon 2026-09-28 06:12:44 CEST; 1 week 0 days ago
   Main PID: 812 (nginx)
      Tasks: 5 (limit: 9443)
     Memory: 21.4M (peak: 38.0M)
        CPU: 2min 11.802s
deploy@web-01:/var/www/app$ tail -n 4 storage/logs/laravel.log
[2026-10-05 17:38:02] production.INFO: cache cleared
[2026-10-05 17:38:04] production.INFO: queue restarted
[2026-10-05 17:39:41] production.WARNING: slow query (812 ms) on carts
[2026-10-05 17:40:10] production.INFO: deploy b71e04a finished
deploy@web-01:/var/www/app$ exit
logout
`;

const sample = (name: string, address: string, endedAgo: number, minutes: number, bytes: number): Recording => ({
  id: newId(),
  name,
  address,
  startedAt: Date.now() - (endedAgo + minutes) * MINUTE,
  endedAt: Date.now() - endedAgo * MINUTE,
  bytes,
  file: `${LOG_DIR}${name}.log`,
});
let recordings: Recording[] = [
  sample('web-01', 'deploy@10.0.10.11', 35, 39, 184_320),
  sample('pve-01', 'root@198.51.100.20', 140, 7, 22_528),
  sample('db-01', 'deploy@10.0.20.21', 60 * 20, 48, 317_440),
  sample('bastion', 'deploy@203.0.113.10', 60 * 23, 14, 98_304),
  sample('nas', 'admin@192.168.1.20', 60 * 24 * 4, 21, 61_440),
];
const runningLog = new Map<number, string>();
const logs = () => [...recordings].sort((a, b) => b.startedAt - a.startedAt);

function stopLog(session: number) {
  const entry = recordings.find((r) => r.id === runningLog.get(session));
  runningLog.delete(session);
  if (entry) entry.endedAt = Date.now();
}

const LS_RESTORE = 'glowport.fakerestore';

const descendants = (id: string): string[] => {
  const found = [id];
  for (let i = 0; i < found.length; i++) for (const g of store!.groups) if (g.parent === found[i] && !found.includes(g.id)) found.push(g.id);
  return found;
};

/** Kleine Wartezeit, damit Ladezustände in der Vorschau sichtbar sind. */
const later = <T>(work: () => T): Promise<T> => new Promise((ok, no) => setTimeout(() => {
  try {
    ok(work());
  } catch (e) {
    no(e);
  }
}, 120));

/** Entwürfe eines Imports, bis sie übernommen oder verworfen sind. */
const drafts = new Map<number, ImportDraft>();

export const fake = {
  logList: () => later(logs),
  logRead: (id: string) => later(() => (recordings.some((r) => r.id === id) ? SAMPLE_LOG : fail('not_found'))),
  logDelete: (id: string) => later(() => ((recordings = recordings.filter((r) => r.id !== id)), logs())),
  logRename: (id: string, title: string) =>
    later(() => {
      const entry = recordings.find((r) => r.id === id) ?? fail('not_found');
      if (!entry.endedAt) fail('log_running');
      entry.title = title.trim() || null;
      return { id, list: logs() };
    }),
  workspaceSave: (input: WorkspaceInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim() || fail('invalid', 'name_required');
      const locals = (layout: SavedLayout): number => ('pane' in layout ? Number(layout.pane.kind === 'local') : locals(layout.a) + locals(layout.b));
      if (!savedHosts(input.layout).length && !locals(input.layout)) fail('invalid', 'workspace_empty');
      const workspace: Workspace = { id: input.id ?? newId(), name, multi: input.multi, layout: input.layout };
      s.workspaces = [...(s.workspaces ?? []).filter((w) => w.id !== workspace.id), workspace];
      return changed(workspace.id);
    }),
  workspaceDelete: (id: string) =>
    later(() => {
      const s = need();
      s.workspaces = (s.workspaces ?? []).filter((w) => w.id !== id);
      return changed();
    }),
  // In der Vorschau gilt jedes Neuladen mit offenen Tabs als Abbruch.
  restoreLoad: () =>
    later((): SavedTab[] | null => {
      const saved = JSON.parse(localStorage.getItem(LS_RESTORE) ?? '[]') as SavedTab[];
      return saved.length ? saved : null;
    }),
  restoreSave: (tabs: SavedTab[]) => Promise.resolve(tabs.length ? localStorage.setItem(LS_RESTORE, JSON.stringify(tabs)) : localStorage.removeItem(LS_RESTORE)),
  pickBackground: () =>
    later(
      () =>
        `data:image/svg+xml,${encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1000"><defs><radialGradient id="a" cx="20%" cy="15%" r="80%"><stop offset="0" stop-color="#ff7a18"/><stop offset=".45" stop-color="#af002d"/><stop offset="1" stop-color="#1a0b2e"/></radialGradient></defs><rect width="1600" height="1000" fill="url(#a)"/><circle cx="1250" cy="260" r="210" fill="#ffd27d" opacity=".55"/><path d="M0 760 Q400 600 800 740 T1600 690 V1000 H0z" fill="#12061f" opacity=".8"/></svg>')}`,
    ),
  status: () => later(status),
  create: (password: string) =>
    later(() => {
      if (store) fail('exists');
      if (password.length < 8) fail('weak_password');
      store = { password, ...seed() };
      open = true;
      persist();
      return status();
    }),
  unlock: (password: string) =>
    later(() => {
      if (store?.password !== password) fail('wrong_password');
      open = true;
      return status();
    }),
  lock: () => later(() => ((open = false), status())),
  /** „Mit Konto anmelden“ beim ersten Start: In der Vorschau entsteht der Beispiel-Tresor und ist gleich verbunden. */
  syncLogin: (request: SyncLogin) =>
    later(() => {
      if (store) fail('exists');
      if (!/^[a-z0-9._-]{3,32}$/.test(request.username)) fail('bad_request');
      if (request.password.length < 8) fail('unauthorized');
      store = { password: request.password, ...seed() };
      open = true;
      fakeSync.link(request.server, request.username, request.device);
      persist();
      return status();
    }),
  changePassword: (old: string, next: string) =>
    later(() => {
      const s = need();
      if (s.password !== old) fail('wrong_password');
      if (next.length < 8) fail('weak_password');
      s.password = next;
      persist();
    }),
  setStartUnlock: (enabled: boolean) =>
    later(() => {
      need().startUnlock = enabled;
      persist();
      return status();
    }),
  backup: (fileName: string) => later(() => (need(), `C:\\Sicherungen\\${fileName}`)),
  /** In der Vorschau gibt es keine Datei: „Einspielen“ legt den Beispiel-Tresor an, gesperrt wie nach einem echten Einspielen. */
  restore: () =>
    later(() => {
      if (store) fail('exists');
      store = { password: 'vorschau-bilder', ...seed() };
      open = false;
      persist();
      return status();
    }),
  /** Wie im Programm: Tresor und Anmeldung sind weg, dann beginnt alles von vorn. */
  wipe: (_force: boolean) =>
    later(() => {
      store = null;
      open = false;
      localStorage.removeItem(LS_KEY);
      localStorage.removeItem(LS_RESTORE);
      fakeSync.reset();
      location.reload();
    }),
  importScan: () => later(() => (need(), sampleFound())),
  importRead: (source: ImportSource) =>
    later((): ImportDraft => {
      need();
      const token = ++seq;
      const found = { token, ...sampleDraft(source, snapshot()) };
      drafts.set(token, found);
      return found;
    }),
  importDiscard: (token: number) => later(() => void drafts.delete(token)),
  importApply: (token: number, options: ImportOptions) =>
    later(() => {
      const s = need();
      const found = drafts.get(token) ?? fail('not_found');
      const report: ImportReport = { hosts: 0, groups: 0, keys: 0, forwards: 0, snippets: 0, knownHosts: 0, updated: 0, skipped: 0, keyFiles: 0, failed: [] };
      const picked = found.hosts.filter((h) => options.hosts.includes(h.ref));
      let root: string | null = null;
      if (options.into && 'id' in options.into) root = options.into.id;
      else if (options.into && picked.length) {
        const made: Group = { id: newId(), name: options.into.name.trim() || fail('invalid', 'name_required'), parent: null, color: null, defs: {} };
        s.groups.push(made);
        root = made.id;
        report.groups += 1;
      }
      // Gruppen der Quelle entstehen nur, soweit ein gewählter Host in ihnen liegt.
      const groupIds = new Map<string, string>();
      const groupFor = (ref: string | null): string | null => {
        if (!ref) return root;
        if (groupIds.has(ref)) return groupIds.get(ref)!;
        const source = found.groups.find((g) => g.ref === ref);
        if (!source) return root;
        const parent = groupFor(source.parent);
        const twin = s.groups.find((g) => g.parent === parent && g.name === source.name);
        const id = twin?.id ?? newId();
        if (!twin) (s.groups.push({ id, name: source.name, parent, color: null, defs: {} }), (report.groups += 1));
        groupIds.set(ref, id);
        return id;
      };
      const keyIds = new Map<string, string>();
      for (const key of found.keys.filter((k) => options.keys.includes(k.ref))) {
        if (key.existing) keyIds.set(key.ref, key.existing);
        else if (key.state === 'ready' && options.keysToVault) {
          const added = fakeKey(key.name.replace(/\.(ppk|pem)$/i, ''), key.kind ?? 'ed25519', key.bits ?? 256, 'imported');
          s.keys = [...(s.keys ?? []), added];
          keyIds.set(key.ref, added.id);
          report.keys += 1;
        } else if (key.state !== 'missing') report.keyFiles += 1;
      }
      const hostIds = new Map<string, string>();
      for (const h of picked) {
        const key = h.key ? found.keys.find((k) => k.ref === h.key) : null;
        const own: Fields = {};
        if (h.user) own.user = h.user;
        if (h.port && h.port !== 22) own.port = h.port;
        if (key && keyIds.has(key.ref)) own.key = keyIds.get(key.ref);
        else if (key?.path && key.state !== 'missing' && options.keys.includes(key.ref)) own.keyFile = key.path;
        if (h.auth === 'agent') own.agent = true;
        const password = options.passwords && h.hasPassword && !h.notes.some((n) => n.code === 'password_unreadable') ? 'vorschau' : undefined;
        if (h.existing && options.existing === 'skip') {
          hostIds.set(h.ref, h.existing);
          report.skipped += 1;
          continue;
        }
        if (h.existing && options.existing === 'update') {
          const old = s.hosts.find((x) => x.id === h.existing)!;
          old.own = { ...old.own, ...own };
          if (password) old.password = password;
          hostIds.set(h.ref, old.id);
          report.updated += 1;
          continue;
        }
        const protocol = h.protocol ?? 'ssh';
        const host: Stored['hosts'][number] = { id: newId(), name: h.name, address: h.address, group: groupFor(h.group), protocol, color: null, os: h.os, own, hasPassword: false, password };
        if (protocol === 'serial') host.serial = { baud: 9600, dataBits: 8, parity: 'none', stopBits: 1, flow: 'none' };
        s.hosts.push(host);
        hostIds.set(h.ref, host.id);
        report.hosts += 1;
      }
      for (const h of picked) {
        const id = hostIds.get(h.ref);
        const jump = h.jump ? hostIds.get(h.jump) : undefined;
        const target = s.hosts.find((x) => x.id === id);
        if (target && jump && jump !== id && !(h.existing && options.existing === 'skip')) target.own.jump = jump;
      }
      for (const f of found.forwards.filter((x) => options.forwards.includes(x.ref))) {
        const host = hostIds.get(f.host);
        if (!host) {
          report.failed.push({ name: f.name, reason: 'host_missing' });
          continue;
        }
        s.forwards = [...(s.forwards ?? []), { id: newId(), name: f.name, kind: f.kind, host, bindAddress: f.bindAddress, bindPort: f.bindPort, destHost: f.destHost, destPort: f.destPort }];
        report.forwards += 1;
      }
      for (const sn of found.snippets.filter((x) => options.snippets.includes(x.ref) && !x.existing)) {
        s.snippets = [...(s.snippets ?? []), { id: newId(), name: sn.name, package: sn.package, kind: 'command', command: sn.command, steps: [], hotkey: null }];
        report.snippets += 1;
      }
      for (const k of found.knownHosts.filter((x) => options.knownHosts.includes(x.ref) && !x.existing)) {
        s.knownHosts = [...(s.knownHosts ?? []), { id: newId(), host: k.host, port: k.port, algorithm: k.algorithm, fingerprint: k.fingerprint, addedAt: Date.now() }];
        report.knownHosts += 1;
      }
      drafts.delete(token);
      return { report, ...changed() };
    }),
  exportData: (request: ExportRequest) =>
    later(() => (need(), `C:\\Users\\ich\\Documents\\${request.format === 'sshconfig' ? 'glowport-ssh-config' : request.format === 'csv' ? 'glowport-hosts.csv' : 'glowport-export.json'}`)),
  hostSave: (input: HostInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim();
      const address = input.address.trim();
      if (!name) fail('invalid', 'name_required');
      if (!address) fail('invalid', 'address_required');
      if (/^-|\s/.test(address)) fail('invalid', 'address_invalid');
      const old = input.id ? (s.hosts.find((h) => h.id === input.id) ?? fail('not_found')) : null;
      const protocol = input.protocol ?? old?.protocol ?? 'ssh';
      const serial = protocol === 'serial' ? (input.serial ?? old?.serial ?? fail('invalid', 'serial_required')) : undefined;
      const ftp = protocol === 'ftp' ? (input.ftp ?? old?.ftp ?? { security: 'explicit' as const, anonymous: false }) : undefined;
      if (serial && !(Number.isInteger(serial.baud) && serial.baud >= 50 && serial.baud <= 4_000_000)) fail('invalid', 'baud_invalid');
      const host: Host & { password?: string; proxyPassword?: string } = { ...(old ?? { id: newId(), hasPassword: false, ...placed(input.vault) }), protocol, serial, ftp, name, address, group: input.group, color: input.color, os: input.os, own: cleanFields(input.own) };
      if (protocol !== 'ssh' && protocol !== 'ftp') delete host.password;
      // Geänderte Einstellungen gelten erst für eine neue Verbindung.
      ftpOpened.delete(host.id);
      if (input.password !== undefined) host.password = input.password || undefined;
      if (input.proxyPassword !== undefined) host.proxyPassword = input.proxyPassword || undefined;
      if (!host.own.proxy) delete host.proxyPassword;
      if (host.own.jump === host.id) fail('invalid', 'jump_self');
      s.hosts = [...s.hosts.filter((h) => h.id !== host.id), host];
      return changed(host.id);
    }),
  hostMove: (id: string, vault: string) =>
    later(() => {
      const host = need().hosts.find((h) => h.id === id) ?? fail('not_found');
      if (vault === PERSONAL) delete host.vault;
      else host.vault = vault;
      host.group = null;
      return changed(id);
    }),
  hostDuplicate: (id: string, name: string) =>
    later(() => {
      const s = need();
      const old = s.hosts.find((h) => h.id === id) ?? fail('not_found');
      const copy = { ...old, id: newId(), name, own: { ...old.own } };
      s.hosts.push(copy);
      return changed(copy.id);
    }),
  hostDelete: (id: string) =>
    later(() => {
      const s = need();
      if (!s.hosts.some((h) => h.id === id)) fail('not_found');
      s.hosts = s.hosts.filter((h) => h.id !== id);
      for (const f of [...s.hosts.map((h) => h.own), ...s.groups.map((g) => g.defs)]) if (f.jump === id) delete f.jump;
      // Port-Regeln laufen über genau einen Host; mit ihm verschwinden sie.
      for (const rule of s.forwards ?? []) if (rule.host === id) fakeForwards.forget(rule.id);
      s.forwards = (s.forwards ?? []).filter((rule) => rule.host !== id);
      // Arbeitsbereiche verlieren den Host; einer ohne Hosts verschwindet.
      s.workspaces = (s.workspaces ?? []).flatMap((w) => {
        const layout = withoutHost(w.layout, id);
        return layout ? [{ ...w, layout }] : [];
      });
      return changed();
    }),
  groupSave: (input: GroupInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim();
      if (!name) fail('invalid', 'name_required');
      if (input.id && input.parent && descendants(input.id).includes(input.parent)) fail('invalid', 'group_cycle');
      const old = s.groups.find((g) => g.id === input.id);
      const group: Group & { proxyPassword?: string } = { id: input.id ?? newId(), name, parent: input.parent, color: input.color, defs: cleanFields(input.defs), proxyPassword: old?.proxyPassword };
      if (input.proxyPassword !== undefined) group.proxyPassword = input.proxyPassword || undefined;
      if (!group.defs.proxy) delete group.proxyPassword;
      s.groups = [...s.groups.filter((g) => g.id !== group.id), group];
      return changed(group.id);
    }),
  knownHostDelete: (id: string) =>
    later(() => {
      const s = need();
      s.knownHosts = (s.knownHosts ?? []).filter((k) => k.id !== id);
      return changed();
    }),
  keyGenerate: (input: KeyGenerate) =>
    later(() => {
      const s = need();
      const name = input.name.trim() || fail('invalid', 'name_required');
      const key = fakeKey(name, input.kind, input.bits, 'generated');
      s.keys = [...(s.keys ?? []), key];
      return changed(key.id);
    }),
  keyPickFile: () => later((): KeyFile | null => ({ path: 'C:\\Users\\ich\\.ssh\\id_ed25519', text: ENCRYPTED_SAMPLE })),
  keyInspect: (text: string, passphrase?: string) => later(() => inspect(text, passphrase)),
  keyImport: (input: KeyImport) =>
    later(() => {
      const s = need();
      const info = inspect(input.text, input.passphrase);
      if (info.encrypted && !input.passphrase) fail('passphrase_required');
      const name = input.name.trim() || fail('invalid', 'name_required');
      const key = fakeKey(name, info.kind ?? 'ed25519', info.bits ?? 256, 'imported');
      s.keys = [...(s.keys ?? []), key];
      return changed(key.id);
    }),
  keyRename: (id: string, name: string) =>
    later(() => {
      const key = need().keys?.find((k) => k.id === id) ?? fail('not_found');
      key.name = name.trim() || fail('invalid', 'name_required');
      return changed(id);
    }),
  keySetCertificate: (id: string, text: string | null) =>
    later(() => {
      const key = need().keys?.find((k) => k.id === id) ?? fail('not_found');
      if (text && !text.includes('-cert-v01@openssh.com')) fail('certificate_unreadable');
      const day = 86_400;
      key.certificate = text ? { text: text.trim(), keyId: `${key.name}@firma`, principals: ['deploy', 'root'], validAfter: Math.floor(Date.now() / 1000) - day, validBefore: Math.floor(Date.now() / 1000) + 90 * day, authority: `SHA256:${random(43)}` } : null;
      return changed(id);
    }),
  keyDelete: (id: string) =>
    later(() => {
      const s = need();
      if (!s.keys?.some((k) => k.id === id)) fail('not_found');
      s.keys = s.keys!.filter((k) => k.id !== id);
      for (const f of [...s.hosts.map((h) => h.own), ...s.groups.map((g) => g.defs)]) if (f.key === id) delete f.key;
      for (const i of s.identities ?? []) if (i.key === id) i.key = null;
      return changed();
    }),
  keyExport: (id: string) => later(() => `C:\\Users\\ich\\.ssh\\${need().keys?.find((k) => k.id === id)?.name ?? fail('not_found')}`),
  /** Tut so, als würde nacheinander auf jedem Host angemeldet. Ein paar Hosts antworten anders, damit alle Ausgänge zu sehen sind. */
  keyDeploy: async (id: string, hosts: string[], adopt: boolean, onResult: (result: DeployResult) => void) => {
    const s = need();
    if (!s.keys?.some((k) => k.id === id)) fail('not_found');
    for (const host of hosts) {
      await new Promise((r) => setTimeout(r, 450));
      const found = s.hosts.find((h) => h.id === host);
      if (!found) onResult({ host, outcome: 'failed', message: 'not_found' });
      else if (found.address.startsWith('10.0.20.')) onResult({ host, outcome: 'failed', message: 'auth_failed' });
      else {
        if (adopt) found.own.key = id;
        onResult({ host, outcome: found.name === 'bastion' ? 'present' : 'added' });
      }
    }
    if (adopt) (persist(), emitChanged(snapshot()));
  },
  identitySave: (input: IdentityInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim() || fail('invalid', 'name_required');
      const user = input.user.trim() || fail('invalid', 'user_required');
      if (/^-|\s/.test(user)) fail('invalid', 'user_invalid');
      if (input.key && !s.keys?.some((k) => k.id === input.key)) fail('invalid', 'key_missing');
      const old = input.id ? (s.identities?.find((i) => i.id === input.id) ?? fail('not_found')) : null;
      const identity: Identity & { password?: string } = { ...(old ?? { id: newId(), hasPassword: false }), name, user, key: input.key };
      if (input.password !== undefined) identity.password = input.password || undefined;
      s.identities = [...(s.identities ?? []).filter((i) => i.id !== identity.id), identity];
      return changed(identity.id);
    }),
  identityDelete: (id: string) =>
    later(() => {
      const s = need();
      if (!s.identities?.some((i) => i.id === id)) fail('not_found');
      s.identities = s.identities!.filter((i) => i.id !== id);
      for (const f of [...s.hosts.map((h) => h.own), ...s.groups.map((g) => g.defs)]) if (f.identity === id) delete f.identity;
      return changed();
    }),
  authorityAdd: (name: string, pattern: string, key: string) =>
    later(() => {
      const s = need();
      if (!name.trim()) fail('invalid', 'name_required');
      if (!pattern.trim()) fail('invalid', 'pattern_invalid');
      if (!/^(ssh-|ecdsa-)\S+ \S+/.test(key.trim())) fail('key_unreadable');
      const authority: Authority = { id: newId(), name: name.trim(), pattern: pattern.trim(), kind: 'Ed25519', fingerprint: `SHA256:${random(43)}`, addedAt: Date.now() };
      s.authorities = [...(s.authorities ?? []), authority];
      return changed(authority.id);
    }),
  authorityDelete: (id: string) =>
    later(() => {
      const s = need();
      s.authorities = (s.authorities ?? []).filter((a) => a.id !== id);
      return changed();
    }),
  forwardSave: (input: ForwardInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim() || fail('invalid', 'name_required');
      if (!s.hosts.some((h) => h.id === input.host)) fail('invalid', 'host_missing');
      const port = (n: number) => (Number.isInteger(n) && n >= 1 && n <= 65535 ? n : fail('invalid', 'port_invalid'));
      const address = (text: string) => (/^[^\s/@]*$/.test(text.trim()) ? text.trim() : fail('invalid', 'address_invalid'));
      const dynamic = input.kind === 'dynamic';
      if (!dynamic && !input.destHost.trim()) fail('invalid', 'dest_required');
      const rule: Forward = {
        id: input.id ?? newId(),
        name,
        kind: input.kind,
        host: input.host,
        bindAddress: address(input.bindAddress) || '127.0.0.1',
        bindPort: port(input.bindPort),
        destHost: dynamic ? '' : address(input.destHost),
        destPort: dynamic ? 0 : port(input.destPort),
      };
      // Eine geänderte Regel läuft nicht mit den alten Werten weiter.
      fakeForwards.forget(rule.id);
      s.forwards = [...(s.forwards ?? []).filter((f) => f.id !== rule.id), rule];
      return changed(rule.id);
    }),
  forwardDelete: (id: string) =>
    later(() => {
      const s = need();
      fakeForwards.forget(id);
      s.forwards = (s.forwards ?? []).filter((f) => f.id !== id);
      return changed();
    }),
  snippetSave: (input: SnippetInput) =>
    later(() => {
      const s = need();
      const name = input.name.trim() || fail('invalid', 'name_required');
      if (input.kind === 'command' && !input.command.trim()) fail('invalid', 'command_required');
      if (input.kind === 'macro' && !input.steps.length) fail('invalid', 'macro_empty');
      if (input.hotkey && hotkeyProblem(input.hotkey)) fail('invalid', 'hotkey_invalid');
      if (input.hotkey && (s.snippets ?? []).some((other) => other.id !== input.id && other.hotkey === input.hotkey)) fail('invalid', 'hotkey_taken');
      const snippet: Snippet = { id: input.id ?? newId(), name, package: input.package.trim(), kind: input.kind, command: input.kind === 'command' ? input.command.trim() : '', steps: input.kind === 'macro' ? input.steps : [], hotkey: input.hotkey || null };
      s.snippets = [...(s.snippets ?? []).filter((other) => other.id !== snippet.id), snippet];
      return changed(snippet.id);
    }),
  snippetDelete: (id: string) =>
    later(() => {
      const s = need();
      s.snippets = (s.snippets ?? []).filter((snippet) => snippet.id !== id);
      return changed();
    }),
  agentList: () =>
    later((): Agent[] => [
      {
        kind: 'openssh',
        running: true,
        keys: [
          { comment: 'ich@laptop', kind: 'ED25519', fingerprint: 'SHA256:u1Qm0Lr2QvorschauNurZumAnsehen4kPz9bTfK2xAgent' },
          { comment: '1Password: Server', kind: 'RSA 4096', fingerprint: 'SHA256:Pz9bTfK2xQm0Lr2QvorschauNurZumAnsehen4kAgent' },
        ],
      },
      { kind: 'pageant', running: false, keys: [] },
    ]),
  groupDelete: (id: string, withContents: boolean) =>
    later(() => {
      const s = need();
      const group = s.groups.find((g) => g.id === id) ?? fail('not_found');
      if (withContents) {
        const gone = descendants(id);
        s.hosts = s.hosts.filter((h) => !h.group || !gone.includes(h.group));
        s.groups = s.groups.filter((g) => !gone.includes(g.id));
      } else {
        for (const h of s.hosts) if (h.group === id) h.group = group.parent;
        for (const g of s.groups) if (g.parent === id) g.parent = group.parent;
        s.groups = s.groups.filter((g) => g.id !== id);
      }
      return changed();
    }),
};

// ---------- Ersatz-Sitzungen: eine Text-Shell, die Eingaben wiederholt ----------

interface FakeLive {
  out: (bytes: Uint8Array) => void;
  line: string;
  host: string;
  port: number;
  hostId: string | null;
  /** Benutzer und Rechnername für die Eingabezeile der Ersatz-Shell. */
  user: string;
  name: string;
  stage: 'hostKey' | 'secret' | 'shell';
  /** Ordner, in dem die Ersatz-Shell steht. */
  cwd: string;
  home: string;
  /** Mosh war gewünscht; `on`: es läuft. */
  mosh: { wanted: boolean; on: boolean };
}

const live = new Map<number, FakeLive>();
let sessionSeq = 0;

/** FTP in der Vorschau: Hosts, die verbunden sind, bestätigte Zertifikate und laufende Rückfragen. */
const ftpOpened = new Set<string>();
const ftpTrusted = new Set<string>();
const ftpLinks = new Map<number, { host: string; plainOk: boolean }>();
/** Laufende Aufbauten zu Servern aus der Schnellverbindung: Nummer und Schlüssel des Orts. */
const ftpDirect = new Map<number, string>();
const FTP_FINGERPRINT = '5F:1A:C3:07:9E:42:B8:6D:11:F0:7A:95:3C:E8:24:D6:0B:71:AF:58:C9:3E:82:14:67:DA:F5:09:BC:4E:A1:30';

/** Der nächste Schritt eines Aufbaus: erst die Warnung, dann das Zertifikat, dann steht die Verbindung. */
function ftpStep(id: number) {
  const link = ftpLinks.get(id);
  const host = link && store?.hosts.find((h) => h.id === link.host);
  if (!link || !host) return;
  const ftp = host.ftp ?? { security: 'explicit' as const, anonymous: false };
  if (ftp.security === 'none' && !ftp.plainOk && !link.plainOk) return emitSession({ id, type: 'plain', host: host.address, offersTls: host.name.startsWith('web'), canRemember: true });
  if (ftp.security !== 'none' && !ftpTrusted.has(host.id)) return emitSession({ id, type: 'certificate', host: host.address, port: host.own.port ?? (ftp.security === 'implicit' ? 990 : 21), fingerprint: FTP_FINGERPRINT, changed: false });
  ftpLinks.delete(id);
  ftpOpened.add(host.id);
  emitSession({ id, type: 'phase', phase: 'connected' });
}
let emitSession: (event: SessionEvent) => void = () => {};
let emitChanged: (data: Snapshot) => void = () => {};
const encoder = new TextEncoder();
const promptOf = (s: FakeLive) => `\x1b[1;32m${s.user}@${s.name}\x1b[0m:\x1b[1;34m${s.cwd === s.home ? '~' : s.cwd.startsWith(`${s.home}/`) ? `~${s.cwd.slice(s.home.length)}` : s.cwd}\x1b[0m$ `;

// Die Ersatz-Dateisysteme fragen hier nach, welcher Host hinter einem Ort steckt.
registerPlaces((place) => {
  if (place.kind === 'host') {
    const host = store?.hosts.find((h) => h.id === place.id);
    if (host?.protocol === 'ftp') return { key: `ftp:${host.name}`, label: host.name, user: host.ftp?.anonymous ? 'anonymous' : (host.own.user ?? 'ftp'), ftp: true, locked: !ftpOpened.has(host.id) };
    return host ? { key: host.name, label: host.name, user: userOf(host) } : null;
  }
  if (place.kind === 'ftp') return { key: `ftp:${place.user}@${place.host}`, label: place.host, user: place.user || 'anonymous', ftp: true, locked: !ftpOpened.has(`direct:${place.user}@${place.host}:${place.port}`) };
    const s = place.kind === 'session' ? live.get(place.id) : undefined;
  return s && s.stage === 'shell' ? { key: s.name, label: s.name, user: s.user } : null;
});

// Der Ersatz-Abgleich legt Beispiel-Hosts in geteilten Tresoren an und räumt sie wieder weg.
registerProxmox({
  hosts: () => store?.hosts ?? [],
  keyNamed: (name) => (store?.keys ?? []).find((key) => key.name === name)?.id,
  identityNamed: (name) => (store?.identities ?? []).find((identity) => identity.name === name)?.id,
  save: (input) => fake.hostSave(input),
  changed: () => changed(),
});

registerSync({
  addHosts: (vault, hosts) => {
    if (!store) return;
    for (const [name, address, os] of hosts) store.hosts.push({ id: newId(), vault, name, address, group: null, protocol: 'ssh', color: null, os, own: {}, hasPassword: false, ...(name.startsWith('pve') ? { password: 'beispiel' } : {}) });
  },
  dropVault: (vault) => {
    if (!store) return;
    store.hosts = store.hosts.filter((h) => h.vault !== vault);
    store.groups = store.groups.filter((g) => g.vault !== vault);
  },
  changed: () => {
    if (!store || !open) return;
    persist();
    emitChanged(snapshot());
  },
  password: () => store?.password ?? null,
});

// Port-Regeln, Snippets auf Hosts und die Server-Info fragen hier nach Hosts, Regeln und laufenden Ersatz-Sitzungen.
registerTools({
  host: (id) => {
    const host = store?.hosts.find((h) => h.id === id);
    return host ? { name: host.name, address: host.address, os: host.os, silent: signsIn(host) } : null;
  },
  forward: (id) => store?.forwards?.find((f) => f.id === id) ?? null,
  session: (id) => {
    const s = live.get(id);
    return s && s.stage === 'shell' ? { name: s.name, os: store?.hosts.find((h) => h.id === s.hostId)?.os ?? null } : null;
  },
  emit: (event) => emitSession(event),
});

/** Werte eines Hosts samt denen seiner Gruppen, die nächste Ebene zuerst. */
function levels(host: Stored['hosts'][number]): Fields[] {
  const out = [host.own];
  for (let g = store?.groups.find((x) => x.id === host.group); g && out.length < 20; g = store?.groups.find((x) => x.id === g!.parent)) out.push(g.defs);
  return out;
}

/** Meldet sich der Host ohne Rückfrage an? Mit gespeichertem Passwort, einem Schlüssel aus dem Tresor oder einer Identität, die eines von beiden mitbringt. */
function signsIn(host: Stored['hosts'][number]): boolean {
  if (host.password) return true;
  const fields = levels(host);
  if (fields.find((f) => f.key !== undefined)?.key) return true;
  const identity = store?.identities?.find((i) => i.id === fields.find((f) => f.identity !== undefined)?.identity);
  return !!identity && (!!identity.key || !!identity.password);
}

function userOf(host: Stored['hosts'][number]): string {
  const fields = levels(host);
  const identity = store?.identities?.find((i) => i.id === fields.find((f) => f.identity !== undefined)?.identity);
  return fields.find((f) => f.user)?.user ?? identity?.user ?? 'root';
}

/** Antworten der Ersatz-Shell auf ein paar Befehle, damit ein Terminal in der Vorschau nach etwas aussieht. */
function reply(id: number, s: FakeLive, line: string): string {
  const place = { kind: 'session', id } as const;
  if (line === 'cd' || line.startsWith('cd ')) {
    const moved = shellCd(place, s.cwd, line.slice(2).trim());
    if ('error' in moved) return `-bash: cd: ${line.slice(2).trim()}: ${moved.error}\r\n`;
    s.cwd = moved.cwd;
    emitSession({ id, type: 'cwd', path: s.cwd });
    return '';
  }
  switch (line) {
    case '':
      return '';
    case 'pwd':
      return `${s.cwd}\r\n`;
    case 'ls':
    case 'ls -a':
    case 'ls -la': {
      const names = shellLs(place, s.cwd, line !== 'ls');
      return names ? `${names}\r\n` : '';
    }
    case 'whoami':
      return `${s.user}\r\n`;
    case 'hostname':
      return `${s.name}\r\n`;
    case 'uptime':
      return ` 17:42:08 up ${7 + (s.name.length % 30)} days,  3:1${s.name.length % 10},  1 user,  load average: 0.${12 + s.name.length}, 0.18, 0.15\r\n`;
    case 'df -h /':
      return `Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        78G   ${20 + s.name.length}G   5${s.name.length % 10}G  ${30 + s.name.length}% /\r\n`;
    case 'systemctl is-active nginx':
      return '\x1b[32mactive\x1b[0m\r\n';
    case 'df -h':
      return `Filesystem      Size  Used Avail Use% Mounted on\r\n/dev/sda1        79G   ${20 + s.name.length}G   ${55 - s.name.length}G  ${27 + s.name.length}% /\r\n/dev/sdb1       197G  1${40 + s.name.length}G   ${45 - s.name.length}G  \x1b[33m${72 + s.name.length}%\x1b[0m /var/lib/docker\r\ntmpfs           3.9G     0  3.9G   0% /dev/shm\r\n`;
    case 'docker ps':
      return 'CONTAINER ID   IMAGE              STATUS        NAMES\r\n4f1c9a2e7b10   nginx:1.27         \x1b[32mUp 3 days\x1b[0m     web\r\na83e5510cc2d   node:22-alpine     \x1b[32mUp 3 days\x1b[0m     app\r\n0c7d2f9be471   redis:7            \x1b[32mUp 3 days\x1b[0m     cache\r\n';
    case 'git pull --ff-only':
      return 'Already up to date.\r\n';
    case 'docker compose up -d':
      return '[+] Running 3/3\r\n \x1b[32m✔\x1b[0m Container web    Running\r\n \x1b[32m✔\x1b[0m Container app    Running\r\n \x1b[32m✔\x1b[0m Container cache  Running\r\n';
    default:
      if (/^sudo systemctl (restart|reload) \S+$/.test(line)) return '';
      if (/^(sudo )?docker logs /.test(line))
        return [
          '2026-10-12T09:41:07Z  info  listening on :3000',
          '2026-10-12T09:41:07Z  info  connected to postgres://shop-db:5432/shop',
          '2026-10-12T09:41:12Z  info  GET /healthz 200 2ms',
          '2026-10-12T09:41:19Z  info  GET /api/products?page=2 200 41ms',
          '2026-10-12T09:41:21Z  \x1b[33mwarn\x1b[0m  slow query (812ms): SELECT * FROM orders WHERE …',
          '2026-10-12T09:41:22Z  info  POST /api/cart 201 18ms',
          '2026-10-12T09:41:27Z  info  GET /healthz 200 1ms',
          '',
        ].join('\r\n');
      if (/^(sudo )?journalctl /.test(line))
        return [
          'Oct 12 09:40:58 web-01 systemd[1]: Starting nginx.service - A high performance web server…',
          'Oct 12 09:40:58 web-01 systemd[1]: Started nginx.service - A high performance web server.',
          'Oct 12 09:41:12 web-01 nginx[812]: 10.0.10.4 - - "GET / HTTP/2.0" 200 5124',
          '',
        ].join('\r\n');
      if (/^(sudo )?docker exec /.test(line)) return 'root@aa11bb22cc33:/app# ';
      return `-bash: ${line.split(' ')[0]}: command not found\r\n`;
  }
}
const FINGERPRINT = 'SHA256:9bTfK2xQm0Lr2QvorschauNurZumAnsehen4kPz';

function shellStart(id: number) {
  const s = live.get(id);
  if (!s) return;
  s.stage = 'shell';
  s.home = s.cwd = shellHome({ kind: 'session', id });
  emitSession({ id, type: 'phase', phase: 'connected' });
  if (s.mosh.wanted) {
    s.mosh.on = s.name !== 'pihole';
    emitSession(s.mosh.on ? { id, type: 'mosh', state: 'active' } : { id, type: 'mosh', state: 'fallback', reason: 'missing' });
  }
  // Ein Startbefehl, der nur den Ordner wechselt, wirkt auch in der Vorschau.
  const host = store?.hosts.find((h) => h.id === s.hostId);
  const start = host ? levels(host).find((f) => f.startcmd !== undefined)?.startcmd : undefined;
  const moved = start?.startsWith('cd ') ? shellCd({ kind: 'session', id }, s.cwd, start.slice(3).trim()) : null;
  if (moved && 'cwd' in moved) s.cwd = moved.cwd;
  emitSession({ id, type: 'cwd', path: s.cwd });
  // Englisch (für die Bilder der README) wie ein echter Server, sonst mit den Befehlen, die die Vorschau kennt.
  const english = JSON.parse(localStorage.getItem('glowport.settings') ?? '{}')?.lang === 'en';
  const hello = english ? 'Last login: Tue Oct 13 09:12:44 2026 from 10.0.0.2' : 'Willkommen in der Vorschau. Befehle: ls, cd, pwd, uptime, whoami, exit, drop';
  s.out(encoder.encode(`${hello}\r\n${promptOf(s)}`));
}

/** Stellt in der Vorschau einen Aussetzer unter Mosh nach: sechs Sekunden still, dann ist der Server wieder da. */
function moshDrop(id: number, s: FakeLive) {
  let silent = 0;
  const timer = setInterval(() => {
    if (!live.has(id)) return clearInterval(timer);
    silent += 1;
    if (silent <= 6) return emitSession({ id, type: 'reach', silent: silent >= 2 ? silent : null });
    clearInterval(timer);
    emitSession({ id, type: 'reach', silent: null });
    s.out(encoder.encode(`
${promptOf(s)}`));
  }, 1000);
}

function authenticate(id: number) {
  const s = live.get(id);
  if (!s) return;
  emitSession({ id, type: 'phase', phase: 'authenticating' });
  const host = store?.hosts.find((h) => h.id === s.hostId);
  if (host && signsIn(host)) return void setTimeout(() => shellStart(id), 200);
  s.stage = 'secret';
  emitSession({ id, type: 'secret', kind: 'password', attempt: 1, file: null, canSave: !!s.hostId });
}

/** Sitzungen ohne SSH: lokales Terminal, Telnet, serielle Leitung. Sie kennen weder Schlüssel noch Rückfragen. */
const devices = new Map<number, Device>();

function openDevice(what: DeviceKind, out: (bytes: Uint8Array) => void): number {
  const id = ++sessionSeq;
  setTimeout(() => devices.has(id) && emitSession({ id, type: 'phase', phase: 'connecting' }), 20);
  const device = startDevice(what, {
    out: (text) => devices.has(id) && out(encoder.encode(text)),
    connected: () => emitSession({ id, type: 'phase', phase: 'connected' }),
    end: (reason, message, exitStatus) => {
      devices.get(id)?.stop();
      if (devices.delete(id)) (stopLog(id), emitSession({ id, type: 'end', reason, message: message ?? null, exitStatus: exitStatus ?? null }));
    },
  });
  devices.set(id, device);
  return id;
}

export const fakeSession = {
  listen:(handler: (event: SessionEvent) => void) => ((emitSession = handler), () => {}),
  onChanged: (handler: (data: Snapshot) => void) => ((emitChanged = handler), () => {}),
  shells: () => later(() => FAKE_SHELLS),
  ports: () => later(() => FAKE_PORTS),
  open: (target: Target, out: (bytes: Uint8Array) => void) =>
    later(() => {
      if (target.kind === 'local') return openDevice({ kind: 'local', shell: FAKE_SHELLS.find((shell) => shell.id === target.shell) ?? fail('shell_missing') }, out);
      if (target.kind === 'telnet') return openDevice({ kind: 'telnet', name: target.host, address: target.host, user: '' }, out);
      const found = target.kind === 'host' ? store?.hosts.find((h) => h.id === target.id) : null;
      if (found?.protocol === 'telnet') return openDevice({ kind: 'telnet', name: found.name, address: found.address, user: found.own.user ?? '' }, out);
      if (found?.protocol === 'serial') return openDevice({ kind: 'serial', name: found.name.split('-')[0], port: found.address, settings: found.serial! }, out);
      const id = ++sessionSeq;
      const host = target.kind === 'host' ? (found?.address ?? fail('not_found')) : target.host;
      const port = target.kind === 'host' ? (found?.own.port ?? 22) : target.port;
      const user = target.kind === 'direct' ? target.user : userOf(found!);
      const mosh = target.kind === 'direct' ? !!target.mosh : !!found && !!levels(found).find((f) => f.mosh !== undefined)?.mosh;
      live.set(id, { out, line: '', host, port, hostId: found?.id ?? null, user, name: found?.name ?? 'vorschau', stage: 'hostKey', cwd: '/', home: '/', mosh: { wanted: mosh, on: false } });
      setTimeout(() => {
        emitSession({ id, type: 'phase', phase: 'connecting' });
        if (host.startsWith('0.')) return void (live.delete(id), emitSession({ id, type: 'end', reason: 'connect_failed', message: 'timed out', exitStatus: null }));
        // Die mitgelieferten Beispiel-Hosts gelten als bekannt; gefragt wird bei eingetippten Adressen und selbst angelegten Hosts.
        const known = (store?.knownHosts ?? []).some((k) => k.host === host && k.port === port) || (!!found && signsIn(found));
        if (known) return authenticate(id);
        emitSession({ id, type: 'hostKey', host, port, algorithm: 'ssh-ed25519', fingerprint: FINGERPRINT, changed: false, known: [] });
      }, 150);
      return id;
    }),
  fsConnect: (hostId: string) =>
    later(() => {
      const host = store?.hosts.find((h) => h.id === hostId) ?? fail('not_found');
      if (host.protocol !== 'ftp') fail('not_supported');
      const id = ++sessionSeq;
      ftpLinks.set(id, { host: host.id, plainOk: false });
      setTimeout(() => (emitSession({ id, type: 'phase', phase: 'connecting' }), ftpStep(id)), 150);
      return id;
    }),
  /** Ein FTP-Server aus der Schnellverbindung: erst die Warnung (unverschlüsselt) oder das Zertifikat, dann steht er. */
  ftpConnect: (place: FtpPlace) =>
    later(() => {
      const id = ++sessionSeq;
      const key = `direct:${place.user}@${place.host}:${place.port}`;
      ftpDirect.set(id, key);
      setTimeout(() => {
        emitSession({ id, type: 'phase', phase: 'connecting' });
        if (place.security === 'none') emitSession({ id, type: 'plain', host: place.host, offersTls: place.host.startsWith('ftp.'), canRemember: false });
        else emitSession({ id, type: 'certificate', host: place.host, port: place.port, fingerprint: FTP_FINGERPRINT, changed: false });
      }, 150);
      return id;
    }),
  answer: (id: number, answer: Answer) =>
    later(() => {
      const direct = ftpDirect.get(id);
      if (direct) {
        ftpDirect.delete(id);
        const accepted = (answer.kind === 'plain' || answer.kind === 'certificate') && answer.accept;
        if (!accepted) return emitSession({ id, type: 'end', reason: answer.kind === 'certificate' ? 'certificate_rejected' : 'user', message: null, exitStatus: null });
        ftpOpened.add(direct);
        return emitSession({ id, type: 'phase', phase: 'connected' });
      }
      const ftp = ftpLinks.get(id);
      if (ftp) {
        const host = store?.hosts.find((h) => h.id === ftp.host);
        const stop = (reason: string) => (ftpLinks.delete(id), emitSession({ id, type: 'end', reason, message: null, exitStatus: null }));
        if (!host) return stop('connect_failed');
        if (answer.kind === 'certificate') {
          if (!answer.accept) return stop('certificate_rejected');
          ftpTrusted.add(host.id);
        } else if (answer.kind === 'plain') {
          if (!answer.accept) return stop('user');
          ftp.plainOk = true;
          if (answer.secure || answer.remember) {
            host.ftp = answer.secure ? { ...(host.ftp ?? { anonymous: false }), security: 'explicit', plainOk: undefined } : { ...(host.ftp ?? { anonymous: false, security: 'none' }), plainOk: true };
            persist();
            emitChanged(snapshot());
          }
        }
        return ftpStep(id);
      }
      // Die Nummer kann auch zu einer Port-Regel gehören, die gerade verbindet.
      if (fakeForwards.answer(id, answer)) return;
      const s = live.get(id);
      if (!s) return;
      const end = (reason: string) => (live.delete(id), emitSession({ id, type: 'end', reason, message: null, exitStatus: null }));
      if (answer.kind === 'hostKey') {
        if (!answer.accept) return end('host_key_rejected');
        if (store && open) {
          store.knownHosts = [...(store.knownHosts ?? []), { id: newId(), host: s.host, port: s.port, algorithm: 'ssh-ed25519', fingerprint: FINGERPRINT, addedAt: Date.now() }];
          persist();
          emitChanged(snapshot());
        }
        return authenticate(id);
      }
      if (answer.kind === 'secret') {
        if (answer.value === undefined) return end('user');
        if (answer.value === 'falsch') return emitSession({ id, type: 'secret', kind: 'password', attempt: 2, file: null, canSave: !!s.hostId });
        const host = store?.hosts.find((h) => h.id === s.hostId);
        if (answer.save && host && open) {
          host.password = answer.value;
          persist();
          emitChanged(snapshot());
        }
        shellStart(id);
      }
    }),
  write: (id: number, text: string) =>
    Promise.resolve().then(() => {
      const device = devices.get(id);
      if (device) return device.write(text);
      const s = live.get(id);
      if (!s || s.stage !== 'shell') return;
      // Pfeiltasten und andere Tastenfolgen kennt die Ersatz-Shell nicht.
      if (text.startsWith('\x1b')) return;
      for (const ch of text) {
        if (ch === '\r') {
          const line = s.line.trim();
          s.line = '';
          if (line === 'exit') return void (s.out(encoder.encode('\r\nlogout\r\n')), live.delete(id), stopLog(id), emitSession({ id, type: 'end', reason: 'remote', message: null, exitStatus: 0 }));
          // Über Mosh übersteht die Sitzung den Abriss: ein paar Sekunden ohne Server, dann geht es weiter.
          if (line === 'drop' && s.mosh.on) return void moshDrop(id, s);
          if (line === 'drop') return void (live.delete(id), stopLog(id), emitSession({ id, type: 'end', reason: 'connection_lost', message: null, exitStatus: null }));
          s.out(encoder.encode(`\r\n${reply(id, s, line)}${promptOf(s)}`));
        } else if (ch === '\x7f') {
          if (s.line) ((s.line = s.line.slice(0, -1)), s.out(encoder.encode('\b \b')));
        } else if (ch === '\x15') {
          // Strg+U leert die Zeile.
          s.out(encoder.encode('\b \b'.repeat(s.line.length)));
          s.line = '';
        } else if (ch === '\x03') {
          s.line = '';
          s.out(encoder.encode(`^C\r\n${promptOf(s)}`));
        } else if (ch < ' ') {
          // Tab und andere Steuerzeichen: nichts.
        } else {
          s.line += ch;
          s.out(encoder.encode(ch));
        }
      }
    }),
  close: (id: number) =>
    Promise.resolve().then(() => {
      if (fakeForwards.close(id)) return;
      if (ftpLinks.delete(id) || ftpDirect.delete(id)) return emitSession({ id, type: 'end', reason: 'user', message: null, exitStatus: null });
      devices.get(id)?.stop();
      if (live.delete(id) || devices.delete(id)) (stopLog(id), emitSession({ id, type: 'end', reason: 'user', message: null, exitStatus: null }));
    }),
  record: (id: number, on: boolean, name: string, address: string) =>
    Promise.resolve().then(() => {
      if (!on) return stopLog(id);
      if (runningLog.has(id) || !(live.has(id) || devices.has(id))) return;
      const entry: Recording = { id: newId(), name, address, startedAt: Date.now(), endedAt: null, bytes: 0, file: `${LOG_DIR}${name}.log` };
      recordings.push(entry);
      runningLog.set(id, entry.id);
    }),
};
