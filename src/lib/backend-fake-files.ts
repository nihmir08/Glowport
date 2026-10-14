// Stand-in file systems and stand-in transfers for the browser preview. Like backend-fake.ts never part of the program.
// Every host gets the same small sample tree on first access; “This PC” one of its own.

import type { BackendError, ChmodRequest, DiffEntry, FileContent, FileEntry, FileKind, Listing, Place, SearchHit, Transfer, TransferRequest, Watched } from './types';

interface Node {
  name: string;
  kind: FileKind;
  size: number;
  modified: number;
  mode: number;
  owner: string;
  group: string;
  children?: Node[];
  text?: string;
  target?: string;
}

/** Where a location leads in the preview: which tree, under which name, as which user. */
export interface Resolved {
  key: string;
  label: string;
  user: string;
  /** An FTP server: web space instead of a whole Linux, without permissions and owners. */
  ftp?: boolean;
  /** Not connected yet: the prompts first (certificate, unencrypted). */
  locked?: boolean;
}

let resolve: (place: Place) => Resolved | null = () => null;
/** backend-fake.ts tells here which host is behind a location. */
export const registerPlaces = (resolver: (place: Place) => Resolved | null) => void (resolve = resolver);

const fail = (code: string, reason?: string): never => {
  throw { code, reason, message: `${code}${reason ? `: ${reason}` : ''}` } satisfies BackendError;
};
const later = <T>(work: () => T, ms = 140): Promise<T> =>
  new Promise((ok, no) =>
    setTimeout(() => {
      try {
        ok(work());
      } catch (e) {
        no(e);
      }
    }, ms),
  );

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const KB = 1024;
const MB = KB * KB;
const now = Date.now();

const NGINX = `user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Protokolle
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
`;

const SITE = `server {
    listen 443 ssl http2;
    server_name app.example.org;

    root /var/www/app/public;
    index index.html;

    ssl_certificate     /etc/letsencrypt/live/app.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.org/privkey.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
`;

const CONFIG = `# Einstellungen der Anwendung
server:
  port: 3000
  host: 127.0.0.1
  workers: 4

database:
  host: db-01.internal
  port: 5432
  name: app_production
  pool: 20

cache:
  driver: redis
  url: redis://10.0.20.31:6379/0
  ttl: 3600

logging:
  level: info
  file: storage/logs/app.log
`;

const BACKUP = `#!/usr/bin/env bash
set -euo pipefail

TARGET="/srv/backup/$(date +%F)"
mkdir -p "$TARGET"

echo "Sichere Datenbank ..."
pg_dump app_production | gzip > "$TARGET/db.sql.gz"

echo "Sichere Dateien ..."
tar -czf "$TARGET/www.tar.gz" -C /var/www app

# Alles löschen, was älter als 14 Tage ist
find /srv/backup -maxdepth 1 -type d -mtime +14 -exec rm -rf {} +
echo "Fertig: $TARGET"
`;

const APPLOG = Array.from({ length: 60 }, (_, i) => {
  const time = new Date(now - (60 - i) * 47_000).toISOString().replace('T', ' ').slice(0, 19);
  const kind = i % 17 === 9 ? 'ERROR' : i % 7 === 3 ? 'WARN ' : 'INFO ';
  const text =
    kind === 'ERROR'
      ? 'db: connection reset by peer (db-01.internal:5432), retry 1/3'
      : kind === 'WARN '
        ? `cache: slow response ${180 + i * 3} ms for key session:${4000 + i}`
        : `GET /api/orders/${1200 + i} 200 ${12 + (i % 9)} ms`;
  return `${time} ${kind} ${text}`;
}).join('\n');

const APPJS = `import { createServer } from './server.js';
import { loadConfig } from './config.js';

const config = await loadConfig('config.yaml');
const server = createServer(config);

server.listen(config.server.port, config.server.host, () => {
  console.log(\`Läuft auf \${config.server.host}:\${config.server.port}\`);
});
`;

const README = `# app

Kleine Beispielanwendung der Vorschau.

- \`config.yaml\` – Einstellungen
- \`public/\` – ausgelieferte Dateien
- \`storage/logs\` – Protokolle
`;

const LOGO = `data:image/svg+xml;utf8,${encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 480 300"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FE9803"/><stop offset="1" stop-color="#FF2E63"/></linearGradient></defs><rect width="480" height="300" rx="28" fill="#12121c"/><circle cx="150" cy="150" r="74" fill="url(#g)"/><path d="M118 150l22 22 44-46" fill="none" stroke="#12121c" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/><text x="250" y="165" font-family="Segoe UI, sans-serif" font-size="54" font-weight="700" fill="#f3f3f8">app</text></svg>',
)}`;

type Extra = Partial<Pick<Node, 'mode' | 'owner' | 'group' | 'modified' | 'target'>>;
let stamp = 0;
/** Every file gets a fixed time of its own, so the list looks like something. */
const age = () => now - ((++stamp * 37) % 400) * HOUR - stamp * 3 * MIN;

function dir(name: string, children: Node[], extra: Extra = {}): Node {
  return { name, kind: 'dir', size: 4096, modified: age(), mode: 0o755, owner: 'root', group: 'root', children, ...extra };
}
function file(name: string, content: number | string, extra: Extra = {}): Node {
  const text = typeof content === 'string' ? content : undefined;
  return { name, kind: 'file', size: text === undefined ? (content as number) : new TextEncoder().encode(text).length, modified: age(), mode: 0o644, owner: 'root', group: 'root', text, ...extra };
}
/** Gives a subtree an owner. */
function owned(node: Node, owner: string, group = owner): Node {
  node.owner = owner;
  node.group = group;
  node.children?.forEach((child) => owned(child, owner, group));
  return node;
}

function appTree(): Node[] {
  // Local and on the server the same state: the times start at the same point every time.
  stamp = 200;
  return [
    dir('public', [file('index.html', 2 * KB + 310), file('style.css', 14 * KB), file('logo.png', 48 * KB), file('favicon.ico', 15 * KB)]),
    dir('releases', [dir('2026-09-18', []), dir('2026-09-29', []), dir('2026-10-04', [])]),
    dir('storage', [dir('logs', [file('app.log', APPLOG), file('app.log.1', 3 * MB + 420 * KB), file('worker.log', 812 * KB)]), dir('uploads', [])]),
    file('.env', 'APP_ENV=production\nAPP_KEY=nur-ein-beispiel\nDB_PASSWORD=nur-ein-beispiel\n', { mode: 0o600 }),
    file('app.js', APPJS, { modified: now - 3 * HOUR }),
    file('config.yaml', CONFIG, { modified: now - 6 * DAY }),
    file('package.json', '{\n  "name": "app",\n  "version": "2.4.1",\n  "type": "module",\n  "scripts": { "start": "node app.js" }\n}\n'),
    file('README.md', README),
    file('server.js', 6 * KB + 120),
    { name: 'current', kind: 'link', size: 19, modified: now - 2 * DAY, mode: 0o777, owner: 'root', group: 'root', target: 'releases/2026-10-04' },
  ];
}

function remoteTree(user: string): Node {
  const home = user === 'root' ? null : owned(dir(user, [dir('.ssh', [file('authorized_keys', 412, { mode: 0o600 })], { mode: 0o700 }), file('.bashrc', 3771), file('.profile', 807), file('backup.sh', BACKUP, { mode: 0o755 }), file('notes.md', '# Maintenance\n\n- Certificate expires in December\n- Keep an eye on the disk of db-02\n')]), user);
  return dir('', [
    dir('etc', [
      dir('nginx', [dir('conf.d', []), dir('sites-enabled', [file('app.conf', SITE)]), file('mime.types', 5 * KB), file('nginx.conf', NGINX)]),
      dir('ssh', [file('sshd_config', 3 * KB + 289), file('ssh_host_ed25519_key', 411, { mode: 0o600 }), file('ssh_host_ed25519_key.pub', 96)]),
      file('fstab', '# <file system> <mount point> <type> <options> <dump> <pass>\nUUID=3f1c-77aa / ext4 errors=remount-ro 0 1\n'),
      file('hostname', 'vorschau\n'),
      file('hosts', '127.0.0.1 localhost\n10.0.20.21 db-01.internal\n10.0.20.22 db-02.internal\n'),
      file('os-release', 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\n'),
    ]),
    dir('home', home ? [home] : []),
    dir('opt', []),
    dir('root', [file('.bashrc', 3106)], { mode: 0o700 }),
    dir('srv', [owned(dir('backup', [file('backup-2026-10-04.tar.gz', 1480 * MB), file('backup-2026-10-05.tar.gz', 1496 * MB), file('db.sql.gz', 212 * MB)]), user)]),
    dir('tmp', [], { mode: 0o1777 }),
    dir('usr', [dir('bin', []), dir('lib', []), dir('local', []), dir('share', [])]),
    dir('var', [
      dir('log', [dir('nginx', [file('access.log', 18 * MB + 77 * KB), file('error.log', 240 * KB)]), file('auth.log', 96 * KB), file('syslog', 2 * MB + 610 * KB)]),
      dir('www', [owned(dir('app', appTree()), user, 'www-data'), dir('html', [file('index.nginx-debian.html', 615)])]),
    ]),
  ]);
}

/** Web space as a hoster shows it over FTP. */
function ftpTree(user: string): Node {
  return owned(
    dir('', [
      dir('htdocs', [
        dir('css', [file('style.css', 18 * KB)]),
        dir('img', [file('logo.svg', 4 * KB), file('titelbild.jpg', 840 * KB), file('team.jpg', 1 * MB + 220 * KB)]),
        dir('downloads', [file('preisliste-2026.pdf', 310 * KB)]),
        file('index.html', '<!doctype html>\n<title>Willkommen</title>\n<h1>Es funktioniert</h1>\n'),
        file('kontakt.html', 6 * KB),
        file('.htaccess', 'Options -Indexes\nErrorDocument 404 /404.html\n'),
        file('robots.txt', 'User-agent: *\nAllow: /\n'),
      ]),
      dir('logs', [file('access.log', 12 * MB), file('error.log', 96 * KB)]),
      dir('backup', [file('site-2026-10-01.zip', 240 * MB)]),
    ]),
    user,
  );
}

function localTree(): Node {
  const mine = appTree().filter((n) => !['.env', 'storage', 'releases', 'current'].includes(n.name));
  // For syncing: locally a newer settings file, an older app.js and a file that does not exist on the server.
  const config = mine.find((n) => n.name === 'config.yaml')!;
  config.text = CONFIG.replace('workers: 4', 'workers: 8').replace('level: info', 'level: debug');
  config.size = config.text.length;
  config.modified = now - 40 * MIN;
  mine.find((n) => n.name === 'app.js')!.modified = now - 9 * DAY;
  (mine.find((n) => n.name === 'public')!.children ??= []).push(file('neu.css', 3 * KB + 40, { modified: now - 25 * MIN }));
  const pc = dir('', [
    dir('C:', [
      dir('Users', [
        dir('ich', [
          dir('Desktop', [file('Rechnung-0931.pdf', 184 * KB), file('server-liste.xlsx', 22 * KB)]),
          dir('Documents', [dir('Verträge', []), file('notizen.txt', 'Einkaufen\nServer aufräumen\n')]),
          dir('Downloads', [file('debian-13.1-amd64-netinst.iso', 702 * MB), file('glowport-logo.png', 96 * KB), file('putty-export.reg', 9 * KB), file('ubuntu-24.04-live-server-amd64.iso', 2610 * MB)]),
          dir('Projekte', [dir('app', mine), dir('dotfiles', [file('.vimrc', 1220), file('.tmux.conf', 2204)]), dir('website', [dir('bilder', Array.from({ length: 48 }, (_, i) => file(`foto-${String(i + 1).padStart(3, '0')}.jpg`, 180 * KB + ((i * 7919) % (240 * KB))))), file('index.html', 5 * KB)])]),
        ]),
      ]),
    ]),
    dir('D:', [dir('Backups', []), dir('Spiele', [])]),
  ]);
  return owned(pc, 'ich');
}

const trees = new Map<string, Node>();
function treeOf(place: Place): { root: Node; local: boolean; where: Resolved } {
  if (place.kind === 'local') {
    if (!trees.has('local')) trees.set('local', localTree());
    return { root: trees.get('local')!, local: true, where: { key: 'local', label: 'Dieser PC', user: 'ich' } };
  }
  const where = resolve(place) ?? fail(place.kind === 'session' ? 'not_connected' : 'not_found');
  if (where.locked) fail('files_auth');
  if (!trees.has(where.key)) trees.set(where.key, where.ftp ? ftpTree(where.user) : remoteTree(where.user));
  return { root: trees.get(where.key)!, local: false, where };
}

const parts = (path: string, local: boolean) => path.split(local ? /[\\/]+/ : /\/+/).filter(Boolean);
const join = (names: string[], local: boolean) => (local ? (names.length === 1 ? `${names[0]}\\` : names.join('\\')) : `/${names.join('/')}`);

/** Walks along a path. Returns the nodes from the first piece to the target. */
function walk(root: Node, path: string, local: boolean): Node[] {
  const trail: Node[] = [];
  let at = root;
  for (const name of parts(path, local)) {
    if (name === '.') continue;
    if (name === '..') {
      trail.pop();
      at = trail[trail.length - 1] ?? root;
      continue;
    }
    const next = at.children?.find((child) => (local ? child.name.toLowerCase() === name.toLowerCase() : child.name === name)) ?? fail('no_such_file', path);
    trail.push(next);
    at = next;
  }
  return trail;
}
const nodeAt = (root: Node, path: string, local: boolean) => walk(root, path, local).at(-1) ?? root;

/** May this user write here? Roughly: their own property, /tmp, and root everywhere. */
function writable(trail: Node[], where: Resolved, local: boolean): boolean {
  if (local) return trail.length > 0;
  if (where.user === 'root') return true;
  const at = trail.at(-1);
  return !!at && (at.owner === where.user || (at.mode & 0o002) !== 0);
}

function entryOf(node: Node, dirPath: string[], local: boolean): FileEntry {
  return { name: node.name, path: join([...dirPath, node.name], local), kind: node.kind, size: node.kind === 'dir' ? 0 : node.size, modified: node.modified, mode: local ? null : node.mode, owner: node.owner, group: node.group, target: node.target };
}

function listing(place: Place, path: string): Listing {
  const { root, local, where } = treeOf(place);
  const trail = walk(root, path, local);
  const at = trail.at(-1) ?? root;
  if (at.kind !== 'dir') fail('not_a_directory', path);
  if (!local && at.name === 'root' && trail.length === 1 && where.user !== 'root') fail('permission_denied', path);
  const names = trail.map((n) => n.name);
  return {
    path: names.length ? join(names, local) : local ? '' : '/',
    crumbs: [{ name: local ? '' : '/', path: local ? '' : '/' }, ...names.map((name, i) => ({ name, path: join(names.slice(0, i + 1), local) }))],
    parent: names.length ? (names.length === 1 ? (local ? '' : '/') : join(names.slice(0, -1), local)) : null,
    entries: (at.children ?? []).map((child) => entryOf(child, names, local)),
    writable: writable(trail, where, local),
    ...(where.ftp ? { ftp: { chmod: false } } : {}),
  };
}

const homeOf = (place: Place) => {
  const { local, where } = treeOf(place);
  return local ? 'C:\\Users\\ich' : where.ftp ? '/' : where.user === 'root' ? '/root' : `/home/${where.user}`;
};

/** A path's folder and the name in it. */
function parentOf(place: Place, path: string) {
  const { root, local, where } = treeOf(place);
  const trail = walk(root, path, local);
  const node = trail.at(-1) ?? fail('no_such_file', path);
  const up = trail.slice(0, -1);
  return { node, parent: up.at(-1) ?? root, canWrite: writable(up, where, local), local };
}

const totals = (node: Node): { bytes: number; files: number } => (node.kind === 'dir' ? (node.children ?? []).map(totals).reduce((a, b) => ({ bytes: a.bytes + b.bytes, files: a.files + b.files }), { bytes: 0, files: 0 }) : { bytes: node.size, files: 1 });
const clone = (node: Node, owner: string): Node => ({ ...node, owner, group: owner, modified: node.modified, children: node.children?.map((child) => clone(child, owner)) });

const TEXTLIKE = /\.(txt|md|log|conf|cfg|ini|ya?ml|json|js|ts|css|html?|sh|env|py|php|sql|xml|toml|service|pub|reg)$|^\.[a-z_]+rc$|^(fstab|hosts|hostname|os-release|sshd_config|authorized_keys|\.env|\.profile|mime\.types)$/i;
const IMAGE = /\.(png|jpe?g|gif|webp|svg|ico|bmp)$/i;

function sample(node: Node): string {
  return node.text ?? `# ${node.name}\n# Beispielinhalt der Vorschau (${node.size} Bytes).\n`;
}

// ---------- Transfers ----------

interface Job extends Transfer {
  /** What appears in the target tree after the end. */
  land: () => void;
  /** Bytes per second at which the preview runs this transfer. */
  pace: number;
}

let jobs: Job[] = [];
let jobSeq = 0;
let emitTransfers: (list: Transfer[]) => void = () => {};
let timer: ReturnType<typeof setInterval> | null = null;
const PARALLEL = 3;
const TICK = 200;

const publicJob = ({ land: _land, pace: _pace, ...rest }: Job): Transfer => rest;
const transfers = () => jobs.map(publicJob);
const publish = () => emitTransfers(transfers());

function tick() {
  const running = jobs.filter((j) => j.state === 'running');
  for (const job of jobs) {
    if (running.length >= PARALLEL) break;
    if (job.state === 'queued') (job.state = 'running'), running.push(job);
  }
  for (const job of running) {
    if (job.error) {
      job.state = 'failed';
      job.speed = 0;
      continue;
    }
    const step = Math.round(job.pace * (TICK / 1000) * (0.85 + Math.random() * 0.3));
    job.done = Math.min(job.bytes, job.done + step);
    job.speed = step * (1000 / TICK);
    job.filesDone = job.bytes ? Math.min(job.files, Math.floor((job.done / job.bytes) * job.files)) : job.files;
    if (job.done >= job.bytes) {
      job.state = 'done';
      job.speed = 0;
      job.filesDone = job.files;
      job.land();
    }
  }
  publish();
  if (!jobs.some((j) => j.state === 'running' || j.state === 'queued') && timer) (clearInterval(timer), (timer = null));
}
const wake = () => void (timer ??= setInterval(tick, TICK));

function startTransfer(given: TransferRequest): number[] {
  // Without a destination folder, downloads land in the downloads folder.
  const request = given.to.kind === 'local' && !given.dest ? { ...given, dest: 'C:\Users\ich\Downloads' } : given;
  const from = treeOf(request.from);
  const to = treeOf(request.to);
  const destTrail = walk(to.root, request.dest, to.local);
  const destNode = destTrail.at(-1) ?? to.root;
  const allowed = writable(destTrail, to.where, to.local);
  const direction = request.from.kind === 'local' ? 'upload' : request.to.kind === 'local' ? 'download' : 'remote';
  const ids: number[] = [];
  for (const path of request.paths) {
    let node: Node;
    try {
      node = nodeAt(from.root, path, from.local);
    } catch {
      // Files dropped in the preview do not exist in the sample tree; they get a made-up size.
      const name = parts(path, true).at(-1) ?? 'datei';
      node = file(name, 200 * KB + ((name.length * 7919) % (6 * MB)), { owner: 'ich', modified: Date.now() });
    }
    const { bytes, files } = totals(node);
    const sep = (local: boolean) => (local ? '\\' : '/');
    const job: Job = {
      id: ++jobSeq,
      name: node.name,
      direction,
      // For this PC the path is enough; for a server its name comes before it.
      source: `${from.local ? '' : `${from.where.label}:`}${path}`,
      dest: `${to.local ? '' : `${to.where.label}:`}${request.dest}${request.dest.endsWith(sep(to.local)) ? '' : sep(to.local)}${node.name}`,
      bytes,
      done: 0,
      files,
      filesDone: 0,
      state: 'queued',
      speed: 0,
      error: allowed && (from.local || from.where.user === 'root' || node.owner === from.where.user || (node.mode & 0o004) !== 0) ? undefined : 'permission_denied',
      pace: files > 8 ? 2.4 * MB : bytes > 500 * MB ? 38 * MB : 9 * MB,
      land: () => {
        destNode.children = [...(destNode.children ?? []).filter((child) => child.name !== node.name), { ...clone(node, to.where.user), modified: node.modified }];
      },
    };
    jobs.push(job);
    ids.push(job.id);
  }
  wake();
  publish();
  return ids;
}

// ---------- Files open in another program ----------

let watched: Watched[] = [];
let emitWatched: (list: Watched[]) => void = () => {};

// ---------- Shell of the stand-in sessions ----------

/** `cd` of the stand-in shell: returns the new folder or an error message. */
export function shellCd(place: Place, cwd: string, arg: string): { cwd: string } | { error: string } {
  try {
    const target = !arg || arg === '~' ? homeOf(place) : arg.startsWith('/') ? arg : `${cwd}/${arg}`;
    return { cwd: listing(place, target).path };
  } catch (e) {
    return { error: (e as BackendError).code === 'permission_denied' ? 'Permission denied' : (e as BackendError).code === 'not_a_directory' ? 'Not a directory' : 'No such file or directory' };
  }
}
export const shellHome = (place: Place) => homeOf(place);
export function shellLs(place: Place, cwd: string, all: boolean): string {
  try {
    return listing(place, cwd)
      .entries.filter((e) => all || !e.name.startsWith('.'))
      .map((e) => (e.kind === 'dir' ? `\x1b[1;34m${e.name}\x1b[0m` : e.kind === 'link' ? `\x1b[1;36m${e.name}\x1b[0m` : e.mode && e.mode & 0o111 ? `\x1b[1;32m${e.name}\x1b[0m` : e.name))
      .join('  ');
  } catch {
    return '';
  }
}

// ---------- Was backend.ts aufruft ----------

export const fakeFiles = {
  home: (place: Place) => later(() => homeOf(place)),
  list: (place: Place, path: string) => later(() => listing(place, path), place.kind === 'local' ? 40 : 160),
  mkdir: (place: Place, dirPath: string, name: string) =>
    later(() => {
      const { root, local, where } = treeOf(place);
      const trail = walk(root, dirPath, local);
      const at = trail.at(-1) ?? root;
      if (!writable(trail, where, local)) fail('permission_denied', dirPath);
      if (!name.trim() || /[\\/]/.test(name)) fail('invalid', 'name_required');
      if (at.children?.some((child) => child.name === name)) fail('file_exists', name);
      (at.children ??= []).push({ ...dir(name, []), owner: where.user, group: where.user, modified: Date.now() });
    }),
  rename: (place: Place, path: string, name: string) =>
    later(() => {
      const { node, parent, canWrite } = parentOf(place, path);
      if (!canWrite) fail('permission_denied', path);
      if (!name.trim() || /[\\/]/.test(name)) fail('invalid', 'name_required');
      if (parent.children?.some((child) => child !== node && child.name === name)) fail('file_exists', name);
      node.name = name;
    }),
  remove: (place: Place, paths: string[]) =>
    later(() => {
      for (const path of paths) {
        const { node, parent, canWrite } = parentOf(place, path);
        if (!canWrite) fail('permission_denied', path);
        parent.children = parent.children?.filter((child) => child !== node);
      }
    }),
  chmod: (place: Place, request: ChmodRequest) =>
    later(() => {
      const { where, local } = treeOf(place);
      if (local) fail('not_supported');
      const apply = (node: Node) => {
        if (request.mode !== null) node.mode = node.kind === 'dir' ? request.mode : request.mode;
        if (request.owner) node.owner = request.owner;
        if (request.group) node.group = request.group;
        if (request.recursive) node.children?.forEach(apply);
      };
      for (const path of request.paths) {
        const { node } = parentOf(place, path);
        if (where.user !== 'root' && (node.owner !== where.user || (request.owner && request.owner !== node.owner))) fail('permission_denied', path);
        apply(node);
      }
    }, 260),
  read: (place: Place, path: string): Promise<FileContent> =>
    later(() => {
      const { root, local, where } = treeOf(place);
      const node = nodeAt(root, path, local);
      if (node.kind === 'dir') fail('is_a_directory', path);
      if (!local && where.user !== 'root' && node.owner !== where.user && (node.mode & 0o004) === 0) fail('permission_denied', path);
      if (IMAGE.test(node.name)) return { kind: 'image', url: LOGO } as const;
      if (!TEXTLIKE.test(node.name) || node.size > 4 * MB) return { kind: 'binary' } as const;
      return { kind: 'text', text: sample(node), truncated: false, editable: true } as const;
    }, 220),
  write: (place: Place, path: string, text: string) =>
    later(() => {
      const { root, local, where } = treeOf(place);
      const node = nodeAt(root, path, local);
      if (!local && where.user !== 'root' && node.owner !== where.user) fail('permission_denied', path);
      node.text = text;
      node.size = new TextEncoder().encode(text).length;
      node.modified = Date.now();
    }, 320),
  /** Searches below a folder by name or in content and reports every hit individually. */
  search: async (place: Place, dirPath: string, query: string, content: boolean, onHit: (hit: SearchHit) => void): Promise<void> => {
    const { root, local } = treeOf(place);
    const start = walk(root, dirPath, local);
    const word = query.trim().toLowerCase();
    if (!word) return;
    const found: SearchHit[] = [];
    const visit = (node: Node, names: string[]) => {
      for (const child of node.children ?? []) {
        const here = [...names, child.name];
        const hit = { path: join(here, local), name: child.name, dir: names.length ? join(names, local) : '/', kind: child.kind, size: child.size };
        if (!content && child.name.toLowerCase().includes(word)) found.push(hit);
        if (content && child.kind === 'file' && child.text) child.text.split('\n').forEach((line, i) => line.toLowerCase().includes(word) && found.push({ ...hit, line: i + 1, text: line.trim().slice(0, 200) }));
        if (child.kind === 'dir') visit(child, here);
      }
    };
    visit(start.at(-1) ?? root, start.map((n) => n.name));
    for (const hit of found.slice(0, 300)) {
      await new Promise((r) => setTimeout(r, 45));
      onHit(hit);
    }
  },
  /** Compares two folders including subfolders by size and modification time. */
  compare: (a: Place, pathA: string, b: Place, pathB: string): Promise<DiffEntry[]> =>
    later(() => {
      const left = treeOf(a);
      const right = treeOf(b);
      const out: DiffEntry[] = [];
      const side = (node: Node | undefined, names: string[], local: boolean) => (node ? { path: join(names, local), size: node.kind === 'dir' ? totals(node).bytes : node.size, modified: node.modified } : null);
      const visit = (l: Node | undefined, r: Node | undefined, lNames: string[], rNames: string[], rel: string) => {
        const names = [...new Set([...(l?.children ?? []), ...(r?.children ?? [])].map((n) => n.name))].sort((x, y) => x.localeCompare(y));
        for (const name of names) {
          const x = l?.children?.find((n) => n.name === name);
          const y = r?.children?.find((n) => n.name === name);
          const path = rel ? `${rel}/${name}` : name;
          const kind = (x ?? y)!.kind;
          if (x && y && kind === 'dir') {
            visit(x, y, [...lNames, name], [...rNames, name], path);
            continue;
          }
          const state = !y ? 'left' : !x ? 'right' : x.size === y.size && Math.abs(x.modified - y.modified) < 2000 ? 'same' : x.modified >= y.modified ? 'newerLeft' : 'newerRight';
          out.push({ rel: path, kind, state, left: side(x, [...lNames, name], left.local), right: side(y, [...rNames, name], right.local) });
        }
      };
      const lTrail = walk(left.root, pathA, left.local);
      const rTrail = walk(right.root, pathB, right.local);
      visit(lTrail.at(-1) ?? left.root, rTrail.at(-1) ?? right.root, lTrail.map((n) => n.name), rTrail.map((n) => n.name), '');
      return out;
    }, 700),

  transferStart: (request: TransferRequest) => later(() => startTransfer(request), 60),
  syncStart: (left: Place, leftPath: string, right: Place, rightPath: string, items: { rel: string; toRight: boolean }[]) =>
    later(() => {
      const ids: number[] = [];
      for (const item of items) {
        const [from, fromPath, to, toPath] = item.toRight ? [left, leftPath, right, rightPath] : [right, rightPath, left, leftPath];
        const names = item.rel.split('/');
        const under = (place: Place, base: string, rest: string[]) => {
          const local = place.kind === 'local';
          return join([...parts(base, local), ...rest], local);
        };
        ids.push(...startTransfer({ from, paths: [under(from, fromPath, names)], to, dest: under(to, toPath, names.slice(0, -1)), policy: 'overwrite', parallel: 4 }));
      }
      return ids;
    }, 60),
  transferList: () => Promise.resolve(transfers()),
  /** Pauses, resumes, cancels or retries; without numbers it applies to all. */
  transferControl: (ids: number[] | null, action: 'pause' | 'resume' | 'cancel' | 'retry') =>
    Promise.resolve().then(() => {
      for (const job of jobs) {
        if (ids && !ids.includes(job.id)) continue;
        if (action === 'pause' && (job.state === 'running' || job.state === 'queued')) (job.state = 'paused'), (job.speed = 0);
        if (action === 'resume' && job.state === 'paused') (job.state = 'queued'), (job.resumed = job.done > 0);
        if (action === 'cancel' && job.state !== 'done') (job.state = 'cancelled'), (job.speed = 0);
        if (action === 'retry' && (job.state === 'failed' || job.state === 'cancelled')) (job.state = 'queued'), (job.resumed = job.done > 0);
      }
      wake();
      publish();
    }),
  /** Clears everything finished, cancelled and failed from the list. */
  transferClear: () => Promise.resolve().then(() => ((jobs = jobs.filter((j) => j.state === 'running' || j.state === 'queued' || j.state === 'paused')), publish())),
  onTransfers: (handler: (list: Transfer[]) => void) => ((emitTransfers = handler), () => {}),

  watchOpen: (place: Place, path: string) =>
    later(() => {
      const { root, local, where } = treeOf(place);
      const node = nodeAt(root, path, local);
      watched = [...watched, { id: ++jobSeq, name: node.name, origin: `${where.label}:${path}`, uploads: 0, uploadedAt: null }];
      emitWatched(watched);
    }),
  watchStop: (id: number) => Promise.resolve().then(() => ((watched = watched.filter((w) => w.id !== id)), emitWatched(watched))),
  watchList: () => Promise.resolve(watched),
  onWatched: (handler: (list: Watched[]) => void) => ((emitWatched = handler), () => {}),
};
