// Ersatz für Port-Regeln, das Ausführen von Snippets auf Hosts und die Server-Info in der Vorschau im Browser.
// Nichts davon öffnet einen Port oder spricht mit einem Server; die Zahlen sind erfunden.

import type { Answer, Forward, ForwardState, RunResult, SessionEvent, StatsSample } from './types';

interface World {
  /** Ein Host aus dem Ersatz-Tresor. `silent`: meldet er sich ohne Rückfrage an? */
  host(id: string): { name: string; address: string; os: string | null; silent: boolean } | null;
  forward(id: string): Forward | null;
  /** Die Ersatz-Sitzung mit dieser Nummer, solange ihre Shell läuft. */
  session(id: number): { name: string; os: string | null } | null;
  /** Schickt ein Ereignis, wie es eine Verbindung an die Oberfläche schickt (Rückfragen, Ende). */
  emit(event: SessionEvent): void;
}

let world: World | null = null;
export const registerTools = (w: World) => (world = w);

const fail = (code: string, reason?: string): never => {
  throw { code, reason, message: `${code}${reason ? `: ${reason}` : ''}` };
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------- Port-Regeln ----------

const states = new Map<string, ForwardState>();
/** Verbindungen, die auf eine Antwort warten: Nummer der Verbindung → Regel. */
const asking = new Map<number, string>();
let connectionSeq = 100_000;
let emitForwards: (list: ForwardState[]) => void = () => {};
let ticker: ReturnType<typeof setInterval> | undefined;

const list = () => [...states.values()].map((s) => ({ ...s }));
const publish = () => emitForwards(list());

function run(id: string) {
  const state = states.get(id);
  const rule = world?.forward(id);
  if (!state || !rule) return;
  // Zwei Regeln können auf diesem PC nicht denselben Port belegen.
  const clash = rule.kind !== 'remote' && [...states.values()].some((s) => s.id !== id && s.phase === 'running' && world?.forward(s.id)?.kind !== 'remote' && world?.forward(s.id)?.bindPort === rule.bindPort);
  Object.assign(state, clash ? { phase: 'failed', error: 'port_in_use', message: null } : { phase: 'running', error: null, since: Date.now() });
  publish();
}

/** Lässt laufende Regeln nach Betrieb aussehen. */
function tick() {
  let changed = false;
  for (const state of states.values()) {
    if (state.phase !== 'running') continue;
    const busy = (state.id.charCodeAt(state.id.length - 1) + Math.floor(Date.now() / 4000)) % 3;
    if (Math.random() < 0.35) (state.open = Math.max(0, Math.min(4, state.open + (Math.random() < 0.55 ? 1 : -1)))), (changed = true);
    if (state.open || busy === 0) {
      state.total += Math.random() < 0.3 ? 1 : 0;
      state.sent += Math.round(Math.random() * 9_000);
      state.received += Math.round(Math.random() * 140_000);
      changed = true;
    }
  }
  if (changed) publish();
}

export const fakeForwards = {
  list: () => Promise.resolve(list()),
  onChange: (handler: (list: ForwardState[]) => void) => {
    emitForwards = handler;
    ticker ??= setInterval(tick, 1000);
    return () => {};
  },
  /** Schaltet eine Regel ein und liefert die Nummer der Verbindung, über die Rückfragen kommen. */
  start: async (id: string): Promise<number> => {
    const rule = world?.forward(id) ?? fail('not_found');
    const host = world?.host(rule.host) ?? fail('invalid', 'host_missing');
    const connection = ++connectionSeq;
    states.set(id, { id, phase: 'starting', error: null, message: null, open: 0, total: 0, sent: 0, received: 0, since: null });
    publish();
    setTimeout(() => {
      if (states.get(id)?.phase !== 'starting') return;
      if (host.silent) return (world?.emit({ id: connection, type: 'phase', phase: 'connected' }), run(id));
      asking.set(connection, id);
      world?.emit({ id: connection, type: 'secret', kind: 'password', attempt: 1, file: null, canSave: true });
    }, 550);
    return connection;
  },
  stop: async (id: string) => {
    states.delete(id);
    for (const [connection, rule] of asking) if (rule === id) asking.delete(connection);
    publish();
  },
  /** Eine Regel wurde gelöscht oder geändert: Sie läuft nicht weiter. */
  forget: (id: string) => {
    if (states.delete(id)) publish();
  },
  /** Beantwortet die Rückfrage einer Regel. Liefert false, wenn die Nummer zu keiner gehört. */
  answer: (connection: number, answer: Answer): boolean => {
    const id = asking.get(connection);
    if (!id) return false;
    const state = states.get(id);
    if (!state) return true;
    if (answer.kind === 'secret' && answer.value === 'falsch') {
      world?.emit({ id: connection, type: 'secret', kind: 'password', attempt: 2, file: null, canSave: true });
      return true;
    }
    asking.delete(connection);
    if (answer.kind === 'secret' && answer.value) {
      world?.emit({ id: connection, type: 'phase', phase: 'connected' });
      run(id);
    } else {
      states.delete(id);
      publish();
      world?.emit({ id: connection, type: 'end', reason: 'user', message: null, exitStatus: null });
    }
    return true;
  },
  /** Bricht einen Verbindungsaufbau ab, der noch auf eine Antwort wartet. */
  close: (connection: number): boolean => {
    const id = asking.get(connection);
    if (!id) return false;
    asking.delete(connection);
    states.delete(id);
    publish();
    return true;
  },
};

// ---------- Snippets auf Hosts ausführen ----------

const cancelled = new Set<number>();

/** Was ein Befehl in der Vorschau ausgibt. Bekannte Befehle sehen echt aus, der Rest nennt sich selbst. */
function output(command: string, name: string): { text: string; exit: number } {
  const n = name.length;
  const first = command.trim().split(/\s+/)[0];
  if (/^df\b/.test(command)) return { text: `Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        79G   ${20 + n}G   ${55 - n}G  ${27 + n}% /\n/dev/sdb1       197G  1${40 + n}G   ${45 - n}G  ${72 + n}% /var/lib/docker\ntmpfs           3.9G     0  3.9G   0% /dev/shm\n`, exit: 0 };
  if (/^uptime\b/.test(command)) return { text: ` 17:42:08 up ${7 + (n % 30)} days,  3:1${n % 10},  1 user,  load average: 0.${12 + n}, 0.18, 0.15\n`, exit: 0 };
  if (/^docker ps\b/.test(command)) return { text: `CONTAINER ID   IMAGE              STATUS        NAMES\n4f1c9a2e7b10   nginx:1.27         Up ${2 + (n % 5)} days     web\na83e5510cc2d   node:22-alpine     Up ${2 + (n % 5)} days     app\n0c7d2f9be471   redis:7            Up ${2 + (n % 5)} days     cache\n`, exit: 0 };
  if (/systemctl (restart|reload)/.test(command)) return name === 'lb-01' ? { text: `Failed to restart ${command.split(/\s+/).pop()}.service: Unit ${command.split(/\s+/).pop()}.service not found.\n`, exit: 5 } : { text: '', exit: 0 };
  if (/git pull/.test(command)) return { text: `From git.example.org:shop/app\n   9f3c1d2..b71e04a  main       -> origin/main\nUpdating 9f3c1d2..b71e04a\nFast-forward\n 2 files changed, 17 insertions(+), 8 deletions(-)\n[+] Running 3/3\n ✔ Container web    Started\n ✔ Container app    Started\n ✔ Container cache  Running\n`, exit: 0 };
  if (/^(whoami|id)\b/.test(command)) return { text: 'deploy\n', exit: 0 };
  if (/^hostname\b/.test(command)) return { text: `${name}\n`, exit: 0 };
  if (/^(apt|apt-get) /.test(command)) return { text: `Hit:1 http://deb.debian.org/debian trixie InRelease\nReading package lists... Done\nBuilding dependency tree... Done\n${n % 3} packages can be upgraded.\n`, exit: 0 };
  return { text: `bash: ${first}: command not found\n`, exit: 127 };
}

export const fakeRun = {
  /** Tut so, als liefe der Befehl auf jedem Host; drei gleichzeitig. */
  run: async (run: number, command: string, hosts: string[], onResult: (result: RunResult) => void): Promise<void> => {
    const queue = [...hosts];
    const worker = async () => {
      for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
        if (cancelled.has(run)) return void onResult({ host: id, state: 'failed', exit: null, output: '', error: 'cancelled', ms: 0 });
        onResult({ host: id, state: 'running', exit: null, output: '', ms: 0 });
        const ms = 350 + Math.round(Math.random() * 900);
        await sleep(ms);
        const host = world?.host(id);
        if (cancelled.has(run)) onResult({ host: id, state: 'failed', exit: null, output: '', error: 'cancelled', ms });
        else if (!host) onResult({ host: id, state: 'failed', exit: null, output: '', error: 'not_found', ms });
        else if (host.address.startsWith('10.0.20.')) onResult({ host: id, state: 'failed', exit: null, output: '', error: 'auth_failed', ms });
        else {
          const result = output(command, host.name);
          onResult({ host: id, state: 'done', exit: result.exit, output: result.text, ms });
        }
      }
    };
    await Promise.all([worker(), worker(), worker()]);
    cancelled.delete(run);
  },
  cancel: async (run: number) => void cancelled.add(run),
};

// ---------- Server-Info ----------

interface Counters {
  at: number;
  total: number;
  idle: number;
  rx: number;
  tx: number;
  started: number;
}
const counters = new Map<number, Counters>();
const GB = 1024 ** 3;
const SYSTEMS: Record<string, string> = { Ub: 'Ubuntu 24.04.1 LTS', De: 'Debian GNU/Linux 13 (trixie)', PVE: 'Proxmox VE 9.0', Rp: 'Raspberry Pi OS 12', Li: 'Linux' };

export const fakeStats = {
  sample: async (id: number): Promise<StatsSample | null> => {
    const session = world?.session(id);
    if (!session) return null;
    const now = Date.now();
    const seed = session.name.length;
    const cores = 4 + (seed % 3) * 2;
    const c = counters.get(id) ?? { at: now - 2000, total: 0, idle: 0, rx: 4.2e9, tx: 9.1e8, started: now };
    counters.set(id, c);
    const dt = Math.max(1, now - c.at);
    // Eine ruhige Welle mit gelegentlichen Spitzen, je Host etwas anders.
    const wave = Math.sin(now / 7000 + seed) * 0.5 + 0.5;
    const busy = Math.min(0.97, 0.08 + wave * 0.34 + Math.random() * 0.07 + (Math.floor(now / 23_000 + seed) % 5 === 0 ? 0.3 : 0));
    const ticks = (dt / 10) * cores;
    c.total += ticks;
    c.idle += ticks * (1 - busy);
    c.rx += (dt / 1000) * (180_000 + wave * 2_600_000 + Math.random() * 300_000);
    c.tx += (dt / 1000) * (40_000 + wave * 380_000 + Math.random() * 60_000);
    c.at = now;
    const memTotal = (cores >= 8 ? 32 : 16) * GB;
    return {
      at: now,
      cpu: { total: Math.round(c.total), idle: Math.round(c.idle) },
      cores,
      mem: { total: memTotal, available: memTotal * (0.58 - wave * 0.08), swapTotal: 2 * GB, swapFree: 2 * GB - 180 * 1024 ** 2 },
      load: [busy * cores * 0.6, 0.37 + seed / 40, 0.31 + seed / 50],
      disks: [
        { mount: '/', device: '/dev/sda1', total: 79 * GB, used: (24 + seed) * GB },
        { mount: '/var/lib/docker', device: '/dev/sdb1', total: 197 * GB, used: (150 + seed) * GB },
      ],
      net: { rx: Math.round(c.rx), tx: Math.round(c.tx) },
      uptime: (3 * 24 + 14) * 3600 + seed * 977 + Math.round((now - c.started) / 1000),
      system: SYSTEMS[session.os ?? ''] ?? 'Linux',
      kernel: session.os === 'PVE' ? '6.14.8-2-pve' : '6.8.0-45-generic',
      hostname: session.name,
    };
  },
};
