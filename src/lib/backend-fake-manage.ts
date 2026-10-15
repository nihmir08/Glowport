// Sample data for management in the sidebar (Docker, services, processes), only for the browser preview.
import type { DockerContainer, Listed, ManageAbilities, ManageDone, ProcessInfo, ProcessSample, ServiceUnit } from './types';

const fail = (code: string, message = ''): never => {
  throw { code, message };
};

const id = (seed: string) => seed.repeat(64).slice(0, 64);
const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

/** A state of its own per session, so starting and stopping have an effect in the preview. */
const containers = new Map<number, DockerContainer[]>();
const started = Date.now();

function containersOf(session: number): DockerContainer[] {
  let list = containers.get(session);
  if (!list) {
    list = [
      { id: id('4c01db0b339c'), name: 'traefik', image: 'traefik:v3.2', state: 'running', ports: ['80->80/tcp', '443->443/tcp'], since: 1_209_600, cpu: 0.4, memory: { used: 58 * MIB, limit: 8 * GIB } },
      { id: id('aa11bb22cc33'), name: 'shop-web', image: 'registry.example.com/shop/web:2026.10', state: 'running', health: 'healthy', ports: ['8080->3000/tcp'], since: 93_600, cpu: 12.6, memory: { used: 412 * MIB, limit: 2 * GIB } },
      { id: id('0123456789ab'), name: 'shop-db', image: 'postgres:17', state: 'running', health: 'healthy', ports: [], since: 1_209_540, cpu: 3.1, memory: { used: 1.3 * GIB, limit: 4 * GIB } },
      { id: id('77aa88bb99cc'), name: 'shop-worker', image: 'registry.example.com/shop/worker:2026.10', state: 'running', health: 'unhealthy', ports: [], since: 5400, cpu: 148.2, memory: { used: 1.9 * GIB, limit: 2 * GIB } },
      { id: id('ffeeddccbbaa'), name: 'redis', image: 'redis:7-alpine', state: 'restarting', ports: [], since: 12, cpu: 0, memory: { used: 6 * MIB, limit: 512 * MIB } },
      { id: id('13579bdf2468'), name: 'backup', image: 'restic/restic:0.17', state: 'exited', ports: [], since: 21_600, exitCode: 0 },
      { id: id('2468ace13579'), name: 'migrate', image: 'registry.example.com/shop/web:2026.09', state: 'exited', ports: [], since: 259_200, exitCode: 1 },
    ];
    containers.set(session, list);
  }
  return list;
}

const SERVICES: ServiceUnit[] = [
  { unit: 'backup-nightly.service', description: 'Nightly backup to object storage', active: 'failed', sub: 'failed', enabled: 'static' },
  { unit: 'certbot.service', description: 'Certbot', active: 'activating', sub: 'start', enabled: 'static' },
  { unit: 'chrony.service', description: 'chrony, an NTP client/server', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'cron.service', description: 'Regular background program processing daemon', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'docker.service', description: 'Docker Application Container Engine', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'fail2ban.service', description: 'Fail2Ban Service', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'nginx.service', description: 'A high performance web server and a reverse proxy server', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'ssh.service', description: 'OpenBSD Secure Shell server', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'systemd-journald.service', description: 'Journal Service', active: 'active', sub: 'running', enabled: 'static' },
  { unit: 'unattended-upgrades.service', description: 'Unattended Upgrades Shutdown', active: 'active', sub: 'running', enabled: 'enabled' },
  { unit: 'apt-daily.service', description: 'Daily apt download activities', active: 'inactive', sub: 'dead', enabled: 'static' },
  { unit: 'console-getty.service', description: 'Console Getty', active: 'inactive', sub: 'dead', enabled: 'masked' },
  { unit: 'rsync.service', description: 'fast remote file copy program daemon', active: 'inactive', sub: 'dead', enabled: 'disabled' },
];
const services = new Map<number, ServiceUnit[]>();
const servicesOf = (session: number) => services.get(session) ?? (services.set(session, structuredClone(SERVICES)), services.get(session)!);

const STATUS = (unit: ServiceUnit) =>
  [
    `● ${unit.unit} - ${unit.description}`,
    `     Loaded: loaded (/usr/lib/systemd/system/${unit.unit}; ${unit.enabled}; preset: enabled)`,
    `     Active: ${unit.active} (${unit.sub}) since Sun 2026-10-11 08:14:02 UTC; 1 day 3h ago`,
    unit.active === 'failed' ? '    Process: 48213 ExecStart=/usr/local/bin/backup.sh (code=exited, status=1/FAILURE)' : '   Main PID: 812 (' + unit.unit.replace('.service', '') + ')',
    '',
    unit.active === 'failed' ? 'Oct 12 03:00:04 web-01 backup.sh[48213]: Fatal: unable to open repository: connection refused' : 'Oct 12 09:41:12 web-01 systemd[1]: Started ' + unit.unit + '.',
    unit.active === 'failed' ? 'Oct 12 03:00:04 web-01 systemd[1]: backup-nightly.service: Main process exited, code=exited, status=1/FAILURE' : 'Oct 12 09:41:12 web-01 ' + unit.unit.replace('.service', '') + '[812]: ready',
  ].join('\n');

const PROCESSES: [number, number, string, string, string, number, number, number][] = [
  // pid, parent, user, name, command, memory (MiB), ticks per second, run time
  [1, 0, 'root', 'systemd', '/sbin/init', 14, 0.2, 1_209_700],
  [2, 0, 'root', 'kthreadd', '[kthreadd]', 0, 0, 1_209_700],
  [612, 1, 'root', 'dockerd', '/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock', 96, 1.4, 1_209_600],
  [812, 1, 'root', 'nginx', 'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;', 9, 0, 1_209_500],
  [813, 812, 'www-data', 'nginx', 'nginx: worker process', 38, 2.2, 93_000],
  [1490, 612, '999', 'postgres', 'postgres: shop shop 172.18.0.5(51922) idle', 1330, 3.1, 1_209_540],
  [2204, 612, '1000', 'node', 'node /app/server.js', 412, 12.6, 93_600],
  [2377, 612, '1000', 'node', 'node /app/worker.js --queue mails --concurrency 8', 1946, 148.2, 5400],
  [3051, 1, 'root', 'sshd', 'sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups', 8, 0, 1_209_600],
  [48_812, 3051, 'alex', 'sshd', 'sshd: alex@pts/0', 7, 0.1, 620],
  [48_813, 48_812, 'alex', 'bash', '-bash', 5, 0, 620],
  [48_990, 48_813, 'alex', 'htop', 'htop', 6, 0.9, 40],
  [733, 1, 'root', 'fail2ban-server', '/usr/bin/python3 /usr/bin/fail2ban-server -xf start', 42, 0.3, 1_209_580],
  [540, 1, 'root', 'cron', '/usr/sbin/cron -f -P', 3, 0, 1_209_650],
];

function sample(): ProcessSample {
  const seconds = (Date.now() - started) / 1000;
  const processes: ProcessInfo[] = PROCESSES.map(([pid, parent, user, name, command, memory, load, elapsed]) => ({
    pid,
    parent,
    user,
    name,
    command,
    memory: memory * MIB,
    elapsed: Math.round(elapsed + seconds),
    // CPU time used: a base load with some movement, so the display looks alive.
    ticks: Math.round((elapsed + seconds) * load * (1 + Math.sin(seconds / 4 + pid) * 0.15)),
    kernel: command.startsWith('['),
  }));
  return { ticksPerSecond: 100, uptime: 1_209_700 + seconds, memoryTotal: 8 * GIB, processes };
}

const done: ManageDone = { outcome: 'done' };

export const fakeManage = {
  probe: async (session: number): Promise<ManageAbilities> => ({ root: session % 2 === 1, docker: true, services: true, processes: true, sudo: session % 2 === 1 }),
  dockerList: async (session: number): Promise<Listed<DockerContainer[]>> => ({ state: 'ok', items: structuredClone(containersOf(session)), sudo: false }),
  dockerAction: async (session: number, container: string, action: 'start' | 'stop' | 'restart'): Promise<ManageDone> => {
    const entry = containersOf(session).find((c) => c.id === container) ?? fail('manage_failed', `Error response from daemon: No such container: ${container.slice(0, 12)}`);
    if (action === 'stop') Object.assign(entry, { state: 'exited', since: 0, exitCode: 0, cpu: undefined, memory: undefined, health: undefined });
    else Object.assign(entry, { state: 'running', since: 0, exitCode: undefined, cpu: 1.2, memory: { used: 64 * MIB, limit: 2 * GIB } });
    return done;
  },
  dockerLine: async (container: string, kind: 'logs' | 'shell', sudo: boolean): Promise<string> =>
    `${sudo ? 'sudo ' : ''}${kind === 'logs' ? 'docker logs --tail 200 -f' : 'docker exec -it'} ${container.slice(0, 12)}${kind === 'shell' ? " sh -c 'command -v bash >/dev/null 2>&1 && exec bash || exec sh'" : ''}`,
  serviceList: async (session: number): Promise<Listed<ServiceUnit[]>> => ({ state: 'ok', items: structuredClone(servicesOf(session)), sudo: false }),
  serviceAction: async (session: number, unit: string, action: 'start' | 'stop' | 'restart' | 'enable' | 'disable'): Promise<ManageDone> => {
    const entry = servicesOf(session).find((s) => s.unit === unit) ?? fail('manage_failed', `Failed to ${action} ${unit}: Unit ${unit} not found.`);
    // Without root and without passwordless sudo: the command goes to the terminal.
    if (session % 2 === 0) return { outcome: 'password', command: `sudo systemctl ${action} '${unit}'` };
    if (action === 'enable') entry.enabled = 'enabled';
    else if (action === 'disable') entry.enabled = 'disabled';
    else Object.assign(entry, action === 'stop' ? { active: 'inactive', sub: 'dead' } : { active: 'active', sub: 'running' });
    return done;
  },
  serviceStatus: async (session: number, unit: string): Promise<string> => STATUS(servicesOf(session).find((s) => s.unit === unit) ?? fail('manage_failed', `Unit ${unit} could not be found.`)),
  serviceLine: async (unit: string, sudo: boolean): Promise<string> => `${sudo ? 'sudo ' : ''}journalctl -n 100 -f -u '${unit}'`,
  processList: async (_session: number): Promise<ProcessSample | null> => sample(),
  processKill: async (session: number, pid: number, signal: 'term' | 'kill'): Promise<ManageDone> => (session % 2 === 0 && pid < 40_000 ? { outcome: 'password', command: `sudo kill -${signal.toUpperCase()} ${pid}` } : done),
};
