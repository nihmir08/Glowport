// Stand-in for the import in the browser preview: made-up sources and entries, so the flow can be looked at.
// Nothing is read here, neither files nor the registry.

import type { DraftForward, DraftGroup, DraftHost, DraftKey, DraftKnownHost, DraftSnippet, ImportDraft, ImportFound, ImportNote, ImportSource, Snapshot } from './types';

const HOME = 'C:\\Users\\alex';

export const sampleFound = (): ImportFound[] => [
  { source: 'sshconfig', where: `${HOME}\\.ssh\\config`, count: 9 },
  { source: 'putty', where: '', count: 7 },
  { source: 'mobaxterm', where: `${HOME}\\AppData\\Roaming\\MobaXterm\\MobaXterm.ini`, count: 11 },
  { source: 'winscp', where: '', count: 5 },
  { source: 'knownhosts', where: `${HOME}\\.ssh\\known_hosts`, count: 23 },
];

type HostSeed = Partial<DraftHost> & { name: string; address: string };

/** Builds a draft; `existing` follows from what is already in the stand-in vault. */
function draft(
  source: ImportSource,
  origin: string,
  vault: Snapshot,
  parts: { groups?: [string, string, string | null][]; hosts?: HostSeed[]; keys?: Partial<DraftKey>[]; forwards?: Partial<DraftForward>[]; snippets?: [string, string, string][]; known?: number; skipped?: [string, string][] },
): Omit<ImportDraft, 'token'> {
  const groups: DraftGroup[] = (parts.groups ?? []).map(([ref, name, parent]) => ({ ref, name, parent }));
  const hosts: DraftHost[] = (parts.hosts ?? []).map((h, i) => {
    const user = h.user ?? null;
    const port = h.port ?? null;
    const twin = vault.hosts.find((x) => x.protocol === (h.protocol ?? 'ssh') && x.address.toLowerCase() === h.address.toLowerCase() && (x.own.port ?? 22) === (port ?? 22));
    return { ref: `h${i}`, group: null, os: null, auth: h.key ? 'key' : h.hasPassword ? 'password' : 'none', hasPassword: false, key: null, jump: null, notes: [], ...h, user, port, existing: twin?.id ?? null };
  });
  const keys: DraftKey[] = (parts.keys ?? []).map((k, i) => {
    const ref = k.ref ?? `k${i}`;
    return { name: 'id_ed25519', path: null, kind: 'ed25519', bits: 256, fingerprint: `SHA256:vorschau${i}NurZumAnsehenQm0Lr2Qv9bTfK2x4kPz`, state: 'ready', existing: null, ...k, ref, uses: hosts.filter((h) => h.key === ref).length };
  });
  const forwards: DraftForward[] = (parts.forwards ?? []).map((f, i) => ({ ref: `f${i}`, name: '', kind: 'local', host: 'h0', bindAddress: '127.0.0.1', bindPort: 8080, destHost: '127.0.0.1', destPort: 80, ...f }));
  const snippets: DraftSnippet[] = (parts.snippets ?? []).map(([name, pack, command], i) => ({ ref: `s${i}`, name, package: pack, command, existing: vault.snippets.some((s) => s.command === command) }));
  const ALGS = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512'];
  const knownHosts: DraftKnownHost[] = Array.from({ length: parts.known ?? 0 }, (_, i) => ({
    ref: `n${i}`,
    host: i < hosts.length ? hosts[i].address : `198.51.100.${10 + i}`,
    port: i % 7 === 3 ? 2222 : 22,
    algorithm: ALGS[i % 3],
    fingerprint: `SHA256:${'Qm0Lr2Qv9bTfK2x4kPzAbCdEfGhIjKlMnOpQrStUvWx'.slice(i % 9, (i % 9) + 30)}${i}`,
    existing: i % 6 === 0,
  }));
  return { source, origin, groups, hosts, keys, forwards, snippets, knownHosts, skipped: (parts.skipped ?? []).map(([name, reason]) => ({ name, reason })) };
}

const note = (code: string, detail?: string): ImportNote => ({ code, detail });

/** What the source provides in the preview. */
export function sampleDraft(source: ImportSource, vault: Snapshot): Omit<ImportDraft, 'token'> {
  switch (source) {
    case 'sshconfig':
      return draft(source, `${HOME}\\.ssh\\config`, vault, {
        hosts: [
          { name: 'bastion', address: '203.0.113.10', user: 'deploy', key: 'k0' },
          { name: 'web-01', address: '10.20.0.11', user: 'deploy', key: 'k0', jump: 'h0' },
          { name: 'web-02', address: '10.20.0.12', user: 'deploy', key: 'k0', jump: 'h0' },
          { name: 'db-primary', address: '10.20.1.5', user: 'postgres', port: 5022, key: 'k0', jump: 'h0' },
          { name: 'grafana', address: 'grafana.intern.example', user: 'admin', key: 'k1' },
          { name: 'gitlab', address: 'git.example.org', user: 'git', port: 2222, key: 'k1', notes: [note('agent_forward')] },
          { name: 'altes-nas', address: '192.168.1.20', user: 'admin', auth: 'none', notes: [note('legacy')] },
          { name: 'kunde-vpn', address: '172.16.4.2', user: 'root', key: 'k2', notes: [note('proxy_command', 'ProxyCommand nc -X connect -x proxy.kunde.example:3128 %h %p')] },
          { name: 'pi', address: 'raspberrypi.local', user: 'pi', auth: 'agent' },
        ],
        keys: [
          { name: 'id_ed25519', path: `${HOME}\\.ssh\\id_ed25519` },
          { name: 'id_rsa_alt', path: `${HOME}\\.ssh\\id_rsa_alt`, kind: 'rsa', bits: 4096, state: 'encrypted', fingerprint: null },
          { name: 'kunde.pem', path: `${HOME}\\Documents\\kunde.pem`, kind: null, bits: null, fingerprint: null, state: 'missing' },
        ],
        forwards: [
          { name: 'grafana · 3000', host: 'h4', bindPort: 3000, destPort: 3000 },
          { name: 'db-primary · 5432', host: 'h3', bindPort: 15432, destPort: 5432 },
          { name: 'bastion · SOCKS', host: 'h0', kind: 'dynamic', bindPort: 1080, destHost: '', destPort: 0 },
        ],
      });
    case 'putty':
      return draft(source, '', vault, {
        hosts: [
          { name: 'mail', address: 'mail.example.org', user: 'root', key: 'k0' },
          { name: 'nas', address: '192.168.1.20', user: 'admin', hasPassword: false },
          { name: 'pi-hole', address: '192.168.1.2', user: 'pi', key: 'k0' },
          { name: 'gitlab', address: 'git.example.org', user: 'git', port: 2222, key: 'k1' },
          { name: 'backup-box', address: '203.0.113.77', user: 'root', port: 2222 },
          { name: 'router', address: '192.168.1.1', protocol: 'telnet' },
          { name: 'COM3', address: 'COM3', protocol: 'serial' },
        ],
        keys: [
          { name: 'arbeit.ppk', path: `${HOME}\\.ssh\\arbeit.ppk` },
          { name: 'alt.ppk', path: `${HOME}\\Documents\\alt.ppk`, kind: 'rsa', bits: 2048, state: 'encrypted', fingerprint: null },
        ],
        forwards: [{ name: 'gitlab · 8080', host: 'h3', bindPort: 8080, destPort: 80 }],
        known: 6,
      });
    case 'mobaxterm':
      return draft(source, `${HOME}\\AppData\\Roaming\\MobaXterm\\MobaXterm.ini`, vault, {
        groups: [
          ['g0', 'Kunden', null],
          ['g1', 'Meier GmbH', 'g0'],
          ['g2', 'Schulz & Söhne', 'g0'],
          ['g3', 'Privat', null],
        ],
        hosts: [
          { name: 'meier-web', address: 'web.meier.example', user: 'admin', group: 'g1', key: 'k0' },
          { name: 'meier-db', address: 'db.meier.example', user: 'admin', group: 'g1', key: 'k0', jump: 'h0' },
          { name: 'meier-backup', address: '10.8.0.30', user: 'backup', group: 'g1', jump: 'h0', hasPassword: true, notes: [note('password_unreadable')] },
          { name: 'schulz-erp', address: 'erp.schulz.example', user: 'root', port: 22022, group: 'g2', key: 'k1' },
          { name: 'schulz-mail', address: 'mail.schulz.example', user: 'root', group: 'g2', key: 'k1', notes: [note('startcmd', 'sudo -i')] },
          { name: 'homeserver', address: '192.168.178.10', user: 'alex', group: 'g3', key: 'k0' },
          { name: 'pve1', address: '192.168.10.11', user: 'root', group: 'g3' },
          { name: 'gameserver', address: 'play.example.net', user: 'steam', port: 2222, group: 'g3' },
          { name: 'switch-keller', address: '192.168.1.250', protocol: 'telnet' },
        ],
        keys: [
          { name: 'id_ed25519', path: `${HOME}\\.ssh\\id_ed25519` },
          { name: 'schulz.ppk', path: `${HOME}\\Documents\\MobaXterm\\schulz.ppk`, kind: 'rsa', bits: 4096 },
        ],
        skipped: [
          ['meier-dc01 (RDP)', 'protocol_rdp'],
          ['schulz-ts (RDP)', 'protocol_rdp'],
        ],
      });
    case 'winscp':
      return draft(source, '', vault, {
        groups: [['g0', 'Webspace', null]],
        hosts: [
          { name: 'kunde-a', address: 'ssh.kunde-a.example', user: 'web123', group: 'g0', hasPassword: true },
          { name: 'kunde-b', address: 'ssh.kunde-b.example', user: 'u55231', group: 'g0', hasPassword: true },
          { name: 'nas', address: '192.168.1.20', user: 'admin', hasPassword: true },
          { name: 'pve1', address: '192.168.10.11', user: 'root', key: 'k0' },
        ],
        keys: [{ name: 'arbeit.ppk', path: `${HOME}\\.ssh\\arbeit.ppk` }],
        skipped: [['alter-ftp (FTP)', 'protocol_ftp']],
      });
    case 'knownhosts':
      return draft(source, `${HOME}\\.ssh\\known_hosts`, vault, { known: 23, skipped: [['4 Einträge mit verdecktem Namen', 'hashed']] });
    case 'csv':
      return draft(source, `${HOME}\\Downloads\\hosts.csv`, vault, {
        groups: [
          ['g0', 'Produktion', null],
          ['g1', 'Test', null],
        ],
        hosts: [
          { name: 'app-01', address: '10.1.0.11', user: 'deploy', group: 'g0', hasPassword: true },
          { name: 'app-02', address: '10.1.0.12', user: 'deploy', group: 'g0', hasPassword: true },
          { name: 'cache', address: '10.1.0.20', user: 'deploy', group: 'g0' },
          { name: 'test-app', address: '10.9.0.11', user: 'root', port: 2200, group: 'g1', hasPassword: true },
        ],
      });
    default:
      return draft(source, `${HOME}\\Downloads\\export`, vault, {
        hosts: [
          { name: 'server-a', address: '198.51.100.21', user: 'root' },
          { name: 'server-b', address: '198.51.100.22', user: 'root' },
        ],
        snippets: [
          ['Platz', 'System', 'df -h'],
          ['Dienste', 'System', 'systemctl --failed'],
        ],
      });
  }
}
