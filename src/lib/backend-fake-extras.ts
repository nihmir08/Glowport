// Stand-in for local terminal, Telnet and serial line in the browser preview.
// Not part of the program: this file is never used in the program window. The “devices” here answer a
// handful of commands, so a terminal in the preview looks like something.

import type { LocalShell, SerialPortInfo, SerialSettings } from './types';

export const FAKE_SHELLS: LocalShell[] = [
  { id: 'pwsh', name: 'PowerShell 7', kind: 'pwsh', detail: 'C:\\Program Files\\PowerShell\\7\\pwsh.exe' },
  { id: 'powershell', name: 'Windows PowerShell', kind: 'powershell', detail: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
  { id: 'cmd', name: 'Command Prompt', kind: 'cmd', detail: 'C:\\Windows\\System32\\cmd.exe' },
  { id: 'gitbash', name: 'Git Bash', kind: 'gitbash', detail: 'C:\\Program Files\\Git\\bin\\bash.exe' },
  { id: 'wsl:Ubuntu', name: 'Ubuntu', kind: 'wsl', detail: 'Ubuntu' },
  { id: 'wsl:Debian', name: 'Debian', kind: 'wsl', detail: 'Debian' },
];

export const FAKE_PORTS: SerialPortInfo[] = [
  { name: 'COM3', label: 'USB-SERIAL CH340' },
  { name: 'COM5', label: 'Silicon Labs CP210x USB to UART Bridge' },
  { name: 'COM1', label: 'Kommunikationsanschluss' },
];

/** What a stand-in device reports to its session. */
export interface DeviceHost {
  out(text: string): void;
  /** The connection is up (for Telnet after setup, for a shell after start). */
  connected(): void;
  end(reason: 'remote' | 'connection_lost' | 'connect_failed', message?: string, exitStatus?: number): void;
}

export interface Device {
  write(text: string): void;
  stop(): void;
}

export type DeviceKind = { kind: 'local'; shell: LocalShell } | { kind: 'telnet'; name: string; address: string; user: string } | { kind: 'serial'; name: string; port: string; settings: SerialSettings };

const G = '\x1b[32m';
const Y = '\x1b[33m';
const B = '\x1b[1;34m';
const D = '\x1b[2m';
const R = '\x1b[0m';

/**
 * Line-by-line input as in a simple shell: characters appear, Backspace deletes, Ctrl+C discards.
 * `secret` suppresses the display (password). The finished line goes to `enter`.
 */
function lineInput(host: DeviceHost, enter: (line: string) => void, secret: () => boolean, interrupt: () => void) {
  let line = '';
  return (text: string) => {
    if (text.startsWith('\x1b')) return;
    for (const ch of text) {
      if (ch === '\r') {
        const done = line;
        line = '';
        enter(done);
      } else if (ch === '\x7f' || ch === '\b') {
        if (line) ((line = line.slice(0, -1)), !secret() && host.out('\b \b'));
      } else if (ch === '\x03') {
        line = '';
        interrupt();
      } else if (ch >= ' ') {
        line += ch;
        if (!secret()) host.out(ch);
      }
    }
  };
}

function localShell(shell: LocalShell, host: DeviceHost): Device {
  const windows = shell.kind === 'pwsh' || shell.kind === 'powershell' || shell.kind === 'cmd';
  let cwd = windows ? 'C:\\Users\\ich' : '~';
  const prompt = () => {
    switch (shell.kind) {
      case 'pwsh':
      case 'powershell':
        return `PS ${cwd}> `;
      case 'cmd':
        return `${cwd}>`;
      case 'gitbash':
        return `\r\n${G}ich@LAPTOP ${R}\x1b[35mMINGW64 ${R}${Y}${cwd}${R}\r\n$ `;
      default:
        return `\x1b[1;32mich@LAPTOP${R}:${B}${cwd}${R}$ `;
    }
  };
  const banner = {
    pwsh: 'PowerShell 7.5.3\r\n',
    powershell: 'Windows PowerShell\r\nCopyright (C) Microsoft Corporation. Alle Rechte vorbehalten.\r\n\r\nInstallieren Sie die neueste PowerShell für neue Funktionen und Verbesserungen! https://aka.ms/PSWindows\r\n\r\n',
    cmd: 'Microsoft Windows [Version 10.0.26200.6899]\r\n(c) Microsoft Corporation. Alle Rechte vorbehalten.\r\n\r\n',
    gitbash: '',
    wsl: `Welcome to ${shell.detail} (GNU/Linux 6.6.87.2-microsoft-standard-WSL2 x86_64)\r\n\r\n`,
  }[shell.kind];
  const listing = windows
    ? `\r\n    Verzeichnis: ${cwd}\r\n\r\nMode                 LastWriteTime         Length Name\r\n----                 -------------         ------ ----\r\nd----          08.10.2026    21:14                ${B}Desktop${R}\r\nd----          02.10.2026    17:40                ${B}Documents${R}\r\nd----          09.10.2026    09:02                ${B}Downloads${R}\r\nd----          04.10.2026    12:31                ${B}Projekte${R}\r\n-a---          30.09.2026    19:55           1204 .gitconfig\r\n\r\n`
    : `${B}Desktop${R}  ${B}Documents${R}  ${B}Downloads${R}  ${B}Projekte${R}  notizen.txt\r\n`;
  const reply = (line: string): string => {
    const [name, ...rest] = line.split(/\s+/);
    const arg = rest.join(' ');
    switch (name.toLowerCase()) {
      case '':
        return '';
      case 'ls':
      case 'dir':
      case 'get-childitem':
        return listing;
      case 'pwd':
      case 'get-location':
        return windows ? `\r\nPath\r\n----\r\n${cwd}\r\n\r\n` : `${cwd === '~' ? '/home/ich' : cwd}\r\n`;
      case 'cd':
        if (!arg || arg === '~') cwd = windows ? 'C:\\Users\\ich' : '~';
        else if (arg === '..') cwd = windows ? cwd.replace(/\\[^\\]+$/, '') || 'C:\\' : cwd.replace(/\/[^/]+$/, '') || '~';
        else cwd = windows ? `${cwd.replace(/\\$/, '')}\\${arg}` : `${cwd}/${arg}`;
        return '';
      case 'whoami':
        return windows ? 'laptop\\ich\r\n' : 'ich\r\n';
      case 'ver':
        return '\r\nMicrosoft Windows [Version 10.0.26200.6899]\r\n';
      case 'hostname':
        return 'LAPTOP\r\n';
      case 'uname':
        return 'Linux LAPTOP 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\r\n';
      case 'git':
        return arg.startsWith('status') ? `On branch main\r\nYour branch is up to date with 'origin/main'.\r\n\r\nnothing to commit, working tree clean\r\n` : `git: '${arg}' is not a git command.\r\n`;
      case 'node':
        return 'v23.9.0\r\n';
      case 'ping':
        return windows
          ? `\r\nPing wird ausgeführt für ${arg || '10.0.10.11'} mit 32 Bytes Daten:\r\nAntwort von ${arg || '10.0.10.11'}: Bytes=32 Zeit=11ms TTL=57\r\nAntwort von ${arg || '10.0.10.11'}: Bytes=32 Zeit=12ms TTL=57\r\nAntwort von ${arg || '10.0.10.11'}: Bytes=32 Zeit=11ms TTL=57\r\n\r\n`
          : `PING ${arg || '10.0.10.11'} 56(84) bytes of data.\r\n64 bytes from ${arg || '10.0.10.11'}: icmp_seq=1 ttl=57 time=11.2 ms\r\n64 bytes from ${arg || '10.0.10.11'}: icmp_seq=2 ttl=57 time=11.6 ms\r\n`;
      default:
        if (shell.kind === 'cmd') return `Der Befehl "${name}" ist entweder falsch geschrieben oder\r\nkonnte nicht gefunden werden.\r\n`;
        if (windows) return `\x1b[31m${name}: Die Benennung "${name}" wurde nicht als Name eines Cmdlet, einer Funktion oder eines Programms erkannt.${R}\r\n`;
        return `${name}: command not found\r\n`;
    }
  };
  const write = lineInput(
    host,
    (line) => {
      const trimmed = line.trim();
      if (trimmed === 'exit') return host.end('remote', undefined, 0);
      host.out(`\r\n${reply(trimmed)}${prompt()}`);
    },
    () => false,
    () => host.out(`^C\r\n${prompt()}`),
  );
  const timer = setTimeout(() => (host.connected(), host.out(banner + prompt())), 180);
  return { write, stop: () => clearTimeout(timer) };
}

function telnetDevice(name: string, address: string, user: string, host: DeviceHost): Device {
  let stage: 'user' | 'password' | 'shell' = user ? 'password' : 'user';
  let enabled = false;
  const prompt = () => `${name}${enabled ? '#' : '>'}`;
  const reply = (line: string): string => {
    switch (line) {
      case '':
        return '';
      case 'enable':
      case 'en':
        enabled = true;
        return '';
      case 'disable':
        enabled = false;
        return '';
      case 'show version':
      case 'sh ver':
        return `Switch Software, Version 15.2(7)E9, RELEASE SOFTWARE\r\n${name} uptime is 41 weeks, 3 days, 7 hours, 12 minutes\r\nSystem image file is "flash:/c2960x-universalk9-mz.152-7.E9.bin"\r\n\r\n48 Gigabit Ethernet interfaces\r\n4 Ten Gigabit Ethernet interfaces\r\n\r\nBase ethernet MAC Address       : 00:1B:54:C2:9A:80\r\nModel number                    : WS-C2960X-48TD-L\r\n`;
      case 'show vlan brief':
      case 'show vlan':
        return `\r\nVLAN Name                             Status    Ports\r\n---- -------------------------------- --------- -------------------------------\r\n1    default                          ${G}active${R}    Gi1/0/45, Gi1/0/46, Gi1/0/47\r\n10   server                           ${G}active${R}    Gi1/0/1, Gi1/0/2, Gi1/0/3, Gi1/0/4\r\n20   clients                          ${G}active${R}    Gi1/0/5, Gi1/0/6, Gi1/0/7, Gi1/0/8\r\n30   gast                             ${G}active${R}    Gi1/0/24\r\n99   management                       ${G}active${R}    Gi1/0/48\r\n`;
      case 'show interfaces status':
      case 'sh int status':
        return `\r\nPort      Name               Status       Vlan       Duplex  Speed Type\r\nGi1/0/1   pve-01             ${G}connected${R}    10         a-full a-1000 10/100/1000BaseTX\r\nGi1/0/2   nas                ${G}connected${R}    10         a-full a-1000 10/100/1000BaseTX\r\nGi1/0/3                      ${D}notconnect${R}   10           auto   auto 10/100/1000BaseTX\r\nGi1/0/5   buero-links        ${G}connected${R}    20         a-full a-1000 10/100/1000BaseTX\r\nGi1/0/24  gast-wlan          ${G}connected${R}    30         a-full a-1000 10/100/1000BaseTX\r\nTe1/0/1   uplink             ${G}connected${R}    trunk        full    10G SFP-10GBase-SR\r\n`;
      default:
        return `          ^\r\n% Invalid input detected at '^' marker.\r\n`;
    }
  };
  const write = lineInput(
    host,
    (line) => {
      if (stage === 'user') return void ((stage = 'password'), host.out('\r\nPassword: '));
      if (stage === 'password') return void ((stage = 'shell'), host.out(`\r\n\r\n${prompt()}`));
      const trimmed = line.trim();
      if (trimmed === 'exit' || trimmed === 'quit' || trimmed === 'logout') return host.end('remote');
      if (trimmed === 'drop') return host.end('connection_lost', 'connection reset');
      host.out(`\r\n${reply(trimmed)}${prompt()}`);
    },
    () => stage === 'password',
    () => host.out(`\r\n${stage === 'shell' ? prompt() : ''}`),
  );
  const timer = setTimeout(() => {
    if (address.startsWith('0.')) return host.end('connect_failed', 'timed out');
    host.connected();
    host.out(`\r\n\r\nUser Access Verification\r\n\r\n${user ? `Username: ${user}\r\nPassword: ` : 'Username: '}`);
  }, 260);
  return { write, stop: () => clearTimeout(timer) };
}

const BOOT = [
  '',
  'U-Boot 2023.07 (Jun 02 2026 - 09:14:21 +0000)',
  '',
  'CPU:   MediaTek MT7621AT ver:1 eco:3',
  'DRAM:  256 MiB',
  'NAND:  128 MiB',
  'Net:   eth0',
  'Hit any key to stop autoboot:  0',
  '## Booting kernel from Legacy Image at 80010000 ...',
  '   Verifying Checksum ... OK',
  'Starting kernel ...',
  '',
  '[    0.000000] Linux version 6.6.52 (builder@buildhost)',
  '[    0.412774] mt7621-pci 1e140000.pcie: PCIE0 enabled',
  '[    1.931022] mt7530-mdio mdio-bus:1f: configuring for fixed/rgmii link mode',
  '[    6.204418] br-lan: port 1(lan1) entered forwarding state',
  '[    9.877305] random: crng init done',
  '',
  'Please press Enter to activate this console.',
];

function serialDevice(name: string, port: string, settings: SerialSettings, host: DeviceHost): Device {
  let active = false;
  const timers: ReturnType<typeof setTimeout>[] = [];
  const prompt = `root@${name}:~# `;
  const boot = (from = 0) => BOOT.slice(from).forEach((line, i) => timers.push(setTimeout(() => host.out(`${line}\r\n`), i * 28)));
  const reply = (line: string): string => {
    switch (line) {
      case '':
        return '';
      case 'uptime':
        return ' 09:41:17 up 12 days,  4:08,  load average: 0.08, 0.05, 0.01\r\n';
      case 'ifconfig br-lan':
      case 'ip a':
        return `br-lan    Link encap:Ethernet  HWaddr 60:38:E0:C4:71:0A\r\n          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\r\n          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n          RX packets:1840221 errors:0 dropped:14 overruns:0 frame:0\r\n`;
      case 'free':
        return '              total        used        free      shared  buff/cache   available\r\nMem:         249520       48212      168844         412       32464      171320\r\n';
      default:
        return `-ash: ${line.split(' ')[0]}: not found\r\n`;
    }
  };
  const write = lineInput(
    host,
    (line) => {
      if (!active) return void ((active = true), host.out(`\r\n\r\nBusyBox v1.36.1 (2026-06-02 09:14:21 UTC) built-in shell (ash)\r\n\r\n${prompt}`));
      const trimmed = line.trim();
      // “drop” simulates the adapter being unplugged.
      if (trimmed === 'drop') return host.end('connection_lost', `${port} is gone`);
      if (trimmed === 'reboot') return void ((active = false), host.out('\r\n'), boot());
      host.out(`\r\n${reply(trimmed)}${prompt}`);
    },
    () => false,
    () => active && host.out(`^C\r\n${prompt}`),
  );
  timers.push(
    setTimeout(() => {
      if (!FAKE_PORTS.some((p) => p.name.toLowerCase() === port.toLowerCase())) return host.end('connect_failed', `${port}: Das System kann die angegebene Datei nicht finden.`);
      host.connected();
      // At a different speed only garbage would arrive; the sample device speaks 115200.
      if (settings.baud !== 115200) return host.out('\x00\ufffd\ufffdx\ufffd\x18\ufffd\ufffd\x00x\ufffd\ufffd\ufffd\x80x\ufffd\r\n');
      boot(12);
    }, 220),
  );
  return { write, stop: () => timers.forEach(clearTimeout) };
}

export function startDevice(what: DeviceKind, host: DeviceHost): Device {
  if (what.kind === 'local') return localShell(what.shell, host);
  if (what.kind === 'telnet') return telnetDevice(what.name, what.address, what.user, host);
  return serialDevice(what.name, what.port, what.settings, host);
}
