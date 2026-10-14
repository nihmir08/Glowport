// Packt die portable Fassung: Programm, die Datei `portable` und eine kurze Anleitung in einem Zip.
// Liegt neben dem Programm eine Datei `portable`, bleiben alle Daten im Ordner `data` daneben (siehe src-tauri/src/lib.rs).
// Aufruf im Projektordner nach `npm run build:app`; `npm run portable` macht beides.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const version = JSON.parse(readFileSync('package.json', 'utf8')).version;
// Ohne Angabe die normale Fassung; eine andere Programmdatei nur zum Ausprobieren des Packens.
const exe = resolve(process.argv[2] ?? 'target/release/glowport.exe');
if (!existsSync(exe)) throw new Error(`${exe} fehlt. Vorher \`npm run build:app\` (nicht \`build:dev\`: Die portable Fassung ist die normale).`);

const out = resolve('target/release/bundle/portable');
const stage = join(out, 'Glowport');
const zip = join(out, `Glowport_${version}_x64_portable.zip`);
rmSync(out, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });

copyFileSync(exe, join(stage, 'Glowport.exe'));
writeFileSync(join(stage, 'portable'), 'As long as this file sits next to Glowport.exe, all data stays in the "data" folder beside it.\r\n');
writeFileSync(
  join(stage, 'README.txt'),
  [
    `Glowport ${version}, portable version`,
    '',
    'Start Glowport.exe. Vault, settings and recordings go into the "data" folder next to the program;',
    'nothing is left on the PC itself. To take it with you, copy the whole folder.',
    '',
    'Put the folder somewhere you can write to (not under "C:\\Program Files").',
    'This version does not update itself: for a new version, replace Glowport.exe and keep "data".',
    '',
    'Glowport draws its interface with Microsoft WebView2. Windows 11 includes it; on Windows 10 it is',
    'usually present, otherwise Microsoft offers the installer ("WebView2 Runtime").',
    '',
  ].join('\r\n'),
);

// Compress-Archive bringt Windows mit; so braucht das Packen kein weiteres Werkzeug.
execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Compress-Archive -Path '${stage}' -DestinationPath '${zip}' -Force`], { stdio: 'inherit' });
rmSync(stage, { recursive: true, force: true });
console.log(`${zip} (${(statSync(zip).size / 1024 / 1024).toFixed(1)} MB)`);
