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
writeFileSync(join(stage, 'portable'), 'Solange diese Datei neben Glowport.exe liegt, bleiben alle Daten im Ordner "data" daneben.\r\n');
writeFileSync(
  join(stage, 'LIESMICH.txt'),
  [
    `Glowport ${version}, portable Fassung`,
    '',
    'Glowport.exe starten. Tresor, Einstellungen und Mitschnitte landen im Ordner "data" neben dem Programm;',
    'auf dem PC selbst bleibt nichts zurück. Zum Mitnehmen den ganzen Ordner kopieren.',
    '',
    'Den Ordner an einen Ort legen, an dem du schreiben darfst (nicht unter "C:\\Program Files").',
    'Diese Fassung aktualisiert sich nicht selbst: Für eine neue Version Glowport.exe ersetzen, "data" bleibt.',
    '',
    'Glowport zeigt seine Oberfläche mit WebView2 von Microsoft. Windows 11 bringt es mit; unter Windows 10',
    'ist es meist vorhanden, sonst gibt es den Installer bei Microsoft ("WebView2 Runtime").',
    '',
    `Glowport ${version}, portable version`,
    '',
    'Start Glowport.exe. Vault, settings and recordings go into the "data" folder next to the program;',
    'nothing is left on the PC itself. To take it with you, copy the whole folder.',
    '',
  ].join('\r\n'),
);

// Compress-Archive bringt Windows mit; so braucht das Packen kein weiteres Werkzeug.
execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Compress-Archive -Path '${stage}' -DestinationPath '${zip}' -Force`], { stdio: 'inherit' });
rmSync(stage, { recursive: true, force: true });
console.log(`${zip} (${(statSync(zip).size / 1024 / 1024).toFixed(1)} MB)`);
