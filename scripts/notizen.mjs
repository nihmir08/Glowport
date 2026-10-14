// Gibt den Abschnitt einer Version aus CHANGELOG.md aus: der Text des Releases und des Update-Dialogs.
// Aufruf: node scripts/notizen.mjs <Version>
import { readFileSync } from 'node:fs';

const version = process.argv[2];
const lines = readFileSync('CHANGELOG.md', 'utf8').split('\n');
const start = lines.findIndex((line) => line.trim() === `## ${version}`);
if (start < 0) throw new Error(`CHANGELOG.md hat keinen Abschnitt „## ${version}“`);
const end = lines.findIndex((line, i) => i > start && line.startsWith('## '));
const text = lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
if (!text) throw new Error(`Der Abschnitt „## ${version}“ in CHANGELOG.md ist leer`);
process.stdout.write(`${text}\n`);
