// Prints a version's section from CHANGELOG.md: the text of the release and of the update dialog.
// Run: node scripts/release-notes.mjs <version>
import { readFileSync } from 'node:fs';

const version = process.argv[2];
const lines = readFileSync('CHANGELOG.md', 'utf8').split('\n');
const start = lines.findIndex((line) => line.trim() === `## ${version}`);
if (start < 0) throw new Error(`CHANGELOG.md hat keinen Abschnitt „## ${version}“`);
const end = lines.findIndex((line, i) => i > start && line.startsWith('## '));
const text = lines.slice(start + 1, end < 0 ? undefined : end).join('\n').trim();
if (!text) throw new Error(`Der Abschnitt „## ${version}“ in CHANGELOG.md ist leer`);
process.stdout.write(`${text}\n`);
