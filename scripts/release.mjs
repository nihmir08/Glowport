// Publishes a new version: set the number everywhere, renew the license list, commit, tag, push.
// GitHub does the rest (.github/workflows/release.yml): build, sign, release with latest.json.
// Write a section “## <version>” in CHANGELOG.md beforehand; everything else must be committed.
// Run in the project folder: node scripts/release.mjs 1.0.1
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts });
const next = process.argv[2] ?? '';
if (!/^\d+\.\d+\.\d+$/.test(next)) throw new Error('Usage: node scripts/release.mjs <version>, e.g. 1.0.1');
const current = JSON.parse(readFileSync('package.json', 'utf8')).version;
const order = (v) => v.split('.').map(Number).reduce((sum, part) => sum * 100_000 + part, 0);
if (order(next) <= order(current)) throw new Error(`${next} is not newer than ${current}`);

const dirty = run('git', ['status', '--porcelain']).split('\n').filter(Boolean).filter((line) => !line.endsWith('CHANGELOG.md'));
if (dirty.length) throw new Error(`Commit first:\n${dirty.join('\n')}`);
if (run('git', ['branch', '--show-current']).trim() !== 'main') throw new Error('Releases are only made from the main branch');
run('node', ['scripts/release-notes.mjs', next]);

const edit = (file, fn) => {
  const before = readFileSync(file, 'utf8');
  const after = fn(before);
  if (after === before) throw new Error(`${file}: version ${current} not found`);
  writeFileSync(file, after);
};
const quoted = (s) => s.replaceAll('.', '\\.');
const toml = (s) => s.replace(new RegExp(`^version = "${quoted(current)}"`, 'm'), `version = "${next}"`);
edit('Cargo.toml', toml);
edit('crates/rdp/Cargo.toml', toml);
edit('src-tauri/tauri.conf.json', (s) => s.replace(`"version": "${current}"`, `"version": "${next}"`));
edit('package.json', (s) => s.replace(`"version": "${current}"`, `"version": "${next}"`));
// In the lockfile only the project's own two entries, not dependencies that happen to have the same number.
edit('package-lock.json', (s) => {
  let n = 0;
  return s.replace(new RegExp(`"version": "${quoted(current)}"`, 'g'), (m) => (n++ < 2 ? `"version": "${next}"` : m));
});
run('cargo', ['update', '--workspace', '--offline'], { stdio: 'inherit' });
run('node', ['scripts/licenses.mjs'], { stdio: 'inherit' });

run('git', ['add', '-A']);
run('git', ['commit', '-m', `Glowport ${next}`], { stdio: 'inherit' });
run('git', ['tag', `v${next}`]);
run('git', ['push', 'origin', 'main', `v${next}`], { stdio: 'inherit' });
console.log(`\nv${next} is pushed. GitHub is building now (a good 15 minutes); after that, installed versions see the update within an hour.`);
