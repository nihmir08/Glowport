// Suggestions while typing in the terminal: commands, subcommands, options, snippets and paths on the server.
// The only basis is the line in the terminal. There is no saved history.

import { fsHome, fsList } from './backend';
import { firstLine } from './snippets';
import { COMMANDS, PREFIXES, SPECS, type Item, type Spec } from './suggest-data';
import type { FileEntry, Place, Snippet } from './types';

export interface Suggestion {
  kind: 'command' | 'sub' | 'option' | 'dir' | 'file' | 'snippet';
  /** What is in the list, and the explanation beside it. */
  label: string;
  detail: string;
  /** How many characters at the end of the line are replaced and with what. */
  replace: number;
  insert: string;
  /** For a snippet: it is pasted as if it had been chosen in the sidebar. */
  snippet?: Snippet;
}

export interface Context {
  /** The line up to the cursor, without the prompt. */
  line: string;
  /** The session's server, for paths; null as long as no connection is up. */
  place: Place | null;
  /** Folder the shell is in, as far as known. */
  cwd: string | null;
  lang: 'de' | 'en';
  snippets: Snippet[];
}

const LIMIT = 7;
const describe = (item: Item, lang: 'de' | 'en') => (lang === 'de' ? item[1] : item[2]);

/** Where the command being typed begins: after the last `|`, `&&`, `||` or `;`. */
function segmentStart(line: string): number {
  let start = 0;
  for (const match of line.matchAll(/\|\||&&|[|;]/g)) start = match.index + match[0].length;
  return start;
}

function items(list: Item[] | undefined, word: string, kind: Suggestion['kind'], lang: 'de' | 'en'): Suggestion[] {
  return (list ?? []).filter((item) => item[0].startsWith(word) && item[0] !== word).map((item) => ({ kind, label: item[0], detail: describe(item, lang), replace: word.length, insert: `${item[0]} ` }));
}

function commands(word: string, context: Context): Suggestion[] {
  if (word.length < 2) return [];
  const lower = word.toLowerCase();
  const known = items(COMMANDS, word, 'command', context.lang);
  const own = context.snippets
    .filter((snippet) => snippet.name.toLowerCase().includes(lower))
    .sort((a, b) => Number(b.name.toLowerCase().startsWith(lower)) - Number(a.name.toLowerCase().startsWith(lower)) || a.name.localeCompare(b.name))
    .map((snippet): Suggestion => ({ kind: 'snippet', label: snippet.name, detail: snippet.kind === 'macro' ? '' : firstLine(snippet.command), replace: word.length, insert: '', snippet }));
  // Your own snippets should not disappear behind a long list of commands.
  const room = Math.max(LIMIT - Math.min(own.length, 3), 0);
  return [...known.slice(0, room), ...own].slice(0, LIMIT);
}

// ---------- Paths ----------

interface Cached {
  at: number;
  entries: Promise<FileEntry[]>;
  failed: boolean;
}
const listings = new Map<string, Cached>();
const homes = new Map<string, Promise<string | null>>();
const placeKey = (place: Place) => (place.kind === 'local' ? 'local' : place.kind === 'ftp' ? `ftp:${place.user}@${place.host}:${place.port}` : `${place.kind}:${place.id}`);

/** The content of a folder on the server. Remembered briefly, so not every key press asks again. */
function listing(place: Place, dir: string): Promise<FileEntry[]> {
  const key = `${placeKey(place)}|${dir}`;
  const cached = listings.get(key);
  if (cached && Date.now() - cached.at < (cached.failed ? 15_000 : 5_000)) return cached.entries;
  const entry: Cached = { at: Date.now(), failed: false, entries: Promise.resolve([]) };
  entry.entries = fsList(place, dir)
    .then((found) => found.entries)
    .catch(() => ((entry.failed = true), []));
  listings.set(key, entry);
  if (listings.size > 60) listings.delete(listings.keys().next().value!);
  return entry.entries;
}

function home(place: Place): Promise<string | null> {
  const key = placeKey(place);
  let known = homes.get(key);
  if (!known) homes.set(key, (known = fsHome(place).catch(() => null)));
  return known;
}

/** Turns a path with `.` and `..` into a clean one starting at the root. */
function clean(path: string): string {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '..') out.pop();
    else if (part && part !== '.') out.push(part);
  }
  return `/${out.join('/')}`;
}

/** Characters the shell would otherwise read as something else. */
const escape = (name: string) => name.replace(/([\s'"\\$`!&;|<>()*?[\]{}#~])/g, '\\$1');

async function paths(word: string, only: 'dir' | 'any', context: Context): Promise<Suggestion[]> {
  if (!context.place || /[*?[\]{}'"\\$`]/.test(word)) return [];
  const slash = word.lastIndexOf('/');
  const before = word.slice(0, slash + 1);
  const name = word.slice(slash + 1);
  let dir: string | null;
  if (before.startsWith('/')) dir = before;
  else if (before.startsWith('~/')) dir = await home(context.place).then((h) => h && `${h}/${before.slice(2)}`);
  else if (before.startsWith('~')) dir = null;
  else dir = context.cwd && `${context.cwd}/${before}`;
  if (!dir) return [];
  const entries = await listing(context.place, clean(dir));
  const isDir = (entry: FileEntry) => entry.kind === 'dir' || (entry.kind === 'link' && !!entry.linksToDir);
  return entries
    .filter((entry) => entry.name.startsWith(name) && (name.startsWith('.') || !entry.name.startsWith('.')) && (only === 'any' || isDir(entry)))
    .sort((a, b) => Number(isDir(b)) - Number(isDir(a)) || a.name.localeCompare(b.name))
    .slice(0, LIMIT)
    .map((entry) => ({ kind: isDir(entry) ? 'dir' : 'file', label: entry.name + (isDir(entry) ? '/' : ''), detail: '', replace: word.length, insert: before + escape(entry.name) + (isDir(entry) ? '/' : ' ') }));
}

const looksLikePath = (word: string) => word.includes('/') || word.startsWith('.') || word.startsWith('~/');

/** The suggestions for a line, the best first; empty if there is nothing sensible. */
export async function suggest(context: Context): Promise<Suggestion[]> {
  const segment = context.line.slice(segmentStart(context.line)).replace(/^\s+/, '');
  if (!segment) return [];
  const words = segment.split(/\s+/);
  // `sudo`, `time` and assignments like `LANG=C` come before the actual command.
  while (words.length > 1 && (PREFIXES.has(words[0]) || /^\w+=\S*$/.test(words[0]))) words.shift();
  const word = words[words.length - 1];
  // Open quotes: free text is there, not a command.
  if ((segment.match(/"/g)?.length ?? 0) % 2 || (segment.match(/'/g)?.length ?? 0) % 2) return [];

  if (words.length === 1) return word.startsWith('/') || word.startsWith('./') || word.startsWith('~/') ? paths(word, 'any', context) : commands(word, context);

  // Subcommands can have subcommands themselves: `docker compose up`.
  let spec: Spec | undefined = SPECS[words[0]];
  let depth = 1;
  while (spec?.nested?.[words[depth]] && words.length - 1 > depth) spec = spec.nested[words[depth++]];
  const first = words.length - 1 === depth;

  if (word.startsWith('-') || word.startsWith('+')) return items(spec?.options, word, 'option', context.lang).slice(0, LIMIT);
  if (first && spec?.subs) {
    const subs = items(spec.subs, word, 'sub', context.lang);
    if (subs.length || !looksLikePath(word)) return subs.slice(0, LIMIT);
  }
  if (spec?.paths && (word || spec.paths === 'dir')) return paths(word, spec.paths, context);
  if (looksLikePath(word)) return paths(word, 'any', context);
  // After the command and a space: show the options it knows.
  if (!word && first) return items(spec?.options, '', 'option', context.lang).slice(0, LIMIT);
  // For some commands, numbers and options with a fixed value are suggestions in the list (`chmod 755`).
  return items(spec?.options, word, 'option', context.lang)
    .filter(() => !!word)
    .slice(0, LIMIT);
}
