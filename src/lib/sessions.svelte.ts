import { inApp, onSessionEvent, sessionAck, sessionAnswer, sessionAttach, sessionClose, sessionCwd, sessionHold, sessionOpen, sessionRecord, sessionWrite, windowMove } from './backend';
import { DEFAULT_TELNET_PORT, addressOf, colorOf, errorText, hostById, inherited, isFtp, protocolOf } from './data.svelte';
import { openInFiles } from './files.svelte';
import { has, t, type Key } from './i18n.svelte';
import { insert, leaves, mapLeaves, remove, setRatio, swap, type Layout, type Side } from './layout';
import { defaultShell, shellById, shellName } from './local.svelte';
import { settings, toast } from './state.svelte';
import type { Answer, MoshFallback, Moving, Prompt, Reconnect, SavedLayout, SavedPane, SavedTab, SessionEnd, SessionEvent, SessionPhase, Target } from './types';

/**
 * Kind of a session. File bar, server info and suggestions while typing only exist for SSH; a local terminal
 * “starts” and “runs” instead of connecting.
 */
export type PaneKind = 'ssh' | 'telnet' | 'serial' | 'local';

/** A terminal pane. It outlives its connection: the content stays, “Reconnect” attaches a new one. */
export interface Pane {
  key: string;
  target: Target;
  /** As last known; stays when the vault is locked. */
  kind: PaneKind;
  /** The session's number in the core, as long as a connection exists or is being set up. */
  sessionId: number | null;
  phase: SessionPhase | 'idle' | 'ended';
  end: SessionEnd | null;
  /** The prompt the session is currently waiting for. */
  prompt: Prompt | null;
  /** Seconds until the next automatic attempt, otherwise null. */
  retryIn: number | null;
  attempts: number;
  /** Is the output being recorded into a file? */
  recording: boolean;
  /** Name and address as last known. They stay readable when the vault is locked. */
  name: string;
  address: string;
  /** A running session from another window that this pane takes over instead of connecting anew. */
  adopt: Moving | null;
  /** Folder the shell was last in, as far as the core knows it. The file bar follows it. */
  cwd: string | null;
  /** A line typed once as soon as the connection is up (a container's logs, a service's journal). */
  run?: string;
  /** Does the terminal run over Mosh? `silent`: seconds without a message from the server, otherwise null; `side`: is the
   * SSH connection next to it up (sidebar, files)? */
  mosh: { silent: number | null; side: boolean } | null;
  /** Mosh was wanted, but the session runs over SSH; the bar in the pane names the reason. */
  moshFallback: { reason: MoshFallback; detail?: string } | null;
}

/** A tab: one or more panes in a free layout. */
export interface Tab {
  key: string;
  /** Custom name; null = the host's name. */
  name: string | null;
  /** Custom color; null = the host's color. */
  color: string | null;
  layout: Layout;
  /** Pane that has the keyboard. */
  focus: string;
  /** Multi-exec: input goes to all panes of the tab. */
  multi: boolean;
}

/** What a terminal offers the rest of the interface. */
export interface TerminalHooks {
  write(bytes: Uint8Array, done: () => void): void;
  /** Writes a line from the interface itself into the terminal, set apart from the server's output. */
  note(text: string): void;
  size(): { columns: number; rows: number };
  focus(): void;
  /** The terminal's content including scrollback as a sequence of control characters that rebuilds it elsewhere. */
  snapshot(): Promise<string>;
  /** Pastes text as if it came from the clipboard: several lines do not run on their own if the shell supports that. */
  paste(text: string): void;
}

export const panes = $state<Pane[]>([]);
export const tabs = $state<Tab[]>([]);
export const view = $state({ active: 'home' });

const terminals = new Map<string, TerminalHooks>();
const paneOfSession = new Map<number, string>();
/** Events that arrive before their session's number is known. */
const early = new Map<number, SessionEvent[]>();
const timers = new Map<string, ReturnType<typeof setInterval>>();
let seq = 0;

/** Waiting times before the automatic attempts, in seconds. After that the last one stays. */
const BACKOFF = [2, 5, 10, 20, 30];

export const paneByKey = (key: string | null | undefined) => (key ? panes.find((pane) => pane.key === key) : undefined);
export const tabByKey = (key: string) => tabs.find((tab) => tab.key === key);
export const tabOf = (pane: string) => tabs.find((tab) => leaves(tab.layout).includes(pane));
export const panesOf = (tab: Tab) =>
  leaves(tab.layout)
    .map((key) => paneByKey(key))
    .filter((pane): pane is Pane => !!pane);
export const activeTab = () => tabByKey(view.active);

/** What a destination is called; undefined if it is a host the (locked) vault does not name right now. */
export function titleOf(target: Target): string | undefined {
  switch (target.kind) {
    case 'direct':
      return `${target.user}@${target.host}`;
    case 'telnet':
      return target.host;
    case 'local': {
      const shell = shellById(target.shell);
      return shell ? shellName(shell) : target.shell;
    }
    default:
      return hostById(target.id)?.name;
  }
}

function addressFor(target: Target): string | undefined {
  switch (target.kind) {
    case 'direct':
      return `${target.user}@${target.host}${target.port === 22 ? '' : `:${target.port}`}`;
    case 'telnet':
      return `${target.host}${target.port === DEFAULT_TELNET_PORT ? '' : `:${target.port}`}`;
    case 'local':
      return t('local.address');
    default: {
      const host = hostById(target.id);
      return host && addressOf(host);
    }
  }
}

/** A destination's kind; undefined if it is a host the vault does not name right now. */
function kindOf(target: Target): PaneKind | undefined {
  if (target.kind === 'local' || target.kind === 'telnet') return target.kind;
  if (target.kind === 'direct') return 'ssh';
  const host = hostById(target.id);
  // An FTP host has no terminal; a pane still pointing to it stays what it was.
  const protocol = host && protocolOf(host);
  return protocol === 'ftp' ? undefined : protocol;
}

export const paneTitle = (pane: Pane): string => titleOf(pane.target) ?? (pane.name || '…');
export const paneAddress = (pane: Pane): string => addressFor(pane.target) ?? pane.address;

export function paneColor(pane: Pane): string | null {
  const host = pane.target.kind === 'host' ? hostById(pane.target.id) : undefined;
  return host ? colorOf(host) : null;
}

/** A tab's name: its own, otherwise that of its first pane, with several “+ n”. */
export function tabTitle(tab: Tab): string {
  if (tab.name) return tab.name;
  const inside = panesOf(tab);
  if (!inside.length) return '…';
  return inside.length > 1 ? `${paneTitle(inside[0])} +${inside.length - 1}` : paneTitle(inside[0]);
}

export function tabColor(tab: Tab): string | null {
  if (tab.color) return tab.color;
  const first = panesOf(tab)[0];
  return first ? paneColor(first) : null;
}

/** A tab's state for its display in the title bar: connected as soon as one pane is. */
export function tabPhase(tab: Tab): Pane['phase'] {
  const inside = panesOf(tab);
  if (inside.some((pane) => pane.phase === 'connected')) return 'connected';
  if (inside.length && inside.every((pane) => pane.phase === 'ended')) return 'ended';
  return inside.find((pane) => pane.phase !== 'ended')?.phase ?? 'idle';
}

/** The pane of a tab currently waiting for an answer; the one with the keyboard first. */
export function askingPane(tab: Tab): Pane | undefined {
  const inside = panesOf(tab);
  return inside.find((pane) => pane.key === tab.focus && pane.prompt) ?? inside.find((pane) => pane.prompt);
}

export const liveCount = () => panes.filter((pane) => pane.sessionId !== null).length;

/** What should apply on a dropped connection: host before group before settings. */
function reconnectMode(pane: Pane): Reconnect {
  const host = pane.target.kind === 'host' ? hostById(pane.target.id) : undefined;
  return host?.own.reconnect ?? (host ? inherited(host.group).reconnect?.value : undefined) ?? settings.reconnect;
}

function newPane(target: Target, from: Partial<SavedPane> = {}): Pane {
  const pane: Pane = {
    key: `p${++seq}`,
    target,
    kind: kindOf(target) ?? 'ssh',
    sessionId: null,
    phase: 'idle',
    end: null,
    prompt: null,
    retryIn: null,
    attempts: 0,
    recording: from.recording ?? settings.recordAuto,
    name: titleOf(target) ?? '',
    address: addressFor(target) ?? '',
    adopt: from.moving ?? null,
    cwd: null,
    mosh: null,
    moshFallback: null,
  };
  panes.push(pane);
  return pane;
}

/** Builds the panes from a saved layout. Panes whose host no longer exists are dropped. */
function build(saved: SavedLayout): Layout | null {
  if ('pane' in saved) {
    // A moving session is already running; it does not need the vault to keep running.
    const known = saved.pane.kind !== 'host' || !!saved.moving || !!hostById(saved.pane.id);
    return known ? { pane: newPane(saved.pane, saved).key } : null;
  }
  const a = build(saved.a);
  const b = build(saved.b);
  return a && b ? { dir: saved.dir, ratio: saved.ratio, a, b } : (a ?? b);
}

function newTab(layout: Layout, at = tabs.length, extra: Partial<Tab> = {}): Tab {
  const tab: Tab = { key: `t${++seq}`, name: null, color: null, layout, focus: leaves(layout)[0], multi: false, ...extra };
  tabs.splice(at, 0, tab);
  return tabByKey(tab.key)!;
}

export function openTab(target: Target) {
  // An FTP host has no terminal: it opens in the file manager.
  if (target.kind === 'host' && isFtp(hostById(target.id))) return openInFiles(target.id);
  view.active = newTab({ pane: newPane(target).key }).key;
}

/** Opens a tab at the same destination and types a line there as soon as the connection is up. */
export function openTabWith(target: Target, line: string) {
  const pane = newPane($state.snapshot(target) as Target);
  pane.run = line;
  view.active = newTab({ pane: pane.key }).key;
}

/** Opens a local terminal: the named shell, otherwise the configured one. */
export function openLocal(shell?: string) {
  const id = shell ?? defaultShell()?.id;
  if (!id) return toast(t('local.none'), 'err');
  openTab({ kind: 'local', shell: id });
}

/** Opens a saved tab. Panes whose host no longer exists are dropped. Returns false if nothing is left. */
export function openSaved(saved: SavedTab, activate = true): boolean {
  const layout = build(saved.layout);
  if (!layout) return false;
  const tab = newTab(layout, tabs.length, { name: saved.name, color: saved.color, multi: saved.multi && leaves(layout).length > 1 });
  if (activate) view.active = tab.key;
  return true;
}

/** The tab in the form in which it can be opened again later. */
export function savedTab(tab: Tab): SavedTab {
  return { name: tab.name, color: tab.color, multi: tab.multi, layout: mapLeaves<string, Target>(tab.layout, (key) => $state.snapshot(paneByKey(key)?.target)) as SavedLayout };
}

/** Takes a pane out of the list. With `keep` its session keeps running, because another window takes it over. */
function dropPane(key: string, keep = false) {
  const index = panes.findIndex((pane) => pane.key === key);
  if (index < 0) return;
  const [pane] = panes.splice(index, 1);
  stopRetry(pane);
  if (pane.sessionId !== null) {
    paneOfSession.delete(pane.sessionId);
    if (!keep) void sessionClose(pane.sessionId);
  }
}

function dropTab(key: string) {
  const index = tabs.findIndex((tab) => tab.key === key);
  if (index < 0) return;
  tabs.splice(index, 1);
  if (view.active === key) view.active = (tabs[index] ?? tabs[index - 1])?.key ?? 'home';
}

export function closeTab(key: string) {
  const tab = tabByKey(key);
  if (!tab) return;
  for (const pane of leaves(tab.layout)) dropPane(pane);
  dropTab(key);
}

export function closeOtherTabs(key: string) {
  for (const tab of [...tabs]) if (tab.key !== key) closeTab(tab.key);
}

/** Detaches a pane from its tab. The tab disappears if it was its last one. */
function detach(key: string) {
  const tab = tabOf(key);
  if (!tab) return;
  const rest = remove(tab.layout, key);
  if (!rest) return dropTab(tab.key);
  tab.layout = rest;
  if (tab.focus === key) tab.focus = leaves(rest)[0];
  if (leaves(rest).length < 2) tab.multi = false;
}

export function closePane(key: string) {
  detach(key);
  dropPane(key);
}

/** Splits a pane: a new one appears beside or below it, without a destination to the same one. */
export function splitPane(key: string, side: Side, target?: Target) {
  const tab = tabOf(key);
  const source = paneByKey(key);
  if (!tab || !source) return;
  const added = newPane(target ?? $state.snapshot(source.target));
  tab.layout = insert(tab.layout, key, { pane: added.key }, side);
  tab.focus = added.key;
}

/** Places a pane at the side of another, also across tabs. */
export function movePane(key: string, onto: string, side: Side) {
  if (key === onto) return;
  const from = tabOf(key);
  // When rearranging within a tab, multi-exec stays as it was; detaching alone would otherwise switch it off.
  const multi = !!from?.multi && from === tabOf(onto);
  detach(key);
  const tab = tabOf(onto);
  if (!tab) return;
  tab.layout = insert(tab.layout, onto, { pane: key }, side);
  tab.focus = key;
  if (multi) tab.multi = true;
  view.active = tab.key;
}

/** Swaps two panes of the same tab. */
export function swapPanes(one: string, other: string) {
  const tab = tabOf(one);
  if (tab && tab === tabOf(other)) tab.layout = swap(tab.layout, one, other);
}

/** Turns a pane into a tab of its own at position `at` of the tab bar. */
export function paneToTab(key: string, at = tabs.length) {
  const from = tabOf(key);
  if (!from || leaves(from.layout).length < 2) return;
  const before = tabs[at]?.key;
  detach(key);
  const index = before ? tabs.findIndex((tab) => tab.key === before) : tabs.length;
  view.active = newTab({ pane: key }, index < 0 ? tabs.length : index).key;
}

/** Places all panes of a tab at the side of a pane in another tab. */
export function mergeTab(key: string, onto: string, side: Side) {
  const tab = tabByKey(key);
  const target = tabOf(onto);
  if (!tab || !target || tab === target) return;
  target.layout = insert(target.layout, onto, $state.snapshot(tab.layout), side);
  target.focus = tab.focus;
  dropTab(key);
  view.active = target.key;
}

export function moveTab(key: string, at: number) {
  const from = tabs.findIndex((tab) => tab.key === key);
  if (from < 0) return;
  const [tab] = tabs.splice(from, 1);
  tabs.splice(from < at ? at - 1 : at, 0, tab);
}

export function duplicateTab(key: string) {
  const tab = tabByKey(key);
  if (!tab) return;
  const saved = savedTab(tab);
  const layout = mapLeaves<Target, string>(saved.layout as Layout<Target>, (target) => newPane(target).key)!;
  view.active = newTab(layout, tabs.indexOf(tab) + 1, { name: tab.name, color: tab.color, multi: tab.multi }).key;
}

/**
 * Moves a tab or a single pane into another window: into the window `to`, with `atCursor` into the one
 * under the mouse pointer, otherwise into a new one. Running sessions move along, with the terminal's previous content.
 */
export async function sendToWindow(item: { tab: string } | { pane: string }, target: { to?: string; atCursor?: boolean } = {}) {
  const tab = 'tab' in item ? tabByKey(item.tab) : tabOf(item.pane);
  if (!tab) return;
  const whole = 'tab' in item || leaves(tab.layout).length === 1;
  const keys = whole ? leaves(tab.layout) : [(item as { pane: string }).pane];
  // In the preview there is no core that hands sessions on; there the new window connects anew.
  const moving = inApp ? keys.map((key) => paneByKey(key)).filter((pane): pane is Pane => pane?.sessionId != null) : [];
  const ids = moving.map((pane) => pane.sessionId!);

  // Pause first, then capture the content: that way no output is lost in between.
  await sessionHold(ids);
  const contents = new Map<string, string>();
  for (const pane of moving) contents.set(pane.key, (await terminals.get(pane.key)?.snapshot()) ?? '');

  const leaf = (key: string): SavedPane | null => {
    const pane = paneByKey(key);
    if (!pane) return null;
    const content = contents.get(key);
    return { pane: $state.snapshot(pane.target), recording: pane.recording, ...(content === undefined ? {} : { moving: { session: pane.sessionId!, content } }) };
  };
  const layout = mapLeaves<string, SavedPane>(whole ? tab.layout : { pane: keys[0] }, leaf);
  if (!layout) return;
  const saved: SavedTab = { name: whole ? tab.name : null, color: whole ? tab.color : null, multi: whole && tab.multi, layout: flatten(layout) };

  try {
    await windowMove(saved, ids, target);
  } catch (error) {
    // The window did not come about: the sessions stay here and are picked up again.
    for (const pane of moving) {
      paneOfSession.delete(pane.sessionId!);
      pane.adopt = { session: pane.sessionId!, content: '' };
      pane.sessionId = null;
      void connect(pane.key);
    }
    throw error;
  }
  for (const key of keys) {
    if (!whole) detach(key);
    dropPane(key, contents.has(key));
  }
  if (whole) dropTab(tab.key);
}

/** `mapLeaves` wraps every leaf in `{ pane: … }`; here the leaf is already the whole pane. */
function flatten(layout: Layout<SavedPane>): SavedLayout {
  return 'pane' in layout ? layout.pane : { dir: layout.dir, ratio: layout.ratio, a: flatten(layout.a), b: flatten(layout.b) };
}

export function resizeSplit(tab: Tab, path: string, ratio: number) {
  tab.layout = setRatio(tab.layout, path, ratio);
}

export function focusPane(key: string) {
  const tab = tabOf(key);
  if (tab) tab.focus = key;
  terminals.get(key)?.focus();
}

/** Disconnects, but leaves the pane in place. */
export function disconnect(key: string) {
  const pane = paneByKey(key);
  if (pane?.sessionId != null) void sessionClose(pane.sessionId);
}

export function registerTerminal(key: string, hooks: TerminalHooks) {
  terminals.set(key, hooks);
  return () => void terminals.delete(key);
}

export function focusTerminal(key: string) {
  terminals.get(key)?.focus();
}

/** Pastes text into a pane's terminal without sending it. */
export function pasteTerminal(key: string, text: string) {
  terminals.get(key)?.paste(text);
}

/** Whoever wants to read along with what is typed into a pane (recording a macro) registers here. */
export const inputTaps = new Set<(key: string, text: string) => void>();

/** A pane's keyboard input. With multi-exec it goes to all connected panes of its tab. */
export function input(key: string, text: string) {
  const tab = tabOf(key);
  for (const tap of inputTaps) tap(key, text);
  for (const pane of tab?.multi ? panesOf(tab) : [paneByKey(key)]) {
    if (pane?.sessionId == null) continue;
    void sessionWrite(pane.sessionId, text);
    // A sent line may have changed the folder.
    if (text.includes('\r')) askCwd(pane.key);
  }
}

/** A terminal's answers that arrived before its session's number was known. */
const answers = new Map<string, string[]>();

/**
 * A terminal's answer to a request from the program inside it (cursor, kind of terminal, focus).
 * It only goes to its own session: never to the other panes (multi-exec) and not into a macro.
 * A local terminal asks right at start and waits for the answer; if it comes before the session has its
 * number, it is delivered later.
 */
export function answerQuery(key: string, text: string) {
  const pane = paneByKey(key);
  if (!pane || pane.phase === 'ended') return;
  if (pane.sessionId === null) answers.set(key, [...(answers.get(key) ?? []), text]);
  else void sessionWrite(pane.sessionId, text);
}

/** Switches a pane's recording. It continues across connections until it is switched off. */
export function setRecording(key: string, on: boolean) {
  const pane = paneByKey(key);
  if (!pane || pane.recording === on) return;
  pane.recording = on;
  if (pane.sessionId !== null) record(pane);
}

function record(pane: Pane) {
  if (pane.sessionId === null) return;
  sessionRecord(pane.sessionId, pane.recording, paneTitle(pane), paneAddress(pane)).catch((e) => {
    pane.recording = false;
    toast(errorText(e), 'err');
  });
}

/** Sets up a pane's connection. Called by the terminal as soon as it knows its size, and when reconnecting. */
export async function connect(key: string) {
  const pane = paneByKey(key);
  const terminal = terminals.get(key);
  if (!pane || !terminal || pane.sessionId !== null) return;
  stopRetry(pane);
  answers.delete(key);
  pane.end = null;
  pane.prompt = null;
  pane.mosh = null;
  pane.moshFallback = null;
  pane.name = titleOf(pane.target) ?? pane.name;
  pane.address = addressFor(pane.target) ?? pane.address;
  pane.kind = kindOf(pane.target) ?? pane.kind;

  const { columns, rows } = terminal.size();
  let id = -1;
  const unconfirmed: number[] = [];
  const draw = (bytes: Uint8Array) => terminal.write(bytes, () => (id >= 0 ? void sessionAck(id, bytes.length) : unconfirmed.push(bytes.length)));

  // A session from another window is already running: restore the content and direct the output here.
  const adopt = pane.adopt;
  pane.adopt = null;
  if (adopt) {
    if (adopt.content) terminal.write(new TextEncoder().encode(adopt.content), () => {});
    try {
      const attached = await sessionAttach(adopt.session, columns, rows, draw);
      pane.phase = attached.phase;
      if (attached.mosh) pane.mosh = { silent: null, side: true };
    } catch {
      // It ended during the move.
      return ended(pane, { type: 'end', reason: 'remote', message: null, exitStatus: null });
    }
    id = adopt.session;
  } else {
    pane.phase = 'connecting';
    try {
      id = await sessionOpen(pane.target, columns, rows, draw);
    } catch (e) {
      return ended(pane, { type: 'end', reason: 'connect_failed', message: errorText(e), exitStatus: null });
    }
  }
  // The pane may have been closed in the meantime.
  if (!paneByKey(key)) return void sessionClose(id);
  pane.sessionId = id;
  paneOfSession.set(id, key);
  // The recording of a session taken over keeps running in the core and needs no new nudge.
  if (pane.recording && !adopt) record(pane);
  for (const bytes of unconfirmed) void sessionAck(id, bytes);
  for (const text of answers.get(key) ?? []) void sessionWrite(id, text);
  answers.delete(key);
  for (const event of early.get(id) ?? []) handle(event);
  early.delete(id);
}

export function answer(key: string, reply: Answer) {
  const pane = paneByKey(key);
  if (pane?.sessionId == null) return;
  pane.prompt = null;
  void sessionAnswer(pane.sessionId, reply);
  terminals.get(key)?.focus();
}

/**
 * A text that reads differently depending on the session's kind: `<stem>.<kind>.<rest>` comes before `<stem>.<rest>`.
 * That way a local terminal says “The shell exited” instead of “The server ended the session”.
 */
export function kindText(kind: PaneKind, stem: string, rest: string, vars?: Record<string, string | number>): string | null {
  const own = `${stem}.${kind}.${rest}`;
  const common = `${stem}.${rest}`;
  return has(own) ? t(own, vars) : has(common) ? t(common, vars) : null;
}

/** Why a session ended, in words. */
export function endText(pane: Pane, end: SessionEnd): string {
  const code = end.exitStatus ? ` (${end.exitStatus})` : '';
  return kindText(pane.kind, 'session.end', end.reason, { message: end.message ?? '', code, name: pane.address }) ?? end.message ?? end.reason;
}

function ended(pane: Pane, end: SessionEnd) {
  if (pane.sessionId !== null) paneOfSession.delete(pane.sessionId);
  pane.sessionId = null;
  pane.phase = 'ended';
  pane.end = end;
  pane.prompt = null;
  terminals.get(pane.key)?.note(endText(pane, end));
  // Automatic reconnects only happen after a dropped connection, never after a rejected password or a deliberate end.
  if (end.reason === 'connection_lost' && reconnectMode(pane) === 'auto') startRetry(pane);
}

function startRetry(pane: Pane) {
  pane.retryIn = BACKOFF[Math.min(pane.attempts, BACKOFF.length - 1)];
  pane.attempts += 1;
  const key = pane.key;
  timers.set(
    key,
    setInterval(() => {
      const current = paneByKey(key);
      if (!current || current.retryIn === null) return stopRetry(current);
      current.retryIn -= 1;
      if (current.retryIn <= 0) void connect(key);
    }, 1000),
  );
}

export function stopRetry(pane: Pane | undefined) {
  if (!pane) return;
  clearInterval(timers.get(pane.key));
  timers.delete(pane.key);
  pane.retryIn = null;
}

/** Connections whose events another part of the interface handles (e.g. the Files page). */
const foreign = new Map<number, (event: SessionEvent) => void>();

/**
 * Hands a connection's events to another receiver. What already arrived before subscribing
 * it gets right away. Returns a function to unsubscribe.
 */
export function claim(id: number, handler: (event: SessionEvent) => void): () => void {
  foreign.set(id, handler);
  const waiting = early.get(id) ?? [];
  early.delete(id);
  for (const event of waiting) handler(event);
  return () => void foreign.delete(id);
}

function handle(event: SessionEvent) {
  const other = foreign.get(event.id);
  if (other) return other(event);
  const pane = paneByKey(paneOfSession.get(event.id));
  if (!pane) {
    // Not assigned yet: keep until `connect` knows the number.
    early.set(event.id, [...(early.get(event.id) ?? []), event]);
    return;
  }
  switch (event.type) {
    case 'phase':
      pane.phase = event.phase;
      if (event.phase === 'connected') (pane.attempts = 0), askCwd(pane.key, 700);
      if (event.phase === 'connected' && pane.run) {
        const line = pane.run;
        pane.run = undefined;
        // Only after the host's startup command, which the core types right after signing in.
        setTimeout(() => pane.sessionId !== null && input(pane.key, `${line}\r`), 900);
      }
      break;
    case 'banner':
      terminals.get(pane.key)?.note(event.text.trimEnd());
      break;
    case 'notice': {
      const text = `session.notice.${event.code}`;
      toast(has(text) ? t(text as Key) : event.message || event.code, 'err');
      break;
    }
    case 'cwd':
      pane.cwd = event.path;
      break;
    case 'mosh':
      if (event.state === 'active') pane.mosh = { silent: null, side: true };
      else pane.moshFallback = { reason: event.reason, detail: event.detail };
      break;
    case 'reach':
      if (pane.mosh) pane.mosh.silent = event.silent;
      break;
    case 'side':
      if (pane.mosh) pane.mosh.side = event.linked;
      break;
    case 'end':
      ended(pane, event);
      break;
    default:
      pane.prompt = event;
  }
}

const cwdTimers = new Map<string, ReturnType<typeof setTimeout>>();

/**
 * Asks shortly afterwards which folder a pane's shell is in. That is needed as long as the
 * file bar follows the terminal or paths are suggested while typing; then after connecting and after
 * every sent line.
 */
export function askCwd(key: string, delay = 350) {
  if (!(settings.fileBar && settings.fileFollow) && !settings.termSuggest) return;
  clearTimeout(cwdTimers.get(key));
  cwdTimers.set(
    key,
    setTimeout(() => {
      cwdTimers.delete(key);
      const pane = paneByKey(key);
      const session = pane?.sessionId;
      // Only a server reached over SSH reveals the shell's folder.
      if (!pane || session == null || pane.phase !== 'connected' || pane.kind !== 'ssh') return;
      void sessionCwd(session)
        .then((path) => path && pane.sessionId === session && (pane.cwd = path))
        .catch(() => {});
    }, delay),
  );
}

/** Subscribes the interface to session events. Call once on start. */
export const initSessions = () => onSessionEvent(handle);
