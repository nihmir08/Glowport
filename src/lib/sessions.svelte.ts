import { inApp, onSessionEvent, sessionAck, sessionAnswer, sessionAttach, sessionClose, sessionCwd, sessionHold, sessionOpen, sessionRecord, sessionWrite, windowMove } from './backend';
import { DEFAULT_TELNET_PORT, addressOf, colorOf, errorText, hostById, inherited, isFtp, protocolOf } from './data.svelte';
import { openInFiles } from './files.svelte';
import { has, t, type Key } from './i18n.svelte';
import { insert, leaves, mapLeaves, remove, setRatio, swap, type Layout, type Side } from './layout';
import { defaultShell, shellById, shellName } from './local.svelte';
import { settings, toast } from './state.svelte';
import type { Answer, MoshFallback, Moving, Prompt, Reconnect, SavedLayout, SavedPane, SavedTab, SessionEnd, SessionEvent, SessionPhase, Target } from './types';

/**
 * Art einer Sitzung. Dateileiste, Server-Info und Vorschläge beim Tippen gibt es nur bei SSH; ein lokales Terminal
 * „startet“ und „läuft“, statt zu verbinden.
 */
export type PaneKind = 'ssh' | 'telnet' | 'serial' | 'local';

/** Ein Terminal-Bereich. Er überlebt seine Verbindung: Der Inhalt bleibt, „Neu verbinden“ hängt eine neue an. */
export interface Pane {
  key: string;
  target: Target;
  /** Wie zuletzt bekannt; bleibt stehen, wenn der Tresor gesperrt ist. */
  kind: PaneKind;
  /** Nummer der Sitzung im Kern, solange eine Verbindung besteht oder aufgebaut wird. */
  sessionId: number | null;
  phase: SessionPhase | 'idle' | 'ended';
  end: SessionEnd | null;
  /** Die Rückfrage, auf die die Sitzung gerade wartet. */
  prompt: Prompt | null;
  /** Sekunden bis zum nächsten automatischen Versuch, sonst null. */
  retryIn: number | null;
  attempts: number;
  /** Wird die Ausgabe in eine Datei mitgeschnitten? */
  recording: boolean;
  /** Name und Adresse, wie sie zuletzt bekannt waren. Sie bleiben lesbar, wenn der Tresor gesperrt ist. */
  name: string;
  address: string;
  /** Eine laufende Sitzung aus einem anderen Fenster, die dieser Bereich übernimmt, statt neu zu verbinden. */
  adopt: Moving | null;
  /** Ordner, in dem die Shell zuletzt stand, soweit der Kern ihn kennt. Ihm folgt die Dateileiste. */
  cwd: string | null;
  /** Eine Zeile, die einmal getippt wird, sobald die Verbindung steht (Logs eines Containers, Journal eines Dienstes). */
  run?: string;
  /** Läuft das Terminal über Mosh? `silent`: Sekunden ohne Nachricht vom Server, sonst null; `side`: steht die
   *  SSH-Verbindung daneben (Seitenleiste, Dateien)? */
  mosh: { silent: number | null; side: boolean } | null;
  /** Mosh war gewünscht, die Sitzung läuft aber per SSH; die Leiste im Bereich nennt den Grund. */
  moshFallback: { reason: MoshFallback; detail?: string } | null;
}

/** Ein Tab: ein oder mehrere Bereiche in freier Anordnung. */
export interface Tab {
  key: string;
  /** Eigener Name; null = Name des Hosts. */
  name: string | null;
  /** Eigene Farbe; null = Farbe des Hosts. */
  color: string | null;
  layout: Layout;
  /** Bereich, der die Tastatur hat. */
  focus: string;
  /** Multi-Exec: Eingaben gehen an alle Bereiche des Tabs. */
  multi: boolean;
}

/** Was ein Terminal dem Rest der Oberfläche anbietet. */
export interface TerminalHooks {
  write(bytes: Uint8Array, done: () => void): void;
  /** Schreibt eine Zeile der Oberfläche selbst in das Terminal, abgesetzt von der Ausgabe des Servers. */
  note(text: string): void;
  size(): { columns: number; rows: number };
  focus(): void;
  /** Der Inhalt des Terminals samt Verlauf als Folge von Steuerzeichen, die ihn anderswo wieder aufbaut. */
  snapshot(): Promise<string>;
  /** Fügt Text ein, als käme er aus der Zwischenablage: Mehrere Zeilen laufen nicht von selbst los, wenn die Shell das unterstützt. */
  paste(text: string): void;
}

export const panes = $state<Pane[]>([]);
export const tabs = $state<Tab[]>([]);
export const view = $state({ active: 'home' });

const terminals = new Map<string, TerminalHooks>();
const paneOfSession = new Map<number, string>();
/** Ereignisse, die eintreffen, bevor die Nummer ihrer Sitzung bekannt ist. */
const early = new Map<number, SessionEvent[]>();
const timers = new Map<string, ReturnType<typeof setInterval>>();
let seq = 0;

/** Wartezeiten vor den automatischen Versuchen, in Sekunden. Danach bleibt es bei der letzten. */
const BACKOFF = [2, 5, 10, 20, 30];

export const paneByKey = (key: string | null | undefined) => (key ? panes.find((pane) => pane.key === key) : undefined);
export const tabByKey = (key: string) => tabs.find((tab) => tab.key === key);
export const tabOf = (pane: string) => tabs.find((tab) => leaves(tab.layout).includes(pane));
export const panesOf = (tab: Tab) =>
  leaves(tab.layout)
    .map((key) => paneByKey(key))
    .filter((pane): pane is Pane => !!pane);
export const activeTab = () => tabByKey(view.active);

/** Wie ein Ziel heißt; undefined, wenn es ein Host ist, den der (gesperrte) Tresor gerade nicht nennt. */
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

/** Die Art eines Ziels; undefined, wenn es ein Host ist, den der Tresor gerade nicht nennt. */
function kindOf(target: Target): PaneKind | undefined {
  if (target.kind === 'local' || target.kind === 'telnet') return target.kind;
  if (target.kind === 'direct') return 'ssh';
  const host = hostById(target.id);
  // Ein FTP-Host hat kein Terminal; ein Bereich, der noch auf ihn zeigt, bleibt, was er war.
  const protocol = host && protocolOf(host);
  return protocol === 'ftp' ? undefined : protocol;
}

export const paneTitle = (pane: Pane): string => titleOf(pane.target) ?? (pane.name || '…');
export const paneAddress = (pane: Pane): string => addressFor(pane.target) ?? pane.address;

export function paneColor(pane: Pane): string | null {
  const host = pane.target.kind === 'host' ? hostById(pane.target.id) : undefined;
  return host ? colorOf(host) : null;
}

/** Name eines Tabs: der eigene, sonst der seines ersten Bereichs, bei mehreren mit „+ n“. */
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

/** Zustand eines Tabs für seine Anzeige in der Titelleiste: verbunden, sobald es ein Bereich ist. */
export function tabPhase(tab: Tab): Pane['phase'] {
  const inside = panesOf(tab);
  if (inside.some((pane) => pane.phase === 'connected')) return 'connected';
  if (inside.length && inside.every((pane) => pane.phase === 'ended')) return 'ended';
  return inside.find((pane) => pane.phase !== 'ended')?.phase ?? 'idle';
}

/** Der Bereich eines Tabs, der gerade auf eine Antwort wartet; der mit der Tastatur zuerst. */
export function askingPane(tab: Tab): Pane | undefined {
  const inside = panesOf(tab);
  return inside.find((pane) => pane.key === tab.focus && pane.prompt) ?? inside.find((pane) => pane.prompt);
}

export const liveCount = () => panes.filter((pane) => pane.sessionId !== null).length;

/** Was bei einem Abriss gelten soll: Host vor Gruppe vor Einstellungen. */
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

/** Baut aus einer gespeicherten Anordnung die Bereiche. Bereiche, deren Host es nicht mehr gibt, fallen weg. */
function build(saved: SavedLayout): Layout | null {
  if ('pane' in saved) {
    // Eine umziehende Sitzung läuft schon; sie braucht den Tresor nicht, um weiterzulaufen.
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
  // Ein FTP-Host hat kein Terminal: Er öffnet sich im Dateimanager.
  if (target.kind === 'host' && isFtp(hostById(target.id))) return openInFiles(target.id);
  view.active = newTab({ pane: newPane(target).key }).key;
}

/** Öffnet einen Tab am selben Ziel und tippt dort, sobald die Verbindung steht, eine Zeile ein. */
export function openTabWith(target: Target, line: string) {
  const pane = newPane($state.snapshot(target) as Target);
  pane.run = line;
  view.active = newTab({ pane: pane.key }).key;
}

/** Öffnet ein lokales Terminal: die genannte Shell, sonst die eingestellte. */
export function openLocal(shell?: string) {
  const id = shell ?? defaultShell()?.id;
  if (!id) return toast(t('local.none'), 'err');
  openTab({ kind: 'local', shell: id });
}

/** Öffnet einen gespeicherten Tab. Bereiche, deren Host es nicht mehr gibt, fallen weg. Liefert false, wenn nichts übrig bleibt. */
export function openSaved(saved: SavedTab, activate = true): boolean {
  const layout = build(saved.layout);
  if (!layout) return false;
  const tab = newTab(layout, tabs.length, { name: saved.name, color: saved.color, multi: saved.multi && leaves(layout).length > 1 });
  if (activate) view.active = tab.key;
  return true;
}

/** Der Tab in der Form, in der er sich später wieder öffnen lässt. */
export function savedTab(tab: Tab): SavedTab {
  return { name: tab.name, color: tab.color, multi: tab.multi, layout: mapLeaves<string, Target>(tab.layout, (key) => $state.snapshot(paneByKey(key)?.target)) as SavedLayout };
}

/** Nimmt einen Bereich aus der Liste. Mit `keep` läuft seine Sitzung weiter, weil ein anderes Fenster sie übernimmt. */
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

/** Löst einen Bereich aus seinem Tab. Der Tab verschwindet, wenn es sein letzter war. */
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

/** Teilt einen Bereich: Daneben oder darunter entsteht ein neuer, ohne Angabe zum selben Ziel. */
export function splitPane(key: string, side: Side, target?: Target) {
  const tab = tabOf(key);
  const source = paneByKey(key);
  if (!tab || !source) return;
  const added = newPane(target ?? $state.snapshot(source.target));
  tab.layout = insert(tab.layout, key, { pane: added.key }, side);
  tab.focus = added.key;
}

/** Legt einen Bereich an die Seite eines anderen, auch über Tabs hinweg. */
export function movePane(key: string, onto: string, side: Side) {
  if (key === onto) return;
  const from = tabOf(key);
  // Beim Umordnen innerhalb eines Tabs bleibt Multi-Exec, wie es war; das Herauslösen allein schaltete es sonst ab.
  const multi = !!from?.multi && from === tabOf(onto);
  detach(key);
  const tab = tabOf(onto);
  if (!tab) return;
  tab.layout = insert(tab.layout, onto, { pane: key }, side);
  tab.focus = key;
  if (multi) tab.multi = true;
  view.active = tab.key;
}

/** Tauscht zwei Bereiche desselben Tabs. */
export function swapPanes(one: string, other: string) {
  const tab = tabOf(one);
  if (tab && tab === tabOf(other)) tab.layout = swap(tab.layout, one, other);
}

/** Macht aus einem Bereich einen eigenen Tab an der Stelle `at` der Tab-Leiste. */
export function paneToTab(key: string, at = tabs.length) {
  const from = tabOf(key);
  if (!from || leaves(from.layout).length < 2) return;
  const before = tabs[at]?.key;
  detach(key);
  const index = before ? tabs.findIndex((tab) => tab.key === before) : tabs.length;
  view.active = newTab({ pane: key }, index < 0 ? tabs.length : index).key;
}

/** Legt alle Bereiche eines Tabs an die Seite eines Bereichs in einem anderen Tab. */
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
 * Verlegt einen Tab oder einen einzelnen Bereich in ein anderes Fenster: in das Fenster `to`, mit `atCursor` in das
 * unter dem Mauszeiger, sonst in ein neues. Laufende Sitzungen ziehen mit um, samt dem bisherigen Inhalt des Terminals.
 */
export async function sendToWindow(item: { tab: string } | { pane: string }, target: { to?: string; atCursor?: boolean } = {}) {
  const tab = 'tab' in item ? tabByKey(item.tab) : tabOf(item.pane);
  if (!tab) return;
  const whole = 'tab' in item || leaves(tab.layout).length === 1;
  const keys = whole ? leaves(tab.layout) : [(item as { pane: string }).pane];
  // In der Vorschau gibt es keinen Kern, der Sitzungen weiterreicht; dort verbindet das neue Fenster neu.
  const moving = inApp ? keys.map((key) => paneByKey(key)).filter((pane): pane is Pane => pane?.sessionId != null) : [];
  const ids = moving.map((pane) => pane.sessionId!);

  // Erst anhalten, dann den Inhalt festhalten: So geht dazwischen keine Ausgabe verloren.
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
    // Das Fenster kam nicht zustande: Die Sitzungen bleiben hier und werden wieder aufgenommen.
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

/** `mapLeaves` verpackt jedes Blatt in `{ pane: … }`; hier ist das Blatt schon der ganze Bereich. */
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

/** Trennt die Verbindung, lässt den Bereich aber stehen. */
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

/** Fügt Text in das Terminal eines Bereichs ein, ohne ihn abzuschicken. */
export function pasteTerminal(key: string, text: string) {
  terminals.get(key)?.paste(text);
}

/** Wer mitlesen will, was in einen Bereich getippt wird (die Aufzeichnung eines Makros), trägt sich hier ein. */
export const inputTaps = new Set<(key: string, text: string) => void>();

/** Tastatureingabe eines Bereichs. Mit Multi-Exec geht sie an alle verbundenen Bereiche seines Tabs. */
export function input(key: string, text: string) {
  const tab = tabOf(key);
  for (const tap of inputTaps) tap(key, text);
  for (const pane of tab?.multi ? panesOf(tab) : [paneByKey(key)]) {
    if (pane?.sessionId == null) continue;
    void sessionWrite(pane.sessionId, text);
    // Eine abgeschickte Zeile kann den Ordner gewechselt haben.
    if (text.includes('\r')) askCwd(pane.key);
  }
}

/** Antworten eines Terminals, die eintrafen, bevor die Nummer seiner Sitzung bekannt war. */
const answers = new Map<string, string[]>();

/**
 * Eine Antwort des Terminals auf eine Anfrage des Programms darin (Schreibmarke, Art des Terminals, Fokus).
 * Sie geht nur an die eigene Sitzung: nie an die anderen Bereiche (Multi-Exec) und nicht in ein Makro.
 * Ein lokales Terminal fragt schon beim Start und wartet auf die Antwort; kommt sie, bevor die Sitzung ihre
 * Nummer hat, wird sie nachgereicht.
 */
export function answerQuery(key: string, text: string) {
  const pane = paneByKey(key);
  if (!pane || pane.phase === 'ended') return;
  if (pane.sessionId === null) answers.set(key, [...(answers.get(key) ?? []), text]);
  else void sessionWrite(pane.sessionId, text);
}

/** Schaltet den Mitschnitt eines Bereichs. Er läuft über Verbindungen hinweg weiter, bis er ausgeschaltet wird. */
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

/** Baut die Verbindung eines Bereichs auf. Wird vom Terminal aufgerufen, sobald es seine Größe kennt, und beim Neuverbinden. */
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

  // Eine Sitzung aus einem anderen Fenster läuft schon: Inhalt wiederherstellen und die Ausgabe hierher lenken.
  const adopt = pane.adopt;
  pane.adopt = null;
  if (adopt) {
    if (adopt.content) terminal.write(new TextEncoder().encode(adopt.content), () => {});
    try {
      const attached = await sessionAttach(adopt.session, columns, rows, draw);
      pane.phase = attached.phase;
      if (attached.mosh) pane.mosh = { silent: null, side: true };
    } catch {
      // Sie ist während des Umzugs zu Ende gegangen.
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
  // Der Bereich kann inzwischen geschlossen worden sein.
  if (!paneByKey(key)) return void sessionClose(id);
  pane.sessionId = id;
  paneOfSession.set(id, key);
  // Der Mitschnitt einer übernommenen Sitzung läuft im Kern weiter und braucht keinen neuen Anstoß.
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
 * Ein Text, der je nach Art der Sitzung anders lautet: `<stamm>.<art>.<rest>` geht vor `<stamm>.<rest>`.
 * So heißt es bei einem lokalen Terminal „Die Shell wurde beendet“ statt „Der Server hat die Sitzung beendet“.
 */
export function kindText(kind: PaneKind, stem: string, rest: string, vars?: Record<string, string | number>): string | null {
  const own = `${stem}.${kind}.${rest}`;
  const common = `${stem}.${rest}`;
  return has(own) ? t(own, vars) : has(common) ? t(common, vars) : null;
}

/** Warum eine Sitzung endete, in Worten. */
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
  // Automatisch wird nur nach einem Abriss neu verbunden, nie nach einem abgelehnten Passwort oder einem bewussten Ende.
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

/** Verbindungen, deren Ereignisse ein anderer Teil der Oberfläche verarbeitet (etwa die Seite „Dateien“). */
const foreign = new Map<number, (event: SessionEvent) => void>();

/**
 * Überlässt die Ereignisse einer Verbindung einem anderen Empfänger. Was vor dem Anmelden schon eingetroffen ist,
 * bekommt er sofort. Liefert eine Funktion zum Abmelden.
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
    // Noch nicht zugeordnet: aufheben, bis `connect` die Nummer kennt.
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
        // Erst nach dem Startbefehl des Hosts, den der Kern gleich nach dem Anmelden tippt.
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
 * Fragt kurz darauf nach, in welchem Ordner die Shell eines Bereichs steht. Gebraucht wird das, solange die
 * Dateileiste dem Terminal folgt oder beim Tippen Pfade vorgeschlagen werden; dann nach dem Verbinden und nach
 * jeder abgeschickten Zeile.
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
      // Den Ordner der Shell verrät nur ein Server, zu dem SSH führt.
      if (!pane || session == null || pane.phase !== 'connected' || pane.kind !== 'ssh') return;
      void sessionCwd(session)
        .then((path) => path && pane.sessionId === session && (pane.cwd = path))
        .catch(() => {});
    }, delay),
  );
}

/** Meldet die Oberfläche für Sitzungsereignisse an. Einmal beim Start aufrufen. */
export const initSessions = () => onSessionEvent(handle);
