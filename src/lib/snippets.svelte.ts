import { vault } from './data.svelte';
import { t } from './i18n.svelte';
import { input, inputTaps, paneByKey, pasteTerminal, focusTerminal } from './sessions.svelte';
import { asInput, fill, MAX_WAIT, variablesOf } from './snippets';
import { toast } from './state.svelte';
import type { MacroStep, Snippet } from './types';

/** Ausführen schickt den Befehl samt Eingabetaste ab, Einfügen tippt ihn nur. */
export type UseMode = 'run' | 'paste';

/** Was rund um Snippets gerade offen ist. Die Dialoge dazu zeichnet `SnippetDialogs.svelte`. */
export const snipUi = $state({
  /** Snippet, dessen Variablen abgefragt werden, bevor es in einen Bereich geht. */
  asking: null as { snippet: Snippet; pane: string; mode: UseMode } | null,
  /** Laufende Aufzeichnung eines Makros. */
  recording: null as { pane: string; steps: MacroStep[]; last: number } | null,
  /** Eine fertige Aufzeichnung, die noch ihren Namen braucht. */
  naming: null as MacroStep[] | null,
  /** Makro, das gerade abgespielt wird. */
  playing: null as { pane: string; name: string } | null,
  /** Editor außerhalb der Seite „Snippets“ (aus der Seitenleiste am Terminal); `snippet` null = neu. */
  editing: null as { snippet: Snippet | null } | null,
  /** Snippet, das auf mehreren Hosts ausgeführt werden soll. */
  running: null as Snippet | null,
});

/** Zuletzt eingesetzte Werte je Snippet. Nur im Speicher: Sie können Geheimes enthalten und werden nie gesichert. */
const remembered = new Map<string, Record<string, string>>();
export const lastValues = (snippet: string) => remembered.get(snippet) ?? {};
export const remember = (snippet: string, values: Record<string, string>) => void remembered.set(snippet, { ...values });

export const snippetForHotkey = (hotkey: string) => vault.snippets.find((snippet) => snippet.hotkey === hotkey);

/** Pakete in der Reihenfolge ihrer Namen; Snippets ohne Paket stehen am Ende unter dem leeren Namen. */
export function packages(snippets: Snippet[] = vault.snippets): { name: string; items: Snippet[] }[] {
  const names = [...new Set(snippets.map((snippet) => snippet.package))].sort((a, b) => Number(!a) - Number(!b) || a.localeCompare(b));
  return names.map((name) => ({ name, items: snippets.filter((snippet) => snippet.package === name).sort((a, b) => a.name.localeCompare(b.name)) }));
}

function connected(pane: string): boolean {
  const found = paneByKey(pane);
  if (found?.sessionId != null && found.phase === 'connected') return true;
  toast(t('snip.offline'), 'err');
  return false;
}

/** Schickt einen fertigen Befehl in einen Bereich. */
export function send(pane: string, command: string, mode: UseMode) {
  if (mode === 'run') input(pane, asInput(command));
  else pasteTerminal(pane, command);
  focusTerminal(pane);
}

/**
 * Benutzt ein Snippet in einem Bereich: Makros werden abgespielt, Befehle ausgeführt oder eingefügt.
 * Hat der Befehl Variablen, fragt erst ein Dialog nach ihren Werten.
 */
export function useSnippet(snippet: Snippet, pane: string, mode: UseMode) {
  if (!connected(pane)) return;
  if (snippet.kind === 'macro') return void play(snippet, pane);
  if (variablesOf(snippet.command).length) snipUi.asking = { snippet, pane, mode };
  else send(pane, snippet.command, mode);
}

/** Schließt die Abfrage der Variablen und schickt den Befehl mit den eingesetzten Werten los. */
export function answerVariables(values: Record<string, string>, mode: UseMode) {
  const asking = snipUi.asking;
  if (!asking) return;
  snipUi.asking = null;
  remember(asking.snippet.id, values);
  send(asking.pane, fill(asking.snippet.command, values), mode);
}

// ---------- Makros ----------

let stopPlaying = false;

/** Spielt ein Makro ab: dieselben Tasten in denselben Abständen, lange Pausen gekürzt. */
export async function play(snippet: Snippet, pane: string) {
  if (snipUi.playing) return toast(t('macro.busy'), 'err');
  snipUi.playing = { pane, name: snippet.name };
  stopPlaying = false;
  focusTerminal(pane);
  for (const step of snippet.steps) {
    if (step.wait > 0) await new Promise((resolve) => setTimeout(resolve, Math.min(step.wait, MAX_WAIT)));
    // Abgebrochen, oder der Bereich ist inzwischen zu oder getrennt.
    if (stopPlaying || paneByKey(pane)?.sessionId == null) break;
    input(pane, step.keys);
  }
  snipUi.playing = null;
}

export const stopMacro = () => (stopPlaying = true);

/** Beginnt, alles mitzuschreiben, was in diesen Bereich getippt wird. */
export function startRecording(pane: string) {
  if (!connected(pane)) return;
  snipUi.recording = { pane, steps: [], last: 0 };
  focusTerminal(pane);
}

/** Beendet die Aufzeichnung. Mit `keep` wird nach einem Namen gefragt, sonst verfällt sie. */
export function stopRecording(keep = true) {
  const recording = snipUi.recording;
  snipUi.recording = null;
  if (!recording || !keep) return;
  if (!recording.steps.length) return toast(t('macro.empty'), 'err');
  snipUi.naming = $state.snapshot(recording.steps);
}

/** Tasten, die kurz hintereinander kommen, gehören zu einem Schritt; eine Zeile endet mit der Eingabetaste. */
const SAME_STEP = 350;

inputTaps.add((key, text) => {
  const recording = snipUi.recording;
  if (!recording || recording.pane !== key || snipUi.playing) return;
  const now = Date.now();
  const wait = recording.last ? now - recording.last : 0;
  recording.last = now;
  const previous = recording.steps[recording.steps.length - 1];
  if (previous && wait < SAME_STEP && !previous.keys.endsWith('\r')) previous.keys += text;
  else recording.steps.push({ wait, keys: text });
});
