import { vault } from './data.svelte';
import { t } from './i18n.svelte';
import { input, inputTaps, paneByKey, pasteTerminal, focusTerminal } from './sessions.svelte';
import { asInput, fill, MAX_WAIT, variablesOf } from './snippets';
import { toast } from './state.svelte';
import type { MacroStep, Snippet } from './types';

/** Run sends the command with Enter, paste only types it. */
export type UseMode = 'run' | 'paste';

/** What is currently open around snippets. `SnippetDialogs.svelte` draws the dialogs for it. */
export const snipUi = $state({
  /** Snippet whose variables are asked for before it goes into a pane. */
  asking: null as { snippet: Snippet; pane: string; mode: UseMode } | null,
  /** Laufende Aufzeichnung eines Makros. */
  recording: null as { pane: string; steps: MacroStep[]; last: number } | null,
  /** A finished recording that still needs its name. */
  naming: null as MacroStep[] | null,
  /** Macro currently being played. */
  playing: null as { pane: string; name: string } | null,
  /** Editor outside the Snippets page (from the sidebar at the terminal); `snippet` null = new. */
  editing: null as { snippet: Snippet | null } | null,
  /** Snippet that should run on several hosts. */
  running: null as Snippet | null,
});

/** Values last used per snippet. Only in memory: they can contain secrets and are never saved. */
const remembered = new Map<string, Record<string, string>>();
export const lastValues = (snippet: string) => remembered.get(snippet) ?? {};
export const remember = (snippet: string, values: Record<string, string>) => void remembered.set(snippet, { ...values });

export const snippetForHotkey = (hotkey: string) => vault.snippets.find((snippet) => snippet.hotkey === hotkey);

/** Packages in the order of their names; snippets without a package come last under the empty name. */
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

/** Sends a finished command into a pane. */
export function send(pane: string, command: string, mode: UseMode) {
  if (mode === 'run') input(pane, asInput(command));
  else pasteTerminal(pane, command);
  focusTerminal(pane);
}

/**
 * Uses a snippet in a pane: macros are played, commands run or pasted.
 * If the command has variables, a dialog asks for their values first.
 */
export function useSnippet(snippet: Snippet, pane: string, mode: UseMode) {
  if (!connected(pane)) return;
  if (snippet.kind === 'macro') return void play(snippet, pane);
  if (variablesOf(snippet.command).length) snipUi.asking = { snippet, pane, mode };
  else send(pane, snippet.command, mode);
}

/** Closes the variable query and sends the command with the filled-in values. */
export function answerVariables(values: Record<string, string>, mode: UseMode) {
  const asking = snipUi.asking;
  if (!asking) return;
  snipUi.asking = null;
  remember(asking.snippet.id, values);
  send(asking.pane, fill(asking.snippet.command, values), mode);
}

// ---------- Makros ----------

let stopPlaying = false;

/** Plays a macro: the same keys at the same intervals, long pauses shortened. */
export async function play(snippet: Snippet, pane: string) {
  if (snipUi.playing) return toast(t('macro.busy'), 'err');
  snipUi.playing = { pane, name: snippet.name };
  stopPlaying = false;
  focusTerminal(pane);
  for (const step of snippet.steps) {
    if (step.wait > 0) await new Promise((resolve) => setTimeout(resolve, Math.min(step.wait, MAX_WAIT)));
    // Cancelled, or the pane has been closed or disconnected in the meantime.
    if (stopPlaying || paneByKey(pane)?.sessionId == null) break;
    input(pane, step.keys);
  }
  snipUi.playing = null;
}

export const stopMacro = () => (stopPlaying = true);

/** Starts recording everything typed into this pane. */
export function startRecording(pane: string) {
  if (!connected(pane)) return;
  snipUi.recording = { pane, steps: [], last: 0 };
  focusTerminal(pane);
}

/** Ends the recording. With `keep` it asks for a name, otherwise it is discarded. */
export function stopRecording(keep = true) {
  const recording = snipUi.recording;
  snipUi.recording = null;
  if (!recording || !keep) return;
  if (!recording.steps.length) return toast(t('macro.empty'), 'err');
  snipUi.naming = $state.snapshot(recording.steps);
}

/** Keys that come in quick succession belong to one step; a line ends with Enter. */
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
