import { dockerList, manageProbe, processList, serviceList } from './backend';
import { errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { pasteTerminal } from './sessions.svelte';
import { toast } from './state.svelte';
import type { DockerContainer, Listed, ManageAbilities, ManageDone, ProcessSample, ServiceUnit } from './types';

/** What there is to manage on a session's server. Checked once per session. */
const found = $state<Record<number, ManageAbilities>>({});
const asked = new Set<number>();

export const abilitiesOf = (session: number | null): ManageAbilities | undefined => (session === null ? undefined : found[session]);

/** Checks as soon as the connection is up. If that fails, there simply are no tabs. */
export function probe(session: number) {
  if (asked.has(session)) return;
  asked.add(session);
  manageProbe(session)
    .then((abilities) => (found[session] = abilities))
    .catch(() => asked.delete(session));
}

export interface Feed<T> {
  value?: T;
  /** Message if reading failed. */
  error: string;
}

/**
 * A list that is reloaded as long as someone is watching (like the load in `stats.svelte.ts`).
 * `merge` gets the previous state, e.g. to compute a load from two measurements.
 */
function feed<Raw, T>(load: (session: number) => Promise<Raw>, interval: number, merge: (next: Raw, before: T | undefined) => T) {
  const states = $state<Record<number, Feed<T>>>({});
  const watchers = new Map<number, { count: number; timer: ReturnType<typeof setInterval> }>();

  async function refresh(session: number) {
    const state = states[session];
    if (!state) return;
    try {
      const next = await load(session);
      if (!states[session]) return;
      state.value = merge(next, state.value);
      state.error = '';
    } catch (e) {
      if (states[session]) state.error = errorText(e);
    }
  }

  /** Reloads as long as someone is watching. Returns a function that ends watching. */
  function watch(session: number): () => void {
    states[session] ??= { error: '' };
    const watcher = watchers.get(session);
    if (watcher) watcher.count += 1;
    else {
      watchers.set(session, { count: 1, timer: setInterval(() => void refresh(session), interval) });
      void refresh(session);
    }
    return () => {
      const current = watchers.get(session);
      if (!current || --current.count > 0) return;
      clearInterval(current.timer);
      watchers.delete(session);
    };
  }

  return { of: (session: number | null): Feed<T> | undefined => (session === null ? undefined : states[session]), watch, refresh };
}

export const docker = feed<Listed<DockerContainer[]>, Listed<DockerContainer[]>>(dockerList, 5000, (next) => next);
export const services = feed<Listed<ServiceUnit[]>, Listed<ServiceUnit[]>>(serviceList, 10_000, (next) => next);

export interface ProcessView {
  sample: ProcessSample;
  /** Load per process in percent of one core, from this and the previous measurement. Missing for the first. */
  cpu: Record<number, number>;
}

/** `null`: the server does not provide the list. */
export const processes = feed<ProcessSample | null, ProcessView | null>(processList, 5000, (next, before) => {
  if (!next) return null;
  const cpu: Record<number, number> = {};
  const old = before?.sample;
  const seconds = old ? next.uptime - old.uptime : 0;
  if (old && seconds > 0) {
    const earlier = new Map(old.processes.map((p) => [p.pid, p]));
    for (const p of next.processes) {
      const was = earlier.get(p.pid);
      // The same number with a shorter run time is a new process.
      if (was && p.elapsed >= was.elapsed && p.ticks >= was.ticks) cpu[p.pid] = ((p.ticks - was.ticks) / next.ticksPerSecond / seconds) * 100;
    }
  }
  // As long as there is only one measurement, the numbers of the previous one stay (the first time: none).
  return { sample: next, cpu: old && seconds > 0 ? cpu : (before?.cpu ?? {}) };
});

/**
 * Runs an action and says how it went. If `sudo` asks for a password, the command goes into the pane's terminal
 * without being sent: the user presses Enter themselves and types the password there.
 */
export async function act(pane: string, work: () => Promise<ManageDone>, done: string): Promise<boolean> {
  try {
    const result = await work();
    if (result.outcome === 'password') {
      pasteTerminal(pane, result.command);
      toast(t('manage.typed'), 'info');
      return false;
    }
    toast(done, 'ok');
    return true;
  } catch (e) {
    toast(errorText(e), 'err');
    return false;
  }
}

/** Duration in the two largest units, short: “3 d 14 h”, “5 h 2 min”, “6 h”, “40 s”. */
export function span(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return hours ? t('manage.span.days', { d: days, h: hours }) : t('manage.span.day', { d: days });
  if (hours) return minutes ? t('manage.span.hours', { h: hours, m: minutes }) : t('manage.span.hour', { h: hours });
  return minutes ? t('manage.span.minutes', { m: minutes }) : t('manage.span.seconds', { s: Math.max(0, Math.round(seconds)) });
}
