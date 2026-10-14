import { dockerList, manageProbe, processList, serviceList } from './backend';
import { errorText } from './data.svelte';
import { t } from './i18n.svelte';
import { pasteTerminal } from './sessions.svelte';
import { toast } from './state.svelte';
import type { DockerContainer, Listed, ManageAbilities, ManageDone, ProcessSample, ServiceUnit } from './types';

/** Was es auf dem Server einer Sitzung zu verwalten gibt. Einmal je Sitzung nachgesehen. */
const found = $state<Record<number, ManageAbilities>>({});
const asked = new Set<number>();

export const abilitiesOf = (session: number | null): ManageAbilities | undefined => (session === null ? undefined : found[session]);

/** Sieht nach, sobald die Verbindung steht. Scheitert das, gibt es die Reiter eben nicht. */
export function probe(session: number) {
  if (asked.has(session)) return;
  asked.add(session);
  manageProbe(session)
    .then((abilities) => (found[session] = abilities))
    .catch(() => asked.delete(session));
}

export interface Feed<T> {
  value?: T;
  /** Meldung, wenn das Lesen scheiterte. */
  error: string;
}

/**
 * Eine Liste, die nachgeladen wird, solange jemand zusieht (wie die Auslastung in `stats.svelte.ts`).
 * `merge` bekommt den vorigen Stand, etwa um aus zwei Messungen eine Auslastung zu rechnen.
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

  /** Lädt nach, solange jemand zusieht. Liefert eine Funktion, die das Zusehen beendet. */
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
  /** Auslastung je Prozess in Prozent eines Kerns, aus dieser und der vorigen Messung. Fehlt bei der ersten. */
  cpu: Record<number, number>;
}

/** `null`: Der Server gibt die Liste nicht her. */
export const processes = feed<ProcessSample | null, ProcessView | null>(processList, 5000, (next, before) => {
  if (!next) return null;
  const cpu: Record<number, number> = {};
  const old = before?.sample;
  const seconds = old ? next.uptime - old.uptime : 0;
  if (old && seconds > 0) {
    const earlier = new Map(old.processes.map((p) => [p.pid, p]));
    for (const p of next.processes) {
      const was = earlier.get(p.pid);
      // Dieselbe Nummer mit kürzerer Laufzeit ist ein neuer Prozess.
      if (was && p.elapsed >= was.elapsed && p.ticks >= was.ticks) cpu[p.pid] = ((p.ticks - was.ticks) / next.ticksPerSecond / seconds) * 100;
    }
  }
  // Solange es nur eine Messung gibt, bleiben die Zahlen der vorigen stehen (beim ersten Mal: keine).
  return { sample: next, cpu: old && seconds > 0 ? cpu : (before?.cpu ?? {}) };
});

/**
 * Führt eine Aktion aus und sagt, wie sie ausging. Verlangt `sudo` ein Passwort, kommt der Befehl ins Terminal
 * des Bereichs, ohne abgeschickt zu werden: Der Nutzer drückt selbst die Eingabetaste und tippt das Passwort dort.
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

/** Dauer in den zwei größten Einheiten, kurz: „3 T 14 Std“, „5 Std 2 Min“, „6 Std“, „40 s“. */
export function span(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return hours ? t('manage.span.days', { d: days, h: hours }) : t('manage.span.day', { d: days });
  if (hours) return minutes ? t('manage.span.hours', { h: hours, m: minutes }) : t('manage.span.hour', { h: hours });
  return minutes ? t('manage.span.minutes', { m: minutes }) : t('manage.span.seconds', { s: Math.max(0, Math.round(seconds)) });
}
