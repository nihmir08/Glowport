import { sessionStats } from './backend';
import { settings } from './state.svelte';
import type { StatsSample } from './types';

/** How many measurements per session stay for the curves (at two seconds' interval a good two minutes, at 60 a good hour). */
const KEEP = 70;
/** Selectable measurement intervals in seconds. Every measurement opens a channel; below one second it gets too much. */
export const STATS_INTERVALS = [1, 2, 5, 10, 30, 60];
const interval = () => (STATS_INTERVALS.includes(settings.statsInterval) ? settings.statsInterval : 2) * 1000;

export interface History {
  samples: StatsSample[];
  /** The server does not provide the numbers (not Linux). */
  unsupported: boolean;
}

/** Measurements per session, so the curves stay when switching between panes. */
const histories = $state<Record<number, History>>({});
const watchers = new Map<number, { count: number; timer?: ReturnType<typeof setTimeout> }>();

export const historyOf = (session: number | null): History | undefined => (session === null ? undefined : histories[session]);

async function measure(session: number) {
  const history = histories[session];
  if (!history || history.unsupported) return;
  try {
    const sample = await sessionStats(session);
    if (!histories[session]) return;
    if (!sample) return void (history.unsupported = true);
    history.samples = [...history.samples.slice(-(KEEP - 1)), sample];
  } catch {
    // The session ended or the measurement did not get through: the next one tries again.
  }
}

/**
 * Measures a session's server as long as someone is watching. Returns a function that ends watching;
 * measurements only happen while the sidebar shows the server info.
 */
export function watchStats(session: number): () => void {
  histories[session] ??= { samples: [], unsupported: false };
  const watcher = watchers.get(session);
  if (watcher) watcher.count += 1;
  else {
    watchers.set(session, { count: 1 });
    void cycle(session);
  }
  return () => {
    const current = watchers.get(session);
    if (!current || --current.count > 0) return;
    clearTimeout(current.timer);
    watchers.delete(session);
  };
}

/** Measures and only plans the next measurement afterwards: at one second's interval slow answers do not overtake each other. */
async function cycle(session: number) {
  await measure(session);
  const watcher = watchers.get(session);
  if (watcher) watcher.timer = setTimeout(() => void cycle(session), interval());
}

/** The interval was changed: every running series measures right away and then follows the new interval. */
export function retimeStats() {
  for (const [session, watcher] of watchers) {
    clearTimeout(watcher.timer);
    void cycle(session);
  }
}

/** Forgets the measurements of ended sessions. */
export function pruneStats(live: number[]) {
  for (const key of Object.keys(histories)) if (!live.includes(Number(key)) && !watchers.has(Number(key))) delete histories[Number(key)];
}

/** Processor load between two measurements, 0 to 1. */
export function cpuBetween(a: StatsSample, b: StatsSample): number {
  const total = b.cpu.total - a.cpu.total;
  return total > 0 ? Math.min(1, Math.max(0, 1 - (b.cpu.idle - a.cpu.idle) / total)) : 0;
}

/** Bytes per second in both directions between two measurements. */
export function netBetween(a: StatsSample, b: StatsSample): { down: number; up: number } {
  const seconds = Math.max(0.001, (b.at - a.at) / 1000);
  return { down: Math.max(0, b.net.rx - a.net.rx) / seconds, up: Math.max(0, b.net.tx - a.net.tx) / seconds };
}
