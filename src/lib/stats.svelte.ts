import { sessionStats } from './backend';
import { settings } from './state.svelte';
import type { StatsSample } from './types';

/** Wie viele Messungen je Sitzung für die Kurven bleiben (bei zwei Sekunden Abstand gut zwei Minuten, bei 60 gut eine Stunde). */
const KEEP = 70;
/** Wählbare Abstände der Messungen in Sekunden. Jede Messung öffnet einen Kanal; unter einer Sekunde wird es zu viel. */
export const STATS_INTERVALS = [1, 2, 5, 10, 30, 60];
const interval = () => (STATS_INTERVALS.includes(settings.statsInterval) ? settings.statsInterval : 2) * 1000;

export interface History {
  samples: StatsSample[];
  /** Der Server gibt die Zahlen nicht her (kein Linux). */
  unsupported: boolean;
}

/** Messungen je Sitzung, damit die Kurven beim Wechsel zwischen Bereichen stehen bleiben. */
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
    // Die Sitzung ist zu Ende oder die Messung kam nicht durch: Die nächste versucht es wieder.
  }
}

/**
 * Misst den Server einer Sitzung, solange jemand zusieht. Liefert eine Funktion, die das Zusehen beendet;
 * gemessen wird nur, während die Seitenleiste die Server-Info zeigt.
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

/** Misst und plant die nächste Messung erst danach: Bei einer Sekunde Abstand überholen sich langsame Antworten nicht. */
async function cycle(session: number) {
  await measure(session);
  const watcher = watchers.get(session);
  if (watcher) watcher.timer = setTimeout(() => void cycle(session), interval());
}

/** Der Abstand wurde geändert: Jede laufende Messreihe misst sofort und folgt dann dem neuen Abstand. */
export function retimeStats() {
  for (const [session, watcher] of watchers) {
    clearTimeout(watcher.timer);
    void cycle(session);
  }
}

/** Vergisst die Messungen beendeter Sitzungen. */
export function pruneStats(live: number[]) {
  for (const key of Object.keys(histories)) if (!live.includes(Number(key)) && !watchers.has(Number(key))) delete histories[Number(key)];
}

/** Auslastung der Prozessoren zwischen zwei Messungen, 0 bis 1. */
export function cpuBetween(a: StatsSample, b: StatsSample): number {
  const total = b.cpu.total - a.cpu.total;
  return total > 0 ? Math.min(1, Math.max(0, 1 - (b.cpu.idle - a.cpu.idle) / total)) : 0;
}

/** Bytes je Sekunde in beide Richtungen zwischen zwei Messungen. */
export function netBetween(a: StatsSample, b: StatsSample): { down: number; up: number } {
  const seconds = Math.max(0.001, (b.at - a.at) / 1000);
  return { down: Math.max(0, b.net.rx - a.net.rx) / seconds, up: Math.max(0, b.net.tx - a.net.tx) / seconds };
}
