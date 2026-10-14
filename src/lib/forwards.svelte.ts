import { forwardList, forwardStart, forwardStop, onForwards, sessionAnswer } from './backend';
import { errorText, forwardById, hostById } from './data.svelte';
import { has, t, type Key } from './i18n.svelte';
import { claim } from './sessions.svelte';
import { toast } from './state.svelte';
import type { Answer, Forward, ForwardState, Prompt } from './types';

/**
 * Port-Regeln im Betrieb. Die Regeln selbst liegen im Tresor (`vault.forwards`); hier steht, welche eingeschaltet
 * sind und wie es ihnen geht. Sie gehören dem Programm und laufen weiter, wenn kein Terminal offen ist.
 */
export const forwards = $state({
  states: [] as ForwardState[],
  /** Die Regel, deren Verbindungsaufbau gerade auf eine Antwort wartet (Schlüssel des Servers, Passwort). */
  asking: null as { rule: string; connection: number; prompt: Prompt } | null,
});

/** Verbindungen, deren Rückfragen dieses Fenster beantwortet: Regel → Nummer und Abmeldung. */
const links = new Map<string, { connection: number; release: () => void }>();

export const stateOf = (id: string) => forwards.states.find((state) => state.id === id);
/** Regeln, die laufen oder gerade verbinden. Gescheiterte zählen nicht. */
export const activeForwards = () => forwards.states.filter((state) => state.phase !== 'failed');

function unlink(id: string) {
  const link = links.get(id);
  if (!link) return;
  links.delete(id);
  link.release();
  if (forwards.asking?.rule === id) forwards.asking = null;
}

/** Schaltet eine Regel ein. Braucht die Anmeldung eine Rückfrage, erscheint sie wie bei einem Terminal. */
export async function startForward(id: string) {
  unlink(id);
  let connection: number;
  try {
    connection = await forwardStart(id);
  } catch (e) {
    return toast(errorText(e), 'err');
  }
  const release = claim(connection, (event) => {
    if (event.type === 'hostKey' || event.type === 'secret' || event.type === 'interactive') forwards.asking = { rule: id, connection, prompt: event };
    else if (event.type === 'notice') toast(has(`session.notice.${event.code}`) ? t(`session.notice.${event.code}` as Key) : event.message || event.code, 'err');
    else if (event.type === 'end' || (event.type === 'phase' && event.phase === 'connected')) forwards.asking?.connection === connection && (forwards.asking = null);
  });
  links.set(id, { connection, release });
}

export async function stopForward(id: string) {
  unlink(id);
  try {
    await forwardStop(id);
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

export const toggleForward = (id: string, on: boolean) => (on ? startForward(id) : stopForward(id));

/** Beantwortet die Rückfrage der Regel, die gerade verbindet. */
export function answerForward(reply: Answer) {
  const asking = forwards.asking;
  if (!asking) return;
  forwards.asking = null;
  void sessionAnswer(asking.connection, reply);
}

/** Was im Feld der Regel steht, wenn sie gescheitert ist oder neu verbindet. */
export function forwardError(state: ForwardState): string {
  const key = `fwd.err.${state.error}`;
  if (state.error && has(key)) return t(key as Key, { message: state.message ?? '' });
  const end = `session.end.${state.error}`;
  if (state.error && has(end)) return t(end as Key, { message: state.message ?? '' });
  return state.message || state.error || t('fwd.err.unknown');
}

/** Eine Regel in einer Zeile: „lokal 3000 → web-01 → 127.0.0.1:3000“. */
export function forwardRoute(rule: Pick<Forward, 'kind' | 'host' | 'bindAddress' | 'bindPort' | 'destHost' | 'destPort'>): string {
  const host = hostById(rule.host)?.name ?? '?';
  const bind = rule.bindAddress && rule.bindAddress !== '127.0.0.1' && rule.bindAddress !== 'localhost' ? `${rule.bindAddress}:${rule.bindPort}` : String(rule.bindPort);
  if (rule.kind === 'dynamic') return `${t('fwd.kind.dynamic.short')} ${bind} → ${host}`;
  if (rule.kind === 'remote') return `${host}:${bind} → ${t('fwd.thispc')} → ${rule.destHost}:${rule.destPort}`;
  return `${t('fwd.kind.local.short')} ${bind} → ${host} → ${rule.destHost}:${rule.destPort}`;
}

/** Die Adresse, unter der eine laufende Regel auf diesem PC zu erreichen ist; bei `remote` die am Server. */
export function forwardEndpoint(rule: Forward): string {
  const address = !rule.bindAddress || rule.bindAddress === '0.0.0.0' ? '127.0.0.1' : rule.bindAddress;
  return rule.kind === 'remote' ? `${hostById(rule.host)?.address ?? '?'}:${rule.bindPort}` : `${address}:${rule.bindPort}`;
}

export const forwardName = (id: string) => forwardById(id)?.name ?? '';

/** Holt den Stand und meldet sich für Änderungen an. Einmal beim Start aufrufen. */
export function initForwards(): () => void {
  forwardList()
    .then((list) => (forwards.states = list))
    .catch((e) => console.error('Port-Regeln nicht lesbar', e));
  return onForwards((list) => {
    forwards.states = list;
    // Eine Regel, die nicht mehr eingeschaltet ist, wartet auch auf keine Antwort mehr.
    for (const id of [...links.keys()]) if (!list.some((state) => state.id === id)) unlink(id);
  });
}
