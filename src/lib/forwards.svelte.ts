import { forwardList, forwardStart, forwardStop, onForwards, sessionAnswer } from './backend';
import { errorText, forwardById, hostById } from './data.svelte';
import { has, t, type Key } from './i18n.svelte';
import { claim } from './sessions.svelte';
import { toast } from './state.svelte';
import type { Answer, Forward, ForwardState, Prompt } from './types';

/**
 * Port rules in operation. The rules themselves are in the vault (`vault.forwards`); here is which ones are switched on
 * and how they are doing. They belong to the program and keep running when no terminal is open.
 */
export const forwards = $state({
  states: [] as ForwardState[],
  /** The rule whose connection setup is currently waiting for an answer (server key, password). */
  asking: null as { rule: string; connection: number; prompt: Prompt } | null,
});

/** Connections whose prompts this window answers: rule → number and unsubscribe. */
const links = new Map<string, { connection: number; release: () => void }>();

export const stateOf = (id: string) => forwards.states.find((state) => state.id === id);
/** Rules that are running or connecting right now. Failed ones do not count. */
export const activeForwards = () => forwards.states.filter((state) => state.phase !== 'failed');

function unlink(id: string) {
  const link = links.get(id);
  if (!link) return;
  links.delete(id);
  link.release();
  if (forwards.asking?.rule === id) forwards.asking = null;
}

/** Switches a rule on. If signing in needs a prompt, it appears as for a terminal. */
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

/** Answers the prompt of the rule currently connecting. */
export function answerForward(reply: Answer) {
  const asking = forwards.asking;
  if (!asking) return;
  forwards.asking = null;
  void sessionAnswer(asking.connection, reply);
}

/** What is in the rule's field when it failed or is reconnecting. */
export function forwardError(state: ForwardState): string {
  const key = `fwd.err.${state.error}`;
  if (state.error && has(key)) return t(key as Key, { message: state.message ?? '' });
  const end = `session.end.${state.error}`;
  if (state.error && has(end)) return t(end as Key, { message: state.message ?? '' });
  return state.message || state.error || t('fwd.err.unknown');
}

/** A rule in one line: “local 3000 → web-01 → 127.0.0.1:3000”. */
export function forwardRoute(rule: Pick<Forward, 'kind' | 'host' | 'bindAddress' | 'bindPort' | 'destHost' | 'destPort'>): string {
  const host = hostById(rule.host)?.name ?? '?';
  const bind = rule.bindAddress && rule.bindAddress !== '127.0.0.1' && rule.bindAddress !== 'localhost' ? `${rule.bindAddress}:${rule.bindPort}` : String(rule.bindPort);
  if (rule.kind === 'dynamic') return `${t('fwd.kind.dynamic.short')} ${bind} → ${host}`;
  if (rule.kind === 'remote') return `${host}:${bind} → ${t('fwd.thispc')} → ${rule.destHost}:${rule.destPort}`;
  return `${t('fwd.kind.local.short')} ${bind} → ${host} → ${rule.destHost}:${rule.destPort}`;
}

/** The address at which a running rule can be reached on this PC; for `remote` the one on the server. */
export function forwardEndpoint(rule: Forward): string {
  const address = !rule.bindAddress || rule.bindAddress === '0.0.0.0' ? '127.0.0.1' : rule.bindAddress;
  return rule.kind === 'remote' ? `${hostById(rule.host)?.address ?? '?'}:${rule.bindPort}` : `${address}:${rule.bindPort}`;
}

export const forwardName = (id: string) => forwardById(id)?.name ?? '';

/** Fetches the state and subscribes to changes. Call once on start. */
export function initForwards(): () => void {
  forwardList()
    .then((list) => (forwards.states = list))
    .catch((e) => console.error('Port-Regeln nicht lesbar', e));
  return onForwards((list) => {
    forwards.states = list;
    // A rule that is no longer switched on is not waiting for an answer any more either.
    for (const id of [...links.keys()]) if (!list.some((state) => state.id === id)) unlink(id);
  });
}
