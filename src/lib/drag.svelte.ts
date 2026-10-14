import type { Side } from './layout';
import { leaves } from './layout';
import { mergeTab, movePane, moveTab, paneToTab, sendToWindow, swapPanes, tabByKey, tabOf, view } from './sessions.svelte';
import { errorText } from './data.svelte';
import { toast } from './state.svelte';

/** Ziehen von Tabs und Bereichen mit der Maus: umordnen, nebeneinander legen, als eigenen Tab oder eigenes Fenster herauslösen. */

export type Dragged = { kind: 'pane'; key: string } | { kind: 'tab'; key: string };
export type Drop =
  /** An die Seite eines Bereichs legen oder (nur Bereiche desselben Tabs) mit ihm tauschen. */
  | { kind: 'pane'; pane: string; side: Side | 'swap' }
  /** In die Tab-Leiste, vor den Tab mit dieser Nummer. */
  | { kind: 'tabbar'; index: number }
  /** Außerhalb des Fensters: eigenes Fenster. */
  | { kind: 'outside' };

export const drag = $state({
  item: null as Dragged | null,
  label: '',
  color: '',
  x: 0,
  y: 0,
  drop: null as Drop | null,
});

/** Ab dieser Strecke in Pixeln gilt eine gedrückte Maus als Ziehen und nicht mehr als Klick. */
const THRESHOLD = 6;
/** Bleibt die Maus beim Ziehen so lange über einem anderen Tab, kommt er nach vorn. */
const HOVER_MS = 550;

let hoverTab: string | null = null;
let hoverTimer: ReturnType<typeof setTimeout> | undefined;

function clearHover() {
  clearTimeout(hoverTimer);
  hoverTab = null;
}

function dropAt(item: Dragged, x: number, y: number): Drop | null {
  if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) return { kind: 'outside' };
  const under = document.elementsFromPoint(x, y);

  const bar = under.find((el) => el.classList.contains('tabs'));
  if (bar) {
    const pills = [...bar.querySelectorAll<HTMLElement>('[data-tab]')];
    const over = pills.find((el) => under.includes(el))?.dataset.tab ?? null;
    // Über einem fremden Tab verweilen holt ihn nach vorn, damit man in seine Bereiche ablegen kann.
    if (over !== hoverTab) {
      clearHover();
      if (over && over !== view.active && !(item.kind === 'tab' && item.key === over)) {
        hoverTab = over;
        hoverTimer = setTimeout(() => tabByKey(over) && (view.active = over), HOVER_MS);
      }
    }
    const index = pills.findIndex((el) => {
      const box = el.getBoundingClientRect();
      return x < box.left + box.width / 2;
    });
    return { kind: 'tabbar', index: index < 0 ? pills.length : index };
  }
  clearHover();

  const target = under.find((el): el is HTMLElement => el instanceof HTMLElement && !!el.dataset.pane);
  if (!target) return null;
  const pane = target.dataset.pane!;
  const tab = tabOf(pane);
  if (!tab) return null;
  // Ein Bereich lässt sich nicht an sich selbst legen, ein Tab nicht in sich selbst.
  if (item.kind === 'pane' && item.key === pane) return null;
  if (item.kind === 'tab' && item.key === tab.key) return null;

  const box = target.getBoundingClientRect();
  const fx = (x - box.left) / box.width;
  const fy = (y - box.top) / box.height;
  const sameTab = item.kind === 'pane' && tabOf(item.key) === tab;
  if (sameTab && Math.abs(fx - 0.5) < 0.2 && Math.abs(fy - 0.5) < 0.2) return { kind: 'pane', pane, side: 'swap' };
  const edges: [number, Side][] = [
    [fx, 'left'],
    [1 - fx, 'right'],
    [fy, 'top'],
    [1 - fy, 'bottom'],
  ];
  return { kind: 'pane', pane, side: edges.sort((a, b) => a[0] - b[0])[0][1] };
}

/**
 * Verlegt einen Tab oder einen einzelnen Bereich in ein anderes Fenster. Ohne Ziel entsteht ein neues;
 * `atCursor` nimmt das Glowport-Fenster unter dem Mauszeiger, falls dort eines liegt.
 */
export async function detachToWindow(item: Dragged, target: { to?: string; atCursor?: boolean } = {}) {
  try {
    await sendToWindow(item.kind === 'tab' ? { tab: item.key } : { pane: item.key }, target);
  } catch (e) {
    toast(errorText(e), 'err');
  }
}

function perform(item: Dragged, drop: Drop) {
  if (drop.kind === 'outside') return void detachToWindow(item, { atCursor: true });
  if (drop.kind === 'tabbar') {
    if (item.kind === 'tab') return moveTab(item.key, drop.index);
    const from = tabOf(item.key);
    if (!from) return;
    // Der einzige Bereich eines Tabs ist der Tab selbst.
    return leaves(from.layout).length > 1 ? paneToTab(item.key, drop.index) : moveTab(from.key, drop.index);
  }
  if (item.kind === 'tab') return drop.side === 'swap' ? undefined : mergeTab(item.key, drop.pane, drop.side);
  if (drop.side === 'swap') return swapPanes(item.key, drop.pane);
  movePane(item.key, drop.pane, drop.side);
}

/**
 * Beginnt bei gedrückter linker Maustaste. Wird die Maus weit genug bewegt, ist es ein Ziehen;
 * sonst bleibt es ein Klick, und das Element behandelt ihn wie gewohnt.
 */
export function startDrag(event: PointerEvent, item: Dragged, label: string, color: string) {
  if (event.button !== 0 || (event.target as Element).closest('button, input')) return;
  const origin = { x: event.clientX, y: event.clientY };
  const source = event.currentTarget as HTMLElement;
  const pointer = event.pointerId;
  let active = false;

  const move = (e: PointerEvent) => {
    if (!active) {
      if (Math.hypot(e.clientX - origin.x, e.clientY - origin.y) < THRESHOLD) return;
      active = true;
      // Mit eingefangener Maus kommen die Bewegungen auch von außerhalb des Fensters an.
      source.setPointerCapture(pointer);
      Object.assign(drag, { item, label, color });
    }
    drag.x = e.clientX;
    drag.y = e.clientY;
    drag.drop = dropAt(item, e.clientX, e.clientY);
  };
  const finish = (e: PointerEvent) => {
    removeEventListener('pointermove', move, true);
    removeEventListener('pointerup', finish, true);
    removeEventListener('pointercancel', finish, true);
    removeEventListener('keydown', escape, true);
    clearHover();
    if (!active) return;
    const drop = e.type === 'pointerup' ? drag.drop : null;
    Object.assign(drag, { item: null, drop: null });
    // Der Klick, der auf das Loslassen folgt, soll nichts auslösen. Bleibt er aus, wird der Fänger gleich wieder entfernt.
    const swallow = (click: Event) => click.stopPropagation();
    addEventListener('click', swallow, { capture: true, once: true });
    setTimeout(() => removeEventListener('click', swallow, true), 0);
    if (drop) perform(item, drop);
  };
  const escape = (e: KeyboardEvent) => {
    if (e.key !== 'Escape') return;
    e.stopPropagation();
    finish(new PointerEvent('pointercancel'));
  };
  addEventListener('pointermove', move, true);
  addEventListener('pointerup', finish, true);
  addEventListener('pointercancel', finish, true);
  addEventListener('keydown', escape, true);
}

/** Stelle der Einfügemarke in der Tab-Leiste, solange dorthin gezogen wird; sonst -1. */
export const tabbarIndex = () => (drag.item && drag.drop?.kind === 'tabbar' ? drag.drop.index : -1);
