import type { Side } from './layout';
import { leaves } from './layout';
import { mergeTab, movePane, moveTab, paneToTab, sendToWindow, swapPanes, tabByKey, tabOf, view } from './sessions.svelte';
import { errorText } from './data.svelte';
import { toast } from './state.svelte';

/** Dragging tabs and panes with the mouse: reorder, place side by side, detach as a tab or window of its own. */

export type Dragged = { kind: 'pane'; key: string } | { kind: 'tab'; key: string };
export type Drop =
  /** Place at the side of a pane or (only panes of the same tab) swap with it. */
  | { kind: 'pane'; pane: string; side: Side | 'swap' }
  /** Into the tab bar, before the tab with this number. */
  | { kind: 'tabbar'; index: number }
  /** Outside the window: a window of its own. */
  | { kind: 'outside' };

export const drag = $state({
  item: null as Dragged | null,
  label: '',
  color: '',
  x: 0,
  y: 0,
  drop: null as Drop | null,
});

/** From this distance in pixels a pressed mouse counts as dragging and no longer as a click. */
const THRESHOLD = 6;
/** If the mouse stays over another tab this long while dragging, it comes to the front. */
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
    // Lingering over another tab brings it to the front, so you can drop into its panes.
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
  // A pane cannot be placed next to itself, a tab not into itself.
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
 * Moves a tab or a single pane into another window. Without a destination a new one is created;
 * `atCursor` takes the Glowport window under the mouse pointer, if there is one.
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
    // A tab's only pane is the tab itself.
    return leaves(from.layout).length > 1 ? paneToTab(item.key, drop.index) : moveTab(from.key, drop.index);
  }
  if (item.kind === 'tab') return drop.side === 'swap' ? undefined : mergeTab(item.key, drop.pane, drop.side);
  if (drop.side === 'swap') return swapPanes(item.key, drop.pane);
  movePane(item.key, drop.pane, drop.side);
}

/**
 * Starts with the left mouse button pressed. If the mouse moves far enough, it is a drag;
 * otherwise it stays a click, and the element handles it as usual.
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
      // With the mouse captured, movements arrive from outside the window too.
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
    // The click that follows the release should trigger nothing. If it does not come, the catcher is removed right away.
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

/** Position of the insertion mark in the tab bar while dragging there; otherwise -1. */
export const tabbarIndex = () => (drag.item && drag.drop?.kind === 'tabbar' ? drag.drop.index : -1);
