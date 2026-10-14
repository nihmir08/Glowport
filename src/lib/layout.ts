// Anordnung geteilter Bereiche: ein Baum, dessen Blätter Bereiche sind und dessen Knoten ihre Fläche in zwei Teile schneiden.
// Reine Funktionen ohne Zustand; jede Änderung liefert einen neuen Baum.

export type Side = 'left' | 'right' | 'top' | 'bottom';

/** `row` legt `a` links neben `b`, `col` legt `a` über `b`. `ratio` ist der Anteil von `a`. */
export type Layout<L = string> = { pane: L } | { dir: 'row' | 'col'; ratio: number; a: Layout<L>; b: Layout<L> };

/** Rechteck in Anteilen der Gesamtfläche, 0 bis 1. */
export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Trennlinie zwischen zwei Teilen. `path` nennt den Knoten (Folge aus `a` und `b` ab der Wurzel). */
export interface Divider {
  path: string;
  dir: 'row' | 'col';
  /** Fläche des Knotens, den die Linie teilt. */
  area: Rect;
  ratio: number;
}

const FULL: Rect = { x: 0, y: 0, w: 1, h: 1 };
export const MIN_RATIO = 0.12;

function cut(r: Rect, dir: 'row' | 'col', ratio: number): [Rect, Rect] {
  return dir === 'row'
    ? [
        { ...r, w: r.w * ratio },
        { ...r, x: r.x + r.w * ratio, w: r.w * (1 - ratio) },
      ]
    : [
        { ...r, h: r.h * ratio },
        { ...r, y: r.y + r.h * ratio, h: r.h * (1 - ratio) },
      ];
}

export function leaves<L>(layout: Layout<L>): L[] {
  return 'pane' in layout ? [layout.pane] : [...leaves(layout.a), ...leaves(layout.b)];
}

export function rects(layout: Layout, area: Rect = FULL, out = new Map<string, Rect>()): Map<string, Rect> {
  if ('pane' in layout) out.set(layout.pane, area);
  else {
    const [a, b] = cut(area, layout.dir, layout.ratio);
    rects(layout.a, a, out);
    rects(layout.b, b, out);
  }
  return out;
}

export function dividers(layout: Layout, area: Rect = FULL, path = '', out: Divider[] = []): Divider[] {
  if ('pane' in layout) return out;
  out.push({ path, dir: layout.dir, area, ratio: layout.ratio });
  const [a, b] = cut(area, layout.dir, layout.ratio);
  dividers(layout.a, a, `${path}a`, out);
  dividers(layout.b, b, `${path}b`, out);
  return out;
}

export function setRatio<L>(layout: Layout<L>, path: string, ratio: number): Layout<L> {
  if ('pane' in layout) return layout;
  if (!path) return { ...layout, ratio: Math.min(1 - MIN_RATIO, Math.max(MIN_RATIO, ratio)) };
  return path[0] === 'a' ? { ...layout, a: setRatio(layout.a, path.slice(1), ratio) } : { ...layout, b: setRatio(layout.b, path.slice(1), ratio) };
}

/** Setzt `added` an die Seite `side` des Bereichs `target`; beide teilen sich dessen Fläche je zur Hälfte. */
export function insert<L>(layout: Layout<L>, target: L, added: Layout<L>, side: Side): Layout<L> {
  if ('pane' in layout) {
    if (layout.pane !== target) return layout;
    const first = side === 'left' || side === 'top';
    return { dir: side === 'left' || side === 'right' ? 'row' : 'col', ratio: 0.5, a: first ? added : layout, b: first ? layout : added };
  }
  return { ...layout, a: insert(layout.a, target, added, side), b: insert(layout.b, target, added, side) };
}

/** Entfernt einen Bereich; sein Nachbar übernimmt die Fläche. `null`, wenn nichts übrig bleibt. */
export function remove<L>(layout: Layout<L>, pane: L): Layout<L> | null {
  if ('pane' in layout) return layout.pane === pane ? null : layout;
  const a = remove(layout.a, pane);
  const b = remove(layout.b, pane);
  return a && b ? { ...layout, a, b } : (a ?? b);
}

/** Baut den Baum mit anderen Blättern nach. Blätter, für die `to` nichts liefert, fallen weg. */
export function mapLeaves<L, M>(layout: Layout<L>, to: (leaf: L) => M | null | undefined): Layout<M> | null {
  if ('pane' in layout) {
    const leaf = to(layout.pane);
    return leaf == null ? null : { pane: leaf };
  }
  const a = mapLeaves(layout.a, to);
  const b = mapLeaves(layout.b, to);
  return a && b ? { dir: layout.dir, ratio: layout.ratio, a, b } : (a ?? b);
}

/** Tauscht zwei Bereiche gegeneinander. */
export function swap(layout: Layout, one: string, other: string): Layout {
  return mapLeaves(layout, (leaf) => (leaf === one ? other : leaf === other ? one : leaf))!;
}

/** Jedes Blatt mit seinem Platz, in der Reihenfolge des Baums. */
export function places<L>(layout: Layout<L>, area: Rect = FULL): { leaf: L; rect: Rect }[] {
  if ('pane' in layout) return [{ leaf: layout.pane, rect: area }];
  const [a, b] = cut(area, layout.dir, layout.ratio);
  return [...places(layout.a, a), ...places(layout.b, b)];
}
