<script lang="ts">
  import { colorOf, hostById } from '../data.svelte';
  import { places, type Layout } from '../layout';
  import { titleOf } from '../sessions.svelte';
  import type { SavedLayout, Target } from '../types';

  /** Kleines Abbild einer Anordnung: jeder Bereich als Feld mit dem Namen seines Ziels. */
  let { layout, small = false }: { layout: SavedLayout; small?: boolean } = $props();

  const cells = $derived(
    places(layout as Layout<Target>).map(({ leaf, rect }) => {
      const host = leaf.kind === 'host' ? hostById(leaf.id) : undefined;
      return { rect, name: titleOf(leaf) ?? '?', color: (host && colorOf(host)) || 'var(--accent)' };
    }),
  );
  const pct = (n: number) => `${(n * 100).toFixed(3)}%`;
</script>

<div class="lprev" class:small aria-hidden="true">
  {#each cells as cell, i (i)}
    <div style="left:{pct(cell.rect.x)};top:{pct(cell.rect.y)};width:{pct(cell.rect.w)};height:{pct(cell.rect.h)};--c:{cell.color}">
      <span><i></i>{#if !small}{cell.name}{/if}</span>
    </div>
  {/each}
</div>
