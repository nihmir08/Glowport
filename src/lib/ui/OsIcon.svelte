<script lang="ts">
  import { ICONS } from '../icons';
  import { UNKNOWN_COLOR, osEntry } from '../os';

  /**
   * Tile with an operating system's logo. An unknown system gets a neutral symbol: a server,
   * for Telnet a network, for a serial line a plug (`protocol`).
   * `bare` shows only the logo without a tile, for tight spots like a pane's header row.
   */
  let { os, size = 'md', bare = false, protocol }: { os: string | null | undefined; size?: 'sm' | 'md' | 'lg'; bare?: boolean; protocol?: string } = $props();

  const entry = $derived(osEntry(os));
  const fallback = $derived(protocol === 'serial' ? ICONS.plug : protocol === 'telnet' ? ICONS.network : ICONS.server);
</script>

<span class="os logo" class:sm={size === 'sm'} class:lg={size === 'lg'} class:bare style="--c:{entry?.color ?? UNKNOWN_COLOR}" title={entry?.name}>
  {#if entry}
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d={entry.icon} /></svg>
  {:else}
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{@html fallback}</svg>
  {/if}
</span>
