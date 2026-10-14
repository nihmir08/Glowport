<script lang="ts">
  import { ICONS } from '../icons';
  import { UNKNOWN_COLOR, osEntry } from '../os';

  /**
   * Kachel mit dem Logo eines Betriebssystems. Ein unbekanntes System bekommt ein neutrales Zeichen: einen Server,
   * bei Telnet ein Netz, bei einer seriellen Leitung einen Stecker (`protocol`).
   * `bare` zeigt nur das Logo ohne Kachel, für enge Stellen wie die Kopfzeile eines Bereichs.
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
