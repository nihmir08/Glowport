<script lang="ts">
  import { shellLook } from '../local.svelte';
  import type { LocalShell } from '../types';

  /** Kachel einer Shell dieses PCs: PowerShell, Eingabeaufforderung, Git Bash oder das Logo der WSL-Distribution. */
  let { shell, size = 'md', bare = false }: { shell: Pick<LocalShell, 'kind' | 'detail'> | undefined; size?: 'sm' | 'md' | 'lg'; bare?: boolean } = $props();

  const look = $derived(shellLook(shell));
</script>

<span class="os logo" class:sm={size === 'sm'} class:lg={size === 'lg'} class:bare style="--c:{look.color}">
  {#if look.path}
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d={look.path} /></svg>
  {:else}
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{@html look.line}</svg>
  {/if}
</span>
