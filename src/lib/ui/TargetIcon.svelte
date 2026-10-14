<script lang="ts">
  import { hostById } from '../data.svelte';
  import { shellById } from '../local.svelte';
  import type { Target } from '../types';
  import OsIcon from './OsIcon.svelte';
  import ShellIcon from './ShellIcon.svelte';

  /** Das Zeichen für das Ziel einer Sitzung: das System des Hosts, die Shell oder das Protokoll. */
  let { target, size = 'md', bare = false }: { target: Target; size?: 'sm' | 'md' | 'lg'; bare?: boolean } = $props();

  const host = $derived(target.kind === 'host' ? hostById(target.id) : undefined);
</script>

{#if target.kind === 'local'}
  <ShellIcon shell={shellById(target.shell)} {size} {bare} />
{:else}
  <OsIcon os={host?.os} protocol={target.kind === 'telnet' ? 'telnet' : host?.protocol} {size} {bare} />
{/if}
