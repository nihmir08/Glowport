<script lang="ts">
  import type { Snippet } from 'svelte';

  let { open = $bindable(false), title, wide = false, children, actions }: { open?: boolean; title: string; wide?: boolean; children?: Snippet; actions?: Snippet } = $props();
</script>

<svelte:window onkeydown={(e) => open && e.key === 'Escape' && (open = false)} />

{#if open}
  <div class="ov" role="presentation" onclick={(e) => e.target === e.currentTarget && (open = false)}>
    <div class="dlg" class:wide role="dialog" aria-modal="true" aria-label={title}>
      <h2>{title}</h2>
      <div class="dlg-b">{@render children?.()}</div>
      {#if actions}<div class="dlg-a">{@render actions()}</div>{/if}
    </div>
  </div>
{/if}
