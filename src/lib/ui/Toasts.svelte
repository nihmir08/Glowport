<script lang="ts">
  import { toasts } from '../state.svelte';
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}"><i></i>{t.text}</div>
  {/each}
</div>
