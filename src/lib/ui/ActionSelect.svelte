<script lang="ts">
  import { t } from '../i18n.svelte';
  import type { Action } from '../quick.svelte';

  /**
   * Select field that can have entries like “New key …” at its end. They select nothing
   * but open a dialog; meanwhile the selection stays as it was.
   */
  let {
    value = $bindable(''),
    options,
    actions = [],
    over = false,
    label,
  }: { value?: string; options: { value: string; label: string }[]; actions?: Action[]; over?: boolean; label?: string } = $props();

  const ACTION = '\u0000neu:';

  function choose(event: Event & { currentTarget: HTMLSelectElement }) {
    const picked = event.currentTarget.value;
    if (!picked.startsWith(ACTION)) return void (value = picked);
    event.currentTarget.value = value;
    actions[Number(picked.slice(ACTION.length))]?.run();
  }
</script>

<select class="dropdown" class:over aria-label={label} {value} onchange={choose}>
  {#each options as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
  {#if actions.length}
    <optgroup label={t('quick.new')}>
      {#each actions as action, i (i)}<option value="{ACTION}{i}">{action.label}</option>{/each}
    </optgroup>
  {/if}
</select>
