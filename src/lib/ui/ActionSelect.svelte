<script lang="ts">
  import { t } from '../i18n.svelte';
  import type { Action } from '../quick.svelte';

  /**
   * Auswahlfeld, an dessen Ende Einträge wie „Neuer Schlüssel …“ stehen können. Sie wählen nichts aus,
   * sondern öffnen einen Dialog; die Auswahl bleibt so lange, wie sie war.
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
