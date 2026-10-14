<script lang="ts" generics="T extends string | number">
  import type { IconName } from '../icons';
  import Icon from './Icon.svelte';

  let {
    options,
    value = $bindable(),
    label,
  }: { options: { value: T; label?: string; icon?: IconName; title?: string }[]; value: T; label: string } = $props();
</script>

<div class="seg" role="radiogroup" aria-label={label}>
  {#each options as o (o.value)}
    <button type="button" role="radio" aria-checked={value === o.value} aria-label={o.label ? undefined : o.title} class:on={value === o.value} title={o.title} onclick={() => (value = o.value)}>
      {#if o.icon}<Icon name={o.icon} size={15} />{/if}{o.label ?? ''}
    </button>
  {/each}
</div>
