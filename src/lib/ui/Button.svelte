<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { IconName } from '../icons';
  import Icon from './Icon.svelte';

  let {
    variant = 'default',
    size = 'md',
    icon,
    active = false,
    disabled = false,
    title,
    onclick,
    children,
  }: {
    variant?: 'default' | 'primary' | 'ghost' | 'danger';
    size?: 'md' | 'sm';
    icon?: IconName;
    active?: boolean;
    disabled?: boolean;
    title?: string;
    onclick?: (e: MouseEvent) => void;
    children?: Snippet;
  } = $props();
</script>

<!-- type="button": in a form the button would otherwise be a submit button and save on click. -->
<button type="button" class="btn {variant} {size}" class:act={active} class:ico={!children} {disabled} {title} aria-label={children ? undefined : title} {onclick}>
  {#if icon}<Icon name={icon} size={size === 'sm' ? 13 : 15} />{/if}{@render children?.()}
</button>
