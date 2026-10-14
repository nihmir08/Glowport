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

<!-- type="button": In einem Formular wäre der Knopf sonst ein Absende-Knopf und würde beim Klick speichern. -->
<button type="button" class="btn {variant} {size}" class:act={active} class:ico={!children} {disabled} {title} aria-label={children ? undefined : title} {onclick}>
  {#if icon}<Icon name={icon} size={size === 'sm' ? 13 : 15} />{/if}{@render children?.()}
</button>
