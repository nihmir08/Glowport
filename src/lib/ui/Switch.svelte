<script lang="ts">
  let { checked = $bindable(false), disabled = false, label }: { checked?: boolean; disabled?: boolean; label: string } = $props();
</script>

<button type="button" class="swt" class:on={checked} role="switch" aria-checked={checked} aria-label={label} {disabled} onclick={() => (checked = !checked)}></button>
