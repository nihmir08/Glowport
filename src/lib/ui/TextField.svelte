<script lang="ts">
  let {
    value = $bindable(''),
    label,
    placeholder,
    hint,
    mono = false,
    password = false,
    autofocus = false,
  }: { value?: string; label: string; placeholder?: string; hint?: string; mono?: boolean; password?: boolean; autofocus?: boolean } = $props();

  let input = $state<HTMLInputElement>();
  $effect(() => {
    if (autofocus) input?.focus();
  });
</script>

<label class="fld">
  <span class="fld-l">{label}</span>
  <input
    bind:this={input}
    class:mono
    type={password ? 'password' : 'text'}
    {placeholder}
    {value}
    spellcheck="false"
    autocomplete="off"
    oninput={(e) => (value = e.currentTarget.value)}
  />
  {#if hint}<span class="fld-h">{hint}</span>{/if}
</label>
