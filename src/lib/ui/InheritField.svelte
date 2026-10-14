<script lang="ts">
  import { t } from '../i18n.svelte';
  import type { Action } from '../quick.svelte';
  import ActionSelect from './ActionSelect.svelte';
  import Icon from './Icon.svelte';

  /**
   * Field for an inheritable value. Empty means: the value comes from further up.
   * `inherited.source` is the name of the group that sets it; null means the program's fixed default.
   * `inherited.from` replaces the origin note if the value does not come from a group (e.g. from an identity).
   * With `options` it becomes a select field whose first entry is “inherited”. `actions` appends entries
   * that create something new instead of selecting something.
   */
  let {
    value = $bindable(''),
    label,
    inherited,
    options,
    actions,
    mono = false,
  }: {
    value?: string;
    label: string;
    inherited?: { value: string; source: string | null; from?: string };
    options?: { value: string; label: string }[];
    actions?: Action[];
    mono?: boolean;
  } = $props();

  const overridden = $derived(value !== '' && !!inherited);
  const from = $derived(inherited?.from ?? (inherited?.source ? t('hosts.from', { src: inherited.source }) : ''));
  const firstOption = $derived(!inherited ? '–' : from ? `${inherited.value} · ${from}` : `${inherited.value} · ${t('detail.default')}`);
</script>

<label class="fld">
  <span class="fld-l">
    {label}
    {#if inherited && !overridden}<span class="inh">{from || t('detail.default')}</span>{/if}
  </span>
  <span class="inh-row">
    {#if options}
      <ActionSelect bind:value over={overridden} options={[{ value: '', label: firstOption }, ...options]} {actions} />
    {:else}
      <input class:mono class:over={overridden} type="text" placeholder={inherited?.value ?? ''} {value} spellcheck="false" autocomplete="off" oninput={(e) => (value = e.currentTarget.value)} />
    {/if}
    {#if overridden}
      <button type="button" class="mini" title={t('edit.inherit.reset')} aria-label={t('edit.inherit.reset')} onclick={() => (value = '')}>
        <Icon name="undo" size={14} />
      </button>
    {/if}
  </span>
  {#if overridden && inherited}
    <span class="fld-h">
      {inherited.source ? t('edit.inherit.overrides', { value: inherited.value, src: inherited.source }) : t('edit.inherit.overrides.default', { value: inherited.value })}
    </span>
  {/if}
</label>
