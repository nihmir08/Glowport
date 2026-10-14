<script lang="ts">
  import { t } from '../i18n.svelte';
  import type { Action } from '../quick.svelte';
  import ActionSelect from './ActionSelect.svelte';
  import Icon from './Icon.svelte';

  /**
   * Feld für einen vererbbaren Wert. Leer heißt: Der Wert kommt von weiter oben.
   * `inherited.source` ist der Name der Gruppe, die ihn festlegt; null bedeutet die feste Vorgabe des Programms.
   * `inherited.from` ersetzt die Herkunftsangabe, wenn der Wert nicht aus einer Gruppe stammt (etwa aus einer Identität).
   * Mit `options` wird daraus ein Auswahlfeld, dessen erster Eintrag „geerbt“ ist. `actions` hängt Einträge an,
   * die etwas Neues anlegen statt etwas auszuwählen.
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
