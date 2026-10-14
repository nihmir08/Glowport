<script lang="ts">
  import { onMount } from 'svelte';
  import { fsCompare, syncStart } from '../backend';
  import { errorText } from '../data.svelte';
  import { fileUi, formatSize, formatWhen, iconFor, placeName, transfers } from '../files.svelte';
  import type { IconName } from '../icons';
  import { t } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { DiffEntry, DiffState } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';

  /** Ordner abgleichen: zeigt, was sich zwischen links und rechts unterscheidet, und überträgt nur das. Gelöscht wird nichts. */
  const { left, right } = fileUi.compare!;
  const leftPath = left.path!;
  const rightPath = right.path!;

  type Direction = 'right' | 'left' | 'both';
  let diff = $state<DiffEntry[] | null>(null);
  let direction = $state<Direction>('right');
  let showSame = $state(false);
  /** Was der Nutzer von Hand an- oder abgewählt hat; für alles andere gilt die Vorgabe. */
  let chosen = $state<Record<string, boolean>>({});
  let busy = $state(false);

  onMount(async () => {
    try {
      diff = await fsCompare(left.place!, leftPath, right.place!, rightPath);
    } catch (e) {
      toast(errorText(e), 'err');
      close();
    }
  });

  const close = () => (fileUi.compare = null);

  /** Wohin eine Zeile bei der gewählten Richtung übertragen würde; null = gar nicht. */
  function flow(entry: DiffEntry): 'right' | 'left' | null {
    const toRight = entry.state === 'left' || entry.state === 'newerLeft';
    if (entry.state === 'same') return null;
    if (direction === 'both') return toRight ? 'right' : 'left';
    // In eine Richtung angleichen heißt: Die Quelle gewinnt, auch wenn das Ziel neuer ist. Was nur am Ziel liegt, bleibt dort.
    if (direction === 'right') return entry.left ? 'right' : null;
    return entry.right ? 'left' : null;
  }

  /** Das Ziel ist neuer als die Quelle: Übertragen hieße, Neueres mit Älterem zu überschreiben. Solche Zeilen sind nicht vorgewählt. */
  const risky = (entry: DiffEntry) => (direction === 'right' && entry.state === 'newerRight') || (direction === 'left' && entry.state === 'newerLeft');
  const isOn = (entry: DiffEntry) => !!flow(entry) && (chosen[entry.rel] ?? !risky(entry));
  // Mit der Richtung ändert sich, was eine Zeile bedeutet; die Handauswahl gilt dann nicht mehr.
  $effect(() => {
    void direction;
    chosen = {};
  });

  const shown = $derived((diff ?? []).filter((e) => showSame || e.state !== 'same'));
  const differing = $derived((diff ?? []).filter((e) => e.state !== 'same').length);
  const planned = $derived((diff ?? []).filter(isOn));
  const bytes = $derived(planned.reduce((n, e) => n + ((flow(e) === 'right' ? e.left : e.right)?.size ?? 0), 0));

  const MARK: Record<DiffState, { icon: IconName; text: 'compare.state.left' | 'compare.state.right' | 'compare.state.newerLeft' | 'compare.state.newerRight' | 'compare.state.same' }> = {
    left: { icon: 'arrowR', text: 'compare.state.left' },
    right: { icon: 'arrowL', text: 'compare.state.right' },
    newerLeft: { icon: 'arrowR', text: 'compare.state.newerLeft' },
    newerRight: { icon: 'arrowL', text: 'compare.state.newerRight' },
    same: { icon: 'equal', text: 'compare.state.same' },
  };

  const toggle = (entry: DiffEntry) => (chosen[entry.rel] = !isOn(entry));

  async function apply() {
    busy = true;
    try {
      await syncStart(left.place!, leftPath, right.place!, rightPath, planned.map((e) => ({ rel: e.rel, toRight: flow(e) === 'right' })));
      transfers.dock = true;
      close();
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
    }
  }
</script>

{#snippet side(info: DiffEntry['left'])}
  {#if info}<span>{formatSize(info.size)}</span><span>{formatWhen(info.modified, true)}</span>{:else}<span class="none">{t('compare.missing')}</span>{/if}
{/snippet}

<Dialog bind:open={() => true, (v) => void (!v && close())} wide title={t('compare.title')}>
  <div class="cmp-h">
    <div><b>{placeName(left.place)}</b><span class="mono">{leftPath}</span></div>
    <Icon name="forward" size={18} />
    <div><b>{placeName(right.place)}</b><span class="mono">{rightPath}</span></div>
  </div>
  <div class="cmp-o">
    <Segmented
      label={t('compare.direction')}
      bind:value={direction}
      options={[
        { value: 'right', label: t('compare.dir.right'), icon: 'arrowR' },
        { value: 'left', label: t('compare.dir.left'), icon: 'arrowL' },
        { value: 'both', label: t('compare.dir.both'), icon: 'forward' },
      ]}
    />
    <span class="grow"></span>
    <label class="check"><input type="checkbox" bind:checked={showSame} />{t('compare.showSame')}</label>
  </div>

  <div class="cmp-l">
    {#if diff === null}
      <p class="fnote">{t('compare.busy')}</p>
    {:else if !shown.length}
      <p class="fnote">{t('compare.equal')}</p>
    {/if}
    {#each shown as entry (entry.rel)}
      {@const to = flow(entry)}
      {@const on = isOn(entry)}
      <label class="cmp-r {entry.state}" class:skip={!on} class:risky={risky(entry)}>
        <input type="checkbox" checked={on} disabled={!to} aria-label={entry.rel} onchange={() => toggle(entry)} />
        <span class="fi {entry.kind}"><Icon name={iconFor({ name: entry.rel, kind: entry.kind })} size={15} /></span>
        <span class="cn"><b>{entry.rel}</b><i>{t(MARK[entry.state].text)}{#if risky(entry)}&nbsp;· {t('compare.risky')}{/if}</i></span>
        <span class="cs">{@render side(entry.left)}</span>
        <span class="cm {to ?? ''}" title={t(MARK[entry.state].text)}><Icon name={to === 'right' ? 'arrowR' : to === 'left' ? 'arrowL' : entry.state === 'same' ? 'equal' : 'min'} size={15} /></span>
        <span class="cs">{@render side(entry.right)}</span>
      </label>
    {/each}
  </div>

  {#snippet actions()}
    <span class="rm">{#if diff}{t('compare.summary', { n: differing })} · {t('compare.nodelete')}{/if}</span>
    <span class="grow"></span>
    <Button onclick={close}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="transfer" disabled={busy || !planned.length} onclick={apply}>{t('compare.apply', { n: planned.length, size: formatSize(bytes) })}</Button>
  {/snippet}
</Dialog>
