<script lang="ts">
  import { snippetCancel, snippetRun } from '../backend';
  import { addressOf, descendants, errorText, pathLabel, sshHosts, vault } from '../data.svelte';
  import { has, t, tn, type Key } from '../i18n.svelte';
  import { fill, variablesOf } from '../snippets';
  import { lastValues, remember } from '../snippets.svelte';
  import { settings, toast } from '../state.svelte';
  import type { RunResult, Snippet } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Führt ein Snippet auf vielen Hosts aus, ohne Terminal, und zeigt je Host, was herauskam. */
  let { snippet, onclose }: { snippet: Snippet; onclose: () => void } = $props();

  // Der Dialog wird je Snippet neu erzeugt ({#key}); die Startwerte werden bewusst nur einmal gelesen.
  const first = (() => snippet)();
  const variables = variablesOf(first.command);
  /** Nummer dieses Laufs, unter der er sich abbrechen lässt. */
  const run = Date.now();

  let values = $state<Record<string, string>>({ ...lastValues(first.id) });
  let query = $state('');
  let picked = $state<string[]>([]);
  let results = $state<Record<string, RunResult>>({});
  let phase = $state<'pick' | 'running' | 'done'>('pick');
  /** Der Host, dessen Ausgabe unten zu lesen ist. */
  let shown = $state<string | null>(null);

  const command = $derived(fill(snippet.command, values));
  const needle = $derived(query.trim().toLowerCase());
  const hosts = $derived(
    sshHosts()
      .filter((h) => !needle || [h.name, h.address, pathLabel(h.group)].some((text) => text.toLowerCase().includes(needle)))
      .sort((a, b) => pathLabel(a.group).localeCompare(pathLabel(b.group)) || a.name.localeCompare(b.name)),
  );
  /** Gruppen der obersten Ebenen, die Hosts enthalten: Ein Klick wählt alle ihre Hosts, auch die in Untergruppen. */
  const groups = $derived(
    vault.groups
      .map((g) => ({ group: g, ids: sshHosts().filter((h) => h.group && descendants(g.id).includes(h.group)).map((h) => h.id) }))
      .filter((entry) => entry.ids.length > 1)
      .sort((a, b) => pathLabel(a.group.id).localeCompare(pathLabel(b.group.id))),
  );
  /** Die gewählten Hosts, unabhängig davon, was gerade im Suchfeld steht. */
  const ran = $derived(sshHosts().filter((h) => picked.includes(h.id)).sort((a, b) => pathLabel(a.group).localeCompare(pathLabel(b.group)) || a.name.localeCompare(b.name)));
  const finished = $derived(Object.values(results).filter((r) => r.state !== 'running'));
  const ok = $derived(finished.filter((r) => r.state === 'done' && r.exit === 0).length);
  const output = $derived(shown ? results[shown] : undefined);
  const missing = $derived(variables.filter((v) => !values[v.name]?.trim() && !v.fallback));

  function toggle(id: string) {
    picked = picked.includes(id) ? picked.filter((p) => p !== id) : [...picked, id];
  }

  /** Wählt alle Hosts einer Gruppe; sind schon alle gewählt, nimmt der Klick sie wieder heraus. */
  function toggleGroup(ids: string[]) {
    picked = ids.every((id) => picked.includes(id)) ? picked.filter((id) => !ids.includes(id)) : [...new Set([...picked, ...ids])];
  }

  function failure(result: RunResult) {
    const key = `run.fail.${result.error}`;
    return has(key) ? t(key as Key) : (result.error ?? t('run.failed'));
  }

  const seconds = (ms: number) => `${(ms / 1000).toFixed(1).replace('.', settings.lang === 'de' ? ',' : '.')} s`;

  async function start() {
    phase = 'running';
    results = {};
    shown = null;
    remember(snippet.id, values);
    try {
      await snippetRun(run, command, picked, (result) => {
        results[result.host] = result;
        // Die erste fertige Ausgabe wird gleich gezeigt; danach entscheidet der Klick.
        if (result.state !== 'running' && shown === null) shown = result.host;
      });
    } catch (e) {
      toast(errorText(e), 'err');
    }
    phase = 'done';
  }

  function close() {
    if (phase === 'running') void snippetCancel(run);
    onclose();
  }
</script>

<Dialog bind:open={() => true, (open) => !open && close()} title={t('run.title', { name: snippet.name })} wide>
  {#if variables.length && phase === 'pick'}
    <div class="run-vars">
      {#each variables as v (v.name)}
        <label class="fld">
          <span class="fld-l">{v.name}</span>
          <input class="mono" type="text" placeholder={v.fallback} value={values[v.name] ?? ''} disabled={phase !== 'pick'} spellcheck="false" autocomplete="off" oninput={(e) => (values[v.name] = e.currentTarget.value)} />
        </label>
      {/each}
    </div>
  {/if}
  <pre class="run-cmd selectable">{command}</pre>

  {#if phase === 'pick'}
    <div class="pickbar">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('deploy.search')} aria-label={t('deploy.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button size="sm" onclick={() => (picked = [...new Set([...picked, ...hosts.map((h) => h.id)])])}>{t('deploy.all')}</Button>
      <Button size="sm" onclick={() => (picked = [])}>{t('deploy.none')}</Button>
    </div>
  {/if}
  {#if groups.length && phase === 'pick'}
    <div class="tags">
      {#each groups as entry (entry.group.id)}
        <button type="button" class="chip pickchip" class:a={entry.ids.every((id) => picked.includes(id))} onclick={() => toggleGroup(entry.ids)}>{pathLabel(entry.group.id)} · {entry.ids.length}</button>
      {/each}
    </div>
  {/if}
  <div class="picklist" class:short={phase !== 'pick'}>
    {#each phase === 'pick' ? hosts : ran as h (h.id)}
      {@const result = results[h.id]}
      {#if phase === 'pick' || picked.includes(h.id)}
        <label class="pick" class:sel={shown === h.id}>
          {#if phase === 'pick'}
            <input type="checkbox" checked={picked.includes(h.id)} onchange={() => toggle(h.id)} />
          {:else}
            <input type="radio" name="run-output" checked={shown === h.id} disabled={!result || result.state === 'running'} onchange={() => (shown = h.id)} />
          {/if}
          <b>{h.name}</b>
          <span class="mono">{addressOf(h)}{#if h.group}&nbsp;· {pathLabel(h.group)}{/if}</span>
          {#if result?.state === 'done' && result.exit === 0}
            <i class="chip ok"><Icon name="check" size={10} />{seconds(result.ms)}</i>
          {:else if result?.state === 'done'}
            <i class="chip err">{t('run.exit', { n: result.exit ?? '?' })}</i>
          {:else if result?.state === 'failed'}
            <i class="chip err">{failure(result)}</i>
          {:else if result}
            <i class="chip">{t('run.running')}</i>
          {:else if phase !== 'pick'}
            <i class="chip">{t('deploy.waiting')}</i>
          {/if}
        </label>
      {/if}
    {/each}
  </div>

  {#if phase !== 'pick'}
    <pre class="run-out selectable">{#if !output}{t('run.output.none')}{:else if output.state === 'failed'}{failure(output)}{:else}{output.output || t('run.output.empty')}{#if output.truncated}{'\n'}{t('run.output.truncated')}{/if}{/if}</pre>
  {/if}

  {#if phase === 'pick'}
    <span class="fld-h">{missing.length ? t('run.missing', { names: missing.map((v) => v.name).join(', ') }) : t('run.hint')}</span>
  {:else if phase === 'running'}
    <span class="fld-h">{t('run.progress', { done: finished.length, n: picked.length })}</span>
  {:else}
    <span class="fld-h">{t('run.done', { ok, failed: finished.length - ok })}</span>
  {/if}
  {#snippet actions()}
    <Button onclick={close}>{phase === 'done' ? t('common.close') : t('common.cancel')}</Button>
    {#if phase === 'done'}
      <Button icon="refresh" onclick={() => (phase = 'pick')}>{t('run.again')}</Button>
    {:else}
      <Button variant="primary" icon="cast" disabled={!picked.length || phase === 'running' || !!missing.length} onclick={start}>{tn('run.start', picked.length)}</Button>
    {/if}
  {/snippet}
</Dialog>
