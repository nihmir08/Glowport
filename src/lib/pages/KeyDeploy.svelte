<script lang="ts">
  import { keyDeploy } from '../backend';
  import { addressOf, errorText, pathLabel, sshHosts, vault } from '../data.svelte';
  import { has, t, type Key } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { DeployResult, SshKey } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  let { key, onclose }: { key: SshKey; onclose: () => void } = $props();

  let query = $state('');
  let picked = $state<string[]>([]);
  let results = $state<Record<string, DeployResult>>({});
  let phase = $state<'pick' | 'running' | 'done'>('pick');
  let adopt = $state(true);

  const needle = $derived(query.trim().toLowerCase());
  const hosts = $derived(
    sshHosts()
      .filter((h) => !needle || [h.name, h.address, pathLabel(h.group)].some((text) => text.toLowerCase().includes(needle)))
      .sort((a, b) => pathLabel(a.group).localeCompare(pathLabel(b.group)) || a.name.localeCompare(b.name)),
  );
  const finished = $derived(Object.values(results));
  const count = (outcome: DeployResult['outcome']) => finished.filter((r) => r.outcome === outcome).length;

  function toggle(id: string) {
    picked = picked.includes(id) ? picked.filter((p) => p !== id) : [...picked, id];
  }

  function failure(result: DeployResult) {
    const key = `deploy.fail.${result.message}`;
    return has(key) ? t(key as Key) : (result.message ?? t('deploy.failed'));
  }

  async function run() {
    phase = 'running';
    results = {};
    try {
      await keyDeploy(key.id, picked, adopt, (result) => (results[result.host] = result));
    } catch (e) {
      toast(errorText(e), 'err');
    }
    phase = 'done';
  }
</script>

<Dialog bind:open={() => true, (open) => !open && onclose()} title={t('deploy.title', { name: key.name })} wide>
  <p>{t('deploy.text')}</p>
  <div class="pickbar">
    <label class="search">
      <Icon name="search" size={14} />
      <input type="text" placeholder={t('deploy.search')} aria-label={t('deploy.search')} bind:value={query} spellcheck="false" />
    </label>
    <Button size="sm" disabled={phase !== 'pick'} onclick={() => (picked = [...new Set([...picked, ...hosts.map((h) => h.id)])])}>{t('deploy.all')}</Button>
    <Button size="sm" disabled={phase !== 'pick'} onclick={() => (picked = [])}>{t('deploy.none')}</Button>
  </div>
  <div class="picklist">
    {#each hosts as h (h.id)}
      {@const result = results[h.id]}
      <label class="pick">
        <input type="checkbox" checked={picked.includes(h.id)} disabled={phase !== 'pick'} onchange={() => toggle(h.id)} />
        <b>{h.name}</b>
        <span class="mono">{addressOf(h)}{#if h.group}&nbsp;· {pathLabel(h.group)}{/if}</span>
        {#if result?.outcome === 'added'}
          <i class="chip ok"><Icon name="check" size={10} />{t('deploy.added')}</i>
        {:else if result?.outcome === 'present'}
          <i class="chip">{t('deploy.present')}</i>
        {:else if result}
          <i class="chip err">{failure(result)}</i>
        {:else if phase === 'running' && picked.includes(h.id)}
          <i class="chip">{t('deploy.waiting')}</i>
        {/if}
      </label>
    {/each}
  </div>
  <label class="check"><input type="checkbox" bind:checked={adopt} disabled={phase !== 'pick'} />{t('deploy.adopt')}</label>
  {#if phase === 'running'}
    <span class="fld-h">{t('deploy.running', { done: finished.length, n: picked.length })}</span>
  {:else if phase === 'done'}
    <span class="fld-h">{t('deploy.done', { added: count('added'), present: count('present'), failed: count('failed') })}</span>
  {/if}
  {#snippet actions()}
    <Button onclick={onclose}>{phase === 'done' ? t('common.close') : t('common.cancel')}</Button>
    {#if phase !== 'done'}
      <Button variant="primary" icon="send" disabled={!picked.length || phase === 'running'} onclick={run}>{t('deploy.start', { n: picked.length })}</Button>
    {/if}
  {/snippet}
</Dialog>
