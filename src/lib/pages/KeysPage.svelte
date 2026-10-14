<script lang="ts">
  import { onMount } from 'svelte';
  import { agentList, identityDelete, keyDelete } from '../backend';
  import { applySnapshot, errorText, hostsUsingIdentity, hostsUsingKey, identityById, keyById, vault } from '../data.svelte';
  import { inScope, scope } from '../sync.svelte';
  import VaultBadge from '../ui/VaultBadge.svelte';
  import VaultSwitch from '../ui/VaultSwitch.svelte';
  import { t } from '../i18n.svelte';
  import { IDENTITY_COLOR, KEY_COLOR, keyLabel } from '../keys';
  import { toast } from '../state.svelte';
  import type { Agent, Changed, Identity, SshKey } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import IdentityEditor from './IdentityEditor.svelte';
  import KeyDeploy from './KeyDeploy.svelte';
  import KeyNew from './KeyNew.svelte';
  import KeyPanel from './KeyPanel.svelte';

  type Panel = { kind: 'key'; id: string } | { kind: 'new'; mode: 'generate' | 'import' } | { kind: 'identity'; id: string | null } | null;

  let panel = $state<Panel>(null);
  let query = $state('');
  let agents = $state<Agent[]>([]);
  let deploying = $state<SshKey | null>(null);
  let deleteKey = $state<SshKey | null>(null);
  let deleteIdentity = $state<Identity | null>(null);

  onMount(() => {
    agentList()
      .then((found) => (agents = found))
      .catch((e) => console.error('Agents not readable', e));
  });

  // If the entry shown disappears (deleted, vault reloaded), the panel closes.
  $effect(() => {
    if (panel?.kind === 'key' && !keyById(panel.id)) panel = null;
    if (panel?.kind === 'identity' && panel.id && !identityById(panel.id)) panel = null;
  });

  const needle = $derived(query.trim().toLowerCase());
  const matches = (...texts: string[]) => !needle || texts.some((text) => text.toLowerCase().includes(needle));
  // What is in the chosen vault is shown; the search finds everything.
  const keys = $derived(vault.keys.filter((k) => (needle || inScope(k)) && matches(k.name, k.fingerprint, keyLabel(k))));
  const identities = $derived(vault.identities.filter((i) => (needle || inScope(i)) && matches(i.name, i.user, keyById(i.key)?.name ?? '')));
  const empty = $derived(!vault.keys.length && !vault.identities.length);
  const usage = (n: number) => (n ? t('hosts.count', { n }) : t('keys.unused'));

  async function remove(work: () => Promise<Changed>) {
    panel = null;
    try {
      applySnapshot((await work()).data);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }

  function confirmDeleteKey() {
    const key = deleteKey!;
    deleteKey = null;
    void remove(() => keyDelete(key.id));
  }

  function confirmDeleteIdentity() {
    const identity = deleteIdentity!;
    deleteIdentity = null;
    void remove(() => identityDelete(identity.id));
  }
</script>

<section class="pg isl" style={empty ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs"></div>
  <div class="ph">
    <div>
      <h1>{t('page.keys.title')}</h1>
      <div class="sub">{t('page.keys.text')}</div>
    </div>
    <div class="acts">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('keys.search')} aria-label={t('keys.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button icon="download" onclick={() => (panel = { kind: 'new', mode: 'import' })}>{t('keys.import')}</Button>
      <Button icon="user" onclick={() => (panel = { kind: 'identity', id: null })}>{t('keys.newIdentity')}</Button>
      <Button variant="primary" icon="plus" onclick={() => (panel = { kind: 'new', mode: 'generate' })}>{t('keys.generate')}</Button>
    </div>
  </div>

  <VaultSwitch />

  {#if empty}
    <div class="empty">
      <span class="ei"><Icon name="key" size={28} /></span>
      <h2>{t('keys.empty.title')}</h2>
      <p>{t('keys.empty.text')}</p>
      <div style="display:flex;gap:8px">
        <Button icon="download" onclick={() => (panel = { kind: 'new', mode: 'import' })}>{t('keys.import')}</Button>
        <Button variant="primary" icon="plus" onclick={() => (panel = { kind: 'new', mode: 'generate' })}>{t('keys.generate')}</Button>
      </div>
    </div>
  {:else if needle && !keys.length && !identities.length}
    <div class="empty"><p>{t('keys.noresults', { q: query.trim() })}</p></div>
  {:else}
    <div class="sec">{t('keys.sec.keys')}</div>
    {#if keys.length}
      <div class="grid">
        {#each keys as k (k.id)}
          <button class="host" class:sel={panel?.kind === 'key' && panel.id === k.id} style="--c:{KEY_COLOR[k.kind]}" onclick={() => (panel = { kind: 'key', id: k.id })}>
            <span class="os"><Icon name="key" size={18} /></span>
            <span class="h-name">{k.name}</span>
            <span class="h-addr">{k.fingerprint}</span>
            <span class="h-meta">
              <i class="chip">{keyLabel(k)}</i>
              <i class="chip">{usage(hostsUsingKey(k.id).length)}</i>
              {#if scope.vault === 'all' || needle}<VaultBadge entry={k} />{/if}
            </span>
          </button>
        {/each}
      </div>
    {:else if !needle}
      <p class="fld-h">{t('keys.none.keys')}</p>
    {/if}

    <div class="sec">{t('keys.sec.identities')}</div>
    {#if identities.length}
      <div class="grid">
        {#each identities as i (i.id)}
          {@const key = keyById(i.key)}
          <button class="host" class:sel={panel?.kind === 'identity' && panel.id === i.id} style="--c:{IDENTITY_COLOR}" onclick={() => (panel = { kind: 'identity', id: i.id })}>
            <span class="os"><Icon name="user" size={18} /></span>
            <span class="h-name">{i.name}</span>
            <span class="h-addr">{i.user}</span>
            <span class="h-meta">
              {#if key}<i class="chip"><Icon name="key" size={10} />{key.name}</i>{/if}
              {#if i.hasPassword}<i class="chip"><Icon name="lock" size={10} />{t('detail.password')}</i>{/if}
              <i class="chip">{usage(hostsUsingIdentity(i.id).length)}</i>
              {#if scope.vault === 'all' || needle}<VaultBadge entry={i} />{/if}
            </span>
          </button>
        {/each}
      </div>
    {:else if !needle}
      <p class="fld-h" style="max-width:70ch">{t('keys.none.identities')}</p>
    {/if}

    {#if agents.length && !needle}
      <div class="sec">{t('keys.sec.agent')}</div>
      <div class="rows">
        {#each agents as a (a.kind)}
          <div class="row">
            <span class="ri"><Icon name="agent" size={16} /></span>
            <div class="rt">
              <b>{a.kind === 'openssh' ? t('agent.openssh') : t('agent.pageant')}</b>
              <span>
                {#if a.keys.length}
                  {a.keys.map((k) => `${k.comment} (${k.kind})`).join(' · ')}
                {:else}
                  {a.kind === 'openssh' ? t('agent.openssh.sub') : t('agent.pageant.sub')}
                {/if}
              </span>
            </div>
            <span class="rm">{a.running ? t('agent.running', { n: a.keys.length }) : t('agent.stopped')}</span>
          </div>
        {/each}
      </div>
      <p class="fld-h" style="margin-top:8px">{t('agent.hint')}</p>
    {/if}
  {/if}
</section>

{#if panel?.kind === 'key'}
  {@const key = keyById(panel.id)}
  {#if key}
    {#key key.id}
      <KeyPanel {key} onclose={() => (panel = null)} ondeploy={() => (deploying = key)} ondelete={() => (deleteKey = key)} />
    {/key}
  {/if}
{:else if panel?.kind === 'new'}
  <KeyNew mode={panel.mode} onclose={() => (panel = null)} onsaved={(id) => (panel = { kind: 'key', id })} />
{:else if panel?.kind === 'identity'}
  {#key panel.id}
    <IdentityEditor identity={identityById(panel.id) ?? null} onclose={() => (panel = null)} onsaved={() => (panel = null)} ondelete={(identity) => (deleteIdentity = identity)} />
  {/key}
{/if}

{#if deploying}
  <KeyDeploy key={deploying} onclose={() => (deploying = null)} />
{/if}

<Dialog open={!!deleteKey} title={t('keys.del.title')}>
  {@const used = deleteKey ? hostsUsingKey(deleteKey.id).length : 0}
  <p>{t('keys.del.text', { name: deleteKey?.name ?? '' })}</p>
  {#if used}<div class="warnbox"><Icon name="alert" size={16} /><span>{t('keys.del.used', { n: used })}</span></div>{/if}
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleteKey = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDeleteKey}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>

<Dialog open={!!deleteIdentity} title={t('ident.del.title')}>
  {@const used = deleteIdentity ? hostsUsingIdentity(deleteIdentity.id).length : 0}
  <p>{t('ident.del.text', { name: deleteIdentity?.name ?? '' })}</p>
  {#if used}<div class="warnbox"><Icon name="alert" size={16} /><span>{t('ident.del.used', { n: used })}</span></div>{/if}
  {#snippet actions()}
    <Button variant="primary" onclick={() => (deleteIdentity = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDeleteIdentity}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>
