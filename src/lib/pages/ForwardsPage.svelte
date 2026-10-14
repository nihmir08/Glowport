<script lang="ts">
  import { forwardDelete } from '../backend';
  import { applySnapshot, errorText, forwardById, hostById, sshHosts, vault } from '../data.svelte';
  import { forwardError, forwardRoute, stateOf, toggleForward } from '../forwards.svelte';
  import { inScope, scope } from '../sync.svelte';
  import VaultBadge from '../ui/VaultBadge.svelte';
  import VaultSwitch from '../ui/VaultSwitch.svelte';
  import { t, type Key } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { Forward } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Switch from '../ui/Switch.svelte';
  import ForwardEditor from './ForwardEditor.svelte';

  /** Port rules: saved forwards, each with a switch. They run even when no terminal is open. */
  let panel = $state<{ id: string | null } | null>(null);
  let query = $state('');
  let removing = $state<Forward | null>(null);
  /** Counts up with every save, so the editor then starts over with the saved values. */
  let version = $state(0);

  // If the rule shown disappears (deleted, vault reloaded), the editor closes.
  $effect(() => {
    if (panel?.id && !forwardById(panel.id)) panel = null;
  });

  const needle = $derived(query.trim().toLowerCase());
  // What is in the chosen vault is shown; the search finds everything.
  const shown = $derived(vault.forwards.filter((rule) => (needle ? [rule.name, hostById(rule.host)?.name ?? '', forwardRoute(rule)].some((text) => text.toLowerCase().includes(needle)) : inScope(rule))));
  const empty = $derived(!vault.forwards.length);

  async function confirmDelete() {
    const rule = removing!;
    removing = null;
    panel = null;
    try {
      applySnapshot((await forwardDelete(rule.id)).data);
      toast(t('common.deleted'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<section class="pg isl" style={empty ? 'display:flex;flex-direction:column' : ''}>
  <div class="crumbs"></div>
  <div class="ph">
    <div>
      <h1>{t('page.fwd.title')}</h1>
      <div class="sub">{t('page.fwd.text')}</div>
    </div>
    <div class="acts">
      <label class="search">
        <Icon name="search" size={14} />
        <input type="text" placeholder={t('fwd.search')} aria-label={t('fwd.search')} bind:value={query} spellcheck="false" />
      </label>
      <Button variant="primary" icon="plus" disabled={!sshHosts().length} onclick={() => (panel = { id: null })}>{t('fwd.new')}</Button>
    </div>
  </div>

  <VaultSwitch />

  {#if empty}
    <div class="empty">
      <span class="ei"><Icon name="forward" size={28} /></span>
      <h2>{t('fwd.empty.title')}</h2>
      <p>{sshHosts().length ? t('fwd.empty.text') : t('fwd.empty.nohosts')}</p>
      {#if sshHosts().length}<Button variant="primary" icon="plus" onclick={() => (panel = { id: null })}>{t('fwd.new')}</Button>{/if}
    </div>
  {:else if !shown.length && needle}
    <div class="empty"><p>{t('fwd.noresults', { q: query.trim() })}</p></div>
  {:else}
    <div class="sec">{t('fwd.sec.rules')}</div>
    <div class="rows">
      {#each shown as rule (rule.id)}
        {@const live = stateOf(rule.id)}
        <div class="row pick-row" class:sel={panel?.id === rule.id} role="button" tabindex="0" onclick={() => (panel = { id: rule.id })} onkeydown={(e) => e.key === 'Enter' && e.target === e.currentTarget && (panel = { id: rule.id })}>
          <span class="ri fwd-i {live?.phase ?? ''}"><Icon name={rule.kind === 'dynamic' ? 'globe' : 'forward'} size={16} /></span>
          <div class="rt">
            <b>{rule.name}</b>
            <span class="mono">{forwardRoute(rule)}</span>
          </div>
          {#if live?.phase === 'running'}
            <i class="chip ok">{t('fwd.running', { n: live.open })}</i>
          {:else if live?.phase === 'failed'}
            <i class="chip err" title={forwardError(live)}>{forwardError(live)}</i>
          {:else if live}
            <i class="chip">{t(`fwd.phase.${live.phase}` as Key)}</i>
          {/if}
          {#if scope.vault === 'all' || needle}<VaultBadge entry={rule} />{/if}
          <i class="chip">{t(`fwd.kind.${rule.kind}` as Key)}</i>
          <!-- The switch does not belong to the row: a click on it does not open the editor. -->
          <span role="presentation" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
            <Switch label={t('fwd.switch')} bind:checked={() => !!live, (on) => void toggleForward(rule.id, on)} />
          </span>
        </div>
      {/each}
    </div>
    <p class="fld-h" style="margin-top:12px;max-width:80ch">{t('fwd.page.hint')}</p>
  {/if}
</section>

{#if panel}
  {#key `${panel.id}:${version}`}
    <ForwardEditor rule={forwardById(panel.id) ?? null} onclose={() => (panel = null)} onsaved={(id) => ((version += 1), (panel = { id }))} ondelete={(rule) => (removing = rule)} />
  {/key}
{/if}

<Dialog open={!!removing} title={t('fwd.del.title')}>
  <p>{t('fwd.del.text', { name: removing?.name ?? '' })}</p>
  {#if removing && stateOf(removing.id)}<div class="warnbox"><Icon name="alert" size={16} /><span>{t('fwd.del.running')}</span></div>{/if}
  {#snippet actions()}
    <Button variant="primary" onclick={() => (removing = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon="trash" onclick={confirmDelete}>{t('common.delete')}</Button>
  {/snippet}
</Dialog>
