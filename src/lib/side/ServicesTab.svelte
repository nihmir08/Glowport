<script lang="ts">
  import { serviceAction, serviceLine, serviceStatus } from '../backend';
  import { errorText } from '../data.svelte';
  import { t } from '../i18n.svelte';
  import { abilitiesOf, act, services } from '../manage.svelte';
  import { openTabWith, type Pane } from '../sessions.svelte';
  import { toast } from '../state.svelte';
  import type { ServiceUnit } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Die systemd-Dienste des Servers, an dem der Bereich hängt. */
  let { pane }: { pane: Pane } = $props();

  type ServiceAction = 'start' | 'stop' | 'restart' | 'enable' | 'disable';

  const session = $derived(pane.phase === 'connected' ? pane.sessionId : null);
  const feed = $derived(services.of(session));
  const listed = $derived(feed?.value);
  const all = $derived(listed?.state === 'ok' ? listed.items : []);

  $effect(() => {
    if (session !== null) return services.watch(session);
  });

  let query = $state('');
  let filter = $state<'all' | 'running' | 'failed'>('all');
  const needle = $derived(query.trim().toLowerCase());
  const failed = $derived(all.filter((s) => s.active === 'failed').length);
  const shown = $derived(
    all.filter((s) => (filter === 'all' || (filter === 'running' ? s.active === 'active' && s.sub === 'running' : s.active === 'failed')) && (!needle || s.unit.toLowerCase().includes(needle) || s.description.toLowerCase().includes(needle))),
  );

  let open = $state<string | null>(null);
  /** Zustand und letzte Meldungen des aufgeklappten Dienstes, wie systemd sie ausgibt. */
  let status = $state('');
  let busy = $state<string | null>(null);
  let confirm = $state<{ service: ServiceUnit; action: 'stop' | 'restart' | 'disable' } | null>(null);

  const short = (unit: string) => unit.replace(/\.service$/, '');
  const tone = (s: ServiceUnit) => (s.active === 'failed' ? 'err' : s.active === 'activating' || s.active === 'deactivating' ? 'warn' : s.active === 'active' ? 'ok' : 'idle');
  const stateText = (s: ServiceUnit) => (s.active === 'active' && s.sub !== 'running' ? t('service.state.done') : t(`service.state.${s.active}`));
  const up = (s: ServiceUnit) => s.active === 'active' || s.active === 'activating';

  async function loadStatus(unit: string) {
    if (session === null) return;
    try {
      const text = await serviceStatus(session, unit);
      if (open === unit) status = text;
    } catch (e) {
      if (open === unit) status = errorText(e);
    }
  }

  function toggle(unit: string) {
    open = open === unit ? null : unit;
    status = '';
    if (open) void loadStatus(unit);
  }

  async function run(service: ServiceUnit, action: ServiceAction) {
    if (session === null || busy) return;
    busy = service.unit;
    const done = await act(pane.key, () => serviceAction(session, service.unit, action), t(`service.done.${action}`, { name: short(service.unit) }));
    busy = null;
    if (!done) return;
    void services.refresh(session);
    if (open === service.unit) void loadStatus(service.unit);
  }

  async function confirmed() {
    const pending = confirm;
    confirm = null;
    if (pending) await run(pending.service, pending.action);
  }

  /** Das Journal läuft in einem neuen Tab am selben Server mit. */
  async function follow(service: ServiceUnit) {
    try {
      openTabWith(pane.target, await serviceLine(service.unit, !abilitiesOf(session)?.root));
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<div class="side-b mg">
  {#if session === null}
    <div class="fnote"><Icon name="gear" size={22} /><p>{t('manage.offline')}</p></div>
  {:else if feed?.error}
    <div class="fnote"><Icon name="alert" size={22} /><p>{feed.error}</p></div>
  {:else if !listed}
    <div class="fnote"><Icon name="gear" size={22} /><p>{t('manage.loading')}</p></div>
  {:else if listed.state !== 'ok'}
    <div class="fnote"><Icon name="alert" size={22} /><p>{t('service.failed')}</p>{#if listed.state === 'failed'}<p class="mono selectable">{listed.message}</p>{/if}</div>
  {:else}
    <div class="mg-tools">
      <label class="mg-search"><Icon name="search" size={14} /><input type="search" placeholder={t('service.search')} bind:value={query} spellcheck="false" /></label>
      <div class="mg-filter" role="group" aria-label={t('service.filter')}>
        <button type="button" class:on={filter === 'all'} onclick={() => (filter = 'all')}>{t('service.filter.all')}</button>
        <button type="button" class:on={filter === 'running'} onclick={() => (filter = 'running')}>{t('service.filter.running')}</button>
        <button type="button" class:on={filter === 'failed'} class:alarm={failed > 0} onclick={() => (filter = 'failed')}>{t('service.filter.failed', { n: failed })}</button>
      </div>
    </div>
    {#if !shown.length}
      <div class="fnote"><Icon name="gear" size={22} /><p>{t('service.none')}</p></div>
    {/if}
    {#each shown as s (s.unit)}
      <div class="mg-row" class:open={open === s.unit}>
        <button type="button" class="mg-head" aria-expanded={open === s.unit} onclick={() => toggle(s.unit)}>
          <span class="mg-dot {tone(s)}"></span>
          <span class="mg-main">
            <b>{short(s.unit)}</b>
            <span class="mg-sub">{s.description || s.unit}</span>
          </span>
          <span class="mg-num"><b class={tone(s)}>{stateText(s)}</b>{#if s.enabled === 'enabled'}<span>{t('service.boot')}</span>{:else if s.enabled === 'masked'}<span>{t('service.masked')}</span>{/if}</span>
        </button>
        {#if open === s.unit}
          <div class="mg-more">
            <pre class="mg-log selectable">{status || t('manage.loading')}</pre>
            <div class="mg-acts">
              {#if s.enabled !== 'masked'}
                {#if up(s)}
                  <Button size="sm" icon="stop" disabled={busy === s.unit} onclick={() => (confirm = { service: s, action: 'stop' })}>{t('manage.stop')}</Button>
                  <Button size="sm" icon="refresh" disabled={busy === s.unit} onclick={() => (confirm = { service: s, action: 'restart' })}>{t('manage.restart')}</Button>
                {:else}
                  <Button size="sm" icon="play" disabled={busy === s.unit} onclick={() => run(s, 'start')}>{t('manage.start')}</Button>
                {/if}
                {#if s.enabled === 'enabled'}
                  <Button size="sm" disabled={busy === s.unit} onclick={() => (confirm = { service: s, action: 'disable' })}>{t('service.disable')}</Button>
                {:else if s.enabled === 'disabled'}
                  <Button size="sm" disabled={busy === s.unit} onclick={() => run(s, 'enable')}>{t('service.enable')}</Button>
                {/if}
              {/if}
              <Button size="sm" icon="log" onclick={() => follow(s)}>{t('service.follow')}</Button>
            </div>
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>

<Dialog open={!!confirm} title={confirm ? t(`service.confirm.${confirm.action}.title`, { name: short(confirm.service.unit) }) : ''}>
  <p>{confirm ? t(`service.confirm.${confirm.action}.text`) : ''}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (confirm = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={confirmed}>{confirm ? t(confirm.action === 'disable' ? 'service.disable' : confirm.action === 'stop' ? 'manage.stop' : 'manage.restart') : ''}</Button>
  {/snippet}
</Dialog>
