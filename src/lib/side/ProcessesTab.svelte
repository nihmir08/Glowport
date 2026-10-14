<script lang="ts">
  import { processKill } from '../backend';
  import { formatSize } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { act, processes, span } from '../manage.svelte';
  import type { Pane } from '../sessions.svelte';
  import type { ProcessInfo } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Die Prozesse des Servers, an dem der Bereich hängt, die mit der höchsten Last zuerst. */
  let { pane }: { pane: Pane } = $props();

  /** Mehr zeigt die Liste nicht. */
  const MOST = 200;

  const session = $derived(pane.phase === 'connected' ? pane.sessionId : null);
  const feed = $derived(processes.of(session));
  const view = $derived(feed?.value);

  $effect(() => {
    if (session !== null) return processes.watch(session);
  });

  let query = $state('');
  let order = $state<'cpu' | 'memory'>('cpu');
  const needle = $derived(query.trim().toLowerCase());
  const cpuOf = (p: ProcessInfo) => view?.cpu[p.pid] ?? 0;
  const shown = $derived(
    (view?.sample.processes ?? [])
      // Fäden des Kerns sind keine Programme und lassen sich nicht beenden.
      .filter((p) => !p.kernel && (!needle || p.name.toLowerCase().includes(needle) || p.user.toLowerCase().includes(needle) || p.command.toLowerCase().includes(needle) || String(p.pid) === needle))
      .sort((a, b) => (order === 'cpu' ? cpuOf(b) - cpuOf(a) || b.memory - a.memory : b.memory - a.memory || cpuOf(b) - cpuOf(a)))
      .slice(0, MOST),
  );
  /** Bei der ersten Messung gibt es noch keine Auslastung. */
  const measured = $derived(!!view && Object.keys(view.cpu).length > 0);

  let open = $state<number | null>(null);
  let busy = $state<number | null>(null);
  let confirm = $state<{ process: ProcessInfo; signal: 'term' | 'kill' } | null>(null);

  async function confirmed() {
    const pending = confirm;
    confirm = null;
    if (!pending || session === null) return;
    busy = pending.process.pid;
    const done = await act(pane.key, () => processKill(session, pending.process.pid, pending.signal), t('process.done', { name: pending.process.name }));
    busy = null;
    if (done) void processes.refresh(session);
  }
</script>

<div class="side-b mg">
  {#if session === null}
    <div class="fnote"><Icon name="list" size={22} /><p>{t('manage.offline')}</p></div>
  {:else if feed?.error}
    <div class="fnote"><Icon name="alert" size={22} /><p>{feed.error}</p></div>
  {:else if view === undefined}
    <div class="fnote"><Icon name="list" size={22} /><p>{t('manage.loading')}</p></div>
  {:else if view === null}
    <div class="fnote"><Icon name="alert" size={22} /><p>{t('process.unsupported')}</p></div>
  {:else}
    <div class="mg-tools">
      <label class="mg-search"><Icon name="search" size={14} /><input type="search" placeholder={t('process.search')} bind:value={query} spellcheck="false" /></label>
      <div class="mg-filter" role="group" aria-label={t('process.order')}>
        <button type="button" class:on={order === 'cpu'} onclick={() => (order = 'cpu')}>{t('process.order.cpu')}</button>
        <button type="button" class:on={order === 'memory'} onclick={() => (order = 'memory')}>{t('process.order.memory')}</button>
      </div>
    </div>
    {#if !shown.length}
      <div class="fnote"><Icon name="list" size={22} /><p>{t('process.none')}</p></div>
    {/if}
    {#each shown as p (p.pid)}
      <div class="mg-row" class:open={open === p.pid}>
        <button type="button" class="mg-head" aria-expanded={open === p.pid} onclick={() => (open = open === p.pid ? null : p.pid)}>
          <span class="mg-main">
            <b>{p.name}</b>
            <span class="mg-sub">{p.user} · {p.pid}</span>
          </span>
          <span class="mg-num"><b class:warn={cpuOf(p) >= 90}>{measured ? `${Math.round(cpuOf(p))} %` : '…'}</b><span>{formatSize(p.memory)}</span></span>
        </button>
        {#if open === p.pid}
          <div class="mg-more">
            <dl class="mg-facts">
              <dt>{t('process.command')}</dt>
              <dd class="mono selectable">{p.command}</dd>
              <dt>{t('process.elapsed')}</dt>
              <dd>{span(p.elapsed)}</dd>
              <dt>{t('process.parent')}</dt>
              <dd class="mono">{p.parent}</dd>
            </dl>
            {#if p.pid > 1}
              <div class="mg-acts">
                <Button size="sm" icon="stop" disabled={busy === p.pid} onclick={() => (confirm = { process: p, signal: 'term' })}>{t('process.term')}</Button>
                <Button size="sm" variant="danger" icon="x" disabled={busy === p.pid} onclick={() => (confirm = { process: p, signal: 'kill' })}>{t('process.kill')}</Button>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>

<Dialog open={!!confirm} title={confirm ? t(`process.confirm.${confirm.signal}.title`, { name: confirm.process.name, pid: confirm.process.pid }) : ''}>
  <p>{confirm ? t(`process.confirm.${confirm.signal}.text`) : ''}</p>
  <p class="mono selectable mg-cmd">{confirm?.process.command}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (confirm = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" onclick={confirmed}>{confirm?.signal === 'kill' ? t('process.kill') : t('process.term')}</Button>
  {/snippet}
</Dialog>
