<script lang="ts">
  import { dockerAction, dockerLine } from '../backend';
  import { errorText } from '../data.svelte';
  import { formatSize } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import { act, docker, span } from '../manage.svelte';
  import { openTabWith, type Pane } from '../sessions.svelte';
  import { toast } from '../state.svelte';
  import type { DockerContainer } from '../types';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';

  /** The containers of the server the pane is connected to. */
  let { pane }: { pane: Pane } = $props();

  const session = $derived(pane.phase === 'connected' ? pane.sessionId : null);
  const feed = $derived(docker.of(session));
  const listed = $derived(feed?.value);
  const containers = $derived(listed?.state === 'ok' ? listed.items : []);

  // Loaded only while this tab is open and the connection is up.
  $effect(() => {
    if (session !== null) return docker.watch(session);
  });

  /** The expanded container. */
  let open = $state<string | null>(null);
  let busy = $state<string | null>(null);
  /** Stopping and restarting ask first. */
  let confirm = $state<{ container: DockerContainer; action: 'stop' | 'restart' } | null>(null);

  const live = (c: DockerContainer) => c.state === 'running' || c.state === 'paused' || c.state === 'restarting';
  const tone = (c: DockerContainer) => (c.health === 'unhealthy' || c.state === 'dead' ? 'err' : c.state === 'restarting' || c.health === 'starting' || c.state === 'paused' ? 'warn' : live(c) ? 'ok' : (c.exitCode ?? 0) !== 0 ? 'err' : 'idle');

  /** State in words: “running for 3 d 14 h”, “exited 6 h ago (error 1)”. */
  function stateText(c: DockerContainer): string {
    const time = c.since === undefined ? '' : span(c.since);
    if (c.state === 'running') return c.health === 'unhealthy' ? t('docker.state.unhealthy', { time }) : c.health === 'starting' ? t('docker.state.starting', { time }) : t('docker.state.running', { time });
    if (c.state === 'exited') return (c.exitCode ?? 0) === 0 ? t('docker.state.exited', { time }) : t('docker.state.failed', { time, code: c.exitCode ?? 0 });
    return t(`docker.state.${c.state}`);
  }

  async function run(container: DockerContainer, action: 'start' | 'stop' | 'restart') {
    if (session === null || busy) return;
    busy = container.id;
    const done = await act(pane.key, () => dockerAction(session, container.id, action), t(`docker.done.${action}`, { name: container.name }));
    busy = null;
    if (done) void docker.refresh(session);
  }

  function ask(container: DockerContainer, action: 'stop' | 'restart') {
    confirm = { container, action };
  }

  async function confirmed() {
    const pending = confirm;
    confirm = null;
    if (pending) await run(pending.container, pending.action);
  }

  /** Logs and shell run in a new tab on the same server. */
  async function tab(container: DockerContainer, kind: 'logs' | 'shell') {
    try {
      openTabWith(pane.target, await dockerLine(container.id, kind, listed?.state === 'ok' && listed.sudo));
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<div class="side-b mg">
  {#if session === null}
    <div class="fnote"><Icon name="blocks" size={22} /><p>{t('manage.offline')}</p></div>
  {:else if feed?.error}
    <div class="fnote"><Icon name="alert" size={22} /><p>{feed.error}</p></div>
  {:else if !listed}
    <div class="fnote"><Icon name="blocks" size={22} /><p>{t('manage.loading')}</p></div>
  {:else if listed.state === 'password'}
    <div class="fnote"><Icon name="lock" size={22} /><p>{t('docker.password')}</p></div>
  {:else if listed.state === 'failed'}
    <div class="fnote"><Icon name="alert" size={22} /><p>{t('docker.failed')}</p><p class="mono selectable">{listed.message}</p></div>
  {:else if !containers.length}
    <div class="fnote"><Icon name="blocks" size={22} /><p>{t('docker.empty')}</p></div>
  {:else}
    <div class="mg-sum">{t('docker.sum', { run: containers.filter(live).length, all: containers.length })}</div>
    {#each containers as c (c.id)}
      <div class="mg-row" class:open={open === c.id}>
        <button type="button" class="mg-head" aria-expanded={open === c.id} onclick={() => (open = open === c.id ? null : c.id)}>
          <span class="mg-dot {tone(c)}"></span>
          <span class="mg-main">
            <b>{c.name}</b>
            <span class="mg-sub">{stateText(c)}</span>
          </span>
          {#if c.cpu !== undefined}
            <span class="mg-num"><b>{Math.round(c.cpu)} %</b>{#if c.memory}<span>{formatSize(c.memory.used)}</span>{/if}</span>
          {/if}
        </button>
        {#if open === c.id}
          <div class="mg-more">
            <dl class="mg-facts">
              <dt>{t('docker.image')}</dt>
              <dd class="mono selectable">{c.image}</dd>
              {#if c.ports.length}
                <dt>{t('docker.ports')}</dt>
                <dd class="mono">{c.ports.map((port) => port.replace('->', ' → ')).join(', ')}</dd>
              {/if}
              {#if c.memory}
                <dt>{t('docker.memory')}</dt>
                <dd>{formatSize(c.memory.used)} / {formatSize(c.memory.limit)}</dd>
              {/if}
            </dl>
            <div class="mg-acts">
              {#if live(c)}
                <Button size="sm" icon="stop" disabled={busy === c.id} onclick={() => ask(c, 'stop')}>{t('manage.stop')}</Button>
                <Button size="sm" icon="refresh" disabled={busy === c.id} onclick={() => ask(c, 'restart')}>{t('manage.restart')}</Button>
              {:else}
                <Button size="sm" icon="play" disabled={busy === c.id} onclick={() => run(c, 'start')}>{t('manage.start')}</Button>
              {/if}
              <Button size="sm" icon="log" onclick={() => tab(c, 'logs')}>{t('docker.logs')}</Button>
              {#if live(c)}<Button size="sm" icon="terminal" onclick={() => tab(c, 'shell')}>{t('docker.shell')}</Button>{/if}
            </div>
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>

<Dialog open={!!confirm} title={confirm ? t(`docker.confirm.${confirm.action}.title`, { name: confirm.container.name }) : ''}>
  <p>{confirm ? t(`docker.confirm.${confirm.action}.text`) : ''}</p>
  {#snippet actions()}
    <Button variant="primary" onclick={() => (confirm = null)}>{t('common.cancel')}</Button>
    <Button variant="danger" icon={confirm?.action === 'stop' ? 'stop' : 'refresh'} onclick={confirmed}>{confirm?.action === 'stop' ? t('manage.stop') : t('manage.restart')}</Button>
  {/snippet}
</Dialog>
