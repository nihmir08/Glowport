<script lang="ts">
  import { clipboardWrite, forwardSave } from '../backend';
  import { applySnapshot, errorText, hostById, pathLabel, sshHosts, vault } from '../data.svelte';
  import { formatSize } from '../files.svelte';
  import { forwardEndpoint, forwardError, stateOf, toggleForward } from '../forwards.svelte';
  import { targetVault } from '../sync.svelte';
  import { t, type Key } from '../i18n.svelte';
  import { hostActions } from '../quick.svelte';
  import { toast } from '../state.svelte';
  import type { Forward, ForwardInput, ForwardKind } from '../types';
  import ActionSelect from '../ui/ActionSelect.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Switch from '../ui/Switch.svelte';
  import TextField from '../ui/TextField.svelte';

  /** Creating and editing a port rule. For a saved rule the top shows whether it is running. */
  let { rule, onclose, onsaved, ondelete }: { rule: Forward | null; onclose: () => void; onsaved: (id: string) => void; ondelete: (rule: Forward) => void } = $props();

  // The editor is created anew per rule ({#key}); the initial values are deliberately read only once.
  const start = (() => rule)();
  const LOOPBACK = ['', '127.0.0.1', 'localhost'];

  let name = $state(start?.name ?? '');
  let kind = $state<ForwardKind>(start?.kind ?? 'local');
  let host = $state(start?.host ?? '');
  let bindPort = $state(start ? String(start.bindPort) : '');
  let destHost = $state(start?.destHost || '127.0.0.1');
  let destPort = $state(start?.destPort ? String(start.destPort) : '');
  /** Reachable for other computers too: listening on all addresses instead of only our own. */
  let open = $state(start ? !LOOPBACK.includes(start.bindAddress) : false);
  let busy = $state(false);
  let error = $state('');

  /** The rule's state while it is switched on. */
  const live = $derived(start ? stateOf(start.id) : undefined);
  const hostName = $derived(hostById(host)?.name ?? t('fwd.route.host'));
  const hosts = $derived([...sshHosts()].sort((a, b) => a.name.localeCompare(b.name)).map((h) => ({ value: h.id, label: h.group ? `${h.name} · ${pathLabel(h.group)}` : h.name })));
  /** The clock only ticks while the rule runs and its run time is visible. */
  let clock = $state(Date.now());
  $effect(() => {
    if (!live?.since) return;
    const timer = setInterval(() => (clock = Date.now()), 1000);
    return () => clearInterval(timer);
  });
  const seconds = $derived(live?.since ? Math.max(0, Math.round((clock - live.since) / 1000)) : 0);

  /** How long the rule has been running, in the largest fitting unit. */
  function since(total: number): string {
    if (total < 60) return t('fwd.since.seconds', { n: total });
    if (total < 3600) return t('fwd.since.minutes', { n: Math.floor(total / 60) });
    return t('fwd.since.hours', { h: Math.floor(total / 3600), m: Math.floor((total % 3600) / 60) });
  }

  async function copy(text: string) {
    await clipboardWrite(text);
    toast(t('fwd.copied', { text }), 'ok');
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    const port = (text: string) => (/^\d{1,5}$/.test(text.trim()) ? Number(text) : NaN);
    const input: ForwardInput = {
      id: start?.id,
      name,
      kind,
      host,
      // A custom address stays as long as the switch does not change it.
      bindAddress: open ? (start && !LOOPBACK.includes(start.bindAddress) ? start.bindAddress : '0.0.0.0') : '127.0.0.1',
      bindPort: port(bindPort),
      destHost: kind === 'dynamic' ? '' : destHost,
      destPort: kind === 'dynamic' ? 0 : port(destPort),
    };
    if (!host) return void (error = t('err.invalid.host_missing'));
    // A new rule goes into the vault shown if its host is there too; otherwise it stays personal.
    if (!start && targetVault() && hostById(host)?.vault === targetVault()) input.vault = targetVault();
    if (Number.isNaN(input.bindPort) || Number.isNaN(input.destPort)) return void (error = t('err.invalid.port_invalid'));
    busy = true;
    try {
      const changed = await forwardSave(input);
      applySnapshot(changed.data);
      toast(t('common.saved'), 'ok');
      onsaved(changed.id!);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<form class="editor isl" onsubmit={save}>
  <header class="ed-h">
    <span class="os lg" style="--c:var(--accent)"><Icon name={kind === 'dynamic' ? 'globe' : 'forward'} size={22} /></span>
    <div style="min-width:0">
      <div class="d-name">{name || t('fwd.title.new')}</div>
      <div class="d-sub">{start ? t('fwd.title.edit') : t('fwd.title.new')}</div>
    </div>
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('common.close')} onclick={onclose} />
  </header>

  <div class="ed-b">
    {#if start}
      <div class="fwd-live" class:on={live?.phase === 'running'} class:bad={live?.phase === 'failed'}>
        <div class="fwd-live-h">
          <i class="dot {live?.phase ?? 'idle'}"></i>
          <b>{live ? t(`fwd.phase.${live.phase}` as Key) : t('fwd.phase.off')}</b>
          <span class="grow"></span>
          <Switch label={t('fwd.switch')} bind:checked={() => !!live, (on) => void toggleForward(start.id, on)} />
        </div>
        {#if live?.phase === 'failed' || live?.phase === 'retrying'}
          <p class="errline">{forwardError(live)}{#if live.phase === 'retrying' && live.retryIn}&nbsp;· {t('session.retry.in', { n: live.retryIn })}{/if}</p>
        {/if}
        {#if live?.phase === 'running'}
          <dl class="fwd-nums">
            <div><dt>{t('fwd.live.open')}</dt><dd>{live.open}</dd></div>
            <div><dt>{t('fwd.live.total')}</dt><dd>{live.total}</dd></div>
            <div><dt>{t('fwd.live.traffic')}</dt><dd>↑ {formatSize(live.sent)} · ↓ {formatSize(live.received)}</dd></div>
            <div><dt>{t('fwd.live.since')}</dt><dd>{since(seconds)}</dd></div>
          </dl>
          <button type="button" class="fwd-addr" title={t('fwd.copy')} onclick={() => copy(forwardEndpoint(start))}>
            <span class="mono">{start.kind === 'dynamic' ? 'socks5://' : ''}{forwardEndpoint(start)}</span><Icon name="copy" size={13} />
          </button>
        {/if}
      </div>
    {/if}

    <TextField label={t('edit.name')} bind:value={name} placeholder="Grafana" autofocus={!start} />
    <div class="fld">
      <span class="fld-l">{t('fwd.kind')}</span>
      <Segmented
        label={t('fwd.kind')}
        bind:value={kind}
        options={[
          { value: 'local', label: t('fwd.kind.local') },
          { value: 'remote', label: t('fwd.kind.remote') },
          { value: 'dynamic', label: t('fwd.kind.dynamic') },
        ]}
      />
      <span class="fld-h">{t(`fwd.kind.${kind}.hint` as Key)}</span>
    </div>
    <label class="fld">
      <span class="fld-l">{t('fwd.host')}</span>
      <ActionSelect bind:value={host} options={[{ value: '', label: t('fwd.host.choose') }, ...hosts]} actions={hostActions((id) => (host = id))} />
    </label>

    <!-- A connection's route: who listens, what it goes through, where it arrives. -->
    <div class="route" aria-hidden="true">
      {#if kind === 'remote'}
        <div class="route-n"><Icon name="server" size={14} /><b>{hostName}</b><span class="mono">:{bindPort || '…'}</span></div>
        <Icon name="arrowR" size={14} />
        <div class="route-n"><Icon name="monitor" size={14} /><b>{t('fwd.thispc')}</b></div>
        <Icon name="arrowR" size={14} />
        <div class="route-n"><span class="mono">{destHost || '…'}:{destPort || '…'}</span></div>
      {:else}
        <div class="route-n"><Icon name="monitor" size={14} /><b>{t('fwd.thispc')}</b><span class="mono">:{bindPort || '…'}</span></div>
        <Icon name="arrowR" size={14} />
        <div class="route-n"><Icon name="server" size={14} /><b>{hostName}</b></div>
        <Icon name="arrowR" size={14} />
        <div class="route-n">{#if kind === 'dynamic'}<Icon name="globe" size={14} /><b>{t('fwd.route.any')}</b>{:else}<span class="mono">{destHost || '…'}:{destPort || '…'}</span>{/if}</div>
      {/if}
    </div>

    <div class="ed-sec">{kind === 'remote' ? t('fwd.sec.listen.remote') : t('fwd.sec.listen.local')}</div>
    <TextField label={t('detail.port')} bind:value={bindPort} placeholder={kind === 'dynamic' ? '1080' : '8080'} mono hint={kind === 'remote' ? undefined : t('fwd.port.hint')} />
    <label class="check"><input type="checkbox" bind:checked={open} />{kind === 'remote' ? t('fwd.open.remote') : t('fwd.open.local')}</label>
    {#if open}
      <div class="warnbox"><Icon name="alert" size={16} /><span>{kind === 'remote' ? t('fwd.open.remote.warn') : t('fwd.open.local.warn')}</span></div>
    {/if}

    {#if kind !== 'dynamic'}
      <div class="ed-sec">{kind === 'remote' ? t('fwd.sec.dest.remote') : t('fwd.sec.dest.local')}</div>
      <div class="ed-row">
        <TextField label={t('detail.address')} bind:value={destHost} placeholder="127.0.0.1" mono />
        <TextField label={t('detail.port')} bind:value={destPort} placeholder="3000" mono />
      </div>
      <span class="fld-h">{kind === 'remote' ? t('fwd.dest.remote.hint') : t('fwd.dest.local.hint', { host: hostName })}</span>
    {:else}
      <span class="fld-h">{t('fwd.dynamic.use', { port: bindPort || '1080' })}</span>
    {/if}
    {#if start && live}<span class="fld-h">{t('fwd.edit.running')}</span>{/if}
    {#if error}<p class="errline" role="alert">{error}</p>{/if}
  </div>

  <footer class="ed-f">
    {#if start}<Button variant="danger" icon="trash" onclick={() => ondelete(start)}>{t('common.delete')}</Button>{/if}
    <span class="grow"></span>
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <button type="submit" class="btn primary" disabled={busy}>{t('common.save')}</button>
  </footer>
</form>
