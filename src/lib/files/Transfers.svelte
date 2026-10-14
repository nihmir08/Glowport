<script lang="ts">
  import { transferClear, transferControl, watchStop } from '../backend';
  import { errorText } from '../data.svelte';
  import { activeTransfers, formatDuration, formatSize, formatWhen, isActive, overallSpeed, transfers } from '../files.svelte';
  import type { IconName } from '../icons';
  import { has, t, type Key } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import type { Transfer } from '../types';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';

  /** The transfer queue. `dock` is the version at the bottom of the Files page, otherwise it floats above the status bar. */
  let { dock = false }: { dock?: boolean } = $props();

  const list = $derived(transfers.list);
  const open = $derived(list.filter((x) => isActive(x) || x.state === 'paused'));
  const closed = $derived(list.some((x) => !isActive(x) && x.state !== 'paused'));
  const paused = $derived(open.length > 0 && open.every((x) => x.state === 'paused'));
  const speed = $derived(overallSpeed());
  const left = $derived(open.reduce((n, x) => n + (x.state === 'paused' ? 0 : x.bytes - x.done), 0));

  const ICON: Record<Transfer['direction'], IconName> = { upload: 'upload', download: 'download', remote: 'forward' };
  const control = (ids: number[] | null, action: 'pause' | 'resume' | 'cancel' | 'retry') => void transferControl(ids, action).catch((e) => toast(errorText(e), 'err'));
  const percent = (x: Transfer) => (x.bytes ? Math.floor((x.done / x.bytes) * 100) : x.state === 'done' ? 100 : 0);

  function status(x: Transfer): string {
    switch (x.state) {
      case 'running':
        return [`${percent(x)} %`, `${formatSize(x.speed)}/s`, x.speed > 0 ? t('transfers.left', { time: formatDuration((x.bytes - x.done) / x.speed) }) : ''].filter(Boolean).join(' · ');
      case 'failed': {
        const key = `err.${x.error ?? 'internal'}`;
        return t('transfers.failed', { why: has(key) ? t(key, { message: '' }) : (x.error ?? '') });
      }
      default:
        return t(`transfers.state.${x.state}`) + (x.state === 'paused' ? ` · ${percent(x)} %` : '');
    }
  }
  const amount = (x: Transfer) => (x.files > 1 ? t('transfers.files', { done: x.filesDone, n: x.files }) + ' · ' : '') + (x.state === 'done' ? formatSize(x.bytes) : `${formatSize(x.done)} / ${formatSize(x.bytes)}`);
</script>

<section class="xfers isl" class:dock aria-label={t('transfers.title')}>
  <header class="xfers-h">
    <Icon name="transfer" size={15} />
    <b>{t('transfers.title')}</b>
    {#if open.length}
      <span class="rm">{t('transfers.summary', { n: activeTransfers().length })}{#if speed}&nbsp;· {formatSize(speed)}/s · {t('transfers.left', { time: formatDuration(left / speed) })}{/if}</span>
    {/if}
    <span class="grow"></span>
    {#if open.length}
      <Button size="sm" icon={paused ? 'play' : 'pause'} onclick={() => control(null, paused ? 'resume' : 'pause')}>{paused ? t('transfers.resumeAll') : t('transfers.pauseAll')}</Button>
    {/if}
    {#if closed}<Button size="sm" icon="check" onclick={() => void transferClear()}>{t('transfers.clear')}</Button>{/if}
    <Button variant="ghost" size="sm" icon={dock ? 'chevD' : 'x'} title={t('common.close')} onclick={() => (dock ? (transfers.dock = false) : (transfers.panel = false))} />
  </header>

  <div class="xfers-b">
    {#if !list.length && !transfers.watched.length}
      <p class="fnote">{t('transfers.empty')}</p>
    {/if}
    {#if transfers.watched.length}
      <div class="xsec">{t('transfers.watched')}</div>
      {#each transfers.watched as w (w.id)}
        <div class="xfer watched">
          <span class="fi"><Icon name="edit" size={15} /></span>
          <div class="xt">
            <div class="xn"><b>{w.name}</b><span class="grow"></span><span class="xs" class:err={!!w.error}>{w.error ? t('transfers.failed', { why: has(`err.${w.error}`) ? t(`err.${w.error}` as Key, { message: '' }) : w.error }) : w.uploadedAt ? t('transfers.watched.last', { n: w.uploads, time: formatWhen(w.uploadedAt) }) : t('transfers.watched.waiting')}</span></div>
            <div class="xp"><span class="mono">{w.origin}</span></div>
          </div>
          <div class="xa"><Button size="sm" onclick={() => void watchStop(w.id)}>{t('transfers.watched.stop')}</Button></div>
        </div>
      {/each}
      {#if list.length}<div class="xsec">{t('transfers.queue')}</div>{/if}
    {/if}
    {#each list as x (x.id)}
      <div class="xfer {x.state}">
        <span class="fi"><Icon name={ICON[x.direction]} size={15} /></span>
        <div class="xt">
          <div class="xn"><b>{x.name}</b>{#if x.resumed && x.state !== 'done'}<i class="chip">{t('transfers.resumed')}</i>{/if}<span class="grow"></span><span class="xs">{status(x)}</span></div>
          <div class="xbar"><i style="width:{percent(x)}%"></i></div>
          <div class="xp"><span class="mono">{x.source}</span><Icon name="arrowR" size={10} /><span class="mono">{x.dest}</span><span class="grow"></span><span>{amount(x)}</span></div>
        </div>
        <div class="xa">
          {#if x.state === 'running' || x.state === 'queued'}
            <button type="button" class="mini" title={t('transfers.pause')} aria-label={t('transfers.pause')} onclick={() => control([x.id], 'pause')}><Icon name="pause" size={13} /></button>
          {:else if x.state === 'paused'}
            <button type="button" class="mini" title={t('transfers.resume')} aria-label={t('transfers.resume')} onclick={() => control([x.id], 'resume')}><Icon name="play" size={13} /></button>
          {:else if x.state === 'failed' || x.state === 'cancelled'}
            <button type="button" class="mini" title={t('transfers.retry')} aria-label={t('transfers.retry')} onclick={() => control([x.id], 'retry')}><Icon name="refresh" size={13} /></button>
          {/if}
          {#if x.state !== 'done' && x.state !== 'cancelled'}
            <button type="button" class="mini" title={t('transfers.cancel')} aria-label={t('transfers.cancel')} onclick={() => control([x.id], 'cancel')}><Icon name="x" size={13} /></button>
          {/if}
        </div>
      </div>
    {/each}

  </div>
</section>
