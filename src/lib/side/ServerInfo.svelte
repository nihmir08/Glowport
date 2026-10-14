<script lang="ts">
  import { formatSize } from '../files.svelte';
  import { t, tn } from '../i18n.svelte';
  import { paneAddress, panes, type Pane } from '../sessions.svelte';
  import { settings } from '../state.svelte';
  import { STATS_INTERVALS, cpuBetween, historyOf, netBetween, pruneStats, retimeStats, watchStats } from '../stats.svelte';
  import Icon from '../ui/Icon.svelte';

  /** Load of the server the pane is connected to: processor, memory, disks, network and a few key facts. */
  let { pane }: { pane: Pane } = $props();

  const session = $derived(pane.phase === 'connected' ? pane.sessionId : null);
  const history = $derived(historyOf(session));
  const samples = $derived(history?.samples ?? []);
  const now = $derived(samples[samples.length - 1]);
  const before = $derived(samples[samples.length - 2]);

  // Measured only while this view is open and the connection is up.
  $effect(() => {
    if (session !== null) return watchStats(session);
  });
  $effect(() => pruneStats(panes.flatMap((p) => (p.sessionId === null ? [] : [p.sessionId]))));

  const cpuSeries = $derived(samples.slice(1).map((sample, i) => cpuBetween(samples[i], sample)));
  const netSeries = $derived(samples.slice(1).map((sample, i) => netBetween(samples[i], sample)));
  const cpu = $derived(cpuSeries[cpuSeries.length - 1]);
  const net = $derived(netSeries[netSeries.length - 1]);
  const memUsed = $derived(now ? now.mem.total - now.mem.available : 0);
  const swapUsed = $derived(now ? now.mem.swapTotal - now.mem.swapFree : 0);

  const percent = (part: number) => `${Math.round(part * 100)} %`;
  const level = (part: number) => (part >= 0.95 ? 'err' : part >= 0.85 ? 'warn' : '');
  const decimal = (n: number) => n.toFixed(2).replace('.', settings.lang === 'de' ? ',' : '.');

  /** Uptime in the two largest units: “3 days 14 h” */
  function uptime(seconds: number): string {
    const days = Math.floor(seconds / 86_400);
    const hours = Math.floor((seconds % 86_400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days) return t('info.uptime.days', { d: days, h: hours });
    return hours ? t('info.uptime.hours', { h: hours, m: minutes }) : t('info.uptime.minutes', { m: minutes });
  }

  /** A curve from values between 0 and `max`, as a path in a 120 × 36 box. */
  function curve(values: number[], max: number): { line: string; area: string } | null {
    if (values.length < 2) return null;
    const step = 120 / (values.length - 1);
    const points = values.map((value, i) => `${(i * step).toFixed(1)} ${(34 - (Math.min(value, max) / (max || 1)) * 31).toFixed(1)}`);
    return { line: `M${points.join(' L')}`, area: `M${points.join(' L')} L120 36 L0 36Z` };
  }
  const cpuCurve = $derived(curve(cpuSeries, 1));
  const netMax = $derived(Math.max(1, ...netSeries.map((n) => Math.max(n.down, n.up))));
  const downCurve = $derived(curve(netSeries.map((n) => n.down), netMax));
  const upCurve = $derived(curve(netSeries.map((n) => n.up), netMax));
</script>

{#snippet meter(label: string, value: string, part: number)}
  <div class="meter">
    <div class="meter-l"><span>{label}</span><b>{value}</b></div>
    <div class="meter-b {level(part)}"><i style="width:{Math.min(100, Math.max(0, part * 100))}%"></i></div>
  </div>
{/snippet}

<div class="side-b">
  {#if session === null}
    <div class="fnote"><Icon name="pulse" size={22} /><p>{t('info.offline')}</p></div>
  {:else if history?.unsupported}
    <div class="fnote"><Icon name="pulse" size={22} /><p>{t('info.unsupported')}</p></div>
  {:else if !now}
    <div class="fnote"><Icon name="pulse" size={22} /><p>{t('info.measuring')}</p></div>
  {:else}
    <div class="meter">
      <div class="meter-l"><span>{t('info.cpu')}</span><b>{cpu === undefined ? '…' : percent(cpu)} · {tn('info.cores', now.cores)}</b></div>
      <svg class="spark" viewBox="0 0 120 36" preserveAspectRatio="none" aria-hidden="true">
        {#if cpuCurve}
          <path d={cpuCurve.area} fill="currentColor" opacity=".14" />
          <path d={cpuCurve.line} fill="none" stroke="currentColor" stroke-width="1.6" vector-effect="non-scaling-stroke" />
        {/if}
      </svg>
    </div>
    {@render meter(t('info.memory'), `${formatSize(memUsed)} / ${formatSize(now.mem.total)}`, memUsed / (now.mem.total || 1))}
    {#if now.mem.swapTotal > 0 && swapUsed > 0}
      {@render meter(t('info.swap'), `${formatSize(swapUsed)} / ${formatSize(now.mem.swapTotal)}`, swapUsed / now.mem.swapTotal)}
    {/if}
    {#each now.disks as disk (disk.mount)}
      {@render meter(t('info.disk', { mount: disk.mount }), `${formatSize(disk.used)} / ${formatSize(disk.total)}`, disk.used / (disk.total || 1))}
    {/each}
    <div class="meter">
      <div class="meter-l">
        <span>{t('info.net')}</span>
        <b>{#if net}<i class="net-d">↓ {formatSize(Math.round(net.down))}/s</i> · <i class="net-u">↑ {formatSize(Math.round(net.up))}/s</i>{:else}…{/if}</b>
      </div>
      <svg class="spark" viewBox="0 0 120 36" preserveAspectRatio="none" aria-hidden="true">
        {#if downCurve && upCurve}
          <path d={downCurve.area} fill="currentColor" opacity=".14" />
          <path d={downCurve.line} fill="none" stroke="currentColor" stroke-width="1.6" vector-effect="non-scaling-stroke" />
          <path class="up" d={upCurve.line} fill="none" stroke-width="1.3" vector-effect="non-scaling-stroke" />
        {/if}
      </svg>
    </div>

    <dl class="facts">
      <dt>{t('info.system')}</dt>
      <dd>{now.system || '–'}</dd>
      <dt>{t('info.kernel')}</dt>
      <dd class="mono">{now.kernel || '–'}</dd>
      <dt>{t('info.uptime')}</dt>
      <dd>{uptime(now.uptime)}</dd>
      <dt>{t('info.load')}</dt>
      <dd class="mono">{now.load.map(decimal).join(' · ')}</dd>
      <dt>{t('info.hostname')}</dt>
      <dd class="mono selectable">{now.hostname || '–'}</dd>
      <dt>{t('info.address')}</dt>
      <dd class="mono selectable">{paneAddress(pane)}</dd>
      <dt>{t('info.rate')}</dt>
      <dd>
        <select class="dropdown rate" aria-label={t('info.rate')} bind:value={settings.statsInterval} onchange={retimeStats}>
          {#each STATS_INTERVALS as n (n)}<option value={n}>{t('info.rate.s', { n })}</option>{/each}
        </select>
      </dd>
    </dl>
  {/if}
</div>
