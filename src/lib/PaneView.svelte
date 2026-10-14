<script lang="ts">
  import { clipboardWrite } from './backend';
  import { hostById } from './data.svelte';
  import { startDrag } from './drag.svelte';
  import { t } from './i18n.svelte';
  import type { Rect } from './layout';
  import { paneBackground, schemeFor } from './look.svelte';
  import { closePane, closeTab, connect, endText, kindText, paneAddress, paneColor, paneTitle, stopRetry, tabOf, type Pane } from './sessions.svelte';
  import Terminal from './Terminal.svelte';
  import Button from './ui/Button.svelte';
  import Icon from './ui/Icon.svelte';
  import TargetIcon from './ui/TargetIcon.svelte';
  import { moshInstall } from './mosh';
  import { toast } from './state.svelte';

  /**
   * Ein Terminal-Bereich an seinem Platz im Tab. `rect` ist sein Platz in Anteilen der Fläche;
   * `split` sagt, ob der Tab mehrere Bereiche hat (dann bekommt jeder eine Kopfzeile zum Greifen).
   */
  let { pane, rect, visible, focused, split, multi }: { pane: Pane; rect: Rect; visible: boolean; focused: boolean; split: boolean; multi: boolean } = $props();

  const scheme = $derived(schemeFor(pane.target));
  const color = $derived(paneColor(pane) ?? 'var(--accent)');
  const pct = (n: number) => `${(n * 100).toFixed(4)}%`;

  function focus() {
    const tab = tabOf(pane.key);
    if (tab) tab.focus = pane.key;
  }

  /** Befehl zum Installieren von mosh, soweit das System des Servers bekannt ist. */
  const install = $derived(pane.moshFallback?.reason === 'missing' ? moshInstall(pane.target.kind === 'host' ? hostById(pane.target.id)?.os : null) : null);

  async function copyInstall() {
    if (!install) return;
    await clipboardWrite(install);
    toast(t('logs.copied'), 'ok');
  }

  /** Schließt den Bereich; ist er der einzige, schließt das den Tab. */
  function close() {
    const tab = tabOf(pane.key);
    if (tab && !split) closeTab(tab.key);
    else closePane(pane.key);
  }
</script>

<div
  class="pane"
  class:off={!visible}
  class:foc={split && focused}
  class:multi
  class:edge-l={rect.x > 0.001}
  class:edge-t={rect.y > 0.001}
  data-pane={pane.key}
  role="group"
  aria-label={paneTitle(pane)}
  style="left:{pct(rect.x)};top:{pct(rect.y)};width:{pct(rect.w)};height:{pct(rect.h)};--pane-bg:{paneBackground(scheme)};--pane-fg:{scheme.foreground};--c:{color}"
  onpointerdowncapture={focus}
>
  {#if split}
    <div class="pane-h" role="presentation" onpointerdown={(e) => startDrag(e, { kind: 'pane', key: pane.key }, paneTitle(pane), color)}>
      <i class="dot {pane.phase}"></i>
      <TargetIcon target={pane.target} bare />
      <b>{paneTitle(pane)}</b>
      <span class="pa">{paneAddress(pane)}</span>
      <span class="grow"></span>
      {#if pane.mosh}<i class="chip a mchip">Mosh</i>{/if}
      {#if pane.recording}<span class="recdot" title={t('session.record.on')}></span>{/if}
      <button type="button" class="mini" title={t('pane.close')} aria-label={t('pane.close')} onclick={close}><Icon name="x" size={12} /></button>
    </div>
  {/if}

  {#if pane.mosh?.silent}
    <div class="moshbar warn" role="status"><Icon name="alert" size={14} /><span>{t('mosh.silent', { n: pane.mosh.silent })}</span></div>
  {:else if pane.moshFallback}
    <div class="moshbar" role="status">
      <Icon name="alert" size={14} />
      <span class="grow">
        {t(`mosh.fallback.${pane.moshFallback.reason}`)}
        {#if pane.moshFallback.detail}<i class="mono">{pane.moshFallback.detail}</i>{/if}
        {#if pane.moshFallback.reason === 'missing'}
          {#if install}{t('mosh.install')} <code class="mono selectable">{install}</code>{:else}{t('mosh.install.other')}{/if}
        {/if}
      </span>
      {#if install}<Button size="sm" icon="copy" title={t('mosh.install.copy')} onclick={copyInstall} />{/if}
      <button type="button" class="mini" title={t('common.close')} aria-label={t('common.close')} onclick={() => (pane.moshFallback = null)}><Icon name="x" size={12} /></button>
    </div>
  {/if}

  <Terminal {pane} {visible} {focused} />

  {#if pane.phase === 'ended'}
    <div class="endbar">
      <span class="grow">
        {pane.end ? endText(pane, pane.end) : ''}
        {#if pane.retryIn !== null}&nbsp;· {t('session.retry.in', { n: pane.retryIn })}{/if}
      </span>
      {#if pane.retryIn !== null}
        <Button size="sm" onclick={() => stopRetry(pane)}>{kindText(pane.kind, 'session.retry', 'stop')}</Button>
        <Button size="sm" variant="primary" onclick={() => connect(pane.key)}>{kindText(pane.kind, 'session.retry', 'now')}</Button>
      {:else}
        <Button size="sm" onclick={close}>{split ? t('pane.close') : t('session.closeTab')}</Button>
        <Button size="sm" variant="primary" icon="play" onclick={() => connect(pane.key)}>{kindText(pane.kind, 'session', 'reconnect')}</Button>
      {/if}
    </div>
  {/if}
</div>
