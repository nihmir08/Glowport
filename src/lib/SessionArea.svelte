<script lang="ts">
  import { hostSave } from './backend';
  import { DEFAULT_PORT, DEFAULT_TELNET_PORT, applySnapshot, errorText, vault } from './data.svelte';
  import { drag } from './drag.svelte';
  import { t } from './i18n.svelte';
  import FileBar from './files/FileBar.svelte';
  import { dividers, leaves, rects, type Divider, type Rect } from './layout';
  import { look } from './look.svelte';
  import PaneView from './PaneView.svelte';
  import SessionPrompt from './SessionPrompt.svelte';
  import SideBar from './side/SideBar.svelte';
  import { activeTab, answer, askingPane, connect, disconnect, kindText, paneAddress, paneByKey, panes, paneTitle, resizeSplit, setRecording, splitPane, tabOf, view } from './sessions.svelte';
  import { settings, toast } from './state.svelte';
  import type { Fields } from './types';
  import Button from './ui/Button.svelte';
  import Icon from './ui/Icon.svelte';
  import TargetIcon from './ui/TargetIcon.svelte';

  /**
   * Alle Sitzungen: die Leiste des vorderen Tabs und darunter die Bereiche.
   * Die Bereiche sämtlicher Tabs liegen nebeneinander in einer Fläche und werden nur ein- und ausgeblendet.
   * So behält jedes Terminal seinen Inhalt, auch wenn es den Platz oder den Tab wechselt.
   */
  let { hidden }: { hidden: boolean } = $props();

  let area = $state<HTMLDivElement>();

  const tab = $derived(activeTab());
  const inside = $derived(tab ? leaves(tab.layout) : []);
  const split = $derived(inside.length > 1);
  const focused = $derived(paneByKey(tab?.focus));
  /** Dateileiste und Server-Info hängen an SSH; bei Telnet, serieller Leitung und lokalem Terminal gibt es sie nicht. */
  const ssh = $derived(focused?.kind === 'ssh');
  const live = $derived(focused?.sessionId != null);
  const asking = $derived(tab ? askingPane(tab) : undefined);
  const lines = $derived(tab ? dividers(tab.layout) : []);

  /** Platz jedes Bereichs in seinem Tab. */
  const places = $derived.by(() => {
    const out = new Map<string, { rect: Rect; tab: string; split: boolean; focus: boolean; multi: boolean }>();
    for (const pane of panes) {
      const owner = tabOf(pane.key);
      if (!owner) continue;
      const all = rects(owner.layout);
      out.set(pane.key, { rect: all.get(pane.key)!, tab: owner.key, split: all.size > 1, focus: owner.focus === pane.key, multi: owner.multi });
    }
    return out;
  });

  /** Die Fläche, die beim Ablegen neu belegt würde. */
  const preview = $derived.by((): Rect | null => {
    const drop = drag.item ? drag.drop : null;
    if (drop?.kind !== 'pane') return null;
    const rect = places.get(drop.pane)?.rect;
    if (!rect) return null;
    switch (drop.side) {
      case 'left':
        return { ...rect, w: rect.w / 2 };
      case 'right':
        return { ...rect, x: rect.x + rect.w / 2, w: rect.w / 2 };
      case 'top':
        return { ...rect, h: rect.h / 2 };
      case 'bottom':
        return { ...rect, y: rect.y + rect.h / 2, h: rect.h / 2 };
      default:
        return rect;
    }
  });

  const pct = (n: number) => `${(n * 100).toFixed(4)}%`;
  const box = (r: Rect) => `left:${pct(r.x)};top:${pct(r.y)};width:${pct(r.w)};height:${pct(r.h)}`;
  const lineStyle = (d: Divider) =>
    d.dir === 'row' ? `left:${pct(d.area.x + d.area.w * d.ratio)};top:${pct(d.area.y)};height:${pct(d.area.h)}` : `top:${pct(d.area.y + d.area.h * d.ratio)};left:${pct(d.area.x)};width:${pct(d.area.w)}`;

  /** Zieht eine Trennlinie: Das Verhältnis folgt der Maus innerhalb der Fläche, die die Linie teilt. */
  function resize(event: PointerEvent, d: Divider) {
    if (event.button !== 0 || !area || !tab) return;
    event.preventDefault();
    const grip = event.currentTarget as HTMLElement;
    const owner = tab;
    const bounds = area.getBoundingClientRect();
    grip.setPointerCapture(event.pointerId);
    grip.classList.add('on');
    const move = (e: PointerEvent) => {
      const ratio = d.dir === 'row' ? (e.clientX - bounds.left - d.area.x * bounds.width) / (d.area.w * bounds.width) : (e.clientY - bounds.top - d.area.y * bounds.height) / (d.area.h * bounds.height);
      resizeSplit(owner, d.path, ratio);
    };
    const stop = () => {
      grip.classList.remove('on');
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', stop);
      grip.removeEventListener('pointercancel', stop);
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', stop);
    grip.addEventListener('pointercancel', stop);
  }

  /** Nach einer Schnellverbindung: die Adresse als Host in den Tresor legen. Der Bereich gehört danach zu diesem Host. */
  async function saveAsHost() {
    const pane = focused;
    const target = pane?.target;
    if (!pane || (target?.kind !== 'direct' && target?.kind !== 'telnet')) return;
    const { host: address, port } = target;
    const own: Fields = target.kind === 'direct' ? { user: target.user } : {};
    if (port !== (target.kind === 'direct' ? DEFAULT_PORT : DEFAULT_TELNET_PORT)) own.port = port;
    try {
      const changed = await hostSave({ name: address, address, protocol: target.kind === 'direct' ? 'ssh' : 'telnet', group: null, color: null, os: null, own });
      applySnapshot(changed.data);
      pane.target = { kind: 'host', id: changed.id! };
      toast(t('common.saved'), 'ok');
    } catch (e) {
      toast(errorText(e), 'err');
    }
  }
</script>

<div class="sview" class:off={hidden}>
  {#if settings.fileBar && focused && ssh}<FileBar pane={focused} />{/if}
  <section class="tarea isl">
    {#if tab && focused}
      <div class="tbar">
        <TargetIcon target={focused.target} size="sm" />
        <div class="tt"><b>{paneTitle(focused)}</b><span>{paneAddress(focused)}</span></div>
        <span class="live {focused.phase}"><i></i>{kindText(focused.kind, 'session.phase', focused.phase === 'idle' ? 'connecting' : focused.phase)}</span>
        {#if focused.mosh}<i class="chip a mchip" title={t('mosh.chip.hint')}>Mosh</i>{/if}
        <span class="grow"></span>
        {#if (focused.target.kind === 'direct' || focused.target.kind === 'telnet') && vault.state === 'open'}
          <Button size="sm" icon="plus" onclick={saveAsHost}>{t('session.save')}</Button>
        {/if}
        {#if ssh}
          <Button size="sm" icon="panel" active={settings.fileBar} title={t('files.bar.hint')} onclick={() => (settings.fileBar = !settings.fileBar)}>{t('nav.files')}</Button>
        {/if}
        <Button size="sm" icon="splitH" title={t('pane.split.right')} onclick={() => splitPane(focused.key, 'right')} />
        <Button size="sm" icon="splitV" title={t('pane.split.down')} onclick={() => splitPane(focused.key, 'bottom')} />
        {#if split}
          <Button size="sm" icon="cast" active={tab.multi} title={t('multi.hint')} onclick={() => (tab.multi = !tab.multi)}>{t('multi.title')}</Button>
        {/if}
        <Button size="sm" icon="rec" active={focused.recording} title={t('session.record.hint')} onclick={() => setRecording(focused.key, !focused.recording)}>{t('session.record')}</Button>
        <Button size="sm" icon="panelR" active={settings.sideBar} title={t(ssh ? 'side.hint' : 'side.hint.plain')} onclick={() => (settings.sideBar = !settings.sideBar)}>{t('side.title')}</Button>
        {#if live}
          <Button size="sm" icon="x" onclick={() => disconnect(focused.key)}>{kindText(focused.kind, 'session', 'disconnect')}</Button>
        {:else if focused.phase === 'ended'}
          <Button size="sm" icon="play" onclick={() => connect(focused.key)}>{kindText(focused.kind, 'session', 'reconnect')}</Button>
        {/if}
      </div>
      {#if tab.multi}
        <div class="mx"><Icon name="cast" size={13} /><span>{t('multi.banner', { n: inside.length })}</span></div>
      {/if}
    {/if}

    <div
      class="panes"
      class:image={!!look.background}
      bind:this={area}
      style={look.background ? `--term-image:url("${look.background}");--term-blur:${settings.termBlur}px` : ''}
    >
      {#each panes as pane (pane.key)}
        {@const place = places.get(pane.key)}
        {#if place}
          <PaneView {pane} rect={place.rect} visible={!hidden && place.tab === view.active} focused={place.focus} split={place.split} multi={place.multi} />
        {/if}
      {/each}
      {#each lines as d (d.path)}
        <div class="divider" class:upright={d.dir === 'row'} class:level={d.dir === 'col'} role="separator" aria-orientation={d.dir === 'row' ? 'vertical' : 'horizontal'} style={lineStyle(d)} onpointerdown={(e) => resize(e, d)}></div>
      {/each}
      {#if preview}<div class="droparea" style={box(preview)}></div>{/if}
    </div>
  </section>
  {#if settings.sideBar && focused}<SideBar pane={focused} />{/if}
</div>

{#if !hidden && asking}<SessionPrompt prompt={asking.prompt} name={paneTitle(asking)} onanswer={(reply) => answer(asking.key, reply)} />{/if}
