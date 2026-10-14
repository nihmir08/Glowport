<script lang="ts">
  import { sessionRelink } from '../backend';
  import type { IconName } from '../icons';
  import { t } from '../i18n.svelte';
  import { abilitiesOf, probe } from '../manage.svelte';
  import type { Pane } from '../sessions.svelte';
  import { settings, type SideTab } from '../state.svelte';
  import Button from '../ui/Button.svelte';
  import Icon from '../ui/Icon.svelte';
  import DockerTab from './DockerTab.svelte';
  import ProcessesTab from './ProcessesTab.svelte';
  import ServerInfo from './ServerInfo.svelte';
  import ServicesTab from './ServicesTab.svelte';
  import SnippetBar from './SnippetBar.svelte';

  /**
   * Seitenleiste rechts neben dem Terminal: Auslastung des Servers, Snippets und, wo der Server sie hergibt,
   * Docker, Dienste und Prozesse für den Bereich mit der Tastatur.
   */
  let { pane }: { pane: Pane } = $props();

  const ALL: { id: SideTab; icon: IconName; label: 'side.info' | 'side.snippets' | 'side.docker' | 'side.services' | 'side.processes' }[] = [
    { id: 'info', icon: 'pulse', label: 'side.info' },
    { id: 'snip', icon: 'snippet', label: 'side.snippets' },
    { id: 'docker', icon: 'blocks', label: 'side.docker' },
    { id: 'services', icon: 'gear', label: 'side.services' },
    { id: 'processes', icon: 'list', label: 'side.processes' },
  ];
  const session = $derived(pane.kind === 'ssh' && pane.phase === 'connected' ? pane.sessionId : null);
  // Was es auf dem Server gibt, wird einmal nachgesehen, sobald die Verbindung steht.
  $effect(() => {
    if (session !== null) probe(session);
  });
  const able = $derived(abilitiesOf(session));
  // Alles außer den Snippets kommt über SSH vom Server. Bei Telnet, serieller Leitung und lokalem Terminal bleiben
  // die Snippets; Docker, Dienste und Prozesse gibt es nur, wo der Server sie hergibt.
  const tabs = $derived(ALL.filter((tab) => tab.id === 'snip' || (pane.kind === 'ssh' && (tab.id === 'info' || !!able?.[tab.id]))));
  const shown = $derived(tabs.some((tab) => tab.id === settings.sideTab) ? settings.sideTab : pane.kind === 'ssh' ? 'info' : 'snip');

  /** Zieht die Breite der Leiste an ihrem linken Rand. */
  function resize(event: PointerEvent) {
    if (event.button !== 0) return;
    event.preventDefault();
    const grip = event.currentTarget as HTMLElement;
    const start = event.clientX + settings.sideBarWidth;
    grip.setPointerCapture(event.pointerId);
    const move = (e: PointerEvent) => (settings.sideBarWidth = Math.round(Math.max(240, Math.min(460, start - e.clientX))));
    const stop = () => (grip.removeEventListener('pointermove', move), grip.removeEventListener('pointerup', stop), grip.removeEventListener('pointercancel', stop));
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', stop);
    grip.addEventListener('pointercancel', stop);
  }
</script>

<aside class="side isl" style="width:{settings.sideBarWidth}px" aria-label={t('side.title')}>
  <header class="side-h" role="tablist">
    {#each tabs as tab (tab.id)}
      <button type="button" class="stab" class:on={shown === tab.id} role="tab" aria-selected={shown === tab.id} title={t(tab.label)} onclick={() => (settings.sideTab = tab.id)}>
        <Icon name={tab.icon} size={14} />{#if shown === tab.id || tabs.length <= 2}<span>{t(tab.label)}</span>{/if}
      </button>
    {/each}
    <span class="grow"></span>
    <Button variant="ghost" size="sm" icon="x" title={t('side.hide')} onclick={() => (settings.sideBar = false)} />
  </header>
  {#if pane.mosh && !pane.mosh.side && shown !== 'snip'}
    <div class="moshbar side-mosh" role="status">
      <span class="grow">{t('mosh.side.lost')}</span>
      <Button size="sm" icon="refresh" onclick={() => pane.sessionId !== null && void sessionRelink(pane.sessionId)}>{t('mosh.side.relink')}</Button>
    </div>
  {/if}
  {#if shown === 'info'}
    <ServerInfo {pane} />
  {:else if shown === 'docker'}
    <DockerTab {pane} />
  {:else if shown === 'services'}
    <ServicesTab {pane} />
  {:else if shown === 'processes'}
    <ProcessesTab {pane} />
  {:else}
    <SnippetBar {pane} />
  {/if}
  <div class="sgrip" role="separator" aria-orientation="vertical" onpointerdown={resize}></div>
</aside>
