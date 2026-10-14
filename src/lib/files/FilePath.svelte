<script lang="ts">
  import type { Browser } from '../files.svelte';
  import { t } from '../i18n.svelte';
  import Icon from '../ui/Icon.svelte';

  /** The path to the open folder as clickable pieces; a click beside them turns it into a field for typing. */
  let { browser }: { browser: Browser } = $props();

  let editing = $state(false);
  let text = $state('');
  let strip = $state<HTMLDivElement>();

  const crumbs = $derived(browser.listing?.crumbs ?? []);

  // For long paths the end matters: scroll there.
  $effect(() => {
    void crumbs.length;
    if (strip) strip.scrollLeft = strip.scrollWidth;
  });

  function edit() {
    text = browser.path ?? '';
    editing = true;
  }

  async function commit() {
    editing = false;
    const wanted = text.trim();
    if (wanted && wanted !== browser.path) await browser.go(wanted);
  }

  function selectAll(node: HTMLInputElement) {
    node.focus();
    node.select();
  }
</script>

<div class="fpath">
  {#if editing}
    <input
      class="mono"
      bind:value={text}
      aria-label={t('files.path')}
      spellcheck="false"
      use:selectAll
      onblur={commit}
      onkeydown={(e) => {
        if (e.key === 'Enter') void commit();
        if (e.key === 'Escape') editing = false;
        e.stopPropagation();
      }}
    />
  {:else}
    <div class="fcrumbs" bind:this={strip} role="presentation" ondblclick={edit}>
      {#each crumbs as crumb, i (crumb.path)}
        {#if i > 0}<Icon name="chev" size={10} />{/if}
        <button type="button" class:last={i === crumbs.length - 1} onclick={() => browser.go(crumb.path)}>{crumb.name || t('files.local')}</button>
      {/each}
    </div>
    <button type="button" class="mini" title={t('files.path.edit')} aria-label={t('files.path.edit')} disabled={!browser.listing} onclick={edit}><Icon name="edit" size={12} /></button>
  {/if}
</div>
