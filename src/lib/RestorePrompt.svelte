<script lang="ts">
  import { t } from './i18n.svelte';
  import { leaves, type Layout } from './layout';
  import { titleOf } from './sessions.svelte';
  import { settings } from './state.svelte';
  import type { SavedTab, Target } from './types';
  import Button from './ui/Button.svelte';
  import LayoutPreview from './ui/LayoutPreview.svelte';

  /**
   * Prompt after a crash: Glowport was not quit properly last time.
   * Restored only after consent; the checkbox switches the prompt off permanently.
   */
  let { saved, onrestore, ondiscard }: { saved: SavedTab[]; onrestore: () => void; ondiscard: () => void } = $props();

  let never = $state(false);

  const hostsOf = (tab: SavedTab) => leaves(tab.layout as Layout<Target>).map((target) => titleOf(target) ?? '?');

  function finish(restore: boolean) {
    if (never) settings.restorePrompt = false;
    if (restore) onrestore();
    else ondiscard();
  }
</script>

<div class="ov" role="presentation">
  <div class="dlg" role="dialog" aria-modal="true" aria-label={t('restore.title')}>
    <h2>{t('restore.title')}</h2>
    <div class="dlg-b">
      <p>{t('restore.text')}</p>
      <div class="rlist">
        {#each saved as tab, i (i)}
          {@const hosts = hostsOf(tab)}
          <div class="ritem">
            <LayoutPreview layout={tab.layout} small />
            <div class="rt">
              <b>{tab.name ?? (hosts.length > 1 ? `${hosts[0]} +${hosts.length - 1}` : hosts[0])}</b>
              <span>{hosts.join(' · ')}</span>
            </div>
          </div>
        {/each}
      </div>
      <p class="fld-h">{t('restore.hint')}</p>
      <label class="check"><input type="checkbox" bind:checked={never} />{t('restore.never')}</label>
      {#if never}<p class="fld-h">{t('restore.never.hint')}</p>{/if}
    </div>
    <div class="dlg-a">
      <Button onclick={() => finish(false)}>{t('restore.discard')}</Button>
      <Button variant="primary" icon="undo" onclick={() => finish(true)}>{t('restore.confirm')}</Button>
    </div>
  </div>
</div>
