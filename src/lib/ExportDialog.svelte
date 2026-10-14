<script lang="ts">
  import { exportData } from './backend';
  import { errorText, pathLabel, vault } from './data.svelte';
  import { t, type Key } from './i18n.svelte';
  import { toast } from './state.svelte';
  import type { ExportFormat } from './types';
  import Button from './ui/Button.svelte';
  import Dialog from './ui/Dialog.svelte';
  import Icon from './ui/Icon.svelte';

  let { onclose }: { onclose: () => void } = $props();

  const FORMATS: ExportFormat[] = ['glowport', 'sshconfig', 'csv'];
  const FILES: Record<ExportFormat, string> = { glowport: 'glowport-export-{date}.json', sshconfig: 'config', csv: 'glowport-hosts-{date}.csv' };

  let format = $state<ExportFormat>('glowport');
  let group = $state('');
  let snippets = $state(true);
  let forwards = $state(true);
  let knownHosts = $state(true);
  let busy = $state(false);

  const groups = $derived([...vault.groups].sort((a, b) => pathLabel(a.id).localeCompare(pathLabel(b.id))));

  async function run() {
    busy = true;
    try {
      const full = format === 'glowport';
      const path = await exportData(
        { format, group: group || null, snippets: full && snippets, forwards: (full || format === 'sshconfig') && forwards, knownHosts: full && knownHosts },
        FILES[format].replace('{date}', new Date().toISOString().slice(0, 10)),
      );
      if (path) {
        toast(t('exp.done', { path }), 'ok');
        onclose();
      }
    } catch (e) {
      toast(errorText(e), 'err');
    }
    busy = false;
  }
</script>

<Dialog bind:open={() => true, (open) => !open && onclose()} title={t('exp.title')} wide>
  <div class="exp-fmt" role="radiogroup" aria-label={t('exp.format')}>
    {#each FORMATS as f (f)}
      <label>
        <input type="radio" name="export-format" value={f} bind:group={format} />
        <b>{t(`exp.fmt.${f}` as Key)}</b>
        <span>{t(`exp.fmt.${f}.sub` as Key)}</span>
      </label>
    {/each}
  </div>
  <label class="imp-opt">
    <span>{t('exp.scope')}</span>
    <select class="dropdown" bind:value={group}>
      <option value="">{t('exp.scope.all', { n: vault.hosts.length })}</option>
      {#each groups as g (g.id)}<option value={g.id}>{pathLabel(g.id)}</option>{/each}
    </select>
  </label>
  {#if format !== 'csv'}
    <div class="exp-what">
      <label class="check"><input type="checkbox" bind:checked={forwards} />{t(format === 'sshconfig' ? 'exp.forwards.config' : 'exp.forwards', { n: vault.forwards.length })}</label>
      {#if format === 'glowport'}
        <label class="check"><input type="checkbox" bind:checked={snippets} />{t('exp.snippets', { n: vault.snippets.length })}</label>
        <label class="check"><input type="checkbox" bind:checked={knownHosts} />{t('exp.known', { n: vault.knownHosts.length })}</label>
      {/if}
    </div>
  {/if}
  <div class="warnbox"><Icon name="lock" size={16} /><span>{t('exp.secrets')}</span></div>
  {#snippet actions()}
    <Button onclick={onclose}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="upload" disabled={busy} onclick={run}>{t('exp.run')}</Button>
  {/snippet}
</Dialog>
