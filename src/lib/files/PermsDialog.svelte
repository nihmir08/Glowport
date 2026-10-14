<script lang="ts">
  import { fsChmod } from '../backend';
  import { errorText } from '../data.svelte';
  import { fileUi, modeText, octal } from '../files.svelte';
  import { t, type Key } from '../i18n.svelte';
  import { toast } from '../state.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import TextField from '../ui/TextField.svelte';

  /** Rechte und Besitzer eines oder mehrerer Einträge ändern, auf Wunsch samt allem darunter. */
  const request = fileUi.perms!;
  const { browser, entries } = request;
  const first = entries[0];
  const hasDir = entries.some((e) => e.kind === 'dir');

  let mode = $state((first.mode ?? 0o644) & 0o777);
  let digits = $state(octal(first.mode ?? 0o644));
  let owner = $state(entries.every((e) => e.owner === first.owner) ? first.owner : '');
  let group = $state(entries.every((e) => e.group === first.group) ? first.group : '');
  let recursive = $state(false);
  let busy = $state(false);

  const WHO: Key[] = ['perms.owner', 'perms.group', 'perms.others'];
  const WHAT: Key[] = ['perms.read', 'perms.write', 'perms.exec'];
  const bit = (who: number, what: number) => 0o400 >> (who * 3 + what);

  function toggle(who: number, what: number) {
    mode ^= bit(who, what);
    digits = octal(mode);
  }
  function typed(value: string) {
    digits = value.replace(/[^0-7]/g, '').slice(0, 3);
    if (digits.length === 3) mode = parseInt(digits, 8);
  }

  const changed = $derived(entries.some((e) => (e.mode ?? 0) !== mode || (owner && e.owner !== owner) || (group && e.group !== group)) || recursive);
  const close = () => (fileUi.perms = null);

  async function apply() {
    busy = true;
    try {
      await fsChmod(browser.place!, { paths: entries.map((e) => e.path), mode, owner: owner.trim() || null, group: group.trim() || null, recursive });
      toast(t('common.saved'), 'ok');
      close();
      void browser.refresh();
    } catch (e) {
      toast(errorText(e), 'err');
    } finally {
      busy = false;
    }
  }
</script>

<Dialog bind:open={() => true, (v) => void (!v && close())} title={t('perms.title')}>
  <p class="perm-what">{entries.length === 1 ? first.name : t('files.selected', { n: entries.length })}</p>
  <div class="perm-grid" role="group" aria-label={t('perms.title')}>
    <span></span>
    {#each WHAT as what (what)}<span class="ph-c">{t(what)}</span>{/each}
    {#each WHO as who, i (who)}
      <span class="ph-r">{t(who)}</span>
      {#each WHAT as what, j (what)}
        <label class="perm-box"><input type="checkbox" checked={(mode & bit(i, j)) !== 0} aria-label="{t(who)}: {t(what)}" onchange={() => toggle(i, j)} /></label>
      {/each}
    {/each}
  </div>
  <div class="perm-num">
    <label class="fld">
      <span class="fld-l">{t('perms.octal')}</span>
      <input class="mono" type="text" inputmode="numeric" maxlength="3" value={digits} spellcheck="false" oninput={(e) => typed(e.currentTarget.value)} />
    </label>
    <code class="mono">{modeText({ mode, kind: first.kind })}</code>
  </div>
  <div class="ed-row" style="grid-template-columns:1fr 1fr">
    <TextField label={t('perms.owner.name')} bind:value={owner} placeholder={t('perms.unchanged')} mono />
    <TextField label={t('perms.group.name')} bind:value={group} placeholder={t('perms.unchanged')} mono />
  </div>
  {#if hasDir}
    <label class="check"><input type="checkbox" bind:checked={recursive} />{t('perms.recursive')}</label>
  {/if}
  {#snippet actions()}
    <Button onclick={close}>{t('common.cancel')}</Button>
    <Button variant="primary" icon="check" disabled={busy || !changed || digits.length !== 3} onclick={apply}>{t('perms.apply')}</Button>
  {/snippet}
</Dialog>
