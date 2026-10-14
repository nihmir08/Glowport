<script lang="ts">
  import { onMount } from 'svelte';
  import { appInfo, vaultCreate, vaultRestore, vaultUnlock } from './backend';
  import { applyStatus, errorText, vault } from './data.svelte';
  import { t } from './i18n.svelte';
  import { toast } from './state.svelte';
  import SyncSetup from './sync/SyncSetup.svelte';
  import Button from './ui/Button.svelte';
  import Icon from './ui/Icon.svelte';
  import TextField from './ui/TextField.svelte';
  import WipeDialog from './WipeDialog.svelte';

  let password = $state('');
  let repeat = $state('');
  let acknowledged = $state(false);
  let busy = $state(false);
  let error = $state('');
  let dataDir = $state('');
  /** Statt einen Tresor anzulegen: mit einem bestehenden Konto anmelden; der Tresor entsteht daraus. */
  let joining = $state(false);
  /** Abmelden und den Tresor hier löschen, ohne ihn öffnen zu können. */
  let wiping = $state(false);

  onMount(() => void appInfo().then((info) => (dataDir = info?.dataDir ?? '')));

  const creating = $derived(vault.state === 'missing');
  const longEnough = $derived([...password].length >= 8);
  const matches = $derived(password !== '' && password === repeat);
  const ready = $derived(!busy && (creating ? longEnough && matches && acknowledged : password !== ''));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready) return;
    busy = true;
    error = '';
    try {
      applyStatus(await (creating ? vaultCreate(password) : vaultUnlock(password)));
    } catch (e) {
      error = errorText(e);
    } finally {
      // Das Passwort bleibt keinen Augenblick länger in der Oberfläche als nötig.
      password = '';
      repeat = '';
      busy = false;
    }
  }

  /** Wer von einem anderen PC kommt, bringt seinen Tresor als Sicherung mit, statt einen neuen anzulegen. */
  async function restore() {
    error = '';
    try {
      const status = await vaultRestore();
      if (!status) return;
      applyStatus(status);
      toast(t('lock.restore.done'), 'ok');
    } catch (e) {
      error = errorText(e);
    }
  }
</script>

<main class="lock">
  {#if vault.state === 'broken'}
    <div class="lock-card isl">
      <span class="ei"><Icon name="alert" size={26} /></span>
      <h1>{t('lock.broken.title')}</h1>
      <p class="errline">{vault.error ? errorText(vault.error) : ''}</p>
      <p>{t('lock.broken.text')}</p>
      {#if dataDir}<p class="mono selectable">{dataDir}</p>{/if}
      <button type="button" class="linkbtn" onclick={() => (wiping = true)}>{t('lock.wipe')}</button>
    </div>
  {:else if creating && joining}
    <div class="lock-card isl wide">
      <span class="ei"><Icon name="cloud" size={26} /></span>
      <h1>{t('lock.sync.title')}</h1>
      <p>{t('lock.sync.text')}</p>
      <SyncSetup fresh />
      <button type="button" class="linkbtn" onclick={() => (joining = false)}>{t('lock.sync.back')}</button>
    </div>
  {:else}
    <form class="lock-card isl" onsubmit={submit}>
      <span class="ei"><Icon name="lock" size={26} /></span>
      <h1>{creating ? t('lock.create.title') : t('lock.unlock.title')}</h1>
      {#if creating}<p>{t('lock.create.text')}</p>{/if}

      <TextField label={t('lock.password')} bind:value={password} password autofocus />
      {#if creating}
        <TextField label={t('lock.repeat')} bind:value={repeat} password />
        <div class="rule" class:ok={longEnough}><Icon name="check" size={14} />{t('lock.rule.length')}</div>
        <div class="rule" class:ok={matches}><Icon name="check" size={14} />{t('lock.rule.match')}</div>
        <div class="warnbox"><Icon name="alert" size={16} /><span>{t('lock.warn')}</span></div>
        <label class="check"><input type="checkbox" bind:checked={acknowledged} />{t('lock.ack')}</label>
      {/if}

      {#if error}<p class="errline" role="alert">{error}</p>{/if}
      <button type="submit" class="btn primary" style="justify-content:center;height:38px" disabled={!ready}>
        {#if busy}{creating ? t('lock.create.busy') : t('lock.unlock.busy')}{:else}{creating ? t('lock.create.button') : t('lock.unlock.button')}{/if}
      </button>
      {#if creating}
        <button type="button" class="linkbtn" disabled={busy} onclick={restore}>{t('lock.restore')}</button>
        <button type="button" class="linkbtn" disabled={busy} onclick={() => (joining = true)}>{t('lock.sync')}</button>
      {:else}
        <button type="button" class="linkbtn" disabled={busy} onclick={() => (wiping = true)}>{t('lock.wipe')}</button>
      {/if}
    </form>
  {/if}
</main>

<WipeDialog bind:open={wiping} />
