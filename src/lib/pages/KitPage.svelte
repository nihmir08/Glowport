<script lang="ts">
  import { t } from '../i18n.svelte';
  import { toast, ui } from '../state.svelte';
  import Button from '../ui/Button.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Icon from '../ui/Icon.svelte';
  import Segmented from '../ui/Segmented.svelte';
  import Switch from '../ui/Switch.svelte';
  import TextField from '../ui/TextField.svelte';

  let dialog = $state(false);
  let on = $state(true);
  let off = $state(false);
  let choice = $state<'a' | 'b' | 'c'>('a');
  let name = $state('web-01');
  let addr = $state('');
</script>

<section class="pg isl">
  <div class="crumbs">
    <button onclick={() => (ui.page = 'settings')}>{t('set.title')}</button><Icon name="chev" size={12} /><span>{t('kit.title')}</span>
  </div>
  <div class="ph">
    <div>
      <h1>{t('kit.title')}</h1>
      <div class="sub">{t('kit.sub')}</div>
    </div>
  </div>

  <div class="sec">{t('kit.buttons')}</div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <Button variant="primary" icon="plus">{t('kit.primary')}</Button>
    <Button icon="down">{t('kit.default')}</Button>
    <Button variant="ghost">{t('kit.ghost')}</Button>
    <Button variant="danger">{t('kit.danger')}</Button>
    <Button disabled>{t('kit.disabled')}</Button>
    <Button active icon="link">{t('kit.active')}</Button>
    <Button size="sm" icon="play">{t('kit.small')}</Button>
    <Button icon="edit" title="Bearbeiten" />
    <Button size="sm" icon="x" title={t('common.close')} />
  </div>

  <div class="sec">{t('kit.controls')}</div>
  <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center">
    <Switch label="an" bind:checked={on} />
    <Switch label="aus" bind:checked={off} />
    <Segmented
      label="Auswahl"
      bind:value={choice}
      options={[
        { value: 'a', label: 'Hinweis' },
        { value: 'b', label: 'Automatisch' },
        { value: 'c', label: 'Nie' },
      ]}
    />
    <select class="dropdown" aria-label="Auswahl">
      <option>Deutsch</option>
      <option>English</option>
    </select>
  </div>

  <div class="sec">{t('kit.fields')}</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;max-width:720px">
    <TextField label={t('kit.field.name')} bind:value={name} />
    <TextField label={t('kit.field.addr')} bind:value={addr} placeholder="203.0.113.10" hint={t('kit.field.addr.hint')} mono />
    <TextField label="Passwort" value="geheim123" password />
  </div>

  <div class="sec">{t('kit.chips')}</div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <i class="chip">SSH</i><i class="chip">{t('hosts.via', { host: 'bastion' })}</i><i class="chip a">VM 101</i>
    <span class="inh">{t('kit.chip.inherited')}</span><kbd>{t('search.kbd')}</kbd>
  </div>

  <div class="sec">{t('kit.feedback')}</div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <Button onclick={() => (dialog = true)}>{t('kit.dialog.open')}</Button>
    <Button onclick={() => toast(t('kit.toast.info.text'))}>{t('kit.toast.info')}</Button>
    <Button onclick={() => toast(t('kit.toast.ok.text'), 'ok')}>{t('kit.toast.ok')}</Button>
    <Button onclick={() => toast(t('kit.toast.err.text'), 'err')}>{t('kit.toast.err')}</Button>
  </div>
</section>

<Dialog bind:open={dialog} title={t('kit.dialog.title')}>
  <p>{t('kit.dialog.text')}</p>
  <p class="mono selectable">SHA256:9bTfK2…Lr2Q · ssh-ed25519</p>
  {#snippet actions()}
    <Button onclick={() => (dialog = false)}>{t('common.cancel')}</Button>
    <Button variant="primary" onclick={() => (dialog = false)}>{t('kit.dialog.trust')}</Button>
  {/snippet}
</Dialog>
