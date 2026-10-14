<script lang="ts">
  import { vault } from '../data.svelte';
  import { t } from '../i18n.svelte';
  import { scope, vaultColor, vaultLabel } from '../sync.svelte';
  import Icon from './Icon.svelte';

  // The vault shown no longer exists (left, removed): back to all.
  $effect(() => {
    if (scope.vault !== 'all' && !vault.vaults.some((v) => v.id === scope.vault)) scope.vault = 'all';
  });
</script>

<!-- Without shared vaults there is nothing to switch. -->
{#if vault.vaults.length > 1}
  <div class="seg vsw" role="radiogroup" aria-label={t('vault.switch')}>
    <button type="button" role="radio" aria-checked={scope.vault === 'all'} class:on={scope.vault === 'all'} onclick={() => (scope.vault = 'all')}>{t('vault.all')}</button>
    {#each vault.vaults as v (v.id)}
      <button type="button" role="radio" aria-checked={scope.vault === v.id} class:on={scope.vault === v.id} style="--vc:{vaultColor(v)}" onclick={() => (scope.vault = v.id)}>
        <i class="vdot"></i>{vaultLabel(v)}{#if v.role === 'read'}<Icon name="eye" size={12} />{/if}
      </button>
    {/each}
  </div>
{/if}
