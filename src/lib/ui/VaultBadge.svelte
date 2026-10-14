<script lang="ts">
  import { vault, vaultOf } from '../data.svelte';
  import { vaultColor, vaultLabel } from '../sync.svelte';

  let { entry }: { entry: { vault?: string } } = $props();
  const home = $derived(vaultOf(entry));
</script>

<!-- Die Marke sagt, in welchem Tresor ein Eintrag liegt. Ohne geteilte Tresore wäre sie überall dieselbe. -->
{#if vault.vaults.length > 1}
  <i class="chip vault" style="--vc:{vaultColor(home)}"><i class="vdot"></i>{vaultLabel(home)}</i>
{/if}
