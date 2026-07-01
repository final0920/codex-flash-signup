<script lang="ts">
  interface Props {
    title: string;
    subtitle?: string;
    description?: string;
    children?: import('svelte').Snippet;
  }

  let { title, subtitle = '', description = '', children }: Props = $props();
</script>

<header class="page-header">
  <div class="page-header-text">
    {#if subtitle}
      <span class="page-header-sub">{subtitle}</span>
    {/if}
    <h1>{title}</h1>
    {#if description}
      <p class="page-header-desc">{description}</p>
    {/if}
  </div>
  {#if children}
    <div class="page-header-actions">
      {@render children()}
    </div>
  {/if}
</header>
