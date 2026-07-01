<script lang="ts">
  interface Props {
    title?: string;
    subtitle?: string;
    compact?: boolean;
    flat?: boolean;
    children?: import('svelte').Snippet;
    actions?: import('svelte').Snippet;
    badge?: import('svelte').Snippet;
  }

  let { title = '', subtitle = '', compact = false, flat = false, children, actions, badge }: Props = $props();
</script>

<div class="card" class:card-flat={flat}>
  {#if title || actions || badge}
    <div class="card-header" class:card-header-compact={compact}>
      <div class="card-header-text">
        {#if subtitle}
          <span class="card-subtitle">{subtitle}</span>
        {/if}
        {#if title}
          <h2 class="card-title">{title}</h2>
        {/if}
      </div>
      <div class="card-header-right">
        {#if badge}
          {@render badge()}
        {/if}
        {#if actions}
          {@render actions()}
        {/if}
      </div>
    </div>
  {/if}
  {#if children}
    {@render children()}
  {/if}
</div>
