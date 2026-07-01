<script lang="ts">
  interface Props {
    message: string;
    variant?: 'warning' | 'success' | 'error';
  }

  let { message, variant = 'warning' }: Props = $props();
</script>

{#if message}
  <div class="notice-bar" class:notice-success={variant === 'success'} class:notice-error={variant === 'error'}>
    <span class="notice-icon">
      {#if variant === 'success'}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 8.5l3 3 7-7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      {:else if variant === 'error'}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M8 5v3.5M8 10.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      {:else}
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2l6 11H2L8 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 7v2.5M8 11v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
      {/if}
    </span>
    <span class="notice-text">{message}</span>
  </div>
{/if}
