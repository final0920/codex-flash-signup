<script lang="ts">
  import { toasts, dismissToast, type Toast } from '../lib/toast';
</script>

<div class="toast-region" aria-live="polite" aria-atomic="false">
  {#each $toasts as item (item.id)}
    <div
      class={`toast toast-${item.variant}`}
      role={item.variant === 'error' ? 'alert' : 'status'}
    >
      <span class="toast-icon" aria-hidden="true">
        {#if item.variant === 'success'}
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M3 8.5l3 3 7-7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        {:else if item.variant === 'error'}
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.6"/><path d="M8 5v3.5M8 10.5v.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
        {:else}
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.6"/><path d="M8 7v4M8 5v.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>
        {/if}
      </span>
      <span class="toast-text">{item.message}</span>
      <button class="toast-close" type="button" aria-label="关闭" onclick={() => dismissToast(item.id)}>×</button>
    </div>
  {/each}
</div>
