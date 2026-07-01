<script lang="ts">
  interface Props {
    open: boolean;
    title: string;
    subtitle?: string;
    kicker?: string;
    size?: 'sm' | 'md' | 'lg';
    sheetMobile?: boolean;
    closeOnBackdrop?: boolean;
    onclose?: () => void;
    children?: import('svelte').Snippet;
    footer?: import('svelte').Snippet;
    headerExtra?: import('svelte').Snippet;
  }

  let {
    open,
    title,
    subtitle = '',
    kicker = '',
    size = 'md',
    sheetMobile = true,
    closeOnBackdrop = true,
    onclose,
    children,
    footer,
    headerExtra
  }: Props = $props();

  function handleBackdropClick(event: MouseEvent) {
    if (!closeOnBackdrop) return;
    if (event.target === event.currentTarget) onclose?.();
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') onclose?.();
  }

  let lastBodyOverflow = '';
  $effect(() => {
    if (typeof document === 'undefined') return;
    if (open) {
      lastBodyOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = lastBodyOverflow;
    }
    return () => {
      document.body.style.overflow = lastBodyOverflow;
    };
  });
</script>

<svelte:window onkeydown={open ? handleKeydown : undefined} />

{#if open}
  <div
    class="modal-backdrop"
    class:modal-sheet-backdrop={sheetMobile}
    role="presentation"
    onclick={handleBackdropClick}
  >
    <div
      class={`modal-card modal-${size}`}
      class:modal-card-sheet={sheetMobile}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      tabindex="-1"
    >
      {#if sheetMobile}
        <div class="modal-grabber" aria-hidden="true"></div>
      {/if}
      <header class="modal-header">
        <div class="modal-title-group">
          {#if kicker}<span class="modal-kicker">{kicker}</span>{/if}
          <h2 id="modal-title">{title}</h2>
          {#if subtitle}<p class="modal-subtitle">{subtitle}</p>{/if}
        </div>
        <div class="modal-header-right">
          {#if headerExtra}{@render headerExtra()}{/if}
          <button class="modal-close" type="button" onclick={() => onclose?.()} aria-label="关闭"></button>
        </div>
      </header>

      <div class="modal-body">
        {#if children}{@render children()}{/if}
      </div>

      {#if footer}
        <footer class="modal-footer">
          {@render footer()}
        </footer>
      {/if}
    </div>
  </div>
{/if}
