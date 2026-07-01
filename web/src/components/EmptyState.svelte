<script lang="ts">
  import Icon, { type IconName } from './Icon.svelte';

  interface Props {
    title?: string;
    message?: string;
    icon?: IconName | false;
    action?: import('svelte').Snippet;
  }

  let { title = '', message = '暂无数据', icon = 'inbox', action }: Props = $props();
</script>

<div class="empty-state-box">
  {#if icon !== false}
    <div class="empty-state-icon">
      <Icon name={icon} size={24} strokeWidth={1.5} />
    </div>
  {/if}
  {#if title}
    <p class="empty-state-text" style="font-size: 15px; color: var(--nx-ink); font-weight: 600;">{title}</p>
  {/if}
  <p class="empty-state-text">{message}</p>
  {#if action}
    <div style="margin-top: 6px;">{@render action()}</div>
  {/if}
</div>
