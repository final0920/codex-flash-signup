<script lang="ts">
  interface Props {
    label: string;
    variant?: 'default' | 'active' | 'expired' | 'temp' | 'failed' | 'uploaded' | 'not-uploaded';
  }

  let { label, variant = 'default' }: Props = $props();
</script>

<span
  class="badge"
  class:badge-active={variant === 'active' || variant === 'uploaded'}
  class:badge-expired={variant === 'expired'}
  class:badge-temp={variant === 'temp'}
  class:badge-failed={variant === 'failed'}
  class:badge-muted={variant === 'not-uploaded' || variant === 'default'}
>
  {label}
</span>
