<script lang="ts">
  interface Props {
    width?: string;
    height?: string;
    rounded?: 'sm' | 'md' | 'lg' | 'full';
    inline?: boolean;
    style?: string;
  }

  let { width = '100%', height = '12px', rounded = 'sm', inline = false, style = '' }: Props = $props();

  const radii: Record<string, string> = {
    sm: 'var(--radius-sm)',
    md: 'var(--radius-md)',
    lg: 'var(--radius-lg)',
    full: 'var(--radius-full)'
  };
</script>

<span
  class="skeleton"
  style="width: {width}; height: {height}; border-radius: {radii[rounded]}; display: {inline ? 'inline-block' : 'block'}; {style}"
  aria-hidden="true"
></span>
