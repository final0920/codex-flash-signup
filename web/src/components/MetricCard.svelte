<script lang="ts">
  interface Props {
    label: string;
    value: string | number;
    variant?: 'default' | 'success' | 'warning' | 'danger';
  }

  let { label, value, variant = 'default' }: Props = $props();
</script>

<div class="metric-card">
  <span class="metric-card-label">{label}</span>
  <strong class="metric-card-value" class:success={variant === 'success'} class:warning={variant === 'warning'} class:danger={variant === 'danger'}>
    {value}
  </strong>
</div>
