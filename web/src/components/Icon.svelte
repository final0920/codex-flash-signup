<script lang="ts">
  interface Props {
    name: IconName;
    size?: number;
    strokeWidth?: number;
    class?: string;
  }

  export type IconName =
    | 'dashboard' | 'globe' | 'mail' | 'user' | 'sparkles'
    | 'plus' | 'minus' | 'close' | 'check' | 'check-circle' | 'alert-circle' | 'info'
    | 'search' | 'filter' | 'refresh' | 'more' | 'menu' | 'arrow-right' | 'arrow-left'
    | 'download' | 'upload' | 'copy' | 'trash' | 'edit' | 'eye' | 'eye-off'
    | 'link' | 'external' | 'play' | 'pause' | 'stop' | 'lock' | 'unlock'
    | 'chevron-down' | 'chevron-right' | 'chevron-left'
    | 'sort' | 'shield' | 'wifi' | 'wifi-off' | 'flag' | 'box' | 'database'
    | 'inbox' | 'tag' | 'clock' | 'zap' | 'list' | 'grid' | 'send'
    | 'cpu' | 'hard-drive' | 'activity' | 'logout' | 'settings'
    | 'sun' | 'moon';

  let { name, size = 16, strokeWidth = 1.6, class: className = '' }: Props = $props();

  const paths: Record<IconName, string> = {
    'dashboard': 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    'globe': 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20M12 2a15 15 0 010 20M12 2a15 15 0 000 20',
    'mail': 'M3 5h18v14H3zM3 7l9 6 9-6',
    'user': 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0',
    'sparkles': 'M12 3l1.5 4.5L18 9l-4.5 1.5L12 15l-1.5-4.5L6 9l4.5-1.5zM18 14l1 3 3 1-3 1-1 3-1-3-3-1 3-1zM5 4l.7 2 2 .7-2 .7L5 9.4l-.7-2-2-.7 2-.7z',
    'plus': 'M12 5v14M5 12h14',
    'minus': 'M5 12h14',
    'close': 'M6 6l12 12M18 6L6 18',
    'check': 'M5 12l5 5L20 7',
    'check-circle': 'M22 11.08V12a10 10 0 11-5.93-9.14M22 4L12 14.01l-3-3',
    'alert-circle': 'M12 22a10 10 0 100-20 10 10 0 000 20zM12 8v4M12 16h.01',
    'info': 'M12 22a10 10 0 100-20 10 10 0 000 20zM12 16v-4M12 8h.01',
    'search': 'M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.35-4.35',
    'filter': 'M22 3H2l8 9.46V19l4 2v-8.54z',
    'refresh': 'M3 12a9 9 0 0115.5-6.36L21 8M3 16h5v5M21 12a9 9 0 01-15.5 6.36L3 16M3 3v5h5',
    'more': 'M12 13a1 1 0 100-2 1 1 0 000 2zM19 13a1 1 0 100-2 1 1 0 000 2zM5 13a1 1 0 100-2 1 1 0 000 2z',
    'menu': 'M3 6h18M3 12h18M3 18h18',
    'arrow-right': 'M5 12h14M13 5l7 7-7 7',
    'arrow-left': 'M19 12H5M11 5l-7 7 7 7',
    'download': 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3',
    'upload': 'M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12',
    'copy': 'M9 4h11v14M5 8h11v14H5z',
    'trash': 'M3 6h18M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6M10 11v6M14 11v6M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2',
    'edit': 'M11 4H4v16h16v-7M18.5 2.5a2.12 2.12 0 013 3L12 15l-4 1 1-4z',
    'eye': 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 100-6 3 3 0 000 6z',
    'eye-off': 'M17.94 17.94A10.94 10.94 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A10.94 10.94 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19M14.12 14.12a3 3 0 11-4.24-4.24M1 1l22 22',
    'link': 'M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71',
    'external': 'M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3',
    'play': 'M5 3l14 9-14 9z',
    'pause': 'M6 4h4v16H6zM14 4h4v16h-4z',
    'stop': 'M6 6h12v12H6z',
    'lock': 'M5 11h14v10H5zM7 11V7a5 5 0 0110 0v4',
    'unlock': 'M5 11h14v10H5zM7 11V7a5 5 0 019.9-1',
    'chevron-down': 'M6 9l6 6 6-6',
    'chevron-right': 'M9 18l6-6-6-6',
    'chevron-left': 'M15 18l-6-6 6-6',
    'sort': 'M3 6h18M6 12h12M10 18h4',
    'shield': 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    'wifi': 'M5 12.55a11 11 0 0114 0M1.42 9a16 16 0 0121.16 0M8.53 16.11a6 6 0 016.95 0M12 20h.01',
    'wifi-off': 'M1 1l22 22M16.72 11.06A10.94 10.94 0 0119 12.55M5 12.55a11 11 0 015.17-2.39M10.71 5.05A16 16 0 0122.58 9M1.42 9a15.91 15.91 0 014.7-2.88M8.53 16.11a6 6 0 016.95 0M12 20h.01',
    'flag': 'M4 22V4l16 6-16 6',
    'box': 'M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16zM3.27 6.96L12 12.01l8.73-5.05M12 22.08V12',
    'database': 'M12 2c-4.97 0-9 1.79-9 4v12c0 2.21 4.03 4 9 4s9-1.79 9-4V6c0-2.21-4.03-4-9-4zM3 6c0 2.21 4.03 4 9 4s9-1.79 9-4M3 12c0 2.21 4.03 4 9 4s9-1.79 9-4',
    'inbox': 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z',
    'tag': 'M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82zM7 7h.01',
    'clock': 'M12 22a10 10 0 100-20 10 10 0 000 20zM12 6v6l4 2',
    'zap': 'M13 2L3 14h9l-1 8 10-12h-9l1-8z',
    'list': 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
    'grid': 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    'send': 'M22 2L11 13M22 2l-7 20-4-9-9-4z',
    'cpu': 'M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3',
    'hard-drive': 'M22 12H2M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11zM6 16h.01M10 16h.01',
    'activity': 'M22 12h-4l-3 9L9 3l-3 9H2',
    'logout': 'M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9',
    'settings': 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z',
    'sun': 'M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42',
    'moon': 'M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z'
  };
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  class={className}
  aria-hidden="true"
>
  <path d={paths[name]} />
</svg>
