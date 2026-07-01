<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { toast } from '../lib/toast';

  type Variant = 'default' | 'success' | 'warning' | 'danger';

  type DiskStatus = {
    name: string; path: string; total_bytes: number; used_bytes: number;
    free_bytes: number; usage_pct: number;
  };

  type SystemStatus = {
    status: string; uptime_ms: number; connections: number; server: string; sampled_at_ms: number;
    cpu: { cores: number; usage_pct: number; load1: number; load5: number; load15: number; };
    memory: {
      total_bytes: number; used_bytes: number; free_bytes: number;
      shared_bytes: number; buff_cache_bytes: number; available_bytes: number;
      usage_pct: number; swap_total_bytes: number; swap_used_bytes: number;
      swap_free_bytes: number; swap_usage_pct: number;
    };
    storage: { root: DiskStatus; data: DiskStatus; };
    network: { rx_bytes: number; tx_bytes: number; rx_rate_Bps: number; tx_rate_Bps: number; };
    sqlite: {
      path: string; size_bytes: number; wal_size_bytes: number; shm_size_bytes: number;
      page_size: number; page_count: number; freelist_count: number;
      estimated_size_bytes: number; freelist_pct: number; journal_mode: string;
      synchronous: number; wal_autocheckpoint: number; cache_size: number;
      foreign_keys: number; schema_version: number; user_version: number;
      tables_count: number; indexes_count: number; triggers_count: number;
      accounts_total: number; accounts_active: number; accounts_expired: number;
      accounts_temp: number; accounts_failed: number; accounts_uploaded: number;
      accounts_not_uploaded: number; stats_updated_at: number;
    };
  };

  let status: SystemStatus | null = $state(null);
  let loading = $state(false);
  let wsState = $state<'connecting' | 'open' | 'closed' | 'error'>('closed');
  let refreshIntervalMs = $state(3000);
  let lastReceivedAt: Date | null = $state(null);
  let socket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let reconnectDelayMs = 1000;
  let shouldReconnect = true;

  function formatUptime(ms: number | undefined) {
    if (ms === undefined) return '—';
    const total = Math.floor(ms / 1000);
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    if (days > 0) return `${days}天 ${hours}时`;
    if (hours > 0) return `${hours}时 ${minutes}分`;
    if (minutes > 0) return `${minutes}分 ${seconds}秒`;
    return `${seconds}秒`;
  }

  function formatBytes(value: number | undefined | null) {
    if (value === undefined || value === null) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = value;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit += 1;
    }
    if (unit === 0) return `${Math.round(size)} ${units[unit]}`;
    return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function formatRate(value: number | undefined | null) {
    if (value === undefined || value === null) return '—';
    return `${formatBytes(value)}/s`;
  }

  function formatPercent(value: number | undefined | null) {
    if (value === undefined || value === null) return '—';
    return `${value.toFixed(1)}%`;
  }

  function formatTime(value: Date | null) {
    return value ? value.toLocaleTimeString() : '—';
  }

  function formatUnixTime(seconds: number | undefined | null) {
    if (!seconds) return '—';
    return new Date(seconds * 1000).toLocaleString();
  }

  function displayWsState(value: string) {
    const states: Record<string, string> = { connecting: '连接中', open: '已连接', closed: '重连中', error: '异常' };
    return states[value] ?? value;
  }

  function sqliteSynchronousLabel(value: number | undefined | null) {
    const labels: Record<number, string> = { 0: 'OFF', 1: 'NORMAL', 2: 'FULL', 3: 'EXTRA' };
    if (value === undefined || value === null) return '—';
    return labels[value] ?? String(value);
  }

  function sqliteCacheSizeLabel(value: number | undefined | null) {
    if (value === undefined || value === null) return '—';
    if (value < 0) return `${Math.abs(value)} KiB`;
    return `${value} 页`;
  }

  function enabledLabel(value: number | undefined | null) {
    if (value === undefined || value === null) return '—';
    return value ? '开启' : '关闭';
  }

  function usageVariant(value: number | undefined | null): Variant {
    if (value === undefined || value === null) return 'default';
    if (value >= 90) return 'danger';
    if (value >= 75) return 'warning';
    return 'success';
  }

  function wsChipClass() {
    if (wsState === 'open') return 'stat-chip stat-chip-success';
    if (wsState === 'connecting' || wsState === 'closed') return 'stat-chip stat-chip-warning';
    return 'stat-chip stat-chip-danger';
  }

  function wsIcon() {
    if (wsState === 'open') return 'wifi';
    if (wsState === 'error') return 'wifi-off';
    return 'wifi';
  }

  function barWidth(value: number | undefined | null) {
    if (value === undefined || value === null || Number.isNaN(value)) return 0;
    return Math.min(100, Math.max(0, value));
  }

  function applyStatus(next: SystemStatus) {
    status = next;
    lastReceivedAt = new Date();
    loading = false;
  }

  async function refreshStatus() {
    loading = true;
    try {
      const response = await fetch('/api/status');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      applyStatus(await response.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      loading = false;
    }
  }

  function subscribeSystemStatus() {
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type: 'system_subscribe', interval_ms: refreshIntervalMs }));
  }

  function scheduleReconnect() {
    if (!shouldReconnect || reconnectTimer !== null) return;
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      connectWebSocket();
    }, reconnectDelayMs);
    reconnectDelayMs = Math.min(reconnectDelayMs * 2, 10000);
  }

  function connectWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${location.host}/ws`);
    wsState = 'connecting';

    socket.onopen = () => {
      wsState = 'open';
      reconnectDelayMs = 1000;
      subscribeSystemStatus();
    };

    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'system_status' && message.payload) {
          applyStatus(message.payload);
        }
      } catch (err) {
        console.warn('system ws parse failed', err);
      }
    };

    socket.onerror = () => { wsState = 'error'; };

    socket.onclose = () => {
      wsState = 'closed';
      socket = null;
      scheduleReconnect();
    };
  }

  function handleIntervalChange() {
    subscribeSystemStatus();
  }

  onMount(() => {
    shouldReconnect = true;
    refreshStatus();
    connectWebSocket();
    return () => {
      shouldReconnect = false;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (socket) socket.close();
    };
  });
</script>

<div class="c-root">

  <!-- ── HEADER ── -->
  <header class="c-header c-anim-up" style="--d:0ms">
    <div class="c-header-main">
      <div class="c-live-pill" class:c-live-pill--on={wsState === 'open'}>
        <span class="c-live-dot"></span>
        实时
      </div>
      <div class="c-header-text">
        <h1 class="c-title">运行仪表盘</h1>
        <p class="c-desc">实时监控系统资源、网络吞吐与 SQLite 状态</p>
      </div>
    </div>
    <div class="c-header-actions">
      <select class="input input-sm refresh-select" aria-label="刷新间隔" bind:value={refreshIntervalMs} onchange={handleIntervalChange}>
        <option value={1000}>每 1 秒</option>
        <option value={3000}>每 3 秒</option>
        <option value={10000}>每 10 秒</option>
        <option value={30000}>每 30 秒</option>
      </select>
      <button class="btn btn-primary" type="button" onclick={refreshStatus} disabled={loading} data-loading={loading}>
        <Icon name="refresh" size={14} />
        {loading ? '刷新中…' : '立即刷新'}
      </button>
    </div>
  </header>

  <!-- ── HERO STATS ── -->
  <div class="c-hero-grid c-anim-up" style="--d:60ms">
    {#if !status}
      {#each Array(4) as _, i (i)}
        <div class="c-hcard-skel">
          <Skeleton width="42px" height="42px" rounded="md" />
          <div style="flex:1; display:grid; gap:6px;">
            <Skeleton height="20px" width="60%" />
            <Skeleton height="11px" width="40%" />
          </div>
        </div>
      {/each}
    {:else}
      <div class="c-hcard" class:c-hcard--ok={status.status === 'ok'}>
        <div class="c-hcard-icon"><Icon name="activity" size={18} /></div>
        <div class="c-hcard-body">
          <div class="c-hcard-val">{status.status === 'ok' ? '正常运行' : '服务异常'}</div>
          <div class="c-hcard-label">服务状态</div>
          <div class="c-hcard-meta">{status.server}</div>
        </div>
      </div>

      <div class="c-hcard">
        <div class="c-hcard-icon"><Icon name="clock" size={18} /></div>
        <div class="c-hcard-body">
          <div class="c-hcard-val">{formatUptime(status.uptime_ms)}</div>
          <div class="c-hcard-label">运行时长</div>
          <div class="c-hcard-meta">持续运行中</div>
        </div>
      </div>

      <div class="c-hcard">
        <div class="c-hcard-icon"><Icon name="link" size={18} /></div>
        <div class="c-hcard-body">
          <div class="c-hcard-val">{status.connections}</div>
          <div class="c-hcard-label">活跃连接</div>
          <div class="c-hcard-meta">HTTP 会话</div>
        </div>
      </div>

      <div class="c-hcard"
        class:c-hcard--ok={wsState === 'open'}
        class:c-hcard--warn={wsState === 'connecting' || wsState === 'closed'}
        class:c-hcard--err={wsState === 'error'}
      >
        <div class="c-hcard-icon"><Icon name={wsIcon()} size={18} /></div>
        <div class="c-hcard-body">
          <div class="c-hcard-val">{displayWsState(wsState)}</div>
          <div class="c-hcard-label">监控通道</div>
          <div class="c-hcard-meta">更新 {formatTime(lastReceivedAt)}</div>
        </div>
      </div>
    {/if}
  </div>

  <!-- ── RESOURCE GRID ── -->
  <div class="c-res-grid c-anim-up" style="--d:120ms">

    <!-- CPU -->
    <div class="c-res-card">
      <div class="c-res-head">
        <span class="c-res-title"><Icon name="cpu" size={12} /> CPU</span>
        {#if status}
          <span class="c-res-badge"
            class:warn={usageVariant(status.cpu.usage_pct) === 'warning'}
            class:danger={usageVariant(status.cpu.usage_pct) === 'danger'}
          >{formatPercent(status.cpu.usage_pct)}</span>
        {/if}
      </div>
      {#if !status}
        <div class="c-ring-skel"><Skeleton width="88px" height="88px" rounded="full" style="margin:0 auto 14px;" /></div>
        <Skeleton height="11px" style="margin-bottom:6px;" />
        <Skeleton height="11px" width="70%" />
      {:else}
        {@const cpuPct = barWidth(status.cpu.usage_pct)}
        {@const cpuV = usageVariant(status.cpu.usage_pct)}
        <div class="c-ring-wrap">
          <svg class="c-ring" viewBox="0 0 36 36" aria-hidden="true">
            <circle class="c-ring-track" cx="18" cy="18" r="15.9155" />
            <circle class="c-ring-fill"
              class:c-ring-warn={cpuV === 'warning'}
              class:c-ring-danger={cpuV === 'danger'}
              cx="18" cy="18" r="15.9155"
              style="stroke-dasharray: {cpuPct} 100;"
            />
          </svg>
          <div class="c-ring-center">
            <span class="c-ring-num">{Math.round(status.cpu.usage_pct)}%</span>
            <span class="c-ring-sub">占用</span>
          </div>
        </div>
        <div class="c-kv-mini">
          <div class="c-kv-mini-item"><span>核心</span><b>{status.cpu.cores}</b></div>
          <div class="c-kv-mini-item"><span>1m</span><b>{status.cpu.load1.toFixed(2)}</b></div>
          <div class="c-kv-mini-item"><span>5m</span><b>{status.cpu.load5.toFixed(2)}</b></div>
          <div class="c-kv-mini-item"><span>15m</span><b>{status.cpu.load15.toFixed(2)}</b></div>
        </div>
      {/if}
    </div>

    <!-- Memory -->
    <div class="c-res-card">
      <div class="c-res-head">
        <span class="c-res-title"><Icon name="hard-drive" size={12} /> 内存</span>
        {#if status}
          <span class="c-res-badge"
            class:warn={usageVariant(status.memory.usage_pct) === 'warning'}
            class:danger={usageVariant(status.memory.usage_pct) === 'danger'}
          >{formatPercent(status.memory.usage_pct)}</span>
        {/if}
      </div>
      {#if !status}
        <div class="c-ring-skel"><Skeleton width="88px" height="88px" rounded="full" style="margin:0 auto 14px;" /></div>
        <Skeleton height="6px" rounded="full" style="margin-bottom:10px;" />
        <Skeleton height="11px" width="80%" />
      {:else}
        {@const memPct = barWidth(status.memory.usage_pct)}
        {@const memV = usageVariant(status.memory.usage_pct)}
        {@const memTotal = status.memory.total_bytes || 1}
        {@const memUsed = status.memory.used_bytes - status.memory.buff_cache_bytes - status.memory.shared_bytes}
        <div class="c-ring-wrap">
          <svg class="c-ring" viewBox="0 0 36 36" aria-hidden="true">
            <circle class="c-ring-track" cx="18" cy="18" r="15.9155" />
            <circle class="c-ring-fill c-ring-blue"
              class:c-ring-warn={memV === 'warning'}
              class:c-ring-danger={memV === 'danger'}
              cx="18" cy="18" r="15.9155"
              style="stroke-dasharray: {memPct} 100;"
            />
          </svg>
          <div class="c-ring-center">
            <span class="c-ring-num">{Math.round(status.memory.usage_pct)}%</span>
            <span class="c-ring-sub">占用</span>
          </div>
        </div>
        <div class="c-seg-bar">
          <span class="c-seg-used" style="width: {(memUsed / memTotal * 100).toFixed(1)}%"></span>
          <span class="c-seg-shared" style="width: {(status.memory.shared_bytes / memTotal * 100).toFixed(1)}%"></span>
          <span class="c-seg-cache" style="width: {(status.memory.buff_cache_bytes / memTotal * 100).toFixed(1)}%"></span>
        </div>
        <div class="c-mem-legend">
          <div class="c-ml-row"><span class="c-ml-dot c-ml-used"></span><span>已用</span><b>{formatBytes(memUsed)}</b></div>
          <div class="c-ml-row"><span class="c-ml-dot c-ml-shared"></span><span>共享</span><b>{formatBytes(status.memory.shared_bytes)}</b></div>
          <div class="c-ml-row"><span class="c-ml-dot c-ml-cache"></span><span>缓存</span><b>{formatBytes(status.memory.buff_cache_bytes)}</b></div>
          <div class="c-ml-row"><span class="c-ml-dot c-ml-free"></span><span>可用</span><b>{formatBytes(status.memory.available_bytes)}</b></div>
        </div>
        {#if status.memory.swap_total_bytes > 0}
          <div class="c-swap-row">Swap {formatPercent(status.memory.swap_usage_pct)} · {formatBytes(status.memory.swap_used_bytes)} / {formatBytes(status.memory.swap_total_bytes)}</div>
        {/if}
      {/if}
    </div>

    <!-- Storage -->
    <div class="c-res-card">
      <div class="c-res-head">
        <span class="c-res-title"><Icon name="database" size={12} /> 存储</span>
      </div>
      {#if !status}
        {#each Array(2) as _, i (i)}
          <div style="margin-bottom:18px;">
            <Skeleton height="12px" width="55%" style="margin-bottom:8px;" />
            <Skeleton height="6px" rounded="full" style="margin-bottom:4px;" />
            <Skeleton height="11px" width="70%" />
          </div>
        {/each}
      {:else}
        <div class="c-disk-item">
          <div class="c-disk-head">
            <span>数据盘 <small>{status.storage.data.path}</small></span>
            <span class="c-res-badge"
              class:warn={usageVariant(status.storage.data.usage_pct) === 'warning'}
              class:danger={usageVariant(status.storage.data.usage_pct) === 'danger'}
            >{formatPercent(status.storage.data.usage_pct)}</span>
          </div>
          <div class="c-disk-bar">
            <span class="c-disk-fill"
              class:c-disk-warn={usageVariant(status.storage.data.usage_pct) === 'warning'}
              class:c-disk-danger={usageVariant(status.storage.data.usage_pct) === 'danger'}
              style="width: {barWidth(status.storage.data.usage_pct)}%"
            ></span>
          </div>
          <span class="c-disk-info">{formatBytes(status.storage.data.used_bytes)} / {formatBytes(status.storage.data.total_bytes)}</span>
        </div>
        <div class="c-disk-item">
          <div class="c-disk-head">
            <span>根分区 <small>{status.storage.root.path}</small></span>
            <span class="c-res-badge"
              class:warn={usageVariant(status.storage.root.usage_pct) === 'warning'}
              class:danger={usageVariant(status.storage.root.usage_pct) === 'danger'}
            >{formatPercent(status.storage.root.usage_pct)}</span>
          </div>
          <div class="c-disk-bar">
            <span class="c-disk-fill"
              class:c-disk-warn={usageVariant(status.storage.root.usage_pct) === 'warning'}
              class:c-disk-danger={usageVariant(status.storage.root.usage_pct) === 'danger'}
              style="width: {barWidth(status.storage.root.usage_pct)}%"
            ></span>
          </div>
          <span class="c-disk-info">{formatBytes(status.storage.root.used_bytes)} / {formatBytes(status.storage.root.total_bytes)}</span>
        </div>
      {/if}
    </div>

    <!-- Network -->
    <div class="c-res-card">
      <div class="c-res-head">
        <span class="c-res-title"><Icon name="activity" size={12} /> 网络</span>
        <span class="c-net-dot" class:c-net-dot--on={!!status}></span>
      </div>
      {#if !status}
        <Skeleton height="52px" rounded="md" style="margin-bottom:12px;" />
        <Skeleton height="11px" style="margin-bottom:6px;" />
        <Skeleton height="11px" />
      {:else}
        <div class="c-net-rates">
          <div class="c-net-rate c-net-down">
            <span class="c-net-arrow">↓</span>
            <div>
              <div class="c-net-val">{formatRate(status.network.rx_rate_Bps)}</div>
              <div class="c-net-label">下载</div>
            </div>
          </div>
          <div class="c-net-rate c-net-up">
            <span class="c-net-arrow">↑</span>
            <div>
              <div class="c-net-val">{formatRate(status.network.tx_rate_Bps)}</div>
              <div class="c-net-label">上传</div>
            </div>
          </div>
        </div>
        <div class="c-net-totals">
          <div class="c-net-total"><span>累计下载</span><b>{formatBytes(status.network.rx_bytes)}</b></div>
          <div class="c-net-total"><span>累计上传</span><b>{formatBytes(status.network.tx_bytes)}</b></div>
        </div>
      {/if}
    </div>

  </div>

  <!-- ── BOTTOM GRID ── -->
  <div class="c-bottom-grid c-anim-up" style="--d:180ms">

    <!-- Account Overview -->
    <div class="c-panel">
      <div class="c-panel-head">
        <span class="c-panel-title">账号概览</span>
        <span class="c-panel-sub">缓存统计</span>
      </div>
      {#if !status}
        <div class="c-ac-grid">
          {#each Array(7) as _, i (i)}
            <Skeleton height="72px" rounded="md" />
          {/each}
        </div>
      {:else}
        <div class="c-ac-grid">
          <div class="c-ac-tile">
            <span class="c-ac-num">{status.sqlite.accounts_total ?? '—'}</span>
            <span class="c-ac-label">总量</span>
          </div>
          <div class="c-ac-tile c-ac-ok">
            <span class="c-ac-num">{status.sqlite.accounts_active ?? '—'}</span>
            <span class="c-ac-label">活跃</span>
          </div>
          <div class="c-ac-tile c-ac-warn">
            <span class="c-ac-num">{status.sqlite.accounts_expired ?? '—'}</span>
            <span class="c-ac-label">过期</span>
          </div>
          <div class="c-ac-tile">
            <span class="c-ac-num">{status.sqlite.accounts_temp ?? '—'}</span>
            <span class="c-ac-label">临时</span>
          </div>
          <div class="c-ac-tile c-ac-err">
            <span class="c-ac-num">{status.sqlite.accounts_failed ?? '—'}</span>
            <span class="c-ac-label">失败</span>
          </div>
          <div class="c-ac-tile c-ac-ok">
            <span class="c-ac-num">{status.sqlite.accounts_uploaded ?? '—'}</span>
            <span class="c-ac-label">已上传</span>
          </div>
          <div class="c-ac-tile">
            <span class="c-ac-num">{status.sqlite.accounts_not_uploaded ?? '—'}</span>
            <span class="c-ac-label">未上传</span>
          </div>
        </div>
      {/if}
    </div>

    <!-- SQLite -->
    <div class="c-panel">
      <div class="c-panel-head">
        <span class="c-panel-title">SQLite</span>
        <span class="c-panel-sub c-panel-sub-path">{status?.sqlite?.path ?? 'storage'}</span>
      </div>
      {#if !status}
        <div style="display:grid; gap:8px;">
          {#each Array(8) as _, i (i)}
            <div style="display:flex; justify-content:space-between; gap:16px;">
              <Skeleton width="50px" height="11px" />
              <Skeleton width="80px" height="11px" />
            </div>
          {/each}
        </div>
      {:else}
        <div class="c-kv-grid">
          <div class="c-kv-row"><span>数据库</span><b>{formatBytes(status.sqlite.size_bytes)}</b></div>
          <div class="c-kv-row"><span>WAL</span><b>{formatBytes(status.sqlite.wal_size_bytes)}</b></div>
          <div class="c-kv-row"><span>页面</span><b>{status.sqlite.page_count} × {formatBytes(status.sqlite.page_size)}</b></div>
          <div class="c-kv-row"><span>空闲页</span><b>{status.sqlite.freelist_count} ({formatPercent(status.sqlite.freelist_pct)})</b></div>
          <div class="c-kv-row"><span>Journal</span><b>{status.sqlite.journal_mode}</b></div>
          <div class="c-kv-row"><span>Sync</span><b>{sqliteSynchronousLabel(status.sqlite.synchronous)}</b></div>
          <div class="c-kv-row"><span>Checkpoint</span><b>{status.sqlite.wal_autocheckpoint} 页</b></div>
          <div class="c-kv-row"><span>Cache</span><b>{sqliteCacheSizeLabel(status.sqlite.cache_size)}</b></div>
          <div class="c-kv-row"><span>FK</span><b>{enabledLabel(status.sqlite.foreign_keys)}</b></div>
          <div class="c-kv-row"><span>Schema</span><b>v{status.sqlite.schema_version}</b></div>
          <div class="c-kv-row"><span>对象</span><b>{status.sqlite.tables_count}T {status.sqlite.indexes_count}I {status.sqlite.triggers_count}Tr</b></div>
          <div class="c-kv-row"><span>统计时间</span><b style="font-size:11px;">{formatUnixTime(status.sqlite.stats_updated_at)}</b></div>
        </div>
      {/if}
    </div>

  </div>

</div>

<style>
/* =========================================
   Console Page — Redesigned Dashboard
   ========================================= */

/* ---- Entrance Animation ---- */
@keyframes console-fade-up {
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0);    }
}

.c-anim-up {
  animation: console-fade-up 0.55s var(--ease-out, cubic-bezier(0.22,1,0.36,1)) both;
  animation-delay: var(--d, 0ms);
}

/* ---- Root ---- */
.c-root {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* ---- HEADER ---- */
.c-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--nx-rule);
  flex-wrap: wrap;
}

.c-header-main {
  display: flex;
  align-items: center;
  gap: 14px;
}

.c-live-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 11px;
  border-radius: var(--radius-full);
  background: var(--nx-warning-bg);
  border: 1px solid var(--nx-warning-border);
  color: var(--nx-warning);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  transition: background 0.3s, color 0.3s, border-color 0.3s;
  flex-shrink: 0;
}

.c-live-pill--on {
  background: var(--nx-success-bg);
  border-color: var(--nx-success-border);
  color: var(--nx-success);
}

.c-live-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex-shrink: 0;
}

.c-live-pill--on .c-live-dot {
  animation: console-pulse 2s ease-in-out infinite;
}

@keyframes console-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.6; transform: scale(1.3); }
}

.c-header-text { display: grid; gap: 2px; }

.c-title {
  margin: 0;
  font-size: 26px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1.15;
  letter-spacing: -0.01em;
}

.c-desc {
  margin: 0;
  font-size: 13px;
  color: var(--nx-ink-muted);
}

.c-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

/* ---- HERO CARDS ---- */
.c-hero-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}

.c-hcard-skel {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px 18px;
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
}

.c-hcard {
  position: relative;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px 18px;
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  overflow: hidden;
  transition: transform 0.2s var(--ease-out), box-shadow 0.2s var(--ease-out), border-color 0.2s;
}

.c-hcard::after {
  content: '';
  position: absolute;
  top: 0; right: 0;
  width: 60%;
  height: 100%;
  background: linear-gradient(270deg, color-mix(in srgb, var(--nx-brand) 5%, transparent), transparent);
  pointer-events: none;
}

.c-hcard:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md);
  border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule));
}

.c-hcard--ok  { border-color: var(--nx-success-border); background: linear-gradient(135deg, var(--nx-success-bg) 0%, var(--nx-card) 55%); }
.c-hcard--warn { border-color: var(--nx-warning-border); background: linear-gradient(135deg, var(--nx-warning-bg) 0%, var(--nx-card) 55%); }
.c-hcard--err  { border-color: var(--nx-danger-border);  background: linear-gradient(135deg, var(--nx-danger-bg)  0%, var(--nx-card) 55%); }

.c-hcard--ok::after  { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-success) 6%, transparent), transparent); }
.c-hcard--warn::after { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-warning) 6%, transparent), transparent); }
.c-hcard--err::after  { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-danger)  6%, transparent), transparent); }

.c-hcard-icon {
  display: grid;
  place-items: center;
  width: 44px;
  height: 44px;
  flex-shrink: 0;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-brand) 12%, transparent);
  color: var(--nx-brand);
  border: 1px solid color-mix(in srgb, var(--nx-brand) 22%, transparent);
  transition: background 0.2s, color 0.2s, border-color 0.2s;
}

.c-hcard--ok  .c-hcard-icon { background: color-mix(in srgb, var(--nx-success) 12%, transparent); color: var(--nx-success); border-color: color-mix(in srgb, var(--nx-success) 25%, transparent); }
.c-hcard--warn .c-hcard-icon { background: color-mix(in srgb, var(--nx-warning) 12%, transparent); color: var(--nx-warning); border-color: color-mix(in srgb, var(--nx-warning) 25%, transparent); }
.c-hcard--err  .c-hcard-icon { background: color-mix(in srgb, var(--nx-danger)  12%, transparent); color: var(--nx-danger);  border-color: color-mix(in srgb, var(--nx-danger)  25%, transparent); }

.c-hcard-body { display: grid; gap: 2px; min-width: 0; }

.c-hcard-val {
  font-family: var(--font-number);
  font-size: 19px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1.1;
  font-variant-numeric: tabular-nums lining-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.c-hcard--ok  .c-hcard-val { color: var(--nx-success); }
.c-hcard--warn .c-hcard-val { color: var(--nx-warning); }
.c-hcard--err  .c-hcard-val { color: var(--nx-danger);  }

.c-hcard-label {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

.c-hcard-meta {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  font-weight: 400;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ---- RESOURCE GRID ---- */
.c-res-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}

.c-res-card {
  padding: 18px;
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  transition: box-shadow 0.2s var(--ease-out), border-color 0.2s;
}

.c-res-card:hover {
  box-shadow: var(--shadow-sm);
  border-color: color-mix(in srgb, var(--nx-brand) 20%, var(--nx-rule));
}

.c-res-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  gap: 8px;
}

.c-res-title {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 10.5px;
  font-weight: 700;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}

.c-res-badge {
  font-family: var(--font-number);
  font-size: 13px;
  font-weight: 700;
  color: var(--nx-brand);
  font-variant-numeric: tabular-nums;
}
.c-res-badge.warn   { color: var(--nx-warning); }
.c-res-badge.danger { color: var(--nx-danger);  }

/* SVG Ring Gauge */
.c-ring-skel { display: flex; justify-content: center; }

.c-ring-wrap {
  position: relative;
  width: 88px;
  height: 88px;
  margin: 0 auto 16px;
}

.c-ring {
  width: 88px;
  height: 88px;
  transform: rotate(-90deg);
  overflow: visible;
}

.c-ring-track {
  fill: none;
  stroke: var(--nx-rule);
  stroke-width: 2.8;
}

.c-ring-fill {
  fill: none;
  stroke: var(--nx-brand);
  stroke-width: 2.8;
  stroke-linecap: round;
  stroke-dasharray: 0 100;
  transition: stroke-dasharray 0.75s cubic-bezier(0.34, 1.18, 0.64, 1);
  filter: drop-shadow(0 0 5px color-mix(in srgb, var(--nx-brand) 55%, transparent));
}

.c-ring-blue   { stroke: #4c9de8; filter: drop-shadow(0 0 5px rgba(76,157,232,0.5)); }
.c-ring-warn   { stroke: var(--nx-warning) !important; filter: drop-shadow(0 0 5px rgba(138,100,24,0.45)) !important; }
.c-ring-danger { stroke: var(--nx-danger)  !important; filter: drop-shadow(0 0 5px rgba(164,63,43,0.45))  !important; }

.c-ring-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  pointer-events: none;
}

.c-ring-num {
  font-family: var(--font-number);
  font-size: 17px;
  font-weight: 700;
  line-height: 1;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums;
}

.c-ring-sub {
  font-size: 9.5px;
  font-weight: 500;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-top: 2px;
}

/* CPU KV mini grid */
.c-kv-mini {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
}

.c-kv-mini-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 6px 8px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--nx-paper-deep) 55%, var(--nx-card));
  border: 1px solid var(--nx-rule);
}

.c-kv-mini-item span {
  font-size: 9.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.c-kv-mini-item b {
  font-family: var(--font-number);
  font-size: 13px;
  font-weight: 600;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums;
}

/* Memory segmented bar */
.c-seg-bar {
  display: flex;
  height: 7px;
  border-radius: var(--radius-full);
  background: var(--nx-rule);
  overflow: hidden;
  margin-bottom: 12px;
  gap: 1px;
}

.c-seg-used, .c-seg-shared, .c-seg-cache {
  display: block;
  height: 100%;
  min-width: 0;
  transition: width 0.75s cubic-bezier(0.34, 1.18, 0.64, 1);
}

.c-seg-used   { background: #4c9de8; transition-delay: 0ms; }
.c-seg-shared { background: #a78bfa; transition-delay: 40ms; }
.c-seg-cache  { background: var(--nx-warning); transition-delay: 80ms; }

.c-mem-legend {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 5px 8px;
}

.c-ml-row {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 11px;
  color: var(--nx-ink-muted);
  min-width: 0;
}

.c-ml-row b {
  margin-left: auto;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums;
  font-weight: 600;
  white-space: nowrap;
}

.c-ml-dot {
  width: 7px;
  height: 7px;
  border-radius: 2px;
  flex-shrink: 0;
}

.c-ml-used   { background: #4c9de8; }
.c-ml-shared { background: #a78bfa; }
.c-ml-cache  { background: var(--nx-warning); }
.c-ml-free   { background: var(--nx-rule); border: 1px solid color-mix(in srgb, var(--nx-ink-muted) 40%, transparent); }

.c-swap-row {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--nx-rule);
  font-size: 11px;
  color: var(--nx-ink-muted);
}

/* Disk bars */
.c-disk-item { margin-bottom: 16px; }
.c-disk-item:last-child { margin-bottom: 0; }

.c-disk-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  margin-bottom: 7px;
  font-size: 12px;
  color: var(--nx-ink-soft);
  font-weight: 500;
}

.c-disk-head small {
  color: var(--nx-ink-muted);
  font-size: 10px;
  font-weight: 400;
  margin-left: 3px;
}

.c-disk-bar {
  height: 7px;
  border-radius: var(--radius-full);
  background: var(--nx-rule);
  overflow: hidden;
  margin-bottom: 5px;
}

.c-disk-fill {
  display: block;
  height: 100%;
  border-radius: inherit;
  min-width: 2px;
  background: linear-gradient(90deg, var(--nx-brand) 0%, var(--nx-brand-glow) 100%);
  transition: width 0.75s cubic-bezier(0.34, 1.18, 0.64, 1);
  box-shadow: 0 0 6px color-mix(in srgb, var(--nx-brand) 40%, transparent);
}

.c-disk-warn   { background: linear-gradient(90deg, var(--nx-warning), #e6b840); box-shadow: 0 0 6px rgba(138,100,24,0.35); }
.c-disk-danger { background: linear-gradient(90deg, var(--nx-danger), #c25d4a);  box-shadow: 0 0 6px rgba(164,63,43,0.35);  }

.c-disk-info {
  font-size: 11px;
  color: var(--nx-ink-muted);
}

/* Network card */
.c-net-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--nx-ink-muted);
  flex-shrink: 0;
  transition: background 0.3s;
}

.c-net-dot--on {
  background: var(--nx-success);
  box-shadow: 0 0 0 2px var(--nx-success-bg);
  animation: console-pulse 2s ease-in-out infinite;
}

.c-net-rates {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}

.c-net-rate {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 11px;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-paper-deep) 55%, var(--nx-card));
  border: 1px solid var(--nx-rule);
}

.c-net-arrow {
  font-size: 18px;
  font-weight: 800;
  line-height: 1;
  flex-shrink: 0;
}

.c-net-down .c-net-arrow { color: var(--nx-success); }
.c-net-up   .c-net-arrow { color: var(--nx-brand); }

.c-net-val {
  font-family: var(--font-number);
  font-size: 14px;
  font-weight: 700;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}

.c-net-label {
  font-size: 10px;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 500;
}

.c-net-totals { display: grid; gap: 1px; }

.c-net-total {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  color: var(--nx-ink-muted);
  padding: 6px 0;
  border-top: 1px solid var(--nx-rule);
}

.c-net-total b {
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}

/* ---- BOTTOM GRID ---- */
.c-bottom-grid {
  display: grid;
  grid-template-columns: 1fr minmax(260px, 380px);
  gap: 12px;
}

.c-panel {
  padding: 18px;
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
}

.c-panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--nx-rule);
}

.c-panel-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--nx-ink);
}

.c-panel-sub {
  font-size: 10.5px;
  font-weight: 700;
  color: var(--nx-brand);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

.c-panel-sub-path {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 500;
  text-transform: none;
  letter-spacing: 0;
  color: var(--nx-ink-muted);
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Account tiles */
.c-ac-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(88px, 1fr));
  gap: 8px;
}

.c-ac-tile {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 14px 8px;
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card));
  text-align: center;
  transition: transform 0.18s var(--ease-out), border-color 0.18s, box-shadow 0.18s;
  cursor: default;
}

.c-ac-tile:hover {
  transform: translateY(-3px);
  border-color: color-mix(in srgb, var(--nx-brand) 35%, var(--nx-rule));
  box-shadow: 0 4px 12px color-mix(in srgb, var(--nx-brand) 12%, transparent);
}

.c-ac-tile.c-ac-ok   { background: var(--nx-success-bg); border-color: var(--nx-success-border); }
.c-ac-tile.c-ac-warn { background: var(--nx-warning-bg); border-color: var(--nx-warning-border); }
.c-ac-tile.c-ac-err  { background: var(--nx-danger-bg);  border-color: var(--nx-danger-border);  }

.c-ac-num {
  font-family: var(--font-number);
  font-size: 22px;
  font-weight: 700;
  line-height: 1;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums lining-nums;
}

.c-ac-tile.c-ac-ok   .c-ac-num { color: var(--nx-success); }
.c-ac-tile.c-ac-warn .c-ac-num { color: var(--nx-warning); }
.c-ac-tile.c-ac-err  .c-ac-num { color: var(--nx-danger);  }

.c-ac-label {
  margin-top: 6px;
  font-size: 11px;
  color: var(--nx-ink-muted);
  font-weight: 500;
}

/* SQLite KV grid */
.c-kv-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 14px;
}

.c-kv-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 7px 0;
  border-bottom: 1px solid var(--nx-rule);
  font-size: 12px;
  gap: 6px;
}

.c-kv-row:last-child,
.c-kv-row:nth-last-child(2):nth-child(odd) {
  border-bottom: 0;
}

.c-kv-row span {
  color: var(--nx-ink-muted);
  font-weight: 400;
  flex-shrink: 0;
}

.c-kv-row b {
  color: var(--nx-ink);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  text-align: right;
  word-break: break-all;
}

/* ---- RESPONSIVE ---- */
@media (max-width: 1280px) {
  .c-res-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 1024px) {
  .c-hero-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .c-bottom-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .c-hero-grid,
  .c-res-grid {
    grid-template-columns: 1fr;
  }
  .c-header {
    flex-direction: column;
    align-items: flex-start;
  }
  .c-header-actions {
    width: 100%;
    justify-content: flex-end;
  }
}
</style>
