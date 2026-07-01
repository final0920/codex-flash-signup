<script lang="ts">
  import { onMount } from 'svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { waitApiJob } from '../lib/apiJobs';
  import { toast } from '../lib/toast';

  type ProxyScheme = 'http' | 'socks5' | 'socks5h';
  type ProxyMode = 'pool' | 'mihomo' | 'direct';
  type MihomoGroupMode = 'load-balance' | 'select';
  type MihomoSubscriptionType = 'url' | 'text';

  type ProxyItem = {
    id: number;
    scheme: string;
    host: string;
    port: number;
    username: string;
    proxy_url: string;
    status: string;
    last_test_ok: number;
    last_http_status: number;
    exit_ip: string;
    exit_loc: string;
    exit_colo: string;
    trace_http: string;
    trace_tls: string;
    last_error: string;
    last_tested_at: number;
  };

  const schemeOptions: { value: ProxyScheme; label: string; hint: string; defaultPort: number }[] = [
    { value: 'http', label: 'HTTP', hint: '标准 HTTP 代理', defaultPort: 8080 },
    { value: 'socks5', label: 'SOCKS5', hint: '客户端解析 DNS', defaultPort: 1080 },
    { value: 'socks5h', label: 'SOCKS5h', hint: '远端解析 DNS（推荐）', defaultPort: 1080 }
  ];

  const statusFilters = [
    { value: '', label: '全部' },
    { value: 'active', label: '可用' },
    { value: 'failed', label: '失败' },
    { value: 'new', label: '未测试' }
  ];

  type MihomoConfig = {
    mode: ProxyMode;
    enabled: boolean;
    managed: boolean;
    subscription_type: MihomoSubscriptionType;
    subscription_url: string;
    subscription_text: string;
    core_path: string;
    config_dir: string;
    mixed_host: string;
    mixed_port: number;
    controller_host: string;
    controller_port: number;
    strategy: string;
    group_mode: MihomoGroupMode;
    node_filter: string;
    exclude_filter: string;
    selected_node: string;
    health_check_url: string;
    provider_interval: number;
    health_check_interval: number;
    proxy_url: string;
    config_path: string;
    process_running: boolean;
    pid: number;
    log_path: string;
    last_error: string;
    group_name: string;
  };

  type MihomoSampleItem = {
    index: number;
    ok: number;
    http_status: number;
    exit_ip: string;
    exit_loc: string;
    exit_colo: string;
    error: string;
  };

  type MihomoSample = {
    ok: number;
    proxy_url: string;
    samples: number;
    items: MihomoSampleItem[];
    unique_exit_count: number;
    unique_exit_ips: string[];
    error?: string;
  };

  type MihomoNodes = {
    ok: number;
    group_name: string;
    group_mode: MihomoGroupMode;
    type: string;
    now: string;
    nodes: string[];
    count: number;
    error?: string;
  };

  const defaultMihomoConfig: MihomoConfig = {
    mode: 'pool',
    enabled: false,
    managed: true,
    subscription_type: 'url',
    subscription_url: '',
    subscription_text: '',
    core_path: 'mihomo',
    config_dir: 'data/mihomo',
    mixed_host: '127.0.0.1',
    mixed_port: 7890,
    controller_host: '127.0.0.1',
    controller_port: 9097,
    strategy: 'round-robin',
    group_mode: 'load-balance',
    node_filter: '',
    exclude_filter: '',
    selected_node: '',
    health_check_url: 'https://www.gstatic.com/generate_204',
    provider_interval: 3600,
    health_check_interval: 120,
    proxy_url: 'http://127.0.0.1:7890',
    config_path: 'data/mihomo/config.yaml',
    process_running: false,
    pid: -1,
    log_path: 'data/mihomo/mihomo.log',
    last_error: '',
    group_name: 'Mongoose-LB'
  };

  let proxies: ProxyItem[] = $state([]);
  let initialLoaded = $state(false);
  let loading = $state(false);
  let testingIds: Set<number> = $state(new Set());
  let busy = $state(false);
  let selectedIds: number[] = $state([]);
  let mihomo: MihomoConfig = $state({ ...defaultMihomoConfig });
  let mihomoLoading = $state(false);
  let mihomoBusy = $state(false);
  let mihomoSampleBusy = $state(false);
  let mihomoNodesBusy = $state(false);
  let mihomoSelectBusy = $state(false);
  let mihomoSample: MihomoSample | null = $state(null);
  let mihomoNodes: MihomoNodes | null = $state(null);
  let mihomoNodeDraft = $state('');

  let searchText = $state('');
  let statusFilter = $state('');
  let schemeFilter: string = $state('');

  let addOpen = $state(false);
  let addBusy = $state(false);
  let addScheme: ProxyScheme = $state('socks5h');
  let addHost = $state('');
  let addPort = $state(1080);
  let addUsername = $state('');
  let addPassword = $state('');
  let addTestAfter = $state(true);

  let importOpen = $state(false);
  let importText = $state('');
  let importBusy = $state(false);

  let detailOpen = $state(false);
  let detailProxy: ProxyItem | null = $state(null);
  let copiedKey: string | null = $state(null);

  let filteredProxies = $derived.by(() => {
    return proxies.filter((proxy) => {
      if (statusFilter && proxy.status !== statusFilter) return false;
      if (schemeFilter && proxy.scheme.toLowerCase() !== schemeFilter) return false;
      if (searchText.trim()) {
        const needle = searchText.trim().toLowerCase();
        const haystack = `${proxy.host} ${proxy.port} ${proxy.username} ${proxy.exit_ip} ${proxy.exit_loc} ${proxy.exit_colo}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  });

  let summary = $derived({
    total: proxies.length,
    active: proxies.filter((p) => p.status === 'active').length,
    failed: proxies.filter((p) => p.status === 'failed').length,
    untested: proxies.filter((p) => p.status === 'new' || !p.status).length
  });

  let allVisibleSelected = $derived(
    filteredProxies.length > 0 && filteredProxies.every((p) => selectedIds.includes(p.id))
  );

  let addPreview = $derived(buildProxyUrl(addScheme, addHost.trim(), addPort, addUsername.trim(), addPassword));

  let parsedImportLines = $derived(
    importText
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'))
  );

  let hasFilter = $derived(Boolean(searchText.trim() || statusFilter || schemeFilter));

  let mihomoStatusText = $derived(
    mihomo.mode === 'mihomo'
      ? (mihomo.process_running || !mihomo.managed ? 'Mihomo' : 'Mihomo 未运行')
      : (mihomo.mode === 'direct' ? '直连' : '代理池')
  );

  function buildProxyUrl(scheme: ProxyScheme, host: string, port: number, user: string, pass: string) {
    if (!host || !port) return '';
    const auth = user ? (pass ? `${user}:${pass}@` : `${user}@`) : '';
    return `${scheme}://${auth}${host}:${port}`;
  }

  async function loadProxies(silent = false) {
    if (!silent) loading = true;
    try {
      const response = await fetch('/api/proxies');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      proxies = data.items ?? [];
      selectedIds = selectedIds.filter((id) => proxies.some((p) => p.id === id));
      if (detailProxy) {
        const fresh = proxies.find((p) => p.id === detailProxy?.id);
        if (fresh) detailProxy = fresh;
      }
    } catch (err) {
      toast.error(`加载失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      loading = false;
      initialLoaded = true;
    }
  }

  async function loadMihomo(silent = false) {
    if (!silent) mihomoLoading = true;
    try {
      const response = await fetch('/api/proxies/mihomo');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      mihomo = { ...defaultMihomoConfig, ...data };
      mihomoNodeDraft = mihomo.selected_node || mihomoNodeDraft;
    } catch (err) {
      toast.error(`Mihomo 配置加载失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      mihomoLoading = false;
    }
  }

  async function saveMihomoConfig(silent = false) {
    mihomoBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mihomo)
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (result.ok === 0) throw new Error(result.error || '保存失败');
      mihomo = { ...defaultMihomoConfig, ...result };
      if (!silent) toast.success(`${mihomoStatusText} 配置已保存`);
      return true;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
      return false;
    } finally {
      mihomoBusy = false;
    }
  }

  async function startMihomo() {
    if (mihomo.mode !== 'mihomo') {
      mihomo.enabled = true;
      const saved = await saveMihomoConfig(true);
      if (!saved) return;
      if (mihomo.mode === 'pool' && summary.active <= 0) {
        toast.info('代理池已启用，但当前没有可用节点；请先测试通过至少一个代理，否则注册任务不会启动');
      } else {
        toast.success(mihomo.mode === 'pool' ? '代理池已启用' : '直连模式已启用');
      }
      return;
    }
    const saved = await saveMihomoConfig(true);
    if (!saved) return;
    mihomoBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo/start', { method: 'POST' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (result.ok === 0) throw new Error(result.error || '启动失败');
      mihomo = { ...defaultMihomoConfig, ...result };
      mihomoNodeDraft = mihomo.selected_node || mihomoNodeDraft;
      toast.success(mihomo.managed ? 'Mihomo 已启动' : 'Mihomo 代理已启用');
      await loadProxies(true);
      if (mihomo.group_mode === 'select') await loadMihomoNodes(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
      await loadMihomo(true);
    } finally {
      mihomoBusy = false;
    }
  }

  async function stopMihomo() {
    mihomoBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo/stop', { method: 'POST' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      mihomo = { ...defaultMihomoConfig, ...result };
      mihomoNodes = null;
      toast.success('Mihomo 已停止，代理模式已切回代理池');
      await loadProxies(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      mihomoBusy = false;
    }
  }

  async function sampleMihomo() {
    mihomoSampleBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo/sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ samples: 12, async: true })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      let result = await response.json();
      if (result.async && result.job_id) {
        result = await waitApiJob<MihomoSample>(result.job_id, {
          timeoutMs: 240000
        });
      }
      mihomoSample = result;
      if (!result.ok) throw new Error(result.error || '出口测试失败');
      toast.success(`出口采样完成：${result.unique_exit_count ?? 0} 个 IP`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      mihomoSampleBusy = false;
    }
  }

  async function loadMihomoNodes(silent = false) {
    mihomoNodesBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo/nodes');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result: MihomoNodes = await response.json();
      mihomoNodes = result;
      if (!result.ok) throw new Error(result.error || '节点读取失败');
      if (result.now) {
        mihomoNodeDraft = result.now;
      } else if (mihomo.selected_node) {
        mihomoNodeDraft = mihomo.selected_node;
      }
      if (!silent) toast.success(`已读取 ${result.count ?? result.nodes?.length ?? 0} 个节点`);
    } catch (err) {
      if (!silent) toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      mihomoNodesBusy = false;
    }
  }

  async function selectMihomoNode() {
    const node = mihomoNodeDraft.trim();
    if (!node) {
      toast.error('请选择订阅节点');
      return;
    }
    mihomo.group_mode = 'select';
    mihomo.selected_node = node;
    const saved = await saveMihomoConfig(true);
    if (!saved) return;
    mihomoSelectBusy = true;
    try {
      const response = await fetch('/api/proxies/mihomo/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (result.ok === 0) throw new Error(result.error || '节点切换失败');
      mihomo = { ...defaultMihomoConfig, ...result };
      mihomoNodeDraft = mihomo.selected_node || node;
      toast.success('订阅节点已应用');
      await loadMihomoNodes(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
      await loadMihomo(true);
    } finally {
      mihomoSelectBusy = false;
    }
  }

  function resetAddForm() {
    addScheme = 'socks5h';
    addHost = '';
    addPort = 1080;
    addUsername = '';
    addPassword = '';
    addTestAfter = true;
  }

  function openAddModal() {
    resetAddForm();
    addOpen = true;
  }

  function changeScheme(scheme: ProxyScheme) {
    addScheme = scheme;
    const opt = schemeOptions.find((o) => o.value === scheme);
    if (opt && (!addPort || schemeOptions.some((o) => o.defaultPort === addPort))) {
      addPort = opt.defaultPort;
    }
  }

  async function submitAddProxy(event: SubmitEvent) {
    event.preventDefault();
    const url = addPreview;
    if (!url) {
      toast.error('请填写主机和端口');
      return;
    }
    addBusy = true;
    try {
      const response = await fetch('/api/proxies/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: url })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (result.imported > 0) {
        toast.success('代理已添加');
      } else if (result.skipped > 0) {
        toast.info('代理已存在，跳过');
      } else if (result.invalid > 0) {
        throw new Error('代理格式无效');
      }
      addOpen = false;
      await loadProxies(true);
      if (addTestAfter && result.imported > 0) {
        const created = proxies.find(
          (p) => p.host === addHost.trim() && p.port === Number(addPort) && p.scheme.toLowerCase() === addScheme
        );
        if (created) testProxies([created.id]);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      addBusy = false;
    }
  }

  async function submitBulkImport() {
    if (parsedImportLines.length === 0) {
      toast.error('请粘贴至少一行代理');
      return;
    }
    importBusy = true;
    try {
      const response = await fetch('/api/proxies/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: importText })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      const parts: string[] = [];
      if (result.imported > 0) parts.push(`新增 ${result.imported}`);
      if (result.skipped > 0) parts.push(`重复 ${result.skipped}`);
      if (result.invalid > 0) parts.push(`无效 ${result.invalid}`);
      toast.success(`导入完成：${parts.join(' · ') || '0'}`);
      importText = '';
      importOpen = false;
      await loadProxies(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      importBusy = false;
    }
  }

  async function testProxies(ids: number[]) {
    busy = true;
    const targetIds = ids.length > 0 ? ids : proxies.map((p) => p.id);
    targetIds.forEach((id) => testingIds.add(id));
    testingIds = new Set(testingIds);
    try {
      const response = await fetch('/api/proxies/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      const items = result.items ?? [];
      const ok = items.filter((item: { ok: number }) => item.ok).length;
      toast.success(`测试完成：${items.length} 个代理 · ${ok} 可用`);
      await loadProxies(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      targetIds.forEach((id) => testingIds.delete(id));
      testingIds = new Set(testingIds);
      busy = false;
    }
  }

  async function deleteIds(ids: number[]) {
    if (ids.length === 0) return;
    if (!window.confirm(`确认删除 ${ids.length} 个代理？此操作不可撤销。`)) return;
    busy = true;
    try {
      const response = await fetch('/api/proxies/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      toast.success(`已删除 ${result.deleted} 个代理`);
      selectedIds = selectedIds.filter((id) => !ids.includes(id));
      if (detailProxy && ids.includes(detailProxy.id)) {
        detailOpen = false;
        detailProxy = null;
      }
      await loadProxies(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busy = false;
    }
  }

  function toggleSelect(event: Event, id: number) {
    event.stopPropagation();
    selectedIds = selectedIds.includes(id)
      ? selectedIds.filter((item) => item !== id)
      : [...selectedIds, id];
  }

  function toggleAllVisible(event: Event) {
    const checked = (event.currentTarget as HTMLInputElement).checked;
    const visibleIds = filteredProxies.map((p) => p.id);
    if (checked) {
      selectedIds = Array.from(new Set([...selectedIds, ...visibleIds]));
    } else {
      selectedIds = selectedIds.filter((id) => !visibleIds.includes(id));
    }
  }

  function openDetail(proxy: ProxyItem) {
    detailProxy = proxy;
    detailOpen = true;
  }

  function statusLabel(status: string) {
    if (status === 'active') return '可用';
    if (status === 'failed') return '失败';
    return '未测试';
  }

  function statusPillClass(status: string) {
    if (status === 'active') return 'pill pill-success';
    if (status === 'failed') return 'pill pill-danger';
    return 'pill';
  }

  function formatUnixTime(value: number) {
    if (!value) return '从未';
    const ms = value * 1000;
    const diff = Date.now() - ms;
    if (diff < 60_000) return '刚刚';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
    if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} 天前`;
    return new Date(ms).toLocaleDateString();
  }

  function formatExactTime(value: number) {
    if (!value) return '-';
    return new Date(value * 1000).toLocaleString();
  }

  async function copy(value: string, key: string, label = '内容') {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      copiedKey = key;
      setTimeout(() => { if (copiedKey === key) copiedKey = null; }, 1400);
      toast.success(`${label}已复制`);
    } catch (err) {
      toast.error(`复制失败：${err instanceof Error ? err.message : String(err)}`);
    }
  }

  function clearFilters() {
    searchText = '';
    statusFilter = '';
    schemeFilter = '';
  }

  onMount(() => {
    loadProxies();
    loadMihomo();
  });
</script>

<div class="p-root">

  <!-- ── HEADER ── -->
  <header class="p-header p-anim-up" style="--d:0ms">
    <div class="p-header-main">
      <h1 class="p-title">代理池</h1>
      <p class="p-desc">管理 HTTP / SOCKS5 出口节点，支持批量导入、连通性测试与出口探测</p>
    </div>
    <div class="p-header-actions">
      <button class="btn" type="button" onclick={() => { loadProxies(); loadMihomo(true); }} disabled={loading || mihomoLoading}>
        <Icon name="refresh" size={14} />
        刷新
      </button>
      <button class="btn" type="button" onclick={() => importOpen = true} disabled={busy}>
        <Icon name="upload" size={14} />
        批量导入
      </button>
      <button class="btn btn-primary" type="button" onclick={openAddModal} disabled={busy}>
        <Icon name="plus" size={14} />
        添加代理
      </button>
    </div>
  </header>

  <!-- ── HERO STATS ── -->
  <div class="p-hero-grid p-anim-up" style="--d:60ms">
    <div class="p-hcard">
      <div class="p-hcard-icon"><Icon name="globe" size={18} /></div>
      <div class="p-hcard-body">
        <div class="p-hcard-val">{summary.total}</div>
        <div class="p-hcard-label">代理总数</div>
        <div class="p-hcard-meta">{filteredProxies.length} 当前可见</div>
      </div>
    </div>
    <div class="p-hcard p-hcard--ok">
      <div class="p-hcard-icon"><Icon name="check-circle" size={18} /></div>
      <div class="p-hcard-body">
        <div class="p-hcard-val">{summary.active}</div>
        <div class="p-hcard-label">可用节点</div>
        <div class="p-hcard-meta p-hcard-meta-bar">
          {#if summary.total > 0}
            <div class="p-rate-bar"><div class="p-rate-fill" style="width:{(summary.active/summary.total*100).toFixed(0)}%"></div></div>
            <span>{(summary.active/summary.total*100).toFixed(0)}% 可用率</span>
          {:else}<span>—</span>{/if}
        </div>
      </div>
    </div>
    <div class="p-hcard p-hcard--err">
      <div class="p-hcard-icon"><Icon name="alert-circle" size={18} /></div>
      <div class="p-hcard-body">
        <div class="p-hcard-val">{summary.failed}</div>
        <div class="p-hcard-label">失败节点</div>
        <div class="p-hcard-meta">最近测试不通过</div>
      </div>
    </div>
    <div class="p-hcard">
      <div class="p-hcard-icon"><Icon name="clock" size={18} /></div>
      <div class="p-hcard-body">
        <div class="p-hcard-val">{summary.untested}</div>
        <div class="p-hcard-label">未测试</div>
        <div class="p-hcard-meta">尚未运行连通性</div>
      </div>
    </div>
  </div>


  <!-- ── MIHOMO PANEL ── -->
  <div class="p-panel p-anim-up" style="--d:120ms">
    <div class="p-panel-head">
      <div class="p-panel-head-left">
        <span class="p-panel-title">Clash / Mihomo</span>
        <span class="p-panel-badge" class:p-badge-ok={mihomo.mode === 'mihomo' && (mihomo.process_running || !mihomo.managed)}>
          {mihomoStatusText}
        </span>
      </div>
      <div class="p-panel-actions">
        <button class="btn btn-sm" type="button" onclick={() => saveMihomoConfig()} disabled={mihomoBusy || mihomoLoading}>
          <Icon name="check" size={12} />
          保存
        </button>
        <button class="btn btn-sm btn-primary" type="button" onclick={startMihomo} disabled={mihomoBusy || mihomoLoading}>
          <Icon name="zap" size={12} />
          启用
        </button>
        <button class="btn btn-sm" type="button" onclick={sampleMihomo} disabled={mihomoSampleBusy || mihomo.mode !== 'mihomo' || !mihomo.enabled}>
          <Icon name="activity" size={12} />
          采样
        </button>
        <button class="btn btn-sm btn-danger" type="button" onclick={stopMihomo} disabled={mihomoBusy || mihomo.mode !== 'mihomo' || (!mihomo.process_running && !mihomo.enabled)}>
          <Icon name="close" size={12} />
          停止
        </button>
      </div>
    </div>

    <div class="p-panel-body">
    <div class="m-mode-grid">
      <button class="m-mode-card" type="button" class:m-mode-active={mihomo.mode === 'pool'} onclick={() => mihomo.mode = 'pool'} disabled={mihomoBusy}>
        <div class="m-mode-icon"><Icon name="globe" size={16} /></div>
        <span class="m-mode-label">代理池</span>
        <span class="m-mode-hint">轮询本地代理列表</span>
      </button>
      <button class="m-mode-card" type="button" class:m-mode-active={mihomo.mode === 'mihomo'} onclick={() => mihomo.mode = 'mihomo'} disabled={mihomoBusy}>
        <div class="m-mode-icon"><Icon name="zap" size={16} /></div>
        <span class="m-mode-label">Mihomo</span>
        <span class="m-mode-hint">订阅节点 / 负载均衡</span>
      </button>
      <button class="m-mode-card" type="button" class:m-mode-active={mihomo.mode === 'direct'} onclick={() => mihomo.mode = 'direct'} disabled={mihomoBusy}>
        <div class="m-mode-icon"><Icon name="arrow-right" size={16} /></div>
        <span class="m-mode-label">直连</span>
        <span class="m-mode-hint">不经过代理直连</span>
      </button>
    </div>
    {#if mihomo.mode === 'mihomo'}
    <div class="m-status-row">
      <div class="m-field-group">
        <span class="m-field-label">运行方式</span>
        <div class="segmented">
          <button type="button" class:active={mihomo.managed} onclick={() => mihomo.managed = true} disabled={mihomoBusy}>托管核心</button>
          <button type="button" class:active={!mihomo.managed} onclick={() => mihomo.managed = false} disabled={mihomoBusy}>外部端口</button>
        </div>
      </div>
      <div class="m-field-group m-field-group-stretch">
        <span class="m-field-label">代理入口</span>
        <div class="m-url-chip" class:m-url-chip-on={mihomo.process_running || !mihomo.managed}>
          <span class="m-url-dot"></span>
          <span class="m-url-text">{mihomo.proxy_url}</span>
          <span class="m-url-status">{mihomo.process_running || !mihomo.managed ? '已启用' : 'Mihomo 未运行'}</span>
        </div>
      </div>
    </div>


    <div class="m-divider"><span>订阅配置</span></div>
    <div class="form-field" style="margin-bottom:10px;">
      <div class="segmented">
        <button type="button" class:active={mihomo.subscription_type === 'url'} onclick={() => mihomo.subscription_type = 'url'} disabled={mihomoBusy || !mihomo.managed}>链接订阅</button>
        <button type="button" class:active={mihomo.subscription_type === 'text'} onclick={() => mihomo.subscription_type = 'text'} disabled={mihomoBusy || !mihomo.managed}>文本订阅</button>
      </div>
    </div>
    {#if mihomo.subscription_type === 'text'}
      <textarea
        class="input m-code-area"
        bind:value={mihomo.subscription_text}
        placeholder={`proxies:\n  - name: node-1\n    type: socks5\n    server: 127.0.0.1\n    port: 1080`}
        disabled={mihomoBusy || !mihomo.managed}
        autocomplete="off"
      ></textarea>
    {:else}
      <div class="m-url-input">
        <span class="m-url-input-icon"><Icon name="link" size={13} /></span>
        <input class="input" type="password" bind:value={mihomo.subscription_url} placeholder="Clash / Mihomo 订阅链接" disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
      </div>
    {/if}
    <div class="form-grid form-grid-2" style="margin-top:12px;">
      <label class="form-field">
        <span class="form-label">核心路径</span>
        <input class="input" bind:value={mihomo.core_path} disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
      </label>
      <label class="form-field">
        <span class="form-label">配置目录</span>
        <input class="input" bind:value={mihomo.config_dir} disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
      </label>
    </div>


    <div class="m-divider"><span>网络 &amp; 节点</span></div>
    <div class="m-twin">
      <div class="m-twin-col">
        <div class="form-grid form-grid-2">
          <label class="form-field">
            <span class="form-label">监听地址</span>
            <input class="input" bind:value={mihomo.mixed_host} disabled={mihomoBusy} autocomplete="off" />
          </label>
          <label class="form-field">
            <span class="form-label">Mixed Port</span>
            <input class="input" type="number" min="1" max="65535" bind:value={mihomo.mixed_port} disabled={mihomoBusy} />
          </label>
        </div>
        <label class="form-field" style="margin-top:10px;">
          <span class="form-label">均衡策略</span>
          <select class="input" bind:value={mihomo.strategy} disabled={mihomoBusy || !mihomo.managed || mihomo.group_mode !== 'load-balance'}>
            <option value="round-robin">Round Robin</option>
            <option value="consistent-hashing">Consistent Hashing</option>
            <option value="sticky-sessions">Sticky Sessions</option>
          </select>
        </label>
      </div>
      <div class="m-twin-col">
        <div class="form-field" style="margin-bottom:10px;">
          <span class="form-label">节点模式</span>
          <div class="segmented" style="margin-top:4px;">
            <button type="button" class:active={mihomo.group_mode === 'load-balance'} onclick={() => mihomo.group_mode = 'load-balance'} disabled={mihomoBusy}>自动均衡</button>
            <button type="button" class:active={mihomo.group_mode === 'select'} onclick={() => mihomo.group_mode = 'select'} disabled={mihomoBusy}>手动节点</button>
          </div>
        </div>
        <div class="form-grid form-grid-2">
          <label class="form-field">
            <span class="form-label">节点过滤</span>
            <input class="input" bind:value={mihomo.node_filter} placeholder="香港|日本" disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
          </label>
          <label class="form-field">
            <span class="form-label">排除过滤</span>
            <input class="input" bind:value={mihomo.exclude_filter} placeholder="倍率|官网" disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
          </label>
        </div>
        {#if mihomo.group_mode === 'select'}
          <label class="form-field" style="margin-top:10px;">
            <span class="form-label">订阅节点</span>
            <input class="input" list="mihomo-node-options" bind:value={mihomoNodeDraft} placeholder="节点名或从列表选择" disabled={mihomoBusy || mihomoSelectBusy} autocomplete="off" />
            <datalist id="mihomo-node-options">
              {#each mihomoNodes?.nodes ?? [] as node}
                <option value={node}></option>
              {/each}
            </datalist>
          </label>
          <div class="m-node-actions">
            <button class="btn btn-sm" type="button" onclick={() => loadMihomoNodes()} disabled={mihomoNodesBusy || mihomo.mode !== 'mihomo' || !mihomo.enabled}>
              <Icon name="list" size={12} />
              读取节点
            </button>
            <button class="btn btn-sm btn-primary" type="button" onclick={selectMihomoNode} disabled={mihomoSelectBusy || !mihomoNodeDraft.trim()}>
              <Icon name="check" size={12} />
              应用节点
            </button>
            {#if mihomoNodes?.now}
              <span class="pill pill-success">{mihomoNodes.now}</span>
            {/if}
          </div>
        {/if}
      </div>
    </div>

    <div class="m-divider m-divider-muted"><span>高级设置</span></div>
    <div class="form-grid form-grid-3">
      <label class="form-field">
        <span class="form-label">Controller 地址</span>
        <input class="input" bind:value={mihomo.controller_host} disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
      </label>
      <label class="form-field">
        <span class="form-label">Controller Port</span>
        <input class="input" type="number" min="1" max="65535" bind:value={mihomo.controller_port} disabled={mihomoBusy || !mihomo.managed} />
      </label>
      <label class="form-field">
        <span class="form-label">健康检查 URL</span>
        <input class="input" bind:value={mihomo.health_check_url} disabled={mihomoBusy || !mihomo.managed} autocomplete="off" />
      </label>
    </div>

  {#if mihomo.last_error}
    <div class="notice-bar notice-error" style="margin-top: 14px;">
      <span class="notice-icon"><Icon name="alert-circle" size={14} /></span>
      <span class="notice-text">{mihomo.last_error}</span>
    </div>
  {/if}

  {#if mihomoSample}
    <div class="p-sample-chip">
      <div class="p-sample-icon"><Icon name="activity" size={16} /></div>
      <div>
        <div class="p-sample-val">{mihomoSample.unique_exit_count ?? 0} 个出口 IP</div>
        <div class="p-sample-ips">{(mihomoSample.unique_exit_ips ?? []).join(' · ') || '未获取到出口 IP'}</div>
      </div>
    </div>
  {/if}
    {/if}
    </div>
  </div>


  <!-- ── PROXY LIST PANEL ── -->
  <div class="p-panel p-anim-up" style="--d:180ms">
    <div class="p-panel-head">
      <div class="p-panel-head-left">
        <span class="p-panel-title">代理列表</span>
        <span class="p-panel-sub">节点</span>
      </div>
      <div class="p-panel-actions">
        <button class="btn btn-sm" type="button" onclick={() => testProxies([])} disabled={busy || proxies.length === 0}>
          <Icon name="zap" size={12} />
          测试全部
        </button>
      </div>
    </div>

    <div class="p-panel-body">
    <div class="filter-bar" style="grid-template-columns: minmax(200px, 1.6fr) minmax(120px, 1fr) minmax(120px, 1fr) auto;">
    <label class="form-field">
      <span class="form-label">搜索</span>
      <div class="search-input">
        <span class="search-input-icon">
          <Icon name="search" size={14} />
        </span>
        <input class="input" bind:value={searchText} placeholder="主机、IP、出口位置" />
        {#if searchText}
          <button class="search-input-clear" type="button" onclick={() => searchText = ''} aria-label="清空搜索">
            <Icon name="close" size={12} />
          </button>
        {/if}
      </div>
    </label>
    <label class="form-field">
      <span class="form-label">状态</span>
      <select class="input" bind:value={statusFilter}>
        {#each statusFilters as opt}<option value={opt.value}>{opt.label}</option>{/each}
      </select>
    </label>
    <label class="form-field">
      <span class="form-label">协议</span>
      <select class="input" bind:value={schemeFilter}>
        <option value="">全部</option>
        <option value="http">HTTP</option>
        <option value="socks5">SOCKS5</option>
        <option value="socks5h">SOCKS5h</option>
      </select>
    </label>
    <button class="btn filter-btn" type="button" onclick={clearFilters} disabled={!hasFilter}>
      清空筛选
    </button>
  </div>

  {#if selectedIds.length > 0}
    <div class="bulk-bar">
      <span class="bulk-meta">已选 <strong style="color: var(--nx-ink); font-weight: 600;">{selectedIds.length}</strong> 个</span>
      <button class="btn btn-sm btn-primary" type="button" onclick={() => testProxies(selectedIds)} disabled={busy}>
        <Icon name="zap" size={12} />
        测试选中
      </button>
      <button class="btn btn-sm btn-danger" type="button" onclick={() => deleteIds(selectedIds)} disabled={busy}>
        <Icon name="trash" size={12} />
        删除
      </button>
      <button class="btn btn-sm btn-ghost" type="button" onclick={() => selectedIds = []}>
        取消选择
      </button>
    </div>
  {/if}

  {#if !initialLoaded}
    <div class="table-wrap has-cards">
      <table class="data-table">
        <thead>
          <tr>
            <th class="col-check"></th>
            <th>代理地址</th>
            <th>状态</th>
            <th>出口</th>
            <th>协议</th>
            <th>最近测试</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each Array(4) as _, i (i)}
            <tr>
              <td class="col-check"><Skeleton width="16px" height="16px" /></td>
              <td><Skeleton width="180px" height="14px" /><Skeleton width="120px" height="11px" style="margin-top: 6px;" /></td>
              <td><Skeleton width="60px" height="20px" rounded="full" /></td>
              <td><Skeleton width="100px" height="14px" /><Skeleton width="80px" height="11px" style="margin-top: 6px;" /></td>
              <td><Skeleton width="50px" height="14px" /></td>
              <td><Skeleton width="80px" height="12px" /></td>
              <td><Skeleton width="120px" height="24px" /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if proxies.length === 0}
    <EmptyState
      title="还没有代理"
      message="添加第一个代理或批量导入一份列表，即可开始测试与分发。"
      icon="globe"
    >
      {#snippet action()}
        <div class="btn-row">
          <button class="btn" type="button" onclick={() => importOpen = true}>
            <Icon name="upload" size={14} />
            批量导入
          </button>
          <button class="btn btn-primary" type="button" onclick={openAddModal}>
            <Icon name="plus" size={14} />
            添加代理
          </button>
        </div>
      {/snippet}
    </EmptyState>
  {:else if filteredProxies.length === 0}
    <EmptyState
      title="没有匹配的代理"
      message="尝试调整搜索关键词或筛选条件。"
      icon="search"
    >
      {#snippet action()}
        <button class="btn btn-sm" type="button" onclick={clearFilters}>
          清空筛选
        </button>
      {/snippet}
    </EmptyState>
  {:else}
    <div class="table-wrap has-cards">
      <table class="data-table">
        <thead>
          <tr>
            <th class="col-check">
              <input type="checkbox" checked={allVisibleSelected} onchange={toggleAllVisible} aria-label="选择全部可见代理" />
            </th>
            <th>代理地址</th>
            <th>状态</th>
            <th>出口信息</th>
            <th>协议指纹</th>
            <th>最近测试</th>
            <th style="text-align: right;">操作</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredProxies as proxy (proxy.id)}
            <tr
              class:row-selected={selectedIds.includes(proxy.id)}
              class="account-row"
              tabindex="0"
              onclick={() => openDetail(proxy)}
              onkeydown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDetail(proxy); } }}
            >
              <td class="col-check">
                <input
                  type="checkbox"
                  checked={selectedIds.includes(proxy.id)}
                  onchange={(event) => toggleSelect(event, proxy.id)}
                  onclick={(event) => event.stopPropagation()}
                  aria-label={`选择代理 ${proxy.id}`}
                />
              </td>
              <td>
                <span class="cell-primary text-mono">{proxy.host}<span style="color: var(--nx-ink-muted);">:</span>{proxy.port}</span>
                <span class="cell-secondary">
                  <span class="tag">{proxy.scheme.toUpperCase()}</span>
                  {#if proxy.username}<span style="margin-left: 6px;">@ {proxy.username}</span>{/if}
                </span>
              </td>
              <td>
                {#if testingIds.has(proxy.id)}
                  <span class="pill"><span class="spinner" style="width: 10px; height: 10px;"></span> 测试中</span>
                {:else}
                  <span class={statusPillClass(proxy.status)}>{statusLabel(proxy.status)}</span>
                {/if}
              </td>
              <td>
                <span class="cell-primary text-mono">{proxy.exit_ip || '—'}</span>
                <span class="cell-secondary">{[proxy.exit_loc, proxy.exit_colo].filter(Boolean).join(' · ') || '—'}</span>
              </td>
              <td>
                <span class="cell-primary">{proxy.trace_http || '—'}</span>
                <span class="cell-secondary">{proxy.trace_tls || '—'}</span>
              </td>
              <td>
                <span class="cell-primary" style="font-weight: 400;">{formatUnixTime(proxy.last_tested_at)}</span>
                {#if proxy.last_http_status}
                  <span class="cell-secondary">HTTP {proxy.last_http_status}</span>
                {/if}
              </td>
              <td>
                <div class="inline-actions">
                  <button class="btn btn-xs" type="button" onclick={(event) => { event.stopPropagation(); testProxies([proxy.id]); }} disabled={busy} aria-label="测试代理">
                    <Icon name="zap" size={11} />
                  </button>
                  <button class="btn btn-xs" type="button" onclick={(event) => { event.stopPropagation(); copy(proxy.proxy_url, `row-${proxy.id}`, '代理 URL'); }} aria-label="复制 URL">
                    <Icon name={copiedKey === `row-${proxy.id}` ? 'check' : 'copy'} size={11} />
                  </button>
                  <button class="btn btn-xs btn-danger" type="button" onclick={(event) => { event.stopPropagation(); deleteIds([proxy.id]); }} disabled={busy} aria-label="删除代理">
                    <Icon name="trash" size={11} />
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="data-cards" role="list">
      {#each filteredProxies as proxy (proxy.id)}
        <div
          class="data-card"
          class:is-selected={selectedIds.includes(proxy.id)}
          role="listitem"
        >
          <input
            class="data-card-checkbox"
            type="checkbox"
            checked={selectedIds.includes(proxy.id)}
            onchange={(event) => toggleSelect(event, proxy.id)}
            aria-label={`选择代理 ${proxy.id}`}
          />
          <div class="data-card-head">
            <button type="button" class="data-card-title text-mono" style="background: transparent; border: 0; padding: 0; cursor: pointer; text-align: left;" onclick={() => openDetail(proxy)}>
              {proxy.host}:{proxy.port}
            </button>
            {#if testingIds.has(proxy.id)}
              <span class="pill"><span class="spinner" style="width: 10px; height: 10px;"></span> 测试中</span>
            {:else}
              <span class={statusPillClass(proxy.status)}>{statusLabel(proxy.status)}</span>
            {/if}
          </div>
          <div class="data-card-meta">
            <span><span class="tag">{proxy.scheme.toUpperCase()}</span>{#if proxy.username}<span style="margin-left: 8px;">@ <strong>{proxy.username}</strong></span>{/if}</span>
            <span>出口 <strong class="text-mono">{proxy.exit_ip || '—'}</strong></span>
            {#if proxy.exit_loc || proxy.exit_colo}<span class="text-muted">{[proxy.exit_loc, proxy.exit_colo].filter(Boolean).join(' · ')}</span>{/if}
            <span class="text-muted">测试 {formatUnixTime(proxy.last_tested_at)}</span>
            {#if proxy.last_error}
              <span class="cell-error" style="font-size: 11.5px;">{proxy.last_error}</span>
            {/if}
          </div>
          <div class="data-card-actions">
            <button class="btn btn-xs" type="button" onclick={() => openDetail(proxy)}>
              <Icon name="info" size={11} />
              详情
            </button>
            <button class="btn btn-xs" type="button" onclick={() => testProxies([proxy.id])} disabled={busy}>
              <Icon name="zap" size={11} />
              测试
            </button>
            <button class="btn btn-xs" type="button" onclick={() => copy(proxy.proxy_url, `card-${proxy.id}`, '代理 URL')}>
              <Icon name={copiedKey === `card-${proxy.id}` ? 'check' : 'copy'} size={11} />
              复制
            </button>
            <button class="btn btn-xs btn-danger" type="button" onclick={() => deleteIds([proxy.id])} disabled={busy}>
              <Icon name="trash" size={11} />
              删除
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
    </div>
  </div>

</div>

<Modal
  open={addOpen}
  title="添加代理"
  kicker="PROXY · 单条"
  subtitle="填写代理服务器信息，认证字段为可选"
  size="sm"
  onclose={() => { if (!addBusy) addOpen = false; }}
>
  <form id="add-proxy-form" class="form-section" onsubmit={submitAddProxy}>
    <div class="form-field">
      <span class="form-label">代理协议</span>
      <div class="segmented" style="display: flex; width: fit-content;">
        {#each schemeOptions as opt}
          <button type="button" class:active={addScheme === opt.value} onclick={() => changeScheme(opt.value)}>
            {opt.label}
          </button>
        {/each}
      </div>
      <p class="form-help">{schemeOptions.find((o) => o.value === addScheme)?.hint}</p>
    </div>

    <div class="form-grid form-grid-2">
      <label class="form-field" style="grid-column: span 2;">
        <span class="form-label form-label-required">主机 / IP</span>
        <input class="input" bind:value={addHost} placeholder="例如 127.0.0.1 或 example.com" required disabled={addBusy} autocomplete="off" />
      </label>
      <label class="form-field">
        <span class="form-label form-label-required">端口</span>
        <input class="input" type="number" min="1" max="65535" bind:value={addPort} required disabled={addBusy} />
      </label>
    </div>

    <div class="form-grid form-grid-2">
      <label class="form-field">
        <span class="form-label">用户名</span>
        <input class="input" bind:value={addUsername} placeholder="可选" disabled={addBusy} autocomplete="off" />
      </label>
      <label class="form-field">
        <span class="form-label">密码</span>
        <input class="input" type="password" bind:value={addPassword} placeholder="可选" disabled={addBusy} autocomplete="new-password" />
      </label>
    </div>

    <label class="toggle-row">
      <input type="checkbox" bind:checked={addTestAfter} disabled={addBusy} />
      <span>添加后自动测试连通性</span>
    </label>

    {#if addPreview}
      <div style="display: flex; align-items: center; gap: 8px; padding: 10px 12px; border: 1px solid var(--nx-rule); border-radius: var(--radius-md); background: var(--nx-paper-deep); font-family: var(--font-mono); font-size: 12px; color: var(--nx-ink-soft); overflow: hidden;">
        <Icon name="link" size={12} />
        <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{addPreview.replace(/:[^@/]*@/, ':***@')}</span>
      </div>
    {/if}
  </form>

  {#snippet footer()}
    <button class="btn" type="button" onclick={() => addOpen = false} disabled={addBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="add-proxy-form" disabled={addBusy || !addPreview} data-loading={addBusy}>
      {addBusy ? '保存中…' : '保存代理'}
    </button>
  {/snippet}
</Modal>

<Modal
  open={importOpen}
  title="批量导入代理"
  kicker="IMPORT"
  subtitle="每行一条，支持 http / socks5 / socks5h，可包含认证"
  size="md"
  onclose={() => { if (!importBusy) importOpen = false; }}
>
  <div class="form-section">
    <label class="form-field">
      <span class="form-label">代理列表</span>
      <textarea
        class="input text-mono"
        rows="10"
        bind:value={importText}
        placeholder={`http://user:pass@127.0.0.1:8080\nsocks5://127.0.0.1:1080\nsocks5h://user:pass@example.com:1080\n# 以 # 开头的行将被忽略`}
        aria-label="批量导入代理"
        disabled={importBusy}
        style="font-size: 12.5px; min-height: 200px;"
      ></textarea>
      <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px;">
        <p class="form-help">
          已识别 <strong style="color: var(--nx-ink);">{parsedImportLines.length}</strong> 条；空行与注释将被忽略。
        </p>
        {#if parsedImportLines.length > 0}
          <button type="button" class="btn-link" onclick={() => importText = ''} disabled={importBusy}>清空</button>
        {/if}
      </div>
    </label>
  </div>

  {#snippet footer()}
    <button class="btn" type="button" onclick={() => importOpen = false} disabled={importBusy}>取消</button>
    <button class="btn btn-primary" type="button" onclick={submitBulkImport} disabled={importBusy || parsedImportLines.length === 0} data-loading={importBusy}>
      {importBusy ? '导入中…' : `导入 ${parsedImportLines.length} 条`}
    </button>
  {/snippet}
</Modal>

<Modal
  open={detailOpen}
  title="代理详情"
  kicker={detailProxy ? `#${detailProxy.id}` : 'DETAIL'}
  size="md"
  onclose={() => { detailOpen = false; detailProxy = null; }}
>
  {#if detailProxy}
    <div class="account-detail-stack">
      <div class="account-detail-head">
        <div class="account-detail-title-row">
          <h3 class="text-mono" style="font-size: 17px;">{detailProxy.scheme}://{detailProxy.host}:{detailProxy.port}</h3>
          {#if testingIds.has(detailProxy.id)}
            <span class="pill"><span class="spinner" style="width: 10px; height: 10px;"></span> 测试中</span>
          {:else}
            <span class={statusPillClass(detailProxy.status)}>{statusLabel(detailProxy.status)}</span>
          {/if}
        </div>
        {#if detailProxy.last_error}
          <div class="notice-bar notice-error" style="margin: 4px 0 0;">
            <span class="notice-icon"><Icon name="alert-circle" size={14} /></span>
            <span class="notice-text">{detailProxy.last_error}</span>
          </div>
        {/if}
        <div class="account-detail-actions">
          <button class="btn btn-sm" type="button" onclick={() => copy(detailProxy?.proxy_url ?? '', `detail-${detailProxy.id}`, '代理 URL')}>
            <Icon name={copiedKey === `detail-${detailProxy.id}` ? 'check' : 'copy'} size={12} />
            复制完整 URL
          </button>
          <button class="btn btn-sm btn-primary" type="button" onclick={() => testProxies([detailProxy.id])} disabled={busy}>
            <Icon name="zap" size={12} />
            立即测试
          </button>
        </div>
      </div>

      <section class="account-detail-section">
        <h4>连接配置</h4>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">协议</span>
            <span class="detail-value"><span class="tag">{detailProxy.scheme.toUpperCase()}</span></span>
          </div>
          <div class="detail-row">
            <span class="detail-label">主机</span>
            <span class="detail-value detail-value-code">{detailProxy.host}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">端口</span>
            <span class="detail-value text-mono">{detailProxy.port}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">认证用户</span>
            <span class="detail-value">{detailProxy.username || '—'}</span>
          </div>
        </div>
      </section>

      <section class="account-detail-section">
        <h4>出口探测</h4>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">出口 IP</span>
            <span class="detail-value detail-value-code">{detailProxy.exit_ip || '—'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">区域</span>
            <span class="detail-value">{detailProxy.exit_loc || '—'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">机房</span>
            <span class="detail-value">{detailProxy.exit_colo || '—'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">HTTP 协议</span>
            <span class="detail-value">{detailProxy.trace_http || '—'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">TLS</span>
            <span class="detail-value">{detailProxy.trace_tls || '—'}</span>
          </div>
        </div>
      </section>

      <section class="account-detail-section">
        <h4>测试历史</h4>
        <div class="detail-list">
          <div class="detail-row">
            <span class="detail-label">最后测试</span>
            <span class="detail-value">{formatExactTime(detailProxy.last_tested_at)}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">HTTP 状态</span>
            <span class="detail-value">{detailProxy.last_http_status || '—'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">连通性</span>
            <span class="detail-value">{detailProxy.last_test_ok ? '通过' : '失败'}</span>
          </div>
        </div>
      </section>
    </div>
  {/if}

  {#snippet footer()}
    {#if detailProxy}
      <button class="btn btn-sm btn-danger" type="button" onclick={() => deleteIds([detailProxy.id])} disabled={busy}>
        <Icon name="trash" size={12} />
        删除代理
      </button>
      <span class="flex-spacer"></span>
      <button class="btn btn-sm" type="button" onclick={() => { detailOpen = false; detailProxy = null; }}>关闭</button>
    {/if}
  {/snippet}
</Modal>

<style>
/* =========================================
   Proxy Pool Page — Redesigned Dashboard
   ========================================= */

/* ---- Entrance Animation ---- */
@keyframes proxy-fade-up {
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0);    }
}

.p-anim-up {
  animation: proxy-fade-up 0.55s var(--ease-out, cubic-bezier(0.22,1,0.36,1)) both;
  animation-delay: var(--d, 0ms);
}

/* ---- Root ---- */
.p-root {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

/* ---- HEADER ---- */
.p-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--nx-rule);
  flex-wrap: wrap;
}

.p-header-main { display: grid; gap: 2px; }

.p-title {
  margin: 0;
  font-size: 26px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1.15;
  letter-spacing: -0.01em;
}

.p-desc {
  margin: 0;
  font-size: 13px;
  color: var(--nx-ink-muted);
}

.p-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

/* ---- HERO CARDS ---- */
.p-hero-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}

.p-hcard {
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

.p-hcard::after {
  content: '';
  position: absolute;
  top: 0; right: 0;
  width: 55%;
  height: 100%;
  background: linear-gradient(270deg, color-mix(in srgb, var(--nx-brand) 5%, transparent), transparent);
  pointer-events: none;
}

.p-hcard:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md);
  border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule));
}

.p-hcard--ok  { border-color: var(--nx-success-border); background: linear-gradient(135deg, var(--nx-success-bg) 0%, var(--nx-card) 55%); }
.p-hcard--warn { border-color: var(--nx-warning-border); background: linear-gradient(135deg, var(--nx-warning-bg) 0%, var(--nx-card) 55%); }
.p-hcard--err  { border-color: var(--nx-danger-border);  background: linear-gradient(135deg, var(--nx-danger-bg)  0%, var(--nx-card) 55%); }

.p-hcard--ok::after  { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-success) 6%, transparent), transparent); }
.p-hcard--warn::after { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-warning) 6%, transparent), transparent); }
.p-hcard--err::after  { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-danger)  6%, transparent), transparent); }

.p-hcard-icon {
  display: grid;
  place-items: center;
  width: 44px;
  height: 44px;
  flex-shrink: 0;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-brand) 12%, transparent);
  color: var(--nx-brand);
  border: 1px solid color-mix(in srgb, var(--nx-brand) 22%, transparent);
  transition: background 0.2s, color 0.2s;
}

.p-hcard--ok  .p-hcard-icon { background: color-mix(in srgb, var(--nx-success) 12%, transparent); color: var(--nx-success); border-color: color-mix(in srgb, var(--nx-success) 25%, transparent); }
.p-hcard--err  .p-hcard-icon { background: color-mix(in srgb, var(--nx-danger)  12%, transparent); color: var(--nx-danger);  border-color: color-mix(in srgb, var(--nx-danger)  25%, transparent); }

.p-hcard-body { display: grid; gap: 2px; min-width: 0; flex: 1; }

.p-hcard-val {
  font-family: var(--font-number);
  font-size: 22px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1;
  font-variant-numeric: tabular-nums lining-nums;
}

.p-hcard--ok  .p-hcard-val { color: var(--nx-success); }
.p-hcard--err  .p-hcard-val { color: var(--nx-danger);  }

.p-hcard-label {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  margin-top: 3px;
}

.p-hcard-meta {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  font-weight: 400;
  margin-top: 2px;
}

.p-hcard-meta-bar {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.p-rate-bar {
  height: 4px;
  border-radius: var(--radius-full);
  background: var(--nx-rule);
  overflow: hidden;
}

.p-rate-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--nx-success), color-mix(in srgb, var(--nx-success) 70%, #7fffbf));
  border-radius: inherit;
  transition: width 0.75s cubic-bezier(0.34, 1.18, 0.64, 1);
  box-shadow: 0 0 6px color-mix(in srgb, var(--nx-success) 40%, transparent);
}

/* ---- PANELS ---- */
.p-panel {
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  overflow: hidden;
  transition: box-shadow 0.2s var(--ease-out);
}

.p-panel:hover {
  box-shadow: var(--shadow-sm);
}

.p-panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 18px;
  border-bottom: 1px solid var(--nx-rule);
  background: color-mix(in srgb, var(--nx-paper-deep) 30%, var(--nx-card));
  flex-wrap: wrap;
}

.p-panel-head-left {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.p-panel-title {
  font-size: 14px;
  font-weight: 700;
  color: var(--nx-ink);
  white-space: nowrap;
}

.p-panel-sub {
  font-size: 10.5px;
  font-weight: 700;
  color: var(--nx-brand);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

.p-panel-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  border-radius: var(--radius-full);
  background: var(--nx-warning-bg);
  border: 1px solid var(--nx-warning-border);
  color: var(--nx-warning);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  transition: background 0.25s, color 0.25s, border-color 0.25s;
  white-space: nowrap;
}

.p-badge-ok {
  background: var(--nx-success-bg);
  border-color: var(--nx-success-border);
  color: var(--nx-success);
}

.p-panel-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.p-panel-body {
  padding: 18px;
}

/* Sample result chip */
.p-sample-chip {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  margin-top: 14px;
  border: 1px solid var(--nx-info-border);
  border-radius: var(--radius-md);
  background: var(--nx-info-bg);
}

.p-sample-icon {
  display: grid;
  place-items: center;
  width: 32px;
  height: 32px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--nx-info) 12%, transparent);
  color: var(--nx-info);
  flex-shrink: 0;
}

.p-sample-val {
  font-family: var(--font-number);
  font-size: 15px;
  font-weight: 700;
  color: var(--nx-info);
  font-variant-numeric: tabular-nums;
}

.p-sample-ips {
  margin-top: 3px;
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  font-family: var(--font-mono);
  word-break: break-all;
}

/* ---- RESPONSIVE ---- */
@media (max-width: 1024px) {
  .p-hero-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 640px) {
  .p-hero-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .p-header {
    flex-direction: column;
    align-items: flex-start;
  }
  .p-header-actions {
    width: 100%;
  }
}

/* =========================================
   Mihomo Config Panel — Redesigned
   ========================================= */

/* Mode selector cards */
.m-mode-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
  margin-bottom: 16px;
}

.m-mode-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 14px 10px 12px;
  border: 1.5px solid var(--nx-rule);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card));
  cursor: pointer;
  transition: border-color 0.18s var(--ease-out), background 0.18s var(--ease-out), transform 0.18s var(--ease-out), box-shadow 0.18s;
  font-family: inherit;
  text-align: center;
}

.m-mode-card:hover:not(:disabled) {
  border-color: color-mix(in srgb, var(--nx-brand) 40%, var(--nx-rule));
  background: color-mix(in srgb, var(--nx-brand) 5%, var(--nx-card));
  transform: translateY(-1px);
  box-shadow: var(--shadow-sm);
}

.m-mode-card:disabled { opacity: 0.55; cursor: not-allowed; }

.m-mode-active {
  border-color: var(--nx-brand) !important;
  background: color-mix(in srgb, var(--nx-brand) 8%, var(--nx-card)) !important;
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--nx-brand) 15%, transparent) !important;
}

.m-mode-icon {
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--nx-ink-muted) 10%, transparent);
  color: var(--nx-ink-muted);
  transition: background 0.18s, color 0.18s;
}

.m-mode-active .m-mode-icon {
  background: color-mix(in srgb, var(--nx-brand) 15%, transparent);
  color: var(--nx-brand);
}

.m-mode-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--nx-ink-soft);
  transition: color 0.18s;
}

.m-mode-active .m-mode-label { color: var(--nx-brand); }

.m-mode-hint {
  font-size: 11px;
  color: var(--nx-ink-muted);
  line-height: 1.35;
}

/* Status row */
.m-status-row {
  display: flex;
  align-items: flex-end;
  gap: 14px;
  margin-bottom: 4px;
  flex-wrap: wrap;
}

.m-field-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.m-field-group-stretch { flex: 1; min-width: 180px; }

.m-field-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

/* Proxy URL chip */
.m-url-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 12px;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-paper-deep) 60%, var(--nx-card));
  border: 1px solid var(--nx-rule);
  height: 38px;
  transition: border-color 0.25s, background 0.25s;
  overflow: hidden;
}

.m-url-chip-on {
  border-color: var(--nx-success-border);
  background: var(--nx-success-bg);
}

.m-url-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--nx-ink-muted);
  flex-shrink: 0;
  transition: background 0.25s, box-shadow 0.25s;
}

.m-url-chip-on .m-url-dot {
  background: var(--nx-success);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--nx-success) 25%, transparent);
  animation: m-pulse 2s ease-in-out infinite;
}

@keyframes m-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.55; transform: scale(1.35); }
}

.m-url-text {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--nx-ink-soft);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.m-url-status {
  font-size: 10px;
  font-weight: 700;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  white-space: nowrap;
  transition: color 0.25s;
  flex-shrink: 0;
}

.m-url-chip-on .m-url-status { color: var(--nx-success); }

/* Section dividers */
.m-divider {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 20px 0 14px;
}

.m-divider > span {
  font-size: 10.5px;
  font-weight: 700;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  white-space: nowrap;
}

.m-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--nx-rule);
}

.m-divider-muted > span { opacity: 0.65; }

/* Subscription URL input with icon */
.m-url-input {
  position: relative;
}

.m-url-input-icon {
  position: absolute;
  left: 12px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--nx-ink-muted);
  pointer-events: none;
  display: flex;
  align-items: center;
}

.m-url-input :global(.input) {
  padding-left: 34px;
}

/* Code-style textarea */
.m-code-area {
  font-family: var(--font-mono);
  font-size: 12.5px;
  min-height: 160px;
  background: color-mix(in srgb, var(--nx-paper-deep) 65%, var(--nx-card));
  color: var(--nx-ink-soft);
  resize: vertical;
  line-height: 1.65;
}

/* Twin column layout */
.m-twin {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.m-twin-col { display: flex; flex-direction: column; }

/* Node actions row */
.m-node-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
  flex-wrap: wrap;
}

@media (max-width: 860px) {
  .m-twin { grid-template-columns: 1fr; }
  .m-mode-grid { grid-template-columns: repeat(3, 1fr); }
}

@media (max-width: 560px) {
  .m-mode-grid { grid-template-columns: 1fr; }
  .m-status-row { flex-direction: column; align-items: stretch; }
}
</style>
