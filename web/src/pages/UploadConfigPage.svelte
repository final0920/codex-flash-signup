<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Panel from '../components/Panel.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { toast } from '../lib/toast';

  type AetherStats = {
    account_uploaded: number;
    account_not_uploaded: number;
    total_attempted: number;
    success_count: number;
    failed_count: number;
    skipped_count: number;
    last_success_at: number;
    last_failed_at: number;
    last_message: string;
    updated_at: number;
  };

  type AetherService = {
    id: number;
    name: string;
    api_url: string;
    provider_id: string;
    provider_name: string;
    oauth_provider_ids: string[];
    oauth_provider_names: string[];
    chatgpt_web_provider_id: string;
    chatgpt_web_provider_name: string;
    proxy_node_id: string;
    proxy_node_name: string;
    proxy_node_mode: 'none' | 'fixed' | 'random';
    retry_count: number;
    has_management_token: number;
    enabled: number;
    priority: number;
    created_at: number;
    updated_at: number;
  };

  type AetherConfig = {
    stats: AetherStats;
    services: AetherService[];
  };

  type ServiceForm = {
    id: number;
    name: string;
    api_url: string;
    management_token: string;
    provider_id: string;
    provider_name: string;
    oauth_provider_ids: string[];
    oauth_provider_names: string[];
    chatgpt_web_provider_id: string;
    chatgpt_web_provider_name: string;
    proxy_node_id: string;
    proxy_node_name: string;
    proxy_node_mode: 'none' | 'fixed' | 'random';
    retry_count: number;
    enabled: boolean;
    priority: number;
  };

  type AetherPool = {
    provider_id: string;
    provider_name: string;
    provider_type: string;
    total_keys: number;
    active_keys: number;
    cooldown_count: number;
    pool_enabled: number;
  };

  type AetherProxyNode = {
    id: string;
    name: string;
    ip: string;
    port: number;
    region: string;
    status: string;
    is_manual: number;
    tunnel_mode: number;
    tunnel_connected: number;
  };

  const emptyStats: AetherStats = {
    account_uploaded: 0,
    account_not_uploaded: 0,
    total_attempted: 0,
    success_count: 0,
    failed_count: 0,
    skipped_count: 0,
    last_success_at: 0,
    last_failed_at: 0,
    last_message: '',
    updated_at: 0
  };

  let config: AetherConfig = $state({ stats: emptyStats, services: [] });
  let initialLoaded = $state(false);
  let loading = $state(false);
  let busy = $state(false);
  let testingId: number | null = $state(null);
  let formOpen = $state(false);
  let form: ServiceForm = $state(createEmptyForm());
  let optionPools: AetherPool[] = $state([]);
  let optionProxyNodes: AetherProxyNode[] = $state([]);
  let optionsLoading = $state(false);
  let optionsError = $state('');
  let showAdvanced = $state(false);

  function normalizeProviderType(providerType: string | null | undefined) {
    return `${providerType ?? ''}`.trim().toLowerCase();
  }

  function isCodexOauthPool(pool: AetherPool) {
    return normalizeProviderType(pool.provider_type) === 'codex';
  }

  function isChatgptWebPool(pool: AetherPool) {
    return normalizeProviderType(pool.provider_type) === 'chatgpt_web';
  }

  let oauthOptionPools = $derived(optionPools.filter(isCodexOauthPool));
  let webOptionPools = $derived(optionPools.filter(isChatgptWebPool));

  let statCards = $derived([
    { label: '已上传账号', value: config.stats.account_uploaded, icon: 'upload' as const, klass: 'stat-chip-success' },
    { label: '未上传账号', value: config.stats.account_not_uploaded, icon: 'database' as const, klass: '' },
    { label: 'Aether 成功', value: config.stats.success_count, icon: 'check-circle' as const, klass: 'stat-chip-info' },
    { label: 'Aether 失败', value: config.stats.failed_count, icon: 'alert-circle' as const, klass: 'stat-chip-danger' },
    { label: '跳过', value: config.stats.skipped_count, icon: 'clock' as const, klass: 'stat-chip-warning' }
  ]);

  function createEmptyForm(): ServiceForm {
    return {
      id: 0,
      name: 'Aether 主服务',
      api_url: '',
      management_token: '',
      provider_id: '',
      provider_name: '',
      oauth_provider_ids: [],
      oauth_provider_names: [],
      chatgpt_web_provider_id: '',
      chatgpt_web_provider_name: '',
      proxy_node_id: '',
      proxy_node_name: '',
      proxy_node_mode: 'none',
      retry_count: 2,
      enabled: true,
      priority: 0
    };
  }

  async function loadConfig(silent = false) {
    if (!silent) loading = true;
    try {
      const response = await fetch('/api/upload/aether');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      config = await response.json();
    } catch (err) {
      toast.error(`上传配置加载失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      loading = false;
      initialLoaded = true;
    }
  }

  function openCreate() {
    form = createEmptyForm();
    optionPools = [];
    optionProxyNodes = [];
    optionsError = '';
    showAdvanced = false;
    formOpen = true;
  }

  function compactStringList(values: Array<string | null | undefined> | undefined) {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const value of values ?? []) {
      const item = `${value ?? ''}`.trim();
      if (!item || seen.has(item)) continue;
      seen.add(item);
      result.push(item);
    }
    return result;
  }

  function serviceOauthIds(service: AetherService) {
    const ids = compactStringList(service.oauth_provider_ids ?? []);
    if (ids.length > 0) return ids;
    return service.provider_id ? [service.provider_id] : [];
  }

  function serviceOauthNames(service: AetherService, ids = serviceOauthIds(service)) {
    const names = service.oauth_provider_names ?? [];
    return ids.map((id, index) => names[index] || (index === 0 ? service.provider_name : '') || id);
  }

  function optionPoolName(providerId: string) {
    return optionPools.find((item) => item.provider_id === providerId)?.provider_name || '';
  }

  function formNameForProvider(providerId: string) {
    const index = form.oauth_provider_ids.indexOf(providerId);
    return index >= 0 ? form.oauth_provider_names[index] || '' : '';
  }

  function oauthNamesForIds(ids: string[]) {
    return ids.map((id, index) => {
      const current = formNameForProvider(id);
      if (current) return current;
      if (index === 0 && form.provider_id === id && form.provider_name.trim()) return form.provider_name.trim();
      return optionPoolName(id) || id;
    });
  }

  function syncPrimaryOauthProvider() {
    const firstId = form.oauth_provider_ids[0] ?? '';
    if (!firstId) {
      form.provider_id = '';
      form.provider_name = '';
      return;
    }
    form.provider_id = firstId;
    form.provider_name = form.oauth_provider_names[0] || optionPoolName(firstId) || firstId;
  }

  function setOauthProviderIds(ids: string[]) {
    const nextIds = compactStringList(ids);
    form.oauth_provider_ids = nextIds;
    form.oauth_provider_names = oauthNamesForIds(nextIds);
    syncPrimaryOauthProvider();
  }

  function toggleOauthPool(providerId: string, checked: boolean) {
    if (checked) {
      setOauthProviderIds([...form.oauth_provider_ids, providerId]);
    } else {
      setOauthProviderIds(form.oauth_provider_ids.filter((id) => id !== providerId));
    }
  }

  function isOauthPoolSelected(providerId: string) {
    return form.oauth_provider_ids.includes(providerId);
  }

  function selectedOauthPools() {
    return form.oauth_provider_ids.map((id, index) => ({
      id,
      name: form.oauth_provider_names[index] || optionPoolName(id) || id
    }));
  }

  function normalizedServicePayload(payload: Partial<ServiceForm> & { id?: number }) {
    const ids = compactStringList(payload.oauth_provider_ids ?? []);
    const manualId = `${payload.provider_id ?? ''}`.trim();
    const providerIds = ids.length > 1 ? ids : (manualId ? [manualId] : ids);
    const names = providerIds.map((id, index) => {
      const byIndex = `${payload.oauth_provider_names?.[index] ?? ''}`.trim();
      const manualName = `${payload.provider_name ?? ''}`.trim();
      if (byIndex) return byIndex;
      if (index === 0 && manualName) return manualName;
      return optionPoolName(id) || id;
    });
    return {
      ...payload,
      provider_id: providerIds[0] ?? manualId,
      provider_name: names[0] ?? `${payload.provider_name ?? ''}`.trim(),
      oauth_provider_ids: providerIds,
      oauth_provider_names: names
    };
  }

  function openEdit(service: AetherService) {
    const oauthIds = serviceOauthIds(service);
    const oauthNames = serviceOauthNames(service, oauthIds);
    form = {
      id: service.id,
      name: service.name,
      api_url: service.api_url,
      management_token: '',
      provider_id: oauthIds[0] || service.provider_id,
      provider_name: oauthNames[0] || service.provider_name,
      oauth_provider_ids: oauthIds,
      oauth_provider_names: oauthNames,
      chatgpt_web_provider_id: service.chatgpt_web_provider_id,
      chatgpt_web_provider_name: service.chatgpt_web_provider_name,
      proxy_node_id: service.proxy_node_id,
      proxy_node_name: service.proxy_node_name,
      proxy_node_mode: service.proxy_node_mode ?? 'fixed',
      retry_count: service.retry_count ?? 2,
      enabled: Boolean(service.enabled),
      priority: service.priority
    };
    optionPools = [];
    optionProxyNodes = [];
    optionsError = '';
    showAdvanced = false;
    formOpen = true;
  }

  function closeForm() {
    formOpen = false;
  }

  async function submitForm(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    try {
      const response = await fetch('/api/upload/aether/service', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalizedServicePayload(form))
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || '保存失败');
      toast.success(result.message || 'Aether 上传服务已保存');
      formOpen = false;
      await loadConfig(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busy = false;
    }
  }

  async function testService(payload: Partial<ServiceForm> & { id?: number }) {
    testingId = payload.id ?? 0;
    try {
      const response = await fetch('/api/upload/aether/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalizedServicePayload(payload))
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || '测试失败');
      if (result.success) toast.success(result.provider_name ? `${result.message}：${result.provider_name}` : result.message);
      else toast.error(result.message || '连接失败');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      testingId = null;
    }
  }

  async function loadAetherOptions() {
    optionsLoading = true;
    optionsError = '';
    try {
      const response = await fetch('/api/upload/aether/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: form.id,
          api_url: form.api_url.trim(),
          management_token: form.management_token.trim()
        })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || '读取选项失败');
      const nextPools: AetherPool[] = result.pools ?? [];
      const validOauthIds = new Set(nextPools.filter(isCodexOauthPool).map((pool) => pool.provider_id));
      optionPools = nextPools;
      optionProxyNodes = result.proxy_nodes ?? [];
      optionsError = result.proxy_nodes_error || '';
      if (form.oauth_provider_ids.length > 0) {
        setOauthProviderIds(form.oauth_provider_ids.filter((id) => validOauthIds.has(id)));
      } else if (form.provider_id && validOauthIds.has(form.provider_id)) {
        setOauthProviderIds([form.provider_id]);
      }
      const parts = [`Provider ${optionPools.length}`, `Codex OAuth ${oauthOptionPools.length}`];
      parts.push(`代理节点 ${optionProxyNodes.length}`);
      toast.success(`已读取 ${parts.join(' · ')}`);
      if (optionsError) toast.info(optionsError);
    } catch (err) {
      optionPools = [];
      optionProxyNodes = [];
      optionsError = err instanceof Error ? err.message : String(err);
      toast.error(optionsError);
    } finally {
      optionsLoading = false;
    }
  }

  function selectPool(kind: 'oauth' | 'web', providerId: string) {
    const pool = optionPools.find((item) => item.provider_id === providerId);
    if (kind === 'oauth') {
      setOauthProviderIds(providerId ? [providerId] : []);
    } else {
      form.chatgpt_web_provider_id = providerId;
      form.chatgpt_web_provider_name = pool?.provider_name ?? '';
    }
  }

  function selectProxyNode(nodeId: string) {
    const node = optionProxyNodes.find((item) => item.id === nodeId);
    form.proxy_node_id = nodeId;
    form.proxy_node_name = node?.name ?? '';
  }

  async function deleteService(service: AetherService) {
    if (!window.confirm(`确认删除 Aether 上传服务「${service.name}」？`)) return;
    busy = true;
    try {
      const response = await fetch('/api/upload/aether/service/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: service.id })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || '删除失败');
      toast.success(result.message || '服务已删除');
      await loadConfig(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busy = false;
    }
  }

  function formatTime(value: number | undefined | null) {
    if (!value) return '—';
    return new Date(value * 1000).toLocaleString();
  }

  function providerDisplay(service: AetherService) {
    const ids = serviceOauthIds(service);
    const names = serviceOauthNames(service, ids);
    if (ids.length > 1) return `${ids.length} 个 OAuth 号池`;
    return names[0] || service.provider_name || service.provider_id || '未配置';
  }

  function providerIdsList(service: AetherService) {
    return serviceOauthIds(service);
  }

  function webProviderDisplay(service: AetherService) {
    if (!service.chatgpt_web_provider_id) return '未配置';
    return service.chatgpt_web_provider_name || service.chatgpt_web_provider_id;
  }

  function proxyDisplay(service: AetherService) {
    if (service.proxy_node_mode === 'random') return '随机在线节点';
    if (service.proxy_node_mode === 'none') return '不使用代理';
    return service.proxy_node_name || service.proxy_node_id || '不使用代理';
  }

  function proxyModeLabel(mode: AetherService['proxy_node_mode']) {
    if (mode === 'random') return '随机模式';
    if (mode === 'fixed') return '固定节点';
    return '不启用';
  }

  let optionsCanLoad = $derived(!optionsLoading && !busy && (form.id > 0 || (form.api_url.trim() !== '' && form.management_token.trim() !== '')));

  onMount(() => {
    loadConfig();
  });
</script>

<PageHeader
  title="上传配置"
  subtitle="AETHER"
  description="管理 Aether 上传服务、号池映射与代理节点；所有启用中的服务会参与账号上传。"
>
  <button class="btn" type="button" onclick={() => loadConfig(false)} disabled={loading || busy}>
    <Icon name="refresh" size={14} />
    刷新
  </button>
  <button class="btn btn-primary" type="button" onclick={openCreate} disabled={busy}>
    <Icon name="plus" size={14} />
    新建配置
  </button>
</PageHeader>

<section class="stat-strip" aria-label="Aether 上传统计">
  {#each statCards as item}
    <div class={`stat-chip ${item.klass}`}>
      <span class="stat-chip-label"><Icon name={item.icon} size={12} /> {item.label}</span>
      <span class="stat-chip-value">{item.value}</span>
    </div>
  {/each}
</section>

<Panel title="本地上传时间线" subtitle="累计与最近一次记录" compact>
  <div class="upload-timeline">
    <div class="upload-timeline-item">
      <span class="upload-timeline-label"><Icon name="activity" size={12} /> 累计尝试</span>
      <span class="upload-timeline-value">{config.stats.total_attempted}</span>
    </div>
    <div class="upload-timeline-item">
      <span class="upload-timeline-label"><Icon name="check-circle" size={12} /> 最近成功</span>
      <span class="upload-timeline-value">{formatTime(config.stats.last_success_at)}</span>
    </div>
    <div class="upload-timeline-item">
      <span class="upload-timeline-label"><Icon name="alert-circle" size={12} /> 最近失败</span>
      <span class="upload-timeline-value">{formatTime(config.stats.last_failed_at)}</span>
    </div>
    <div class="upload-timeline-item upload-timeline-item-wide">
      <span class="upload-timeline-label"><Icon name="info" size={12} /> 最近消息</span>
      <span class="upload-timeline-value upload-timeline-message">{config.stats.last_message || '—'}</span>
    </div>
  </div>
</Panel>

<Panel title="Aether 上传服务" subtitle={`${config.services.length} 个配置`}>
  {#snippet actions()}
    <button class="btn btn-sm" type="button" onclick={() => loadConfig(false)} disabled={loading || busy}>
      <Icon name="refresh" size={12} />
      刷新
    </button>
    <button class="btn btn-sm btn-primary" type="button" onclick={openCreate} disabled={busy}>
      <Icon name="plus" size={12} />
      新建
    </button>
  {/snippet}

  {#if !initialLoaded}
    <div class="upload-service-grid">
      {#each Array(2) as _, index (index)}
        <Skeleton height="220px" rounded="md" />
      {/each}
    </div>
  {:else if config.services.length === 0}
    <EmptyState title="暂无上传配置" message="先添加 Aether 地址、管理员 Token 和 Provider ID" icon="upload">
      {#snippet action()}
        <button class="btn btn-sm btn-primary" type="button" onclick={openCreate}>
          <Icon name="plus" size={12} />
          新建配置
        </button>
      {/snippet}
    </EmptyState>
  {:else}
    <div class="upload-service-grid" role="list">
      {#each config.services as service (service.id)}
        <article class="upload-service" role="listitem" class:upload-service-disabled={!service.enabled}>
          <header class="upload-service-head">
            <div class="upload-service-identity">
              <div class="upload-service-title">
                <Icon name="upload" size={14} />
                <span>{service.name}</span>
              </div>
              <span class="upload-service-url text-mono" title={service.api_url}>{service.api_url}</span>
            </div>
            <div class="upload-service-status">
              <StatusBadge label={service.enabled ? '启用' : '停用'} variant={service.enabled ? 'active' : 'not-uploaded'} />
              <span class="upload-service-priority">优先级 {service.priority}</span>
            </div>
          </header>

          <div class="upload-service-body">
            <div class="upload-service-cell">
              <span class="upload-service-label">OAuth 账号池</span>
              <span class="upload-service-value">{providerDisplay(service)}</span>
              {#if providerIdsList(service).length > 0}
                <div class="upload-service-tags">
                  {#each providerIdsList(service).slice(0, 3) as id (id)}
                    <span class="tag text-mono">{id}</span>
                  {/each}
                  {#if providerIdsList(service).length > 3}
                    <span class="tag tag-info">+{providerIdsList(service).length - 3}</span>
                  {/if}
                </div>
              {:else}
                <span class="upload-service-meta">未配置</span>
              {/if}
            </div>

            <div class="upload-service-cell">
              <span class="upload-service-label">ChatGPT Web</span>
              <span class="upload-service-value">{webProviderDisplay(service)}</span>
              {#if service.chatgpt_web_provider_id}
                <span class="upload-service-meta text-mono">{service.chatgpt_web_provider_id}</span>
              {:else}
                <span class="upload-service-meta">未启用</span>
              {/if}
            </div>

            <div class="upload-service-cell">
              <span class="upload-service-label">代理节点</span>
              <span class="upload-service-value">{proxyDisplay(service)}</span>
              <span class="upload-service-meta">{proxyModeLabel(service.proxy_node_mode)}</span>
            </div>

            <div class="upload-service-cell">
              <span class="upload-service-label">失败重试</span>
              <span class="upload-service-value">{service.retry_count} 次</span>
              <span class="upload-service-meta">{service.has_management_token ? '已配置 Token' : '未保存 Token'}</span>
            </div>
          </div>

          <footer class="upload-service-foot">
            <button class="btn btn-sm" type="button" onclick={() => testService({ id: service.id })} disabled={testingId !== null || busy} data-loading={testingId === service.id}>
              <Icon name={testingId === service.id ? 'refresh' : 'wifi'} size={12} />
              测试
            </button>
            <button class="btn btn-sm" type="button" onclick={() => openEdit(service)} disabled={busy}>
              <Icon name="edit" size={12} />
              编辑
            </button>
            <span class="flex-spacer"></span>
            <button class="btn btn-sm btn-danger" type="button" onclick={() => deleteService(service)} disabled={busy}>
              <Icon name="trash" size={12} />
              删除
            </button>
          </footer>
        </article>
      {/each}
    </div>
  {/if}
</Panel>

<Modal
  open={formOpen}
  title={form.id ? '编辑 Aether 上传服务' : '新建 Aether 上传服务'}
  kicker="AETHER"
  subtitle="填写连接信息后读取号池与代理节点选项"
  size="lg"
  onclose={closeForm}
>
  <form id="aether-service-form" class="upload-form" onsubmit={submitForm}>
    <section class="form-section">
      <div class="form-section-head">
        <h4>基础信息</h4>
        <p>命名与启停策略</p>
      </div>
      <div class="form-grid form-grid-2">
        <label class="form-field">
          <span class="form-label">名称</span>
          <input class="input" bind:value={form.name} required placeholder="Aether 主服务" />
        </label>
        <label class="form-field">
          <span class="form-label">优先级</span>
          <input class="input" type="number" bind:value={form.priority} />
        </label>
        <label class="form-field">
          <span class="form-label">失败重试次数</span>
          <input class="input" type="number" min="0" max="10" bind:value={form.retry_count} />
        </label>
        <label class="form-field">
          <span class="form-label">启用状态</span>
          <label class="form-field-inline form-toggle-row">
            <input type="checkbox" bind:checked={form.enabled} />
            <span>{form.enabled ? '启用此上传服务' : '已停用'}</span>
          </label>
        </label>
      </div>
    </section>

    <section class="form-section">
      <div class="form-section-head">
        <h4>连接 / 鉴权</h4>
        <p>填好地址与 Token 后读取号池</p>
      </div>
      <label class="form-field">
        <span class="form-label">Aether 地址</span>
        <input class="input" bind:value={form.api_url} required placeholder="https://aether.example.com" />
      </label>
      <label class="form-field">
        <span class="form-label">管理员 Token</span>
        <input class="input" type="password" bind:value={form.management_token} placeholder={form.id ? '留空则沿用已保存 Token' : 'ae_...'} />
      </label>
      <div class="upload-options-row">
        <button class="btn btn-sm" type="button" onclick={loadAetherOptions} disabled={!optionsCanLoad} data-loading={optionsLoading}>
          <Icon name="download" size={12} />
          读取号池 / 代理节点
        </button>
        {#if optionsLoading}
          <span class="upload-options-hint"><span class="spinner"></span> 正在读取选项…</span>
        {:else if optionPools.length > 0}
          <span class="upload-options-hint">
            已读取 Provider {optionPools.length} · Codex OAuth {oauthOptionPools.length} · Web {webOptionPools.length} · 代理节点 {optionProxyNodes.length}
          </span>
        {/if}
        {#if optionsError}
          <span class="upload-options-hint text-danger">{optionsError}</span>
        {/if}
      </div>
    </section>

    {#if optionPools.length > 0}
      <section class="form-section">
        <div class="form-section-head">
          <h4>OAuth 账号池</h4>
          <p>支持多选合并上传</p>
        </div>
        {#if oauthOptionPools.length > 0}
          <div class="option-check-list">
            {#each oauthOptionPools as pool (pool.provider_id)}
              <label class="option-check">
                <input
                  type="checkbox"
                  checked={isOauthPoolSelected(pool.provider_id)}
                  onchange={(event) => toggleOauthPool(pool.provider_id, (event.currentTarget as HTMLInputElement).checked)}
                />
                <span class="option-check-body">
                  <span class="option-check-title">{pool.provider_name || pool.provider_id}</span>
                  <span class="option-check-meta">{pool.provider_type || 'provider'} · {pool.active_keys}/{pool.total_keys}</span>
                </span>
              </label>
            {/each}
          </div>
        {:else}
          <p class="form-help text-danger">未读取到 Codex OAuth 固定池</p>
        {/if}
        {#if selectedOauthPools().length > 0}
          <div class="selected-pool-row">
            {#each selectedOauthPools() as pool (pool.id)}
              <span class="tag tag-info">{pool.name}</span>
            {/each}
          </div>
        {/if}
      </section>

      <section class="form-section">
        <div class="form-section-head">
          <h4>ChatGPT Web 账号池</h4>
          <p>可选；用于上传 Web 类型账号</p>
        </div>
        <label class="form-field">
          <span class="form-label">选择号池</span>
          <select class="input" bind:value={form.chatgpt_web_provider_id} onchange={(event) => selectPool('web', (event.currentTarget as HTMLSelectElement).value)}>
            <option value="">不配置 Web 账号池</option>
            {#each webOptionPools as pool (pool.provider_id)}
              <option value={pool.provider_id}>
                {pool.provider_name || pool.provider_id} · {pool.provider_type || 'provider'} · {pool.active_keys}/{pool.total_keys}
              </option>
            {/each}
          </select>
        </label>
      </section>
    {/if}

    <section class="form-section">
      <div class="form-section-head">
        <h4>代理节点</h4>
        <p>控制上传请求的出口节点</p>
      </div>
      <label class="form-field">
        <span class="form-label">分配模式</span>
        <select class="input" bind:value={form.proxy_node_mode}>
          <option value="none">不使用代理节点</option>
          <option value="fixed">固定代理节点</option>
          <option value="random">随机在线节点</option>
        </select>
      </label>
      {#if form.proxy_node_mode === 'fixed'}
        {#if optionProxyNodes.length > 0}
          <label class="form-field">
            <span class="form-label">代理节点</span>
            <select class="input" bind:value={form.proxy_node_id} onchange={(event) => selectProxyNode((event.currentTarget as HTMLSelectElement).value)}>
              <option value="">— 未选择 —</option>
              {#each optionProxyNodes as node (node.id)}
                <option value={node.id}>
                  {node.name || node.id} · {node.region || node.status || 'online'} · {node.ip}{node.port ? `:${node.port}` : ''}
                </option>
              {/each}
            </select>
          </label>
        {/if}
        <div class="form-grid form-grid-2">
          <label class="form-field">
            <span class="form-label">代理节点 ID</span>
            <input class="input text-mono" bind:value={form.proxy_node_id} placeholder="可选" />
          </label>
          <label class="form-field">
            <span class="form-label">代理节点名称</span>
            <input class="input" bind:value={form.proxy_node_name} placeholder="可选" />
          </label>
        </div>
      {/if}
    </section>

    <section class="form-section">
      <div class="form-section-head">
        <h4>手动 Provider 覆盖</h4>
        <p>未读取号池时可在此手动填写</p>
        <button class="btn btn-xs btn-ghost" type="button" onclick={() => (showAdvanced = !showAdvanced)}>
          {showAdvanced ? '收起' : '展开'}
        </button>
      </div>
      {#if showAdvanced}
        <div class="form-grid form-grid-2">
          <label class="form-field">
            <span class="form-label">主 OAuth Provider ID</span>
            <input class="input text-mono" bind:value={form.provider_id} required readonly={form.oauth_provider_ids.length > 1} placeholder="provider-codex" />
          </label>
          <label class="form-field">
            <span class="form-label">主 OAuth Provider 名称</span>
            <input class="input" bind:value={form.provider_name} readonly={form.oauth_provider_ids.length > 1} placeholder="正常号池" />
          </label>
          <label class="form-field">
            <span class="form-label">ChatGPT Web Provider ID</span>
            <input class="input text-mono" bind:value={form.chatgpt_web_provider_id} placeholder="可选" />
          </label>
          <label class="form-field">
            <span class="form-label">ChatGPT Web Provider 名称</span>
            <input class="input" bind:value={form.chatgpt_web_provider_name} placeholder="可选" />
          </label>
        </div>
      {/if}
    </section>
  </form>

  {#snippet footer()}
    <button class="btn btn-sm" type="button" onclick={() => testService(form)} disabled={testingId !== null || busy}>
      <Icon name="wifi" size={12} />
      测试连接
    </button>
    <span class="flex-spacer"></span>
    <button class="btn btn-sm" type="button" onclick={closeForm} disabled={busy}>取消</button>
    <button class="btn btn-sm btn-primary" type="submit" form="aether-service-form" disabled={busy} data-loading={busy}>
      <Icon name="check" size={12} />
      保存
    </button>
  {/snippet}
</Modal>
