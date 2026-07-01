<script lang="ts">
  import { onMount } from 'svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { toast } from '../lib/toast';

  type DomainRule = {
    id: number;
    pattern: string;
    base_domain: string;
    wildcard_depth: number;
    is_active: number;
    created_at: number;
    updated_at: number;
  };

  type MailConfig = {
    backend: string;
    transport: string;
    base_url: string;
    has_api_key: number;
    api_key_preview: string;
    ws_url: string;
    ws_started: number;
    ws_connected: number;
    ws_subscribed: number;
    ws_cached_records: number;
    ws_last_error: string;
    domains: DomainRule[];
  };

  type FetchAction = 'codes' | 'messages' | 'message' | 'message-code';
  type MailBackend = 'rapid_inbox' | 'rapid_inbox_head' | 'otprelay' | 'temp_mail';

  const legacyFetchActions: { value: FetchAction; label: string; description: string; needId: boolean; allowLimit: boolean }[] = [
    { value: 'codes', label: '验证码列表', description: '提取最近邮件中的验证码', needId: false, allowLimit: true },
    { value: 'messages', label: '邮件列表', description: '查看完整邮件元信息', needId: false, allowLimit: true },
    { value: 'message', label: '邮件详情', description: '按 Delivery ID 读取', needId: true, allowLimit: false },
    { value: 'message-code', label: '单封验证码', description: '按 Delivery ID 抽取验证码', needId: true, allowLimit: false }
  ];
  const otprelayFetchActions: { value: FetchAction; label: string; description: string; needId: boolean; allowLimit: boolean }[] = [
    { value: 'codes', label: '验证码领取', description: '通过 OTPRelay C 直接领取最新验证码', needId: false, allowLimit: false }
  ];
  const tempMailFetchActions: { value: FetchAction; label: string; description: string; needId: boolean; allowLimit: boolean }[] = [
    { value: 'codes', label: '验证码列表', description: '从 Temp-Mail 原始邮件中抽取验证码', needId: false, allowLimit: true },
    { value: 'messages', label: '邮件列表', description: '查看 Temp-Mail 原始邮件列表', needId: false, allowLimit: true }
  ];

  let config: MailConfig = $state({
    backend: 'rapid_inbox',
    transport: 'http',
    base_url: '',
    has_api_key: 0,
    api_key_preview: '',
    ws_url: '',
    ws_started: 0,
    ws_connected: 0,
    ws_subscribed: 0,
    ws_cached_records: 0,
    ws_last_error: '',
    domains: []
  });
  let initialLoaded = $state(false);

  let configOpen = $state(false);
  let configBackend = $state<MailBackend>('rapid_inbox');
  let configTransport = $state<'http' | 'ws'>('http');
  let configBaseUrl = $state('');
  let configApiKey = $state('');
  let configClearKey = $state(false);
  let configBusy = $state(false);

  let domainOpen = $state(false);
  let domainPattern = $state('');
  let domainBusy = $state(false);
  let domainBatchOpen = $state(false);
  let domainBatchText = $state('');
  let domainBatchBusy = $state(false);

  let selectedDomainIds: number[] = $state([]);

  let mailbox = $state('');
  let action: FetchAction = $state('codes');
  let deliveryId = $state('');
  let limit = $state(20);
  let fetchBusy = $state(false);
  let fetchResult = $state('');
  let fetchStatus = $state('');
  let fetchEndpoint = $state('');
  let copiedKey: string | null = $state(null);

  let fetchActions = $derived(config.backend === 'otprelay' ? otprelayFetchActions : config.backend === 'temp_mail' ? tempMailFetchActions : legacyFetchActions);
  let activeAction = $derived(fetchActions.find((a) => a.value === action) ?? fetchActions[0]);
  let parsedFetch = $derived(parseResult(fetchResult));
  let domainPreview = $derived(buildDomainPreview(domainPattern.trim()));
  let domainBatchItems = $derived(parseDomainBatch(domainBatchText));

  let fetchStatusOk = $derived(fetchStatus && fetchStatus.startsWith('2'));

  function buildDomainPreview(pattern: string) {
    if (!pattern) return null;
    const wildcards = (pattern.match(/\*/g) ?? []).length;
    const base = pattern.replace(/\*+\./g, '');
    return { base, wildcards };
  }

  function parseDomainBatch(value: string) {
    return value
      .split(/[\r\n,;]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  async function loadConfig() {
    try {
      const response = await fetch('/api/mail/config');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      config = await response.json();
      configBackend = normalizeBackend(config.backend);
      configTransport = config.transport === 'ws' ? 'ws' : 'http';
      if (!fetchActions.some((item) => item.value === action)) {
        action = fetchActions[0].value;
      }
      selectedDomainIds = selectedDomainIds.filter((id) => config.domains.some((item) => item.id === id));
    } catch (err) {
      toast.error(`配置加载失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      initialLoaded = true;
    }
  }

  function openConfigModal() {
    configBackend = normalizeBackend(config.backend);
    configTransport = config.transport === 'ws' ? 'ws' : 'http';
    configBaseUrl = config.base_url || defaultBaseUrl(configBackend);
    configApiKey = '';
    configClearKey = false;
    configOpen = true;
  }

  function selectConfigBackend(value: MailBackend) {
    const current = configBaseUrl.trim();
    const oldDefault = defaultBaseUrl(configBackend);
    const nextDefault = defaultBaseUrl(value);
    configBackend = value;
    if (!current || current === oldDefault) configBaseUrl = nextDefault;
    if (value !== 'otprelay') configTransport = 'http';
  }

  async function submitConfig(event: SubmitEvent) {
    event.preventDefault();
    configBusy = true;
    try {
      const body: { base_url: string; api_key?: string; backend: string; transport: string } = {
        base_url: configBaseUrl.trim(),
        backend: configBackend,
        transport: configBackend === 'otprelay' ? configTransport : 'http'
      };
      if (configClearKey) body.api_key = '';
      else if (configApiKey.trim() !== '') body.api_key = configApiKey.trim();
      const response = await fetch('/api/mail/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      toast.success(configClearKey ? 'API 密钥已清空' : '配置已保存');
      configOpen = false;
      await loadConfig();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      configBusy = false;
    }
  }

  function openDomainModal() {
    domainPattern = '';
    domainOpen = true;
  }

  function openDomainBatchModal() {
    domainBatchText = '';
    domainBatchOpen = true;
  }

  async function submitDomain(event: SubmitEvent) {
    event.preventDefault();
    domainBusy = true;
    try {
      const response = await fetch('/api/mail/domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: domainPattern.trim() })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || '域名规则无效');
      toast.success(`已保存：${result.pattern}`);
      domainOpen = false;
      domainPattern = '';
      await loadConfig();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      domainBusy = false;
    }
  }

  async function submitDomainBatch(event: SubmitEvent) {
    event.preventDefault();
    domainBatchBusy = true;
    try {
      const response = await fetch('/api/mail/domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: domainBatchText })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) {
        const first = Array.isArray(result.errors) && result.errors[0]
          ? `：${result.errors[0].pattern} ${result.errors[0].error}`
          : '';
        throw new Error(`${result.error || '批量导入失败'}${first}`);
      }
      const saved = Number(result.saved_count ?? 0);
      const invalid = Number(result.invalid_count ?? 0);
      const duplicate = Number(result.duplicate_count ?? 0);
      const parts = [`保存 ${saved} 条`];
      if (duplicate > 0) parts.push(`去重 ${duplicate} 条`);
      if (invalid > 0) parts.push(`无效 ${invalid} 条`);
      if (invalid > 0) toast.info(`批量导入完成：${parts.join(' · ')}`, 5200);
      else toast.success(`批量导入完成：${parts.join(' · ')}`);
      domainBatchOpen = false;
      domainBatchText = '';
      await loadConfig();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      domainBatchBusy = false;
    }
  }

  async function deleteDomainIds(ids: number[]) {
    if (ids.length === 0) return;
    if (!window.confirm(`确认删除 ${ids.length} 条域名规则？`)) return;
    try {
      const response = await fetch('/api/mail/domains/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      toast.success(`已删除 ${result.deleted} 条`);
      selectedDomainIds = selectedDomainIds.filter((id) => !ids.includes(id));
      await loadConfig();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    }
  }

  async function fetchInbox() {
    if (!mailbox.trim()) {
      toast.error('请填写邮箱地址');
      return;
    }
    fetchBusy = true;
    fetchResult = '';
    fetchStatus = '';
    fetchEndpoint = '';
    try {
      const response = await fetch('/api/mail/fetch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mailbox: mailbox.trim(),
          action,
          delivery_id: deliveryId.trim(),
          limit
        })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const result = await response.json();
      if (!result.ok) throw new Error(result.error || `HTTP ${result.status_code}`);
      fetchStatus = String(result.status_code ?? '');
      fetchEndpoint = result.endpoint ?? '';
      fetchResult = result.body ?? '';
      toast.success('读取完成');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      fetchBusy = false;
    }
  }

  function toggleDomain(id: number, event?: Event) {
    event?.stopPropagation();
    selectedDomainIds = selectedDomainIds.includes(id)
      ? selectedDomainIds.filter((item) => item !== id)
      : [...selectedDomainIds, id];
  }

  function toggleAllDomains(event: Event) {
    const checked = (event.currentTarget as HTMLInputElement).checked;
    selectedDomainIds = checked ? config.domains.map((d) => d.id) : [];
  }

  function parseResult(value: string) {
    if (!value) return null;
    try { return JSON.parse(value); } catch { return null; }
  }

  function prettyResult(value: string) {
    const parsed = parseResult(value);
    if (parsed) return JSON.stringify(parsed, null, 2);
    return value;
  }

  function normalizeBackend(value: string): MailBackend {
    if (value === 'otprelay') return 'otprelay';
    if (value === 'temp_mail') return 'temp_mail';
    if (value === 'rapid_inbox_head') return 'rapid_inbox_head';
    return 'rapid_inbox';
  }

  function backendLabel(value = config.backend) {
    if (value === 'otprelay') return 'OTPRelay C';
    if (value === 'temp_mail') return 'Temp-Mail';
    if (value === 'rapid_inbox_head') return 'Rapid-Inbox Head';
    return 'Rapid-Inbox';
  }

  function defaultBaseUrl(value: MailBackend) {
    if (value === 'otprelay') return 'http://127.0.0.1:8080';
    if (value === 'temp_mail') return 'https://your-worker.example.com';
    return 'http://127.0.0.1:8000';
  }

  function transportLabel(value = config.transport) {
    return config.backend === 'otprelay' && value === 'ws' ? 'WS 订阅' : 'HTTP';
  }

  function wsStateLabel() {
    if (config.ws_subscribed) return '已订阅';
    if (config.ws_connected) return '已连接';
    if (config.ws_started) return '连接中';
    return '未启动';
  }

  function wsStateClass() {
    if (config.ws_subscribed) return 'pill pill-success';
    if (config.ws_started || config.ws_connected) return 'pill pill-warning';
    return 'pill';
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

  onMount(() => {
    loadConfig();
  });
</script>

<div class="e-root">

  <!-- ── HEADER ── -->
  <header class="e-header e-anim-up" style="--d:0ms">
    <div class="e-header-main">
      <h1 class="e-title">邮件</h1>
      <p class="e-desc">Rapid-Inbox / Head / OTPRelay / Temp-Mail 接入配置，管理域名规则，并直接探查任意邮箱内容</p>
    </div>
    <div class="e-header-actions">
      <button class="btn" type="button" onclick={loadConfig}>
        <Icon name="refresh" size={14} />
        刷新
      </button>
      <button class="btn btn-primary" type="button" onclick={openConfigModal}>
        <Icon name="settings" size={14} />
        API 配置
      </button>
    </div>
  </header>

  <!-- ── HERO STATS ── -->
  <div class="e-hero-grid e-anim-up" style="--d:60ms">
    <div class="e-hcard">
      <div class="e-hcard-icon"><Icon name="box" size={18} /></div>
      <div class="e-hcard-body">
        <div class="e-hcard-val">{backendLabel()}</div>
        <div class="e-hcard-label">服务类型</div>
        <div class="e-hcard-meta">{transportLabel()}</div>
      </div>
    </div>

    <div class="e-hcard" class:e-hcard--ok={!!config.has_api_key}>
      <div class="e-hcard-icon"><Icon name="lock" size={18} /></div>
      <div class="e-hcard-body">
        <div class="e-hcard-val">{config.has_api_key ? '已配置' : '未配置'}</div>
        <div class="e-hcard-label">API 密钥</div>
        <div class="e-hcard-meta">{config.has_api_key ? config.api_key_preview : '—'}</div>
      </div>
    </div>

    <div class="e-hcard">
      <div class="e-hcard-icon"><Icon name="tag" size={18} /></div>
      <div class="e-hcard-body">
        <div class="e-hcard-val">{config.domains.length}</div>
        <div class="e-hcard-label">域名规则</div>
        <div class="e-hcard-meta">条可用规则</div>
      </div>
    </div>

    {#if config.backend === 'otprelay' && config.transport === 'ws'}
      <div class="e-hcard"
        class:e-hcard--ok={!!config.ws_subscribed}
        class:e-hcard--warn={!!config.ws_started && !config.ws_subscribed}
      >
        <div class="e-hcard-icon"><Icon name="wifi" size={18} /></div>
        <div class="e-hcard-body">
          <div class="e-hcard-val">{wsStateLabel()}</div>
          <div class="e-hcard-label">WS 订阅</div>
          <div class="e-hcard-meta">{config.ws_cached_records} 条缓存</div>
        </div>
      </div>
    {:else}
      <div class="e-hcard">
        <div class="e-hcard-icon"><Icon name="link" size={18} /></div>
        <div class="e-hcard-body">
          <div class="e-hcard-val e-hcard-val-url">{config.base_url || '—'}</div>
          <div class="e-hcard-label">接口地址</div>
          <div class="e-hcard-meta">HTTP 传输</div>
        </div>
      </div>
    {/if}
  </div>

  <!-- ── MAIN GRID ── -->
  <div class="e-main-grid e-anim-up" style="--d:120ms">

    <!-- Left: config summary + domains -->
    <div class="e-col-left">

      <!-- API Config card -->
      <div class="e-panel">
        <div class="e-panel-head">
          <span class="e-panel-title">API 配置</span>
          <span class="e-panel-sub">{backendLabel()}</span>
          <button class="btn btn-sm" type="button" style="margin-left:auto;" onclick={openConfigModal}>
            <Icon name="edit" size={12} />
            编辑
          </button>
        </div>
        <div class="e-panel-body">
          {#if !initialLoaded}
            <div style="display:grid; gap:10px;">
              {#each Array(3) as _}<Skeleton height="14px" />{/each}
            </div>
          {:else}
            <div class="e-kv">
              <div class="e-kv-row"><span>服务类型</span><b>{backendLabel()}</b></div>
              <div class="e-kv-row"><span>接入方式</span><b>{transportLabel()}</b></div>
              <div class="e-kv-row">
                <span>接口地址</span>
                <code class="e-kv-code">{config.base_url || '—'}</code>
              </div>
              {#if config.backend !== 'otprelay'}
                <div class="e-kv-row">
                  <span>API 密钥</span>
                  <div style="display:flex; align-items:center; gap:8px;">
                    {#if config.has_api_key}
                      <span class="pill pill-success">已配置</span>
                      <code class="e-kv-code">{config.api_key_preview}</code>
                    {:else}
                      <span class="pill">未配置</span>
                    {/if}
                  </div>
                </div>
              {/if}
              {#if config.backend === 'otprelay' && config.transport === 'ws'}
                <div class="e-kv-row">
                  <span>WS 状态</span>
                  <div style="display:flex; align-items:center; gap:8px;">
                    <span class={wsStateClass()}>{wsStateLabel()}</span>
                    <span style="font-size:11px; color:var(--nx-ink-muted);">{config.ws_cached_records} 条</span>
                  </div>
                </div>
                {#if config.ws_last_error}
                  <div class="e-kv-row">
                    <span>WS 提示</span>
                    <span style="font-size:11.5px; color:var(--nx-warning);">{config.ws_last_error}</span>
                  </div>
                {/if}
              {/if}
            </div>
          {/if}
        </div>
      </div>

      <!-- Domain rules card -->
      <div class="e-panel e-panel-grow">
        <div class="e-panel-head">
          <span class="e-panel-title">域名规则</span>
          {#if config.domains.length > 0}
            <span class="e-panel-badge">{config.domains.length}</span>
          {/if}
          <div style="display:flex; gap:6px; margin-left:auto;">
            <button class="btn btn-sm" type="button" onclick={openDomainBatchModal}>
              <Icon name="upload" size={12} />
              批量
            </button>
            <button class="btn btn-sm btn-primary" type="button" onclick={openDomainModal}>
              <Icon name="plus" size={12} />
              添加
            </button>
          </div>
        </div>
        <div class="e-panel-body e-panel-scroll">
          {#if !initialLoaded}
            <div style="display:grid; gap:8px;">
              {#each Array(4) as _, i (i)}<Skeleton height="38px" rounded="md" />{/each}
            </div>
          {:else if config.domains.length === 0}
            <EmptyState title="还没有域名规则" message="添加规则后即可使用对应域生成临时邮箱" icon="tag">
              {#snippet action()}
                <div class="btn-row" style="margin:0;">
                  <button class="btn btn-sm" type="button" onclick={openDomainBatchModal}>
                    <Icon name="upload" size={12} /> 批量导入
                  </button>
                  <button class="btn btn-sm btn-primary" type="button" onclick={openDomainModal}>
                    <Icon name="plus" size={12} /> 添加域名
                  </button>
                </div>
              {/snippet}
            </EmptyState>
          {:else}
            <div class="e-bulk-bar">
              <label class="toggle-row" style="font-size:12px;">
                <input
                  type="checkbox"
                  checked={selectedDomainIds.length === config.domains.length && config.domains.length > 0}
                  onchange={toggleAllDomains}
                />
                <span>全选</span>
              </label>
              {#if selectedDomainIds.length > 0}
                <button class="btn btn-xs btn-danger" type="button" onclick={() => deleteDomainIds(selectedDomainIds)}>
                  <Icon name="trash" size={11} />
                  删除 ({selectedDomainIds.length})
                </button>
              {/if}
            </div>
            <div class="e-domain-list">
              {#each config.domains as domain}
                <div class="e-domain-row" class:e-domain-row-sel={selectedDomainIds.includes(domain.id)}>
                  <input
                    type="checkbox"
                    checked={selectedDomainIds.includes(domain.id)}
                    onchange={(e) => toggleDomain(domain.id, e)}
                    aria-label={`选择 ${domain.pattern}`}
                  />
                  <span class="e-domain-icon"><Icon name="tag" size={11} /></span>
                  <span class="e-domain-pattern">{domain.pattern}</span>
                  <span class="e-domain-depth">深度 {domain.wildcard_depth}</span>
                  <button class="btn btn-xs btn-danger" type="button" onclick={() => deleteDomainIds([domain.id])} aria-label="删除">
                    <Icon name="trash" size={11} />
                  </button>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </div>
    </div>

    <!-- Right: fetch tool + result -->
    <div class="e-col-right">

      <!-- Fetch form -->
      <div class="e-panel">
        <div class="e-panel-head">
          <span class="e-panel-title">邮箱探查</span>
          <span class="e-panel-sub">Inbox Fetch</span>
        </div>
        <div class="e-panel-body">
          <div class="form-field" style="margin-bottom:14px;">
            <span class="form-label">读取类型</span>
            <div class="e-action-grid">
              {#each fetchActions as item}
                <button
                  class="e-action-btn"
                  type="button"
                  class:e-action-active={action === item.value}
                  onclick={() => action = item.value}
                >
                  <span class="e-action-label">{item.label}</span>
                  <span class="e-action-desc">{item.description}</span>
                </button>
              {/each}
            </div>
          </div>

          <label class="form-field" style="margin-bottom:12px;">
            <span class="form-label form-label-required">邮箱地址</span>
            <div class="search-input">
              <span class="search-input-icon"><Icon name="mail" size={14} /></span>
              <input class="input" bind:value={mailbox} placeholder="code@example.com" />
            </div>
          </label>

          {#if activeAction.needId}
            <label class="form-field" style="margin-bottom:12px;">
              <span class="form-label form-label-required">Delivery ID</span>
              <input class="input text-mono" bind:value={deliveryId} placeholder="DEL_XXXXXXXX" />
            </label>
          {/if}

          {#if activeAction.allowLimit}
            <label class="form-field" style="margin-bottom:12px;">
              <span class="form-label">数量上限</span>
              <input class="input" type="number" min="1" max="100" bind:value={limit} />
            </label>
          {/if}

          <div class="e-fetch-row">
            <button class="btn btn-primary" type="button" onclick={fetchInbox} disabled={fetchBusy || !mailbox.trim()} data-loading={fetchBusy}>
              <Icon name="send" size={14} />
              {fetchBusy ? '读取中…' : '发起读取'}
            </button>
            {#if fetchEndpoint}
              <button class="btn btn-sm" type="button" onclick={() => copy(fetchEndpoint, 'endpoint', '请求 URL')}>
                <Icon name={copiedKey === 'endpoint' ? 'check' : 'link'} size={12} />
                复制 URL
              </button>
            {/if}
          </div>
        </div>
      </div>

      <!-- Result panel -->
      <div class="e-panel e-panel-grow">
        <div class="e-panel-head">
          <span class="e-panel-title">响应结果</span>
          {#if fetchStatus}
            <span class={fetchStatusOk ? 'pill pill-success' : 'pill pill-danger'}>HTTP {fetchStatus}</span>
          {/if}
          {#if fetchResult}
            <button class="btn btn-sm" type="button" style="margin-left:auto;" onclick={() => copy(fetchResult, 'body', '响应内容')}>
              <Icon name={copiedKey === 'body' ? 'check' : 'copy'} size={12} />
              复制
            </button>
          {/if}
        </div>
        <div class="e-panel-body e-panel-scroll">
          {#if fetchEndpoint}
            <div class="e-endpoint-chip">
              <span class="e-endpoint-icon"><Icon name="link" size={11} /></span>
              <span>{fetchEndpoint}</span>
            </div>
          {/if}
          {#if fetchBusy}
            <Skeleton height="160px" rounded="md" />
          {:else if !fetchResult}
            <EmptyState title="尚未读取" message="填写邮箱地址并点击「发起读取」" icon="inbox" />
          {:else}
            {#if parsedFetch?.items?.length}
              <div class="e-result-list">
                {#each parsedFetch.items as item}
                  <div class="e-result-item">
                    <div class="e-result-main">
                      <span class="e-result-primary">{item.code ?? item.subject ?? item.delivery_id ?? '—'}</span>
                      {#if item.received_at || item.from_addr || item.message_id}
                        <span class="e-result-meta">{item.received_at ?? item.from_addr ?? item.message_id ?? ''}</span>
                      {/if}
                    </div>
                    {#if item.code || item.delivery_id}
                      <button class="btn btn-xs" type="button" onclick={() => copy(item.code ?? item.delivery_id, `r-${item.delivery_id ?? item.code}`)}>
                        <Icon name={copiedKey === `r-${item.delivery_id ?? item.code}` ? 'check' : 'copy'} size={11} />
                      </button>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
            <pre class="code-block">{prettyResult(fetchResult)}</pre>
          {/if}
        </div>
      </div>
    </div>

  </div>

</div>

<Modal
  open={configOpen}
  title="API 配置"
  kicker="MAIL · 配置"
  subtitle="Rapid-Inbox / OTPRelay / Temp-Mail 服务地址与认证"
  size="sm"
  onclose={() => { if (!configBusy) configOpen = false; }}
>
  <form id="config-form" class="form-section" onsubmit={submitConfig}>
    <label class="form-field">
      <span class="form-label">服务类型</span>
      <div class="segmented" style="display: flex;">
        <button type="button" class:active={configBackend === 'rapid_inbox'} onclick={() => selectConfigBackend('rapid_inbox')}>
          Rapid-Inbox
        </button>
        <button type="button" class:active={configBackend === 'rapid_inbox_head'} onclick={() => selectConfigBackend('rapid_inbox_head')}>
          Head
        </button>
        <button type="button" class:active={configBackend === 'otprelay'} onclick={() => selectConfigBackend('otprelay')}>
          OTPRelay C
        </button>
        <button type="button" class:active={configBackend === 'temp_mail'} onclick={() => selectConfigBackend('temp_mail')}>
          Temp-Mail
        </button>
      </div>
    </label>

    {#if configBackend === 'otprelay'}
      <label class="form-field">
        <span class="form-label">接入方式</span>
        <div class="segmented" style="display: flex;">
          <button type="button" class:active={configTransport === 'http'} onclick={() => configTransport = 'http'}>
            HTTP
          </button>
          <button type="button" class:active={configTransport === 'ws'} onclick={() => configTransport = 'ws'}>
            WS 订阅
          </button>
        </div>
      </label>
    {/if}

    <label class="form-field">
      <span class="form-label form-label-required">接口地址</span>
      <div class="search-input">
        <span class="search-input-icon"><Icon name="link" size={14} /></span>
        <input
          class="input"
          bind:value={configBaseUrl}
          placeholder={defaultBaseUrl(configBackend)}
          required
          disabled={configBusy}
        />
      </div>
    </label>
    {#if configBackend !== 'otprelay'}
      <label class="form-field">
        <span class="form-label">{configBackend === 'temp_mail' ? 'Admin 密钥' : 'API 密钥'}</span>
        <input
          class="input"
          type="password"
          bind:value={configApiKey}
          placeholder={config.has_api_key ? config.api_key_preview : '未配置'}
          disabled={configBusy || configClearKey}
          autocomplete="new-password"
        />
        <p class="form-help">留空则保留现有密钥；勾选下方「清空」以删除已存密钥</p>
      </label>
      {#if config.has_api_key}
        <label class="toggle-row">
          <input type="checkbox" bind:checked={configClearKey} disabled={configBusy} />
          <span>清空已存的 API 密钥</span>
        </label>
      {/if}
    {/if}
  </form>

  {#snippet footer()}
    <button class="btn" type="button" onclick={() => configOpen = false} disabled={configBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="config-form" disabled={configBusy || !configBaseUrl.trim()} data-loading={configBusy}>
      {configBusy ? '保存中…' : '保存配置'}
    </button>
  {/snippet}
</Modal>

<Modal
  open={domainBatchOpen}
  title="批量导入域名"
  kicker="DOMAIN"
  subtitle="一次保存多条域名规则"
  size="md"
  onclose={() => { if (!domainBatchBusy) domainBatchOpen = false; }}
>
  <form id="domain-batch-form" class="form-section" onsubmit={submitDomainBatch}>
    <label class="form-field">
      <span class="form-label form-label-required">域名规则</span>
      <textarea
        class="input text-mono"
        bind:value={domainBatchText}
        placeholder={`example.com\n*.example.com\n**.x.com`}
        required
        disabled={domainBatchBusy}
        autocomplete="off"
        rows="10"
      ></textarea>
      <p class="form-help">支持换行、逗号或分号分隔；已有规则会刷新为启用状态。</p>
    </label>
    {#if domainBatchItems.length > 0}
      <div style="display: grid; gap: 10px; padding: 12px 14px; border: 1px solid var(--nx-rule); border-radius: var(--radius-md); background: var(--nx-paper-deep);">
        <div style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--nx-ink-muted);">
          <Icon name="list" size={12} />
          待导入 {domainBatchItems.length} 条
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
          {#each domainBatchItems.slice(0, 8) as item}
            <span class="tag text-mono">{item}</span>
          {/each}
          {#if domainBatchItems.length > 8}
            <span class="tag">+{domainBatchItems.length - 8}</span>
          {/if}
        </div>
      </div>
    {/if}
  </form>

  {#snippet footer()}
    <button class="btn" type="button" onclick={() => domainBatchOpen = false} disabled={domainBatchBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="domain-batch-form" disabled={domainBatchBusy || domainBatchItems.length === 0} data-loading={domainBatchBusy}>
      {domainBatchBusy ? '导入中…' : '批量导入'}
    </button>
  {/snippet}
</Modal>

<Modal
  open={domainOpen}
  title="添加域名规则"
  kicker="DOMAIN"
  subtitle="支持精确域名或带通配符的子域规则"
  size="sm"
  onclose={() => { if (!domainBusy) domainOpen = false; }}
>
  <form id="domain-form" class="form-section" onsubmit={submitDomain}>
    <label class="form-field">
      <span class="form-label form-label-required">规则</span>
      <input class="input text-mono" bind:value={domainPattern} placeholder="*.example.com" required disabled={domainBusy} autocomplete="off" />
      <p class="form-help">通配符 <strong>*</strong> 表示任意子域，每个 <strong>*</strong> 代表一层。例如 <code class="text-mono">**.x.com</code> 匹配 <code class="text-mono">a.b.x.com</code>。</p>
    </label>
    {#if domainPreview}
      <div style="display: grid; gap: 8px; padding: 12px 14px; border: 1px solid var(--nx-rule); border-radius: var(--radius-md); background: var(--nx-paper-deep);">
        <div style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--nx-ink-muted);">
          <Icon name="info" size={12} />
          解析结果
        </div>
        <div style="display: flex; gap: 16px; font-size: 12.5px;">
          <span>基础域：<strong class="text-mono">{domainPreview.base}</strong></span>
          <span>通配深度：<strong>{domainPreview.wildcards}</strong></span>
        </div>
      </div>
    {/if}
  </form>

  {#snippet footer()}
    <button class="btn" type="button" onclick={() => domainOpen = false} disabled={domainBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="domain-form" disabled={domainBusy || !domainPattern.trim()} data-loading={domainBusy}>
      {domainBusy ? '保存中…' : '保存规则'}
    </button>
  {/snippet}
</Modal>

<style>
/* =========================================
   Mail Page — Redesigned
   ========================================= */

@keyframes mail-fade-up {
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0);    }
}

.e-anim-up {
  animation: mail-fade-up 0.55s var(--ease-out, cubic-bezier(0.22,1,0.36,1)) both;
  animation-delay: var(--d, 0ms);
}

.e-root { display: flex; flex-direction: column; gap: 20px; }

/* ---- Header ---- */
.e-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 22px;
  border-bottom: 1px solid var(--nx-rule);
  flex-wrap: wrap;
}

.e-header-main { display: grid; gap: 2px; }

.e-title {
  margin: 0;
  font-size: 26px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1.15;
  letter-spacing: -0.01em;
}

.e-desc { margin: 0; font-size: 13px; color: var(--nx-ink-muted); }

.e-header-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }

/* ---- Hero Cards ---- */
.e-hero-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}

.e-hcard {
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
  transition: transform 0.2s var(--ease-out), box-shadow 0.2s, border-color 0.2s;
}

.e-hcard::after {
  content: '';
  position: absolute;
  top: 0; right: 0;
  width: 55%; height: 100%;
  background: linear-gradient(270deg, color-mix(in srgb, var(--nx-brand) 5%, transparent), transparent);
  pointer-events: none;
}

.e-hcard:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-md);
  border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule));
}

.e-hcard--ok  { border-color: var(--nx-success-border); background: linear-gradient(135deg, var(--nx-success-bg) 0%, var(--nx-card) 55%); }
.e-hcard--warn { border-color: var(--nx-warning-border); background: linear-gradient(135deg, var(--nx-warning-bg) 0%, var(--nx-card) 55%); }

.e-hcard--ok::after  { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-success) 6%, transparent), transparent); }
.e-hcard--warn::after { background: linear-gradient(270deg, color-mix(in srgb, var(--nx-warning) 6%, transparent), transparent); }

.e-hcard-icon {
  display: grid;
  place-items: center;
  width: 44px; height: 44px;
  flex-shrink: 0;
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-brand) 12%, transparent);
  color: var(--nx-brand);
  border: 1px solid color-mix(in srgb, var(--nx-brand) 22%, transparent);
}

.e-hcard--ok  .e-hcard-icon { background: color-mix(in srgb, var(--nx-success) 12%, transparent); color: var(--nx-success); border-color: color-mix(in srgb, var(--nx-success) 25%, transparent); }
.e-hcard--warn .e-hcard-icon { background: color-mix(in srgb, var(--nx-warning) 12%, transparent); color: var(--nx-warning); border-color: color-mix(in srgb, var(--nx-warning) 25%, transparent); }

.e-hcard-body { display: grid; gap: 2px; min-width: 0; flex: 1; }

.e-hcard-val {
  font-family: var(--font-number);
  font-size: 20px;
  font-weight: 700;
  color: var(--nx-ink);
  line-height: 1.1;
  font-variant-numeric: tabular-nums lining-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.e-hcard--ok  .e-hcard-val { color: var(--nx-success); }
.e-hcard--warn .e-hcard-val { color: var(--nx-warning); }

.e-hcard-val-url {
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 500;
}

.e-hcard-label {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.07em;
  margin-top: 3px;
}

.e-hcard-meta {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ---- Main Grid ---- */
.e-main-grid {
  display: grid;
  grid-template-columns: minmax(260px, 360px) minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.e-col-left, .e-col-right {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* ---- Panels ---- */
.e-panel {
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-lg);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  overflow: hidden;
  transition: box-shadow 0.2s;
}

.e-panel:hover { box-shadow: var(--shadow-sm); }
.e-panel-grow { flex: 1; }

.e-panel-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--nx-rule);
  background: color-mix(in srgb, var(--nx-paper-deep) 30%, var(--nx-card));
  flex-wrap: wrap;
}

.e-panel-title { font-size: 13px; font-weight: 700; color: var(--nx-ink); white-space: nowrap; }

.e-panel-sub {
  font-size: 10.5px;
  font-weight: 700;
  color: var(--nx-brand);
  text-transform: uppercase;
  letter-spacing: 0.07em;
}

.e-panel-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  height: 20px;
  padding: 0 5px;
  border-radius: var(--radius-full);
  background: color-mix(in srgb, var(--nx-brand) 15%, transparent);
  color: var(--nx-brand);
  font-size: 10.5px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.e-panel-body { padding: 14px 16px; }

.e-panel-scroll { overflow-y: auto; max-height: 400px; }

/* ---- KV list ---- */
.e-kv { display: grid; }

.e-kv-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid var(--nx-rule);
  font-size: 12.5px;
}

.e-kv-row:last-child { border-bottom: 0; }
.e-kv-row > span:first-child { color: var(--nx-ink-muted); flex-shrink: 0; }
.e-kv-row b { color: var(--nx-ink); font-weight: 600; text-align: right; }

.e-kv-code {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--nx-ink-soft);
  background: color-mix(in srgb, var(--nx-paper-deep) 60%, var(--nx-card));
  padding: 2px 6px;
  border-radius: 4px;
  border: 1px solid var(--nx-rule);
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
  vertical-align: middle;
}

/* ---- Bulk select bar ---- */
.e-bulk-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 1px solid var(--nx-rule);
}

/* ---- Domain list ---- */
.e-domain-list { display: grid; gap: 4px; }

.e-domain-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card));
  transition: background 0.15s, border-color 0.15s;
}

.e-domain-row:hover { background: var(--nx-card-sun); border-color: var(--nx-rule); }

.e-domain-row-sel {
  background: color-mix(in srgb, var(--nx-brand) 6%, var(--nx-card)) !important;
  border-color: color-mix(in srgb, var(--nx-brand) 25%, transparent) !important;
}

.e-domain-icon { color: var(--nx-ink-muted); flex-shrink: 0; display: flex; }

.e-domain-pattern {
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 600;
  color: var(--nx-ink);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.e-domain-depth {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  background: color-mix(in srgb, var(--nx-ink-muted) 10%, transparent);
  padding: 1px 6px;
  border-radius: var(--radius-full);
  white-space: nowrap;
  flex-shrink: 0;
}

/* ---- Action type cards ---- */
.e-action-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 8px;
  margin-top: 6px;
}

.e-action-btn {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 3px;
  padding: 10px 12px;
  border: 1.5px solid var(--nx-rule);
  border-radius: var(--radius-md);
  background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card));
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
  font-family: inherit;
  text-align: left;
}

.e-action-btn:hover {
  border-color: color-mix(in srgb, var(--nx-brand) 35%, var(--nx-rule));
  background: color-mix(in srgb, var(--nx-brand) 4%, var(--nx-card));
}

.e-action-active {
  border-color: var(--nx-brand) !important;
  background: color-mix(in srgb, var(--nx-brand) 8%, var(--nx-card)) !important;
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--nx-brand) 12%, transparent);
}

.e-action-label { font-size: 12.5px; font-weight: 600; color: var(--nx-ink-soft); transition: color 0.15s; }
.e-action-active .e-action-label { color: var(--nx-brand); }
.e-action-desc { font-size: 10.5px; color: var(--nx-ink-muted); line-height: 1.3; }

/* ---- Fetch row ---- */
.e-fetch-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 14px;
  flex-wrap: wrap;
}

/* ---- Endpoint chip ---- */
.e-endpoint-chip {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 7px 10px;
  margin-bottom: 12px;
  background: color-mix(in srgb, var(--nx-paper-deep) 60%, var(--nx-card));
  border: 1px solid var(--nx-rule);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--nx-ink-muted);
  word-break: break-all;
}

.e-endpoint-icon { flex-shrink: 0; display: flex; margin-top: 1px; }

/* ---- Result list ---- */
.e-result-list { display: grid; gap: 4px; margin-bottom: 12px; }

.e-result-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card));
  border: 1px solid var(--nx-rule);
  transition: background 0.15s;
}

.e-result-item:hover { background: var(--nx-card-sun); }

.e-result-main { flex: 1; min-width: 0; display: grid; gap: 2px; }

.e-result-primary {
  font-family: var(--font-mono);
  font-size: 14px;
  font-weight: 700;
  color: var(--nx-brand);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.e-result-meta { font-size: 11px; color: var(--nx-ink-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* ---- Responsive ---- */
@media (max-width: 1100px) {
  .e-main-grid { grid-template-columns: 1fr; }
  .e-col-left { display: grid; grid-template-columns: 1fr 1fr; }
}

@media (max-width: 1024px) {
  .e-hero-grid { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 700px) {
  .e-col-left { grid-template-columns: 1fr; }
}

@media (max-width: 640px) {
  .e-hero-grid { grid-template-columns: repeat(2, 1fr); }
  .e-header { flex-direction: column; align-items: flex-start; }
  .e-action-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>
