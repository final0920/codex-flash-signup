<script lang="ts">
  import { onMount } from 'svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Panel from '../components/Panel.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { waitApiJob } from '../lib/apiJobs';
  import { toast } from '../lib/toast';

  type AccountStatus = 'active' | 'expired' | 'temp' | 'failed';
  type UploadState = 'uploaded' | 'not_uploaded';
  type AccountAction = 'refresh-token' | 'validate-token' | 'reupload' | 'delete' | 'oauth' | 'chatgpt-login';
  type PageToken = number | 'ellipsis-start' | 'ellipsis-end';
  type SecretKey = 'password' | 'access_token' | 'refresh_token' | 'id_token' | 'session_token' | 'cookies';

  type AccountSummary = {
    total: number; active: number; expired: number; temp: number; failed: number;
    uploaded: number; not_uploaded: number; updated_at: number;
  };

  type AccountItem = {
    id: number; email: string; status: AccountStatus; upload_state: UploadState;
    created_at: number; updated_at: number; last_refreshed_at: number;
    auth_source: string;
  };

  type AccountDetail = AccountItem & {
    password: string; access_token: string; refresh_token: string;
    id_token: string; session_token: string; cookies: string;
    external_account_id: string; workspace_id: string;
  };

  type AccountDetailResponse = { ok: number; account?: AccountDetail; error?: string; };
  type TokenValidationDetail = { id: number; valid: boolean; http_status: number; error: string; };
  type TokenValidationResponse = {
    ok: number; checked_count?: number; valid_count?: number; invalid_count?: number;
    proxy_used?: boolean; details?: TokenValidationDetail[]; error?: string; validated_at?: number;
  };
  type TokenRefreshDetail = { id: number; success: boolean; http_status: number; rotated: boolean; expires_in: number; error: string; };
  type TokenRefreshResponse = {
    ok: number; checked_count?: number; success_count?: number; failed_count?: number;
    affected?: number; proxy_used?: boolean; details?: TokenRefreshDetail[]; error?: string;
  };
  type AccountActionDetail = { success: boolean; error?: string };
  type AccountActionResult = {
    ok: number;
    task_id?: string;
    job_id?: string;
    affected?: number;
    async?: number;
    error?: string;
    success_count?: number;
    failed_count?: number;
    skipped_count?: number;
    service_count?: number;
    details?: AccountActionDetail[];
  };
  type AetherUploadService = {
    enabled?: number;
    chatgpt_web_provider_id?: string;
  };
  type AetherUploadConfig = {
    services?: AetherUploadService[];
  };

  const statusOptions = [
    { value: '', label: '全部状态' },
    { value: 'active', label: '活跃' },
    { value: 'expired', label: '过期' },
    { value: 'temp', label: '临时' },
    { value: 'failed', label: '失败' }
  ];

  const uploadOptions = [
    { value: '', label: '全部上传' },
    { value: 'uploaded', label: '已上传' },
    { value: 'not_uploaded', label: '未上传' }
  ];

  const authSourceOptions = [
    { value: '', label: '全部来源' },
    { value: 'chatgpt2api', label: 'ChatGPT2API' },
    { value: 'standard', label: '普通' }
  ];

  const emptySummary: AccountSummary = {
    total: 0, active: 0, expired: 0, temp: 0, failed: 0,
    uploaded: 0, not_uploaded: 0, updated_at: 0
  };

  let summary = $state(emptySummary);
  let accounts: AccountItem[] = $state([]);
  let initialLoaded = $state(false);
  let selectedIds: number[] = $state([]);
  let searchText = $state('');
  let statusFilter = $state('');
  let uploadFilter = $state('');
  let authSourceFilter = $state('');
  let limit = $state(50);
  let oauthConcurrency = $state(10);
  let currentPage = $state(1);
  let totalCount = $state(0);
  let totalPages = $state(1);
  let jumpPageText = $state('1');
  let loading = $state(false);
  let actionBusy = $state(false);

  let detailOpen = $state(false);
  let selectedAccountId: number | null = $state(null);
  let accountDetail: AccountDetail | null = $state(null);
  let detailLoading = $state(false);
  let detailError = $state('');
  let showPassword = $state(false);
  let showAccessToken = $state(false);
  let showRefreshToken = $state(false);
  let showIdToken = $state(false);
  let showSessionToken = $state(false);
  let showCookies = $state(false);
  let detailRequestSerial = 0;
  let copiedKey: string | null = $state(null);
  let latestValidation: TokenValidationResponse | null = $state(null);
  let hasChatgptWebUploadPool = $state(false);

  let allVisibleSelected = $derived(accounts.length > 0 && accounts.every((account) => selectedIds.includes(account.id)));
  let selectedListAccount = $derived(accounts.find((account) => account.id === selectedAccountId) ?? null);
  let detailAccount = $derived(accountDetail ?? selectedListAccount);
  let detailValidation = $derived(latestValidation?.details?.find((item) => item.id === selectedAccountId) ?? null);
  let pageTokens = $derived(buildPageTokens(currentPage, totalPages));
  let pageStart = $derived(totalCount === 0 ? 0 : (currentPage - 1) * Number(limit) + 1);
  let pageEnd = $derived(totalCount === 0 ? 0 : Math.min(currentPage * Number(limit), totalCount));

  let summaryCards = $derived([
    { label: '账号总量', value: summary.total, icon: 'database' as const, klass: '' },
    { label: '活跃', value: summary.active, icon: 'check-circle' as const, klass: 'stat-chip-success' },
    { label: '过期', value: summary.expired, icon: 'clock' as const, klass: 'stat-chip-warning' },
    { label: '失败', value: summary.failed, icon: 'alert-circle' as const, klass: 'stat-chip-danger' },
    { label: '已上传', value: summary.uploaded, icon: 'upload' as const, klass: 'stat-chip-info' }
  ]);

  let detailCredentials = $derived(accountDetail ? [
    { key: 'password' as SecretKey, label: '密码', value: accountDetail.password, copyLabel: '密码' },
    { key: 'access_token' as SecretKey, label: 'Access Token', value: accountDetail.access_token, copyLabel: 'Access Token' },
    { key: 'refresh_token' as SecretKey, label: 'Refresh Token', value: accountDetail.refresh_token, copyLabel: 'Refresh Token' },
    { key: 'id_token' as SecretKey, label: 'ID Token', value: accountDetail.id_token, copyLabel: 'ID Token' },
    { key: 'session_token' as SecretKey, label: 'Session Token', value: accountDetail.session_token, copyLabel: 'Session Token' },
    { key: 'cookies' as SecretKey, label: 'Cookies', value: accountDetail.cookies, copyLabel: 'Cookies' }
  ] : []);

  let detailIdentityRows = $derived(accountDetail ? [
    { key: 'ext-id', label: 'Account ID', value: accountDetail.external_account_id, copyLabel: 'Account ID' },
    { key: 'ws-id', label: 'Workspace ID', value: accountDetail.workspace_id, copyLabel: 'Workspace ID' }
  ] : []);

  let detailTimeRows = $derived(accountDetail ? [
    { label: '创建时间', value: formatExactTime(accountDetail.created_at) },
    { label: '更新时间', value: formatExactTime(accountDetail.updated_at) },
    { label: '最后刷新', value: formatRelativeTime(accountDetail.last_refreshed_at) }
  ] : []);

  let hasFilter = $derived(Boolean(searchText.trim() || statusFilter || uploadFilter || authSourceFilter));

  async function loadSummary() {
    try {
      const response = await fetch('/api/accounts/summary');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      summary = await response.json();
    } catch (err) {
      toast.error(`摘要加载失败：${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async function loadUploadConfig() {
    try {
      const response = await fetch('/api/upload/aether');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json() as AetherUploadConfig;
      hasChatgptWebUploadPool = (data.services ?? []).some((service) =>
        Boolean(Number(service.enabled ?? 0)) && `${service.chatgpt_web_provider_id ?? ''}`.trim() !== ''
      );
    } catch {
      hasChatgptWebUploadPool = false;
    }
  }

  async function loadAccounts(reset = false, page = currentPage) {
    loading = true;
    if (reset) {
      currentPage = 1;
      jumpPageText = '1';
    }
    const targetPage = reset ? 1 : normalizePage(page);
    try {
      const params = new URLSearchParams();
      params.set('limit', String(limit));
      params.set('page', String(targetPage));
      if (searchText.trim()) params.set('q', searchText.trim());
      if (statusFilter) params.set('status', statusFilter);
      if (uploadFilter) params.set('upload_state', uploadFilter);
      if (authSourceFilter) params.set('auth_source', authSourceFilter);
      const response = await fetch(`/api/accounts?${params.toString()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      accounts = data.items ?? [];
      totalCount = Math.max(0, Number(data.total_count ?? data.returned ?? accounts.length) || 0);
      totalPages = Math.max(1, Number(data.total_pages ?? Math.ceil(totalCount / Number(limit))) || 1);
      currentPage = Math.min(Math.max(1, Number(data.page ?? targetPage) || targetPage), totalPages);
      jumpPageText = String(currentPage);
      selectedIds = selectedIds.filter((id) => accounts.some((item) => item.id === id));
      syncVisibleDetailSelection();
    } catch (err) {
      accounts = []; totalCount = 0; totalPages = 1; currentPage = 1; jumpPageText = '1';
      clearAccountDetail();
      toast.error(`列表加载失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      loading = false;
      initialLoaded = true;
    }
  }

  async function refreshPage(reset = false) {
    await Promise.all([loadSummary(), loadAccounts(reset), loadUploadConfig()]);
  }

  async function submitAccountAction(action: AccountAction, ids: number[], extra: Record<string, unknown> = {}) {
    const response = await fetch('/api/accounts/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action,
        ids,
        async: action === 'reupload',
        concurrency: Math.max(1, Math.min(5000, Number(oauthConcurrency) || 1)),
        ...extra
      })
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    let result = await response.json() as AccountActionResult;
    if (result.async && result.job_id) {
      result = await waitApiJob(result.job_id, { timeoutMs: 300000 }) as AccountActionResult;
    }
    if (!result.ok) throw new Error(result.error || '操作执行失败');
    return result;
  }

  function uploadResultPart(label: string, result: AccountActionResult) {
    const success = Number(result.success_count ?? 0);
    const failed = Number(result.failed_count ?? 0);
    const skipped = Number(result.skipped_count ?? 0);
    const serviceCount = Number(result.service_count ?? 0);
    const serviceText = serviceCount > 1 ? `，已同步到 ${serviceCount} 个服务` : '';
    return `${label} 成功 ${success} 个，失败 ${failed} 个，跳过 ${skipped} 个${serviceText}`;
  }

  function firstUploadError(result: AccountActionResult | null) {
    return result?.details?.find((item) => !item.success && item.error)?.error ?? '';
  }

  async function runReupload(ids: number[]) {
    await loadUploadConfig();
    const oauthResult = await submitAccountAction('reupload', ids, { pool_type: 'oauth' });
    let webResult: AccountActionResult | null = null;
    let webError = '';

    if (hasChatgptWebUploadPool) {
      try {
        webResult = await submitAccountAction('reupload', ids, { pool_type: 'chatgpt_web' });
      } catch (err) {
        webError = err instanceof Error ? err.message : String(err);
      }
    }

    const parts = [uploadResultPart('Codex 号池', oauthResult)];
    if (webResult) {
      parts.push(uploadResultPart('Web 号池', webResult));
    } else if (webError) {
      parts.push(`Web 号池失败：${webError}`);
    }

    const firstError = firstUploadError(oauthResult) || firstUploadError(webResult) || webError;
    const oauthFailed = Number(oauthResult.failed_count ?? 0);
    const oauthSkipped = Number(oauthResult.skipped_count ?? 0);
    const webFailed = Number(webResult?.failed_count ?? 0);
    const webSkipped = Number(webResult?.skipped_count ?? 0);
    const message = `Aether 上传完成：${parts.join('；')}${firstError ? `，首个失败：${firstError}` : ''}`;

    if (webError || (oauthFailed > 0 && Number(oauthResult.success_count ?? 0) === 0)) {
      toast.error(message);
    } else if (oauthFailed > 0 || oauthSkipped > 0 || webFailed > 0 || webSkipped > 0) {
      toast.info(message);
    } else {
      toast.success(message);
    }
  }

  async function runAction(action: AccountAction, ids: number[]) {
    if (ids.length === 0) return;
    if (action === 'delete' && !window.confirm(`确认删除 ${ids.length} 个账号？此操作不可撤销。`)) return;
    const detailWillBeDeleted = selectedAccountId !== null && action === 'delete' && ids.includes(selectedAccountId);
    actionBusy = true;
    try {
      if (action === 'reupload') {
        await runReupload(ids);
      } else {
        const result = await submitAccountAction(action, ids);
        if (action === 'validate-token') {
          const validation = result as TokenValidationResponse;
          latestValidation = { ...validation, validated_at: Date.now() };
          const valid = Number(validation.valid_count ?? 0);
          const invalid = Number(validation.invalid_count ?? 0);
          const firstError = validation.details?.find((item) => !item.valid && item.error)?.error;
          const message = `Token 验证完成：有效 ${valid} 个，无效 ${invalid} 个${firstError ? `，首个失败：${firstError}` : ''}`;
          if (invalid > 0) toast.info(message);
          else toast.success(message);
        } else if (action === 'refresh-token') {
          const refresh = result as TokenRefreshResponse;
          const success = Number(refresh.success_count ?? refresh.affected ?? 0);
          const failed = Number(refresh.failed_count ?? 0);
          const rotated = refresh.details?.filter((item) => item.success && item.rotated).length ?? 0;
          const firstError = refresh.details?.find((item) => !item.success && item.error)?.error;
          const proxyText = refresh.proxy_used ? '，已使用活跃代理' : '';
          const message = `Token 刷新完成：成功 ${success} 个，失败 ${failed} 个${rotated ? `，Refresh Token 轮换 ${rotated} 个` : ''}${proxyText}${firstError ? `，首个失败：${firstError}` : ''}`;
          if (failed > 0 && success === 0) toast.error(message);
          else if (failed > 0) toast.info(message);
          else toast.success(message);
        } else {
          const message = result.task_id
            ? `${actionLabel(action)}任务已创建（${result.affected ?? ids.length} 个）`
            : `${actionLabel(action)}完成：${result.affected ?? 0} 个`;
          toast.success(message);
        }
      }
      if (action === 'delete') {
        selectedIds = [];
        if (detailWillBeDeleted) clearAccountDetail();
      }
      await refreshPage(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      actionBusy = false;
    }
  }

  function runSingleAction(event: MouseEvent, action: AccountAction, id: number) {
    event.stopPropagation();
    runAction(action, [id]);
  }

  function selectAccount(id: number) {
    detailOpen = true;
    if (selectedAccountId === id && accountDetail?.id === id && !detailError) return;
    selectedAccountId = id;
    showPassword = false;
    showAccessToken = false;
    showRefreshToken = false;
    showIdToken = false;
    showSessionToken = false;
    showCookies = false;
    loadAccountDetail(id);
  }

  function syncVisibleDetailSelection() {
    if (!detailOpen || selectedAccountId === null) return;
    if (accounts.length === 0 || !accounts.some((account) => account.id === selectedAccountId)) {
      clearAccountDetail();
      return;
    }
    loadAccountDetail(selectedAccountId);
  }

  function clearAccountDetail() {
    detailRequestSerial += 1;
    detailOpen = false;
    selectedAccountId = null;
    accountDetail = null;
    detailLoading = false;
    detailError = '';
    showPassword = false;
    showAccessToken = false;
    showRefreshToken = false;
    showIdToken = false;
    showSessionToken = false;
    showCookies = false;
  }

  async function loadAccountDetail(id: number) {
    const requestSerial = ++detailRequestSerial;
    detailLoading = true;
    detailError = '';
    try {
      const response = await fetch(`/api/accounts/detail?id=${id}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json() as AccountDetailResponse;
      if (requestSerial !== detailRequestSerial) return;
      if (!data.ok || !data.account) throw new Error(data.error || '账号详情不存在');
      accountDetail = data.account;
    } catch (err) {
      if (requestSerial !== detailRequestSerial) return;
      accountDetail = null;
      detailError = err instanceof Error ? err.message : String(err);
    } finally {
      if (requestSerial === detailRequestSerial) detailLoading = false;
    }
  }

  function toggleAccount(event: Event, id: number) {
    event.stopPropagation();
    selectedIds = selectedIds.includes(id)
      ? selectedIds.filter((item) => item !== id)
      : [...selectedIds, id];
  }

  function toggleAllVisible(event: Event) {
    const checked = (event.currentTarget as HTMLInputElement).checked;
    const visibleIds = accounts.map((account) => account.id);
    if (checked) {
      selectedIds = Array.from(new Set([...selectedIds, ...visibleIds]));
    } else {
      selectedIds = selectedIds.filter((id) => !visibleIds.includes(id));
    }
  }

  function normalizePage(value: number | string) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return currentPage;
    return Math.min(Math.max(1, Math.trunc(parsed)), Math.max(1, totalPages));
  }

  function goToPage(page: number | string) {
    const next = normalizePage(page);
    jumpPageText = String(next);
    if (loading || next === currentPage) return;
    currentPage = next;
    loadAccounts(false, next);
  }

  function nextPage() {
    if (currentPage >= totalPages) return;
    goToPage(currentPage + 1);
  }

  function previousPage() {
    if (currentPage <= 1) return;
    goToPage(currentPage - 1);
  }

  function submitJumpPage() {
    const parsed = Number(jumpPageText);
    if (!Number.isFinite(parsed) || parsed < 1) {
      jumpPageText = String(currentPage);
      toast.error('请输入有效页码');
      return;
    }
    const next = normalizePage(parsed);
    if (next !== Math.trunc(parsed)) {
      toast.info(`最多 ${totalPages} 页，已跳到第 ${next} 页`);
    }
    goToPage(next);
  }

  function buildPageTokens(page: number, total: number): PageToken[] {
    const safeTotal = Math.max(1, Math.trunc(total || 1));
    const safePage = Math.min(Math.max(1, Math.trunc(page || 1)), safeTotal);
    if (safeTotal <= 7) return Array.from({ length: safeTotal }, (_, index) => index + 1);

    const tokens: PageToken[] = [1];
    let start = Math.max(2, safePage - 2);
    let end = Math.min(safeTotal - 1, safePage + 2);

    if (safePage <= 4) end = Math.min(6, safeTotal - 1);
    if (safePage >= safeTotal - 3) start = Math.max(2, safeTotal - 5);

    if (start > 2) tokens.push('ellipsis-start');
    for (let pageNum = start; pageNum <= end; pageNum++) tokens.push(pageNum);
    if (end < safeTotal - 1) tokens.push('ellipsis-end');
    tokens.push(safeTotal);
    return tokens;
  }

  function actionLabel(action: AccountAction) {
    if (action === 'refresh-token') return '刷新 Token';
    if (action === 'validate-token') return '验证 Token';
    if (action === 'reupload') return '重新上传';
    if (action === 'oauth') return 'OAuth';
    if (action === 'chatgpt-login') return 'ChatGPT 登录';
    return '删除';
  }

  function statusLabel(status: string) {
    const labels: Record<string, string> = { active: '活跃', expired: '过期', temp: '临时', failed: '失败' };
    return labels[status] ?? status;
  }

  function statusVariant(status: string) {
    const map: Record<string, 'active' | 'expired' | 'temp' | 'failed'> = { active: 'active', expired: 'expired', temp: 'temp', failed: 'failed' };
    return map[status] ?? 'default';
  }

  function uploadLabel(state: string) { return state === 'uploaded' ? '已上传' : '未上传'; }
  function uploadVariant(state: string) { return state === 'uploaded' ? 'uploaded' as const : 'not-uploaded' as const; }

  function formatExactTime(value: number | undefined | null) {
    if (!value) return '—';
    return new Date(value * 1000).toLocaleString();
  }

  function formatRelativeTime(value: number | undefined | null) {
    if (!value) return '从未';
    const ms = value * 1000;
    const diff = Date.now() - ms;
    if (diff < 60_000) return '刚刚';
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
    if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} 天前`;
    return new Date(ms).toLocaleDateString();
  }

  function hasValue(value: string | undefined | null) {
    return Boolean(value && value.trim());
  }

  function validationLabel(result: TokenValidationDetail | null | undefined) {
    if (!result) return '尚未验证';
    if (result.valid) return 'Token 有效';
    return result.error || 'Token 无效';
  }

  function validationMeta(result: TokenValidationDetail | null | undefined) {
    if (!result) return latestValidation?.validated_at ? '最近一次验证未包含当前账号' : '点击验证后显示结果';
    const http = result.http_status > 0 ? `HTTP ${result.http_status}` : '未取得 HTTP 状态';
    return `${http} · ${latestValidation?.proxy_used ? '已使用活跃代理' : '直连'}`;
  }

  function secretVisible(key: SecretKey) {
    if (key === 'password') return showPassword;
    if (key === 'access_token') return showAccessToken;
    if (key === 'refresh_token') return showRefreshToken;
    if (key === 'id_token') return showIdToken;
    if (key === 'session_token') return showSessionToken;
    return showCookies;
  }

  function toggleSecret(key: SecretKey) {
    if (key === 'password') showPassword = !showPassword;
    if (key === 'access_token') showAccessToken = !showAccessToken;
    if (key === 'refresh_token') showRefreshToken = !showRefreshToken;
    if (key === 'id_token') showIdToken = !showIdToken;
    if (key === 'session_token') showSessionToken = !showSessionToken;
    if (key === 'cookies') showCookies = !showCookies;
  }

  function secretPreview(value: string, visible: boolean) {
    if (!hasValue(value)) return '暂无数据';
    if (visible) return value;
    if (value.length <= 14) return '•'.repeat(8);
    return `${value.slice(0, 6)}${'•'.repeat(8)}${value.slice(-6)}`;
  }

  async function copyToClipboard(value: string | undefined | null, key: string, label = '内容') {
    if (!hasValue(value)) return;
    const text = value ?? '';
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
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
    uploadFilter = '';
    authSourceFilter = '';
    loadAccounts(true);
  }

  onMount(() => { refreshPage(true); });
</script>

<PageHeader
  title="账号管理"
  subtitle="账号"
  description="管理已注册账号的状态、Token 与上传情况，可批量执行 OAuth、刷新、验证与删除。"
>
  <button class="btn" type="button" onclick={() => refreshPage(false)} disabled={loading || actionBusy}>
    <Icon name="refresh" size={14} />
    刷新
  </button>
</PageHeader>

<section class="stat-strip" aria-label="账号状态">
  {#each summaryCards as item}
    <div class={`stat-chip ${item.klass}`}>
      <span class="stat-chip-label"><Icon name={item.icon} size={12} /> {item.label}</span>
      <span class="stat-chip-value">{item.value}</span>
    </div>
  {/each}
</section>

<Panel title="账号列表" subtitle={`本页 ${accounts.length} 条 · 匹配 ${initialLoaded ? totalCount : summary.total}`}>
  <div class="filter-bar accounts-filter-bar">
    <label class="form-field">
      <span class="form-label">搜索</span>
      <div class="search-input">
        <span class="search-input-icon"><Icon name="search" size={14} /></span>
        <input class="input" bind:value={searchText} placeholder="ID 或邮箱" onkeydown={(event) => event.key === 'Enter' && loadAccounts(true)} />
        {#if searchText}
          <button class="search-input-clear" type="button" onclick={() => { searchText = ''; loadAccounts(true); }} aria-label="清空">
            <Icon name="close" size={12} />
          </button>
        {/if}
      </div>
    </label>
    <label class="form-field">
      <span class="form-label">状态</span>
      <select class="input" bind:value={statusFilter} onchange={() => loadAccounts(true)}>
        {#each statusOptions as opt}<option value={opt.value}>{opt.label}</option>{/each}
      </select>
    </label>
    <label class="form-field">
      <span class="form-label">上传</span>
      <select class="input" bind:value={uploadFilter} onchange={() => loadAccounts(true)}>
        {#each uploadOptions as opt}<option value={opt.value}>{opt.label}</option>{/each}
      </select>
    </label>
    <label class="form-field">
      <span class="form-label">来源</span>
      <select class="input" bind:value={authSourceFilter} onchange={() => loadAccounts(true)}>
        {#each authSourceOptions as opt}<option value={opt.value}>{opt.label}</option>{/each}
      </select>
    </label>
    <label class="form-field">
      <span class="form-label">每页</span>
      <select class="input" bind:value={limit} onchange={() => loadAccounts(true)}>
        <option value={50}>50</option>
        <option value={100}>100</option>
        <option value={200}>200</option>
      </select>
    </label>
    <button class="btn filter-btn" type="button" onclick={() => loadAccounts(true)} disabled={loading}>
      <Icon name="search" size={12} />
      查询
    </button>
  </div>

  {#if hasFilter}
    <div style="margin-bottom: 14px; font-size: 12px; color: var(--nx-ink-muted);">
      <button class="btn-link" type="button" onclick={clearFilters}>
        <Icon name="close" size={11} />
        清空筛选条件
      </button>
    </div>
  {/if}

  {#if selectedIds.length > 0}
    <div class="bulk-bar">
      <span class="bulk-meta">已选 <strong style="color: var(--nx-ink); font-weight: 600;">{selectedIds.length}</strong> 个</span>
      <button class="btn btn-sm btn-primary" type="button" onclick={() => runAction('oauth', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="zap" size={12} />
        OAuth
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('chatgpt-login', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="globe" size={12} />
        ChatGPT 登录
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('refresh-token', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="refresh" size={12} />
        刷新
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('validate-token', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="shield" size={12} />
        验证
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('reupload', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="upload" size={12} />
        上传
      </button>
      <button class="btn btn-sm btn-danger" type="button" onclick={() => runAction('delete', selectedIds)} disabled={loading || actionBusy}>
        <Icon name="trash" size={12} />
        删除
      </button>
      <span class="divider-vertical"></span>
      <label class="bulk-inline-field">
        <span>并发</span>
        <input class="input input-sm bulk-number" type="number" min="1" max="5000" bind:value={oauthConcurrency} disabled={loading || actionBusy} />
      </label>
      <button class="btn btn-sm btn-ghost" type="button" onclick={() => selectedIds = []}>取消选择</button>
    </div>
  {/if}

  {#if !initialLoaded}
    <div class="table-wrap has-cards">
      <table class="data-table account-data-table">
        <thead>
          <tr>
            <th class="col-check"></th>
            <th>ID</th>
            <th>账号邮箱</th>
            <th>状态</th>
            <th>上传</th>
            <th>来源</th>
            <th>时间</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each Array(5) as _, i (i)}
            <tr>
              <td class="col-check"><Skeleton width="16px" height="16px" /></td>
              <td><Skeleton width="50px" height="13px" /></td>
              <td><Skeleton width="180px" height="14px" /><Skeleton width="120px" height="10px" style="margin-top: 6px;" /></td>
              <td><Skeleton width="60px" height="22px" rounded="full" /></td>
              <td><Skeleton width="60px" height="22px" rounded="full" /></td>
              <td><Skeleton width="70px" height="22px" rounded="full" /></td>
              <td><Skeleton width="100px" height="12px" /></td>
              <td><Skeleton width="160px" height="22px" /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else if accounts.length === 0}
    <EmptyState
      title="暂无账号"
      message={hasFilter ? '没有匹配筛选条件的账号' : '通过注册工作台创建第一个账号'}
      icon="user"
    >
      {#if hasFilter}
        {#snippet action()}
          <button class="btn btn-sm" type="button" onclick={clearFilters}>清空筛选</button>
        {/snippet}
      {/if}
    </EmptyState>
  {:else}
    <div class="table-wrap has-cards">
      <table class="data-table account-data-table">
        <thead>
          <tr>
            <th class="col-check"><input type="checkbox" checked={allVisibleSelected} onchange={toggleAllVisible} aria-label="选择当前页" /></th>
            <th>ID</th>
            <th>账号邮箱</th>
            <th>状态</th>
            <th>上传</th>
            <th>来源</th>
            <th>更新</th>
            <th style="text-align: right;">操作</th>
          </tr>
        </thead>
        <tbody>
          {#each accounts as account (account.id)}
            <tr
              class:row-selected={selectedIds.includes(account.id)}
              class:row-detail-selected={detailOpen && selectedAccountId === account.id}
              class="account-row"
              tabindex="0"
              onclick={() => selectAccount(account.id)}
              onkeydown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectAccount(account.id); } }}
            >
              <td class="col-check">
                <input type="checkbox" checked={selectedIds.includes(account.id)} onchange={(event) => toggleAccount(event, account.id)} onclick={(event) => event.stopPropagation()} aria-label={`选择账号 ${account.id}`} />
              </td>
              <td><span class="cell-mono">#{account.id}</span></td>
              <td class="account-email-cell">
                <span class="cell-primary">{account.email}</span>
                <span class="cell-secondary">注册 {formatRelativeTime(account.created_at)}</span>
              </td>
              <td><StatusBadge label={statusLabel(account.status)} variant={statusVariant(account.status)} /></td>
              <td><StatusBadge label={uploadLabel(account.upload_state)} variant={uploadVariant(account.upload_state)} /></td>
              <td>
                {#if account.auth_source === 'chatgpt2api'}
                  <span class="tag" style="background: rgba(99,102,241,0.14); color: #6366f1;">ChatGPT2API</span>
                {:else}
                  <span class="cell-secondary">普通</span>
                {/if}
              </td>
              <td>
                <span class="cell-primary" style="font-weight: 400;">{formatRelativeTime(account.updated_at)}</span>
                {#if account.last_refreshed_at}<span class="cell-secondary">刷新 {formatRelativeTime(account.last_refreshed_at)}</span>{/if}
              </td>
              <td>
                <div class="inline-actions">
                  <button class="btn btn-xs" type="button" onclick={(event) => { event.stopPropagation(); selectAccount(account.id); }} aria-label="查看" title="查看">
                    <Icon name="info" size={11} />
                  </button>
                  <button class="btn btn-xs btn-primary" type="button" onclick={(event) => runSingleAction(event, 'oauth', account.id)} disabled={actionBusy} aria-label="OAuth" title="OAuth">
                    <Icon name="zap" size={11} />
                  </button>
                  <button class="btn btn-xs" type="button" onclick={(event) => runSingleAction(event, 'chatgpt-login', account.id)} disabled={actionBusy} aria-label="ChatGPT 登录" title="ChatGPT 登录">
                    <Icon name="globe" size={11} />
                  </button>
                  <button class="btn btn-xs" type="button" onclick={(event) => runSingleAction(event, 'refresh-token', account.id)} disabled={actionBusy} aria-label="刷新 Token" title="刷新 Token">
                    <Icon name="refresh" size={11} />
                  </button>
                  <button class="btn btn-xs" type="button" onclick={(event) => runSingleAction(event, 'validate-token', account.id)} disabled={actionBusy} aria-label="验证 Token" title="验证 Token">
                    <Icon name="shield" size={11} />
                  </button>
                  <button class="btn btn-xs" type="button" onclick={(event) => runSingleAction(event, 'reupload', account.id)} disabled={actionBusy} aria-label="重新上传" title="重新上传">
                    <Icon name="upload" size={11} />
                  </button>
                  <button class="btn btn-xs btn-danger" type="button" onclick={(event) => runSingleAction(event, 'delete', account.id)} disabled={actionBusy} aria-label="删除" title="删除">
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
      {#each accounts as account (account.id)}
        <div
          class="data-card"
          class:is-selected={selectedIds.includes(account.id)}
          role="listitem"
        >
          <input
            class="data-card-checkbox"
            type="checkbox"
            checked={selectedIds.includes(account.id)}
            onchange={(event) => toggleAccount(event, account.id)}
            aria-label={`选择账号 ${account.id}`}
          />
          <div class="data-card-head">
            <button type="button" class="data-card-title" style="background: transparent; border: 0; padding: 0; cursor: pointer; text-align: left; color: inherit;" onclick={() => selectAccount(account.id)}>
              {account.email}
            </button>
          </div>
          <div style="display: flex; gap: 6px; flex-wrap: wrap;">
            <StatusBadge label={statusLabel(account.status)} variant={statusVariant(account.status)} />
            <StatusBadge label={uploadLabel(account.upload_state)} variant={uploadVariant(account.upload_state)} />
            {#if account.auth_source === 'chatgpt2api'}<span class="tag" style="background: rgba(99,102,241,0.14); color: #6366f1;">ChatGPT2API</span>{/if}
            <span class="tag">#{account.id}</span>
          </div>
          <div class="data-card-meta">
            <span>注册 {formatRelativeTime(account.created_at)}</span>
            <span>更新 {formatRelativeTime(account.updated_at)}</span>
            {#if account.last_refreshed_at}<span>最后刷新 {formatRelativeTime(account.last_refreshed_at)}</span>{/if}
          </div>
          <div class="data-card-actions">
            <button class="btn btn-xs" type="button" onclick={() => selectAccount(account.id)} aria-label="查看" title="查看">
              <Icon name="info" size={11} /> 查看
            </button>
            <button class="btn btn-xs btn-primary" type="button" onclick={() => runAction('oauth', [account.id])} disabled={actionBusy} aria-label="OAuth" title="OAuth">
              <Icon name="zap" size={11} /> OAuth
            </button>
            <button class="btn btn-xs" type="button" onclick={() => runAction('chatgpt-login', [account.id])} disabled={actionBusy} aria-label="ChatGPT 登录" title="ChatGPT 登录">
              <Icon name="globe" size={11} /> ChatGPT
            </button>
            <button class="btn btn-xs" type="button" onclick={() => runAction('refresh-token', [account.id])} disabled={actionBusy} aria-label="刷新 Token" title="刷新 Token">
              <Icon name="refresh" size={11} /> 刷新
            </button>
            <button class="btn btn-xs" type="button" onclick={() => runAction('validate-token', [account.id])} disabled={actionBusy} aria-label="验证 Token" title="验证 Token">
              <Icon name="shield" size={11} /> 验证
            </button>
            <button class="btn btn-xs" type="button" onclick={() => runAction('reupload', [account.id])} disabled={actionBusy} aria-label="重新上传" title="重新上传">
              <Icon name="upload" size={11} /> 上传
            </button>
            <button class="btn btn-xs btn-danger" type="button" onclick={() => runAction('delete', [account.id])} disabled={actionBusy} aria-label="删除" title="删除">
              <Icon name="trash" size={11} /> 删除
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}

  {#if initialLoaded}
    <div class="pagination-bar account-pagination">
      <span class="pagination-summary">
        {#if loading}
          加载中…
        {:else}
          显示 {pageStart}-{pageEnd} / {totalCount} 条
        {/if}
      </span>

      <div class="pagination-controls" aria-label="账号列表分页">
        <button class="btn btn-sm" type="button" onclick={previousPage} disabled={loading || currentPage <= 1}>
          <Icon name="chevron-left" size={12} /> 上一页
        </button>

        <div class="page-number-group">
          {#each pageTokens as token (token)}
            {#if typeof token === 'number'}
              <button
                class="btn btn-sm page-number"
                class:active={token === currentPage}
                type="button"
                aria-current={token === currentPage ? 'page' : undefined}
                onclick={() => goToPage(token)}
                disabled={loading}
              >
                {token}
              </button>
            {:else}
              <span class="pagination-ellipsis" aria-hidden="true">…</span>
            {/if}
          {/each}
        </div>

        <button class="btn btn-sm" type="button" onclick={nextPage} disabled={loading || currentPage >= totalPages}>
          下一页 <Icon name="chevron-right" size={12} />
        </button>
      </div>

      <form class="pagination-jump" onsubmit={(event) => { event.preventDefault(); submitJumpPage(); }}>
        <span>跳至</span>
        <input
          class="input input-sm pagination-jump-input"
          type="number"
          min="1"
          max={totalPages}
          bind:value={jumpPageText}
          disabled={loading}
          aria-label="跳转页码"
        />
        <span>页</span>
        <button class="btn btn-sm" type="submit" disabled={loading}>跳转</button>
      </form>
    </div>
  {/if}
</Panel>

<Modal
  open={detailOpen}
  title="账号详情"
  kicker={detailAccount ? `#${detailAccount.id}` : 'DETAIL'}
  size="md"
  onclose={clearAccountDetail}
>
  {#if !detailAccount}
    <EmptyState message="正在读取账号详情" icon={false} />
  {:else}
    <div class="account-detail-stack">
      <div class="account-detail-head">
        <h3 style="word-break: break-all;">{detailAccount.email}</h3>
        <div class="account-detail-badges">
          <StatusBadge label={statusLabel(detailAccount.status)} variant={statusVariant(detailAccount.status)} />
          <StatusBadge label={uploadLabel(detailAccount.upload_state)} variant={uploadVariant(detailAccount.upload_state)} />
          {#if detailAccount.auth_source === 'chatgpt2api'}<span class="tag" style="background: rgba(99,102,241,0.14); color: #6366f1;">ChatGPT2API</span>{/if}
        </div>
        <div class="account-detail-actions">
          <button class="btn btn-sm" type="button" onclick={() => copyToClipboard(detailAccount?.email, 'email', '邮箱')} disabled={!detailAccount?.email}>
            <Icon name={copiedKey === 'email' ? 'check' : 'copy'} size={12} />
            复制邮箱
          </button>
          <button class="btn btn-sm" type="button" onclick={() => runAction('validate-token', [detailAccount.id])} disabled={actionBusy}>
            <Icon name="shield" size={12} />
            验证 Token
          </button>
          <button class="btn btn-sm btn-primary" type="button" onclick={() => runAction('oauth', [detailAccount.id])} disabled={actionBusy}>
            <Icon name="zap" size={12} />
            执行 OAuth
          </button>
          <button class="btn btn-sm" type="button" onclick={() => runAction('chatgpt-login', [detailAccount.id])} disabled={actionBusy}>
            <Icon name="globe" size={12} />
            ChatGPT 登录
          </button>
        </div>
      </div>

      {#if detailLoading}
        <div style="display: grid; gap: 12px;">
          <Skeleton height="20px" />
          <Skeleton height="120px" rounded="md" />
          <Skeleton height="80px" rounded="md" />
        </div>
      {:else if detailError}
        <div class="notice-bar notice-error">
          <span class="notice-icon"><Icon name="alert-circle" size={14} /></span>
          <span class="notice-text">{detailError}</span>
        </div>
      {:else if accountDetail}
        <section class="account-detail-section">
          <h4>时间信息</h4>
          <div class="detail-list">
            {#each detailTimeRows as row}
              <div class="detail-row">
                <span class="detail-label">{row.label}</span>
                <span class="detail-value">{row.value}</span>
              </div>
            {/each}
          </div>
        </section>

        <section class="account-detail-section">
          <h4>Token 验证</h4>
          <div class={`notice-bar ${detailValidation?.valid ? 'notice-success' : detailValidation ? 'notice-error' : ''}`}>
            <span class="notice-icon"><Icon name={detailValidation?.valid ? 'check-circle' : detailValidation ? 'alert-circle' : 'shield'} size={14} /></span>
            <span class="notice-text">
              <strong>{validationLabel(detailValidation)}</strong>
              <span class="account-validation-meta">{validationMeta(detailValidation)}</span>
            </span>
          </div>
        </section>

        <section class="account-detail-section">
          <h4>账号标识</h4>
          <div class="detail-list">
            {#each detailIdentityRows as row}
              <div class="detail-row detail-row-copy">
                <span class="detail-label">{row.label}</span>
                <span class="detail-value detail-value-code">{hasValue(row.value) ? row.value : '—'}</span>
                <button class="copy-btn" type="button" onclick={() => copyToClipboard(row.value, row.key, row.copyLabel)} disabled={!hasValue(row.value)} aria-label="复制">
                  <Icon name={copiedKey === row.key ? 'check' : 'copy'} size={12} />
                </button>
              </div>
            {/each}
          </div>
        </section>

        <section class="account-detail-section">
          <h4>凭据与 Token</h4>
          <div class="credential-list">
            {#each detailCredentials as item}
              <div class="credential-row">
                <div class="credential-title">
                  <span>{item.label}</span>
                  <span style="font-weight: 400; font-family: var(--font-mono);">{hasValue(item.value) ? `${item.value.length} 字符` : '空'}</span>
                </div>
                <pre class="credential-value" class:credential-empty={!hasValue(item.value)}>{secretPreview(item.value, secretVisible(item.key))}</pre>
                <div class="credential-actions">
                  <button class="btn btn-xs" type="button" onclick={() => toggleSecret(item.key)} disabled={!hasValue(item.value)}>
                    <Icon name={secretVisible(item.key) ? 'eye-off' : 'eye'} size={11} />
                    {secretVisible(item.key) ? '隐藏' : '显示'}
                  </button>
                  <button class="btn btn-xs" type="button" onclick={() => copyToClipboard(item.value, item.key, item.copyLabel)} disabled={!hasValue(item.value)}>
                    <Icon name={copiedKey === item.key ? 'check' : 'copy'} size={11} />
                    复制
                  </button>
                </div>
              </div>
            {/each}
          </div>
        </section>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    {#if accountDetail}
      <button class="btn btn-sm btn-danger" type="button" onclick={() => runAction('delete', [accountDetail.id])} disabled={actionBusy}>
        <Icon name="trash" size={12} />
        删除
      </button>
      <span class="flex-spacer"></span>
      <button class="btn btn-sm" type="button" onclick={() => runAction('refresh-token', [accountDetail.id])} disabled={actionBusy}>
        <Icon name="refresh" size={12} />
        刷新 Token
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('validate-token', [accountDetail.id])} disabled={actionBusy}>
        <Icon name="shield" size={12} />
        验证 Token
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('reupload', [accountDetail.id])} disabled={actionBusy}>
        <Icon name="upload" size={12} />
        重新上传
      </button>
      <button class="btn btn-sm" type="button" onclick={() => runAction('chatgpt-login', [accountDetail.id])} disabled={actionBusy}>
        <Icon name="globe" size={12} />
        ChatGPT 登录
      </button>
    {/if}
  {/snippet}
</Modal>
