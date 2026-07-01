<script lang="ts">
  import { onMount, tick } from 'svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import StatusBadge from '../components/StatusBadge.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon, { type IconName } from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { toast } from '../lib/toast';

  type RegistrationStatus = {
    ok: number; engine: string; provider_ready: number;
    default_request_core?: string; request_cores?: string[];
    curl_impersonate_ready?: number; libcurl_impersonate_ready?: number;
    libcurl_ready?: number;
    active_tasks: number; active_flows: number; queued_flows: number;
    active_domains: number; active_proxies: number; temp_accounts: number;
  };

  type RegistrationTask = {
    id: string; status: string; mode?: string; workflow?: string;
    scheduler_mode?: string; register_provider?: string; target_metric?: string;
    request_core?: string; libcurl_impersonate_target?: string;
    mihomo_node?: string; mihomo_proxy_url?: string; mihomo_task_proxy?: number;
    auto_upload_service_mode?: string; auto_upload_service_id?: number;
    auto_upload_service_name?: string;
    count?: number; target_count?: number; concurrency: number;
    max_inflight?: number; oauth_delay_seconds?: number; detailed_logs: number;
    auto_upload_oauth_success?: number;
    discard_oauth_failed_accounts?: number;
    fast_email_otp_resend?: number;
    current_session_oauth_fallback?: number;
    current_session_oauth_fallback_mode?: string;
    current_session_oauth_retry_after_seconds?: number;
    infinite?: number; stop_requested?: number;
    started: number; active: number; success: number; failed: number;
    register_success?: number; register_failed?: number;
    oauth_success?: number; oauth_failed?: number; expired_written?: number;
    upload_success?: number; upload_failed?: number; upload_skipped?: number;
    fastlane_pre_email_active?: number; fastlane_waiting_email?: number;
    fastlane_post_email_active?: number; fastlane_alive_total?: number;
    log_count?: number; log_limit?: number;
    created_ms: number; started_ms: number; updated_ms: number; finished_ms: number;
    error: string;
  };

  type RegistrationLog = {
    seq: number; ts_ms: number; level: string; flow_id: string; message: string;
  };

  type MihomoConfig = {
    mode?: string;
    enabled?: boolean;
    process_running?: boolean;
    managed?: boolean;
    proxy_url?: string;
  };

  type MihomoNodes = {
    ok: number;
    group_name: string;
    now: string;
    nodes: string[];
    count: number;
    error?: string;
  };

  type UploadService = {
    id: number;
    name: string;
    enabled: number;
    provider_id?: string;
    provider_name?: string;
    chatgpt_web_provider_id?: string;
    chatgpt_web_provider_name?: string;
  };

  type UploadConfig = {
    services: UploadService[];
  };

  type Workflow = 'register_only' | 'register_then_oauth' | 'register_then_current_codex' | 'codex_cli_simplified' | 'outlook_direct';
  type SchedulerMode = 'normal' | 'fastlane';
  type TargetMetric = 'register_task' | 'oauth_success';
  type RegisterProvider = 'platform' | 'temporary';
  type RequestCore = 'curl_impersonate' | 'libcurl_impersonate';
  type CurrentSessionOauthFallbackMode = 'single' | 'double' | 'single_timeout_retry';
  type AutoUploadServiceChoice = 'random' | 'all' | `fixed:${number}`;

  type LibcurlTargetOption = { value: string; label: string };
  type LibcurlTargetGroup = { label: string; options: LibcurlTargetOption[] };

  const emptyStatus: RegistrationStatus = {
    ok: 0, engine: 'curl-impersonate', provider_ready: 0,
    active_tasks: 0, active_flows: 0, queued_flows: 0,
    active_domains: 0, active_proxies: 0, temp_accounts: 0
  };

  const workflowOptions: { value: Workflow; label: string; hint: string; icon: IconName }[] = [
    { value: 'register_only', label: '单独注册', hint: '只完成注册流程，不做 OAuth 授权', icon: 'check' },
    { value: 'register_then_current_codex', label: 'Codex 极速', hint: '复用 Platform 登录态直接完成 Codex OAuth', icon: 'zap' },
    { value: 'register_then_oauth', label: '注册 + OAuth', hint: '注册成功后再走独立 OAuth 授权', icon: 'link' },
    { value: 'codex_cli_simplified', label: 'Codex 直注', hint: 'Codex CLI 直连注册，Team 域跳过手机号', icon: 'zap' },
    { value: 'outlook_direct', label: 'Outlook 直注', hint: 'Outlook 母邮箱直注，outlook007 接码，注册后走当前会话 Codex OAuth（独立工作空间）', icon: 'mail' }
  ];

  const schedulerOptions: { value: SchedulerMode; label: string; hint: string; icon: IconName }[] = [
    { value: 'normal', label: '常规', hint: '稳定的并发上限', icon: 'activity' },
    { value: 'fastlane', label: '高速', hint: '前后置错峰，吞吐更高', icon: 'zap' }
  ];

  const registerProviderOptions: { value: RegisterProvider; label: string; hint: string; icon: IconName }[] = [
    { value: 'platform', label: '过期账号', hint: '复用过期账号继续注册', icon: 'database' },
    { value: 'temporary', label: '临时账号', hint: '使用临时账号入口', icon: 'inbox' }
  ];

  const requestCoreOptions: { value: RequestCore; label: string; hint: string }[] = [
    { value: 'libcurl_impersonate', label: 'libcurl-impersonate', hint: '默认核心，进程内动态库，保留 Chrome TLS 指纹' },
    { value: 'curl_impersonate', label: 'curl-impersonate', hint: '外部命令核心，兼容原有执行方式' }
  ];

  const currentSessionOauthFallbackOptions: { value: CurrentSessionOauthFallbackMode; label: string; hint: string }[] = [
    { value: 'single', label: '单 OA', hint: '当前会话失败后只走一次独立 OAuth' },
    { value: 'double', label: '双 OA', hint: '当前会话失败后启动两路独立 OAuth 抢码' },
    { value: 'single_timeout_retry', label: '超时二次', hint: '先走单路，超过设定秒数仍未收到验证码即触发第二路' }
  ];

  const defaultLibcurlImpersonateTarget = 'chrome145';

  const libcurlTargetGroups: LibcurlTargetGroup[] = [
    {
      label: 'Chrome',
      options: [
        { value: 'chrome99', label: 'Chrome 99' },
        { value: 'chrome99_android', label: 'Chrome 99 Android' },
        { value: 'chrome100', label: 'Chrome 100' },
        { value: 'chrome101', label: 'Chrome 101' },
        { value: 'chrome104', label: 'Chrome 104' },
        { value: 'chrome107', label: 'Chrome 107' },
        { value: 'chrome110', label: 'Chrome 110' },
        { value: 'chrome116', label: 'Chrome 116' },
        { value: 'chrome119', label: 'Chrome 119' },
        { value: 'chrome120', label: 'Chrome 120' },
        { value: 'chrome123', label: 'Chrome 123' },
        { value: 'chrome124', label: 'Chrome 124' },
        { value: 'chrome131', label: 'Chrome 131' },
        { value: 'chrome131_android', label: 'Chrome 131 Android' },
        { value: 'chrome133a', label: 'Chrome 133a' },
        { value: 'chrome136', label: 'Chrome 136' },
        { value: 'chrome142', label: 'Chrome 142' },
        { value: 'chrome145', label: 'Chrome 145' },
        { value: 'chrome146', label: 'Chrome 146' }
      ]
    },
    {
      label: 'Edge',
      options: [
        { value: 'edge99', label: 'Edge 99' },
        { value: 'edge101', label: 'Edge 101' }
      ]
    },
    {
      label: 'Firefox',
      options: [
        { value: 'firefox133', label: 'Firefox 133' },
        { value: 'firefox135', label: 'Firefox 135' },
        { value: 'firefox144', label: 'Firefox 144' },
        { value: 'firefox147', label: 'Firefox 147' }
      ]
    },
    {
      label: 'Safari',
      options: [
        { value: 'safari153', label: 'Safari 15.3' },
        { value: 'safari15_3', label: 'Safari 15.3' },
        { value: 'safari155', label: 'Safari 15.5' },
        { value: 'safari15_5', label: 'Safari 15.5' },
        { value: 'safari170', label: 'Safari 17.0' },
        { value: 'safari17_0', label: 'Safari 17.0' },
        { value: 'safari172_ios', label: 'Safari 17.2 iOS' },
        { value: 'safari17_2_ios', label: 'Safari 17.2 iOS' },
        { value: 'safari180', label: 'Safari 18.0' },
        { value: 'safari18_0', label: 'Safari 18.0' },
        { value: 'safari180_ios', label: 'Safari 18.0 iOS' },
        { value: 'safari18_0_ios', label: 'Safari 18.0 iOS' },
        { value: 'safari184', label: 'Safari 18.4' },
        { value: 'safari18_4', label: 'Safari 18.4' },
        { value: 'safari184_ios', label: 'Safari 18.4 iOS' },
        { value: 'safari18_4_ios', label: 'Safari 18.4 iOS' },
        { value: 'safari260', label: 'Safari 26.0' },
        { value: 'safari26_0', label: 'Safari 26.0' },
        { value: 'safari2601', label: 'Safari 26.0.1' },
        { value: 'safari26_0_1', label: 'Safari 26.0.1' },
        { value: 'safari260_ios', label: 'Safari 26.0 iOS' },
        { value: 'safari26_0_ios', label: 'Safari 26.0 iOS' }
      ]
    }
  ];

  const targetOptions: { value: TargetMetric; label: string }[] = [
    { value: 'register_task', label: '注册任务数' },
    { value: 'oauth_success', label: 'OAuth 成功数' }
  ];

  let status = $state(emptyStatus);
  let workflow: Workflow = $state('register_only');
  let schedulerMode: SchedulerMode = $state('normal');
  let registerProvider: RegisterProvider = $state('platform');
  let requestCore: RequestCore = $state('libcurl_impersonate');
  let libcurlImpersonateTarget = $state(defaultLibcurlImpersonateTarget);
  let targetMetric: TargetMetric = $state('register_task');
  let targetCount = $state(10);
  let concurrency = $state(20);
  let maxInflight = $state(20);
  let oauthDelaySeconds = $state(0);
  let infiniteMode = $state(false);
  let detailedLogs = $state(false);
  let fastEmailOtpResend = $state(true);
  let autoUploadOauthSuccess = $state(false);
  let discardOauthFailedAccounts = $state(false);
  let currentSessionOauthFallbackEnabled = $state(true);
  let currentSessionOauthFallbackMode: CurrentSessionOauthFallbackMode = $state('double');
  let currentSessionOauthRetryAfterSeconds = $state(30);
  let tasks: RegistrationTask[] = $state([]);
  let selectedTask: RegistrationTask | null = $state(null);
  let logs: RegistrationLog[] = $state([]);
  let starting = $state(false);
  let initialLoaded = $state(false);
  let tasksLoading = $state(false);
  let taskListError = $state('');
  let mihomoConfig: MihomoConfig = $state({});
  let mihomoNodes: MihomoNodes | null = $state(null);
  let mihomoNodesLoading = $state(false);
  let taskMihomoNode = $state('');
  let mihomoLoadError = $state('');
  let uploadConfig: UploadConfig | null = $state(null);
  let uploadConfigLoading = $state(false);
  let uploadConfigError = $state('');
  let autoUploadServiceChoice: AutoUploadServiceChoice = $state('random');
  let wsState = $state<'connecting' | 'open' | 'closed' | 'error'>('closed');
  let ws: WebSocket | null = null;
  let logsOpen = $state(false);
  let detailLogList = $state(null as HTMLOListElement | null);
  let modalLogList = $state(null as HTMLOListElement | null);
  let expandedLogs: Set<number> = $state(new Set());
  let now = $state(Date.now());
  let taskLoadSeq = 0;
  let selectedTaskLoadSeq = 0;

  // Section visibility (collapsible groups)
  let showExecution = $state(true);
  let showAdvanced = $state(false);

  const LOG_STICK_THRESHOLD = 24;
  const LOG_KEEP_LIMIT = 120;
  const LOG_VIEW_LIMIT = 60;
  const LOG_MODAL_LIMIT = 120;
  const MIN_VALID_EPOCH_MS = 1_600_000_000_000;

  let effectiveTargetMetric = $derived(workflow === 'register_only' ? 'register_task' : targetMetric);
  let selectedTaskCanStop = $derived(Boolean(selectedTask && ['queued', 'running', 'stopping'].includes(selectedTask.status)));
  let isFastlane = $derived(schedulerMode === 'fastlane');
  let isWithOauth = $derived(workflow !== 'register_only');
  let usesIndependentOauth = $derived(workflow === 'register_then_oauth');
  let usesCurrentSessionCodex = $derived(workflow === 'register_then_current_codex');
  let currentSessionOauthFallbackActive = $derived(usesCurrentSessionCodex && currentSessionOauthFallbackEnabled);
  let mihomoTaskPickerVisible = $derived(mihomoConfig.mode === 'mihomo' && Boolean(mihomoConfig.enabled));
  let mihomoSelectableNodes = $derived((mihomoNodes?.nodes ?? []).filter(isSelectableMihomoNode));
  let enabledUploadServices = $derived((uploadConfig?.services ?? []).filter((service) => Boolean(service.enabled)));
  let autoUploadServiceSummary = $derived(autoUploadChoiceLabel(autoUploadServiceChoice));

  let kpiCards = $derived([
    {
      label: '运行任务',
      value: status.active_tasks,
      sub: `${status.active_flows} 个流程进行中`,
      icon: 'activity' as IconName,
      tone: status.active_tasks > 0 ? 'success' : 'default'
    },
    {
      label: '可用域名',
      value: status.active_domains,
      sub: status.active_domains > 0 ? '已就绪' : '暂无可用',
      icon: 'tag' as IconName,
      tone: status.active_domains > 0 ? 'default' : 'warning'
    },
    {
      label: '活跃代理',
      value: status.active_proxies,
      sub: status.active_proxies > 0 ? '池中可用' : '无可用代理',
      icon: 'globe' as IconName,
      tone: status.active_proxies > 0 ? 'default' : 'warning'
    },
    {
      label: '临时账号',
      value: status.temp_accounts,
      sub: registerProvider === 'temporary' ? '当前来源' : '池中暂存',
      icon: 'inbox' as IconName,
      tone: 'default'
    }
  ]);

  let configSummary = $derived([
    providerLabel(registerProvider),
    workflowLabel(workflow),
    isFastlane ? '高速' : '常规',
    requestCoreLabel(requestCore),
    proxyModeLabel(mihomoConfig.mode),
    isWithOauth && discardOauthFailedAccounts ? '不留 OA 失败' : '',
    isWithOauth && autoUploadOauthSuccess ? `上传:${autoUploadServiceSummary}` : ''
  ].filter(Boolean));

  function statusLabel(value: string) {
    if (value === 'success') return '成功';
    if (value === 'partial') return '部分';
    if (value === 'failed') return '失败';
    if (value === 'running') return '运行中';
    if (value === 'queued') return '排队';
    if (value === 'stopping') return '停止中';
    if (value === 'stopped') return '已停止';
    return value || '-';
  }

  function statusVariant(value: string) {
    if (value === 'success') return 'active' as const;
    if (value === 'partial') return 'temp' as const;
    if (value === 'failed') return 'failed' as const;
    if (value === 'stopping' || value === 'stopped') return 'expired' as const;
    return 'default' as const;
  }

  function workflowLabel(value: string | undefined) {
    if (value === 'register_then_current_codex') return 'Codex 极速';
    if (value === 'register_then_oauth') return '注册 + OAuth';
    if (value === 'oauth_only') return '仅 OAuth';
    return '单独注册';
  }

  function schedulerLabel(value: string | undefined) {
    return value === 'fastlane' ? '高速' : '常规';
  }

  function taskUsesFastlane(task: RegistrationTask | null) {
    return (task?.scheduler_mode ?? 'normal') === 'fastlane';
  }

  function metricLabel(value: string | undefined) {
    return value === 'oauth_success' ? 'OAuth 成功' : '注册任务';
  }

  function providerLabel(value: string | undefined) {
    return value === 'temporary' ? '临时账号' : '过期账号';
  }

  function taskProviderLabel(task: RegistrationTask | null) {
    if (!task) return '-';
    return (task.workflow ?? task.mode) === 'oauth_only' ? '账号池 OAuth' : providerLabel(task.register_provider);
  }

  function proxyModeLabel(mode: string | undefined) {
    if (mode === 'mihomo') return '代理:Mihomo';
    if (mode === 'direct') return '代理:直连';
    return '代理:代理池';
  }

  function requestCoreLabel(value: string | undefined) {
    if (value === 'libcurl_impersonate' || value === 'libcurl') return 'libcurl-impersonate';
    if (value === 'plain_libcurl' || value === 'libcurl_plain') return 'libcurl';
    return 'curl-impersonate';
  }

  function libcurlTargetLabel(value: string | undefined) {
    const target = value || defaultLibcurlImpersonateTarget;
    for (const group of libcurlTargetGroups) {
      const option = group.options.find((item) => item.value === target);
      if (option) return option.label;
    }
    return target;
  }

  function taskLibcurlTarget(task: RegistrationTask | null) {
    return task?.libcurl_impersonate_target || defaultLibcurlImpersonateTarget;
  }

  function shortNodeLabel(node: string | undefined) {
    if (!node) return '';
    return node.length > 28 ? `${node.slice(0, 28)}…` : node;
  }

  function isSelectableMihomoNode(node: string | undefined) {
    const normalized = node?.trim().toUpperCase() ?? '';
    return Boolean(normalized && normalized !== 'DIRECT' && normalized !== 'REJECT');
  }

  function currentSessionOauthFallbackLabel(value: string | undefined) {
    if (!value || value === 'none' || value === 'off' || value === 'disabled') return '不兜底';
    if (value === 'single') return '单 OAuth 兜底';
    if (value === 'single_timeout_retry') return '超时二次 OA';
    if (value === 'double') return '双 OAuth 兜底';
    return 'OAuth 兜底';
  }

  function uploadServiceName(service: UploadService | undefined) {
    if (!service) return '';
    return service.name || service.provider_name || service.provider_id || `服务 #${service.id}`;
  }

  function parseAutoUploadServiceChoice(choice: string) {
    if (choice === 'all') return { mode: 'all', id: 0 };
    if (choice.startsWith('fixed:')) {
      const id = Number(choice.slice('fixed:'.length)) || 0;
      return { mode: 'fixed', id };
    }
    return { mode: 'random', id: 0 };
  }

  function autoUploadChoiceLabel(choice: string) {
    if (choice === 'all') return '全部服务';
    if (choice.startsWith('fixed:')) {
      const id = Number(choice.slice('fixed:'.length)) || 0;
      const service = enabledUploadServices.find((item) => item.id === id);
      return uploadServiceName(service) || `服务 #${id}`;
    }
    return '随机服务';
  }

  function taskUploadServiceLabel(task: RegistrationTask | null) {
    if (!task?.auto_upload_oauth_success) return '';
    if (task.auto_upload_service_mode === 'all') return '全部服务';
    const name = task.auto_upload_service_name || (task.auto_upload_service_id ? `服务 #${task.auto_upload_service_id}` : '');
    if (task.auto_upload_service_mode === 'fixed') return name ? `指定 ${name}` : '指定服务';
    if (task.auto_upload_service_mode === 'random') return name ? `随机 ${name}` : '随机服务';
    return name || '自动上传';
  }

  function taskTargetLabel(task: RegistrationTask) {
    if (task.infinite) return '∞';
    return String(task.target_count ?? task.count ?? 0);
  }

  function progressPct(task: RegistrationTask) {
    if (task.infinite) return null;
    const target = task.target_count ?? task.count ?? 0;
    if (!target) return null;
    return Math.min(100, Math.max(0, (task.success / target) * 100));
  }

  function progressTone(task: RegistrationTask) {
    if (task.status === 'failed') return 'danger';
    if (task.status === 'stopping' || task.status === 'stopped') return 'warning';
    if (task.failed > 0 && task.success === 0) return 'danger';
    if (task.failed > 0 && task.failed > task.success) return 'warning';
    return 'success';
  }

  function formatRelativeTime(ms: number) {
    if (!isValidWallClockMs(ms)) return '时间待刷新';
    const diff = now - ms;
    if (diff < 5_000) return '刚刚';
    if (diff < 60_000) return `${Math.floor(diff / 1000)} 秒前`;
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
    return new Date(ms).toLocaleString();
  }

  function isValidWallClockMs(ms: number) {
    return Number.isFinite(ms) && ms >= MIN_VALID_EPOCH_MS;
  }

  function formatAbsoluteTime(ms: number) {
    if (!isValidWallClockMs(ms)) return '时间待刷新';
    return new Date(ms).toLocaleString();
  }

  function formatDuration(start: number, end: number) {
    if (!isValidWallClockMs(start)) return '—';
    const endMs = isValidWallClockMs(end) ? end : now;
    const elapsed = endMs >= start ? endMs - start : 0;
    const total = Math.floor(elapsed / 1000);
    if (total < 60) return `${total}s`;
    const minutes = Math.floor(total / 60);
    const seconds = total % 60;
    if (minutes < 60) return `${minutes}分 ${seconds.toString().padStart(2, '0')}秒`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}时 ${mins.toString().padStart(2, '0')}分`;
  }

  function taskElapsedMs(task: RegistrationTask | null) {
    if (!task || !isValidWallClockMs(task.started_ms)) return 0;
    const endMs = isValidWallClockMs(task.finished_ms) ? task.finished_ms : now;
    return endMs >= task.started_ms ? endMs - task.started_ms : 0;
  }

  function formatRatePerMinute(count: number | undefined, task: RegistrationTask | null) {
    const elapsed = taskElapsedMs(task);
    if (elapsed <= 0) return '0/分钟';
    const rate = (Number(count) || 0) * 60_000 / Math.max(elapsed, 1000);
    if (rate >= 100) return `${Math.round(rate)}/分钟`;
    if (rate >= 10) return `${rate.toFixed(1)}/分钟`;
    return `${rate.toFixed(2)}/分钟`;
  }

  function formatPercent(numerator: number | undefined, denominator: number | undefined) {
    const den = Number(denominator) || 0;
    if (den <= 0) return '—';
    const value = Math.max(0, Math.min(100, ((Number(numerator) || 0) / den) * 100));
    return `${value.toFixed(1)}%`;
  }

  function registrationSuccessRate(task: RegistrationTask | null) {
    if (!task) return '—';
    const success = task.register_success ?? 0;
    const failed = task.register_failed ?? 0;
    return formatPercent(success, success + failed);
  }

  function oauthSuccessRate(task: RegistrationTask | null) {
    if (!task) return '—';
    return formatPercent(task.oauth_success ?? 0, task.register_success ?? 0);
  }

  function trimFlowId(flowId: string) {
    if (!flowId) return 'task';
    return flowId.length > 14 ? `${flowId.slice(0, 14)}…` : flowId;
  }

  function formatLogTime(ts: number) {
    if (!ts) return '';
    const d = new Date(ts);
    const hh = d.getHours().toString().padStart(2, '0');
    const mm = d.getMinutes().toString().padStart(2, '0');
    const ss = d.getSeconds().toString().padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
  }

  function isNearLogBottom(element: HTMLElement | null) {
    if (!element) return true;
    return element.scrollHeight - element.scrollTop - element.clientHeight <= LOG_STICK_THRESHOLD;
  }

  function scrollLogToBottom(element: HTMLElement | null) {
    if (!element) return;
    element.scrollTop = element.scrollHeight;
  }

  async function followLogTail(detailShouldStick = isNearLogBottom(detailLogList), modalShouldStick = isNearLogBottom(modalLogList)) {
    await tick();
    if (detailShouldStick) scrollLogToBottom(detailLogList);
    if (modalShouldStick) scrollLogToBottom(modalLogList);
  }

  async function openLogsModal() {
    logsOpen = true;
    await followLogTail(false, true);
  }

  function jumpDetailLogToBottom() {
    scrollLogToBottom(detailLogList);
  }

  function toggleLogExpanded(seq: number) {
    const next = new Set(expandedLogs);
    if (next.has(seq)) next.delete(seq);
    else next.add(seq);
    expandedLogs = next;
  }

  function setLogsLightweight(nextLogs: RegistrationLog[]) {
    const limited = nextLogs.slice(-LOG_KEEP_LIMIT);
    const liveSeq = new Set(limited.map((item) => item.seq));
    if (expandedLogs.size > 0) {
      expandedLogs = new Set([...expandedLogs].filter((seq) => liveSeq.has(seq)));
    }
    logs = limited;
  }

  function handleWorkflowChange() {
    if (workflow === 'register_only') targetMetric = 'register_task';
    if (workflow === 'register_only') autoUploadOauthSuccess = false;
  }

  function errorMessage(err: unknown) {
    return err instanceof Error ? err.message : String(err);
  }

  async function readJsonResponse(response: Response) {
    const text = await response.text();
    let data: any = {};
    if (text.trim()) {
      try {
        data = JSON.parse(text);
      } catch {
        const preview = text.trim().slice(0, 120);
        throw new Error(preview ? `服务端返回了非 JSON 响应：${preview}` : '服务端返回了非 JSON 响应');
      }
    }
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}`);
    }
    return data;
  }

  async function refreshRegistration() {
    await Promise.all([loadStatus(), loadTasks()]);
  }

  async function loadStatus() {
    try {
      const response = await fetch('/api/registration/status');
      status = await readJsonResponse(response);
    } catch (err) {
      console.warn('registration status load failed', err);
    }
  }

  async function loadMihomoContext(silent = false) {
    mihomoNodesLoading = true;
    try {
      const configResponse = await fetch('/api/proxies/mihomo', { cache: 'no-store' });
      const config = await readJsonResponse(configResponse);
      mihomoConfig = config;
      if (config.mode === 'mihomo' && config.enabled) {
        const nodesResponse = await fetch('/api/proxies/mihomo/nodes', { cache: 'no-store' });
        const nodes = await readJsonResponse(nodesResponse);
        if (!nodes.ok) throw new Error(nodes.error || 'Mihomo 节点读取失败');
        mihomoNodes = nodes;
        const selectableNodes = Array.isArray(nodes.nodes) ? nodes.nodes.filter(isSelectableMihomoNode) : [];
        if (taskMihomoNode.trim() && !selectableNodes.includes(taskMihomoNode.trim())) {
          taskMihomoNode = '';
        }
        mihomoLoadError = '';
      } else {
        mihomoNodes = null;
        mihomoLoadError = '';
        taskMihomoNode = '';
      }
    } catch (err) {
      mihomoLoadError = errorMessage(err);
      if (!silent) toast.error(mihomoLoadError);
      console.warn('registration mihomo context load failed', err);
    } finally {
      mihomoNodesLoading = false;
    }
  }

  async function loadUploadConfig(silent = false) {
    uploadConfigLoading = true;
    try {
      const response = await fetch('/api/upload/aether', { cache: 'no-store' });
      const data = await readJsonResponse(response);
      const services = Array.isArray(data.services) ? data.services : [];
      uploadConfig = { services };
      uploadConfigError = '';
      const selection = parseAutoUploadServiceChoice(autoUploadServiceChoice);
      if (selection.mode === 'fixed' && !services.some((service: UploadService) => service.enabled && service.id === selection.id)) {
        autoUploadServiceChoice = 'random';
      }
    } catch (err) {
      uploadConfigError = errorMessage(err);
      if (!silent) toast.error(`上传服务读取失败：${uploadConfigError}`);
      console.warn('registration upload config load failed', err);
    } finally {
      uploadConfigLoading = false;
    }
  }

  async function loadTasks(options: { preferredTaskId?: string } = {}) {
    const seq = ++taskLoadSeq;
    tasksLoading = true;
    try {
      const response = await fetch('/api/registration/tasks', { cache: 'no-store' });
      const data = await readJsonResponse(response);
      if (seq !== taskLoadSeq) return false;
      tasks = Array.isArray(data.items) ? data.items : [];
      taskListError = '';
      initialLoaded = true;

      if (options.preferredTaskId && tasks.some((task) => task.id === options.preferredTaskId)) {
        await selectTask(options.preferredTaskId, true);
      } else if (!selectedTask && tasks.length > 0) {
        await selectTask(tasks[0].id, true);
      } else if (selectedTask) {
        const fresh = tasks.find((task) => task.id === selectedTask?.id);
        if (fresh) selectedTask = fresh;
        else {
          selectedTask = null;
          logs = [];
          logsOpen = false;
          if (tasks.length > 0) await selectTask(tasks[0].id, true);
        }
      }
      return true;
    } catch (err) {
      if (seq === taskLoadSeq) {
        taskListError = errorMessage(err);
        initialLoaded = true;
        console.warn('registration tasks load failed', err);
      }
      return false;
    } finally {
      if (seq === taskLoadSeq) tasksLoading = false;
    }
  }

  async function selectTask(taskId: string, silent = false) {
    const seq = ++selectedTaskLoadSeq;
    const switchingTask = selectedTask?.id !== taskId;
    const listedTask = tasks.find((task) => task.id === taskId);
    if (switchingTask) {
      if (listedTask) selectedTask = listedTask;
      setLogsLightweight([]);
    }
    try {
      const response = await fetch(`/api/registration/task?id=${encodeURIComponent(taskId)}&log_limit=${LOG_KEEP_LIMIT}`, { cache: 'no-store' });
      const data = await readJsonResponse(response);
      if (seq !== selectedTaskLoadSeq) return false;
      if (data.ok && data.task) {
        selectedTask = data.task;
        setLogsLightweight(data.logs ?? []);
        subscribeTask(taskId);
        await followLogTail(true, true);
        return true;
      }
      if (!silent) toast.error(data.error || '任务不存在');
      if (selectedTask?.id === taskId) {
        selectedTask = null;
        setLogsLightweight([]);
        logsOpen = false;
      }
    } catch (err) {
      if (seq !== selectedTaskLoadSeq) return false;
      if (!silent) toast.error(errorMessage(err));
      console.warn('registration task detail load failed', err);
    }
    return false;
  }

  async function startTask(count: number, forceFinite = false) {
    starting = true;
    try {
      const safeCount = Math.max(1, Math.min(10000, Number(count) || 1));
      const safeConcurrency = Math.max(1, Math.min(5000, Number(concurrency) || 1));
      const safeMaxInflight = schedulerMode === 'fastlane'
        ? Math.max(1, Math.min(1000, Number(maxInflight) || 20))
        : safeConcurrency;
      const safeOauthDelay = workflow === 'register_then_oauth'
        ? Math.max(0, Math.min(3600, Number(oauthDelaySeconds) || 0))
        : 0;
      const safeCurrentSessionRetryAfter = Math.max(1, Math.min(300, Number(currentSessionOauthRetryAfterSeconds) || 30));
      const selectedUploadChoice = parseAutoUploadServiceChoice(autoUploadServiceChoice);
      const availableUploadServices = enabledUploadServices;
      const selectedMihomoNode = taskMihomoNode.trim();
      if (mihomoConfig.mode === 'pool' && status.active_proxies <= 0) {
        throw new Error('代理池当前没有可用节点，请先在代理池页面测试通过至少一个代理，或切换为直连模式');
      }
      if (mihomoConfig.mode === 'mihomo' && !mihomoConfig.enabled) {
        throw new Error('Mihomo 代理模式未启用，请先在代理池页面启用，或切换为代理池/直连模式');
      }
      if (selectedMihomoNode && !mihomoSelectableNodes.includes(selectedMihomoNode)) {
        throw new Error('请选择节点列表中的 Clash 节点，或留空自动随机');
      }
      if (isWithOauth && autoUploadOauthSuccess) {
        if (availableUploadServices.length === 0) {
          throw new Error('请先配置至少一个启用的 Aether 上传服务');
        }
        if (selectedUploadChoice.mode === 'fixed' && !availableUploadServices.some((service) => service.id === selectedUploadChoice.id)) {
          throw new Error('请选择列表中的启用上传服务');
        }
      }
      const useInfinite = !forceFinite && infiniteMode;
      const response = await fetch('/api/registration/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workflow,
          scheduler_mode: schedulerMode,
          register_provider: registerProvider,
          request_core: requestCore,
          libcurl_impersonate_target: requestCore === 'libcurl_impersonate'
            ? libcurlImpersonateTarget
            : undefined,
          mihomo_node: selectedMihomoNode || undefined,
          target_metric: effectiveTargetMetric,
          target_count: useInfinite ? 0 : safeCount,
          concurrency: safeConcurrency,
          max_inflight: safeMaxInflight,
          oauth_delay_seconds: safeOauthDelay,
          current_session_oauth_retry_after_seconds: currentSessionOauthFallbackActive && currentSessionOauthFallbackMode === 'single_timeout_retry'
            ? safeCurrentSessionRetryAfter
            : 0,
          infinite: useInfinite,
          fast_email_otp_resend: fastEmailOtpResend,
          auto_upload_oauth_success: isWithOauth && autoUploadOauthSuccess,
          discard_oauth_failed_accounts: isWithOauth && discardOauthFailedAccounts,
          auto_upload_service_mode: isWithOauth && autoUploadOauthSuccess ? selectedUploadChoice.mode : undefined,
          auto_upload_service_id: isWithOauth && autoUploadOauthSuccess && selectedUploadChoice.mode === 'fixed'
            ? selectedUploadChoice.id
            : undefined,
          current_session_oauth_fallback: currentSessionOauthFallbackActive,
          current_session_oauth_fallback_mode: currentSessionOauthFallbackActive
            ? currentSessionOauthFallbackMode
            : 'none',
          detailed_logs: detailedLogs
        })
      });
      const data = await readJsonResponse(response);
      if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
      toast.success(`任务已创建：${data.task_id}`);
      await loadStatus();
      await loadTasks({ preferredTaskId: data.task_id });
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      starting = false;
    }
  }

  async function stopSelectedTask() {
    if (!selectedTask) return;
    const taskId = selectedTask.id;
    starting = true;
    try {
      const response = await fetch('/api/registration/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_id: taskId })
      });
      const data = await readJsonResponse(response);
      if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
      toast.success(`已请求停止：${taskId}`);
      await loadTasks({ preferredTaskId: taskId });
      await selectTask(taskId, true);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      starting = false;
    }
  }

  function ensureWebSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsState = 'connecting';
    ws.onopen = () => { wsState = 'open'; if (selectedTask) subscribeTask(selectedTask.id); };
    ws.onclose = () => { wsState = 'closed'; };
    ws.onerror = () => { wsState = 'error'; };
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'registration_task' && message.payload?.task) {
          if (!selectedTask || message.payload.task.id === selectedTask.id) selectedTask = message.payload.task;
        } else if (message.type === 'registration_task' && message.payload?.ok === 0 && selectedTask) {
          selectedTask = null;
          logs = [];
          logsOpen = false;
        }
        if (message.type === 'registration_logs' && message.task_id === selectedTask?.id) {
          const nextLogs: RegistrationLog[] = message.logs ?? [];
          if (nextLogs.length > 0) {
            const detailShouldStick = isNearLogBottom(detailLogList);
            const modalShouldStick = isNearLogBottom(modalLogList);
            const seen = new Set(logs.map((item) => item.seq));
            setLogsLightweight([...logs, ...nextLogs.filter((item) => !seen.has(item.seq))]);
            void followLogTail(detailShouldStick, modalShouldStick);
          }
        }
      } catch (err) { console.warn('registration ws parse failed', err); }
    };
  }

  function subscribeTask(taskId: string) {
    ensureWebSocket();
    if (ws?.readyState === WebSocket.OPEN) {
      const lastSeq = logs.length > 0 ? logs[logs.length - 1].seq : 0;
      ws.send(JSON.stringify({ type: 'registration_subscribe', task_id: taskId, last_seq: lastSeq }));
    }
  }

  function wsLabel() {
    if (wsState === 'open') return '实时';
    if (wsState === 'connecting') return '连接中';
    if (wsState === 'error') return '异常';
    return '离线';
  }

  function wsToneClass() {
    if (wsState === 'open') return 'r-ws-ok';
    if (wsState === 'error') return 'r-ws-err';
    if (wsState === 'connecting') return 'r-ws-warn';
    return 'r-ws-off';
  }

  onMount(() => {
    void refreshRegistration(); ensureWebSocket();
    void loadMihomoContext(true);
    void loadUploadConfig(true);
    const dataTimer = window.setInterval(() => { void refreshRegistration(); }, 2500);
    const clockTimer = window.setInterval(() => { now = Date.now(); }, 1000);
    return () => {
      window.clearInterval(dataTimer);
      window.clearInterval(clockTimer);
      ws?.close();
    };
  });
</script>

<PageHeader
  title="注册工作台"
  subtitle="注册"
  description="按目标数量批量注册账号；可选高速调度，注册后立即执行 OAuth。"
>
  <span class={`r-ws-pill ${wsToneClass()}`} title="WebSocket 状态">
    <span class="r-ws-dot"></span>
    {wsLabel()}
  </span>
  <button class="btn btn-sm" type="button" onclick={() => { void refreshRegistration(); void loadMihomoContext(false); void loadUploadConfig(false); }}>
    <Icon name="refresh" size={14} />
    刷新
  </button>
</PageHeader>

<!-- KPI overview -->
<section class="r-kpi-grid" aria-label="资源概览">
  {#each kpiCards as card}
    <div class="r-kpi-card" data-tone={card.tone}>
      <div class="r-kpi-head">
        <span class="r-kpi-icon"><Icon name={card.icon} size={14} /></span>
        <span class="r-kpi-label">{card.label}</span>
      </div>
      <span class="r-kpi-value">{card.value}</span>
      <span class="r-kpi-sub">{card.sub}</span>
    </div>
  {/each}
</section>

<!-- Launcher -->
<section class="r-launcher" aria-label="启动新任务">
  <header class="r-launcher-head">
    <div class="r-launcher-title">
      <span class="r-launcher-mark"><Icon name="zap" size={14} /></span>
      <div>
        <span class="r-launcher-kicker">配置任务</span>
        <h2>启动新一轮注册</h2>
      </div>
    </div>
    <div class="r-launcher-summary">
      {#each configSummary as item, i}
        {#if i > 0}<span class="r-summary-sep">·</span>{/if}
        <span class="r-summary-chip">{item}</span>
      {/each}
      {#if infiniteMode}
        <span class="r-summary-chip r-summary-chip-accent">无限</span>
      {/if}
    </div>
  </header>

  <!-- 流程类型 -->
  <div class="r-section">
    <div class="r-section-head">
      <span class="r-section-title">流程类型</span>
      <span class="r-section-hint">选择账号来源与编排方式</span>
    </div>
    <div class="r-choice-grid">
      <div>
        <span class="r-choice-label">账号来源</span>
        <div class="r-choice-row">
          {#each registerProviderOptions as opt}
            <button
              type="button"
              class="r-choice"
              class:r-choice-active={registerProvider === opt.value}
              onclick={() => registerProvider = opt.value}
              disabled={starting}
            >
              <Icon name={opt.icon} size={14} />
              <div class="r-choice-text">
                <span class="r-choice-name">{opt.label}</span>
                <span class="r-choice-hint">{opt.hint}</span>
              </div>
            </button>
          {/each}
        </div>
      </div>
      <div>
        <span class="r-choice-label">编排方式</span>
        <div class="r-choice-row r-choice-row-3">
          {#each workflowOptions as opt}
            <button
              type="button"
              class="r-choice"
              class:r-choice-active={workflow === opt.value}
              onclick={() => { workflow = opt.value; handleWorkflowChange(); }}
              disabled={starting}
            >
              <Icon name={opt.icon} size={14} />
              <div class="r-choice-text">
                <span class="r-choice-name">{opt.label}</span>
                <span class="r-choice-hint">{opt.hint}</span>
              </div>
            </button>
          {/each}
        </div>
      </div>
    </div>
  </div>

  <!-- 执行设置 (collapsible) -->
  <div class="r-section r-section-collapsible" class:is-open={showExecution}>
    <button class="r-section-toggle" type="button" onclick={() => showExecution = !showExecution}>
      <div class="r-section-head">
        <span class="r-section-title">执行设置</span>
        <span class="r-section-hint">请求核心、调度模式与数量参数</span>
      </div>
      <span class="r-section-chev">
        <Icon name="chevron-down" size={14} />
      </span>
    </button>

    {#if showExecution}
      <div class="r-section-body">
        <div class="r-field-grid">
          <div class="r-field">
            <span class="r-field-label">请求核心</span>
            <div class="segmented segmented-block">
              {#each requestCoreOptions as opt}
                <button type="button" class:active={requestCore === opt.value} onclick={() => requestCore = opt.value} disabled={starting}>
                  {opt.label}
                </button>
              {/each}
            </div>
            <span class="r-field-hint">{requestCoreOptions.find((o) => o.value === requestCore)?.hint}</span>
          </div>

          {#if requestCore === 'libcurl_impersonate'}
            <label class="r-field">
              <span class="r-field-label">指纹版本</span>
              <select class="input" bind:value={libcurlImpersonateTarget} disabled={starting}>
                {#each libcurlTargetGroups as group}
                  <optgroup label={group.label}>
                    {#each group.options as opt}
                      <option value={opt.value}>{opt.label}</option>
                    {/each}
                  </optgroup>
                {/each}
              </select>
              <span class="r-field-hint">默认 Chrome 145</span>
            </label>
          {/if}

          <div class="r-field">
            <span class="r-field-label">调度模式</span>
            <div class="segmented segmented-block">
              {#each schedulerOptions as opt}
                <button type="button" class:active={schedulerMode === opt.value} onclick={() => schedulerMode = opt.value} disabled={starting}>
                  {opt.label}
                </button>
              {/each}
            </div>
            <span class="r-field-hint">{schedulerOptions.find((o) => o.value === schedulerMode)?.hint}</span>
          </div>
        </div>

        <div class="r-field-grid">
          <div class="r-field r-field-wide">
            <span class="r-field-label">
              代理方式
              {#if mihomoConfig.mode === 'mihomo'}
                {#if mihomoConfig.enabled}
                  <span class="r-field-tag">已启用</span>
                {:else}
                  <span class="r-field-tag r-field-tag-warning">未启用</span>
                {/if}
              {/if}
            </span>
            <div class="segmented segmented-block">
              <button type="button" class:active={mihomoConfig.mode === 'pool'} disabled>代理池</button>
              <button type="button" class:active={mihomoConfig.mode === 'mihomo'} disabled>Mihomo</button>
              <button type="button" class:active={mihomoConfig.mode === 'direct'} disabled>直连</button>
            </div>
            <span class="r-field-hint">当前代理配置，前往代理池页面修改</span>
          </div>
        </div>

        {#if mihomoTaskPickerVisible}
          <div class="r-field-grid">
            <label class="r-field r-field-wide">
              <span class="r-field-label">
                Clash 节点
                {#if mihomoNodesLoading}
                  <span class="r-field-tag r-field-tag-warning">读取中</span>
                {:else if mihomoLoadError}
                  <span class="r-field-tag r-field-tag-danger">读取失败</span>
                {:else if mihomoSelectableNodes.length}
                  <span class="r-field-tag">{mihomoSelectableNodes.length} 个可用</span>
                {/if}
              </span>
              <div class="r-mihomo-row">
                <select class="input" bind:value={taskMihomoNode} disabled={starting || mihomoNodesLoading}>
                  <option value="">自动随机订阅节点</option>
                  {#each mihomoSelectableNodes as node}
                    <option value={node}>{node}</option>
                  {/each}
                </select>
                <button class="btn btn-sm" type="button" onclick={() => void loadMihomoContext(false)} disabled={starting || mihomoNodesLoading}>
                  <Icon name="refresh" size={12} />
                  刷新
                </button>
              </div>
              <span class="r-field-hint">
                {taskMihomoNode.trim()
                  ? `本任务固定使用 ${shortNodeLabel(taskMihomoNode.trim())}`
                  : '不填写时发布任务会随机绑定一个订阅节点'}
              </span>
            </label>
          </div>
        {/if}

        <div class="r-field-grid">
          <label class="r-field">
            <span class="r-field-label">
              目标数量
              {#if infiniteMode}<span class="r-field-tag r-field-tag-accent">无限</span>{/if}
            </span>
            <input class="input" type="number" min="1" max="10000" bind:value={targetCount} disabled={starting || infiniteMode} />
            <span class="r-field-hint">{infiniteMode ? '已启用无限模式，忽略目标数' : '单次任务的目标数'}</span>
          </label>

          {#if isWithOauth}
            <label class="r-field">
              <span class="r-field-label">目标口径</span>
              <select class="input" bind:value={targetMetric} disabled={starting}>
                {#each targetOptions as opt}<option value={opt.value}>{opt.label}</option>{/each}
              </select>
              <span class="r-field-hint">达成该口径数量后任务结束</span>
            </label>
          {/if}

          <label class="r-field">
            <span class="r-field-label">{isFastlane ? '前置并发' : '并发上限'}</span>
            <input class="input" type="number" min="1" max="5000" bind:value={concurrency} disabled={starting} />
            <span class="r-field-hint">{isFastlane ? '注册前阶段同时进行的流程数' : '同时进行的注册流程数'}</span>
          </label>

          {#if isFastlane}
            <label class="r-field">
              <span class="r-field-label">最大存活</span>
              <input class="input" type="number" min="1" max="1000" bind:value={maxInflight} disabled={starting} />
              <span class="r-field-hint">前后置加起来的总上限</span>
            </label>
          {/if}

          {#if usesIndependentOauth}
            <label class="r-field">
              <span class="r-field-label">OAuth 延迟</span>
              <div class="input-suffix">
                <input class="input" type="number" min="0" max="3600" step="1" bind:value={oauthDelaySeconds} disabled={starting} />
                <span class="input-suffix-text">秒</span>
              </div>
              <span class="r-field-hint">注册成功后等待秒数再开始 OAuth</span>
            </label>
          {/if}
        </div>
      </div>
    {/if}
  </div>

  <!-- 高级选项 (collapsible) -->
  <div class="r-section r-section-collapsible" class:is-open={showAdvanced}>
    <button class="r-section-toggle" type="button" onclick={() => showAdvanced = !showAdvanced}>
      <div class="r-section-head">
        <span class="r-section-title">高级选项</span>
        <span class="r-section-hint">日志、兜底策略与自动上传</span>
      </div>
      <span class="r-section-chev">
        <Icon name="chevron-down" size={14} />
      </span>
    </button>

    {#if showAdvanced}
      <div class="r-section-body">
        <div class="r-toggle-grid">
          <label class="r-toggle">
            <input type="checkbox" bind:checked={infiniteMode} disabled={starting} />
            <div class="r-toggle-text">
              <span class="r-toggle-name">无限模式</span>
              <span class="r-toggle-hint">持续运行直到手动停止</span>
            </div>
          </label>
          <label class="r-toggle">
            <input type="checkbox" bind:checked={detailedLogs} disabled={starting} />
            <div class="r-toggle-text">
              <span class="r-toggle-name">详细日志</span>
              <span class="r-toggle-hint">记录每一步流程的细节</span>
            </div>
          </label>
          <label class="r-toggle" title="10 秒未收到即重发，最多连续 3 次">
            <input type="checkbox" bind:checked={fastEmailOtpResend} disabled={starting} />
            <div class="r-toggle-text">
              <span class="r-toggle-name">快速重发验证码</span>
              <span class="r-toggle-hint">10s 未收到自动重发，最多 3 次</span>
            </div>
          </label>
          {#if isWithOauth}
            <label class="r-toggle">
              <input type="checkbox" bind:checked={autoUploadOauthSuccess} disabled={starting} />
              <div class="r-toggle-text">
                <span class="r-toggle-name">OAuth 成功后自动上传</span>
                <span class="r-toggle-hint">注册并授权完成立即上传</span>
              </div>
            </label>
            <label class="r-toggle">
              <input type="checkbox" bind:checked={discardOauthFailedAccounts} disabled={starting} />
              <div class="r-toggle-text">
                <span class="r-toggle-name">不保存 OA 失败账号</span>
                <span class="r-toggle-hint">OAuth 最终失败时移除新注册账号</span>
              </div>
            </label>
          {/if}
        </div>

        {#if isWithOauth && autoUploadOauthSuccess}
          <div class="r-field-grid">
            <label class="r-field r-field-wide">
              <span class="r-field-label">
                上传服务
                {#if uploadConfigLoading}
                  <span class="r-field-tag r-field-tag-warning">读取中</span>
                {:else if uploadConfigError}
                  <span class="r-field-tag r-field-tag-danger">读取失败</span>
                {:else}
                  <span class="r-field-tag">{enabledUploadServices.length} 个启用</span>
                {/if}
              </span>
              <div class="r-mihomo-row">
                <select
                  class="input"
                  value={autoUploadServiceChoice}
                  onchange={(event) => autoUploadServiceChoice = (event.currentTarget as HTMLSelectElement).value as AutoUploadServiceChoice}
                  disabled={starting || uploadConfigLoading}
                >
                  <option value="random">随机一个启用服务</option>
                  <option value="all">全部启用服务</option>
                  {#each enabledUploadServices as service (service.id)}
                    <option value={`fixed:${service.id}`}>
                      {uploadServiceName(service)}
                      {service.provider_name || service.provider_id ? ` · ${service.provider_name || service.provider_id}` : ''}
                    </option>
                  {/each}
                </select>
                <button class="btn btn-sm" type="button" onclick={() => void loadUploadConfig(false)} disabled={starting || uploadConfigLoading}>
                  <Icon name="refresh" size={12} />
                  刷新
                </button>
              </div>
              <span class="r-field-hint">
                {#if uploadConfigError}
                  {uploadConfigError}
                {:else if enabledUploadServices.length === 0}
                  请先在上传配置中启用至少一个 Aether 服务
                {:else if autoUploadServiceChoice === 'random'}
                  任务创建时随机绑定一个启用服务
                {:else if autoUploadServiceChoice === 'all'}
                  沿用旧行为，上传到所有启用服务
                {:else}
                  本任务固定上传到 {autoUploadServiceSummary}
                {/if}
              </span>
            </label>
          </div>
        {/if}

        {#if usesCurrentSessionCodex}
          <div class="r-fallback-card" class:is-disabled={!currentSessionOauthFallbackEnabled}>
            <div class="r-fallback-head">
              <div class="r-fallback-title">
                <Icon name="shield" size={13} />
                <span>当前会话失败兜底</span>
              </div>
              <label class="r-fallback-toggle">
                <input type="checkbox" bind:checked={currentSessionOauthFallbackEnabled} disabled={starting} />
                <span>{currentSessionOauthFallbackEnabled ? '开启' : '关闭'}</span>
              </label>
            </div>
            <div class="segmented segmented-block" class:segmented-disabled={!currentSessionOauthFallbackEnabled}>
              {#each currentSessionOauthFallbackOptions as opt}
                <button
                  type="button"
                  class:active={currentSessionOauthFallbackMode === opt.value}
                  onclick={() => currentSessionOauthFallbackMode = opt.value}
                  disabled={starting || !currentSessionOauthFallbackEnabled}
                >{opt.label}</button>
              {/each}
            </div>
            <p class="r-fallback-hint">
              {currentSessionOauthFallbackEnabled
                ? currentSessionOauthFallbackOptions.find((o) => o.value === currentSessionOauthFallbackMode)?.hint
                : '关闭后当前会话失败会直接结束，便于测试 Codex 极速'}
            </p>
            {#if currentSessionOauthFallbackActive && currentSessionOauthFallbackMode === 'single_timeout_retry'}
              <label class="r-field r-fallback-retry">
                <span class="r-field-label">二次 OA 触发</span>
                <div class="input-suffix">
                  <input class="input" type="number" min="1" max="300" step="1" bind:value={currentSessionOauthRetryAfterSeconds} disabled={starting} />
                  <span class="input-suffix-text">秒</span>
                </div>
                <span class="r-field-hint">第二次 OA 邮箱超时固定 30 秒</span>
              </label>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>

  <!-- Launcher actions -->
  <footer class="r-launcher-actions">
    <button class="btn" type="button" onclick={() => startTask(1, true)} disabled={starting}>
      <Icon name="play" size={12} />
      单次执行
    </button>
    <button class="btn btn-primary btn-lg r-launcher-cta" type="button" onclick={() => startTask(targetCount)} disabled={starting} data-loading={starting}>
      <Icon name={infiniteMode ? 'activity' : 'zap'} size={14} />
      {infiniteMode ? '启动无限任务' : `启动 ${targetCount} 个目标`}
    </button>
    <span class="flex-spacer"></span>
    <button class="btn btn-danger" type="button" onclick={stopSelectedTask} disabled={starting || !selectedTaskCanStop}>
      <Icon name="stop" size={12} />
      停止选中任务
    </button>
  </footer>
</section>

<!-- Tasks: list + detail -->
<section class="r-tasks" aria-label="任务监控">
  <div class="r-tasks-list-col">
    <div class="r-tasks-list-head">
      <div class="r-tasks-list-title">
        <h3>任务列表</h3>
        <span class="r-tasks-count">{tasks.length}</span>
      </div>
      <button class="btn btn-xs" type="button" onclick={() => void loadTasks()} disabled={tasksLoading} data-loading={tasksLoading}>
        <Icon name="refresh" size={11} />
        刷新
      </button>
    </div>

    {#if taskListError}
      <div class="notice-bar notice-error r-error-bar">
        <span class="notice-icon"><Icon name="alert-circle" size={14} /></span>
        <span class="notice-text">{taskListError}</span>
      </div>
    {/if}

    {#if !initialLoaded}
      <div class="r-tasks-loading">
        {#each Array(3) as _, i (i)}
          <Skeleton height="92px" rounded="md" />
        {/each}
      </div>
    {:else if tasks.length === 0}
      <EmptyState
        title="暂无任务"
        message="使用上方启动新任务，将在此显示运行状态"
        icon="zap"
      />
    {:else}
      <ul class="r-task-list" role="listbox" aria-label="任务列表">
        {#each tasks as task (task.id)}
          {@const pct = progressPct(task)}
          {@const tone = progressTone(task)}
          {@const fastlane = taskUsesFastlane(task)}
          {@const isActive = selectedTask?.id === task.id}
          <li>
            <button
              type="button"
              class="r-task-card"
              class:is-active={isActive}
              onclick={() => selectTask(task.id)}
            >
              <div class="r-task-card-row">
                <span class="r-task-id">{task.id}</span>
                <StatusBadge label={statusLabel(task.status)} variant={statusVariant(task.status)} />
              </div>
              <div class="r-task-tags">
                <span class="r-task-tag">{taskProviderLabel(task)}</span>
                <span class="r-task-tag">{workflowLabel(task.workflow ?? task.mode)}</span>
                {#if fastlane}<span class="r-task-tag r-task-tag-accent"><Icon name="zap" size={10} />高速</span>{/if}
                {#if task.mihomo_node}<span class="r-task-tag r-task-tag-info" title={task.mihomo_node}>节点 {shortNodeLabel(task.mihomo_node)}</span>{/if}
                {#if task.auto_upload_oauth_success}<span class="r-task-tag r-task-tag-info">上传 {taskUploadServiceLabel(task)}</span>{/if}
                <span class="r-task-time">{formatRelativeTime(task.created_ms)}</span>
              </div>

              {#if pct !== null || task.infinite}
                <div class="r-task-progress">
                  <span class="r-task-progress-text">
                    <strong>{task.success}</strong>
                    <span class="r-task-progress-sep">/</span>
                    <span class="r-task-progress-target">{taskTargetLabel(task)}</span>
                  </span>
                  <div class="r-task-progress-bar">
                    <span
                      class="r-task-progress-fill"
                      data-tone={tone}
                      class:is-infinite={task.infinite}
                      style={`width: ${task.infinite ? 100 : pct}%;`}
                    ></span>
                  </div>
                  {#if pct !== null}
                    <span class="r-task-progress-pct">{Math.round(pct)}%</span>
                  {/if}
                </div>
              {/if}

              <div class="r-task-pips">
                <span class="r-task-pip">
                  <span class="dot dot-success"></span>
                  注册 <strong>{task.register_success ?? 0}</strong>
                </span>
                {#if (task.workflow ?? task.mode) !== 'register_only' && (task.oauth_success ?? 0) > 0}
                  <span class="r-task-pip">
                    <span class="dot dot-info"></span>
                    OAuth <strong>{task.oauth_success}</strong>
                  </span>
                {/if}
                {#if task.failed > 0}
                  <span class="r-task-pip r-task-pip-danger">
                    <span class="dot dot-danger"></span>
                    失败 <strong>{task.failed}</strong>
                  </span>
                {/if}
                {#if task.active > 0}
                  <span class="r-task-pip">
                    <span class="r-task-pip-spinner spinner"></span>
                    运行 <strong>{task.active}</strong>
                  </span>
                {/if}
              </div>
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </div>

  <div class="r-tasks-detail-col">
    {#if !selectedTask}
      <div class="r-detail-empty">
        <EmptyState
          title="未选中任务"
          message="从左侧选择一项任务，查看实时进度与日志"
          icon="info"
        />
      </div>
    {:else}
      {@const fastlane = taskUsesFastlane(selectedTask)}
      {@const isRunning = ['queued', 'running', 'stopping'].includes(selectedTask.status)}
      {@const pct = progressPct(selectedTask)}
      {@const tone = progressTone(selectedTask)}

      <div class="r-detail-head">
        <div class="r-detail-title-row">
          <div class="r-detail-title">
            <StatusBadge label={statusLabel(selectedTask.status)} variant={statusVariant(selectedTask.status)} />
            <h3 class="r-detail-id">{selectedTask.id}</h3>
          </div>
          <div class="r-detail-actions">
            {#if isRunning}
              <button class="btn btn-sm btn-danger" type="button" onclick={stopSelectedTask} disabled={starting}>
                <Icon name="stop" size={11} />
                停止
              </button>
            {/if}
            <button class="btn btn-sm" type="button" onclick={openLogsModal}>
              <Icon name="list" size={11} />
              日志 ({logs.length})
            </button>
          </div>
        </div>

        <div class="r-detail-tags">
          <span class="r-task-tag">{taskProviderLabel(selectedTask)}</span>
          <span class="r-task-tag">{workflowLabel(selectedTask.workflow ?? selectedTask.mode)}</span>
          <span class="r-task-tag">{requestCoreLabel(selectedTask.request_core)}</span>
          {#if selectedTask.request_core === 'libcurl_impersonate'}
            <span class="r-task-tag">{libcurlTargetLabel(taskLibcurlTarget(selectedTask))}</span>
          {/if}
          {#if selectedTask.mihomo_node}
            <span class="r-task-tag r-task-tag-info" title={selectedTask.mihomo_proxy_url || selectedTask.mihomo_node}>节点 {shortNodeLabel(selectedTask.mihomo_node)}</span>
          {/if}
          {#if fastlane}
            <span class="r-task-tag r-task-tag-accent"><Icon name="zap" size={10} />高速</span>
          {/if}
          {#if selectedTask.fast_email_otp_resend}
            <span class="r-task-tag r-task-tag-info">快发验证码</span>
          {/if}
          {#if selectedTask.auto_upload_oauth_success}
            <span class="r-task-tag r-task-tag-info">自动上传 · {taskUploadServiceLabel(selectedTask)}</span>
          {/if}
          {#if selectedTask.discard_oauth_failed_accounts}
            <span class="r-task-tag r-task-tag-info">不留 OA 失败</span>
          {/if}
          {#if selectedTask.current_session_oauth_fallback}
            <span class="r-task-tag r-task-tag-info">{currentSessionOauthFallbackLabel(selectedTask.current_session_oauth_fallback_mode)}</span>
          {/if}
          <span class="r-task-tag">{metricLabel(selectedTask.target_metric)}</span>
        </div>

        <div class="r-detail-meta">
          <span class="r-detail-meta-item">
            <Icon name="clock" size={11} />
            创建 {formatAbsoluteTime(selectedTask.created_ms)}
          </span>
          {#if selectedTask.started_ms}
            <span class="r-detail-meta-item">
              <Icon name="play" size={11} />
              运行 {formatDuration(selectedTask.started_ms, selectedTask.finished_ms)}
            </span>
            <span class="r-detail-meta-item">
              <Icon name="activity" size={11} />
              注册速度 {formatRatePerMinute(selectedTask.register_success, selectedTask)}
            </span>
            {#if (selectedTask.workflow ?? selectedTask.mode) !== 'register_only'}
              <span class="r-detail-meta-item">
                <Icon name="zap" size={11} />
                OAuth 速度 {formatRatePerMinute(selectedTask.oauth_success, selectedTask)}
              </span>
            {/if}
          {/if}
          {#if selectedTask.finished_ms}
            <span class="r-detail-meta-item">
              <Icon name="check" size={11} />
              结束 {formatRelativeTime(selectedTask.finished_ms)}
            </span>
          {/if}
        </div>
      </div>

      {#if pct !== null || selectedTask.infinite}
        <div class="r-detail-progress">
          <div class="r-detail-progress-head">
            <span class="r-detail-progress-label">进度</span>
            <span class="r-detail-progress-value">
              <strong>{selectedTask.success}</strong>
              <span class="r-detail-progress-sep">/</span>
              <span class="r-detail-progress-target">{taskTargetLabel(selectedTask)}</span>
              {#if pct !== null}<span class="r-detail-progress-pct">{pct.toFixed(1)}%</span>{/if}
            </span>
          </div>
          <div class="r-detail-progress-bar">
            <span
              class="r-detail-progress-fill"
              data-tone={tone}
              class:is-infinite={selectedTask.infinite}
              style={`width: ${selectedTask.infinite ? 100 : pct}%;`}
            ></span>
          </div>
        </div>
      {/if}

      <div class="r-stat-grid">
        <div class="r-stat">
          <span class="r-stat-label">运行中</span>
          <span class="r-stat-value">{selectedTask.active}</span>
        </div>
        <div class="r-stat r-stat-success">
          <span class="r-stat-label">注册成功</span>
          <span class="r-stat-value">{selectedTask.register_success ?? 0}</span>
          <span class="r-stat-sub">{registrationSuccessRate(selectedTask)} 成功率</span>
        </div>
        {#if (selectedTask.workflow ?? selectedTask.mode) !== 'register_only'}
          <div class="r-stat r-stat-success">
            <span class="r-stat-label">OAuth 成功</span>
            <span class="r-stat-value">{selectedTask.oauth_success ?? 0}</span>
            <span class="r-stat-sub">{oauthSuccessRate(selectedTask)} 成功率</span>
          </div>
        {/if}
        {#if selectedTask.auto_upload_oauth_success}
          <div class="r-stat r-stat-success">
            <span class="r-stat-label">上传成功 · {taskUploadServiceLabel(selectedTask)}</span>
            <span class="r-stat-value">{selectedTask.upload_success ?? 0}</span>
            <span class="r-stat-sub">失败 {selectedTask.upload_failed ?? 0} · 跳过 {selectedTask.upload_skipped ?? 0}</span>
          </div>
        {/if}
        <div class="r-stat" class:r-stat-danger={selectedTask.failed > 0}>
          <span class="r-stat-label">失败</span>
          <span class="r-stat-value">{selectedTask.failed}</span>
        </div>
      </div>

      {#if fastlane}
        {@const aliveTotal = selectedTask.fastlane_alive_total ?? selectedTask.active}
        {@const aliveMax = selectedTask.max_inflight ?? selectedTask.concurrency}
        {@const alivePct = aliveMax > 0 ? Math.min(100, (aliveTotal / aliveMax) * 100) : 0}
        <div class="r-fastlane">
          <div class="r-fastlane-title">
            <Icon name="zap" size={11} />
            <span>高速模式</span>
            <span class="r-fastlane-cap">存活 {aliveTotal} / {aliveMax}</span>
          </div>
          <div class="r-fastlane-stages">
            <div class="r-fastlane-stage" class:is-active={(selectedTask.fastlane_pre_email_active ?? 0) > 0}>
              <span class="r-fastlane-stage-num">{selectedTask.fastlane_pre_email_active ?? 0}</span>
              <span class="r-fastlane-stage-name">前置</span>
            </div>
            <span class="r-fastlane-arrow"><Icon name="chevron-right" size={11} /></span>
            <div class="r-fastlane-stage" class:is-active={(selectedTask.fastlane_waiting_email ?? 0) > 0}>
              <span class="r-fastlane-stage-num">{selectedTask.fastlane_waiting_email ?? 0}</span>
              <span class="r-fastlane-stage-name">等邮箱</span>
            </div>
            <span class="r-fastlane-arrow"><Icon name="chevron-right" size={11} /></span>
            <div class="r-fastlane-stage" class:is-active={(selectedTask.fastlane_post_email_active ?? 0) > 0}>
              <span class="r-fastlane-stage-num">{selectedTask.fastlane_post_email_active ?? 0}</span>
              <span class="r-fastlane-stage-name">后置</span>
            </div>
          </div>
          <div class="r-fastlane-bar">
            <span class="r-fastlane-fill" style={`width: ${alivePct}%;`}></span>
          </div>
        </div>
      {/if}

      <div class="r-logs">
        <div class="r-logs-head">
          {#if isRunning}<span class="r-logs-pulse"></span>{/if}
          <span class="r-logs-title">实时日志</span>
          <span class="r-logs-meta">
            最近 {Math.min(logs.length, LOG_VIEW_LIMIT)} / 保留 {logs.length}
            {#if selectedTask?.log_count && selectedTask.log_count > logs.length}
              · 任务内 {selectedTask.log_count}
            {/if}
          </span>
          {#if logs.length > LOG_VIEW_LIMIT}
            <button class="btn-link r-logs-more" type="button" onclick={openLogsModal}>查看全部</button>
          {/if}
        </div>

        {#if logs.length === 0}
          <div class="r-logs-empty">
            <Icon name="info" size={14} />
            <span>暂无日志输出</span>
          </div>
        {:else}
          <div class="r-logs-scroll-wrap">
            <ol class="log-list log-list-scroll r-logs-list" bind:this={detailLogList}>
              {#each logs.slice(-LOG_VIEW_LIMIT) as item (item.seq)}
                <li>
                  <button
                    type="button"
                    class="log-item"
                    class:log-error={item.level === 'error'}
                    class:log-warn={item.level === 'warn'}
                    class:log-debug={item.level === 'debug'}
                    class:is-expanded={expandedLogs.has(item.seq)}
                    aria-expanded={expandedLogs.has(item.seq)}
                    onclick={() => toggleLogExpanded(item.seq)}
                  >
                    <span class="log-flow text-mono">{formatLogTime(item.ts_ms)} · {trimFlowId(item.flow_id)}</span>
                    <span class="log-msg">{item.message}</span>
                    <span class="log-chevron" aria-hidden="true">
                      <Icon name="chevron-down" size={12} />
                    </span>
                  </button>
                </li>
              {/each}
            </ol>
            {#if isRunning}
              <button type="button" class="btn btn-xs r-logs-jump" onclick={jumpDetailLogToBottom} title="跳到最新">
                <Icon name="chevron-down" size={11} />
                最新
              </button>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</section>

<Modal
  open={logsOpen}
  title="任务日志"
  kicker={selectedTask ? selectedTask.id : 'LOGS'}
  subtitle={selectedTask ? `${statusLabel(selectedTask.status)} · 最近 ${Math.min(logs.length, LOG_MODAL_LIMIT)} 条` : `最近 ${Math.min(logs.length, LOG_MODAL_LIMIT)} 条`}
  size="lg"
  onclose={() => logsOpen = false}
>
  {#if logs.length === 0}
    <EmptyState message="暂无日志输出" icon="info" />
  {:else}
    <ol class="log-list r-modal-log-list" bind:this={modalLogList}>
      {#each logs.slice(-LOG_MODAL_LIMIT) as item (item.seq)}
        <li>
          <button
            type="button"
            class="log-item"
            class:log-error={item.level === 'error'}
            class:log-warn={item.level === 'warn'}
            class:log-debug={item.level === 'debug'}
            class:is-expanded={expandedLogs.has(item.seq)}
            aria-expanded={expandedLogs.has(item.seq)}
            onclick={() => toggleLogExpanded(item.seq)}
          >
            <span class="log-flow text-mono">{formatLogTime(item.ts_ms)} · {trimFlowId(item.flow_id)}</span>
            <span class="log-msg">{item.message}</span>
            <span class="log-chevron" aria-hidden="true">
              <Icon name="chevron-down" size={12} />
            </span>
          </button>
        </li>
      {/each}
    </ol>
  {/if}

  {#snippet footer()}
    <button class="btn btn-sm" type="button" onclick={() => scrollLogToBottom(modalLogList)}>
      <Icon name="chevron-down" size={11} />
      跳到最新
    </button>
    <span class="flex-spacer"></span>
    <button class="btn btn-sm" type="button" onclick={() => logsOpen = false}>关闭</button>
  {/snippet}
</Modal>

<style>
/* =========================================================
   Registration Page — Refined Layout
   ========================================================= */

/* ---------- WS status pill ---------- */
.r-ws-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 0 10px;
  height: 24px;
  border-radius: var(--radius-full);
  background: var(--nx-paper-deep);
  border: 1px solid var(--nx-rule-soft);
  font-size: 11px;
  font-weight: 500;
  color: var(--nx-ink-muted);
  white-space: nowrap;
}

.r-ws-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  opacity: 0.85;
}

.r-ws-ok { color: var(--nx-success); background: var(--nx-success-bg); border-color: var(--nx-success-border); }
.r-ws-warn { color: var(--nx-warning); background: var(--nx-warning-bg); border-color: var(--nx-warning-border); }
.r-ws-err { color: var(--nx-danger); background: var(--nx-danger-bg); border-color: var(--nx-danger-border); }
.r-ws-off { color: var(--nx-ink-muted); }

.r-ws-ok .r-ws-dot { animation: r-pulse 2s ease-in-out infinite; }

@keyframes r-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.45; transform: scale(0.85); }
}

/* ---------- KPI overview ---------- */
.r-kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 22px;
}

.r-kpi-card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 16px 18px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-xl);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  transition: border-color var(--duration-base) var(--ease-out),
              transform var(--duration-base) var(--ease-out),
              box-shadow var(--duration-base) var(--ease-out);
}

.r-kpi-card:hover {
  border-color: color-mix(in srgb, var(--nx-brand) 26%, var(--nx-rule));
  transform: translateY(-1px);
  box-shadow: var(--shadow-sm);
}

.r-kpi-head {
  display: flex;
  align-items: center;
  gap: 8px;
}

.r-kpi-icon {
  display: inline-grid;
  place-items: center;
  width: 26px;
  height: 26px;
  border-radius: var(--radius-sm);
  background: var(--nx-paper-deep);
  color: var(--nx-ink-soft);
}

.r-kpi-label {
  font-size: 11.5px;
  font-weight: 500;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-kpi-value {
  font-family: var(--font-number);
  font-size: 28px;
  font-weight: 700;
  line-height: 1;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums lining-nums;
  font-feature-settings: "tnum" 1, "lnum" 1;
  letter-spacing: -0.03em;
  margin-top: 4px;
}

.r-kpi-sub {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  font-weight: 400;
}

.r-kpi-card[data-tone="success"] {
  border-color: var(--nx-success-border);
  background: linear-gradient(180deg, var(--nx-success-bg) 0%, var(--nx-card) 60%);
}
.r-kpi-card[data-tone="success"] .r-kpi-icon {
  background: color-mix(in srgb, var(--nx-success) 14%, transparent);
  color: var(--nx-success);
}
.r-kpi-card[data-tone="success"] .r-kpi-value { color: var(--nx-success); }

.r-kpi-card[data-tone="warning"] {
  border-color: var(--nx-warning-border);
  background: linear-gradient(180deg, var(--nx-warning-bg) 0%, var(--nx-card) 60%);
}
.r-kpi-card[data-tone="warning"] .r-kpi-icon {
  background: color-mix(in srgb, var(--nx-warning) 14%, transparent);
  color: var(--nx-warning);
}
.r-kpi-card[data-tone="warning"] .r-kpi-value { color: var(--nx-warning); }

/* ---------- Launcher card ---------- */
.r-launcher {
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-2xl);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  margin-bottom: 22px;
  overflow: hidden;
}

.r-launcher-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 20px 24px 16px;
  border-bottom: 1px solid var(--nx-rule-soft);
  background: linear-gradient(180deg, var(--nx-card-sun) 0%, var(--nx-card) 100%);
  flex-wrap: wrap;
}

:global(.dark) .r-launcher-head {
  background: linear-gradient(180deg, color-mix(in srgb, var(--nx-brand) 6%, var(--nx-card)) 0%, var(--nx-card) 100%);
}

.r-launcher-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.r-launcher-mark {
  display: inline-grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-md);
  background: linear-gradient(135deg, var(--nx-brand) 0%, var(--nx-brand-deep) 100%);
  color: #fff;
  box-shadow: 0 2px 6px rgba(201, 100, 66, 0.32);
}

.r-launcher-kicker {
  display: block;
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--nx-brand);
  margin-bottom: 2px;
}

.r-launcher-title h2 {
  margin: 0;
  font-size: 17px;
  font-weight: 650;
  letter-spacing: -0.018em;
  line-height: 1.2;
  color: var(--nx-ink);
}

.r-launcher-summary {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.r-summary-chip {
  display: inline-flex;
  align-items: center;
  padding: 3px 9px;
  border-radius: var(--radius-full);
  background: var(--nx-paper-deep);
  border: 1px solid var(--nx-rule-soft);
  color: var(--nx-ink-soft);
  font-size: 11.5px;
  font-weight: 500;
}

.r-summary-chip-accent {
  background: var(--nx-brand-tint);
  border-color: color-mix(in srgb, var(--nx-brand) 28%, var(--nx-rule));
  color: var(--nx-brand);
  font-weight: 600;
}

.r-summary-sep {
  color: var(--nx-ink-muted);
  font-size: 11px;
  margin: 0 -2px;
}

/* ---------- Sections ---------- */
.r-section {
  border-bottom: 1px solid var(--nx-rule-soft);
}

.r-section:last-of-type {
  border-bottom: 0;
}

.r-section-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
  text-align: left;
}

.r-section-title {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--nx-ink);
  letter-spacing: -0.005em;
}

.r-section-hint {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  font-weight: 400;
}

.r-section-collapsible .r-section-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  width: 100%;
  padding: 16px 24px;
  border: 0;
  background: transparent;
  cursor: pointer;
  color: inherit;
  transition: background var(--duration-fast) var(--ease-out);
}

.r-section-collapsible .r-section-toggle:hover {
  background: color-mix(in srgb, var(--nx-ink) 3%, transparent);
}

.r-section-chev {
  display: inline-grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  background: var(--nx-paper-deep);
  color: var(--nx-ink-muted);
  transition: transform var(--duration-base) var(--ease-out),
              background var(--duration-fast) var(--ease-out),
              color var(--duration-fast) var(--ease-out);
}

.r-section-collapsible.is-open .r-section-chev {
  transform: rotate(180deg);
  background: var(--nx-brand-tint);
  color: var(--nx-brand);
}

.r-section:not(.r-section-collapsible) {
  padding: 18px 24px;
}

.r-section-body {
  padding: 4px 24px 20px;
  display: grid;
  gap: 16px;
  animation: r-section-fade var(--duration-base) var(--ease-out);
}

@keyframes r-section-fade {
  from { opacity: 0; transform: translateY(-4px); }
  to { opacity: 1; transform: translateY(0); }
}

/* ---------- Choice grid (provider / workflow) ---------- */
.r-choice-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr);
  gap: 16px 20px;
  margin-top: 12px;
}

.r-choice-label {
  display: block;
  font-size: 11px;
  font-weight: 600;
  color: var(--nx-ink-soft);
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-choice-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
}

.r-choice-row-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }

.r-choice {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-md);
  background: var(--nx-paper-soft);
  color: var(--nx-ink);
  font-family: inherit;
  cursor: pointer;
  text-align: left;
  transition: all var(--duration-fast) var(--ease-out);
}

:global(.dark) .r-choice {
  background: var(--nx-paper-deep);
}

.r-choice :global(svg) {
  flex-shrink: 0;
  color: var(--nx-ink-muted);
  margin-top: 2px;
}

.r-choice:hover:not(:disabled) {
  border-color: var(--nx-brand-soft);
  background: var(--nx-card-sun);
}

.r-choice:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.r-choice-active {
  border-color: var(--nx-brand);
  background: var(--nx-brand-tint);
  box-shadow: 0 0 0 1px var(--nx-brand) inset, var(--shadow-xs);
}

:global(.dark) .r-choice-active {
  background: color-mix(in srgb, var(--nx-brand) 16%, var(--nx-card));
}

.r-choice-active :global(svg) {
  color: var(--nx-brand);
}

.r-choice-text {
  display: grid;
  gap: 3px;
  min-width: 0;
  flex: 1;
}

.r-choice-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--nx-ink);
  letter-spacing: -0.005em;
}

.r-choice-active .r-choice-name { color: var(--nx-brand); }

.r-choice-hint {
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  line-height: 1.4;
  font-weight: 400;
}

/* ---------- Field grid ---------- */
.r-field-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 14px 18px;
}

.r-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.r-field-wide { grid-column: 1 / -1; }

.r-field-label {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--nx-ink-soft);
  letter-spacing: 0;
}

.r-field-hint {
  font-size: 11px;
  color: var(--nx-ink-muted);
  line-height: 1.5;
  font-weight: 400;
}

.r-field-tag {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: var(--radius-full);
  background: var(--nx-paper-deep);
  border: 1px solid var(--nx-rule-soft);
  color: var(--nx-ink-muted);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0;
}

.r-field-tag-warning { background: var(--nx-warning-bg); border-color: var(--nx-warning-border); color: var(--nx-warning); }
.r-field-tag-danger { background: var(--nx-danger-bg); border-color: var(--nx-danger-border); color: var(--nx-danger); }
.r-field-tag-accent { background: var(--nx-brand-tint); border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule)); color: var(--nx-brand); }

.r-mihomo-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
}

/* ---------- Toggle grid ---------- */
.r-toggle-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 8px;
}

.r-toggle {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 11px 14px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-md);
  background: var(--nx-paper-soft);
  cursor: pointer;
  transition: background var(--duration-fast) var(--ease-out),
              border-color var(--duration-fast) var(--ease-out);
}

:global(.dark) .r-toggle {
  background: var(--nx-paper-deep);
}

.r-toggle:hover:not(:has(input:disabled)) {
  border-color: var(--nx-brand-soft);
  background: var(--nx-card-sun);
}

.r-toggle input[type="checkbox"] {
  flex-shrink: 0;
  margin: 0;
}

.r-toggle:has(input:checked) {
  border-color: color-mix(in srgb, var(--nx-brand) 36%, var(--nx-rule));
  background: var(--nx-brand-tint);
}

:global(.dark) .r-toggle:has(input:checked) {
  background: color-mix(in srgb, var(--nx-brand) 14%, var(--nx-card));
}

.r-toggle-text {
  display: grid;
  gap: 1px;
  min-width: 0;
}

.r-toggle-name {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--nx-ink);
  letter-spacing: -0.005em;
}

.r-toggle-hint {
  font-size: 11px;
  color: var(--nx-ink-muted);
  line-height: 1.45;
  font-weight: 400;
}

/* ---------- Fallback card ---------- */
.r-fallback-card {
  display: grid;
  gap: 10px;
  padding: 16px 18px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-lg);
  background: var(--nx-paper-soft);
  transition: opacity var(--duration-base) var(--ease-out);
}

:global(.dark) .r-fallback-card {
  background: var(--nx-paper-deep);
}

.r-fallback-card.is-disabled {
  opacity: 0.6;
}

.r-fallback-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.r-fallback-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  color: var(--nx-ink);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: -0.005em;
}

.r-fallback-title :global(svg) { color: var(--nx-brand); }

.r-fallback-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--nx-ink-soft);
  cursor: pointer;
  user-select: none;
}

.r-fallback-toggle input[type="checkbox"] { margin: 0; }

.r-fallback-hint {
  margin: 0;
  font-size: 11.5px;
  color: var(--nx-ink-muted);
  line-height: 1.5;
}

.r-fallback-retry {
  margin-top: 4px;
  padding-top: 12px;
  border-top: 1px solid var(--nx-rule-soft);
  max-width: 240px;
}

/* ---------- Launcher actions ---------- */
.r-launcher-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 24px;
  background: color-mix(in srgb, var(--nx-paper-deep) 50%, var(--nx-card));
  border-top: 1px solid var(--nx-rule-soft);
  flex-wrap: wrap;
}

:global(.dark) .r-launcher-actions {
  background: var(--nx-paper-deep);
}

.r-launcher-cta {
  min-width: 200px;
}

/* ---------- Tasks layout ---------- */
.r-tasks {
  display: grid;
  grid-template-columns: minmax(280px, 0.85fr) minmax(0, 1.4fr);
  gap: 18px;
  align-items: start;
}

.r-tasks-list-col,
.r-tasks-detail-col {
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-xl);
  background: var(--nx-card);
  box-shadow: var(--shadow-xs);
  padding: 18px 20px;
  min-width: 0;
}

.r-tasks-detail-col {
  align-self: stretch;
}

.r-tasks-list-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding-bottom: 14px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--nx-rule-soft);
}

.r-tasks-list-title {
  display: flex;
  align-items: baseline;
  gap: 8px;
}

.r-tasks-list-title h3 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: -0.005em;
  color: var(--nx-ink);
}

.r-tasks-count {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  border-radius: var(--radius-full);
  background: var(--nx-paper-deep);
  border: 1px solid var(--nx-rule-soft);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  font-variant-numeric: tabular-nums;
}

.r-tasks-loading {
  display: grid;
  gap: 8px;
}

.r-error-bar { margin: 0 0 12px; }

/* ---------- Task cards ---------- */
.r-task-list {
  display: grid;
  align-content: start;
  gap: 8px;
  max-height: 580px;
  overflow-y: auto;
  padding: 2px;
  margin: 0;
  list-style: none;
}

.r-task-card {
  position: relative;
  display: grid;
  gap: 9px;
  width: 100%;
  padding: 12px 14px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-md);
  background: var(--nx-card);
  text-align: left;
  cursor: pointer;
  font-family: inherit;
  box-shadow: var(--shadow-xs);
  transition: all var(--duration-fast) var(--ease-out);
}

.r-task-card:hover {
  border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule));
  box-shadow: var(--shadow-sm);
}

.r-task-card:focus-visible {
  outline: none;
  border-color: var(--nx-brand);
  box-shadow: var(--focus-ring);
}

.r-task-card.is-active {
  border-color: var(--nx-brand);
  background: color-mix(in srgb, var(--nx-brand) 7%, transparent);
  box-shadow: var(--shadow-sm);
}

.r-task-card.is-active::before {
  content: "";
  position: absolute;
  left: -1px;
  top: 14px;
  bottom: 14px;
  width: 3px;
  border-radius: var(--radius-full);
  background: linear-gradient(180deg, var(--nx-brand) 0%, var(--nx-brand-glow) 100%);
}

.r-task-card-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.r-task-id {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--nx-ink);
  overflow-wrap: anywhere;
  letter-spacing: -0.005em;
  flex: 1;
  min-width: 0;
}

.r-task-tags {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-wrap: wrap;
}

.r-task-tag {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 7px;
  border-radius: var(--radius-sm);
  background: var(--nx-paper-deep);
  border: 1px solid var(--nx-rule-soft);
  color: var(--nx-ink-soft);
  font-size: 10.5px;
  font-weight: 500;
  white-space: nowrap;
}

.r-task-tag-info {
  background: color-mix(in srgb, var(--nx-info) 8%, transparent);
  border-color: color-mix(in srgb, var(--nx-info) 24%, var(--nx-rule));
  color: var(--nx-info);
}

.r-task-tag-accent {
  background: var(--nx-brand-tint);
  border-color: color-mix(in srgb, var(--nx-brand) 30%, var(--nx-rule));
  color: var(--nx-brand);
  font-weight: 600;
}

.r-task-time {
  margin-left: auto;
  color: var(--nx-ink-muted);
  font-size: 10.5px;
  font-weight: 400;
}

/* Task progress bar */
.r-task-progress {
  display: flex;
  align-items: center;
  gap: 8px;
}

.r-task-progress-text {
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  color: var(--nx-ink);
  min-width: 56px;
}

.r-task-progress-text strong {
  font-weight: 700;
  color: var(--nx-ink);
}

.r-task-progress-sep {
  color: var(--nx-ink-muted);
  margin: 0 1px;
}

.r-task-progress-target {
  color: var(--nx-ink-muted);
  font-weight: 400;
}

.r-task-progress-bar {
  flex: 1;
  height: 4px;
  border-radius: var(--radius-full);
  background: var(--nx-rule);
  overflow: hidden;
}

.r-task-progress-fill {
  display: block;
  height: 100%;
  background: var(--nx-success);
  border-radius: inherit;
  transition: width 0.4s var(--ease-out);
}

.r-task-progress-fill[data-tone="danger"] { background: var(--nx-danger); }
.r-task-progress-fill[data-tone="warning"] { background: var(--nx-warning); }

.r-task-progress-fill.is-infinite {
  background: linear-gradient(90deg,
    color-mix(in srgb, var(--nx-success) 30%, transparent) 0%,
    var(--nx-success) 50%,
    color-mix(in srgb, var(--nx-success) 30%, transparent) 100%);
  background-size: 200% 100%;
  animation: r-infinite-shimmer 2s linear infinite;
}

@keyframes r-infinite-shimmer {
  from { background-position: 0% 0; }
  to { background-position: -200% 0; }
}

.r-task-progress-pct {
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  color: var(--nx-ink-muted);
  min-width: 32px;
  text-align: right;
  font-weight: 500;
}

/* Task pips (stat row) */
.r-task-pips {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 11.5px;
  color: var(--nx-ink-muted);
}

.r-task-pip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.r-task-pip strong {
  color: var(--nx-ink);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

.r-task-pip-danger strong { color: var(--nx-danger); }

.r-task-pip-spinner {
  width: 8px;
  height: 8px;
  color: var(--nx-ink-muted);
}

/* ---------- Task detail ---------- */
.r-detail-empty {
  padding: 40px 20px;
}

.r-detail-head {
  display: grid;
  gap: 12px;
  padding-bottom: 16px;
  margin-bottom: 18px;
  border-bottom: 1px solid var(--nx-rule-soft);
}

.r-detail-title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.r-detail-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
  min-width: 0;
}

.r-detail-id {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 14px;
  font-weight: 600;
  color: var(--nx-ink);
  letter-spacing: -0.005em;
  overflow-wrap: anywhere;
}

.r-detail-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.r-detail-tags {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-wrap: wrap;
}

.r-detail-meta {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  font-size: 11.5px;
  color: var(--nx-ink-muted);
}

.r-detail-meta-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

/* Detail progress */
.r-detail-progress {
  margin-bottom: 18px;
}

.r-detail-progress-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 8px;
}

.r-detail-progress-label {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-detail-progress-value {
  font-family: var(--font-number);
  font-variant-numeric: tabular-nums;
}

.r-detail-progress-value strong {
  font-size: 18px;
  font-weight: 700;
  color: var(--nx-ink);
  letter-spacing: -0.018em;
}

.r-detail-progress-sep {
  color: var(--nx-ink-muted);
  margin: 0 4px;
  font-weight: 400;
}

.r-detail-progress-target {
  font-size: 14px;
  color: var(--nx-ink-muted);
  font-weight: 500;
}

.r-detail-progress-pct {
  margin-left: 10px;
  font-size: 13px;
  color: var(--nx-ink-soft);
  font-weight: 500;
}

.r-detail-progress-bar {
  height: 8px;
  border-radius: var(--radius-full);
  background: var(--nx-rule);
  overflow: hidden;
  box-shadow: inset 0 1px 0 rgba(0, 0, 0, 0.04);
}

.r-detail-progress-fill {
  display: block;
  height: 100%;
  background: var(--nx-success);
  border-radius: inherit;
  transition: width 0.4s var(--ease-out);
}

.r-detail-progress-fill[data-tone="danger"] { background: var(--nx-danger); }
.r-detail-progress-fill[data-tone="warning"] { background: var(--nx-warning); }

.r-detail-progress-fill.is-infinite {
  background: linear-gradient(90deg,
    color-mix(in srgb, var(--nx-success) 30%, transparent) 0%,
    var(--nx-success) 50%,
    color-mix(in srgb, var(--nx-success) 30%, transparent) 100%);
  background-size: 200% 100%;
  animation: r-infinite-shimmer 2s linear infinite;
}

/* Stat grid */
.r-stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 8px;
  margin-bottom: 18px;
}

.r-stat {
  display: grid;
  gap: 4px;
  padding: 12px 14px;
  border: 1px solid var(--nx-rule-soft);
  border-radius: var(--radius-md);
  background: var(--nx-paper-soft);
  transition: border-color var(--duration-fast) var(--ease-out),
              transform var(--duration-fast) var(--ease-out);
}

:global(.dark) .r-stat {
  background: var(--nx-paper-deep);
}

.r-stat:hover {
  border-color: color-mix(in srgb, var(--nx-brand) 24%, var(--nx-rule));
  transform: translateY(-1px);
}

.r-stat-label {
  font-size: 10.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-stat-value {
  font-family: var(--font-number);
  font-size: 22px;
  font-weight: 700;
  color: var(--nx-ink);
  font-variant-numeric: tabular-nums lining-nums;
  font-feature-settings: "tnum" 1, "lnum" 1;
  letter-spacing: -0.025em;
  line-height: 1.05;
}

.r-stat-sub {
  font-size: 10.5px;
  color: var(--nx-ink-muted);
  font-weight: 400;
  margin-top: 2px;
}

.r-stat-success {
  border-color: var(--nx-success-border);
  background: var(--nx-success-bg);
}
.r-stat-success .r-stat-value { color: var(--nx-success); }

.r-stat-danger {
  border-color: var(--nx-danger-border);
  background: var(--nx-danger-bg);
}
.r-stat-danger .r-stat-value { color: var(--nx-danger); }

/* ---------- Fastlane ---------- */
.r-fastlane {
  margin-bottom: 18px;
  padding: 14px 16px;
  border: 1px solid var(--nx-success-border);
  border-radius: var(--radius-md);
  background: var(--nx-success-bg);
}

.r-fastlane-title {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 12px;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--nx-success);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-fastlane-cap {
  margin-left: auto;
  font-size: 11px;
  font-weight: 500;
  color: var(--nx-ink-soft);
  text-transform: none;
  letter-spacing: 0;
  font-variant-numeric: tabular-nums;
}

.r-fastlane-stages {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.r-fastlane-stage {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: var(--radius-full);
  background: var(--nx-card);
  border: 1px solid var(--nx-rule-soft);
  transition: border-color var(--duration-fast) var(--ease-out),
              background var(--duration-fast) var(--ease-out);
}

.r-fastlane-stage.is-active {
  border-color: var(--nx-success-border);
  background: var(--nx-card-elev);
}

.r-fastlane-stage-num {
  font-family: var(--font-number);
  font-size: 14px;
  font-weight: 700;
  font-variant-numeric: tabular-nums lining-nums;
  font-feature-settings: "tnum" 1, "lnum" 1;
  color: var(--nx-ink);
  min-width: 12px;
  text-align: center;
  letter-spacing: -0.018em;
}

.r-fastlane-stage.is-active .r-fastlane-stage-num { color: var(--nx-success); }

.r-fastlane-stage-name {
  font-size: 11px;
  font-weight: 500;
  color: var(--nx-ink-muted);
  white-space: nowrap;
}

.r-fastlane-arrow {
  color: var(--nx-ink-muted);
  opacity: 0.5;
  display: inline-flex;
  flex-shrink: 0;
}

.r-fastlane-bar {
  height: 4px;
  border-radius: 2px;
  background: var(--nx-rule);
  overflow: hidden;
}

.r-fastlane-fill {
  display: block;
  height: 100%;
  background: var(--nx-success);
  border-radius: inherit;
  transition: width 0.3s ease;
}

/* ---------- Logs ---------- */
.r-logs {
  display: grid;
  gap: 8px;
}

.r-logs-head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--nx-rule-soft);
}

.r-logs-pulse {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--nx-success);
  flex-shrink: 0;
  animation: r-pulse 1.4s ease-in-out infinite;
}

.r-logs-title {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--nx-ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.r-logs-meta {
  margin-left: auto;
  font-size: 11px;
  color: var(--nx-ink-muted);
  font-variant-numeric: tabular-nums;
}

.r-logs-more {
  font-size: 11px;
  margin-left: 4px;
}

.r-logs-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 32px 16px;
  border: 1px dashed var(--nx-rule);
  border-radius: var(--radius-md);
  background: var(--nx-paper-deep);
  color: var(--nx-ink-muted);
  font-size: 12.5px;
}

.r-logs-scroll-wrap {
  position: relative;
}

.r-logs-list {
  margin: 0;
  padding: 2px;
}

.r-logs-jump {
  position: absolute;
  right: 10px;
  bottom: 10px;
  padding: 4px 9px;
  background: color-mix(in srgb, var(--nx-card) 94%, transparent);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  box-shadow: var(--shadow-sm);
}

.r-modal-log-list {
  max-height: none;
}

/* ---------- Responsive ---------- */
@media (max-width: 1100px) {
  .r-kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .r-tasks { grid-template-columns: 1fr; }
  .r-tasks-list-col { max-height: 480px; overflow: auto; }
}

@media (max-width: 900px) {
  .r-launcher-head {
    padding: 16px 18px 12px;
  }
  .r-launcher-actions {
    padding: 12px 18px;
    flex-direction: column;
    align-items: stretch;
  }
  .r-launcher-actions .flex-spacer { display: none; }
  .r-launcher-cta { min-width: 0; width: 100%; }

  .r-section-collapsible .r-section-toggle,
  .r-section:not(.r-section-collapsible) {
    padding-left: 18px;
    padding-right: 18px;
  }
  .r-section-body {
    padding-left: 18px;
    padding-right: 18px;
  }

  .r-choice-grid {
    grid-template-columns: 1fr;
  }
  .r-choice-row,
  .r-choice-row-3 {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .r-kpi-grid { grid-template-columns: 1fr; gap: 10px; }
  .r-kpi-value { font-size: 24px; }

  .r-launcher-head {
    flex-direction: column;
    align-items: flex-start;
  }

  .r-task-card { padding: 11px 12px; }
  .r-task-progress-text { min-width: 48px; }
  .r-stat-grid { grid-template-columns: repeat(2, 1fr); }
  .r-stat-value { font-size: 20px; }

  .r-detail-title-row { gap: 8px; }
  .r-detail-actions { width: 100%; }
  .r-detail-actions .btn { flex: 1; justify-content: center; }
}
</style>
