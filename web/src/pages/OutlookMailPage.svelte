<script lang="ts">
  import { onMount } from 'svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import Modal from '../components/Modal.svelte';
  import Icon from '../components/Icon.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { toast } from '../lib/toast';

  type Mailbox = {
    id: number;
    email: string;
    code_api_url: string;
    alias_count: number;
    max_aliases: number;
    in_use: number;
    is_active: number;
    last_used_at: number;
    created_at: number;
  };
  type OutlookData = { workspace_id: string; join_mode: string; items: Mailbox[] };

  let data = $state<OutlookData>({ workspace_id: '', join_mode: 'request', items: [] });
  let loaded = $state(false);
  let selectedIds: number[] = $state([]);

  let cfgOpen = $state(false);
  let cfgWorkspace = $state('');
  let cfgBusy = $state(false);

  let importOpen = $state(false);
  let importText = $state('');
  let importBusy = $state(false);

  let importItems = $derived(importText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
  let availableCount = $derived(data.items.filter((m) => !m.in_use && m.is_active).length);
  let totalAliases = $derived(data.items.reduce((n, m) => n + (m.alias_count || 0), 0));

  async function load() {
    try {
      const r = await fetch('/api/outlook/list');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      data = await r.json();
      selectedIds = selectedIds.filter((id) => data.items.some((m) => m.id === id));
    } catch (e) {
      toast.error(`加载失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      loaded = true;
    }
  }

  function openCfg() {
    cfgWorkspace = data.workspace_id;
    cfgOpen = true;
  }

  async function saveCfg(e: SubmitEvent) {
    e.preventDefault();
    cfgBusy = true;
    try {
      const r = await fetch('/api/outlook/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace_id: cfgWorkspace.trim() })
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      toast.success('已保存 workspace 目标配置');
      cfgOpen = false;
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      cfgBusy = false;
    }
  }

  async function submitImport(e: SubmitEvent) {
    e.preventDefault();
    importBusy = true;
    try {
      const r = await fetch('/api/outlook/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: importText })
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const res = await r.json();
      if (!res.ok) throw new Error(res.error || '导入失败');
      const parts = [`保存 ${res.saved_count ?? 0} 条`];
      if ((res.duplicate_count ?? 0) > 0) parts.push(`去重 ${res.duplicate_count}`);
      if ((res.invalid_count ?? 0) > 0) parts.push(`无效 ${res.invalid_count}`);
      if ((res.invalid_count ?? 0) > 0) toast.info(`导入完成：${parts.join(' · ')}`, 5000);
      else toast.success(`导入完成：${parts.join(' · ')}`);
      importOpen = false;
      importText = '';
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      importBusy = false;
    }
  }

  async function del(ids: number[]) {
    if (!ids.length) return;
    if (!window.confirm(`确认删除 ${ids.length} 个母邮箱？`)) return;
    try {
      const r = await fetch('/api/outlook/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const res = await r.json();
      toast.success(`已删除 ${res.deleted} 个`);
      selectedIds = selectedIds.filter((id) => !ids.includes(id));
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  function toggle(id: number, e?: Event) {
    e?.stopPropagation();
    selectedIds = selectedIds.includes(id)
      ? selectedIds.filter((x) => x !== id)
      : [...selectedIds, id];
  }

  function toggleAll(e: Event) {
    selectedIds = (e.currentTarget as HTMLInputElement).checked ? data.items.map((m) => m.id) : [];
  }

  function maskUrl(url: string) {
    if (!url) return '—';
    return url.length > 52 ? url.slice(0, 40) + '…' + url.slice(-8) : url;
  }

  onMount(load);
</script>

<div class="o-root">
  <header class="o-header">
    <div class="o-header-main">
      <h1 class="o-title">Outlook 邮箱池</h1>
      <p class="o-desc">
        Outlook 直注渠道的母邮箱池：批量导入「母邮箱 ---- 接码链接」，注册以 <code>+别名</code> 扩展，
        同一母邮箱单线程接码。注册成功后自动加入下方 workspace。
      </p>
    </div>
    <div class="o-header-actions">
      <button class="btn" type="button" onclick={load}>
        <Icon name="refresh" size={14} />
        刷新
      </button>
      <button class="btn" type="button" onclick={openCfg}>
        <Icon name="settings" size={14} />
        Workspace 配置
      </button>
      <button class="btn btn-primary" type="button" onclick={() => { importText = ''; importOpen = true; }}>
        <Icon name="upload" size={14} />
        批量导入
      </button>
    </div>
  </header>

  <div class="o-hero">
    <div class="o-hcard">
      <div class="o-hcard-icon"><Icon name="mail" size={18} /></div>
      <div class="o-hcard-body">
        <div class="o-hcard-val">{data.items.length}</div>
        <div class="o-hcard-label">母邮箱总数</div>
      </div>
    </div>
    <div class="o-hcard o-hcard--ok">
      <div class="o-hcard-icon"><Icon name="check" size={18} /></div>
      <div class="o-hcard-body">
        <div class="o-hcard-val">{availableCount}</div>
        <div class="o-hcard-label">当前空闲</div>
      </div>
    </div>
    <div class="o-hcard">
      <div class="o-hcard-icon"><Icon name="user" size={18} /></div>
      <div class="o-hcard-body">
        <div class="o-hcard-val">{totalAliases}</div>
        <div class="o-hcard-label">已用别名累计</div>
      </div>
    </div>
    <div class="o-hcard">
      <div class="o-hcard-icon"><Icon name="box" size={18} /></div>
      <div class="o-hcard-body">
        <div class="o-hcard-val o-hcard-val-ws">{data.workspace_id || '未配置'}</div>
        <div class="o-hcard-label">加入的 Workspace</div>
      </div>
    </div>
  </div>

  <div class="o-panel">
    <div class="o-panel-head">
      <span class="o-panel-title">母邮箱列表</span>
      {#if data.items.length > 0}
        <span class="o-panel-badge">{data.items.length}</span>
      {/if}
      <div class="o-bulk">
        {#if selectedIds.length > 0}
          <button class="btn btn-sm btn-danger" type="button" onclick={() => del(selectedIds)}>
            <Icon name="trash" size={12} />
            删除 ({selectedIds.length})
          </button>
        {/if}
      </div>
    </div>
    <div class="o-panel-body">
      {#if !loaded}
        <div style="display:grid; gap:8px;">
          {#each Array(4) as _, i (i)}<Skeleton height="42px" rounded="md" />{/each}
        </div>
      {:else if data.items.length === 0}
        <EmptyState title="还没有母邮箱" message="点击「批量导入」粘贴「母邮箱 ---- 接码链接」，每行一条" icon="mail">
          {#snippet action()}
            <button class="btn btn-sm btn-primary" type="button" onclick={() => { importText = ''; importOpen = true; }}>
              <Icon name="upload" size={12} /> 批量导入
            </button>
          {/snippet}
        </EmptyState>
      {:else}
        <div class="o-bulk-bar">
          <label class="toggle-row" style="font-size:12px;">
            <input
              type="checkbox"
              checked={selectedIds.length === data.items.length && data.items.length > 0}
              onchange={toggleAll}
            />
            <span>全选</span>
          </label>
        </div>
        <div class="o-list">
          {#each data.items as m (m.id)}
            <div class="o-row" class:o-row-sel={selectedIds.includes(m.id)}>
              <input type="checkbox" checked={selectedIds.includes(m.id)} onchange={(e) => toggle(m.id, e)} aria-label={`选择 ${m.email}`} />
              <div class="o-row-main">
                <span class="o-row-email">{m.email}</span>
                <span class="o-row-url" title={m.code_api_url}>{maskUrl(m.code_api_url)}</span>
              </div>
              {#if m.in_use}
                <span class="pill pill-warning">占用中</span>
              {:else}
                <span class="pill pill-success">空闲</span>
              {/if}
              <span class="o-row-count" title="已用别名数">别名 {m.alias_count}</span>
              <button class="btn btn-xs btn-danger" type="button" onclick={() => del([m.id])} aria-label="删除">
                <Icon name="trash" size={11} />
              </button>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>
</div>

<Modal open={cfgOpen} title="Workspace 目标配置" kicker="OUTLOOK" subtitle="注册成功后子号将加入该母号 workspace" size="sm" onclose={() => { if (!cfgBusy) cfgOpen = false; }}>
  <form id="o-cfg-form" class="form-section" onsubmit={saveCfg}>
    <label class="form-field">
      <span class="form-label form-label-required">Workspace ID</span>
      <input class="input text-mono" bind:value={cfgWorkspace} placeholder="63d426c3-e5bf-4846-8b9f-490637a55312" required disabled={cfgBusy} autocomplete="off" />
      <p class="form-help">加入母号 workspace 的 UUID（regist.txt 里的 workspace ID）。所有 Outlook 直注号都会申请加入它。</p>
    </label>
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={() => cfgOpen = false} disabled={cfgBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="o-cfg-form" disabled={cfgBusy || !cfgWorkspace.trim()} data-loading={cfgBusy}>
      {cfgBusy ? '保存中…' : '保存'}
    </button>
  {/snippet}
</Modal>

<Modal open={importOpen} title="批量导入母邮箱" kicker="OUTLOOK" subtitle="每行一条：母邮箱 ---- 接码链接" size="md" onclose={() => { if (!importBusy) importOpen = false; }}>
  <form id="o-import-form" class="form-section" onsubmit={submitImport}>
    <label class="form-field">
      <span class="form-label form-label-required">邮箱数据</span>
      <textarea
        class="input text-mono"
        bind:value={importText}
        placeholder={`ShascaraFrfnz6565@outlook.com----http://ms.outlook007.cc/api/open/email/latest?api_key=xxx&pt=yyy&email=ShascaraFrfnz6565@outlook.com`}
        required
        disabled={importBusy}
        autocomplete="off"
        rows="10"
      ></textarea>
      <p class="form-help">格式：<code>母邮箱----接码API链接</code>，用 <strong>----</strong> 分隔。重复母邮箱会更新接码链接。</p>
    </label>
    {#if importItems.length > 0}
      <div class="o-preview">
        <div class="o-preview-head"><Icon name="list" size={12} /> 待导入 {importItems.length} 行</div>
      </div>
    {/if}
  </form>
  {#snippet footer()}
    <button class="btn" type="button" onclick={() => importOpen = false} disabled={importBusy}>取消</button>
    <button class="btn btn-primary" type="submit" form="o-import-form" disabled={importBusy || importItems.length === 0} data-loading={importBusy}>
      {importBusy ? '导入中…' : `导入 ${importItems.length} 行`}
    </button>
  {/snippet}
</Modal>

<style>
  .o-root { display: flex; flex-direction: column; gap: 20px; }
  .o-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding-bottom: 22px; border-bottom: 1px solid var(--nx-rule); flex-wrap: wrap; }
  .o-header-main { display: grid; gap: 4px; max-width: 620px; }
  .o-title { margin: 0; font-size: 26px; font-weight: 700; color: var(--nx-ink); line-height: 1.15; }
  .o-desc { margin: 0; font-size: 13px; color: var(--nx-ink-muted); line-height: 1.5; }
  .o-desc code { font-family: var(--font-mono); background: var(--nx-paper-deep); padding: 1px 4px; border-radius: 4px; }
  .o-header-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; flex-wrap: wrap; }

  .o-hero { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .o-hcard { display: flex; align-items: center; gap: 14px; padding: 16px 18px; border: 1px solid var(--nx-rule); border-radius: var(--radius-lg); background: var(--nx-card); box-shadow: var(--shadow-xs); }
  .o-hcard--ok { border-color: var(--nx-success-border); background: linear-gradient(135deg, var(--nx-success-bg) 0%, var(--nx-card) 55%); }
  .o-hcard-icon { display: grid; place-items: center; width: 44px; height: 44px; flex-shrink: 0; border-radius: var(--radius-md); background: color-mix(in srgb, var(--nx-brand) 12%, transparent); color: var(--nx-brand); border: 1px solid color-mix(in srgb, var(--nx-brand) 22%, transparent); }
  .o-hcard--ok .o-hcard-icon { background: color-mix(in srgb, var(--nx-success) 12%, transparent); color: var(--nx-success); border-color: color-mix(in srgb, var(--nx-success) 25%, transparent); }
  .o-hcard-body { display: grid; gap: 2px; min-width: 0; }
  .o-hcard-val { font-family: var(--font-number); font-size: 22px; font-weight: 700; color: var(--nx-ink); line-height: 1.1; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .o-hcard-val-ws { font-family: var(--font-mono); font-size: 11.5px; font-weight: 500; }
  .o-hcard-label { font-size: 10.5px; font-weight: 600; color: var(--nx-ink-muted); text-transform: uppercase; letter-spacing: 0.07em; }

  .o-panel { border: 1px solid var(--nx-rule); border-radius: var(--radius-lg); background: var(--nx-card); box-shadow: var(--shadow-xs); overflow: hidden; }
  .o-panel-head { display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--nx-rule); background: color-mix(in srgb, var(--nx-paper-deep) 30%, var(--nx-card)); }
  .o-panel-title { font-size: 13px; font-weight: 700; color: var(--nx-ink); }
  .o-panel-badge { display: inline-flex; align-items: center; justify-content: center; min-width: 20px; height: 20px; padding: 0 5px; border-radius: var(--radius-full); background: color-mix(in srgb, var(--nx-brand) 15%, transparent); color: var(--nx-brand); font-size: 10.5px; font-weight: 700; }
  .o-bulk { margin-left: auto; }
  .o-panel-body { padding: 14px 16px; }
  .o-bulk-bar { display: flex; align-items: center; gap: 10px; padding-bottom: 10px; margin-bottom: 10px; border-bottom: 1px solid var(--nx-rule); }
  .o-list { display: grid; gap: 4px; }
  .o-row { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: var(--radius-sm); border: 1px solid transparent; background: color-mix(in srgb, var(--nx-paper-deep) 40%, var(--nx-card)); }
  .o-row:hover { background: var(--nx-card-sun); border-color: var(--nx-rule); }
  .o-row-sel { background: color-mix(in srgb, var(--nx-brand) 6%, var(--nx-card)) !important; border-color: color-mix(in srgb, var(--nx-brand) 25%, transparent) !important; }
  .o-row-main { flex: 1; min-width: 0; display: grid; gap: 2px; }
  .o-row-email { font-family: var(--font-mono); font-size: 12.5px; font-weight: 600; color: var(--nx-ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .o-row-url { font-size: 10.5px; color: var(--nx-ink-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .o-row-count { font-size: 10.5px; font-weight: 600; color: var(--nx-ink-muted); background: color-mix(in srgb, var(--nx-ink-muted) 10%, transparent); padding: 1px 7px; border-radius: var(--radius-full); white-space: nowrap; flex-shrink: 0; }
  .o-preview { padding: 10px 12px; border: 1px solid var(--nx-rule); border-radius: var(--radius-md); background: var(--nx-paper-deep); }
  .o-preview-head { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--nx-ink-muted); }

  @media (max-width: 1024px) { .o-hero { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 640px) { .o-header { flex-direction: column; align-items: stretch; } }
</style>
