<script lang="ts">
  import { onMount } from 'svelte';
  import ConsolePage from './pages/ConsolePage.svelte';
  import AccountPage from './pages/AccountPage.svelte';
  import LoginPage from './pages/LoginPage.svelte';
  import MailConfigPage from './pages/MailConfigPage.svelte';
  import OutlookMailPage from './pages/OutlookMailPage.svelte';
  import ProxyPoolPage from './pages/ProxyPoolPage.svelte';
  import RegistrationPage from './pages/RegistrationPage.svelte';
  import UploadConfigPage from './pages/UploadConfigPage.svelte';
  import ToastRegion from './components/ToastRegion.svelte';
  import Icon, { type IconName } from './components/Icon.svelte';
  import { pathForRoute, routeFromPath, type AppRoute } from './lib/routes';

  const routeTitles: Record<AppRoute, string> = {
    login: '登录',
    console: '控制台',
    'proxy-pool': '代理池',
    mail: '邮件',
    accounts: '账号管理',
    registration: '注册工作台',
    'upload-config': '上传配置'
  };

  type NavItem = { route: AppRoute; label: string; icon: IconName; hint?: string };

  const navGroups: { title: string; items: NavItem[] }[] = [
    {
      title: '总览',
      items: [
        { route: 'console', label: '控制台', icon: 'dashboard' }
      ]
    },
    {
      title: '资源',
      items: [
        { route: 'proxy-pool', label: '代理池', icon: 'globe' },
        { route: 'mail', label: '邮件', icon: 'mail' },
        { route: 'outlook-mail', label: 'Outlook 池', icon: 'mail' },
        { route: 'accounts', label: '账号管理', icon: 'user' }
      ]
    },
    {
      title: '运行',
      items: [
        { route: 'registration', label: '注册工作台', icon: 'sparkles' },
        { route: 'upload-config', label: '上传配置', icon: 'upload' }
      ]
    }
  ];

  let route: AppRoute = $state(routeFromPath(window.location.pathname));
  let authChecked = $state(false);
  let authenticated = $state(false);
  let username = $state('');
  let authDisabled = $state(false);
  let drawerOpen = $state(false);
  let darkMode = $state(false);

  let userInitial = $derived((authDisabled ? 'L' : (username || '?').charAt(0)).toUpperCase());

  function initTheme() {
    const stored = localStorage.getItem('mongoose-theme');
    if (stored === 'light') {
      darkMode = false;
      document.documentElement.classList.remove('dark');
    } else {
      darkMode = true;
      document.documentElement.classList.add('dark');
    }
  }

  function toggleTheme() {
    darkMode = !darkMode;
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('mongoose-theme', darkMode ? 'dark' : 'light');
  }

  function setRoute(next: AppRoute, replace = false) {
    const path = pathForRoute(next);
    route = next;
    document.title = `Mongoose · ${routeTitles[next]}`;
    if (window.location.pathname !== path) {
      const method = replace ? window.history.replaceState : window.history.pushState;
      method.call(window.history, {}, '', path);
    }
  }

  function syncRouteFromLocation() {
    setRoute(routeFromPath(window.location.pathname), true);
  }

  function navigate(event: MouseEvent, next: AppRoute) {
    event.preventDefault();
    drawerOpen = false;
    setRoute(next);
  }

  async function checkAuth() {
    try {
      const response = await fetch('/api/auth/me');
      const data = await response.json();
      authenticated = Boolean(data.authenticated);
      authDisabled = Boolean(data.auth_disabled);
      username = data.user?.username ?? '';
      authChecked = true;
      if (!authenticated && route !== 'login') {
        setRoute('login', true);
      } else if (authenticated && route === 'login') {
        setRoute('console', true);
      }
    } catch (err) {
      console.error('鉴权状态检查失败', err);
      authenticated = false;
      authChecked = true;
      setRoute('login', true);
    }
  }

  function handleLoggedIn(nextUsername: string) {
    authenticated = true;
    username = nextUsername;
    authChecked = true;
    setRoute('console', true);
  }

  async function logout() {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
    } finally {
      authenticated = false;
      username = '';
      drawerOpen = false;
      setRoute('login');
    }
  }

  function toggleDrawer() {
    drawerOpen = !drawerOpen;
  }

  function closeDrawer() {
    drawerOpen = false;
  }

  function handleDrawerKey(event: KeyboardEvent) {
    if (event.key === 'Escape') closeDrawer();
  }

  onMount(() => {
    initTheme();
    syncRouteFromLocation();
    checkAuth();
    window.addEventListener('popstate', syncRouteFromLocation);
    return () => window.removeEventListener('popstate', syncRouteFromLocation);
  });
</script>

<ToastRegion />

{#if !authChecked}
  <main class="boot-shell">
    <section class="boot-card">
      <span class="login-mark" style="margin: 0 auto 16px;">M</span>
      <h1>Mongoose 控制台</h1>
      <p>正在检查登录状态…</p>
    </section>
  </main>
{:else if !authenticated || route === 'login'}
  <LoginPage onLoggedIn={handleLoggedIn} />
{:else}
<div class="shell">
  <aside class="sidebar" aria-label="主导航">
    <p class="sidebar-brand">
      <span class="topbar-brand-mark">M</span>
      Mongoose
    </p>
    <nav class="site-nav" aria-label="栏目">
      {#each navGroups as group, gi}
        {#if gi > 0}
          <div class="nav-group-spacer"></div>
        {/if}
        <span class="nav-group-title">{group.title}</span>
        {#each group.items as item}
          <a
            href={pathForRoute(item.route)}
            class:active={route === item.route}
            aria-current={route === item.route ? 'page' : undefined}
            onclick={(event) => navigate(event, item.route)}
          >
            <Icon name={item.icon} size={16} strokeWidth={1.7} />
            <span>{item.label}</span>
          </a>
        {/each}
      {/each}
    </nav>
    <div class="sidebar-footer">
      <button class="btn-ghost btn btn-sm sidebar-action" type="button" onclick={toggleTheme}>
        <Icon name={darkMode ? 'sun' : 'moon'} size={14} />
        <span>{darkMode ? '浅色模式' : '深色模式'}</span>
      </button>
      <div class="sidebar-user">
        <span class="sidebar-user-avatar">{userInitial}</span>
        <div class="sidebar-user-info">
          <span class="sidebar-user-label">{authDisabled ? '本地模式' : '已登录'}</span>
          <strong>{authDisabled ? '调试用户' : username}</strong>
        </div>
      </div>
      <button class="btn-ghost btn btn-sm sidebar-action" type="button" onclick={logout}>
        <Icon name="logout" size={14} />
        <span>退出登录</span>
      </button>
    </div>
  </aside>

  <div class="page-shell">
    <header class="topbar">
      <div class="topbar-inner">
        <button class="topbar-toggle" type="button" onclick={toggleDrawer} aria-label="打开导航">
          <Icon name="menu" size={18} strokeWidth={1.8} />
        </button>
        <p class="topbar-brand">
          <span class="topbar-brand-mark">M</span>
          Mongoose
        </p>
        <span class="topbar-route" aria-hidden="true">{routeTitles[route]}</span>
        <button class="topbar-theme-toggle" type="button" onclick={toggleTheme} aria-label="切换主题">
          <Icon name={darkMode ? 'sun' : 'moon'} size={15} />
        </button>
        <span class="topbar-user-chip" title={username}>
          <span class="topbar-user-mark">{userInitial}</span>
          {authDisabled ? '本地' : (username || '游客')}
        </span>
      </div>
    </header>

    {#if drawerOpen}
      <div
        class="nav-drawer-backdrop is-open"
        role="presentation"
        onclick={closeDrawer}
        onkeydown={handleDrawerKey}
      ></div>
      <aside class="nav-drawer" aria-label="移动导航">
        <div class="nav-drawer-head">
          <h2 class="nav-drawer-title">
            <span class="nav-drawer-title-mark">M</span>
            Mongoose
          </h2>
          <button class="nav-drawer-close" type="button" onclick={closeDrawer} aria-label="关闭导航">×</button>
        </div>
        <nav class="site-nav" aria-label="栏目">
          {#each navGroups as group, gi}
            {#if gi > 0}
              <div class="nav-group-spacer"></div>
            {/if}
            <span class="nav-group-title">{group.title}</span>
            {#each group.items as item}
              <a
                href={pathForRoute(item.route)}
                class:active={route === item.route}
                aria-current={route === item.route ? 'page' : undefined}
                onclick={(event) => navigate(event, item.route)}
              >
                <Icon name={item.icon} size={16} strokeWidth={1.7} />
                <span>{item.label}</span>
              </a>
            {/each}
          {/each}
        </nav>
        <div class="sidebar-footer">
          <button class="btn-ghost btn btn-sm sidebar-action" type="button" onclick={toggleTheme}>
            <Icon name={darkMode ? 'sun' : 'moon'} size={14} />
            <span>{darkMode ? '浅色模式' : '深色模式'}</span>
          </button>
          <div class="sidebar-user">
            <span class="sidebar-user-avatar">{userInitial}</span>
            <div class="sidebar-user-info">
              <span class="sidebar-user-label">{authDisabled ? '本地模式' : '已登录'}</span>
              <strong>{authDisabled ? '调试用户' : username}</strong>
            </div>
          </div>
          <button class="btn-ghost btn btn-sm sidebar-action" type="button" onclick={logout}>
            <Icon name="logout" size={14} />
            <span>退出登录</span>
          </button>
        </div>
      </aside>
    {/if}

    <main class="page-content">
      {#if route === 'console'}
        <ConsolePage />
      {:else if route === 'proxy-pool'}
        <ProxyPoolPage />
      {:else if route === 'mail'}
        <MailConfigPage />
      {:else if route === 'outlook-mail'}
        <OutlookMailPage />
      {:else if route === 'accounts'}
        <AccountPage />
      {:else if route === 'registration'}
        <RegistrationPage />
      {:else if route === 'upload-config'}
        <UploadConfigPage />
      {:else}
        <ConsolePage />
      {/if}
    </main>
  </div>
</div>
{/if}

<style>
  .nav-group-title {
    display: block;
    padding: 12px 14px 6px;
    color: var(--nx-ink-muted);
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .nav-group-spacer {
    height: 2px;
  }

  .sidebar-action {
    width: 100%;
    justify-content: flex-start;
    gap: 10px;
    height: 34px;
    padding: 0 12px;
    color: var(--nx-ink-soft);
  }

  .sidebar-action :global(svg) {
    flex-shrink: 0;
    opacity: 0.75;
  }

  .topbar-theme-toggle {
    display: inline-grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: transparent;
    color: var(--nx-ink-soft);
    cursor: pointer;
    transition: background var(--duration-fast) var(--ease-out),
                color var(--duration-fast) var(--ease-out);
  }

  .topbar-theme-toggle:hover {
    background: color-mix(in srgb, var(--nx-ink) 6%, transparent);
    color: var(--nx-ink);
  }

  .topbar-user-mark {
    display: inline-grid;
    place-items: center;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--nx-brand), var(--nx-brand-deep));
    color: #fff;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: -0.03em;
    box-shadow: 0 1px 3px rgba(201, 100, 66, 0.32);
  }
</style>
