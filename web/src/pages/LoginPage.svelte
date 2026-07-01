<script lang="ts">
  import Icon from '../components/Icon.svelte';
  import { toast } from '../lib/toast';

  interface Props {
    onLoggedIn: (username: string) => void;
  }

  let { onLoggedIn }: Props = $props();
  let username = $state('admin');
  let password = $state('');
  let busy = $state(false);
  let showPassword = $state(false);

  async function submitLogin(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password
        })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }
      const next = data.user?.username ?? username.trim();
      toast.success(`欢迎回来，${next}`);
      onLoggedIn(next);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busy = false;
    }
  }
</script>

<main class="login-shell auth-shell">
  <section class="auth-card" aria-labelledby="login-title">
    <div class="auth-main">
      <header class="auth-head">
        <p class="auth-kicker">控制台登录</p>
        <h1 id="login-title">欢迎回来</h1>
        <p class="auth-sub">登录以继续管理你的账号与任务</p>
      </header>

      <form class="auth-form" onsubmit={submitLogin}>
        <label class="field">
          <span>用户名</span>
          <div class="field-control">
            <span class="field-icon">
              <Icon name="user" size={14} />
            </span>
            <input
              class="input field-input"
              bind:value={username}
              autocomplete="username"
              required
              disabled={busy}
              placeholder="请输入账号"
            />
          </div>
        </label>
        <label class="field">
          <span>密码</span>
          <div class="field-control">
            <span class="field-icon">
              <Icon name="lock" size={14} />
            </span>
            <input
              class="input field-input field-input-pwd"
              bind:value={password}
              type={showPassword ? 'text' : 'password'}
              autocomplete="current-password"
              required
              disabled={busy}
              placeholder="请输入密码"
            />
            <button
              type="button"
              class="field-toggle"
              onclick={() => showPassword = !showPassword}
              disabled={busy}
              aria-label={showPassword ? '隐藏密码' : '显示密码'}
              tabindex="-1"
            >
              <Icon name={showPassword ? 'eye-off' : 'eye'} size={14} />
            </button>
          </div>
        </label>
        <button
          class="btn btn-primary btn-lg auth-submit"
          type="submit"
          disabled={busy || username.trim() === '' || password === ''}
          data-loading={busy}
        >
          {busy ? '正在登录…' : '登录控制台'}
        </button>
      </form>

      <div class="auth-foot">
        <Icon name="shield" size={12} />
        <span>会话仅在本机有效，关闭浏览器后失效</span>
      </div>
    </div>
  </section>
</main>

<style>
  .auth-shell {
    padding: 32px 20px;
  }

  .auth-card {
    width: min(100%, 430px);
    border: 1px solid var(--nx-rule);
    border-radius: var(--radius-2xl);
    background: var(--nx-card);
    box-shadow: var(--shadow-xl);
    overflow: hidden;
    animation: auth-pop var(--duration-slow) var(--ease-spring) both;
  }

  @keyframes auth-pop {
    from { opacity: 0; transform: translateY(8px) scale(0.99); }
    to { opacity: 1; transform: none; }
  }

  /* ---- Form main ---- */
  .auth-main {
    display: flex;
    flex-direction: column;
    justify-content: center;
    padding: 42px 40px;
  }

  .auth-head {
    margin-bottom: 24px;
  }

  .auth-kicker {
    margin: 0 0 7px;
    color: var(--nx-brand);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.09em;
  }

  .auth-head h1 {
    margin: 0;
    font-size: 24px;
    font-weight: 650;
    line-height: 1.2;
    letter-spacing: -0.02em;
  }

  .auth-sub {
    margin: 7px 0 0;
    color: var(--nx-ink-muted);
    font-size: 13px;
  }

  .auth-form {
    display: grid;
    gap: 15px;
  }

  .field-control {
    position: relative;
    display: flex;
    align-items: center;
  }

  .field-icon {
    position: absolute;
    left: 14px;
    color: var(--nx-ink-muted);
    pointer-events: none;
    display: inline-flex;
  }

  .field-input {
    padding-left: 38px;
  }

  .field-input-pwd {
    padding-right: 42px;
  }

  .field-toggle {
    position: absolute;
    right: 6px;
    display: inline-grid;
    place-items: center;
    width: 30px;
    height: 30px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--nx-ink-muted);
    cursor: pointer;
    transition: all var(--duration-fast) var(--ease-out);
  }

  .field-toggle:hover:not(:disabled) {
    background: var(--nx-paper-deep);
    color: var(--nx-ink);
  }

  .field-toggle:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .auth-submit {
    width: 100%;
    margin-top: 5px;
  }

  .auth-foot {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 22px;
    padding-top: 18px;
    border-top: 1px solid var(--nx-rule-soft);
    color: var(--nx-ink-muted);
    font-size: 11.5px;
  }

  /* ---- Responsive ---- */
  @media (max-width: 480px) {
    .auth-main {
      padding: 30px 24px;
    }

    .auth-head h1 {
      font-size: 22px;
    }
  }
</style>
