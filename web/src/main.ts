import '@fontsource-variable/inter';
import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');

if (target) {
  try {
    target.innerHTML = '';
    mount(App, { target });
  } catch (err) {
    console.error('应用启动失败', err);
    target.innerHTML = `
      <main class="boot-shell">
        <section class="boot-card">
          <h1>Mongoose 控制台</h1>
          <p>界面启动失败，请刷新页面或查看浏览器控制台。</p>
        </section>
      </main>
    `;
  }
}
