/* eslint-disable no-unused-vars */
(function () {
  const getEl = (id) => document.getElementById(id);

  const safeText = (value) => (value === null || value === undefined) ? '' : String(value);

  function showToast() {
    const toast = getEl('toast');
    if (!toast) return;
    toast.classList.remove('translate-y-20', 'opacity-0');
    window.setTimeout(() => {
      toast.classList.add('translate-y-20', 'opacity-0');
    }, 2000);
  }

  function copyToClipboard(text) {
    const normalized = safeText(text);
    if (!normalized) return;
    navigator.clipboard.writeText(normalized).then(() => {
      showToast();
    }).catch(() => {
      alert('Failed to copy');
    });
  }

  function copyLink(elementId) {
    const element = getEl(elementId);
    if (!element) return;
    copyToClipboard(element.value);
  }

  function toggleConfig() {
    const content = getEl('configContent');
    const arrow = getEl('arrow');
    if (!content || !arrow) return;

    content.classList.toggle('hidden');
    arrow.classList.toggle('rotate-180');
  }

  function switchOsTab(osType) {
    document.querySelectorAll('.os-tab-btn').forEach((btn) => {
      btn.className = 'os-tab-btn flex items-center gap-2 px-4 py-2 text-sm font-medium text-muted hover:text-white hover:bg-white/5 rounded-lg transition-colors';
    });
    const activeBtn = getEl(`os-tab-${osType}`);
    if (activeBtn) {
      activeBtn.className = 'os-tab-btn active flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg transition-colors';
    }
    renderApps(osType);
  }

  function switchAppTab(e, tabId) {
    document.querySelectorAll('.app-content').forEach((el) => el.classList.add('hidden'));
    document.querySelectorAll('.app-tab-btn').forEach((btn) => {
      btn.className = 'app-tab-btn px-4 py-2 text-sm font-medium text-muted hover:text-white hover:bg-white/5 rounded-lg transition-colors whitespace-nowrap';
    });

    if (e?.currentTarget) {
      e.currentTarget.className = 'app-tab-btn active px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg transition-colors whitespace-nowrap';
    }

    const tab = getEl(tabId);
    if (tab) tab.classList.remove('hidden');
  }

  let currentFAQPlatform = 'android';

  function switchFAQPlatform(platform) {
    currentFAQPlatform = platform;

    document.querySelectorAll('.faq-platform-btn').forEach((btn) => {
      btn.className = 'faq-platform-btn flex items-center gap-2 px-4 py-2 text-sm font-medium text-muted hover:text-white hover:bg-white/5 rounded-lg transition-colors';
    });
    const activeBtn = getEl(`faq-tab-${platform}`);
    if (activeBtn) {
      activeBtn.className = 'faq-platform-btn active flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg transition-colors';
    }

    renderFAQs();
  }

  function toggleFAQ(id) {
    const content = getEl(`faq-content-${id}`);
    const icon = getEl(`faq-icon-${id}`);
    if (!content || !icon) return;

    content.classList.toggle('hidden');
    icon.classList.toggle('rotate-180');
  }

  let apps = [];
  let faqs = [];

  function loadData() {
    const dataEl = getEl('sub-data');
    if (!dataEl) return;
    try {
      apps = JSON.parse(dataEl.dataset.apps || '[]');
    } catch {
      apps = [];
    }
    try {
      faqs = JSON.parse(dataEl.dataset.faqs || '[]');
    } catch {
      faqs = [];
    }
  }

  function initProgressBar() {
    const bar = getEl('used-progress');
    if (!bar) return;
    const width = Number(bar.getAttribute('data-width'));
    const bounded = Number.isFinite(width) ? Math.max(0, Math.min(100, width)) : 0;
    bar.style.width = `${bounded}%`;
  }

  function renderApps(osType) {
    const tabsContainer = getEl('app-tabs-container');
    const contentContainer = getEl('app-content-container');
    if (!tabsContainer || !contentContainer) return;

    tabsContainer.textContent = '';
    contentContainer.textContent = '';

    const filteredApps = (apps || []).filter((app) => (app.os_type || 'android') === osType);
    if (filteredApps.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'text-center text-muted py-4 w-full';
      empty.textContent = 'No apps found for this platform.';
      contentContainer.appendChild(empty);
      return;
    }

    filteredApps.forEach((app, index) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = index === 0
        ? 'app-tab-btn active px-4 py-2 text-sm font-medium text-white bg-white/10 rounded-lg transition-colors whitespace-nowrap'
        : 'app-tab-btn px-4 py-2 text-sm font-medium text-muted hover:text-white hover:bg-white/5 rounded-lg transition-colors whitespace-nowrap';
      btn.textContent = safeText(app.name);
      btn.addEventListener('click', (e) => switchAppTab(e, `tab-${app.id}`));
      tabsContainer.appendChild(btn);

      const os = app.os_type || 'android';
      let storeIcon = '';
      let storeLabel = 'Store';

      if (os === 'android') {
        storeLabel = 'Google Play';
        storeIcon = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M3,20.5V3.5C3,2.91 3.34,2.39 3.84,2.15L13.69,12L3.84,21.85C3.34,21.6 3,21.09 3,20.5M16.81,15.12L6.05,21.34L14.54,12.85L16.81,15.12M20.16,10.81C20.5,11.08 20.75,11.5 20.75,12C20.75,12.5 20.5,12.92 20.16,13.19L17.89,14.5L15.39,12L17.89,9.5L20.16,10.81M6.05,2.66L16.81,8.88L14.54,11.15L6.05,2.66Z" /></svg>';
      } else if (os === 'ios') {
        storeLabel = 'App Store';
        storeIcon = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M18.71,19.5C17.88,20.74 17,21.95 15.66,21.97C14.32,22 13.89,21.18 12.37,21.18C10.84,21.18 10.37,21.95 9.1,22C7.79,22.05 6.8,20.68 5.96,19.47C4.25,17 2.94,12.45 4.7,9.39C5.57,7.87 7.13,6.91 8.82,6.88C10.1,6.86 11.32,7.75 12.11,7.75C12.89,7.75 14.37,6.68 15.92,6.84C16.57,6.87 18.39,7.1 19.56,8.82C19.47,8.88 17.39,10.1 17.41,12.63C17.44,15.65 20.06,16.66 20.09,16.7C20.06,16.74 19.67,18.11 18.71,19.5M13,3.5C13.73,2.67 14.94,2.04 15.94,2C16.07,3.17 15.6,4.35 14.9,5.19C14.21,6.04 13.07,6.7 11.95,6.61C11.8,5.37 12.36,4.26 13,3.5Z" /></svg>';
      } else {
        storeIcon = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"></path><line x1="3" y1="6" x2="21" y2="6"></line><path d="M16 10a4 4 0 0 1-8 0"></path></svg>';
      }

      const tutorialIcon = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>';
      const downloadIcon = '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';

      const descLines = safeText(app.description_fa || '').split('\n').filter(Boolean);
      const desc = descLines.map((line, i) =>
        `<li class="flex gap-3 text-sm text-muted"><span class="w-5 h-5 rounded-full bg-white/5 flex items-center justify-center text-xs font-bold text-white shrink-0">${i + 1}</span><span class="rtl">${line}</span></li>`
      ).join('');

      const content = document.createElement('div');
      content.id = `tab-${app.id}`;
      content.className = index === 0 ? 'app-content' : 'app-content hidden';
      content.innerHTML = `
        <div class="bg-bg/50 rounded-xl p-4 border border-white/5">
          <h3 class="font-semibold text-white mb-4 rtl">${safeText(app.title_fa || app.name)}</h3>
          <ul class="space-y-3 mb-5 rtl">${desc}</ul>
          <div class="flex gap-3">
            ${app.download_link ? `<a href="${app.download_link}" target="_blank" rel="noopener" class="flex-1 border border-white/20 bg-white/5 hover:bg-white/10 hover:border-primary/50 text-white py-2.5 rounded-lg text-sm font-medium text-center transition-all flex items-center justify-center gap-2">${downloadIcon} Download</a>` : ''}
            ${app.store_link ? `<a href="${app.store_link}" target="_blank" rel="noopener" class="flex-1 border border-white/20 bg-white/5 hover:bg-white/10 hover:border-primary/50 text-white py-2.5 rounded-lg text-sm font-medium text-center transition-all flex items-center justify-center gap-2">${storeIcon} ${storeLabel}</a>` : ''}
            ${app.tutorial_link ? `<a href="${app.tutorial_link}" target="_blank" rel="noopener" class="flex-1 border border-white/20 bg-white/5 hover:bg-white/10 hover:border-primary/50 text-white py-2.5 rounded-lg text-sm font-medium text-center transition-all flex items-center justify-center gap-2">${tutorialIcon} Tutorial</a>` : ''}
          </div>
        </div>
      `;
      contentContainer.appendChild(content);
    });
  }

  function renderFAQs() {
    const container = getEl('faq-container');
    if (!container) return;

    const filteredFaqs = (faqs || []).filter((f) => (f.platform || 'android') === currentFAQPlatform);
    if (!filteredFaqs || filteredFaqs.length === 0) {
      container.textContent = '';
      const empty = document.createElement('div');
      empty.className = 'text-center text-muted py-4';
      empty.textContent = 'No FAQs available for this platform.';
      container.appendChild(empty);
      return;
    }

    container.innerHTML = filteredFaqs.map((faq) => `
      <div class="border border-white/10 rounded-lg overflow-hidden bg-white/5">
        <button type="button" data-action="toggleFAQ" data-faq-id="${faq.id}" class="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-white/5 transition-colors rtl">
          <span class="font-medium text-white">${safeText(faq.title)}</span>
          <svg id="faq-icon-${faq.id}" class="w-4 h-4 text-muted transition-transform duration-200" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        </button>
        <div id="faq-content-${faq.id}" class="hidden border-t border-white/10 bg-bg/50">
          <div class="p-4 text-sm text-muted space-y-4 rtl">
            ${faq.image_url ? `<img src="${faq.image_url}" alt="${safeText(faq.title)}" class="w-full rounded-lg mb-3">` : ''}
            <div class="prose prose-invert max-w-none text-sm">${faq.content || ''}</div>
            ${faq.video_url ? `
              <div class="mt-3">
                <a href="${faq.video_url}" target="_blank" rel="noopener" class="inline-flex items-center gap-2 text-primary hover:text-primary/80 transition-colors">
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
                  Watch Video Tutorial
                </a>
              </div>
            ` : ''}
          </div>
        </div>
      </div>
    `).join('');
  }

  function bindEvents() {
    document.addEventListener('click', (e) => {
      const target = e.target;
      if (!(target instanceof Element)) return;

      const actionEl = target.closest('[data-action]');
      if (!actionEl) return;

      const action = actionEl.getAttribute('data-action');
      if (action === 'copyLink') {
        e.preventDefault();
        copyLink('subLink');
        return;
      }
      if (action === 'switchOsTab') {
        e.preventDefault();
        const os = actionEl.getAttribute('data-os');
        if (os) switchOsTab(os);
        return;
      }
      if (action === 'switchFAQPlatform') {
        e.preventDefault();
        const platform = actionEl.getAttribute('data-platform');
        if (platform) switchFAQPlatform(platform);
        return;
      }
      if (action === 'toggleConfig') {
        e.preventDefault();
        toggleConfig();
        return;
      }
      if (action === 'toggleFAQ') {
        e.preventDefault();
        const idRaw = actionEl.getAttribute('data-faq-id');
        const id = Number(idRaw);
        if (Number.isFinite(id)) toggleFAQ(id);
        return;
      }
      if (action === 'copyConfig') {
        e.preventDefault();
        const txt = actionEl.getAttribute('data-config');
        copyToClipboard(txt);
        return;
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    loadData();
    initProgressBar();
    bindEvents();
    renderApps('android');
    renderFAQs();
  });
})();
