const connectionLabels = {
  idle: '已连接',
  connected: '已连接',
  syncing: '正在同步',
  connecting: '正在连接',
  disconnected: '连接中断',
  unconfigured: '等待设置连接',
  unpaired: '等待证书配对',
  approval_required: '等待首次同步确认',
  upgrade_required: '从机需要升级',
  error: '连接异常',
};
let lastShownSyncError = '';

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
}

function localTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  }).format(date);
}

function humanBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

function updateReplica(replica) {
  const available = Boolean(replica);
  setText('replica-root', replica?.root);
  setText('replica-addr', replica?.addr);
  setText('replica-version', replica?.version || (available ? '旧版，需手动升级一次' : '—'));
  setText('replica-availability', available ? '已连接' : '未连接');
  const historyEnabled = available && replica.retention_days > 0;
  setText('history-help', !available
    ? '连接后可设置历史备份'
    : historyEnabled ? '覆盖同路径文件前保存旧版本' : '已关闭；再次开启默认保留 7 天，已有历史保留');
  const historySwitch = document.getElementById('replica-history-switch');
  if (historySwitch) {
    if (!historySwitch.dataset.pending) historySwitch.disabled = !available;
    historySwitch.classList.toggle('is-on', historyEnabled);
    historySwitch.setAttribute('aria-checked', String(historyEnabled));
    historySwitch.value = historyEnabled ? 'false' : 'true';
  }
  for (const [id, key] of [
    ['replica-retention', 'retention_days'],
    ['replica-verify', 'verify_interval_secs'],
  ]) {
    const input = document.getElementById(id);
    if (!input) continue;
    input.disabled = !available;
    if (!input.dataset.dirty) input.value = available ? replica[key] : '';
  }
  const save = document.getElementById('replica-save');
  if (save) save.disabled = !available;
}

function updateUpgrade(upgrade, replica, target, sourceVersion) {
  const phase = upgrade?.phase || 'idle';
  const active = ['queued', 'sending', 'restarting'].includes(phase);
  const supported = Boolean(replica?.upgrade_supported);
  const open = document.getElementById('upgrade-open');
  if (open) open.disabled = !supported || active;
  setText('upgrade-help', supported
    ? `从主机 ${sourceVersion} 传送程序，有更新时自动重启`
    : replica ? '从机需先手动安装支持远程升级的版本' : '连接从机后可查看升级能力');
  const state = document.getElementById('upgrade-state');
  if (state) {
    state.hidden = phase === 'idle';
    state.classList.toggle('is-error', phase === 'failed');
    state.textContent = upgrade?.message || '';
  }
  const progress = document.getElementById('upgrade-progress');
  if (progress) {
    progress.hidden = phase !== 'sending' || !upgrade?.total_bytes;
    progress.value = upgrade?.total_bytes
      ? Math.min(100, Math.round(100 * upgrade.sent_bytes / upgrade.total_bytes)) : 0;
  }
  if (!document.getElementById('upgrade-dialog')?.open) {
    const targetInput = document.getElementById('upgrade-target');
    if (targetInput) targetInput.value = target || '';
    const versionInput = document.getElementById('upgrade-version');
    if (versionInput) versionInput.value = replica?.version || '';
    setText('upgrade-dialog-detail', `将从机 ${replica?.version || '未知版本'} 更新为主机 ${sourceVersion}；有更新时自动重启。当前同步会在安全检查点中断，之后续传。`);
  }
}

async function refreshStatus() {
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    if (!response.ok) return null;
    const status = await response.json();
    setText('connection', connectionLabels[status.connection] || status.connection);
    setText('target-address', status.target || '未设置');
    setText('pairing-state', status.peer_configured ? '已配对' : '未配对');
    const syncAction = document.getElementById('sync-action');
    if (syncAction) syncAction.value = status.first_sync_confirmed ? 'sync' : 'confirm';
    setText('sync-button', status.first_sync_confirmed ? '立即同步' : '确认并开始首次同步');
    setText('paused-flag', status.paused ? '已暂停' : '运行中');
    for (const key of ['pending_files', 'last_files', 'last_scan_hashed', 'last_scan_cached', 'last_scan_workers']) {
      setText(key, status[key]);
    }
    setText('transfer_bps', `${humanBytes(status.transfer_bps)}/s`);
    setText('last_success', localTime(status.last_success));
    const pauseAction = document.getElementById('pause-action');
    if (pauseAction) pauseAction.value = status.paused ? 'resume' : 'pause';
    setText('pause-button', status.paused ? '恢复自动同步' : '暂停自动同步');
    const connected = ['idle', 'connected', 'syncing', 'upgrade_required'].includes(status.connection);
    document.getElementById('connection-indicator')?.classList.toggle('offline', !connected);
    if (!status.last_error) {
      lastShownSyncError = '';
    } else if (status.last_error !== lastShownSyncError && toast?.hidden) {
      showToast(`同步异常：${status.last_error}`, true);
      lastShownSyncError = status.last_error;
    }
    updateReplica(status.replica);
    updateUpgrade(status.upgrade, status.replica, status.target, status.source_version);
    return status;
  } catch (_) {
    // A later poll will pick up a restarted web listener.
    return null;
  }
}

function openHashSection() {
  const section = document.getElementById(location.hash.slice(1));
  if (section?.matches('details.peer-details')) section.open = true;
}

const toast = document.getElementById('toast');
let toastTimer;

function showToast(message, error = false) {
  if (!toast) return;
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.classList.toggle('is-error', error);
  toast.setAttribute('role', error ? 'alert' : 'status');
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3500);
}

if (toast && !toast.hidden && toast.textContent.trim()) showToast(toast.textContent.trim());
const pageUrl = new URL(location.href);
if (pageUrl.searchParams.has('saved')) {
  pageUrl.searchParams.delete('saved');
  history.replaceState(history.state, '', `${pageUrl.pathname}${pageUrl.search}${pageUrl.hash}`);
}

async function submitSettingForm(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || form.getAttribute('method')?.toLowerCase() !== 'post') return;
  event.preventDefault();
  const endpoint = form.getAttribute('action');
  if (!endpoint) {
    showToast('页面表单缺少提交地址。', true);
    return;
  }
  const historyForm = form.id === 'replica-history-form';
  const scrollPosition = window.scrollY;
  const submitter = event.submitter;
  const body = new URLSearchParams(new FormData(form));
  if (submitter?.name) body.append(submitter.name, submitter.value);
  if (submitter) {
    submitter.disabled = true;
    submitter.dataset.pending = 'true';
  }
  clearTimeout(toastTimer);
  if (toast) toast.hidden = true;
  try {
    const response = await fetch(endpoint, {
      method: 'POST', body, credentials: 'same-origin', cache: 'no-store',
    });
    if (response.ok) {
      const returnedPage = new DOMParser().parseFromString(await response.text(), 'text/html');
      const savedNotice = returnedPage.getElementById('toast');
      if (!savedNotice) {
        showToast('操作结果无法确认，请刷新页面查看。', true);
        return;
      }
      if (endpoint === '/api/excludes') {
        const currentRules = document.getElementById('settings-exclusions');
        const updatedRules = returnedPage.getElementById('settings-exclusions');
        if (!currentRules || !updatedRules) {
          showToast('排除规则已保存，请刷新页面查看。', true);
          return;
        }
        currentRules.replaceWith(updatedRules);
        updatedRules.querySelectorAll('form[method="post"]').forEach(bindForm);
        window.scrollTo(0, scrollPosition);
      }
      if (endpoint === '/api/source-peer') form.reset();
      if (endpoint === '/api/replica-upgrade') document.getElementById('upgrade-dialog')?.close();
      if (endpoint === '/api/replica-settings' || historyForm) {
        document.querySelectorAll('#settings-replica input[type="number"]').forEach(input => {
          delete input.dataset.dirty;
        });
      }
      await refreshStatus();
      const message = historyForm
        ? (body.get('enabled') === 'true' ? '历史备份已开启' : '历史备份已关闭')
        : savedNotice.textContent.trim();
      showToast(message);
      return;
    }
    const detail = (await response.text()).trim();
    const message = detail && !detail.startsWith('<') ? detail : `操作失败（HTTP ${response.status}）。`;
    showToast(message, true);
  } catch (_) {
    showToast('连接中断，请稍后重试。', true);
  } finally {
    if (endpoint === '/api/replica-upgrade') document.getElementById('upgrade-dialog')?.close();
    if (submitter) {
      delete submitter.dataset.pending;
      submitter.disabled = false;
    }
  }
}

function bindForm(form) {
  form.addEventListener('submit', submitSettingForm);
}
document.querySelectorAll('form[method="post"]').forEach(bindForm);
document.getElementById('upgrade-open')?.addEventListener('click', () => {
  document.getElementById('upgrade-dialog')?.showModal();
});
document.getElementById('upgrade-cancel')?.addEventListener('click', () => {
  document.getElementById('upgrade-dialog')?.close();
});
for (const input of document.querySelectorAll('.settings-form input[type="number"]')) {
  input.addEventListener('input', () => { input.dataset.dirty = 'true'; });
}
addEventListener('hashchange', openHashSection);
openHashSection();
refreshStatus();
setInterval(refreshStatus, 1000);
