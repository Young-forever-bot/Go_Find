// Young@Asset Collection 渲染进程逻辑：任务下发 + SSE 实时渲染。
/* eslint-disable no-console */
'use strict';

// ---------- API 地址 ----------
// file:// 协议（Electron）用 preload 暴露的地址；由后端托管时用同源。
const API = (location.protocol === 'file:')
  ? ((window.gofind && window.gofind.apiBase) || 'http://127.0.0.1:18525')
  : '';

const $ = (id) => document.getElementById(id);

// ---------- 页面切换 ----------
const PAGE_TITLES = { pipeline: '全面测绘', subdomain: '子域名收集', portscan: '端口开放探测', service: '端口服务识别', whois: 'WHOIS / 备案查询', tasks: '任务中心' };
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $('page-' + btn.dataset.page).classList.add('active');
    $('page-title').textContent = PAGE_TITLES[btn.dataset.page];
    if (btn.dataset.page === 'tasks') refreshTaskList();
    if (btn.dataset.page === 'service') loadPortscanTaskOptions();
  });
});

// ---------- 健康检查 ----------
async function pollHealth() {
  const dot = $('health-dot'), text = $('health-text');
  try {
    const res = await fetch(API + '/api/health', { signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    dot.className = 'dot ok';
    text.textContent = '后端在线 v' + data.version;
    $('backend-version').textContent = 'Backend v' + data.version;
  } catch {
    dot.className = 'dot bad';
    text.textContent = '后端离线';
  }
}
setInterval(pollHealth, 5000);
pollHealth();

// ---------- 通用任务运行器 ----------
// 每个功能页独立任务状态；done 后允许再次提交。
const pageState = {
  pipeline:  { taskId: null, es: null, running: false },
  subdomain: { taskId: null, es: null, running: false },
  portscan:  { taskId: null, es: null, running: false },
  service:   { taskId: null, es: null, running: false },
  whois:     { taskId: null, es: null, running: false },
};

const PAGE_PREFIX = { pipeline: 'pl', subdomain: 'sub', portscan: 'ps', service: 'sv', whois: 'wi' };
const PAGE_START_LABEL = { pipeline: '🚀 开始测绘', subdomain: '开始收集', portscan: '开始扫描', service: '开始识别', whois: '开始查询' };

function setRunning(page, running) {
  pageState[page].running = running;
  const prefix = PAGE_PREFIX[page];
  $(prefix + '-start').disabled = running;
  $(prefix + '-start').textContent = running ? '任务进行中…' : PAGE_START_LABEL[page];
  $(prefix + '-cancel').classList.toggle('hidden', !running);
}

function resetPageUI(page, prefix) {
  $(prefix + '-results').innerHTML = '';
  $(prefix + '-count').textContent = '0';
  $(prefix + '-progress').style.width = '0';
  $(prefix + '-progress-text').textContent = '';
  const logs = $(prefix + '-logs');
  logs.innerHTML = '';
  logs.classList.remove('show');
  ['export-csv', 'export-json'].forEach(k => {
    const a = $(prefix + '-' + k);
    a.removeAttribute('href');
    a.classList.add('hidden');
  });
}

function appendLog(prefix, log) {
  const box = $(prefix + '-logs');
  box.classList.add('show');
  const line = document.createElement('div');
  if (log.level && log.level !== 'info') line.className = 'log-' + log.level;
  const t = new Date(log.time).toLocaleTimeString();
  line.textContent = `[${t}] ${log.level === 'info' ? '' : '[' + log.level + '] '}${log.msg}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function setProgress(prefix, p) {
  const pct = p.total > 0 ? Math.min(100, Math.round(p.done / p.total * 100)) : 0;
  $(prefix + '-progress').style.width = pct + '%';
  $(prefix + '-progress-text').textContent = `${p.done}/${p.total} (${pct}%)`;
}

function enableExport(prefix, taskId) {
  $(prefix + '-export-csv').href = `${API}/api/tasks/${taskId}/export?format=csv`;
  $(prefix + '-export-json').href = `${API}/api/tasks/${taskId}/export?format=json`;
  $(prefix + '-export-csv').classList.remove('hidden');
  $(prefix + '-export-json').classList.remove('hidden');
}

function showError(prefix, msg) {
  appendLog(prefix, { time: new Date().toISOString(), level: 'error', msg });
}

/**
 * 启动任务并订阅 SSE。
 * @param page  页面 key（pageState / 前缀映射用）
 * @param endpoint API 端点名
 * @param body 请求体
 * @param renderRow (data) => HTMLElement[]
 */
async function startTask(page, endpoint, body, renderRow) {
  const prefix = PAGE_PREFIX[page];
  resetPageUI(page, prefix);
  setRunning(page, true);
  try {
    const res = await fetch(`${API}/api/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const taskId = data.task_id;
    pageState[page].taskId = taskId;
    enableExport(prefix, taskId);

    const es = new EventSource(`${API}/api/tasks/${taskId}/events`);
    pageState[page].es = es;
    es.onmessage = (e) => {
      const ev = JSON.parse(e.data);
      if (ev.type === 'snapshot') {
        (ev.data.logs || []).forEach(l => appendLog(prefix, l));
        (ev.data.results || []).forEach(r => addRow(prefix, renderRow(r)));
        setProgress(prefix, ev.data.progress || { done: 0, total: 0 });
      } else if (ev.type === 'log') {
        appendLog(prefix, ev.data);
      } else if (ev.type === 'progress') {
        setProgress(prefix, ev.data);
      } else if (ev.type === 'result') {
        addRow(prefix, renderRow(ev.data));
      } else if (ev.type === 'done') {
        es.close();
        pageState[page].es = null;
        setRunning(page, false);
        if (ev.data.status === 'error') showError(prefix, '任务失败: ' + (ev.data.error || '未知错误'));
      }
    };
    es.onerror = () => {
      // 连接断开：任务已终态时 EventSource 自动重连会 404，直接关闭
      if (!pageState[page].running) { es.close(); return; }
    };
  } catch (err) {
    showError(prefix, err.message);
    setRunning(page, false);
  }
}

function addRow(prefix, cells) {
  const tbody = $(prefix + '-results');
  const tr = document.createElement('tr');
  cells.forEach(c => {
    const td = document.createElement('td');
    if (typeof c === 'string') { td.textContent = c; }
    else if (c instanceof HTMLElement) { td.appendChild(c); }
    else { td.textContent = String(c ?? ''); }
    if (td.children.length === 0) td.classList.add('mono');
    tr.appendChild(td);
  });
  tbody.prepend(tr);
  const count = $(prefix + '-count');
  count.textContent = String(Number(count.textContent) + 1);
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text) e.textContent = text;
  return e;
}

// ---------- 子域名收集页 ----------
$('sub-start').addEventListener('click', () => {
  const domain = $('sub-domain').value.trim();
  if (!domain) { alert('请输入主域名'); return; }
  const methods = [];
  if ($('sub-m-brute').checked) methods.push('brute');
  if ($('sub-m-crtsh').checked) methods.push('crtsh');
  if ($('sub-m-ht').checked) methods.push('hackertarget');
  const wordlist = $('sub-wordlist').value.split('\n').map(s => s.trim()).filter(Boolean);
  startTask('subdomain', 'subdomain', {
    domain,
    methods,
    concurrency: Number($('sub-concurrency').value) || 50,
    dns: $('sub-dns').value.trim(),
    timeout_ms: Number($('sub-timeout').value) || 3000,
    wordlist,
  }, (r) => [r.subdomain, (r.ips || []).join(', '), r.source]);
});

$('sub-cancel').addEventListener('click', () => cancelTask('subdomain'));

// ---------- 端口开放探测页 ----------
$('ps-preset').addEventListener('change', () => {
  const custom = $('ps-preset').value === 'custom';
  $('ps-ports').disabled = !custom;
  if (custom) $('ps-ports').focus();
});

$('ps-start').addEventListener('click', () => {
  const targets = $('ps-targets').value.trim();
  if (!targets) { alert('请输入扫描目标'); return; }
  const preset = $('ps-preset').value;
  const ports = preset === 'custom' ? $('ps-ports').value.trim() : preset;
  startTask('portscan', 'portscan', {
    targets,
    ports,
    timeout_ms: Number($('ps-timeout').value) || 1000,
    workers: Number($('ps-workers').value) || 500,
  }, (r) => {
    const st = el('span', 'status-open', r.status);
    const detect = el('a', 'btn small', '识别服务');
    detect.href = '#';
    detect.addEventListener('click', (e) => {
      e.preventDefault();
      const host = r.ip || r.host;
      document.querySelector('[data-page="service"]').click();
      $('sv-targets').value = `${host}:${r.port}`;
    });
    return [r.host, r.ip, String(r.port), st, detect];
  });
});

$('ps-cancel').addEventListener('click', () => cancelTask('portscan'));

// ---------- 端口服务识别页 ----------
$('sv-start').addEventListener('click', () => {
  const targets = $('sv-targets').value.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  if (!targets.length) { alert('请输入 host:port 目标'); return; }
  startTask('service', 'service', {
    targets,
    timeout_ms: Number($('sv-timeout').value) || 5000,
    workers: Number($('sv-workers').value) || 50,
  }, (r) => {
    const httpPart = r.http
      ? `${r.http.status_code || ''} ${r.http.title || ''} ${r.http.server ? '| ' + r.http.server : ''}`.trim()
      : '';
    const banner = r.banner || (r.tls ? `TLS: ${r.tls.issuer || ''} ${r.tls.subject || ''}`.trim() : '');
    return [r.host, r.ip || '', String(r.port), r.service, r.version || '', httpPart, banner];
  });
});

$('sv-cancel').addEventListener('click', () => cancelTask('service'));

// ---------- WHOIS / 备案查询页 ----------
$('wi-start').addEventListener('click', () => {
  const domains = $('wi-domains').value.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  if (!domains.length) { alert('请输入查询域名'); return; }
  startTask('whois', 'whois', {
    domains,
    whois: $('wi-do-whois').checked,
    icp: $('wi-do-icp').checked,
    timeout_ms: Number($('wi-timeout').value) || 10000,
    icp_api: $('wi-icp-api').value.trim(),
  }, (r) => {
    const registrar = r.registrar || (r.whois_error ? `查询失败: ${r.whois_error}` : '—');
    const created = r.creation_date || '';
    const expiry = r.expiry_date || '';
    const ns = (r.name_servers || []).join(', ');
    const icpName = r.icp && r.icp.name ? r.icp.name : '';
    const icpNo = r.icp && r.icp.icp ? r.icp.icp : '';
    const errs = [];
    if (r.icp_error) errs.push('备案: ' + r.icp_error);
    return [r.domain, registrar, created, expiry, ns, icpName, icpNo, errs.join('；')];
  });
});

$('wi-cancel').addEventListener('click', () => cancelTask('whois'));

async function loadPortscanTaskOptions() {
  try {
    const res = await fetch(API + '/api/tasks');
    const tasks = await res.json();
    const sel = $('sv-import');
    sel.innerHTML = '<option value="">— 选择已完成的端口扫描任务 —</option>';
    tasks.filter(t => t.type === 'portscan' && t.status === 'done' && t.results.length > 0)
      .forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.id;
        opt.textContent = `${t.id}  (${t.results.length} 个开放端口, ${new Date(t.created_at).toLocaleString()})`;
        sel.appendChild(opt);
      });
  } catch { /* 后端离线时忽略 */ }
}

$('sv-import-btn').addEventListener('click', async () => {
  const id = $('sv-import').value;
  if (!id) { alert('请先选择端口扫描任务'); return; }
  try {
    const res = await fetch(`${API}/api/tasks/${id}`);
    const t = await res.json();
    const targets = t.results.map(r => `${r.ip || r.host}:${r.port}`);
    $('sv-targets').value = targets.join('\n');
    appendLog('sv', { time: new Date().toISOString(), level: 'info', msg: `已导入 ${targets.length} 个目标` });
  } catch (err) {
    appendLog('sv', { time: new Date().toISOString(), level: 'error', msg: '导入失败: ' + err.message });
  }
});

// ---------- 任务取消 ----------
async function cancelTask(page) {
  const st = pageState[page];
  if (!st.taskId) return;
  if (st.es) { st.es.close(); st.es = null; }
  try {
    await fetch(`${API}/api/tasks/${st.taskId}`, { method: 'DELETE' });
  } catch { /* ignore */ }
  setRunning(page, false);
  appendLog(PAGE_PREFIX[page],
    { time: new Date().toISOString(), level: 'warn', msg: '任务已请求取消' });
}

// ---------- 任务中心 ----------
const TASK_TYPE_NAMES = { pipeline: '全面测绘', subdomain: '子域名', portscan: '端口扫描', service: '服务识别', whois: 'WHOIS/备案' };
const DETAIL_COLUMNS = {
  subdomain: ['子域名', 'IP', '来源'],
  portscan: ['主机', 'IP', '端口', '状态'],
  service: ['主机', 'IP', '端口', '服务', '版本', '标题', 'Banner'],
  whois: ['域名', '注册商', '创建时间', '到期时间', 'DNS', '备案主体', '备案号'],
  pipeline: ['阶段', '摘要'],
};

async function refreshTaskList() {
  try {
    const res = await fetch(API + '/api/tasks');
    const tasks = await res.json();
    const tbody = $('tk-list');
    tbody.innerHTML = '';
    if (!tasks.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="7" class="empty-tip">暂无任务，去左侧功能页创建一个吧</td>';
      tbody.appendChild(tr);
      return;
    }
    tasks.forEach(t => {
      const tr = document.createElement('tr');
      const pct = t.progress.total > 0 ? Math.round(t.progress.done / t.progress.total * 100) : 0;
      const view = el('a', 'btn small', '查看');
      view.href = '#';
      view.addEventListener('click', (e) => { e.preventDefault(); showTaskDetail(t.id); });
      const tds = [
        el('span', 'mono', t.id),
        el('span', 'tag type-' + t.type, TASK_TYPE_NAMES[t.type] || t.type),
        el('span', 'tag st-' + t.status, t.status),
        el('span', 'mono', `${t.progress.done}/${t.progress.total} (${pct}%)`),
        el('span', 'mono', String(t.results.length)),
        el('span', 'mono', new Date(t.created_at).toLocaleString()),
        view,
      ];
      tds.forEach(c => { const td = el('td'); td.appendChild(c); tr.appendChild(td); });
      tbody.appendChild(tr);
    });
  } catch {
    /* ignore */
  }
}
$('tk-refresh').addEventListener('click', refreshTaskList);
setInterval(() => { if ($('page-tasks').classList.contains('active')) refreshTaskList(); }, 5000);

async function showTaskDetail(id) {
  try {
    const res = await fetch(`${API}/api/tasks/${id}`);
    const t = await res.json();
    $('tk-detail-card').classList.remove('hidden');
    $('tk-detail-id').textContent = `${t.id} (${TASK_TYPE_NAMES[t.type] || t.type} · ${t.status})`;
    $('tk-export-csv').href = `${API}/api/tasks/${id}/export?format=csv`;
    $('tk-export-json').href = `${API}/api/tasks/${id}/export?format=json`;
    $('tk-export-csv').classList.remove('hidden');
    $('tk-export-json').classList.remove('hidden');

    const head = $('tk-detail-head');
    head.innerHTML = '';
    const htr = document.createElement('tr');
    (DETAIL_COLUMNS[t.type] || []).forEach(c => { const th = el('th', '', c); htr.appendChild(th); });
    head.appendChild(htr);

    const body = $('tk-detail-body');
    body.innerHTML = '';
    (t.results || []).forEach(r => {
      const tr = document.createElement('tr');
      let cells;
      if (t.type === 'pipeline') {
        const stageTag = el('span', 'tag type-service', r.stage || 'result');
        const summary = el('span', '', describePipelineResult(r));
        const td1 = el('td'); td1.appendChild(stageTag);
        const td2 = el('td', 'mono wrap'); td2.appendChild(summary);
        tr.appendChild(td1); tr.appendChild(td2);
        body.appendChild(tr);
        return;
      }
      if (t.type === 'subdomain') cells = [r.subdomain, (r.ips || []).join(', '), r.source];
      else if (t.type === 'portscan') cells = [r.host, r.ip, String(r.port), r.status];
      else if (t.type === 'whois') cells = [r.domain, r.registrar || r.whois_error || '', r.creation_date || '',
        r.expiry_date || '', (r.name_servers || []).join(', '),
        r.icp && r.icp.name ? r.icp.name : '', r.icp && r.icp.icp ? r.icp.icp : ''];
      else cells = [r.host, r.ip || '', String(r.port), r.service, r.version || '',
        r.http ? (r.http.title || r.http.server || '') : '', r.banner || ''];
      cells.forEach(c => {
        const td = el('td', 'mono');
        td.textContent = c ?? '';
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });

    const logs = $('tk-detail-logs');
    logs.innerHTML = '';
    logs.classList.toggle('show', (t.logs || []).length > 0);
    (t.logs || []).forEach(l => {
      const line = document.createElement('div');
      if (l.level && l.level !== 'info') line.className = 'log-' + l.level;
      line.textContent = `[${new Date(l.time).toLocaleTimeString()}] ${l.msg}`;
      logs.appendChild(line);
    });
  } catch (err) {
    alert('加载任务详情失败: ' + err.message);
  }
}

// ---------- 通用：结果表格过滤 ----------
function attachFilter(inputId, wrapIds) {
  const input = $(inputId);
  if (!input) return;
  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    wrapIds.forEach(wid => {
      const wrap = $(wid);
      if (!wrap) return;
      wrap.querySelectorAll('tbody tr').forEach(tr => {
        tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
      });
    });
  });
}
attachFilter('sub-filter', ['sub-results']);
attachFilter('ps-filter', ['ps-results']);
attachFilter('sv-filter', ['sv-results']);
attachFilter('wi-filter', ['wi-results']);
attachFilter('tk-filter', ['tk-detail-body']);
attachFilter('pl-filter', ['pl-t-sub', 'pl-t-probe', 'pl-t-port', 'pl-t-svc', 'pl-t-whois']);

// ---------- 全面测绘（流水线） ----------
const PL_STAGES = ['subdomain', 'probe', 'portscan', 'service', 'whois'];
const PL_STAGE_NAMES = { subdomain: '子域名收集', probe: '存活探测', portscan: '端口扫描', service: '服务识别', whois: 'WHOIS/备案' };
const PL_STAGE_ICONS = { subdomain: '🌐', probe: '💚', portscan: '🔌', service: '🛰️', whois: '📇' };
let plStageState = {};   // key -> {status, note}
let plCurProgress = { done: 0, total: 0 };

function renderStages() {
  const box = $('pl-stages');
  box.innerHTML = '';
  PL_STAGES.forEach(key => {
    const st = plStageState[key] || { status: 'pending', note: '' };
    const row = document.createElement('div');
    row.className = 'stage-row';
    const ico = document.createElement('span');
    ico.className = 'stage-ico';
    ico.textContent = PL_STAGE_ICONS[key] || '•';
    const name = document.createElement('span');
    name.className = 'stage-name';
    name.textContent = PL_STAGE_NAMES[key];
    const tag = document.createElement('span');
    tag.className = 'tag stage-' + st.status;
    tag.textContent = { pending: '待执行', running: '进行中', ok: '完成', fail: '失败', skip: '跳过' }[st.status] || st.status;
    row.appendChild(ico); row.appendChild(name); row.appendChild(tag);
    if (st.note) {
      const note = document.createElement('span');
      note.className = 'stage-note mono';
      note.textContent = st.note;
      row.appendChild(note);
    }
    if (st.status === 'running' && plCurProgress.total > 0) {
      const prog = document.createElement('span');
      prog.className = 'stage-note mono grow';
      prog.style.textAlign = 'right';
      prog.textContent = `${plCurProgress.done}/${plCurProgress.total}`;
      row.appendChild(prog);
    } else {
      const pad = document.createElement('span');
      pad.className = 'grow';
      row.appendChild(pad);
    }
    box.appendChild(row);
  });
  // 总进度 = 完成阶段比例 + 当前阶段内部进度
  const doneStages = PL_STAGES.filter(k => ['ok', 'skip', 'fail'].includes((plStageState[k] || {}).status)).length;
  const curIdx = PL_STAGES.findIndex(k => (plStageState[k] || {}).status === 'running');
  let pct = doneStages / PL_STAGES.length * 100;
  if (curIdx >= 0 && plCurProgress.total > 0) {
    pct += (plCurProgress.done / plCurProgress.total) / PL_STAGES.length * 100;
  }
  $('pl-progress').style.width = Math.min(100, pct) + '%';
  $('pl-progress-text').textContent = Math.round(pct) + '%';
}

function resetPipelineUI() {
  plStageState = {};
  plCurProgress = { done: 0, total: 0 };
  renderStages();
  ['pl-t-sub', 'pl-t-probe', 'pl-t-port', 'pl-t-svc', 'pl-t-whois'].forEach(id => { $(id).innerHTML = ''; });
  ['pl-c-sub', 'pl-c-probe', 'pl-c-port', 'pl-c-svc'].forEach(id => { $(id).textContent = '0'; });
  ['pl-s-sub', 'pl-s-alive', 'pl-s-port', 'pl-s-svc', 'pl-s-icp', 'pl-s-time'].forEach(id => { $(id).textContent = '—'; });
  $('pl-notes').textContent = '';
  $('pl-duration').textContent = '';
  $('pl-progress').style.width = '0';
  $('pl-progress-text').textContent = '';
  const logs = $('pl-logs');
  logs.innerHTML = '';
  logs.classList.remove('show');
  ['pl-export-csv', 'pl-export-json'].forEach(id => { $(id).removeAttribute('href'); $(id).classList.add('hidden'); });
}

function appendCell(tr, c) {
  const td = document.createElement('td');
  if (typeof c === 'string') td.textContent = c;
  else if (c instanceof HTMLElement) td.appendChild(c);
  else td.textContent = String(c ?? '');
  tr.appendChild(td);
}

function bump(id) {
  const n = $(id);
  n.textContent = String(Number(n.textContent) + 1);
}

// 按数据形态把流水线结果路由到对应标签表
function routePipelineResult(r) {
  if (r.stage === 'summary' || (r.duration && r.subdomains !== undefined)) {
    $('pl-s-sub').textContent = r.subdomains ?? '—';
    $('pl-s-alive').textContent = r.alive ?? '—';
    $('pl-s-port').textContent = r.open_ports ?? '—';
    $('pl-s-svc').textContent = r.services ?? '—';
    $('pl-s-icp').textContent = r.icp || '未备案';
    $('pl-s-time').textContent = r.duration || '—';
    $('pl-notes').textContent = (r.notes || []).join('；');
    $('pl-duration').textContent = '耗时 ' + (r.duration || '');
    return;
  }
  const addRows = (tbodyId, cells) => {
    const tr = document.createElement('tr');
    cells.forEach(c => appendCell(tr, c));
    $(tbodyId).prepend(tr);
  };
  if (r.subdomain) {
    addRows('pl-t-sub', [r.subdomain, (r.ips || []).join(', '), r.source || '']);
    bump('pl-c-sub');
  } else if (r.url !== undefined || r.alive !== undefined) {
    const alive = r.alive ? el('span', 'status-open', String(r.status_code || 'ok')) : el('span', 'muted', '超时');
    addRows('pl-t-probe', [r.host, r.url || '—', alive, r.title || '', (r.fingerprints || []).join(' / '), r.length ? String(r.length) : '']);
    bump('pl-c-probe');
  } else if (r.port && r.status) {
    const st = el('span', 'status-open', r.status);
    addRows('pl-t-port', [r.host, r.ip || '', String(r.port), st]);
    bump('pl-c-port');
  } else if (r.service) {
    const httpPart = r.http ? `${r.http.status_code || ''} ${r.http.title || ''} ${r.http.server ? '| ' + r.http.server : ''}`.trim() : '';
    addRows('pl-t-svc', [r.host, r.ip || '', String(r.port), r.service, r.version || '', httpPart, r.banner || '']);
    bump('pl-c-svc');
  } else if (r.registrable || r.registrar || r.icp) {
    const icpName = r.icp && r.icp.name ? r.icp.name : '';
    const icpNo = r.icp && r.icp.icp ? r.icp.icp : '';
    const errs = [r.whois_error, r.icp_error].filter(Boolean).join('；');
    addRows('pl-t-whois', [r.domain, r.registrar || '—', r.creation_date || '', r.expiry_date || '', icpName, icpNo, errs]);
  }
}

// 标签页切换
document.querySelectorAll('#pl-tabs .tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#pl-tabs .tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('#page-pipeline .tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $(btn.dataset.tab).classList.add('active');
  });
});

$('pl-preset').addEventListener('change', () => {
  const custom = $('pl-preset').value === 'custom';
  $('pl-ports').disabled = !custom;
  if (custom) $('pl-ports').focus();
});

$('pl-start').addEventListener('click', async () => {
  const domain = $('pl-domain').value.trim();
  if (!domain) { alert('请输入主域名'); return; }
  resetPipelineUI();
  setRunning('pipeline', true);
  const methods = [];
  if ($('pl-m-brute').checked) methods.push('brute');
  if ($('pl-m-crtsh').checked) methods.push('crtsh');
  if ($('pl-m-ht').checked) methods.push('hackertarget');
  const preset = $('pl-preset').value;
  const ports = preset === 'custom' ? $('pl-ports').value.trim() : preset;
  const wordlist = $('pl-wordlist').value.split('\n').map(x => x.trim()).filter(Boolean);
  try {
    const res = await fetch(`${API}/api/pipeline`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain, methods, ports, wordlist,
        concurrency: Number($('pl-concurrency').value) || 50,
        workers: Number($('pl-workers').value) || 500,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    const taskId = data.task_id;
    pageState.pipeline.taskId = taskId;
    // 首个 stage 事件可能在 SSE 订阅前发出，这里乐观标记第一阶段进行中
    if (!plStageState.subdomain || plStageState.subdomain.status === 'pending') {
      plStageState.subdomain = { status: 'running', note: '' };
      renderStages();
    }
    $('pl-export-csv').href = `${API}/api/tasks/${taskId}/export?format=csv`;
    $('pl-export-json').href = `${API}/api/tasks/${taskId}/export?format=json`;
    $('pl-export-csv').classList.remove('hidden');
    $('pl-export-json').classList.remove('hidden');

    const es = new EventSource(`${API}/api/tasks/${taskId}/events`);
    pageState.pipeline.es = es;
    es.onmessage = (e) => {
      const ev = JSON.parse(e.data);
      if (ev.type === 'snapshot') {
        // 恢复：按快照结果逐条路由（stage 进度状态不可恢复，仅恢复结果）
        (ev.data.results || []).forEach(r => routePipelineResult(r));
        (ev.data.logs || []).forEach(l => appendLog('pl', l));
      } else if (ev.type === 'stage') {
        plStageState[ev.data.key] = { status: ev.data.status, note: ev.data.note || '' };
        plCurProgress = { done: 0, total: 0 };
        renderStages();
      } else if (ev.type === 'log') {
        appendLog('pl', ev.data);
      } else if (ev.type === 'progress') {
        plCurProgress = ev.data;
        renderStages();
      } else if (ev.type === 'result') {
        routePipelineResult(ev.data);
      } else if (ev.type === 'done') {
        es.close();
        pageState.pipeline.es = null;
        setRunning('pipeline', false);
        if (ev.data.status === 'error') appendLog('pl', { time: new Date().toISOString(), level: 'error', msg: '任务失败: ' + (ev.data.error || '') });
      }
    };
  } catch (err) {
    appendLog('pl', { time: new Date().toISOString(), level: 'error', msg: err.message });
    setRunning('pipeline', false);
  }
});

$('pl-cancel').addEventListener('click', () => cancelTask('pipeline'));

// 任务中心：pipeline 类型摘要行
function describePipelineResult(r) {
  if (r.stage === 'summary') return `汇总: 子域名 ${r.subdomains} · 存活 ${r.alive} · 端口 ${r.open_ports} · 服务 ${r.services} · 耗时 ${r.duration}`;
  if (r.subdomain) return `${r.subdomain}  [${(r.ips || []).join(', ')}]  来源:${r.source || ''}`;
  if (r.url !== undefined || r.alive !== undefined) return `${r.alive ? '存活' : '超时'} ${r.url || r.host}  ${r.title || ''} ${(r.fingerprints || []).join(',')}`;
  if (r.port && r.status) return `${r.host} (${r.ip}):${r.port} ${r.status}`;
  if (r.service) return `${r.host}:${r.port} ${r.service} ${r.version || ''} ${r.http && r.http.title ? '| ' + r.http.title : ''}`;
  if (r.registrable || r.registrar) return `${r.domain} 注册商:${r.registrar || '—'} 备案:${(r.icp && r.icp.icp) || r.icp_error || '—'}`;
  return JSON.stringify(r).slice(0, 120);
}
