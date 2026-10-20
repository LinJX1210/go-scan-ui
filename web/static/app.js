'use strict';
(() => {
const $ = (id) => document.getElementById(id);
const PORT_PRESETS = {
  common: '', '1-1024': '1-1024', '1-65535': '1-65535',
  web: '80,81,443,591,2082,2083,3000,5000,7001,8000,8008,8080,8081,8088,8443,8888,9000,9090,9443',
  db: '1433,1521,3306,5432,5984,6379,7474,9042,9200,11211,27017,28017',
};
const state = { mode: 'native', jobId: null, es: null, rows: new Map(), hosts: new Map(), sortKey: 'host', sortAsc: true, running: false, demoTimer: null, resultMode: null };
let token = new URLSearchParams(location.search).get('token') || localStorage.getItem('goscan-token') || '';

async function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Content-Type': 'application/json', 'X-Token': token }, opts.headers || {});
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) {
    token = prompt('请输入访问令牌（启动参数 -token）') || '';
    localStorage.setItem('goscan-token', token);
    throw new Error('令牌无效，请重试');
  }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

// ---------- 环境信息 ----------
let toolSpecs = [
  ['arp-scan', 'ARP 主机发现'], ['gobuster', 'Gobuster 目录演示'],
  ['whatweb', 'WhatWeb 指纹演示'], ['wpscan', 'WPScan'],
  ['joomscan', 'JoomScan'], ['droopescan', 'Droopescan'], ['nikto', 'Nikto'],
].map(([id, name]) => ({ id, name, description: '固定模拟输出，不启动工具。', available: false }));
async function loadInfo() {
  try {
    const i = await api('/api/info');
    const nm = i.nmap.available ? `<span class="ok">nmap ✓</span> ${esc(i.nmap.version || '')}` : '<span class="bad">未检测到 nmap</span>';
    const root = i.root ? '<span class="ok">root ✓</span>' : '<span class="bad">非 root（SYN/UDP/OS 需 sudo）</span>';
    $('env').innerHTML = `${nm} · ${root} · ${esc(i.os)}/${esc(i.arch)}`;
    fillTools();
  } catch (e) { $('env').textContent = '环境检测失败：' + e.message; }
}
function fillTools() {
  const sel = $('t-tool');
  sel.innerHTML = toolSpecs.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
  updateToolDesc();
}
function updateToolDesc() {
  const t = toolSpecs.find((x) => x.id === $('t-tool').value);
  if (!t) return;
  $('t-desc').textContent = t.description;
  $('t-status').textContent = '离线演示 · 不检测或执行工具，无需安装';
  $('t-wl-box').classList.toggle('hidden', t.id !== 'gobuster');
}

// ---------- 模式切换 ----------
const MODE_FORMS = { native: 'form-native', nmap: 'form-nmap', dir: 'form-dir', tool: 'form-tool' };
document.querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === b));
  if (state.running) return;
  state.mode = b.dataset.mode;
  $('btn-start').textContent = isDemo() ? '播放演示' : '开始扫描';
  $('preview-label').textContent = isDemo() ? '演示参数（不执行命令）' : '将执行的命令';
  Object.entries(MODE_FORMS).forEach(([m, id]) => $(id).classList.toggle('hidden', m !== state.mode));
  // dir / tool 模式有各自的目标输入，隐藏共享的目标框
  document.querySelector('.field').classList.toggle('hidden', state.mode === 'dir' || state.mode === 'tool');
  preview();
}));
$('t-tool').addEventListener('change', () => { updateToolDesc(); preview(); });
$('d-wordlist-mode').addEventListener('change', () => {
  $('d-wordlist').classList.toggle('hidden', $('d-wordlist-mode').value !== 'custom');
});
document.querySelectorAll('.stab').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.stab').forEach((x) => x.classList.toggle('active', x === b));
  ['table', 'hosts', 'log'].forEach((v) => $('view-' + v).classList.toggle('hidden', v !== b.dataset.view));
}));

// ---------- 原生参数 ----------
$('n-port-preset').addEventListener('change', () => {
  const v = $('n-port-preset').value;
  if (v !== 'custom') $('n-ports').value = PORT_PRESETS[v];
  $('n-ports').focus(); preview();
});
function nativeOptions() {
  return {
    targets: $('targets').value, ports: $('n-ports').value.trim(),
    timeoutMs: +$('n-timeout').value || 800, concurrency: +$('n-conc').value || 200,
    discovery: $('n-discovery').checked, banner: $('n-banner').checked, showClosed: $('n-closed').checked,
  };
}

// ---------- Nmap 参数 ----------
$('m-port-mode').addEventListener('change', () => {
  const m = $('m-port-mode').value;
  $('m-top').classList.toggle('hidden', m !== 'top');
  $('m-ports').classList.toggle('hidden', m !== 'list');
});
function nmapOptions() {
  const pm = $('m-port-mode').value;
  const scripts = [...document.querySelectorAll('#m-scripts input:checked')].map((x) => x.value)
    .concat($('m-script-custom').value.split(',').map((s) => s.trim()).filter(Boolean));
  const num = (id, def) => { const v = $(id).value.trim(); return v === '' ? def : +v; };
  return {
    targets: $('targets').value, scanType: $('m-type').value, alsoUdp: $('m-udp').checked,
    ports: pm === 'list' ? $('m-ports').value : '', topPorts: pm === 'top' ? +$('m-top').value : 0,
    allPorts: pm === 'all', fast: pm === 'fast',
    noPing: $('m-pn').checked, noDns: $('m-n').checked,
    version: $('m-sv').checked, versionIntensity: +$('m-vi').value, os: $('m-os').checked,
    aggressive: $('m-a').checked, traceroute: $('m-tr').checked,
    defaultScripts: $('m-sc').checked, scripts, scriptArgs: $('m-script-args').value,
    timing: +$('m-timing').value, minRate: num('m-minrate', 0), maxRetries: num('m-retries', -1),
    hostTimeout: $('m-htimeout').value, openOnly: $('m-open').checked, reason: $('m-reason').checked,
    verbose: $('m-v').checked, fragment: $('m-f').checked, ipv6: $('m-6').checked, extra: $('m-extra').value,
  };
}
const PRESETS = {
  quick: { 'm-type': 'sT', 'm-port-mode': 'fast', 'm-timing': '4', 'm-open': true },
  discover: { 'm-type': 'sn', 'm-port-mode': 'default', 'm-timing': '4' },
  service: { 'm-type': 'sS', 'm-port-mode': 'default', 'm-sv': true, 'm-sc': true, 'm-timing': '4', 'm-open': true },
  full: { 'm-type': 'sS', 'm-port-mode': 'all', 'm-a': true, 'm-pn': true, 'm-timing': '4', 'm-open': true },
  vuln: { 'm-type': 'sS', 'm-port-mode': 'default', 'm-sv': true, 'm-timing': '4', 'm-open': true, scripts: ['vuln'] },
};
document.querySelectorAll('[data-preset]').forEach((b) => b.addEventListener('click', () => {
  $('form-nmap').reset();
  const p = PRESETS[b.dataset.preset];
  document.querySelectorAll('#m-scripts input').forEach((x) => { x.checked = (p.scripts || []).includes(x.value); });
  Object.entries(p).forEach(([id, v]) => {
    if (id === 'scripts') return;
    const el = $(id); if (typeof v === 'boolean') el.checked = v; else el.value = v;
  });
  $('m-port-mode').dispatchEvent(new Event('change'));
  preview();
}));

// ---------- 目录爆破参数 ----------
function dirOptions() {
  return {
    baseUrl: $('d-url').value.trim(),
    wordlist: $('d-wordlist-mode').value === 'custom' ? $('d-wordlist').value : '',
    extensions: $('d-ext').value.trim(),
    threads: +$('d-threads').value || 20,
    timeoutMs: +$('d-timeout').value || 8000,
    statusCodes: $('d-codes').value.split(',').map((s) => +s.trim()).filter((n) => n > 0),
    followRedir: $('d-redir').checked,
  };
}

// ---------- Kali 工具参数 ----------
function toolOptions() {
  return {
    tool: $('t-tool').value, target: $('t-target').value.trim(),
    wordlist: $('t-wordlist').value.trim(), extra: $('t-extra').value.trim(),
  };
}

// ---------- 命令预览 ----------
let previewTimer;
let previewVersion = 0;
function preview() {
  const version = ++previewVersion;
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    const el = $('cmd-preview');
    el.classList.remove('err');
    if (isDemo()) {
      const o = state.mode === 'dir' ? dirOptions() : toolOptions();
      el.textContent = '[离线演示 · 固定模拟数据 · 不发送目标请求]\n' + JSON.stringify(o, null, 2);
      return;
    }
    if (state.mode === 'native') {
      const o = nativeOptions();
      el.textContent = `[原生 TCP Connect] 端口=${o.ports || '常用端口'} 超时=${o.timeoutMs}ms 并发=${o.concurrency}` +
        (o.discovery ? ' +存活探测' : '') + (o.banner ? ' +Banner' : '');
      return;
    }
    if (!$('targets').value.trim()) { el.textContent = '请先输入目标'; return; }
    try {
      const r = await api('/api/nmap/preview', { method: 'POST', body: JSON.stringify(nmapOptions()) });
      if (version !== previewVersion) return;
      if (r.error) { el.textContent = r.error; el.classList.add('err'); return; }
      el.textContent = (r.requiresRoot ? 'sudo ' : '') + r.command;
    } catch (e) { if (version === previewVersion) { el.textContent = e.message; el.classList.add('err'); } }
  }, 200);
}
document.querySelectorAll('input,select,textarea').forEach((el) => {
  el.addEventListener('input', preview); el.addEventListener('change', preview);
});
$('copy-cmd').addEventListener('click', () => navigator.clipboard && navigator.clipboard.writeText($('cmd-preview').textContent));

// ---------- 离线演示（不调用扫描或工具接口） ----------
function isDemo() { return state.mode === 'dir' || state.mode === 'tool'; }
function runDemo() {
  resetResults();
  state.resultMode = state.mode;
  state.jobId = null;
  if (state.es) { state.es.close(); state.es = null; }
  $('result-note').classList.remove('hidden');
  setRunning(true, '演示中');
  const name = state.mode === 'dir' ? '目录界面' : ($('t-tool').selectedOptions[0]?.textContent || '工具界面');
  const lines = state.mode === 'dir'
    ? ['示例路径 /docs → HTTP 200（模拟）', '示例路径 /missing → HTTP 404（模拟）', '示例重定向 /welcome → /docs（未发起请求）']
    : [`工具选择：${name}（未启动进程）`, '示例指纹：DemoCMS 1.0（虚构，不是识别结果）', '示例诊断：仅用于验证日志、筛选和导出界面'];
  appendLog('[模拟数据] 离线演示开始；不会连接输入地址，也不会运行外部工具。');
  let step = 0;
  state.demoTimer = setInterval(() => {
    appendLog('[模拟数据] ' + lines[step]);
    if (step === 0) addPort({ host: '127.0.0.1', port: 8080, proto: 'demo', state: 'simulated', service: 'demo-http', product: '虚构服务', version: '1.0', banner: '模拟数据，未经网络探测；不是开放端口结论' });
    step++;
    $('bar').style.width = (100 * step / lines.length).toFixed(1) + '%';
    if (step === lines.length) {
      clearInterval(state.demoTimer); state.demoTimer = null;
      appendLog('[模拟数据] 演示完成；以上不是实际扫描结果。');
      setRunning(false, '演示完成');
    }
  }, 450);
}

// ---------- 扫描 ----------
$('btn-start').addEventListener('click', async () => {
  if (state.running) return;
  if (isDemo()) { runDemo(); return; }
  if (!$('targets').value.trim()) { alert('请输入扫描目标'); return; }
  const body = { mode: state.mode };
  if (state.mode === 'native') body.native = nativeOptions(); else body.nmap = nmapOptions();
  resetResults();
  setRunning(true, '启动中');
  try {
    const { id } = await api('/api/scan', { method: 'POST', body: JSON.stringify(body) });
    state.jobId = id;
    listen(id);
  } catch (e) { appendLog('错误：' + e.message); setRunning(false, '失败'); }
});
$('btn-stop').addEventListener('click', async () => {
  if (state.demoTimer !== null) {
    clearInterval(state.demoTimer); state.demoTimer = null;
    appendLog('[模拟数据] 演示已停止。');
    setRunning(false, '演示已停止');
    return;
  }
  if (state.jobId) await api(`/api/scan/${state.jobId}/stop`, { method: 'POST' }).catch(() => {});
});

function listen(id) {
  if (state.es) state.es.close();
  const es = new EventSource(`/api/scan/${id}/events?token=${encodeURIComponent(token)}`);
  state.es = es;
  setRunning(true, '扫描中');
  es.onmessage = (m) => {
    const e = JSON.parse(m.data);
    switch (e.type) {
      case 'log': appendLog(e.message); break;
      case 'host': addHost(e.hostResult); break;
      case 'port': addPort(e.portResult); break;
      case 'progress': if (e.total) $('bar').style.width = (100 * e.done / e.total).toFixed(1) + '%'; break;
      case 'error': appendLog('✖ ' + e.message); $('st-status').textContent = e.message; break;
      case 'done':
        es.close(); state.es = null;
        setRunning(false, $('st-status').textContent === '扫描中' ? '完成' : $('st-status').textContent);
        $('bar').style.width = '100%';
        appendLog('— ' + e.message + ' —');
        break;
    }
  };
}

function setRunning(on, label) {
  state.running = on;
  document.querySelectorAll('.tab').forEach((b) => { b.disabled = on; });
  $('btn-start').disabled = on; $('btn-stop').disabled = !on;
  $('st-status').textContent = label;
}

function resetResults() {
  state.resultMode = state.mode;
  $('result-note').classList.add('hidden');
  state.rows.clear(); state.hosts.clear();
  $('log').textContent = ''; $('bar').style.width = '0';
  renderTable(); renderHosts();
}

// ---------- 结果 ----------
function addHost(h) {
  const old = state.hosts.get(h.address) || {};
  state.hosts.set(h.address, Object.assign(old, h, { ports: old.ports || [] }));
  scheduleRender();
}
function addPort(p) {
  state.rows.set(`${p.host}|${p.proto}|${p.port}`, p);
  const h = state.hosts.get(p.host) || { address: p.host, state: p.state === 'simulated' ? 'simulated' : 'up', ports: [] };
  if (p.state === 'open' && !h.ports.some((x) => x.port === p.port && x.proto === p.proto)) h.ports.push(p);
  state.hosts.set(p.host, h);
  scheduleRender();
}
let renderPending = false;
function scheduleRender() {
  if (renderPending) return;
  renderPending = true;
  requestAnimationFrame(() => { renderPending = false; renderTable(); renderHosts(); });
}

const ipKey = (s) => s.split('.').every((x) => /^\d+$/.test(x)) ? s.split('.').map((x) => x.padStart(3, '0')).join('.') : s;
function filteredRows() {
  const q = $('filter').value.trim().toLowerCase();
  let rows = [...state.rows.values()];
  if (q) rows = rows.filter((r) => [r.host, r.port, r.proto, r.state, r.service, r.product, r.version, r.banner].join(' ').toLowerCase().includes(q));
  const k = state.sortKey, dir = state.sortAsc ? 1 : -1;
  rows.sort((a, b) => {
    let x = a[k], y = b[k];
    if (k === 'host') { x = ipKey(x); y = ipKey(y); }
    if (x === y) return (a.port - b.port) * dir;
    return (x > y ? 1 : -1) * dir;
  });
  return rows;
}
function renderTable() {
  const rows = filteredRows();
  $('st-open').textContent = [...state.rows.values()].filter((r) => r.state === 'open').length;
  $('st-hosts').textContent = state.hosts.size;
  if (!rows.length) { $('tbody').innerHTML = '<tr class="empty"><td colspan="6">暂无结果</td></tr>'; return; }
  $('tbody').innerHTML = rows.slice(0, 5000).map((r) => {
    const cls = ['open', 'closed', 'filtered'].includes(r.state) ? r.state : 'other';
    const ver = [r.product, r.version].filter(Boolean).join(' ');
    const extra = [ver, r.banner].filter(Boolean).join(' — ');
    return `<tr><td class="mono">${esc(r.host)}</td><td class="mono">${r.port}</td><td>${esc(r.proto)}</td>` +
      `<td><span class="st st-${cls}">${esc(r.state)}</span></td><td>${esc(r.service || '')}</td><td class="banner">${esc(extra)}</td></tr>`;
  }).join('');
}
function renderHosts() {
  const hs = [...state.hosts.values()].sort((a, b) => ipKey(a.address) > ipKey(b.address) ? 1 : -1);
  if (!hs.length) { $('hosts').innerHTML = '<p class="empty-text">暂无主机</p>'; return; }
  $('hosts').innerHTML = hs.map((h) => `<div class="host-card"><h4>${esc(h.address)}</h4>` +
    `<div class="meta">${esc([h.hostname, h.state, h.os].filter(Boolean).join(' · '))}</div>` +
    `<div class="pl">${h.ports.sort((a, b) => a.port - b.port).map((p) => `<span>${p.port}/${esc(p.proto)} ${esc(p.service || '')}</span>`).join('') || '<small>无开放端口</small>'}</div></div>`).join('');
}
$('filter').addEventListener('input', renderTable);
document.querySelectorAll('th[data-sort]').forEach((th) => th.addEventListener('click', () => {
  const k = th.dataset.sort;
  state.sortAsc = state.sortKey === k ? !state.sortAsc : true; state.sortKey = k; renderTable();
}));

function appendLog(line) {
  const el = $('log');
  if (el.textContent.length > 2e6) el.textContent = el.textContent.slice(-1e6);
  el.textContent += line + '\n';
  el.scrollTop = el.scrollHeight;
}

// ---------- 导出 ----------
function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
const stamp = () => new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
$('exp-json').addEventListener('click', () => download(`${['dir', 'tool'].includes(state.resultMode) ? 'demo' : 'scan'}-${stamp()}.json`,
  JSON.stringify({ simulated: ['dir', 'tool'].includes(state.resultMode), mode: state.resultMode, hosts: [...state.hosts.values()], ports: filteredRows() }, null, 2), 'application/json'));
$('exp-csv').addEventListener('click', () => {
  const cell = (v) => { let s = String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const lines = [['host', 'port', 'proto', 'state', 'service', 'product', 'version', 'banner', 'simulated'].join(',')]
    .concat(filteredRows().map((r) => [r.host, r.port, r.proto, r.state, r.service, r.product, r.version, r.banner, ['dir', 'tool'].includes(state.resultMode)].map(cell).join(',')));
  download(`${['dir', 'tool'].includes(state.resultMode) ? 'demo' : 'scan'}-${stamp()}.csv`, '\ufeff' + lines.join('\n'), 'text/csv');
});

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

document.querySelectorAll('.mode-form').forEach((form) => form.addEventListener('submit', (e) => e.preventDefault()));
fillTools();
loadInfo();
preview();
})();
