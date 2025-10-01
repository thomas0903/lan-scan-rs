(() => {
  const $ = (sel) => document.querySelector(sel);

  const statusText = $('#statusText');
  const progressEl = $('#progress');
  const tableBody = $('#resultsTable tbody');
  let pollTimer = null;

  function parseTargets(raw) {
    if (!raw) return [];
    return raw.split(',').map(s => s.trim()).filter(Boolean);
  }

  function parsePorts(raw) {
    if (!raw) return [];
    // Very lightweight parse: split by comma, keep numeric or range-like tokens. The backend validates.
    return raw.split(',')
      .map(s => s.trim())
      .filter(Boolean)
      .flatMap(tok => {
        if (tok.includes('-')) {
          // range a-b -> expand a..=b (cap to sane range)
          const [a, b] = tok.split('-').map(x => parseInt(x, 10));
          if (Number.isFinite(a) && Number.isFinite(b) && a > 0 && b >= a && b <= 65535) {
            const arr = [];
            for (let p = a; p <= b; p++) arr.push(p);
            return arr;
          }
          return [];
        } else {
          const p = parseInt(tok, 10);
          return Number.isFinite(p) && p > 0 && p <= 65535 ? [p] : [];
        }
      });
  }

  function setStatus(msg) {
    statusText.textContent = msg;
  }

  async function apiGet(path) {
    const res = await fetch(`/api${path}`);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    if (res.status === 204) return null;
    return res.json();
  }

  async function apiPost(path, body) {
    const res = await fetch(`/api${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }

  function renderResults(results) {
    tableBody.innerHTML = '';
    (results.entries || []).forEach(e => {
      const tr = document.createElement('tr');
      const tdIp = document.createElement('td'); tdIp.textContent = e.ip;
      const tdPort = document.createElement('td'); tdPort.textContent = e.port;
      const tdSvc = document.createElement('td'); tdSvc.textContent = e.service || '';
      const tdLat = document.createElement('td'); tdLat.textContent = e.latency_ms;
      const tdBanner = document.createElement('td'); tdBanner.textContent = e.banner || '';
      tr.appendChild(tdIp);
      tr.appendChild(tdPort);
      tr.appendChild(tdSvc);
      tr.appendChild(tdLat);
      tr.appendChild(tdBanner);
      tableBody.appendChild(tr);
    });
  }

  async function pollLoop() {
    try {
      const s = await apiGet('/status');
      if (!s) return;
      const pct = s.total > 0 ? Math.floor((s.scanned / s.total) * 100) : 0;
      setStatus(`${s.state.toUpperCase()} — scanned ${s.scanned}/${s.total} (${pct}%), open: ${s.open}`);
      progressEl.style.width = pct + '%';
      progressEl.setAttribute('data-progress', pct + '%');
      if (s.state === 'done') {
        clearInterval(pollTimer);
        pollTimer = null;
        const r = await apiGet('/results');
        if (r) renderResults(r);
      }
    } catch (e) {
      // Soft-fail poll errors
      console.warn('status poll failed', e);
    }
  }

  async function startScan() {
    const targets = parseTargets($('#targets').value);
    if (targets.length === 0) {
      alert('Please enter at least one target (IP or CIDR).');
      return;
    }
    const ports = parsePorts($('#ports').value);
    const concurrency = parseInt($('#concurrency').value, 10) || 200;
    const timeout_ms = parseInt($('#timeout').value, 10) || 400;
    const probe_redis = !!$('#probeRedis').checked;

    try {
      setStatus('Starting scan...');
      tableBody.innerHTML = '';
      await apiPost('/scan', { targets, ports, concurrency, timeout_ms, probe_redis });
      setStatus('RUNNING — scanned 0/0');
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(pollLoop, 1000);
      pollLoop();
    } catch (e) {
      alert('Failed to start scan: ' + e.message);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('#startBtn').addEventListener('click', startScan);
    // Start with an initial status fetch
    pollLoop();
  });
})();
