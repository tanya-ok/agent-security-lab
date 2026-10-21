const $ = (selector) => document.querySelector(selector);
let token;
let sending = false;
let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    if (!token) {
      const session = await fetch('/api/session');
      if (!session.ok) throw new Error('Unavailable');
      token = (await session.json()).token;
    }
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error('Unavailable');
    const status = await response.json();
    const control = status.control;
    $('#start').disabled = sending || control.busy;
    $('#demo').disabled = sending || control.busy;
    $('#stop').disabled = sending || control.external || control.stopping;
    $('#stop').textContent = control.busy && !control.stopping ? 'Cancel & stop' : 'Stop stack';
    if (!sending) {
      $('#control-message').textContent = control.message;
      $('#control-message').classList.remove('error');
    }
    const run = status.latest || status.demo;
    if (run) {
      if (run.state === 'running' && !control.busy) {
        run.state = 'interrupted';
        $('#control-message').textContent = 'The previous operation was interrupted. Inspect the stack before retrying.';
      }
      const labels = {passed: run.operation === 'down' ? 'Stack stopped' : run.operation === 'up' ? 'Stack started' : 'Run complete', failed: 'Run needs attention', interrupted: 'Run interrupted', running: run.operation === 'down' ? 'Stopping stack' : run.operation === 'up' ? 'Starting stack' : 'Demonstration in progress'};
      $('#run-state').textContent = labels[run.state] || 'Run recorded';
      $('#verdict').textContent = run.state.toUpperCase();
      $('#verdict').className = `pill ${run.state}`;
      const passed = run.steps.filter((step) => step.state === 'passed').length;
      $('#run-detail').textContent = `${passed} of ${run.steps.length} steps passed · ${new Date(run.started_at).toLocaleString()} · ${run.operation}`;
      const children = run.steps.map((step) => {
        const row = document.createElement('div');
        row.className = `step ${step.state}`;
        const symbol = document.createElement('span');
        symbol.className = 'symbol';
        symbol.textContent = step.state === 'passed' ? '✓' : step.state === 'failed' ? '!' : '◌';
        const name = document.createElement('span');
        name.textContent = step.name;
        const time = document.createElement('time');
        time.textContent = step.duration_seconds === undefined ? `${Math.max(0, Math.floor((Date.now() - Date.parse(step.started_at)) / 1000))}s` : `${step.duration_seconds}s`;
        row.append(symbol, name, time);
        return row;
      });
      $('#steps').replaceChildren(...children);
    }
    for (const node of document.querySelectorAll('[data-service]')) {
      const online = status.ports[node.dataset.service];
      node.textContent = online ? 'PORT LISTENING' : 'STOPPED';
      node.classList.toggle('online', online);
    }
    $('#runtime-state').textContent = status.runtimes.map((vm) => `${vm.name}: ${vm.status}`).join(' · ') || 'VMs not started';
  } catch {
    $('#runtime-state').textContent = 'Local status unavailable';
    for (const id of ['start', 'demo', 'stop']) $(`#${id}`).disabled = true;
    $('#control-message').textContent = 'Local controls unavailable. Keep this page open and retry shortly.';
  } finally { refreshing = false; }
}
async function act(action) {
  if (sending || !token) return;
  sending = true;
  for (const id of ['start', 'demo', 'stop']) $(`#${id}`).disabled = true;
  $('#control-message').classList.remove('error');
  $('#control-message').textContent = 'Sending your request...';
  try {
    const response = await fetch('/api/control', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Lab-Token': token},
      body: JSON.stringify({action}),
    });
    const result = await response.json();
    if (!response.ok) {
      if (response.status === 403) token = undefined;
      throw new Error(result.error || 'Request was not accepted');
    }
  } catch (error) {
    $('#control-message').textContent = error.message;
    $('#control-message').classList.add('error');
    sending = false;
    // Leave the error readable until the next normal refresh.
    return;
  }
  sending = false;
  await refresh();
}
for (const action of ['start', 'demo', 'stop']) {
  $(`#${action}`).addEventListener('click', () => act(action));
}
refresh();
setInterval(refresh, 3000);
