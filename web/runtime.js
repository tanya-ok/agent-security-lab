import {credentialView} from './credentials.mjs';

const $ = (selector) => document.querySelector(selector);
const labels = {healthy: 'Healthy', reachable: 'Reachable', ready: 'Ready', degraded: 'Needs attention', stopped: 'Stopped', unknown: 'Unknown', current: 'Expiry observed', expiring: 'Expires soon', expired: 'Expired'};
let busy = false;
let lastChecked;
let sessionToken;
let actionBusy = false;
let activeService;
let catalog = [];
let control = {busy:true};
const endpointTargets = {viewer:'viewer', identity:'zitadel', login:'zitadel-login', grc:'grc-backend', dashboard:'dashboard'};
async function serviceRequest(action, service) {
  if (!sessionToken) {
    const response = await fetch('/api/session');
    if (!response.ok) throw new Error('Local session unavailable');
    sessionToken = (await response.json()).token;
  }
  const response = await fetch('/api/service', {method:'POST', headers:{'Content-Type':'application/json','X-Lab-Token':sessionToken}, body:JSON.stringify({action,service})});
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 403) sessionToken = undefined;
    throw new Error(result.error || 'Service action unavailable');
  }
  return result;
}
function serviceActions(id, label, includeLogs = true) {
  const target = catalog.find((item) => item.id === id);
  const actions = element('div', undefined, 'service-actions');
  if (!target) return actions;
  const restart = element('button', label || 'Restart'); restart.type = 'button';
  restart.setAttribute('aria-label', label || `Restart ${id}`);
  restart.disabled = !target.restartable || actionBusy || control.busy;
  restart.dataset.restart = id;
  restart.addEventListener('click', async () => {
    actionBusy = true; updateButtons();
    $('#service-operation').textContent = `Requesting restart: ${id}`;
    try {
      await serviceRequest('restart', id);
      await pollOperation();
    } catch (error) { $('#service-operation').textContent = error.message; }
    finally { actionBusy = false; updateButtons(); }
  });
  const logs = element('button','View logs'); logs.type='button';
  logs.setAttribute('aria-label', `View logs ${id}`);
  logs.addEventListener('click', () => { activeService = id; $('#log-title').textContent = `Logs: ${id}`; $('#log-dialog').showModal(); loadLogs(); });
  actions.append(restart);
  if (includeLogs) actions.append(logs);
  if (target.note && includeLogs) actions.append(element('p', target.note, 'note'));
  return actions;
}
function updateButtons() {
  for (const button of document.querySelectorAll('[data-restart]')) {
    const item = catalog.find((row) => row.id === button.dataset.restart);
    button.disabled = !item?.restartable || actionBusy || control.busy;
  }
}
async function pollOperation() {
  try {
    const response = await fetch('/api/status');
    if (!response.ok) throw new Error('Unavailable');
    const data = await response.json();
    control = data.control;
    $('#service-operation').textContent = control.message;
    updateButtons();
  } catch {
    control = {busy:true}; updateButtons();
    $('#service-operation').textContent = 'Local controls unavailable. Refresh this page before retrying.';
  }
}
async function loadLogs() {
  const id = activeService;
  $('#refresh-logs').disabled = true;
  $('#log-content').textContent = 'Loading recent logs...';
  $('#log-meta').textContent = '';
  try {
    const data = await serviceRequest('logs', id);
    if (id !== activeService || !$('#log-dialog').open) return;
    $('#log-meta').textContent = `Checked ${new Date(data.checked_at).toLocaleTimeString()} · ${data.sampled_lines} lines sampled · ${data.hidden_lines} unclassified lines hidden`;
    $('#log-content').textContent = data.entries.length ? data.entries.map((line) => `${line.time || 'Time not recorded'}  ${line.level}  ${line.summary}`).join('\n') : 'No diagnostic signals in the recent sample. Unclassified messages remain private.';
  } catch (error) { if (id === activeService) $('#log-content').textContent = error.message; }
  finally { $('#refresh-logs').disabled = false; }
}
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function badge(state) { return element('span', labels[state] || state, `health-badge ${state}`); }
function renderCredentials(value) {
  const view = credentialView(value);
  const notice = element('article', undefined, `credential-notice ${view.state}`);
  const heading = element('div', undefined, 'card-heading');
  heading.append(element('h2', view.title), badge(view.state));
  notice.append(heading, element('p', view.message));
  const dates = element('dl', undefined, 'credential-dates');
  for (const item of view.items) {
    const row = element('div');
    row.append(element('dt', item.name), element('dd', item.text));
    if (item.expires_at) {
      const date = element('time', new Date(item.expires_at).toLocaleString());
      date.dateTime = item.expires_at;
      row.append(date);
    }
    dates.append(row);
  }
  notice.append(dates);
  if (view.guidance) {
    notice.append(element('p', view.guidance, 'credential-guidance'));
    const link = element('a', 'Open demo controls'); link.href = '/';
    notice.append(link);
  }
  notice.append(element('p', 'Expiry does not prove that sign-in works or detect revoked credentials. Dates use your local time.', 'note'));
  $('#credential-lifetime').replaceChildren(notice);
}
function render(data) {
  renderCredentials(data.credentials);
  lastChecked = data.checked_at;
  catalog = data.management;
  control = data.control;
  $('#runtime-diagnostics').replaceChildren(...(data.diagnostics || []).map((item) => {
    const notice = element('article', undefined, 'recovery-notice');
    notice.append(element('h2', item.title), element('p', item.detail));
    if (item.code === 'local-access-offline') notice.append(serviceActions('viewer', 'Reconnect local access', false));
    return notice;
  }));
  $('#service-operation').textContent = control.message;
  const containers = data.workloads.flatMap((vm) => vm.containers);
  $('#vm-count').textContent = data.workloads.some((vm) => vm.vm_state === 'Unknown') ? 'Unknown' : `${data.workloads.filter((vm) => vm.vm_state === 'Running').length} / ${data.workloads.length}`;
  $('#ready-count').textContent = data.workloads.some((vm) => vm.state === 'unknown') ? 'Unknown' : `${containers.filter((row) => row.ready).length} / ${containers.length}`;
  const health = data.services.filter((service) => service.key !== 'viewer');
  $('#health-count').textContent = `${health.filter((service) => service.state === 'healthy').length} / ${health.length}`;
  $('#pin-count').textContent = `${data.projects.filter((p) => p.integrity === 'verified').length} / ${data.projects.length}`;
  $('#checked').textContent = `Checked ${new Date(data.checked_at).toLocaleTimeString()} · refreshes every 15 seconds`;
  $('#checked').classList.remove('error');
  $('#health-cards').replaceChildren(...data.services.map((service) => {
    const card = element('article', undefined, 'health-card');
    const heading = element('div', undefined, 'card-heading');
    heading.append(element('h3', service.name), badge(service.state));
    const link = element('a', new URL(service.url).host + new URL(service.url).pathname, 'endpoint');
    link.href = service.url; link.target = '_blank'; link.rel = 'noreferrer';
    card.append(heading, element('p', service.detail), link,
      element('p', service.http_status ? `HTTP ${service.http_status} · ${service.latency_ms} ms` : 'No application result', 'note'), serviceActions(endpointTargets[service.key]));
    return card;
  }));
  $('#project-cards').replaceChildren(...data.projects.map((project) => {
    const card = element('article', undefined, 'project-card');
    const heading = element('div', undefined, 'card-heading');
    heading.append(element('h3', project.name), element('span', project.integrity === 'verified' ? 'Pin verified' : 'Pin unverified', `health-badge ${project.integrity === 'verified' ? 'ready' : 'unknown'}`));
    const version = project.version ? `Manifest version ${project.version}` : project.name === 'it-grc' ? 'Adapter tracked by commit' : 'Manifest version unavailable';
    card.append(heading, element('p', version), element('code', project.commit.slice(0, 12)),
      element('p', project.kind === 'library' ? 'Library embedded in the FHIR demo. No standalone health endpoint.' : project.kind === 'experiment' ? 'Runs on demand. No background service or profile installation.' : 'Source manifest version; running containers are listed below.', 'note'));
    return card;
  }));
  const demo = data.last_demo;
  $('#last-demo').textContent = demo ? `Last demo: ${demo.state} · ${new Date(demo.finished_at || demo.started_at).toLocaleString()}. Demo evidence is separate from live health.` : 'No demo report yet. Live health does not execute scenarios.';
  const expanded = new Set([...document.querySelectorAll('.container-row[open]')].map((row) => row.dataset.key));
  $('#workloads').replaceChildren(...data.workloads.map((vm) => {
    const section = element('article', undefined, 'workload-group');
    const heading = element('div', undefined, 'card-heading');
    heading.append(element('h3', vm.name), badge(vm.state));
    section.append(heading, element('p', `VM: ${vm.vm_state} · ${vm.containers.filter((row) => row.ready).length} / ${vm.containers.length} observed containers ready`, 'note'));
    if (vm.missing_containers.length) section.append(element('p', `Not observed: ${vm.missing_containers.join(', ')}`, 'note'));
    if (!vm.containers.length) section.append(element('p', vm.state === 'stopped' ? 'The VM is stopped. Start the stack from Overview.' : 'Workload observation unavailable. No healthy state is assumed.', 'note'));
    for (const row of vm.containers) {
      const details = element('details', undefined, 'container-row');
      details.dataset.key = `${vm.name}/${row.namespace}/${row.name}`;
      details.open = expanded.has(details.dataset.key);
      const summary = element('summary');
      const name = element('span'); name.append(element('strong', row.name), element('small', row.namespace));
      summary.append(name, element('span', row.version ? `${row.version} · digest matched` : row.image ? 'Observed image digest' : 'Image not observed', 'image-version'), badge(row.ready ? 'ready' : 'degraded'));
      details.append(summary, element('p', `Pod: ${row.pod} · ${row.phase} · restarts ${row.restarts}`, 'note'), element('code', row.image || 'Image ID unavailable'));
      const target = catalog.find((item) => !item.host && item.namespace === row.namespace && item.container === row.name);
      if (target) details.append(serviceActions(target.id));
      section.append(details);
    }
    return section;
  }));
}
async function refresh() {
  if (busy) return;
  busy = true;
  try {
    const response = await fetch('/api/runtime');
    if (!response.ok) throw new Error('Unavailable');
    render(await response.json());
  } catch {
    $('#checked').textContent = lastChecked ? `Live checks unavailable. Last observation: ${new Date(lastChecked).toLocaleTimeString()}. Values below are stale.` : 'Live checks unavailable. No healthy state is assumed.';
    $('#checked').classList.add('error');
    $('#runtime-diagnostics').replaceChildren();
    renderCredentials(undefined);
    for (const id of ['vm-count', 'ready-count', 'health-count', 'pin-count']) $(`#${id}`).textContent = 'Unknown';
    for (const node of document.querySelectorAll('.health-badge')) { node.textContent = 'Stale'; node.className = 'health-badge unknown'; }
  } finally { busy = false; }
}
$('#close-logs').addEventListener('click', () => { activeService = undefined; $('#log-dialog').close(); });
$('#refresh-logs').addEventListener('click', loadLogs);
refresh();
setInterval(refresh, 15000);
setInterval(pollOperation, 2500);
