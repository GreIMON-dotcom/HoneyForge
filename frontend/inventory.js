import {t, tk, label, plural, formatDate, formatNumber, relativeTime, safeError, esc, state, pages, actions, forms, modal, api, post,
  patch, remove, toast, badge, button, panel, heading, table, empty, formField, selectField, textArea, openDialog, keyValues,
  detailList, rawDetails, meter, admin, canOperate, potName, serviceName, navigate, rerender, prefs, applyPrefs, icon} from './ui.js';
import {SECTIONS, serviceSection, openEditor, syncDraft, draftProblems, fieldGrid, siteEditor, ownSettings, fieldText} from './specform.js';
import {startWizard} from './constructor.js';

const PAGE_SIZE = 10;
const selected = value => Array.isArray(value) ? value : value ? [value] : [];
const matches = (values, value) => !selected(values).length || selected(values).includes(value);
function filterChoices(name, title, options, value) {
  const values = selected(value);
  return `<details class="filter-choices" data-filter-set="${name}"><summary>${esc(title)}<span>${esc(values.length ? t('pots.selectedCount', {count: values.length}) : t('pots.anyFilter'))}</span></summary>` +
    `<fieldset><legend class="sr-only">${esc(title)}</legend>${options.map(([id, text]) => `<label class="check"><input type="checkbox" name="${name}" value="${esc(id)}" ${values.includes(id) ? 'checked' : ''}>${esc(text)}</label>`).join('')}</fieldset></details>`;
}
const TRANSITIONAL = ['deploying', 'starting', 'stopping', 'restarting', 'updating', 'deleting'];
const clone = value => JSON.parse(JSON.stringify(value));
const plugin = key => state.services.find(service => service.key === key);
const tags = list => (list || []).map(tag => `<span class="tag">${esc(tag)}</span>`).join('');
const megabytes = bytes => formatNumber(Math.round(bytes / 1048576));
const publicAddress = endpoint => `${endpoint.published_address === '0.0.0.0' ? location.hostname : endpoint.published_address || '—'}:${endpoint.published_observed}`;
function publicationText(endpoint) {
  if (!endpoint) return t('pots.publicationNone');
  if (endpoint.published_port && endpoint.published_observed === endpoint.published_port) return t('pots.publicationActive', {address: publicAddress(endpoint)});
  if (endpoint.published_port) return t('pots.publicationPending', {port: endpoint.published_port});
  return endpoint.published_observed ? t('pots.publicationWithdrawing') : t('pots.publicationNone');
}


const SORTS = {
  name: pot => pot.name.toLowerCase(), status: pot => label('status', pot.status), events: pot => pot.event_count,
  created: pot => pot.created_at, endpoint: pot => pot.endpoint?.port || 0, service: pot => serviceName(pot.service_key),
};
function filteredPots() {
  const view = state.inventory;
  const text = view.q.trim().toLowerCase();
  const rows = state.pots.filter(pot =>
    (!text || [pot.name, pot.description, pot.profile_name, pot.endpoint?.address, ...(pot.tags || [])].join(' ').toLowerCase().includes(text)) &&
    matches(view.status, pot.status) && matches(view.service, pot.service_key) && matches(view.host, pot.host_id));
  const key = SORTS[view.sort] || SORTS.name;
  rows.sort((a, b) => (key(a) > key(b) ? 1 : key(a) < key(b) ? -1 : 0) * (view.order === 'desc' ? -1 : 1));
  return rows;
}
function rowActions(pot) {
  const controls = [button(t('common.details'), 'pot-open', pot.id, 'ghost')];
  if (admin() && ['draft', 'failed'].includes(pot.status)) controls.push(button(t('pots.deploy'), 'pot-deploy', pot.id, 'primary'));
  if (canOperate() && pot.deployed && pot.status !== 'deleting')
    controls.push(pot.desired_state === 'running' ? button(t('common.stop'), 'stop', pot.id) : button(t('common.start'), 'start', pot.id));
  return `<div class="actions">${controls.join('')}</div>`;
}
function agentText(pot) {
  if (!pot.agent) return esc(t('pots.agentNone'));
  return esc(t(!pot.agent.approved ? 'pots.agentRevoked' : pot.agent.connected ? 'pots.agentOnline' : 'pots.agentOffline'));
}
function agentState(pot) {
  if (!pot.agent) return `<small>${t('pots.agentNone')}</small>`;
  if (!pot.agent.approved) return badge('revoked');
  return badge(pot.agent.connected ? 'connected' : 'disconnected');
}
pages.honeypots = async () => {
  const view = state.inventory;
  const rows = filteredPots();
  const total = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  view.page = Math.min(view.page, total);
  const visible = rows.slice((view.page - 1) * PAGE_SIZE, view.page * PAGE_SIZE);
  const statuses = [...new Set(state.pots.map(pot => pot.status))];
  const filters = `<form id="inventory-filters" class="filters inventory-filters" data-auto-filter>` +
    formField('q', t('pots.search'), view.q, 'search', `placeholder="${esc(t('pots.searchHint'))}"`) +
    filterChoices('status', t('common.state'), statuses.map(value => [value, label('status', value)]), view.status) +
    filterChoices('service', t('pots.type'), state.services.map(item => [item.key, item.display_name]), view.service) +
    filterChoices('host', t('common.host'), state.hosts.map(host => [host.id, host.name]), view.host) +
    selectField('sort', t('pots.sortBy'), Object.keys(SORTS).map(key => [key, label('sort', key)]), view.sort) +
    selectField('order', t('events.sort'), [['asc', t('pots.ascending')], ['desc', t('pots.descending')]], view.order) +
    `${button(t('common.reset'), 'inventory-reset', '', 'ghost')}</form>`;
  const body = table([t('pots.name'), t('pots.type'), t('common.profile'), t('common.host'), t('pots.ipAddress'), t('pots.portColumn'),
    t('common.state'), t('pots.lastActivity'), t('common.actions')], visible.map(pot =>
    `<tr><td><a href="#honeypot/${esc(pot.id)}"><strong>${esc(pot.name)}</strong></a><br><small class="mono">${esc(pot.id.slice(0, 8))}</small> ${tags(pot.tags)}</td>` +
    `<td>${esc(serviceName(pot.service_key))}<br><small>${esc(label('interaction', pot.interaction_level))}</small></td>` +
    `<td>${esc(pot.profile_name)} <small>v${pot.profile_version}</small>${pot.update_available ? `<br>${badge('update_available')}` : ''}</td>` +
    `<td>${esc(pot.host_name)}</td>` +
    `<td class="mono">${esc(pot.ip_address || '—')}<br><small>${esc(pot.endpoint?.alias || '')}</small></td>` +
    `<td class="mono">${esc(pot.endpoint?.port ?? '—')}${pot.endpoint?.published_port ? `<br><small>${esc(t('pots.publishedShort', {port: pot.endpoint.published_port}))}</small>` : ''}</td>` +
    `<td>${badge(pot.status)}<br><small>${pot.error ? esc(t('honeypots.reportedError')) : agentText(pot)}</small></td>` +
    `<td><span class="mono">${esc(formatDate(pot.last_seen))}</span><br><small>${esc(plural('counts.events', pot.event_count))}</small></td>` +
    `<td>${rowActions(pot)}</td></tr>`), state.pots.length ? t('pots.nothingFound') : t('pots.empty'));
  const pager = `<div class="pagination"><span>${t('pots.pagination', {count: plural('counts.honeypots', rows.length), page: formatNumber(view.page), pages: formatNumber(total)})}</span><div class="actions">` +
    `${view.page > 1 ? button(t('common.previousArrow'), 'inventory-page', view.page - 1) : ''}${view.page < total ? button(t('common.nextArrow'), 'inventory-page', view.page + 1) : ''}</div></div>`;
  return heading(t('pots.title'), t('pots.description'), admin() ? button(t('pots.create'), 'pot-new', '', 'primary') : '') +
    `<section class="panel">${filters}${body}${pager}</section>`;
};
forms['inventory-filters'] = async (form, data) => {
  const fields = new FormData(form);
  Object.assign(state.inventory, data, {page: 1, status: fields.getAll('status'), service: fields.getAll('service'), host: fields.getAll('host')});
  for (const choice of form.querySelectorAll('[data-filter-set]')) {
    const count = fields.getAll(choice.dataset.filterSet).length;
    choice.querySelector('summary span').textContent = count ? t('pots.selectedCount', {count}) : t('pots.anyFilter');
  }
  await rerender();
};


function instanceActions(pot) {
  const controls = [];
  const busy = TRANSITIONAL.includes(pot.status);
  if (admin() && ['draft', 'failed'].includes(pot.status)) controls.push(button(t('pots.deploy'), 'pot-deploy', pot.id, 'primary'));
  if (canOperate() && pot.deployed && pot.status !== 'deleting') {
    controls.push(pot.desired_state === 'running' ? button(t('common.stop'), 'stop', pot.id) : button(t('common.start'), 'start', pot.id));
    controls.push(button(t('common.restart'), 'restart', pot.id));
  }
  if (canOperate() && pot.update_available && pot.status !== 'deleting') controls.push(button(t('pots.applyUpdates'), 'pot-apply-updates', pot.id, 'primary'));
  if (canOperate() && pot.status !== 'deleting') controls.push(button(t('pots.settings'), 'pot-edit', pot.id));
  if (admin() && pot.deployed && pot.status !== 'deleting') {
    controls.push(pot.endpoint?.published_port ? button(t('pots.unpublish'), 'pot-unpublish', pot.id) : button(t('pots.publish'), 'pot-publish', pot.id));
  }
  if (admin()) controls.push(button(t('pots.clone'), 'pot-clone', pot.id));
  if (admin() && !busy) controls.push(button(t('pots.delete'), 'pot-delete', pot.id, 'danger'));
  if (admin() && pot.status === 'deleting') controls.push(button(t('pots.forceDelete'), 'pot-force-delete', pot.id, 'danger'));
  return controls.join('');
}
function containerRow(caption, item) {
  if (!item) return `<tr><td>${esc(caption)}</td><td colspan="4">${t('pots.noContainer')}</td></tr>`;
  return `<tr><td>${esc(caption)}</td><td class="mono">${esc(item.id.slice(0, 12))}</td><td>${badge(item.state, 'container')}${item.health ? ' ' + badge(item.health, 'container') : ''}</td>` +
    `<td>${megabytes(item.memory_limit)} ${t('units.mb')} · ${formatNumber(item.nano_cpus / 1e9)} ${t('units.cores')}</td><td>${formatNumber(item.restart_count)}</td></tr>`;
}
const logRows = logs => logs.map(row =>
  `<tr><td class="mono">${esc(formatDate(row.timestamp))}</td><td>${badge(row.level, 'logLevel')}</td><td>${esc(label('log', row.code))}` +
  `${row.details?.error ? `<br><small>${esc(safeError(row.details.error))}</small>` : ''}</td></tr>`);

pages.honeypot = async () => {
  let pot;
  try {
    pot = await api('/honeypots/' + state.param);
  } catch {
    return heading(t('pots.detailsTitle'), t('pots.description'), button(t('pots.backToList'), 'navigate', 'honeypots')) + empty(t('pots.missing'));
  }
  const [events, logs] = await Promise.all([api(`/events?honeypot_id=${pot.id}&page_size=8`), api(`/honeypots/${pot.id}/logs`)]);
  const runtime = pot.runtime || {};
  const stats = runtime.stats;
  const config = pot.configuration;
  const banner = pot.error ? `<div class="error-banner">${esc(safeError(pot.error))}</div>` : '';
  const updateNote = pot.update_available ? `<div class="notice warning">${t('pots.updateAvailable', {current: pot.profile_version, latest: pot.profile_latest_version})}</div>` : '';
  const general = keyValues([
    [t('common.state'), `${badge(pot.status)} ${pot.synchronized ? `<small>${t('honeypots.synchronized')}</small>` : pot.deployed ? `<small>${t('honeypots.awaitAck')}</small>` : ''}`],
    [t('pots.type'), esc(`${serviceName(pot.service_key)} · ${label('interaction', pot.interaction_level)}`)],
    [t('common.profile'), `${esc(pot.profile_name)} · v${pot.profile_version} · ${esc(label('policy', pot.update_policy))}`],
    [t('wizard.descriptionField'), esc(pot.description || '—')],
    [t('pots.tags'), tags(pot.tags) || '—'],
    [t('common.generation'), `${formatNumber(pot.applied_generation)} / ${formatNumber(pot.generation)}`],
    [t('pots.created'), esc(formatDate(pot.created_at))],
    [label('field', 'id'), `<span class="mono">${esc(pot.id)}</span>`],
  ]);
  const network = keyValues([
    [t('common.host'), `${esc(pot.host.name)} · ${esc(pot.host.controller_connected ? t('resources.controllerOnline') : t('resources.controllerOffline'))}`],
    [t('pots.endpoint'), `<span class="mono">${esc(pot.endpoint?.address || '—')}</span>`],
    [t('pots.publication'), esc(publicationText(pot.endpoint))],
    [label('field', 'ip_address'), `<span class="mono">${esc(pot.ip_address || t('honeypots.awaitAddress'))}</span>`],
    [t('wizard.network'), esc(t('wizard.networkValue', {name: pot.endpoint?.network || '—'}))],
    [t('wizard.allocation'), esc(label('portMode', pot.endpoint?.mode))],
    [t('pots.agent'), pot.agent ? `<span class="mono">${esc(pot.agent.id)}</span> ${agentState(pot)}` : t('pots.agentNone')],
    [t('honeypots.heartbeat'), `${esc(formatDate(pot.last_seen))} · ${esc(relativeTime(pot.last_seen))}`],
    [label('field', 'queue_size'), formatNumber(pot.queue_size)],
    [label('field', 'last_delivery'), esc(formatDate(pot.last_delivery))],
  ]);
  const usage = stats ? `<div class="meters">${meter(t('pots.memoryUse'), Math.round(stats.memory_bytes / 1048576), config.memory_mb, t('units.mb'))}` +
    `${meter(t('pots.cpuUse'), Math.round(stats.cpu_percent), Math.round(config.cpu_limit * 100), '%')}</div>` : `<p class="hint">${t('pots.noStats')}</p>`;
  const containers = `<div class="table-wrap"><table><thead><tr><th>${t('pots.container')}</th><th>${label('field', 'id')}</th><th>${t('common.state')}</th><th>${t('pots.limits')}</th><th>${t('pots.restarts')}</th></tr></thead>` +
    `<tbody>${containerRow(t('pots.decoy'), runtime.decoy)}${containerRow(t('pots.sidecar'), runtime.agent)}${pot.service_key === 'linux-sandbox' ? containerRow(t('pots.sandbox'), runtime.sandbox) : ''}</tbody></table></div>`;
  const summary = keyValues(serviceSection(config.service_key, config.service_type).concat(SECTIONS.resources)
    .map(name => [tk('fields', name), esc(fieldText(name, config[name]))]));
  const eventRows = events.items.map(e => `<tr><td class="mono">${e.id}</td><td class="mono">${esc(formatDate(e.timestamp))}</td><td class="mono">${esc(e.source_ip)}:${e.source_port}</td>` +
    `<td>${esc(label('event', e.event_type))}<br><small>${esc(e.payload.summary || '')}</small></td><td>${badge(e.severity, 'severity')}</td><td>${button(t('common.inspect'), 'event', e.id)}</td></tr>`);
  const deployments = pot.deployments.map(d => `<tr><td>${esc(formatDate(d.started_at))}</td><td>${badge(d.status)}</td><td>${esc(formatDate(d.completed_at))}</td>` +
    `<td>${esc(d.error_message ? safeError(d.error_message) : '—')}</td><td>${button(t('monitor.log'), 'deployment-log', d.id)}</td></tr>`);
  const commands = pot.commands.map(c => `<tr><td>${esc(formatDate(c.created_at))}</td><td>${esc(label('command', c.command_type))}</td><td>${c.generation}</td><td>${badge(c.status)}</td><td>${esc(c.error ? safeError(c.error) : '—')}</td></tr>`);
  return heading(esc(pot.name), t('pots.detailsTitle'), button(t('pots.backToList'), 'navigate', 'honeypots') + instanceActions(pot)) + banner + updateNote +
    `<div class="grid even">${panel(t('pots.general'), `<div class="panel-body">${general}</div>`)}${panel(t('pots.networkAgent'), `<div class="panel-body">${network}</div>`)}</div>` +
    `<div class="grid even">${panel(t('pots.runtime'), `${containers}<div class="panel-body">${usage}</div>`)}` +
    `${panel(t('honeypots.currentConfig'), `<div class="panel-body">${summary}${rawDetails(config, t('profiles.preview'))}${Object.keys(pot.overrides).length ? rawDetails(pot.overrides, t('pots.overrides')) : ''}</div>`)}</div>` +
    panel(t('pots.eventHistory'), table([t('events.id'), t('common.time'), t('common.source'), t('common.eventType'), t('common.severity'), ''], eventRows, t('common.waitingEvents')),
      `<span>${plural('counts.events', events.total)}</span>${button(t('honeypots.inspectEvents'), 'pot-events', pot.id)}`) +
    `<div class="grid even">${panel(t('deployments.history'), table([t('deployments.started'), t('common.status'), t('monitor.completed'), t('common.error'), ''], deployments))}` +
    `${panel(t('honeypots.commands'), table([t('common.time'), t('common.operation'), t('common.generation'), t('common.state'), t('common.error')], commands))}</div>` +
    panel(t('pots.operationLog'), table([t('common.time'), t('monitor.level'), t('monitor.step')], logRows(logs)));
};

function settingsDialog(pot) {
  const service = plugin(pot.service_key);
  const draft = clone(pot.configuration);
  openEditor(draft, service);
  const compatible = state.profiles.filter(profile => profile.spec.service_type === pot.service_type);
  openDialog(t('pots.settingsTitle', {name: pot.name}),
    `<form id="pot-settings" data-id="${esc(pot.id)}"><div class="form-section"><h3>${t('pots.general')}</h3><div class="form-grid">` +
    formField('name', t('wizard.name'), pot.name, 'text', 'required maxlength="80"') + formField('tags', t('wizard.tags'), (pot.tags || []).join(', ')) +
    `<div class="full">${formField('description', t('wizard.descriptionField'), pot.description, 'text', 'maxlength="1000"')}</div>` +
    selectField('profile_id', t('common.profile'), compatible.map(profile => [profile.id, `${profile.name} · v${profile.version}`]), pot.profile_id) +
    selectField('update_policy', t('wizard.updatePolicy'), [['manual', label('policy', 'manual')], ['auto', label('policy', 'auto')]], pot.update_policy) +
    formField('port', t('pots.port'), pot.endpoint.port, 'number', `min="${pot.host.port_range_start}" max="${pot.host.port_range_end}" required`) +
    `</div><p class="hint">${t('pots.settingsHint')}</p></div>` +
    `<div class="form-section"><h3>${esc(service.display_name)}</h3>${fieldGrid([...serviceSection(service.key, service.emulator), ...SECTIONS.behaviour], draft, service)}</div>` +
    (service.emulator === 'http' ? `<div id="spec-site">${siteEditor()}</div>` : '') +
    `<div class="form-section"><h3>${t('wizard.telemetry')}</h3>${fieldGrid(SECTIONS.monitoring, draft, service)}</div>` +
    `<div class="form-section"><h3>${t('wizard.instanceLimits')}</h3>${fieldGrid(SECTIONS.resources, draft, service)}</div>` +
    `<div class="dialog-footer"><button class="primary">${t('pots.saveSettings')}</button></div></form>`);
}
forms['pot-settings'] = async (form, data) => {
  const pot = await api('/honeypots/' + form.dataset.id);
  const draft = syncDraft(form);
  const problem = draftProblems(draft)[0];
  if (problem) throw new Error(problem);
  const base = state.profiles.find(profile => profile.id === data.profile_id)?.spec || pot.profile.spec;
  const overrides = ownSettings(draft, base);
  const body = {name: data.name, description: data.description, tags: data.tags.split(',').map(tag => tag.trim()).filter(Boolean),
    update_policy: data.update_policy, overrides};
  if (data.profile_id !== pot.profile_id) body.profile_id = data.profile_id;
  if (Number(data.port) !== pot.endpoint.port) body.port = Number(data.port);
  await patch('/honeypots/' + pot.id, body);
  toast(t('pots.settingsSaved'));
};
forms['pot-publish'] = async (form, data) => {
  await post(`/honeypots/${form.dataset.id}/publish`, {port: Number(data.port)});
  toast(t('pots.publishRequested'));
};
forms['pot-clone'] = async (form, data) => {
  const copy = await post(`/honeypots/${form.dataset.id}/clone`, {name: data.name, deploy: form.elements.deploy.checked});
  toast(t('pots.cloned'));
  navigate('honeypot/' + copy.id);
};

Object.assign(actions, {
  'pot-new': () => startWizard(),
  'pot-open': id => navigate('honeypot/' + id),
  'pot-events': id => { modal.close(); state.filters = {honeypot_id: id}; state.eventPage = 1; navigate('events'); },
  'pot-deploy': async id => { await post(`/honeypots/${id}/deploy`); toast(t('pots.deployRequested')); await rerender(); },
  'pot-apply-updates': async id => {
    if (!confirm(t('confirm.applyUpdates'))) return;
    await post(`/honeypots/${id}/apply-updates`);
    toast(t('pots.updatesApplied'));
    await rerender();
  },
  'pot-edit': async id => settingsDialog(await api('/honeypots/' + id)),
  'pot-clone': id => {
    const source = state.pots.find(pot => pot.id === id);
    openDialog(t('pots.cloneTitle', {name: source?.name || ''}),
      `<form id="pot-clone" data-id="${esc(id)}"><p>${t('pots.cloneHint')}</p>${formField('name', t('pots.cloneName'), (source?.name || '') + ' — ' + t('pots.copySuffix'), 'text', 'required maxlength="80"')}` +
      `<label class="check"><input name="deploy" type="checkbox" checked>${t('pots.cloneDeploy')}</label><button class="primary">${t('pots.clone')}</button></form>`);
  },
  'pot-publish': async id => {
    const pot = await api('/honeypots/' + id);
    const [capacity, endpoints] = await Promise.all([api(`/hosts/${pot.host_id}/capacity`), api('/network-endpoints')]);
    const policy = capacity.publication;
    const taken = new Set(endpoints.filter(e => e.host_id === pot.host_id && e.honeypot_id !== pot.id).map(e => e.published_port).filter(Boolean));
    const free = policy.ports.filter(port => !taken.has(port));
    const body = !policy.enabled ? `<div class="notice warning">${t('pots.publishDisabled')}</div>`
      : !free.length ? `<div class="notice warning">${t('pots.publishNoPorts')}</div>`
      : `<form id="pot-publish" data-id="${esc(pot.id)}"><div class="notice warning">${t('pots.publishWarning')}</div>` +
        selectField('port', t('pots.publishPort'), free.map(port => [String(port), String(port)]), String(free[0])) +
        `<p class="hint">${esc(t('pots.publishTarget', {port: pot.endpoint.port}))}</p>` +
        `<label class="check"><input name="understood" type="checkbox" required>${t('pots.publishConfirm')}</label>` +
        `<button class="primary">${t('pots.publish')}</button></form>`;
    openDialog(t('pots.publishTitle', {name: pot.name}), body);
  },
  'pot-unpublish': async id => {
    if (!confirm(t('confirm.unpublish'))) return;
    await post(`/honeypots/${id}/unpublish`);
    toast(t('pots.unpublishRequested'));
    await rerender();
  },
  'pot-delete': async id => {
    if (!confirm(t('confirm.potDelete'))) return;
    const result = await remove('/honeypots/' + id);
    toast(result.deleted ? t('notifications.potDeleted') : t('pots.deleteRequested'));
    if (result.deleted) navigate('honeypots');
    await rerender();
  },
  'pot-force-delete': async id => {
    if (!confirm(t('confirm.potForceDelete'))) return;
    await remove(`/honeypots/${id}?force=true`);
    toast(t('notifications.potDeleted'));
    navigate('honeypots');
    await rerender();
  },
  'inventory-reset': async () => { document.querySelector('#inventory-filters')?.remove(); Object.assign(state.inventory, {q: '', status: [], service: [], host: [], sort: 'name', order: 'asc', page: 1}); await rerender(); },
  'inventory-page': async page => { state.inventory.page = Number(page); await rerender(); },
  'deployment-log': async id => {
    const logs = await api(`/deployments/${id}/logs`);
    openDialog(t('monitor.logTitle'), table([t('common.time'), t('monitor.level'), t('monitor.step')], logRows(logs), t('monitor.noLog')));
  },
});


pages.profiles = async () => heading(t('profiles.title'), t('profiles.description'), admin() ? button(t('profiles.create'), 'profile-new', '', 'primary') : '') +
  panel(t('profiles.list'), table([t('common.profile'), t('pots.type'), t('profiles.defaultPort'), t('common.version'), t('profiles.instances'), t('common.state'), t('common.actions')],
    state.profiles.map(p => `<tr><td><strong>${esc(p.name)}</strong><br><small>${esc(p.spec.description)}</small></td>` +
      `<td>${esc(serviceName(p.service_key))}<br><small>${esc(label('interaction', p.interaction_level))}</small></td><td class="mono">${p.spec.port}</td><td>v${p.version}</td>` +
      `<td>${formatNumber(p.instances)}</td><td>${p.spec.enabled ? t('common.enabled') : t('common.disabled')}</td><td><div class="actions">` +
      button(admin() ? t('common.edit') : t('common.view'), 'profile-edit', p.id, 'ghost') +
      (admin() ? button(t('profiles.createPot'), 'profile-use', p.id) + button(t('common.duplicate'), 'profile-duplicate', p.id) + button(t('common.delete'), 'profile-delete', p.id, 'danger') : '') +
      `</div></td></tr>`))) + `<p class="hint">${t('profiles.libraryHint')}</p>`;

async function profileEditor(id, serviceKey) {
  const existing = state.profiles.find(profile => profile.id === id);
  const key = existing?.service_key || serviceKey || 'tcp-banner';
  const service = plugin(key);
  const draft = existing ? clone(existing.spec) : {...(await api('/service-types/' + key)).defaults, name: ''};
  if (!admin()) return openDialog(existing.name, detailList({service_key: key, interaction_level: existing.interaction_level, port: existing.spec.port}) + rawDetails(existing.spec, t('profiles.preview')));
  openEditor(draft, service);
  const chooser = existing ? '' : selectField('service_key', t('wizard.service'), state.services.map(item => [item.key, item.display_name]), key, 'data-profile-service="1"');
  openDialog(existing ? t('profiles.editTitle', {version: formatNumber(existing.version)}) : t('profiles.createTitle'),
    `<form id="profile-form" data-id="${esc(id || '')}"><div class="form-section"><h3>${t('profiles.general')}</h3><div class="form-grid">` +
    `<label>${t('profiles.name')}<input aria-label="${esc(t('profiles.name'))}" data-path="name" data-kind="text" value="${esc(draft.name)}" required maxlength="80"></label>${chooser}</div>` +
    fieldGrid(['description', 'port', 'enabled'], draft, service) +
    (existing && existing.instances ? `<p class="hint">${t('profiles.inUseHint', {count: formatNumber(existing.instances)})}</p>` : '') + `</div>` +
    `<div class="form-section"><h3>${esc(service.display_name)}</h3>${fieldGrid([...serviceSection(service.key, service.emulator), ...SECTIONS.behaviour], draft, service)}</div>` +
    (service.emulator === 'http' ? `<div id="spec-site">${siteEditor()}</div>` : '') +
    `<div class="form-section"><h3>${t('profiles.telemetry')}</h3>${fieldGrid(SECTIONS.monitoring, draft, service)}</div>` +
    `<div class="form-section"><h3>${t('profiles.resources')}</h3><p class="hint">${t('profiles.resourceHint')}</p>${fieldGrid(SECTIONS.resources, draft, service)}</div>` +
    `<details><summary>${t('profiles.preview')}</summary><pre id="profile-preview"></pre></details>` +
    `<div class="dialog-footer"><button class="primary">${t('profiles.save')}</button></div></form>`);
  previewProfile();
}
function previewProfile() {
  const form = document.querySelector('#profile-form');
  if (form) document.querySelector('#profile-preview').textContent = JSON.stringify(syncDraft(form), null, 2);
}
document.addEventListener('input', event => { if (event.target.closest('#profile-form')) previewProfile(); });
document.addEventListener('change', async event => {
  if (event.target.dataset?.profileService) await profileEditor(null, event.target.value);
});
forms['profile-form'] = async form => {
  const draft = syncDraft(form);
  const problem = draftProblems(draft)[0];
  if (problem) throw new Error(problem);
  const id = form.dataset.id;
  await api('/profiles' + (id ? '/' + id : ''), {method: id ? 'PATCH' : 'POST', body: JSON.stringify(draft)});
  toast(t('notifications.profileSaved'));
};
Object.assign(actions, {
  'profile-new': id => profileEditor(null, id || undefined),
  'profile-edit': id => profileEditor(id),
  'profile-use': id => startWizard(id),
  'profile-duplicate': async id => { await post(`/profiles/${id}/duplicate`); toast(t('notifications.profileDuplicated')); await rerender(); },
  'profile-delete': async id => {
    if (!confirm(t('confirm.profileDelete'))) return;
    await remove('/profiles/' + id);
    toast(t('notifications.profileDeleted'));
    await rerender();
  },
});


pages.catalog = async () => heading(t('navigation.catalog'), t('catalog.description')) +
  panel(t('catalog.available'), `<div class="cards catalog-cards">${state.services.map(service => `<details class="card catalog-service" data-service="${esc(service.key)}" ${prefs.catalogOpen.includes(service.key) ? 'open' : ''}><summary class="card-head"><h2>${esc(service.display_name)}</h2>${badge(service.interaction_level, 'interaction')}${icon('chevron')}</summary><div class="catalog-service-body">` +
    `<p>${esc(service.description)}</p>` + keyValues([
      [t('events.protocol'), esc(service.protocol)], [t('profiles.defaultPort'), esc(service.default_port)],
      [t('catalog.events'), esc(service.event_types.map(type => label('event', type)).join(', '))],
      [t('catalog.runtime'), esc(t('catalog.runtimeValue', {memory: formatNumber(service.runtime.memory_mb), cpu: formatNumber(service.runtime.cpu_limit), containers: service.runtime.containers}))],
      [t('catalog.health'), esc(service.health_check)],
      [t('catalog.instances'), formatNumber(state.pots.filter(pot => pot.service_key === service.key).length)],
    ]) + `<h3>${t('catalog.capabilities')}</h3><ul>${service.capabilities.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` +
    `<h3>${t('catalog.options')}</h3><p class="hint">${esc(service.fields.filter(name => !['pages', 'routes'].includes(name)).map(name => tk('fields', name)).join(' · '))}` +
    `${service.fields.includes('routes') ? ' · ' + esc(t('pageBuilder.heading')) + ' · ' + esc(t('routes.heading')) : ''}</p>` +
    (admin() ? `<div class="actions">${button(t('pots.create'), 'service-use', service.key, 'primary')}${button(t('profiles.create'), 'profile-new', service.key)}</div>` : '') +
    `</div></details>`).join('')}</div><p class="hint panel-body">${t('catalog.hint')}</p>`);
actions['service-use'] = key => startWizard(key);
document.addEventListener('toggle', event => {
  const node = event.target;
  if (!node.matches?.('details.catalog-service[data-service]') || !node.isConnected) return;
  const current = prefs.catalogOpen.filter(key => key !== node.dataset.service);
  applyPrefs({catalogOpen: node.open ? [...current, node.dataset.service] : current});
}, true);


function agentsPanel(agents) {
  if (!admin()) return '';
  return panel(t('enrollment.title'), table([t('enrollment.agent'), t('common.honeypot'), t('enrollment.registration'), t('enrollment.access'), t('enrollment.action')],
    agents.map(a => `<tr><td class="mono">${esc(a.id)}</td><td>${esc(a.honeypot_name || '—')}</td><td>${a.last_seen ? esc(formatDate(a.last_seen)) : t('enrollment.waiting')}</td>` +
      `<td>${badge(a.retired ? 'retired' : a.approved ? 'approved' : 'revoked')}</td>` +
      `<td>${a.retired ? '' : a.approved ? button(t('enrollment.revoke'), 'agent-revoke', a.id, 'danger') : button(t('enrollment.approve'), 'agent-approve', a.id)}</td></tr>`))) +
    `<p class="hint">${t('enrollment.hint')}</p>`;
}
pages.deployments = async () => {
  const [deployments, agents] = await Promise.all([api('/deployments'), admin() ? api('/agent-enrollments') : []]);
  const active = state.pots.filter(pot => TRANSITIONAL.includes(pot.status) || pot.status === 'failed');
  const progress = table([t('common.honeypot'), t('common.state'), t('common.generation'), t('monitor.since'), t('common.error'), ''], active.map(pot =>
    `<tr><td><a href="#honeypot/${esc(pot.id)}">${esc(pot.name)}</a></td><td>${badge(pot.status)}</td><td>${pot.applied_generation} / ${pot.generation}</td>` +
    `<td>${esc(relativeTime(pot.transition_at || pot.updated_at))}</td><td>${esc(pot.error ? safeError(pot.error) : '—')}</td><td>${button(t('common.details'), 'pot-open', pot.id)}</td></tr>`), t('monitor.idle'));
  const history = table([t('deployments.started'), t('common.honeypot'), t('common.host'), t('common.status'), t('monitor.completed'), t('common.error'), ''], deployments.map(d =>
    `<tr><td>${esc(formatDate(d.started_at))}</td><td><a href="#honeypot/${esc(d.honeypot_id)}">${esc(potName(d.honeypot_id))}</a></td><td>${esc(d.host_id)}</td><td>${badge(d.status)}</td>` +
    `<td>${esc(formatDate(d.completed_at))}</td><td>${esc(d.error_message ? safeError(d.error_message) : '—')}</td>` +
    `<td><div class="actions">${button(t('monitor.log'), 'deployment-log', d.id)}${admin() && d.status === 'pending' ? button(t('deployments.stop'), 'deployment-cancel', d.id) : ''}</div></td></tr>`));
  return heading(t('monitor.title'), t('monitor.description'), admin() ? button(t('pots.create'), 'pot-new', '', 'primary') : '') +
    panel(t('monitor.inProgress'), progress) + panel(t('deployments.history'), history) + agentsPanel(agents);
};
Object.assign(actions, {
  'agent-approve': async id => {
    if (!confirm(t('confirm.agentApprove', {id}))) return;
    await patch('/agent-enrollments/' + id, {approved: true});
    toast(t('notifications.agentApproved'));
    await rerender();
  },
  'agent-revoke': async id => {
    if (!confirm(t('confirm.agentRevoke', {id}))) return;
    await patch('/agent-enrollments/' + id, {approved: false});
    toast(t('notifications.agentRevoked'));
    await rerender();
  },
  'deployment-cancel': async id => { if (confirm(t('confirm.deploymentStop'))) { await post(`/deployments/${id}/cancel`); await rerender(); } },
});


pages.resources = async () => {
  const endpoints = await api('/network-endpoints');
  const hosts = state.hosts.map(host => {
    const {policy, allocated, observed} = host.capacity;
    const ports = policy.port_range_end - policy.port_range_start + 1;
    const measured = observed.ncpu ? keyValues([
      [t('resources.dockerVersion'), esc(observed.version)], [t('resources.hostCpu'), formatNumber(observed.ncpu)],
      [t('resources.hostMemory'), `${megabytes(observed.memory_bytes)} ${t('units.mb')}`],
      [t('resources.runningContainers'), formatNumber(observed.containers_running)],
      [t('resources.managedContainers'), formatNumber(observed.managed_containers ?? 0)],
      [t('resources.lastReport'), esc(formatDate(observed.reported_at))]]) : `<p class="hint">${t('resources.noReport')}</p>`;
    return panel(esc(host.name), `<div class="panel-body"><div class="meters">` +
      meter(t('resources.instances'), allocated.instances, policy.max_instances) + meter(t('resources.cpu'), allocated.cpu, policy.cpu_budget) +
      meter(t('resources.memory'), allocated.memory_mb, policy.memory_budget_mb, t('units.mb')) + meter(t('resources.endpoints'), allocated.endpoints, ports) + `</div>` +
      keyValues([[t('resources.running'), formatNumber(allocated.running)], [t('resources.failed'), formatNumber(allocated.failed)],
        [t('resources.portRange'), `${policy.port_range_start}–${policy.port_range_end}`], [t('wizard.network'), esc(t('wizard.networkValue', {name: host.network}))]]) +
      `<h3>${t('resources.observed')}</h3>${measured}</div>`,
      `${badge(host.controller_connected ? 'connected' : 'disconnected')}${admin() ? button(t('resources.editPolicy'), 'host-edit', host.id) : ''}`);
  }).join('');
  const usage = table([t('common.honeypot'), t('common.state'), t('pots.memoryUse'), t('pots.cpuUse'), t('pots.limits')],
    state.pots.filter(pot => pot.deployed).map(pot => {
      const stats = pot.runtime?.stats;
      return `<tr><td><a href="#honeypot/${esc(pot.id)}">${esc(pot.name)}</a></td><td>${badge(pot.status)}</td>` +
        `<td>${stats ? megabytes(stats.memory_bytes) + ' ' + t('units.mb') : '—'}</td><td>${stats ? formatNumber(stats.cpu_percent) + ' %' : '—'}</td>` +
        `<td>${formatNumber(pot.configuration.memory_mb)} ${t('units.mb')} · ${formatNumber(pot.configuration.cpu_limit)} ${t('units.cores')}</td></tr>`;
    }), t('pots.empty'));
  const allocated = table([t('pots.endpoint'), t('common.honeypot'), t('common.host'), t('wizard.network'), t('wizard.allocation'), t('resources.publication')],
    endpoints.map(e => `<tr><td class="mono">${esc(e.address)}</td><td><a href="#honeypot/${esc(e.honeypot_id)}">${esc(e.honeypot_name)}</a></td><td>${esc(e.host_id)}</td>` +
      `<td>${esc(e.network)}</td><td>${esc(label('portMode', e.mode))}</td><td>${e.published_port ? formatNumber(e.published_port) : t('resources.notPublished')}</td></tr>`));
  return heading(t('navigation.resources'), t('resources.description')) + (hosts || empty(t('wizard.noHosts'))) +
    panel(t('resources.usage'), usage) + panel(t('resources.allocatedEndpoints'), allocated) + `<p class="hint">${t('resources.hint')}</p>`;
};
actions['host-edit'] = id => {
  const host = state.hosts.find(item => item.id === id);
  const policy = host.capacity.policy;
  openDialog(t('resources.policyTitle', {name: host.name}), `<form id="host-policy" data-id="${esc(id)}"><div class="form-grid">` +
    formField('max_instances', t('resources.maxInstances'), policy.max_instances, 'number', 'min="0" max="200" required') +
    formField('cpu_budget', t('resources.cpuBudget'), policy.cpu_budget, 'number', 'min="0" max="256" step="0.25" required') +
    formField('memory_budget_mb', t('resources.memoryBudget'), policy.memory_budget_mb, 'number', 'min="0" max="1048576" required') +
    formField('port_range_start', t('resources.portStart'), policy.port_range_start, 'number', 'min="1024" max="65535" required') +
    formField('port_range_end', t('resources.portEnd'), policy.port_range_end, 'number', 'min="1024" max="65535" required') +
    `</div><p class="hint">${t('resources.policyHint')}</p><button class="primary">${t('resources.savePolicy')}</button></form>`);
};
forms['host-policy'] = async (form, data) => {
  await patch('/hosts/' + form.dataset.id, Object.fromEntries(Object.entries(data).map(([key, value]) => [key, Number(value)])));
  toast(t('resources.policySaved'));
};
