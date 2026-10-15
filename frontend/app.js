import {t, tk, label, plural, formatDate, formatNumber, safeError, esc, state, pages, actions, forms, root, modal, setRefresh, api, post,
  toast, badge, button, panel, heading, table, empty, formField, selectField, checkField, openDialog, detailValue, detailList,
  rawDetails, keyValues, admin, canOperate, potName, navigate, download, icon, hydrate, prefs, applyPrefs, effectiveTheme, afterRender, smoothly, still} from './ui.js';
import './specform.js';
import './constructor.js';
import './inventory.js';
import './insights.js';
import {live as monitorLive} from './monitor.js';
import {describeEvent} from './insights.js';
import './snake.js';

const NAVIGATION = [
  ['monitoring', ['dashboard', 'events', 'analytics', 'alerts']],
  ['honeypots', ['honeypots', 'constructor', 'profiles', 'catalog']],
  ['infrastructure', ['deployments', 'resources']],
  ['system', ['audit', 'settings']],
];
const ADMIN_ONLY = ['audit', 'constructor'];
const NO_LIVE_REFRESH = ['constructor'];
const EVENT_TYPES = ['connection', 'data_received', 'http_request', 'authentication_attempt', 'navigation'];
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const date = formatDate;
const clock = new Intl.DateTimeFormat('ru-RU', {hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false});
const SECTION_OF = {honeypot: 'honeypots', session: 'events', source: 'events', report: 'analytics'};
const currentSection = () => SECTION_OF[state.page] || state.page;
let refreshTimer, reconnectTimer, enterTimer, renderVersion = 0;


function loginPage() {
  document.title = t('auth.title');
  root.innerHTML = `<div class="login"><section class="login-card glass"><div class="brand"><img class="brand-mark" src="/assets/logo.jpg" alt="" width="34" height="34"><span class="brand-name">HoneyForge</span></div>` +
    `<p class="login-tagline">${t('auth.tagline')}</p><h1>${t('auth.title')}</h1><p>${t('auth.intro')}</p><form id="login-form">` +
    formField('username', t('auth.username'), '', 'text', 'required autocomplete="username"') +
    formField('password', t('auth.password'), '', 'password', 'required autocomplete="current-password"') +
    `<div id="login-error" role="alert"></div><button class="primary">${t('auth.signIn')}</button></form><p class="hint">${t('auth.accountsHint')}</p></section></div>`;
  hydrate(root);
}
function shell() {
  const current = currentSection();
  const groups = NAVIGATION.map(([group, items]) => {
    const links = items.filter(id => !ADMIN_ONLY.includes(id) || admin()).map(id =>
      `<a href="#${id}" class="${current === id ? 'selected' : ''}" ${current === id ? 'aria-current="page"' : ''} title="${esc(tk('navigation', id))}">${icon(id)}<span>${esc(tk('navigation', id))}</span></a>`).join('');
    const folded = prefs.navCollapsed.includes(group);
    return `<div class="nav-group${folded ? ' folded' : ''}" data-nav-group="${group}"><div class="nav-group-heading"><a class="nav-label" href="#section/${group}" aria-label="${esc(t('shell.openSection', {section: tk('shell.groups', group)}))}">${esc(tk('shell.groups', group))}</a>` +
      `<button type="button" class="ghost icon-button nav-group-toggle" data-action="nav-group-toggle" data-id="${group}" aria-expanded="${!folded}" aria-label="${esc(t(folded ? 'panels.expand' : 'panels.collapse') + ': ' + tk('shell.groups', group))}">${icon('chevron')}</button></div><div class="nav-group-links" ${folded ? 'hidden' : ''}>${links}</div></div>`;
  }).join('');
  const group = state.page === 'section' ? state.param : NAVIGATION.find(([, items]) => items.includes(current))?.[0];
  const crumbs = `<nav class="crumb" aria-label="${esc(t('shell.breadcrumbLabel'))}"><a href="#section/${group || 'monitoring'}" aria-label="${esc(t('shell.openSection', {section: tk('shell.groups', group || 'monitoring')}))}">${esc(tk('shell.groups', group || 'monitoring'))}</a>` +
    (state.page === 'section' ? '' : `<span aria-hidden="true">/</span><span aria-current="page">${esc(tk('navigation', current))}</span>`) + `</nav>`;
  const environment = state.system?.mode === 'development-preview' ? t('common.preview') : t('shell.isolated');
  root.innerHTML = `<div class="shell"><aside class="sidebar" id="sidebar"><div class="brand"><img class="brand-mark" src="/assets/logo.jpg" alt="" width="34" height="34"><span class="brand-name">HoneyForge</span></div>` +
    `<nav aria-label="${esc(t('shell.navigation'))}">${groups}</nav>` +
    `<div class="sidebar-foot"><div class="environment"><i aria-hidden="true"></i><span>${esc(environment)}</span></div>` +
    `<button type="button" class="ghost with-icon collapse-toggle" data-action="sidebar-toggle" aria-label="${esc(t('shell.collapse'))}" title="${esc(t('shell.collapse'))}">${icon('collapse')}<span>${t('shell.collapse')}</span></button>` +
    `<small>HoneyForge v${esc(state.system?.version || '')}</small></div></aside>` +
    `<button type="button" class="scrim" data-action="nav-close" aria-label="${esc(t('shell.closeMenu'))}"></button>` +
    `<main class="main"><header class="topbar"><button type="button" class="icon-button nav-toggle" data-action="nav-open" aria-label="${esc(t('shell.openMenu'))}">${icon('menu')}</button>` +
    `${crumbs}<div class="topbar-right">` +
    `<span id="last-event" class="topbar-note"></span><span id="connection" class="connection"></span>` +
    `<button type="button" id="theme-toggle" class="icon-button" data-action="theme-toggle">${themeIcon()}</button>` +
    `<a id="bell" class="icon-button" href="#alerts">${icon('bell')}</a>` +
    `<div class="user-menu"><button type="button" class="user-button" data-action="user-menu" aria-haspopup="true" aria-expanded="false">` +
    `<span class="avatar">${esc(state.user.username.slice(0, 1).toUpperCase())}</span><span class="user-text"><strong>${esc(state.user.username)}</strong><small>${esc(label('role', state.user.role))}</small></span></button>` +
    `<div class="menu" id="user-menu" hidden><a href="#settings">${t('navigation.settings')}</a>${button(t('auth.signOut'), 'logout', '', 'ghost')}</div></div>` +
    `</div></header><div id="danger-strip" class="danger-strip" role="alert" hidden></div>` +
    `<div id="content" class="content">${empty(t('common.loading'))}</div></main></div>`;
  connectionText();
  bell();
}
async function loadRegistry() {
  [state.profiles, state.pots, state.hosts, state.services] = await Promise.all([api('/profiles'), api('/honeypots'), api('/hosts'), api('/service-types')]);
}
async function render(quiet = false) {
  if (!state.user) return;
  const version = ++renderVersion;
  if (!quiet || !document.querySelector('#content')) shell();
  document.title = 'HoneyForge — ' + (state.page === 'section' ? tk('shell.groups', state.param || 'monitoring') : tk('titles', currentSection()));
  try {
    await loadRegistry();
    const output = await pages[state.page]();
    if (version !== renderVersion || !state.user) return;
    const content = document.querySelector('#content');
    const filter = quiet ? content.querySelector('form[data-auto-filter]') : null;
    const focused = filter?.contains(document.activeElement) ? document.activeElement : null;
    const fragment = document.createElement('template');
    fragment.innerHTML = output;
    const replacement = filter && fragment.content.querySelector('form[data-auto-filter]');
    if (filter && replacement?.id === filter.id) replacement.replaceWith(filter);
    content.replaceChildren(fragment.content);
    focused?.focus({preventScroll: true});
    if (!quiet && !still()) {
      content.classList.remove('entering');
      void content.offsetWidth;
      content.classList.add('entering');
      clearTimeout(enterTimer);
      enterTimer = setTimeout(() => content.classList.remove('entering'), 1100);
    }
    hydrate(content);
  } catch (error) {
    if (version === renderVersion && document.querySelector('#content'))
      document.querySelector('#content').innerHTML = `<div class="error-banner" role="alert">${esc(safeError(error))}</div>${button(t('common.retry'), 'refresh')}`;
  }
}
setRefresh(render);

pages.section = async () => {
  const [group, items] = NAVIGATION.find(([id]) => id === state.param) || NAVIGATION[0];
  return heading(esc(tk('shell.groups', group)), t('shell.sectionDescription')) + `<div class="section-links">` +
    items.filter(id => !ADMIN_ONLY.includes(id) || admin()).map(id => `<a class="card section-link" href="#${id}">${icon(id)}<strong>${esc(tk('navigation', id))}</strong>${icon('expand')}</a>`).join('') + `</div>`;
};

function route() {
  const [page, ...rest] = location.hash.slice(1).split('/');
  state.page = page in pages ? page : 'dashboard';
  state.param = rest.join('/') || null;
  document.documentElement.classList.remove('nav-open');
}
function signedOut() {
  state.user = null;
  state.ws?.close();
  loginPage();
}
document.addEventListener('session-expired', signedOut);

function connectionText() {
  const node = document.querySelector('#connection');
  if (!node) return;
  node.className = 'connection ' + (state.connected ? 'on' : 'off');
  node.innerHTML = `<i aria-hidden="true"></i>${esc(state.connected ? t('shell.connected') : t('shell.reconnecting'))}`;
}
async function bell() {
  const node = document.querySelector('#bell');
  if (!node) return;
  let open = null;
  try {
    open = (await api('/alerts/summary')).open;
  } catch {   }
  node.setAttribute('aria-label', open === null ? t('shell.alertsUnknown') : t('shell.alertsOpen', {count: formatNumber(open)}));
  node.title = node.getAttribute('aria-label');
  node.innerHTML = icon('bell') + (open ? `<b class="count">${formatNumber(open)}</b>` : '');
}
function liveRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    if (modal.open || NO_LIVE_REFRESH.includes(state.page) || document.querySelector('#content form:focus-within')) return;
    render(true);
  }, 300);
}
function connect() {
  clearTimeout(reconnectTimer);
  if (!state.user) return;
  const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/v1/ws`);
  state.ws = socket;
  socket.onopen = () => {
    const restored = state.wasConnected;
    state.connected = state.wasConnected = true;
    connectionText();
    if (!monitorLive({type: restored ? 'reconnected' : 'status'}) && restored) liveRefresh();
  };
  socket.onmessage = event => {
    let message;
    try { message = JSON.parse(event.data); } catch { return; }
    if (!message || message.type === 'heartbeat' || message.type === 'connected') return;
    if (message.type === 'alert') {
      toast(message.name ? t('notifications.alertFor', {name: message.name}) : t('notifications.alert'), true);
      bell();
    }
    if (message.type === 'events') {
      const note = document.querySelector('#last-event');
      if (note) note.textContent = t('shell.lastEvent', {time: clock.format(new Date())});
    }
    if (!monitorLive(message)) liveRefresh();
  };
  socket.onclose = () => {
    state.connected = false;
    connectionText();
    monitorLive({type: 'status'});
    if (state.user) reconnectTimer = setTimeout(connect, 3000);
  };
}


function eventTable(events) {
  return table([t('events.id'), t('common.time'), t('common.honeypot'), t('common.source'), t('common.service'), t('common.eventType'), t('common.severity'), ''],
    events.map(e => `<tr><td class="mono">${e.id}</td><td class="mono">${esc(date(e.timestamp))}</td><td>${esc(potName(e.honeypot_id))}</td>` +
      `<td><a class="mono" href="#source/${encodeURIComponent(e.source_ip)}">${esc(e.source_ip)}</a><small class="mono">:${e.source_port}</small></td><td>${esc(e.protocol)} :${e.destination_port}</td>` +
      `<td class="event-description">${esc(describeEvent(e))}<br><small>${esc(label('event', e.event_type))}</small></td><td>${badge(e.severity, 'severity')}</td>` +
      `<td><div class="actions">${button(t('common.inspect'), 'event', e.id, 'ghost')}<a href="#session/${esc(e.honeypot_id)}/${esc(e.session_id)}">${t('session.open')}</a></div></td></tr>`), t('events.empty'));
}
function filterForm() {
  const f = state.filters;
  return `<form id="filters" class="filters" data-auto-filter>` +
    selectField('honeypot_id', t('common.honeypot'), [['', t('events.allPots')], ...state.pots.map(p => [p.id, p.name])], f.honeypot_id) +
    selectField('interaction_level', t('common.interaction'), [['', t('events.allLevels')], ['low', t('events.low')], ['medium', t('events.medium')], ['high', t('events.high')]], f.interaction_level) +
    selectField('protocol', t('events.protocol'), [['', t('events.allProtocols')], ['TCP', 'TCP'], ['HTTP', 'HTTP']], f.protocol) +
    selectField('event_type', t('common.eventType'), [['', t('events.allTypes')], ...EVENT_TYPES.map(x => [x, label('event', x)])], f.event_type) +
    selectField('severity', t('common.severity'), [['', t('events.allSeverities')], ...SEVERITIES.map(x => [x, label('severity', x)])], f.severity) +
    formField('source_ip', t('events.sourceIp'), f.source_ip) + formField('q', t('events.search'), f.q) +
    formField('start', t('events.from'), f.start, 'datetime-local') + formField('end', t('events.until'), f.end, 'datetime-local') +
    selectField('order', t('events.sort'), [['desc', t('events.newest')], ['asc', t('events.oldest')]], f.order || 'desc') +
    `${button(t('common.reset'), 'filters-reset', '', 'ghost')}</form>`;
}
function eventQuery() {
  const f = {...state.filters, page: state.eventPage};
  for (const key of ['start', 'end']) if (f[key]) f[key] = new Date(f[key]).toISOString();
  return new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString();
}
pages.events = async () => {
  const data = await api('/events?' + eventQuery());
  const pagesTotal = Math.max(1, Math.ceil(data.total / data.page_size));
  return heading(t('events.pageTitle'), t('events.description'), canOperate() ? button(t('events.csv'), 'csv') + button(t('events.ioc'), 'ioc') : '') +
    `<section class="panel events-panel">${filterForm()}${eventTable(data.items)}<div class="pagination"><span>${t('events.pagination', {events: plural('counts.events', data.total), page: formatNumber(data.page), pages: formatNumber(pagesTotal)})}</span>` +
    `<div class="actions">${state.eventPage > 1 ? button(t('common.previousArrow'), 'event-prev') : ''}${state.eventPage * data.page_size < data.total ? button(t('common.nextArrow'), 'event-next') : ''}</div></div></section>`;
};
forms.filters = async (form, data) => { state.filters = data; state.eventPage = 1; await render(true); };


pages.alerts = async () => {
  const [alerts, rules, totals] = await Promise.all([api('/alerts'), api('/alerts/rules'), api('/alerts/summary')]);
  state.rules = rules;
  const count = status => totals[status];
  const severe = SEVERITIES.map(level => ({label: level, count: alerts.filter(alert => alert.severity === level && alert.status !== 'resolved').length})).filter(row => row.count);
  const summaryTiles = `<div class="tiles three"><div class="tile"><span>${t('alerts.open')}</span><strong>${formatNumber(count('open'))}</strong></div>` +
    `<div class="tile"><span>${t('alerts.acknowledged')}</span><strong>${formatNumber(count('acknowledged'))}</strong></div>` +
    `<div class="tile"><span>${t('alerts.resolved')}</span><strong>${formatNumber(count('resolved'))}</strong></div></div>` +
    (severe.length ? `<p class="hint">${t('alerts.activeBySeverity')} ${severe.map(row => `${badge(row.label, 'severity')} ${formatNumber(row.count)}`).join(' · ')}</p>` : '');
  const history = table([t('alerts.triggered'), t('common.honeypot'), t('alerts.evidence'), t('common.severity'), t('common.state'), t('common.actions')], alerts.map(a =>
    `<tr><td class="mono">${esc(date(a.triggered_at))}</td><td>${esc(potName(a.honeypot_id))}</td><td>${esc(a.details.rule)}<br><small>${t('alerts.observations', {count: plural('counts.observations', a.details.count), seconds: plural('counts.seconds', a.details.window_seconds)})}</small></td>` +
    `<td>${badge(a.severity, 'severity')}</td><td>${badge(a.status)}</td><td><div class="actions">${button(t('alerts.evidence'), 'alert-evidence', a.id, 'ghost')}` +
    `${canOperate() && a.status === 'open' ? button(t('alerts.acknowledge'), 'alert-ack', a.id) : ''}${canOperate() && a.status !== 'resolved' ? button(t('alerts.resolve'), 'alert-resolve', a.id) : ''}</div></td></tr>`), t(rules.some(rule => rule.enabled) ? 'alerts.noMatches' : 'alerts.noRules'));
  const list = table([t('alerts.rule'), t('alerts.condition'), t('alerts.window'), t('common.scope'), t('common.state'), ''], rules.map(r =>
    `<tr><td>${esc(r.name)}${r.system ? `<br><small>${t('alerts.systemRule')}</small>` : ''}</td><td>${esc(label('event', r.event_type))}${r.system ? '' : ' ≥ ' + r.threshold}</td><td>${r.system ? t('alerts.untilRecovery') : plural('counts.seconds', r.window_seconds)}</td>` +
    `<td>${r.honeypot_id ? esc(potName(r.honeypot_id)) : t('events.allPots')}</td><td>${r.enabled ? t('common.enabled') : t('common.disabled')}</td>` +
    `<td><div class="actions">${admin() ? button(t('common.edit'), 'rule-edit', r.id, 'ghost') + button(t('common.delete'), 'rule-delete', r.id, 'danger') : ''}</div></td></tr>`));
  return heading(t('navigation.alerts'), t('alerts.description'), admin() ? button(t('alerts.create'), 'rule-new', '', 'primary') : '') +
    panel(t('alerts.summary'), `<div class="panel-body">${summaryTiles}</div>`) + panel(t('alerts.history'), history) + panel(t('alerts.rules'), list);
};
function ruleForm(id) {
  const r = state.rules?.find(x => x.id === id) || {name: t('alerts.defaultName'), event_type: 'authentication_attempt', threshold: 10, window_seconds: 60, severity: 'medium', enabled: true};
  openDialog(id ? t('alerts.edit') : t('alerts.createTitle'), `<form id="rule-form" data-id="${esc(id || '')}">${formField('name', t('alerts.name'), r.name, 'text', 'required')}<div class="form-grid">` +
    (r.system ? `<p class="notice full">${esc(t('alerts.systemCondition', {condition: label('event', r.event_type)}))}</p>` :
    selectField('event_type', t('common.eventType'), [...EVENT_TYPES, 'offline', 'queue_backlog'].map(x => [x, label('event', x)]), r.event_type) +
    selectField('honeypot_id', t('common.scope'), [['', t('events.allPots')], ...state.pots.map(p => [p.id, p.name])], r.honeypot_id || '') +
    formField('threshold', t('alerts.threshold'), r.threshold, 'number', 'min="1" max="100000" required') +
    formField('window_seconds', t('alerts.windowSeconds'), r.window_seconds, 'number', 'min="10" max="86400" required')) +
    selectField('severity', t('common.severity'), SEVERITIES.map(x => [x, label('severity', x)]), r.severity) + checkField('enabled', t('common.enabled'), r.enabled) +
    `</div><button class="primary">${t('alerts.save')}</button></form>`);
}
forms['rule-form'] = async (form, data) => {
  const id = form.dataset.id;
  const previous = state.rules?.find(rule => rule.id === id);
  const body = {...data, event_type: data.event_type || previous?.event_type, threshold: Number(data.threshold ?? previous?.threshold),
    window_seconds: Number(data.window_seconds ?? previous?.window_seconds), enabled: form.elements.enabled.checked, honeypot_id: data.honeypot_id || null};
  await api('/alerts/rules' + (id ? '/' + id : ''), {method: id ? 'PATCH' : 'POST', body: JSON.stringify(body)});
  toast(t('notifications.ruleSaved'));
};


pages.audit = async () => {
  if (!admin()) return empty(t('errors.adminRequired'));
  const data = await api('/audit?page=' + state.auditPage);
  const details = value => Object.keys(value || {}).length ? `<code>${esc(JSON.stringify(value))}</code>` : '—';
  const rows = data.items.map(a => `<tr><td class="mono">${esc(date(a.timestamp))}</td><td class="mono">${esc(a.actor)}</td><td>${esc(label('audit', a.action))}</td>` +
    `<td class="mono">${esc(a.resource)}</td><td>${badge(a.result)}</td><td class="details-cell">${details(a.details)}</td></tr>`);
  return heading(t('navigation.audit'), t('audit.description')) + panel(t('audit.history'),
    table([t('common.timestamp'), t('audit.actor'), t('common.operation'), t('common.resource'), t('common.result'), t('common.details')], rows) +
    `<div class="pagination"><span>${t('audit.pagination', {operations: plural('counts.operations', data.total), page: formatNumber(state.auditPage)})}</span><div class="actions">` +
    `${state.auditPage > 1 ? button(t('common.previous'), 'audit-prev') : ''}${state.auditPage * 50 < data.total ? button(t('common.next'), 'audit-next') : ''}</div></div>`);
};
pages.settings = async () => {
  const config = await api('/settings');
  const users = admin() ? await api('/users') : [];
  state.users = users;
  const system = keyValues(Object.entries(config).map(([k, v]) => [label('field', k), esc(detailValue(k, v))]));
  const account = keyValues([[t('auth.username'), esc(state.user.username)], [t('settings.role'), esc(label('role', state.user.role))]]) +
    `<form id="password-form">${formField('current_password', t('settings.currentPassword'), '', 'password', 'required autocomplete="current-password"')}` +
    `${formField('new_password', t('settings.newPassword'), '', 'password', 'required minlength="12" autocomplete="new-password"')}` +
    `${formField('confirm_password', t('settings.confirmPassword'), '', 'password', 'required minlength="12" autocomplete="new-password"')}<button class="secondary">${t('settings.updatePassword')}</button></form>`;
  const appearance = `<form id="interface-form">` +
    selectField('theme', t('settings.theme'), ['system', 'light', 'dark'].map(value => [value, tk('settings', 'theme_' + value)]), prefs.theme) +
    `${checkField('reducedEffects', t('settings.reducedEffects'), prefs.reducedEffects)}` +
    `${checkField('compact', t('settings.compact'), prefs.compact)}<p class="hint">${t('settings.interfaceHint')}</p><button class="secondary">${t('settings.saveInterface')}</button></form>`;
  const accounts = admin() ? panel(t('settings.users'), table([t('auth.username'), t('settings.role'), t('common.state'), ''], users.map(u =>
    `<tr><td>${esc(u.username)}</td><td>${esc(label('role', u.role))}</td><td>${badge(u.is_active ? 'active' : 'disabled')}</td>` +
    `<td>${u.id !== state.user.id ? button(t('settings.editAccess'), 'user-edit', u.id, 'ghost') : t('settings.currentAccount')}</td></tr>`)), button(t('settings.addUser'), 'user-new')) : '';
  return heading(t('navigation.settings'), t('settings.description')) +
    `<div class="settings-layout"><div>${panel(t('settings.profile'), `<div class="panel-body">${account}</div>`)}${accounts}</div>` +
    `<div>${panel(t('settings.interface'), `<div class="panel-body">${appearance}</div>`)}${panel(t('settings.system'), `<div class="panel-body">${system}<p class="hint">${t('settings.tlsHint')}</p></div>`)}</div></div>`;
};
forms['password-form'] = async (form, data) => {
  if (data.new_password !== data.confirm_password) {
    form.elements.confirm_password.setCustomValidity(t('settings.passwordMismatch'));
    form.elements.confirm_password.reportValidity();
    return 'stay';
  }
  await post('/auth/password', {current_password: data.current_password, new_password: data.new_password});
  signedOut(); toast(t('notifications.password')); return 'stay';
};
forms['interface-form'] = async form => {
  const chosen = {theme: form.elements.theme.value, reducedEffects: form.elements.reducedEffects.checked, compact: form.elements.compact.checked};
  smoothly(() => applyPrefs(chosen));
  toast(t('settings.interfaceSaved'));
  return 'stay';
};
forms['user-form'] = async (form, data) => { await post('/users', data); toast(t('notifications.userCreated')); };
forms['user-access'] = async (form, data) => {
  await api('/users/' + form.dataset.id, {method: 'PATCH', body: JSON.stringify({role: data.role, is_active: form.elements.is_active.checked})});
  toast(t('notifications.access'));
};
forms['login-form'] = async (form, data) => { state.user = await post('/auth/login', data); await start(); return 'stay'; };

Object.assign(actions, {
  close: () => modal.close(),
  refresh: () => render(),
  navigate,
  logout: async () => { await post('/auth/logout'); signedOut(); },
  'nav-open': () => document.documentElement.classList.add('nav-open'),
  'nav-close': () => document.documentElement.classList.remove('nav-open'),
  'sidebar-toggle': () => applyPrefs({sidebarCollapsed: !prefs.sidebarCollapsed}),
  'nav-group-toggle': group => {
    const folded = !prefs.navCollapsed.includes(group);
    applyPrefs({navCollapsed: folded ? [...prefs.navCollapsed, group] : prefs.navCollapsed.filter(value => value !== group)});
    const node = document.querySelector(`[data-nav-group="${group}"]`);
    node?.classList.toggle('folded', folded);
    node?.querySelector('.nav-group-links')?.toggleAttribute('hidden', folded);
    node?.querySelector('.nav-group-toggle')?.setAttribute('aria-expanded', String(!folded));
  },
  'password-toggle': (id, control) => {
    const input = control.closest('.password-input').querySelector('input');
    const visible = input.type === 'password';
    input.type = visible ? 'text' : 'password';
    control.innerHTML = icon(visible ? 'eye-off' : 'eye');
    control.setAttribute('aria-pressed', String(visible));
    control.setAttribute('aria-label', t(visible ? 'settings.hidePassword' : 'settings.showPassword'));
  },
  'theme-toggle': () => { smoothly(() => applyPrefs({theme: effectiveTheme() === 'dark' ? 'light' : 'dark'})); },
  'user-menu': () => {
    const menu = document.querySelector('#user-menu');
    menu.hidden = !menu.hidden;
    document.querySelector('.user-button').setAttribute('aria-expanded', String(!menu.hidden));
  },
  start: async id => { await post(`/honeypots/${id}/start`); toast(t('notifications.start')); await render(true); },
  stop: async id => { if (confirm(t('confirm.stop'))) { await post(`/honeypots/${id}/stop`); toast(t('notifications.stop')); await render(true); } },
  restart: async id => { await post(`/honeypots/${id}/restart`); toast(t('notifications.restart')); await render(true); },
  event: async id => {
    const e = await api('/events/' + id);
    openDialog(t('events.title', {id}), `<p class="lead">${esc(describeEvent(e))}</p>` + detailList(e, ['payload']) + rawDetails(e),
      button(t('findings.openSource'), 'open-page', 'source/' + encodeURIComponent(e.source_ip)) +
      button(t('session.openFull'), 'open-page', `session/${e.honeypot_id}/${e.session_id}`, 'primary'));
  },
  'open-page': target => { modal.close(); navigate(target); },
  'event-prev': () => { state.eventPage--; return render(true); },
  'event-next': () => { state.eventPage++; return render(true); },
  'filters-reset': () => { document.querySelector('#filters')?.remove(); state.filters = {}; state.eventPage = 1; return render(true); },
  csv: () => download('/events/export?' + eventQuery(), 'honeyforge-events.csv'),
  ioc: () => download('/events/export?format=ioc&' + eventQuery(), 'honeyforge-observations.json'),
  'rule-new': () => ruleForm(),
  'rule-edit': ruleForm,
  'rule-delete': async id => { if (confirm(t('confirm.ruleDelete'))) { await api('/alerts/rules/' + id, {method: 'DELETE'}); await render(true); } },
  'alert-ack': async id => { await post(`/alerts/${id}/acknowledge`); bell(); await render(true); },
  'alert-resolve': async id => { await post(`/alerts/${id}/resolve`); bell(); await render(true); },
  'alert-evidence': async id => { const a = (await api('/alerts')).find(x => x.id === id); openDialog(t('alerts.evidenceTitle'), detailList(a.details) + rawDetails(a)); },
  'audit-prev': () => { state.auditPage--; return render(true); },
  'audit-next': () => { state.auditPage++; return render(true); },
  'user-new': () => openDialog(t('settings.createUser'), `<form id="user-form">${formField('username', t('auth.username'), '', 'text', 'required')}` +
    `${formField('password', t('settings.initialPassword'), '', 'password', 'required minlength="12"')}` +
    `${selectField('role', t('settings.role'), ['viewer', 'operator', 'administrator'].map(x => [x, label('role', x)]))}<button class="primary">${t('settings.createAccount')}</button></form>`),
  'user-edit': id => {
    const u = state.users.find(x => x.id === id);
    openDialog(t('settings.editTitle', {name: u.username}), `<form id="user-access" data-id="${esc(id)}">${selectField('role', t('settings.role'), ['viewer', 'operator', 'administrator'].map(x => [x, label('role', x)]), u.role)}` +
      `${checkField('is_active', t('settings.accountEnabled'), u.is_active)}<button class="primary">${t('settings.saveAccess')}</button></form>`);
  },
});


document.addEventListener('click', async event => {
  const control = event.target.closest('[data-action]');
  if (!event.target.closest('.user-menu')) document.querySelector('#user-menu')?.setAttribute('hidden', '');
  if (!control) return;
  event.preventDefault();
  try {
    control.disabled = true;
    control.classList.add('loading');
    await actions[control.dataset.action]?.(control.dataset.id, control);
  } catch (error) {
    toast(safeError(error), true);
  } finally {
    control.disabled = false;
    control.classList.remove('loading');
  }
});
document.addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.target;
  const handler = forms[form.id];
  if (!handler) return;
  const submit = form.querySelector('button[type=submit],button:not([type])');
  if (submit) { submit.disabled = true; submit.classList.add('loading'); }
  try {
    const outcome = await handler(form, Object.fromEntries(new FormData(form)));
    if (outcome !== 'stay' && form.closest('dialog')) {
      modal.close();
      await render(true);
    }
  } catch (error) {
    if (form.id === 'login-form') document.querySelector('#login-error').textContent = safeError(error);
    else toast(safeError(error), true);
  } finally {
    if (submit) { submit.disabled = false; submit.classList.remove('loading'); }
  }
});
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  document.documentElement.classList.remove('nav-open');
  document.querySelector('#user-menu')?.setAttribute('hidden', '');
});
window.addEventListener('hashchange', () => { route(); render(); });

const calmMotion = matchMedia('(prefers-reduced-motion: reduce)');
let lightFrame = 0;
document.addEventListener('pointermove', event => {
  if (event.pointerType === 'touch' || prefs.reducedEffects || calmMotion.matches) return;
  const surface = event.target.closest?.('.glass, .card');
  if (!surface) return;
  cancelAnimationFrame(lightFrame);
  lightFrame = requestAnimationFrame(() => {
    const box = surface.getBoundingClientRect();
    surface.style.setProperty('--pointer-x', `${event.clientX - box.left}px`);
    surface.style.setProperty('--pointer-y', `${event.clientY - box.top}px`);
  });
}, {passive: true});

async function start() {
  state.system = await api('/settings');
  route();
  await render();
  connect();
}
const themeIcon = () => icon(effectiveTheme() === 'dark' ? 'sun' : 'moon');
function paintThemeToggle() {
  const control = document.getElementById('theme-toggle');
  if (!control) return;
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  control.innerHTML = icon(next === 'dark' ? 'moon' : 'sun');
  control.setAttribute('aria-label', tk('shell', 'theme_' + next));
  control.setAttribute('title', tk('shell', 'theme_' + next));
}
document.addEventListener('themechange', paintThemeToggle);
afterRender(paintThemeToggle);
applyPrefs();
try {
  state.user = await api('/auth/me');
  await start();
} catch {
  loginPage();
}

document.addEventListener('invalid', event => {
  const input = event.target;
  if (!input.validity) return;
  const v = input.validity;
  if (v.customError) return;
  const message = v.valueMissing ? t('errors.required') : v.tooShort ? t('errors.length', {min: input.minLength})
    : v.rangeUnderflow ? t('errors.minimum', {min: input.min}) : v.rangeOverflow ? t('errors.maximum', {max: input.max})
    : v.stepMismatch ? t('errors.step', {step: input.step}) : t('errors.format');
  input.setCustomValidity(message);
}, true);
document.addEventListener('input', event => event.target.setCustomValidity?.(''));
document.addEventListener('change', event => event.target.setCustomValidity?.(''));
