import {t, tk, label, plural, formatDate, formatNumber, relativeTime, esc, state, pages, actions, api, button, panel, heading,
  table, empty, badge, icon, keyValues, serviceName, canOperate, download, navigate, afterRender, rerender, openDialog, modal} from './ui.js';

const SHELL = 'Shell command';
const ACCEPTED = ['accepted', 'simulated_success'];
const REPORT_RANGES = ['24h', '7d', '30d'];
const report = {range: '24h'};
const dismissedDanger = new Set();
const dangerKey = pot => `${pot.id}:${pot.status}:${pot.generation}:${pot.error || ''}`;
const dangerStorageKey = () => 'honeyforge.hidden-danger.' + state.user?.id;
function hiddenDanger() {
  try { return JSON.parse(localStorage.getItem(dangerStorageKey()) || '[]'); } catch { return []; }
}
const tidy = text => text.replace(/\s+/g, ' ').replace(/ ([.,:])/g, '$1').trim();
const sourceLink = address => `<a class="mono" href="#source/${encodeURIComponent(address)}">${esc(address)}</a>`;
const sessionLink = (item, caption) => `<a href="#session/${esc(item.honeypot_id)}/${esc(item.session_uid)}">${esc(caption)}</a>`;


export function describeEvent(event) {
  const p = event.payload || {};
  if ((p.summary || event.summary) === 'Sandbox session closed; reset required') return t('explain.sandboxClosed');
  if (p.stream === 'artifact' || p.stream === 'artifact_chunk') return t('explain.sandboxArtifact', {path: p.artifact_path || '—', sha: (p.sha256 || '').slice(0, 16)});
  if (p.stream === 'output' || p.stream === 'syscall') {
    let text = '';
    try { text = new TextDecoder().decode(Uint8Array.from(atob(p.data || ''), char => char.charCodeAt(0))).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '').trim().slice(0, 240); } catch {   }
    return t(p.stream === 'output' ? 'explain.sandboxOutput' : 'explain.sandboxTrace', {text});
  }
  if (event.event_type === 'authentication_attempt') {
    if (!p.result) return t('explain.loginGeneric');
    const accepted = ACCEPTED.includes(p.result);
    return p.username ? t(accepted ? 'explain.loginAccepted' : 'explain.loginRejected', {user: p.username})
      : t(accepted ? 'explain.loginAcceptedAnon' : 'explain.loginRejectedAnon');
  }
  if (event.event_type === 'data_received') {
    if ((p.summary || event.summary) === SHELL) return p.input_preview ? t('explain.command', {line: p.input_preview}) : t('explain.commandGeneric');
    return p.bytes_received ? t('explain.data', {bytes: formatNumber(p.bytes_received)}) : t('explain.dataGeneric');
  }
  if (event.event_type === 'http_request')
    return p.path ? t('explain.request', {method: p.method || 'GET', path: p.path, status: p.status ?? '—'}) : t('explain.requestGeneric');
  if (event.event_type === 'navigation') return p.path ? t('explain.page', {path: p.path}) : t('explain.pageGeneric');
  return t('explain.connection');
}


const within = seconds => seconds < 1 ? '' : t('span.within', {span: spanText(seconds)});
function spanText(seconds) {
  if (seconds < 1) return t('session.instant');
  if (seconds < 90) return t('span.seconds', {n: formatNumber(seconds)});
  if (seconds < 5400) return t('span.minutes', {n: formatNumber(Math.round(seconds / 60))});
  if (seconds < 172800) return t('span.hours', {n: formatNumber(Math.round(seconds / 3600))});
  return t('span.days', {n: formatNumber(Math.round(seconds / 86400))});
}
const placeText = item => item.country ? ` (${item.country})` : item.scope && item.scope !== 'public' ? ` (${label('scope', item.scope)})` : '';
export function findingText(item) {
  const d = item.details, source = item.source_ip + placeText(item), pot = item.honeypot_name || '—';
  if (item.kind === 'brute_force')
    return tidy(t('findings.bruteForce', {service: serviceName(item.service_key), pot, attempts: plural('counts.attempts', d.attempts),
      span: within(d.duration_seconds), source}) + (d.accepted ? ' ' + t('findings.bruteForceAccepted') : ''));
  if (item.kind === 'login_success') return tidy(t(d.username ? 'findings.loginNamed' : 'findings.login', {pot, source, user: d.username}));
  if (item.kind === 'payload_attempt') return tidy(t('findings.payload', {commands: plural('counts.commands', d.commands), pot, source}));
  if (item.kind === 'path_scan') return tidy(t('findings.pathScan', {paths: plural('counts.paths', d.paths), pot, source}));
  return tidy(t('findings.multiTarget', {source, count: formatNumber(d.honeypots)}));
}
export function findingsList(items, emptyText = t('findings.empty'), link = true) {
  if (!items.length) return `<div class="empty">${esc(emptyText)}<br><small>${esc(t('findings.emptyHint'))}</small></div>`;
  return `<ul class="findings">${items.map(item => `<li class="finding ${esc(item.severity)}">${badge(item.severity, 'severity')}` +
    `<div class="finding-text"><p>${esc(findingText(item))}</p><small>${esc(tk('findings.kinds', item.kind))} · ${esc(relativeTime(item.last_seen))} · ${esc(formatDate(item.last_seen))}</small></div>` +
    (link ? `<a class="finding-link" href="#source/${encodeURIComponent(item.source_ip)}">${esc(t('findings.openSource'))}</a>` : '') + `</li>`).join('')}</ul>`;
}


function timesText(value) {
  const rounded = Math.round(value * 10) / 10;
  const n = Math.abs(rounded) % 100, k = n % 10;
  const few = !Number.isInteger(rounded) || (k >= 2 && k <= 4 && !(n >= 12 && n <= 14));
  return `${formatNumber(rounded)} ${t(few ? 'compare.timesFew' : 'compare.timesMany')}`;
}
export function comparisonText(current, previous, comparable) {
  if (!comparable) return t('compare.noHistory');
  if (!previous) return current ? t('compare.fromZero') : t('compare.same');
  if (!current) return t('compare.toZero');
  const ratio = current / previous;
  if (ratio >= 2) return t('compare.timesMore', {times: timesText(ratio)});
  if (ratio <= 0.5) return t('compare.timesLess', {times: timesText(1 / ratio)});
  const percent = Math.round((ratio - 1) * 100);
  return percent ? t(percent > 0 ? 'compare.more' : 'compare.less', {percent: formatNumber(Math.abs(percent))}) : t('compare.same');
}


export function paintDanger() {
  const node = document.getElementById('danger-strip');
  if (!node) return;
  const hidden = hiddenDanger();
  const down = state.pots.filter(pot => ['failed', 'offline'].includes(pot.status) && !dismissedDanger.has(dangerKey(pot)) && !hidden.includes(dangerKey(pot)));
  node.hidden = !down.length;
  node.innerHTML = !down.length ? '' : `<strong>${icon('alerts')}${esc(t('danger.title'))}</strong><span class="danger-items">` +
    down.map(pot => `<span class="danger-notification"><a href="#honeypot/${esc(pot.id)}">${esc(t(pot.status === 'offline' ? 'danger.offline' : 'danger.failed', {name: pot.name}))}</a>` +
      `<button type="button" class="ghost icon-button" data-action="danger-options" data-id="${esc(pot.id)}" aria-label="${esc(t('danger.closeFor', {name: pot.name}))}">${icon('close')}</button></span>`).join('') + `</span>`;
}

actions['danger-options'] = id => {
  const pot = state.pots.find(item => item.id === id);
  if (!pot) return;
  openDialog(t('danger.dismissTitle'), `<p>${esc(t('danger.dismissHint'))}</p><div class="actions">` +
    button(t('danger.dismissOnce'), 'danger-dismiss', id) + button(t('danger.dismissForever'), 'danger-hide', id, 'secondary') + `</div>`);
};
actions['danger-dismiss'] = id => {
  const pot = state.pots.find(item => item.id === id);
  if (pot) dismissedDanger.add(dangerKey(pot));
  modal.close(); paintDanger();
};
actions['danger-hide'] = id => {
  const pot = state.pots.find(item => item.id === id);
  if (pot) {
    try { localStorage.setItem(dangerStorageKey(), JSON.stringify([...new Set([...hiddenDanger(), dangerKey(pot)])].slice(-200))); } catch { dismissedDanger.add(dangerKey(pot)); }
  }
  modal.close(); paintDanger();
};
afterRender(paintDanger);


function offsetText(from, to) {
  const seconds = Math.max(0, Math.round((new Date(to) - new Date(from)) / 1000));
  return `+${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}
function outcomeText(o) {
  const parts = [];
  if (o.login_attempts) parts.push(t(o.logged_in ? 'session.loginsIn' : 'session.loginsOut', {count: formatNumber(o.login_attempts)}));
  if (o.commands) parts.push(t('session.commands', {count: plural('counts.commands', o.commands)}));
  if (o.requests) parts.push(t('session.requests', {count: formatNumber(o.requests)}));
  if (o.risky) parts.push(t('session.risky', {count: formatNumber(o.risky)}));
  return parts.length ? parts.join(' ') : t('session.onlyConnected');
}
pages.session = async () => {
  const [potId, uid] = (state.param || '').split('/');
  const back = button(t('session.back'), 'navigate', 'events');
  let data;
  try {
    data = await api(`/sessions/${encodeURIComponent(potId)}/${encodeURIComponent(uid || '')}`);
  } catch {
    return heading(t('session.title'), t('session.description'), back) + empty(t('session.missing'));
  }
  const facts = keyValues([
    [t('common.source'), sourceLink(data.source_ip) + esc(placeText(data))],
    [t('common.honeypot'), `<a href="#honeypot/${esc(data.honeypot_id)}">${esc(data.honeypot_name || data.honeypot_id)}</a> · ${esc(serviceName(data.service_key))}`],
    [t('session.started'), esc(formatDate(data.started_at))],
    [t('session.duration'), esc(spanText(data.duration_seconds))],
    [t('session.events'), formatNumber(data.event_count)],
    [t('session.outcome'), esc(outcomeText(data.outcome))],
  ]);
  const steps = data.events.map(event => `<li class="step ${esc(event.severity)}"><time class="mono">${esc(offsetText(data.started_at, event.timestamp))}</time>` +
    `<span class="feed-icon ${esc(event.severity)}">${icon(event.event_type)}</span>` +
    `<div class="step-text"><p>${esc(describeEvent(event))}</p><small>${esc(label('event', event.event_type))} · ${esc(formatDate(event.timestamp))}</small></div>` +
    `${button(t('common.inspect'), 'event', event.id, 'ghost')}</li>`).join('');
  const capture = data.service_key === 'linux-sandbox' && canOperate() ? button(t('session.downloadCapture'), 'sandbox-capture', `${potId}/${uid}`) : '';
  const artifacts = canOperate() ? data.events.filter(event => event.payload?.stream === 'artifact').map(event =>
    `<li><code>${esc(event.payload.artifact_path)}</code> ${button(t('session.downloadArtifact'), 'sandbox-artifact', `${potId}/${uid}/${event.payload.sha256}`, 'ghost')}</li>`).join('') : '';
  return heading(t('session.title'), t('session.description'), back + capture) +
    `<div class="grid wide-right">${panel(t('session.facts'), `<div class="panel-body">${facts}</div>`)}` +
    `${panel(t('session.timeline'), `<ol class="timeline">${steps}</ol>` + (data.truncated ? `<p class="hint panel-body">${t('session.truncated')}</p>` : ''))}</div>` +
    (artifacts ? panel(t('session.artifacts'), `<ul class="panel-body">${artifacts}</ul>`) : '');
};
actions['sandbox-capture'] = id => download(`/sandbox/sessions/${id}/capture`, 'honeyforge-session.json');
actions['sandbox-artifact'] = id => download(`/sandbox/sessions/${id}/artifact`, 'honeyforge-artifact.bin');


const ranked = rows => rows.length ? `<ol class="ranked">${rows.map(row => `<li><span class="mono">${esc(row.label)}</span><strong>${formatNumber(row.count)}</strong></li>`).join('')}</ol>`
  : empty(t('top.none'));
export function topPanels(data) {
  if (data.restricted) return `<div class="notice">${t('top.restricted')}</div>`;
  return `<div class="grid three">${panel(t('top.usernames'), `<div class="panel-body">${ranked(data.usernames)}</div>`)}` +
    `${panel(t('top.commands'), `<div class="panel-body">${ranked(data.commands)}</div>`)}` +
    `${panel(t('top.paths'), `<div class="panel-body">${ranked(data.paths)}</div>`)}</div>`;
}
const sessionRows = rows => table([t('session.started'), t('common.honeypot'), t('session.duration'), t('session.events'), ''], rows.map(row =>
  `<tr><td class="mono">${esc(formatDate(row.started_at))}</td><td>${esc(row.honeypot_name || '—')}</td>` +
  `<td>${esc(spanText(row.duration_seconds))}</td><td>${formatNumber(row.event_count)}</td>` +
  `<td>${sessionLink(row, t('session.open'))}</td></tr>`), t('session.none'));
pages.source = async () => {
  const address = decodeURIComponent(state.param || '');
  const back = button(t('source.back'), 'navigate', 'events');
  let card;
  try {
    card = await api('/sources/' + encodeURIComponent(address));
  } catch {
    return heading(t('source.title'), t('source.description'), back) + empty(t('source.missing'));
  }
  const place = [card.country, card.city].filter(Boolean).join(', ');
  const facts = keyValues([
    [t('source.address'), `<span class="mono">${esc(card.source_ip)}</span> ${badge(card.scope, 'scope')}`],
    [t('source.place'), esc(place || t(card.scope === 'public' ? 'source.placeUnknown' : 'source.placeLocal'))],
    [t('net.firstSeen'), `${esc(formatDate(card.first_seen))} · ${esc(relativeTime(card.first_seen))}`],
    [t('net.lastSeen'), `${esc(formatDate(card.last_seen))} · ${esc(relativeTime(card.last_seen))}`],
    [t('source.events'), formatNumber(card.events)],
    [t('source.sessions'), formatNumber(card.sessions)],
  ]);
  const pots = table([t('common.honeypot'), t('pots.type'), t('source.events'), t('net.lastSeen')], card.honeypots.map(pot =>
    `<tr><td><a href="#honeypot/${esc(pot.id)}">${esc(pot.name || pot.id)}</a></td><td>${esc(serviceName(pot.service_key))}</td>` +
    `<td>${formatNumber(pot.events)}</td><td class="mono">${esc(formatDate(pot.last_seen))}</td></tr>`));
  const kinds = card.event_types.map(row => `<li><span>${esc(label('event', row.label))}</span><strong>${formatNumber(row.count)}</strong></li>`).join('');
  return heading(`${t('source.title')} ${esc(card.source_ip)}`, t('source.description'), back + button(t('source.allEvents'), 'source-events', card.source_ip)) +
    `<div class="grid even">${panel(t('source.facts'), `<div class="panel-body">${facts}<p class="hint">${t('source.disclaimer')}</p></div>`)}` +
    `${panel(t('source.behaviour'), findingsList(card.findings, t('source.noFindings'), false))}</div>` +
    `<div class="grid even">${panel(t('source.honeypots'), pots)}${panel(t('source.kinds'), `<div class="panel-body"><ol class="ranked">${kinds}</ol></div>`)}</div>` +
    topPanels(card) + panel(t('source.recentSessions'), sessionRows(card.recent_sessions));
};


pages.report = async () => {
  const [data, top] = await Promise.all([api('/analytics/summary?range=' + report.range), api('/analytics/top?range=' + report.range)]);
  const rows = ['events', 'sessions', 'unique_sources', 'connections', 'authentication_attempts', 'commands', 'http_requests'].map(key =>
    `<tr><td>${esc(tk('report.metrics', key))}</td><td>${formatNumber(data.current[key])}</td><td>${data.comparable ? formatNumber(data.previous[key]) : '—'}</td>` +
    `<td>${esc(comparisonText(data.current[key], data.previous[key], data.comparable))}</td></tr>`);
  const pots = data.honeypots;
  const state_ = pots.down.length ? `<div class="notice error">${esc(t('report.potsDown', {count: formatNumber(pots.down.length)}))}: ${pots.down.map(pot => esc(pot.name)).join(', ')}</div>`
    : `<div class="notice ok">${esc(t('report.potsOk', {running: formatNumber(pots.running), total: formatNumber(pots.total)}))}</div>`;
  const countries = table([t('geo.country'), t('geo.events'), t('geo.uniqueIps')], data.countries.map(country =>
    `<tr><td>${esc(country.name)} <small class="mono">${esc(country.code)}</small></td><td>${formatNumber(country.events)}</td><td>${formatNumber(country.unique_ips)}</td></tr>`), t('report.noCountries'));
  const ranges = `<div class="segmented no-print" role="group" aria-label="${esc(t('report.period'))}">` + REPORT_RANGES.map(value =>
    `<button type="button" data-action="report-range" data-id="${value}" class="${value === report.range ? 'selected' : ''}" aria-pressed="${value === report.range}">${esc(tk('report.ranges', value))}</button>`).join('') + `</div>`;
  const controls = ranges + button(t('report.print'), 'report-print', '', 'primary no-print') +
    (canOperate() ? button(t('report.export'), 'sources-export', report.range, 'no-print') : '');
  return heading(t('report.title'), t('report.period') + `: ${esc(formatDate(data.from))} — ${esc(formatDate(data.to))}`, controls) +
    `<div class="report">${state_}` +
    panel(t('report.numbers'), table([t('report.metric'), t('report.current'), t('report.previous'), t('report.change')], rows)) +
    panel(t('report.findings'), findingsList(data.findings)) +
    panel(t('report.countries'), countries) + topPanels(top) +
    `<p class="hint">${t('report.note', {time: formatDate(data.generated_at)})}</p></div>`;
};

Object.assign(actions, {
  'report-range': range => { report.range = range; return rerender(); },
  'report-print': () => window.print(),
  'sources-export': range => download(`/export/sources?range=${range || '7d'}`, `honeyforge-sources-${range || '7d'}.txt`),
  'source-events': address => { state.filters = {source_ip: address}; state.eventPage = 1; navigate('events'); },
});
