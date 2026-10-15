import {t, tk, label, plural, formatDate, formatNumber, relativeTime, safeError, esc, state, pages, actions, forms, api, button, panel,
  heading, table, empty, skeleton, failed, metricCard, selectField, formField, badge, icon, admin, potName, afterRender, hydrate, counted,
  prefs, applyPrefs} from './ui.js';
import {chartHost, updateChart, donut} from './charts.js';
import {worldMap, setMarkers} from './worldmap.js';
import {describeEvent, findingsList, comparisonText, paintDanger, topPanels} from './insights.js';

const EVENT_TYPES = ['connection', 'data_received', 'http_request', 'authentication_attempt', 'navigation'];
const NET_RANGES = ['15m', '1h', '6h', '24h', '7d'];
const GEO_RANGES = ['24h', '7d', '30d', 'all'];
const SERIES = [
  {key: 'total', tone: 'tone-total', fill: true},
  {key: 'connection', tone: 'tone-connection'},
  {key: 'authentication_attempt', tone: 'tone-auth'},
  {key: 'http_request', tone: 'tone-http'},
];
const STACK = [
  {key: 'connection', tone: 'tone-connection'},
  {key: 'authentication_attempt', tone: 'tone-auth'},
  {key: 'http_request', tone: 'tone-http'},
  {key: 'other', tone: 'tone-other'},
];
const NET_VIEWS = ['line', 'bars', 'types', 'protocols', 'table'];
const SOURCE_VIEWS = ['table', 'columns', 'donut'];
const FEED_SIZE = 12;
const net = {range: '1h', filters: {}, data: null, error: null, token: 0, sort: 'count', order: -1};
const geo = {range: '7d', data: null, error: null, token: 0, sort: 'events', order: -1, query: ''};
const feed = {items: null, error: null, paused: false, pending: [], type: ''};
const summary = {overview: null, digest: null, health: null, error: null};
const seen = new Set();
const fresh = new Set();
let reconcileTimer = 0, statusTimer = 0, ticker = 0;

const section = id => document.querySelector('#' + id);
const onDashboard = () => Boolean(section('dash'));
function paint(id, html) {
  const node = section(id);
  if (!node) return;
  node.innerHTML = html;
  hydrate(node);
}
const netView = () => NET_VIEWS.includes(prefs.netView) ? prefs.netView : 'line';
const sourcesView = () => SOURCE_VIEWS.includes(prefs.sourcesView) ? prefs.sourcesView : 'table';
const viewSelect = (name, values, current, group) => `<label class="inline-filter">${t('net.view')}<select data-view="${name}" aria-label="${esc(t('net.view'))}">` +
  values.map(value => `<option value="${value}" ${value === current ? 'selected' : ''}>${esc(tk(group, value))}</option>`).join('') + `</select></label>`;
const segmented = (action, values, current, group) => `<div class="segmented" role="group" aria-label="${esc(t(group + '.rangeLabel'))}">` +
  values.map(value => `<button type="button" data-action="${action}" data-id="${value}" class="${value === current ? 'selected' : ''}" aria-pressed="${value === current}">${esc(tk(group + '.ranges', value))}</button>`).join('') + `</div>`;
const tile = (caption, value, note = '') =>
  `<div class="tile"><span>${esc(caption)}</span><strong ${counted('tile:' + caption, value)}>${value === null || value === undefined ? '—' : formatNumber(value)}</strong>${note ? `<small>${esc(note)}</small>` : ''}</div>`;
export function barList(rows, names = value => value) {
  if (!rows.length) return empty(t('common.waitingEvents'));
  const peak = Math.max(1, ...rows.map(row => row.count));
  return `<div class="bars">${rows.map(row => `<div class="bar-row"><span>${esc(names(row.label))}</span><strong>${formatNumber(row.count)}</strong>` +
    `<progress value="${row.count}" max="${peak}" aria-label="${esc(names(row.label))}"></progress></div>`).join('')}</div>`;
}


function paintMetrics() {
  const o = summary.overview;
  if (summary.error && !o) return paint('dash-metrics', failed(summary.error, 'dash-reload'));
  const d = summary.digest;
  const pots = d?.honeypots;
  const idle = pots ? pots.total - pots.running - pots.down.length : 0;
  paint('dash-metrics', [
    metricCard({title: t('dashboard.working'), text: pots ? t('dashboard.workingValue', {running: formatNumber(pots.running), total: formatNumber(pots.total)}) : null,
      glyph: pots?.down.length ? 'alerts' : 'running', tone: pots?.down.length ? 'critical' : 'good', href: '#honeypots',
      note: !pots ? '' : pots.down.length ? t('dashboard.downNote', {count: formatNumber(pots.down.length)})
        : !pots.total ? t('dashboard.noPots') : idle ? t('dashboard.idleNote', {count: formatNumber(idle)}) : t('dashboard.allWorking')}),
    metricCard({title: t('dashboard.events24'), value: d ? d.current.events : null, glyph: 'day', href: '#events',
      note: d ? comparisonText(d.current.events, d.previous.events, d.comparable) : ''}),
    metricCard({title: t('dashboard.alerts'), value: o ? o.active_alerts : null, glyph: 'alerts', tone: o && o.active_alerts ? 'critical' : '', href: '#alerts', note: t('dashboard.alertsNote')}),
  ].join(''));
}
function paintNow() {
  const d = summary.digest;
  if (summary.error && !d) return paint('dash-now', failed(summary.error, 'dash-reload'));
  if (!d) return;
  paint('dash-now', findingsList(d.findings.slice(0, 6)) + `<p class="hint panel-body">${t('findings.hint')} <a href="#report">${t('findings.report')}</a></p>`);
}
const healthRow = (caption, kind, text) =>
  `<li class="health ${kind}"><span>${esc(caption)}</span><strong><i aria-hidden="true"></i>${esc(label('health', kind))}</strong><small>${esc(text)}</small></li>`;
function paintHealth() {
  const h = summary.health;
  const o = summary.overview;
  const checking = !h;
  const deployed = state.pots.filter(pot => pot.deployed && pot.status !== 'deleting');
  const connected = deployed.filter(pot => pot.agent?.connected).length;
  const controllers = state.hosts.filter(host => host.controller_connected).length;
  const rows = [
    healthRow(t('dashboard.api'), checking ? 'checking' : h.api ? 'ok' : 'error', checking ? t('health.checking') : h.api ? t('health.apiOk') : t('health.noAnswer')),
    healthRow(t('dashboard.database'), checking ? 'checking' : h.database ? 'ok' : 'error', checking ? t('health.checking') : h.database ? t('health.dbOk') : t('health.dbFail')),
    healthRow(t('dashboard.websocket'), state.connected ? 'ok' : 'offline', state.connected ? t('health.wsOk') : t('health.wsOff')),
    healthRow(t('dashboard.controllers'), !state.hosts.length ? 'unknown' : controllers === state.hosts.length ? 'ok' : controllers ? 'warning' : 'offline',
      t('dashboard.controllersCount', {connected: formatNumber(controllers), total: formatNumber(state.hosts.length)})),
    healthRow(t('dashboard.agents'), !deployed.length ? 'unknown' : connected === deployed.length ? 'ok' : connected ? 'warning' : 'offline',
      deployed.length ? t('health.agents', {connected: formatNumber(connected), total: formatNumber(deployed.length)}) : t('health.noAgents')),
    healthRow(t('dashboard.queue'), !o ? 'checking' : !deployed.length ? 'unknown' : o.queue_size ? 'warning' : 'ok',
      !o ? t('health.checking') : t('dashboard.buffered', {count: formatNumber(o.queue_size)})),
  ];
  paint('dash-health', `<ul class="health-list">${rows.join('')}</ul><p class="hint">${t('health.hint')}</p>`);
}
async function loadSummary() {
  try {
    [summary.overview, state.pots, state.hosts, summary.digest] = await Promise.all([
      api('/analytics/overview'), api('/honeypots'), api('/hosts'), api('/analytics/summary?range=24h')]);
    summary.error = null;
  } catch (error) {
    summary.error = safeError(error);
  }
  const [alive, ready] = await Promise.allSettled([api('/health'), api('/ready')]);
  summary.health = {api: alive.status === 'fulfilled', database: ready.status === 'fulfilled' && ready.value.database === 'ok'};
  paintDanger();
  if (!onDashboard()) return;
  paintMetrics();
  paintNow();
  paintHealth();
}


function netQuery() {
  return new URLSearchParams(Object.entries({range: net.range, ...net.filters}).filter(([, value]) => value)).toString();
}
function chartConfig() {
  if (netView() === 'bars') return {kind: 'bars', bucketSeconds: net.data.bucket_seconds, label: t('net.chartLabel'), totalLabel: tk('net.series', 'total'),
    buckets: net.data.buckets.map(b => ({...b, other: Math.max(0, b.total - (b.connection || 0) - (b.authentication_attempt || 0) - (b.http_request || 0))})),
    series: STACK.map(series => ({...series, label: series.key === 'other' ? t('net.otherEvents') : tk('net.series', series.key)}))};
  return {buckets: net.data.buckets, bucketSeconds: net.data.bucket_seconds, label: t('net.chartLabel'),
    series: SERIES.map(series => ({...series, label: tk('net.series', series.key)}))};
}
const charted = () => ['line', 'bars'].includes(netView());
function intervalTable() {
  const rows = net.data.buckets.filter(b => b.total).reverse();
  return `<div class="interval-table">${table([t('net.interval'), ...SERIES.map(series => esc(tk('net.series', series.key)))], rows.map(b =>
    `<tr><td class="mono">${esc(formatDate(b.timestamp))}</td>${SERIES.map(series => `<td>${formatNumber(b[series.key] || 0)}</td>`).join('')}</tr>`), t('net.empty'))}</div>`;
}
function viewBody() {
  const d = net.data;
  if (!d.totals.events) return `<div class="chart-empty">${empty(t('net.empty'))}</div>`;
  const view = netView();
  if (view === 'types') return donut(d.event_types, {label: tk('net.views', 'types'), caption: t('net.eventsCaption'), other: t('net.otherEvents'), names: type => label('event', type)});
  if (view === 'protocols') return donut(d.protocols, {label: tk('net.views', 'protocols'), caption: t('net.eventsCaption'), other: t('net.otherEvents')});
  if (view === 'table') return intervalTable();
  return chartHost('network', chartConfig());
}
function paintView() {
  if (charted() && net.data.totals.events && section('net-view')?.querySelector('[data-chart]')) updateChart('network', chartConfig());
  else paint('net-view', viewBody());
}
function netTiles() {
  const d = net.data;
  const minutes = Math.round(d.events_per_minute.window_seconds / 60);
  return tile(t('net.connections'), d.totals.connection) + tile(t('net.uniqueSources'), d.totals.unique_sources) +
    tile(t('net.authAttempts'), d.totals.authentication_attempt) + tile(t('net.httpRequests'), d.totals.http_request) +
    tile(t('net.sessions'), d.active_sessions.value, t('net.windowNote', {minutes})) +
    tile(t('net.perMinute'), d.events_per_minute.value, t('net.windowNote', {minutes}));
}
function netControls() {
  const f = net.filters;
  return `<form id="net-filters" class="filters compact-filters">` +
    selectField('honeypot_id', t('common.honeypot'), [['', t('events.allPots')], ...state.pots.map(pot => [pot.id, pot.name])], f.honeypot_id) +
    selectField('event_type', t('common.eventType'), [['', t('events.allTypes')], ...EVENT_TYPES.map(type => [type, label('event', type)])], f.event_type) +
    selectField('protocol', t('events.protocol'), [['', t('events.allProtocols')], ['TCP', 'TCP'], ['HTTP', 'HTTP']], f.protocol) +
    formField('source_ip', t('events.sourceIp'), f.source_ip || '', 'text', 'inputmode="decimal" autocomplete="off"') +
    `<button class="secondary">${t('events.apply')}</button>${button(t('common.reset'), 'net-reset', '', 'ghost')}</form>`;
}
function paintNetwork() {
  if (net.error && !net.data) {
    paint('dash-network', failed(net.error, 'net-reload'));
    paint('dash-breakdown', failed(net.error, 'net-reload'));
    paint('dash-sources', failed(net.error, 'net-reload'));
    return;
  }
  if (!net.data) return;
  const d = net.data;
  paint('dash-network', netControls() + (net.error ? `<p class="notice warning">${esc(net.error)}</p>` : '') + `<div id="net-view">${viewBody()}</div>` +
    `<div class="tiles" id="net-tiles">${netTiles()}</div><p class="hint">${t('net.hint', {from: formatDate(d.from), to: formatDate(d.to)})}</p>`);
  paint('dash-breakdown', `<h3>${t('net.protocols')}</h3>${barList(d.protocols)}<h3>${t('net.eventTypes')}</h3>${barList(d.event_types, type => label('event', type))}`);
  paintSources();
}
function sortButton(action, key, caption, current) {
  const active = current.sort === key;
  return `<button type="button" class="sort ${active ? 'active' : ''}" data-action="${action}" data-id="${key}" aria-label="${esc(t('common.sortBy', {column: caption}))}">` +
    `${esc(caption)}<span aria-hidden="true">${active ? (current.order < 0 ? '↓' : '↑') : '↕'}</span></button>`;
}
function paintSources() {
  const view = sourcesView();
  if (view !== 'table') {
    const top = [...net.data.top_sources].sort((a, b) => b.count - a.count);
    paint('dash-sources', `<div class="panel-body">${!top.length ? empty(t('net.noSources')) : view === 'donut'
      ? donut(top.map(row => ({label: row.source_ip, count: row.count})), {label: t('net.topSources'), caption: t('net.eventsCaption'), other: t('net.otherSources')})
      : chartHost('sources-chart', {kind: 'columns', label: t('net.topSources'),
        items: top.map(row => ({label: row.source_ip, count: row.count, href: '#source/' + encodeURIComponent(row.source_ip)}))})}</div>`);
    return;
  }
  const rows = [...net.data.top_sources].sort((a, b) => (a[net.sort] > b[net.sort] ? 1 : a[net.sort] < b[net.sort] ? -1 : 0) * net.order);
  paint('dash-sources', table([t('events.sourceIp'), t('net.scope'), sortButton('net-sort', 'count', t('net.eventCount'), net),
    sortButton('net-sort', 'first_seen', t('net.firstSeen'), net), sortButton('net-sort', 'last_seen', t('net.lastSeen'), net),
    sortButton('net-sort', 'honeypots', t('net.honeypots'), net), ''], rows.map(row =>
    `<tr><td><a class="mono" href="#source/${encodeURIComponent(row.source_ip)}">${esc(row.source_ip)}</a></td><td>${badge(row.scope, 'scope')}</td><td>${formatNumber(row.count)}</td>` +
    `<td class="mono">${esc(formatDate(row.first_seen))}</td><td class="mono">${esc(formatDate(row.last_seen))}</td><td>${formatNumber(row.honeypots)}</td>` +
    `<td>${button(t('net.filterSource'), 'net-source', row.source_ip, 'ghost')}</td></tr>`), t('net.noSources')));
}
async function loadNetwork(quiet = false) {
  const token = ++net.token;
  if (!quiet && !net.data) paint('dash-network', skeleton(6));
  section('dash-network')?.classList.add('busy');
  try {
    const data = await api('/analytics/network-activity?' + netQuery());
    if (token !== net.token) return;
    net.data = data;
    net.error = null;
  } catch (error) {
    if (token !== net.token) return;
    net.error = safeError(error);
    if (!quiet) net.data = null;
  }
  section('dash-network')?.classList.remove('busy');
  if (!onDashboard()) return;
  if (quiet && net.data && section('net-view')) {
    paintView();
    paint('net-tiles', netTiles());
    paint('dash-breakdown', `<h3>${t('net.protocols')}</h3>${barList(net.data.protocols)}<h3>${t('net.eventTypes')}</h3>${barList(net.data.event_types, type => label('event', type))}`);
    paintSources();
  } else paintNetwork();
}
function matchesFilters(event) {
  const f = net.filters;
  return (!f.honeypot_id || f.honeypot_id === event.honeypot_id) && (!f.event_type || f.event_type === event.event_type) &&
    (!f.protocol || f.protocol === event.protocol) && (!f.source_ip || f.source_ip === event.source_ip);
}
function addToChart(event) {
  if (!net.data || !matchesFilters(event)) return false;
  const start = new Date(net.data.from).getTime();
  const index = Math.floor((new Date(event.timestamp).getTime() - start) / (net.data.bucket_seconds * 1000));
  const bucket = net.data.buckets[index];
  if (!bucket) return false;
  bucket.total += 1;
  if (event.event_type in bucket) bucket[event.event_type] += 1;
  net.data.totals.events += 1;
  if (event.event_type in net.data.totals) net.data.totals[event.event_type] += 1;
  return true;
}


function providerLine(provider) {
  if (provider.name === 'none') return t('geo.providerNone');
  if (!provider.ready) return t('geo.providerBroken');
  return t('geo.providerReady', {records: formatNumber(provider.records), updated: formatDate(provider.database_updated_at)});
}
function attributionLine(provider) {
  if (!provider.ready || !provider.attribution) return '';
  const name = esc(provider.attribution);
  const link = provider.attribution_url ? `<a href="${esc(provider.attribution_url)}" target="_blank" rel="noopener noreferrer">${name}</a>` : name;
  return ` ${t('geo.attribution')} ${link}.`;
}
function countryRows() {
  const text = geo.query.trim().toLowerCase();
  return geo.data.countries.filter(country => !text || country.name.toLowerCase().includes(text) || country.code.toLowerCase() === text)
    .sort((a, b) => (a[geo.sort] > b[geo.sort] ? 1 : a[geo.sort] < b[geo.sort] ? -1 : 0) * geo.order);
}
function paintCountries() {
  paint('geo-countries', table([t('geo.country'), sortButton('geo-sort', 'events', t('geo.events'), geo),
    sortButton('geo-sort', 'unique_ips', t('geo.uniqueIps'), geo), sortButton('geo-sort', 'last_seen', t('geo.lastActivity'), geo)],
    countryRows().map(country => `<tr><td>${esc(country.name)} <small class="mono">${esc(country.code)}</small></td><td>${formatNumber(country.events)}</td>` +
      `<td>${formatNumber(country.unique_ips)}</td><td class="mono">${esc(formatDate(country.last_seen))}</td></tr>`), t('geo.noCountries')));
}
function paintGeo() {
  if (geo.error && !geo.data) return paint('dash-geo', failed(geo.error, 'geo-reload'));
  if (!geo.data) return;
  const d = geo.data;
  setMarkers(d.markers);
  const overlay = d.markers.length ? '' : `<div class="map-empty"><strong>${t(d.sources.public ? 'geo.emptyUnknown' : 'geo.emptyLocal')}</strong>` +
    `<span>${t('geo.privateNote')}</span></div>`;
  const coverage = d.coverage_percent === null ? '' : `<div class="tile wide"><span>${t('geo.coverageTitle')}</span><strong>${formatNumber(d.coverage_percent)} %</strong>` +
    `<small>${esc(t('geo.coverage', {percent: formatNumber(d.coverage_percent)}))}</small></div>`;
  paint('dash-geo', `<div class="geo-layout"><div class="map-frame">${worldMap(d.markers)}${overlay}` +
    `<div class="map-legend"><span><i class="legend-point"></i>${t('geo.legendMarker')}</span><span>${t('geo.legendSize')}</span></div></div>` +
    `<aside class="geo-side"><div class="tiles two">${coverage}` +
    tile(t('geo.publicSources'), d.sources.public) + tile(t('geo.located'), d.sources.geolocated) +
    tile(t('geo.unknown'), d.sources.unknown) + tile(t('geo.localSources'), d.sources.local, t('geo.localEvents', {count: plural('counts.events', d.local.events)})) +
    `</div><h3>${t('geo.countriesTitle')}</h3>` +
    `<label class="inline-filter">${t('geo.countryFilter')}<input type="search" data-geo-filter value="${esc(geo.query)}" aria-label="${esc(t('geo.countryFilter'))}"></label>` +
    `<div id="geo-countries"></div></aside></div>` +
    `<p class="hint">${esc(providerLine(d.provider))}${attributionLine(d.provider)} ${t('geo.disclaimer')}${d.truncated ? ' ' + t('geo.truncated') : ''}</p>`);
  paintCountries();
}
async function loadGeo(quiet = false) {
  const token = ++geo.token;
  if (!quiet && !geo.data) paint('dash-geo', skeleton(8));
  try {
    const data = await api('/analytics/geography?range=' + geo.range);
    if (token !== geo.token) return;
    geo.data = data;
    geo.error = null;
  } catch (error) {
    if (token !== geo.token) return;
    geo.error = safeError(error);
  }
  if (onDashboard()) paintGeo();
}


function feedRow(event) {
  return `<li class="${fresh.has(event.id) ? 'fresh' : ''}"><button type="button" class="feed-row" data-action="event" data-id="${event.id}" aria-label="${esc(t('feed.open', {id: event.id}))}">` +
    `<span class="feed-icon ${esc(event.severity)}">${icon(event.event_type)}</span>` +
    `<span class="feed-main"><strong>${esc(describeEvent(event))}</strong><small>${esc(label('event', event.event_type))}</small></span>` +
    `<span class="feed-meta"><span>${esc(potName(event.honeypot_id))}</span><span class="mono">${esc(event.source_ip)}</span></span>` +
    `<span class="feed-side">${badge(event.severity, 'severity')}<time class="mono">${esc(formatDate(event.timestamp))}</time></span></button></li>`;
}
function paintFeed() {
  if (feed.error && !feed.items) return paint('dash-feed', failed(feed.error, 'feed-reload'));
  if (!feed.items) return;
  const waiting = feed.pending.length ? `<p class="notice">${t('feed.pending', {count: plural('counts.events', feed.pending.length)})}</p>` : '';
  const list = feed.items.length ? `<ul class="feed">${feed.items.map(feedRow).join('')}</ul>` : empty(t('feed.empty'));
  paint('dash-feed', waiting + list);
  fresh.clear();
  const control = section('feed-toggle');
  if (control) control.innerHTML = `${icon(feed.paused ? 'play' : 'pause')}<span>${t(feed.paused ? 'feed.resume' : 'feed.pause')}</span>`;
}
async function loadFeed() {
  try {
    const type = feed.type ? `&event_type=${feed.type}` : '';
    feed.items = (await api(`/events?page_size=${FEED_SIZE}${type}`)).items;
    feed.items.forEach(event => seen.add(event.id));
    feed.pending = [];
    feed.error = null;
  } catch (error) {
    feed.error = safeError(error);
  }
  if (onDashboard()) paintFeed();
}


function reconcile(delay = 4000) {
  clearTimeout(reconcileTimer);
  reconcileTimer = setTimeout(() => {
    if (!onDashboard()) return;
    loadSummary();
    loadNetwork(true);
    loadGeo(true);
    if (!feed.paused) loadFeed();
  }, delay);
}
export function live(message) {
  if (!onDashboard()) return false;
  if (message.type === 'reconnected') {
    loadFeed();
    reconcile(0);
    return true;
  }
  if (message.type !== 'events') {
    clearTimeout(statusTimer);
    statusTimer = setTimeout(loadSummary, 500);
    return true;
  }
  let counted = false;
  for (const event of Array.isArray(message.events) ? message.events : []) {
    if (!Number.isInteger(event?.id) || typeof event.timestamp !== 'string' || !EVENT_TYPES.includes(event.event_type) || seen.has(event.id)) continue;
    seen.add(event.id);
    if (seen.size > 5000) seen.delete(seen.values().next().value);
    if (summary.overview) summary.overview.events += 1;
    if (summary.digest) summary.digest.current.events += 1;
    counted = addToChart(event) || counted;
    if (feed.items && (!feed.type || feed.type === event.event_type)) {
      if (feed.paused) feed.pending.unshift(event);
      else { feed.items.unshift(event); feed.items.length = Math.min(feed.items.length, FEED_SIZE); fresh.add(event.id); }
    }
  }
  paintMetrics();
  paintFeed();
  if (counted && section('net-view')?.querySelector('[data-chart]')) {
    updateChart('network', chartConfig());
    paint('net-tiles', netTiles());
  }
  reconcile();
  return true;
}

pages.dashboard = async () => {
  const control = `<button type="button" id="feed-toggle" class="ghost with-icon" data-action="feed-toggle"></button>`;
  const feedFilter = `<label class="inline-filter">${t('feed.filter')}<select data-feed-filter aria-label="${esc(t('feed.filter'))}">` +
    [['', t('events.allTypes')], ...EVENT_TYPES.map(type => [type, label('event', type)])].map(([value, caption]) =>
      `<option value="${value}" ${value === feed.type ? 'selected' : ''}>${esc(caption)}</option>`).join('') + `</select></label>`;
  return heading(t('dashboard.title'), t('dashboard.description'), admin() ? button(t('pots.create'), 'pot-new', '', 'primary') : button(t('dashboard.viewEvents'), 'navigate', 'events')) +
    `<div id="dash"><section id="dash-metrics" class="metrics" aria-label="${esc(t('dashboard.metricsLabel'))}">${skeleton(2)}</section>` +
    `<div class="grid even">${panel(t('findings.title'), `<div id="dash-now">${skeleton(4)}</div>`)}` +
    `${panel(t('feed.title'), `<div id="dash-feed">${skeleton(6)}</div>`, `<div class="actions">${feedFilter}${control}<a href="#events">${t('dashboard.explore')}</a></div>`)}</div>` +
    `<div class="grid wide-left">${panel(t('net.title'), `<div id="dash-network" class="panel-body">${skeleton(6)}</div>`,
      `<div class="actions">${viewSelect('net', NET_VIEWS, netView(), 'net.views')}${segmented('net-range', NET_RANGES, net.range, 'net')}</div>`)}` +
    `${panel(t('net.breakdown'), `<div id="dash-breakdown" class="panel-body">${skeleton(5)}</div>`)}</div>` +
    panel(t('geo.title'), `<div id="dash-geo" class="panel-body">${skeleton(8)}</div>`, segmented('geo-range', GEO_RANGES, geo.range, 'geo')) +
    `<div class="grid wide-left">${panel(t('net.topSources'), `<div id="dash-sources">${skeleton(4)}</div>`, viewSelect('sources', SOURCE_VIEWS, sourcesView(), 'net.sourceViews'))}` +
    `${panel(t('dashboard.health'), `<div id="dash-health" class="panel-body">${skeleton(5)}</div>`)}</div></div>`;
};
afterRender(node => {
  const dash = node.querySelector?.('#dash') || (node.id === 'dash' ? node : null);
  if (!dash || dash.dataset.started) return;
  dash.dataset.started = '1';
  if (summary.overview) paintMetrics();
  if (summary.digest) paintNow();
  if (net.data) paintNetwork();
  if (geo.data) paintGeo();
  if (feed.items) paintFeed();
  loadSummary();
  loadNetwork(Boolean(net.data));
  loadGeo(Boolean(geo.data));
  loadFeed();
  clearInterval(ticker);
  ticker = setInterval(() => { if (onDashboard()) reconcile(0); else clearInterval(ticker); }, 30000);
});

Object.assign(actions, {
  'dash-reload': loadSummary,
  'net-reload': () => loadNetwork(),
  'geo-reload': () => loadGeo(),
  'feed-reload': loadFeed,
  'net-range': async range => { net.range = range; markSelected('net-range', range); await loadNetwork(Boolean(net.data)); paintNetwork(); },
  'geo-range': async range => { geo.range = range; markSelected('geo-range', range); await loadGeo(Boolean(geo.data)); },
  'net-reset': async () => { net.filters = {}; net.data = null; await loadNetwork(); },
  'net-source': async address => { net.filters = {...net.filters, source_ip: address}; net.data = null; await loadNetwork(); section('dash-network')?.scrollIntoView({block: 'nearest'}); },
  'net-sort': key => { net.order = net.sort === key ? -net.order : -1; net.sort = key; paintSources(); },
  'geo-sort': key => { geo.order = geo.sort === key ? -geo.order : -1; geo.sort = key; paintCountries(); },
  'feed-toggle': () => {
    feed.paused = !feed.paused;
    if (!feed.paused && feed.pending.length) {
      feed.items = [...feed.pending, ...feed.items].slice(0, FEED_SIZE);
      feed.pending = [];
    }
    paintFeed();
  },
});
function markSelected(action, value) {
  for (const control of document.querySelectorAll(`[data-action="${action}"]`)) {
    control.classList.toggle('selected', control.dataset.id === value);
    control.setAttribute('aria-pressed', control.dataset.id === value);
  }
}
forms['net-filters'] = async (form, data) => {
  net.filters = Object.fromEntries(Object.entries(data).map(([key, value]) => [key, value.trim()]).filter(([, value]) => value));
  net.data = null;
  await loadNetwork();
  return 'stay';
};
document.addEventListener('change', event => {
  if (event.target.matches?.('[data-feed-filter]')) { feed.type = event.target.value; feed.items = null; loadFeed(); }
  if (event.target.matches?.('[data-view="net"]')) { applyPrefs({netView: event.target.value}); if (net.data && section('net-view')) paint('net-view', viewBody()); }
  if (event.target.matches?.('[data-view="sources"]')) { applyPrefs({sourcesView: event.target.value}); if (net.data) paintSources(); }
});
document.addEventListener('input', event => {
  if (event.target.matches?.('[data-geo-filter]')) { geo.query = event.target.value; paintCountries(); }
});


const single = (id, points, caption, bucketSeconds) => chartHost(id, {label: caption, bucketSeconds,
  buckets: points.map(point => ({timestamp: point.timestamp, total: point.count})), series: [{key: 'total', tone: 'tone-total', fill: true, label: t('net.series.total')}]});
pages.analytics = async () => {
  const [o, hourly, daily, protocols, sources, auth, places, top] = await Promise.all([
    api('/analytics/overview'), api('/analytics/timeline'), api('/analytics/timeline?bucket=day'), api('/analytics/protocols'),
    api('/analytics/sources'), api('/analytics/timeline?event_type=authentication_attempt'), api('/analytics/geography?range=all'),
    api('/analytics/top?range=7d')]);
  const controls = button(t('report.open'), 'navigate', 'report', 'primary') +
    (['administrator', 'operator'].includes(state.user?.role) ? button(t('report.export'), 'sources-export', '7d') : '');
  const countries = table([t('geo.country'), t('geo.events'), t('geo.uniqueIps'), t('geo.lastActivity')], places.countries.map(country =>
    `<tr><td>${esc(country.name)} <small class="mono">${esc(country.code)}</small></td><td>${formatNumber(country.events)}</td>` +
    `<td>${formatNumber(country.unique_ips)}</td><td class="mono">${esc(formatDate(country.last_seen))}</td></tr>`), t('geo.noCountries'));
  const body = chart => `<div class="panel-body">${chart}</div>`;
  return heading(t('navigation.analytics'), t('analytics.description'), controls) +
    `<section class="metrics four">${metricCard({title: t('dashboard.events'), value: o.events, glyph: 'events'})}` +
    `${metricCard({title: t('dashboard.events24'), value: o.events_24h, glyph: 'day'})}` +
    `${metricCard({title: t('dashboard.sources'), value: o.unique_sources, glyph: 'globe'})}` +
    `${metricCard({title: t('dashboard.authAttempts'), value: o.authentication_attempts, glyph: 'authentication_attempt'})}</section>` +
    `<div class="grid even">${panel(t('analytics.hourly'), body(single('hourly', hourly, t('analytics.hourly'), 3600)))}` +
    `${panel(t('analytics.daily'), body(single('daily', daily, t('analytics.daily'), 86400)))}</div>` +
    `<div class="grid even">${panel(t('dashboard.authTrend'), body(single('auth', auth, t('dashboard.authTrend'), 3600)))}` +
    `${panel(t('analytics.types'), body(barList(o.by_type, type => label('event', type))))}</div>` +
    `<div class="grid three">${panel(t('dashboard.byHoneypot'), body(barList(o.by_honeypot, potName)))}` +
    `${panel(t('dashboard.protocols'), body(barList(protocols)))}${panel(t('dashboard.activeSources'), body(barList(sources)))}</div>` +
    `<h3 class="section-title">${t('top.title')}</h3>` + topPanels(top) +
    panel(t('geo.countriesTitle'), countries) + `<p class="hint">${t('geo.disclaimer')}</p>`;
};
