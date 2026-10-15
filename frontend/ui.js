import {t, label, formatDate, formatNumber, plural, relativeTime, safeError} from './i18n.js';
import {icon} from './icons.js';
export {t, label, formatDate, formatNumber, plural, relativeTime, safeError, icon};

export const root = document.querySelector('#app');
export const modal = document.querySelector('#modal');
export const state = {
  user: null, page: 'dashboard', param: null, system: null, ws: null, connected: false,
  profiles: [], pots: [], hosts: [], services: [],
  filters: {}, eventPage: 1, auditPage: 1,
  inventory: {q: '', status: '', service: '', host: '', sort: 'name', order: 'asc', page: 1},
};
export const pages = Object.create(null);
export const actions = Object.create(null);
export const forms = Object.create(null);
const hooks = [];
export const afterRender = hook => { hooks.push(hook); };
export const hydrate = (node = document) => { for (const hook of hooks) hook(node); };

const PREFS_KEY = 'honeyforge.interface';
export const prefs = {reducedEffects: false, compact: false, sidebarCollapsed: false, theme: 'system', collapsed: [], navCollapsed: [], catalogOpen: [], ...readPrefs()};
const darkSystem = window.matchMedia('(prefers-color-scheme: dark)');
export const effectiveTheme = () => prefs.theme === 'light' || prefs.theme === 'dark' ? prefs.theme : (darkSystem.matches ? 'dark' : 'light');
function readPrefs() {
  try { return JSON.parse(localStorage.getItem(PREFS_KEY)) || {}; } catch { return {}; }
}
export function applyPrefs(changes = {}) {
  Object.assign(prefs, changes);
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch {   }
  document.documentElement.classList.toggle('reduced-effects', prefs.reducedEffects);
  document.documentElement.classList.toggle('compact', prefs.compact);
  document.documentElement.classList.toggle('sidebar-collapsed', prefs.sidebarCollapsed);
  if (prefs.theme === 'light' || prefs.theme === 'dark') document.documentElement.dataset.theme = prefs.theme;
  else delete document.documentElement.dataset.theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', effectiveTheme() === 'dark' ? '#15161a' : '#f6f7f9');
  document.dispatchEvent(new CustomEvent('themechange'));
}
darkSystem.addEventListener?.('change', () => applyPrefs());

let refresh = async () => {};
export const setRefresh = handler => { refresh = handler; };
export const rerender = (quiet = true) => refresh(quiet);

export const tk = (group, key) => t(`${group}.${key}`);
export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
export const admin = () => state.user?.role === 'administrator';
export const canOperate = () => ['administrator', 'operator'].includes(state.user?.role);
export const potName = id => state.pots.find(p => p.id === id)?.name || id;
export const serviceName = key => state.services.find(s => s.key === key)?.display_name || key || '—';
export const navigate = target => { location.hash = target; };

export async function api(path, options = {}) {
  let response;
  try {
    response = await fetch('/api/v1' + path, {...options, headers: {'Content-Type': 'application/json', 'X-HoneyForge': '1', ...options.headers}});
  } catch {
    throw new Error(t('errors.network'));
  }
  if (response.status === 401 && path !== '/auth/login') {
    document.dispatchEvent(new CustomEvent('session-expired'));
    throw new Error(t('errors.sessionExpired'));
  }
  if (!response.ok) {
    const error = await response.json().catch(() => ({detail: response.statusText}));
    const text = Array.isArray(error.detail) ? error.detail.map(item => safeError(item.msg)).join(' ') : safeError(error.detail);
    throw new Error(text);
  }
  return response.status === 204 ? null : response.json();
}
export const post = (path, body = {}) => api(path, {method: 'POST', body: JSON.stringify(body)});
export const patch = (path, body = {}) => api(path, {method: 'PATCH', body: JSON.stringify(body)});
export const remove = path => api(path, {method: 'DELETE'});

let toastTimer;
export function toast(message, error = false) {
  const node = document.querySelector('#toast');
  node.textContent = message;
  node.className = 'visible' + (error ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.className = ''; }, 5500);
}

export const badge = (value, category = 'status') => `<span class="badge ${esc(value)}"><i aria-hidden="true"></i>${esc(label(category, value))}</span>`;
export const empty = text => `<div class="empty">${esc(text)}</div>`;
export const skeleton = (lines = 3) => `<div class="skeleton" aria-busy="true" aria-label="${esc(t('common.loading'))}">${'<span></span>'.repeat(lines)}</div>`;
export const failed = (message, action) => `<div class="load-error" role="alert"><strong>${esc(t('errors.loadFailed'))}</strong><span>${esc(message)}</span>${button(t('common.retry'), action)}</div>`;
const calmMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
export const still = () => prefs.reducedEffects || calmMotion.matches;
export const smoothly = change => document.startViewTransition && !still() ? document.startViewTransition(change) : change();

const shownNumbers = new Map();
afterRender(node => {
  for (const item of node.querySelectorAll?.('[data-count]') || []) {
    const key = item.dataset.countKey, target = Number(item.dataset.count);
    const from = shownNumbers.has(key) ? shownNumbers.get(key) : 0;
    shownNumbers.set(key, target);
    if (from === target || still() || !Number.isInteger(target)) continue;
    const started = performance.now();
    item.textContent = formatNumber(from);
    const step = moment => {
      if (!item.isConnected) return;
      const progress = Math.min(1, (moment - started) / 650);
      item.textContent = formatNumber(Math.round(from + (target - from) * (1 - (1 - progress) ** 3)));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
});
export const counted = (key, value) => Number.isInteger(value) ? `data-count="${value}" data-count-key="${esc(key)}"` : '';

export function metricCard({title, value, text, note = '', glyph, tone = '', href}) {
  const shown = text !== undefined && text !== null ? esc(text) : value === null || value === undefined ? '<span class="metric-unknown">—</span>' : formatNumber(value);
  const body = `<span class="metric-icon">${icon(glyph)}</span><span class="metric-title">${esc(title)}</span>` +
    `<strong class="metric-value" ${text === undefined || text === null ? counted('metric:' + title, value) : ''}>${shown}</strong><span class="metric-note">${esc(note)}</span>`;
  return href ? `<a class="metric-card glass ${tone}" href="${esc(href)}">${body}</a>` : `<div class="metric-card glass ${tone}" tabindex="0">${body}</div>`;
}
export const button = (text, action, id = '', cls = '', extra = '') =>
  `<button type="button" class="${cls}" data-action="${action}" data-id="${esc(id)}" ${extra}>${text}</button>`;
const panelKey = title => `${state.page}:${String(title).replace(/<[^>]*>/g, '').trim().slice(0, 80)}`;
export const panel = (title, body, extra = '') => {
  const key = panelKey(title);
  const folded = prefs.collapsed.includes(key);
  const toggle = `<button type="button" class="ghost icon-button panel-toggle" data-action="panel-toggle" data-id="${esc(key)}" ` +
    `aria-expanded="${!folded}" aria-label="${esc(t(folded ? 'panels.expand' : 'panels.collapse'))}" title="${esc(t(folded ? 'panels.expand' : 'panels.collapse'))}">${icon('chevron')}</button>`;
  return `<section class="panel${folded ? ' collapsed' : ''}" data-panel="${esc(key)}"><div class="panel-head"><div class="panel-title">${toggle}<h2>${title}</h2></div>${extra}</div>${body}</section>`;
};
actions['panel-toggle'] = key => {
  const folded = !prefs.collapsed.includes(key);
  applyPrefs({collapsed: folded ? [...prefs.collapsed, key].slice(-200) : prefs.collapsed.filter(item => item !== key)});
  for (const section of document.querySelectorAll('section.panel[data-panel]')) {
    if (section.dataset.panel !== key) continue;
    section.classList.toggle('collapsed', folded);
    section.classList.toggle('unfolding', !folded);
    if (!folded) setTimeout(() => section.classList.remove('unfolding'), 400);
    const control = section.querySelector(':scope > .panel-head .panel-toggle');
    control?.setAttribute('aria-expanded', String(!folded));
    control?.setAttribute('aria-label', t(folded ? 'panels.expand' : 'panels.collapse'));
    control?.setAttribute('title', t(folded ? 'panels.expand' : 'panels.collapse'));
    if (!folded) window.dispatchEvent(new Event('resize'));
  }
};
export const heading = (title, subtitle, controls = '') =>
  `<div class="page-head"><div class="page-title"><h1>${title}</h1><p>${subtitle}</p></div><div class="actions">${controls}</div></div>`;

export function table(headers, rows, emptyText = t('common.empty')) {
  if (!rows.length) return empty(emptyText);
  return `<div class="table-wrap"><table><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
export const formField = (name, text, value = '', type = 'text', extra = '') => {
  const input = `<input aria-label="${esc(text)}" name="${name}" type="${type}" value="${esc(value)}" ${extra}>`;
  return `<label>${text}${type === 'password' ? `<span class="password-input">${input}<button type="button" class="ghost icon-button" data-action="password-toggle" aria-label="${esc(t('settings.showPassword'))}" aria-pressed="false">${icon('eye')}</button></span>` : input}</label>`;
};

let filterTimer, filterVersion = 0;
async function applyFilters(form) {
  if (!form.isConnected) return;
  const version = ++filterVersion, page = state.page;
  const focus = document.activeElement;
  const selection = focus && ['search', 'text'].includes(focus.type) ? [focus.selectionStart, focus.selectionEnd] : null;
  const openSets = [...form.querySelectorAll('details[open]')].map(item => item.dataset.filterSet);
  try {
    await forms[form.id]?.(form, Object.fromEntries(new FormData(form)));
    if (version !== filterVersion || state.page !== page) return;
    const updated = document.getElementById(form.id);
    for (const details of updated?.querySelectorAll('details') || []) details.open = openSets.includes(details.dataset.filterSet);
    const replacement = [...(updated?.elements || [])].find(item => item.name === focus?.name && item.value === focus?.value);
    if (replacement) {
      replacement.focus({preventScroll: true});
      if (selection) replacement.setSelectionRange(...selection);
    }
  } catch (error) { toast(safeError(error), true); }
}
document.addEventListener('input', event => {
  const form = event.target.closest('form[data-auto-filter]');
  if (!form || !['search', 'text'].includes(event.target.type) || event.isComposing) return;
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => applyFilters(form), 250);
});
document.addEventListener('change', event => {
  const form = event.target.closest('form[data-auto-filter]');
  if (!form || ['search', 'text'].includes(event.target.type)) return;
  clearTimeout(filterTimer);
  applyFilters(form);
});
export const selectField = (name, text, options, value = '', extra = '') =>
  `<label>${text}<select aria-label="${esc(text)}" name="${name}" ${extra}>${options.map(([v, caption]) =>
    `<option value="${esc(v)}" ${String(v) === String(value) ? 'selected' : ''}>${esc(caption)}</option>`).join('')}</select></label>`;
export const checkField = (name, text, value, extra = '') =>
  `<label class="check"><input name="${name}" type="checkbox" ${value ? 'checked' : ''} ${extra}>${text}</label>`;
export const textArea = (name, text, value = '', extra = '') =>
  `<label>${text}<textarea aria-label="${esc(text)}" name="${name}" ${extra}>${esc(value)}</textarea></label>`;

export function openDialog(title, body, footer = '') {
  modal.setAttribute('aria-label', title);
  modal.innerHTML = `<div class="panel-head"><h2>${esc(title)}</h2>${button(t('common.close'), 'close')}</div>` +
    `<div class="dialog-body">${body}</div>${footer ? `<div class="dialog-footer">${footer}</div>` : ''}`;
  if (!modal.open) modal.showModal();
}

const DATE_KEYS = ['last_seen', 'created_at', 'updated_at', 'last_transmission', 'last_delivery', 'certificate_expires_at',
  'timestamp', 'received_at', 'started_at', 'completed_at', 'transition_at', 'triggered_at'];
export function detailValue(key, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'boolean') return t(value ? 'common.yes' : 'common.no');
  if (DATE_KEYS.includes(key)) return formatDate(value);
  if (['status', 'desired_state', 'actual_state'].includes(key)) return label('status', value);
  if (['mode', 'certificate_validity', 'geolocation'].includes(key)) return label('settingValue', value);
  if (key === 'event_type') return label('event', value);
  if (key === 'severity') return label('severity', value);
  if (key === 'interaction_level') return label('interaction', value);
  if (key === 'update_policy') return label('policy', value);
  if (key === 'service_key') return serviceName(value);
  if (key === 'error') return safeError(value);
  if (Array.isArray(value)) return value.length ? value.join(', ') : '—';
  if (typeof value === 'number') return formatNumber(value);
  if (typeof value === 'object') return JSON.stringify(value);
  return value;
}
export const keyValues = rows =>
  `<dl class="key-values">${rows.map(([name, value]) => `<dt>${esc(name)}</dt><dd>${value}</dd>`).join('')}</dl>`;
export const detailList = (object, omit = []) =>
  keyValues(Object.entries(object).filter(([key]) => !omit.includes(key)).map(([key, value]) => [label('field', key), esc(detailValue(key, value))]));
export const rawDetails = (object, caption = t('events.raw')) =>
  `<details><summary>${caption}</summary><pre>${esc(JSON.stringify(object, null, 2))}</pre></details>`;

export function meter(caption, used, total, unit = '') {
  const ratio = total > 0 ? Math.min(used / total, 1) : 0;
  const level = ratio >= 0.9 ? 'critical' : ratio >= 0.7 ? 'warning' : 'ok';
  return `<div class="meter ${level}"><div class="meter-head"><span>${esc(caption)}</span><strong>${formatNumber(used)} / ${formatNumber(total)}${unit ? ' ' + esc(unit) : ''}</strong></div>` +
    `<progress value="${used}" max="${Math.max(total, 1)}" aria-label="${esc(caption)}"></progress></div>`;
}

export async function download(path, name) {
  const response = await fetch('/api/v1' + path);
  if (!response.ok) throw new Error(t('errors.export'));
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
