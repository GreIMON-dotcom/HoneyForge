import {t, tk, label, esc, button, toast, actions} from './ui.js';

export const FIELDS = {
  description: {type: 'text', max: 1000, wide: true},
  enabled: {type: 'check'},
  port: {type: 'number', min: 1024, max: 65535},
  response_delay_ms: {type: 'number', min: 0, max: 2000},
  max_connections: {type: 'number', min: 1, max: 256},
  banner: {type: 'text', max: 200, wide: true},
  banner_encoding: {type: 'select', options: ['utf-8', 'ascii', 'latin-1']},
  connection_timeout: {type: 'number', min: 1, max: 600},
  hostname: {type: 'text', max: 31},
  max_commands: {type: 'number', min: 1, max: 200},
  max_input_bytes: {type: 'number', min: 0, max: 4096},
  identity: {type: 'text', max: 80},
  site_description: {type: 'text', max: 300, wide: true},
  site_layout: {type: 'select', options: ['plain', 'store', 'portal']},
  site_footer: {type: 'text', max: 300, wide: true},
  decoy_accounts: {type: 'list'},
  authentication_mode: {type: 'select', options: ['accept-all', 'configured-accounts']},
  status_message: {type: 'text', max: 1000, wide: true},
  session_timeout: {type: 'number', min: 60, max: 86400},
  login_path: {type: 'text', max: 120},
  telemetry_enabled: {type: 'check'},
  connection_logging: {type: 'check'},
  authentication_logging: {type: 'check'},
  request_logging: {type: 'check'},
  logging_verbosity: {type: 'select', options: ['metadata', 'detailed']},
  batch_interval: {type: 'number', min: 1, max: 30},
  buffer_limit: {type: 'number', min: 100, max: 1000000},
  health_interval: {type: 'number', min: 1, max: 15},
  retry_max_seconds: {type: 'number', min: 3, max: 120},
  memory_mb: {type: 'number', min: 64, max: 256},
  cpu_limit: {type: 'number', min: 0.1, max: 1, step: 0.1},
};
export const SECTIONS = {
  tcp: ['banner', 'banner_encoding', 'connection_timeout', 'max_input_bytes'],
  'telnet-shell': ['banner', 'banner_encoding', 'hostname', 'authentication_mode', 'decoy_accounts', 'connection_timeout',
    'max_input_bytes', 'max_commands'],
  http: ['identity', 'site_description', 'site_layout', 'site_footer', 'authentication_mode', 'decoy_accounts', 'status_message', 'session_timeout', 'login_path'],
  behaviour: ['response_delay_ms', 'max_connections'],
  monitoring: ['telemetry_enabled', 'connection_logging', 'authentication_logging', 'request_logging', 'logging_verbosity',
    'batch_interval', 'buffer_limit', 'health_interval', 'retry_max_seconds'],
  resources: ['memory_mb', 'cpu_limit'],
};
export const serviceSection = (key, family) => SECTIONS[key] || SECTIONS[family];
SECTIONS['linux-sandbox'] = [...SECTIONS['telnet-shell']];
const COMPONENT_TYPES = ['heading', 'paragraph', 'form', 'links', 'info_panel', 'status_panel', 'hero', 'products', 'cards'];
const GARMENTS = ['tshirt', 'hoodie', 'jeans', 'dress', 'jacket', 'sneakers', 'cap', 'bag'];
const COLORS = ['black', 'white', 'grey', 'beige', 'navy', 'blue', 'green', 'olive', 'red', 'pink', 'brown'];
const NEW_COMPONENT = {
  heading: () => ({type: 'heading', text: t('pageBuilder.newHeading'), level: 2}),
  paragraph: () => ({type: 'paragraph', text: t('pageBuilder.newParagraph')}),
  form: () => ({type: 'form', action: '/login', submit_label: t('pageBuilder.submitDefault'), fields: [
    {name: 'username', label: t('pageBuilder.usernameDefault'), kind: 'text'},
    {name: 'password', label: t('pageBuilder.passwordDefault'), kind: 'password'}]}),
  links: () => ({type: 'links', items: [{label: t('pageBuilder.linkDefault'), href: '/'}]}),
  info_panel: () => ({type: 'info_panel', title: t('pageBuilder.panelDefault'), text: t('pageBuilder.newParagraph')}),
  status_panel: () => ({type: 'status_panel', title: t('pageBuilder.statusDefault'), items: [
    {label: t('pageBuilder.itemDefault'), value: t('pageBuilder.valueDefault'), state: 'ok'}]}),
  hero: () => ({type: 'hero', title: t('pageBuilder.newHeading'), text: t('pageBuilder.newParagraph'), button_label: t('pageBuilder.buttonDefault'), button_href: '/'}),
  products: () => ({type: 'products', title: '', items: [NEW_ITEM.products()]}),
  cards: () => ({type: 'cards', title: '', items: [NEW_ITEM.cards()]}),
};
const NEW_ITEM = {
  form: () => ({name: 'field', label: t('pageBuilder.fieldDefault'), kind: 'text'}),
  links: () => ({label: t('pageBuilder.linkDefault'), href: '/'}),
  status_panel: () => ({label: t('pageBuilder.itemDefault'), value: t('pageBuilder.valueDefault'), state: 'ok'}),
  products: () => ({name: t('pageBuilder.productDefault'), price: t('pageBuilder.priceDefault'), note: '', kind: 'tshirt', color: 'black', href: '/'}),
  cards: () => ({title: t('pageBuilder.panelDefault'), text: t('pageBuilder.newParagraph')}),
};
const ITEM_LIST = {form: 'fields', links: 'items', status_panel: 'items', products: 'items', cards: 'items'};
const PLACEHOLDER_NAMES = {title: '{title}', description: '{description}', account: '{account}', status: '{status}'};

const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
export const sameValue = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const PROFILE_ONLY = ['name', 'service_key', 'service_type', 'interaction_level', 'listen_address', 'network', 'outbound_policy', 'port'];
export const ownSettings = (draft, base) => Object.fromEntries(Object.entries(draft).filter(([key, value]) =>
  !PROFILE_ONLY.includes(key) && !sameValue(value, base[key])));

let editor = null;
export function openEditor(draft, plugin) { editor = {draft, plugin}; return editor; }
export const editorDraft = () => editor?.draft;

function resolve(target, path) {
  const keys = path.split('.');
  const last = keys.pop();
  for (const key of keys) target = target[key];
  return [target, last];
}
function inputValue(node) {
  const kind = node.dataset.kind;
  if (kind === 'check') return node.checked;
  if (kind === 'number') return node.value === '' ? null : Number(node.value);
  if (kind === 'list') return node.value.split(',').map(v => v.trim()).filter(Boolean);
  if (kind === 'json') { try { return JSON.parse(node.value); } catch { return node.value; } }
  if (kind === 'optional') return node.value || null;
  return node.value;
}
export function syncDraft(container = document) {
  if (!editor) return null;
  for (const node of container.querySelectorAll('[data-path]')) {
    try {
      const [target, key] = resolve(editor.draft, node.dataset.path);
      target[key] = inputValue(node);
    } catch {   }
  }
  return editor.draft;
}
export function draftProblems(draft) {
  const problems = [];
  for (const route of draft.routes || []) {
    if (route.response === 'json' && (typeof route.json_body !== 'object' || route.json_body === null || Array.isArray(route.json_body)))
      problems.push(t('routes.invalidJson', {path: route.path}));
    if (route.response === 'page' && !route.page) problems.push(t('routes.pageRequired', {path: route.path}));
  }
  return problems;
}

function control(path, text, value, meta, extra = '') {
  const bound = `data-path="${esc(path)}" aria-label="${esc(text)}" ${extra}`;
  if (meta.type === 'check')
    return `<label class="check"><input type="checkbox" data-kind="check" ${bound} ${value ? 'checked' : ''}>${esc(text)}</label>`;
  if (meta.type === 'select')
    return `<label>${esc(text)}<select data-kind="${meta.kind || 'text'}" ${bound}>${meta.options.map(option => {
      const [key, caption] = Array.isArray(option) ? option : [option, meta.captions ? label(meta.captions, option) : option];
      return `<option value="${esc(key)}" ${String(key) === String(value ?? '') ? 'selected' : ''}>${esc(caption)}</option>`;
    }).join('')}</select></label>`;
  if (meta.type === 'area')
    return `<label class="full">${esc(text)}<textarea data-kind="${meta.kind || 'text'}" ${bound} maxlength="${meta.max || 2000}">${esc(value ?? '')}</textarea></label>`;
  if (meta.type === 'list')
    return `<label>${esc(text)}<input type="text" data-kind="list" ${bound} value="${esc((value || []).join(', '))}"></label>`;
  if (meta.type === 'number')
    return `<label>${esc(text)}<input type="number" data-kind="number" ${bound} value="${esc(value ?? '')}" min="${meta.min}" max="${meta.max}" step="${meta.step || 1}" required></label>`;
  return `<label class="${meta.wide ? 'full' : ''}">${esc(text)}<input type="text" data-kind="text" ${bound} value="${esc(value ?? '')}" maxlength="${meta.max || 200}"></label>`;
}
const CAPTIONS = {banner_encoding: null, authentication_mode: 'authMode', logging_verbosity: 'verbosity', site_layout: 'siteLayout'};
export function fieldText(name, value) {
  if (typeof value === 'boolean') return t(value ? 'common.yes' : 'common.no');
  if (Array.isArray(value)) return value.join(', ');
  return CAPTIONS[name] ? label(CAPTIONS[name], value) : String(value ?? '—');
}
export function fieldGrid(names, draft, plugin) {
  const shown = names.filter(name => !plugin || plugin.fields.includes(name));
  return `<div class="form-grid">${shown.map(name =>
    control(name, tk('fields', name), draft[name], {...FIELDS[name], captions: CAPTIONS[name]})).join('')}</div>`;
}

function itemRows(page, index, component) {
  const list = ITEM_LIST[component.type];
  const base = `pages.${page}.components.${index}.${list}`;
  const rows = component[list].map((item, position) => {
    const at = `${base}.${position}`;
    const cells = component.type === 'form'
      ? control(at + '.name', t('pageBuilder.fieldName'), item.name, {type: 'text', max: 40}) +
        control(at + '.label', t('pageBuilder.fieldLabel'), item.label, {type: 'text', max: 80}) +
        control(at + '.kind', t('pageBuilder.fieldKind'), item.kind, {type: 'select', options: ['text', 'password'], captions: 'inputKind'})
      : component.type === 'links'
        ? control(at + '.label', t('pageBuilder.linkLabel'), item.label, {type: 'text', max: 80}) +
          control(at + '.href', t('pageBuilder.linkTarget'), item.href, {type: 'text', max: 120})
        : component.type === 'products'
        ? control(at + '.name', t('pageBuilder.productName'), item.name, {type: 'text', max: 80}) +
          control(at + '.price', t('pageBuilder.productPrice'), item.price, {type: 'text', max: 40}) +
          control(at + '.note', t('pageBuilder.productNote'), item.note, {type: 'text', max: 30}) +
          control(at + '.kind', t('pageBuilder.productKind'), item.kind, {type: 'select', options: GARMENTS, captions: 'garment'}) +
          control(at + '.color', t('pageBuilder.productColor'), item.color, {type: 'select', options: COLORS, captions: 'colorName'}) +
          control(at + '.href', t('pageBuilder.linkTarget'), item.href, {type: 'text', max: 120})
        : component.type === 'cards'
        ? control(at + '.title', t('pageBuilder.title'), item.title, {type: 'text', max: 80}) +
          control(at + '.text', t('pageBuilder.text'), item.text, {type: 'text', max: 300})
        : control(at + '.label', t('pageBuilder.itemLabel'), item.label, {type: 'text', max: 80}) +
          control(at + '.value', t('pageBuilder.itemValue'), item.value, {type: 'text', max: 120}) +
          control(at + '.state', t('pageBuilder.itemState'), item.state, {type: 'select', options: ['ok', 'warning', 'error'], captions: 'itemState'});
    return `<div class="item-row">${cells}${button(t('common.remove'), 'spec-item-remove', `${page}|${index}|${position}`, 'danger')}</div>`;
  }).join('');
  return rows + button(t('pageBuilder.addItem'), 'spec-item-add', `${page}|${index}`);
}
function componentEditor(page, index, component, count) {
  const at = `pages.${page}.components.${index}`;
  let body = '';
  if (component.type === 'heading')
    body = control(at + '.text', t('pageBuilder.text'), component.text, {type: 'text', max: 200, wide: true}) +
      control(at + '.level', t('pageBuilder.level'), component.level, {type: 'select', kind: 'number', options: [[1, '1'], [2, '2'], [3, '3']]});
  else if (component.type === 'paragraph')
    body = control(at + '.text', t('pageBuilder.text'), component.text, {type: 'area'});
  else if (component.type === 'form')
    body = control(at + '.action', t('pageBuilder.formAction'), component.action, {type: 'text', max: 120}) +
      control(at + '.submit_label', t('pageBuilder.submitLabel'), component.submit_label, {type: 'text', max: 40}) +
      `<div class="full">${itemRows(page, index, component)}</div>`;
  else if (component.type === 'links')
    body = `<div class="full">${itemRows(page, index, component)}</div>`;
  else if (component.type === 'info_panel')
    body = control(at + '.title', t('pageBuilder.title'), component.title, {type: 'text', max: 120, wide: true}) +
      control(at + '.text', t('pageBuilder.text'), component.text, {type: 'area'});
  else if (component.type === 'hero')
    body = control(at + '.title', t('pageBuilder.title'), component.title, {type: 'text', max: 120, wide: true}) +
      control(at + '.text', t('pageBuilder.text'), component.text, {type: 'area', max: 400}) +
      control(at + '.button_label', t('pageBuilder.buttonLabel'), component.button_label, {type: 'text', max: 40}) +
      control(at + '.button_href', t('pageBuilder.linkTarget'), component.button_href, {type: 'text', max: 120});
  else if (component.type === 'products' || component.type === 'cards')
    body = control(at + '.title', t('pageBuilder.blockTitle'), component.title, {type: 'text', max: 120, wide: true}) +
      `<div class="full">${itemRows(page, index, component)}</div>`;
  else
    body = control(at + '.title', t('pageBuilder.title'), component.title, {type: 'text', max: 120, wide: true}) +
      `<div class="full">${itemRows(page, index, component)}</div>`;
  const id = `${page}|${index}`;
  return `<div class="component"><div class="component-head"><strong>${esc(label('component', component.type))}</strong><div class="actions">` +
    (index > 0 ? button('↑', 'spec-component-up', id, '', `title="${esc(t('pageBuilder.moveUp'))}" aria-label="${esc(t('pageBuilder.moveUp'))}"`) : '') +
    (index < count - 1 ? button('↓', 'spec-component-down', id, '', `title="${esc(t('pageBuilder.moveDown'))}" aria-label="${esc(t('pageBuilder.moveDown'))}"`) : '') +
    button(t('common.remove'), 'spec-component-remove', id, 'danger') +
    `</div></div><div class="form-grid">${body}</div></div>`;
}
function pageEditor(key, page) {
  const components = page.components.map((component, index) => componentEditor(key, index, component, page.components.length)).join('');
  const picker = `<select aria-label="${esc(t('pageBuilder.componentType'))}" data-new-component="${esc(key)}">${COMPONENT_TYPES.map(type =>
    `<option value="${type}">${esc(label('component', type))}</option>`).join('')}</select>`;
  return `<details class="page-editor" ${Object.keys(editor.draft.pages)[0] === key ? 'open' : ''}><summary>${esc(t('pageBuilder.page', {key}))} · ${esc(page.title)}</summary>` +
    `<div class="form-grid">${control(`pages.${key}.title`, t('pageBuilder.pageTitle'), page.title, {type: 'text', max: 120, wide: true})}</div>` +
    (components || `<p class="hint">${t('pageBuilder.emptyPage')}</p>`) +
    `<div class="actions builder-add">${picker}${button(t('pageBuilder.addComponent'), 'spec-component-add', key)}${button(t('pageBuilder.removePage'), 'spec-page-remove', key, 'danger')}</div></details>`;
}
function routeEditor(route, index, pageOptions) {
  const at = `routes.${index}`;
  const optional = [['', t('routes.none')], ...pageOptions];
  return `<div class="route"><div class="form-grid route-grid">` +
    control(at + '.path', t('routes.path'), route.path, {type: 'text', max: 120}) +
    control(at + '.method', t('routes.method'), route.method, {type: 'select', options: ['GET', 'POST']}) +
    control(at + '.response', t('routes.response'), route.response, {type: 'select', options: ['page', 'json', 'login'], captions: 'response'}, 'data-rerender="1"') +
    control(at + '.status', t('routes.status'), route.status, {type: 'select', kind: 'number', options: [200, 201, 400, 401, 403, 404, 500, 503].map(code => [code, String(code)])}) +
    (route.response === 'json' ? '' : control(at + '.page', route.response === 'login' ? t('routes.successPage') : t('routes.page'), route.page, {type: 'select', kind: 'optional', options: optional})) +
    (route.response === 'login' ? control(at + '.failure_page', t('routes.failurePage'), route.failure_page, {type: 'select', kind: 'optional', options: optional}) : '') +
    (route.response === 'json' ? control(at + '.json_body', t('routes.jsonBody'), typeof route.json_body === 'string' ? route.json_body : JSON.stringify(route.json_body ?? {}, null, 2), {type: 'area', kind: 'json', max: 2000}) : '') +
    control(at + '.requires_login', t('routes.requiresLogin'), route.requires_login, {type: 'check'}) +
    control(at + '.log', t('routes.log'), route.log, {type: 'check'}) +
    `</div>${button(t('routes.remove'), 'spec-route-remove', index, 'danger')}</div>`;
}
export function siteEditor() {
  const draft = editor.draft;
  const pageOptions = Object.entries(draft.pages).map(([key, page]) => [key, `${key} · ${page.title}`]);
  return `<div class="form-section"><h3>${t('pageBuilder.heading')}</h3><p class="hint">${esc(t('pageBuilder.hint', PLACEHOLDER_NAMES))}</p>` +
    (Object.entries(draft.pages).map(([key, page]) => pageEditor(key, page)).join('') || `<p class="hint">${t('pageBuilder.noPages')}</p>`) +
    `<div class="actions builder-add">${button(t('pageBuilder.addPage'), 'spec-page-add')}</div></div>` +
    `<div class="form-section"><h3>${t('routes.heading')}</h3><p class="hint">${t('routes.hint')}</p>` +
    (draft.routes.map((route, index) => routeEditor(route, index, pageOptions)).join('') || `<p class="hint">${t('routes.empty')}</p>`) +
    `<div class="actions builder-add">${button(t('routes.add'), 'spec-route-add')}</div></div>`;
}
function redraw() {
  const host = document.querySelector('#spec-site');
  if (host) host.innerHTML = siteEditor();
}
function structural(change) {
  return id => {
    if (!editor) return;
    syncDraft();
    const result = change(editor.draft, String(id ?? '').split('|'));
    if (typeof result === 'string') toast(result, true);
    redraw();
  };
}
Object.assign(actions, {
  'spec-page-add': structural(draft => {
    if (Object.keys(draft.pages).length >= 12) return t('pageBuilder.tooManyPages');
    let number = Object.keys(draft.pages).length + 1;
    while (draft.pages['page' + number]) number++;
    draft.pages['page' + number] = {title: t('pageBuilder.newPage'), components: [NEW_COMPONENT.heading()]};
  }),
  'spec-page-remove': structural((draft, [key]) => {
    if (draft.routes.some(route => route.page === key || route.failure_page === key)) return t('pageBuilder.pageInUse');
    delete draft.pages[key];
  }),
  'spec-component-add': structural((draft, [key]) => {
    if (draft.pages[key].components.length >= 30) return t('pageBuilder.tooManyComponents');
    const type = document.querySelector(`[data-new-component="${CSS.escape(key)}"]`).value;
    draft.pages[key].components.push(NEW_COMPONENT[type]());
  }),
  'spec-component-remove': structural((draft, [key, index]) => { draft.pages[key].components.splice(Number(index), 1); }),
  'spec-component-up': structural((draft, [key, index]) => {
    const list = draft.pages[key].components;
    list.splice(Number(index) - 1, 0, list.splice(Number(index), 1)[0]);
  }),
  'spec-component-down': structural((draft, [key, index]) => {
    const list = draft.pages[key].components;
    list.splice(Number(index) + 1, 0, list.splice(Number(index), 1)[0]);
  }),
  'spec-item-add': structural((draft, [key, index]) => {
    const component = draft.pages[key].components[Number(index)];
    component[ITEM_LIST[component.type]].push(NEW_ITEM[component.type]());
  }),
  'spec-item-remove': structural((draft, [key, index, position]) => {
    const component = draft.pages[key].components[Number(index)];
    if (component[ITEM_LIST[component.type]].length <= 1) return t('pageBuilder.lastItem');
    component[ITEM_LIST[component.type]].splice(Number(position), 1);
  }),
  'spec-route-add': structural(draft => {
    if (draft.routes.length >= 24) return t('routes.tooMany');
    const first = Object.keys(draft.pages)[0];
    draft.routes.push(first
      ? {path: '/new', method: 'GET', response: 'page', page: first, failure_page: null, json_body: null, status: 200, requires_login: false, log: true}
      : {path: '/new', method: 'GET', response: 'json', page: null, failure_page: null, json_body: {synthetic: true}, status: 200, requires_login: false, log: true});
  }),
  'spec-route-remove': structural((draft, [index]) => { draft.routes.splice(Number(index), 1); }),
});
document.addEventListener('change', event => {
  if (!editor || !event.target.dataset?.rerender) return;
  syncDraft();
  for (const route of editor.draft.routes) {
    if (route.response === 'json' && (route.json_body === null || route.json_body === undefined)) route.json_body = {synthetic: true};
    if (route.response !== 'json') route.json_body = null;
    if (route.response === 'login') route.method = 'POST';
  }
  redraw();
});
