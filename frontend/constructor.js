import {t, tk, label, plural, formatNumber, esc, state, pages, actions, api, post, toast, button, heading, panel, admin,
  empty, formField, selectField, checkField, keyValues, rawDetails, meter, navigate, rerender, serviceName} from './ui.js';
import {SECTIONS, serviceSection, openEditor, syncDraft, draftProblems, fieldGrid, siteEditor, ownSettings} from './specform.js';

const STEPS = ['general', 'service', 'network', 'resources', 'monitoring', 'review', 'deploy'];
const clone = value => JSON.parse(JSON.stringify(value));
let wizard = null;

function blank() {
  return {step: 0, name: '', description: '', tags: '', serviceKey: 'tcp-banner', profileId: '', profileName: '',
    draft: null, hostId: '', portMode: 'auto', port: '', updatePolicy: 'manual', endpointCheck: null, validation: null, busy: false,
    alert: {enabled: false, event_type: 'authentication_attempt', threshold: 10, window_seconds: 60, severity: 'medium'}};
}
const plugin = () => state.services.find(service => service.key === wizard.serviceKey);
const selectedProfile = () => state.profiles.find(profile => profile.id === wizard.profileId);
const selectedHost = () => state.hosts.find(host => host.id === wizard.hostId);

async function loadDraft() {
  const profile = selectedProfile();
  const spec = profile ? clone(profile.spec) : (await api('/service-types/' + wizard.serviceKey)).defaults;
  wizard.draft = spec;
  wizard.validation = wizard.endpointCheck = null;
}
function overrides() {
  const base = selectedProfile()?.spec;
  return base ? ownSettings(wizard.draft, base) : {};
}
function requestBody(deploy) {
  const body = {name: wizard.name.trim(), description: wizard.description.trim(),
    tags: wizard.tags.split(',').map(tag => tag.trim()).filter(Boolean), host_id: wizard.hostId,
    port_mode: wizard.portMode, port: wizard.portMode === 'manual' ? Number(wizard.port) : null,
    update_policy: wizard.updatePolicy, deploy};
  if (wizard.profileId) return {...body, profile_id: wizard.profileId, overrides: overrides()};
  return {...body, profile: {...wizard.draft, name: wizard.profileName.trim() || wizard.name.trim()}, overrides: {}};
}

function collect() {
  const form = document.querySelector('#wizard-form');
  if (!form) return;
  const value = name => form.elements[name]?.value;
  if (STEPS[wizard.step] === 'general') {
    Object.assign(wizard, {name: value('name'), description: value('description'), tags: value('tags'), profileName: value('profile_name') ?? wizard.profileName});
  } else if (STEPS[wizard.step] === 'network') {
    Object.assign(wizard, {hostId: value('host_id'), portMode: value('port_mode'), port: value('port') ?? wizard.port});
  } else if (STEPS[wizard.step] === 'monitoring') {
    wizard.updatePolicy = value('update_policy');
    wizard.alert = {enabled: form.elements.alert_enabled.checked, event_type: value('alert_event'),
      threshold: Number(value('alert_threshold')), window_seconds: Number(value('alert_window')), severity: value('alert_severity')};
  }
  syncDraft(form);
}
function stepProblem() {
  const step = STEPS[wizard.step];
  if (step === 'general') {
    if (!wizard.name.trim()) return t('wizard.nameRequired');
    if (!wizard.profileId && !wizard.profileName.trim()) return t('wizard.profileNameRequired');
  }
  if (step === 'service') return draftProblems(wizard.draft)[0];
  if (step === 'network') {
    if (!wizard.hostId) return t('wizard.hostRequired');
    if (wizard.portMode === 'manual' && !wizard.port) return t('wizard.portRequired');
  }
  return null;
}

function stepper() {
  return `<ol class="stepper">${STEPS.map((step, index) =>
    `<li class="${index === wizard.step ? 'current' : index < wizard.step ? 'done' : ''}"><span>${index + 1}</span>${tk('wizard.steps', step)}</li>`).join('')}</ol>`;
}
function generalStep() {
  const profiles = state.profiles.filter(profile => profile.service_key === wizard.serviceKey);
  const service = plugin();
  return `<div class="form-grid">${formField('name', t('wizard.name'), wizard.name, 'text', 'required maxlength="80"')}` +
    formField('tags', t('wizard.tags'), wizard.tags, 'text', 'maxlength="200"') +
    `<div class="full">${formField('description', t('wizard.descriptionField'), wizard.description, 'text', 'maxlength="1000"')}</div>` +
    selectField('service_key', t('wizard.service'), state.services.map(item => [item.key, item.display_name]), wizard.serviceKey, 'data-wizard="service"') +
    `<label>${t('wizard.level')}<input aria-label="${esc(t('wizard.level'))}" value="${esc(label('interaction', service.interaction_level))}" readonly></label>` +
    selectField('profile_id', t('wizard.profile'), [['', t('wizard.newProfile')], ...profiles.map(profile => [profile.id, `${profile.name} · v${profile.version}`])], wizard.profileId, 'data-wizard="profile"') +
    (wizard.profileId ? '' : formField('profile_name', t('wizard.profileName'), wizard.profileName, 'text', 'maxlength="80"')) +
    `</div><p class="hint">${esc(service.description)}</p><p class="hint">${wizard.profileId ? t('wizard.existingProfileHint') : t('wizard.newProfileHint')}</p>`;
}
function serviceStep() {
  const service = plugin();
  const family = service.emulator;
  return `<div class="form-section"><h3>${esc(service.display_name)}</h3>${fieldGrid(serviceSection(service.key, family), wizard.draft, service)}</div>` +
    `<div class="form-section"><h3>${t('wizard.behaviour')}</h3>${fieldGrid(SECTIONS.behaviour, wizard.draft, service)}</div>` +
    (family === 'http' ? `<div id="spec-site">${siteEditor()}</div>` : '');
}
function networkStep() {
  const high = wizard.serviceKey === 'linux-sandbox';
  const hosts = state.hosts.filter(host => host.approved && (!high || (host.id !== 'lab-docker' && host.controller_connected && host.metrics?.sandbox?.ready && host.metrics.sandbox.runtime === 'runsc')));
  const host = hosts.find(item => item.id === wizard.hostId) || hosts[0];
  wizard.hostId = host?.id || '';
  if (!host) return empty(t(high ? 'wizard.noSandboxHosts' : 'wizard.noHosts'));
  const check = wizard.endpointCheck;
  const result = check ? `<p class="${check.available ? 'notice ok' : 'notice error'}">${esc(check.available ? t('wizard.endpointFree', {port: check.port}) : check.reason)}</p>` : '';
  return `<div class="form-grid">` +
    selectField('host_id', t('wizard.host'), hosts.map(item => [item.id, `${item.name} · ${item.controller_connected ? t('resources.controllerOnline') : t('resources.controllerOffline')}`]), wizard.hostId, 'data-wizard="host"') +
    `<label>${t('wizard.network')}<input aria-label="${esc(t('wizard.network'))}" value="${esc(t('wizard.networkValue', {name: host.network}))}" readonly></label>` +
    `<label>${t('wizard.servicePort')}<input aria-label="${esc(t('wizard.servicePort'))}" value="${esc(wizard.draft.port)}" readonly></label>` +
    selectField('port_mode', t('wizard.allocation'), [['auto', label('portMode', 'auto')], ['manual', label('portMode', 'manual')]], wizard.portMode, 'data-wizard="mode"') +
    (wizard.portMode === 'manual' ? formField('port', t('wizard.manualPort'), wizard.port, 'number', `min="${host.port_range_start}" max="${host.port_range_end}" required`) : '') +
    `<label>${t('wizard.clients')}<input aria-label="${esc(t('wizard.clients'))}" value="${esc(t('wizard.clientsValue'))}" readonly></label>` +
    `</div><div class="actions">${button(t('wizard.checkEndpoint'), 'wizard-check-endpoint')}</div>${result}` +
    `<p class="hint">${t('wizard.networkHint', {start: host.port_range_start, end: host.port_range_end})}</p>`;
}
function resourcesStep() {
  const host = selectedHost();
  const capacity = host?.capacity;
  const base = capacity?.per_instance_overhead || {memory_mb: 0, cpu: 0};
  const extra = {memory_mb: base.memory_mb + (wizard.serviceKey === 'linux-sandbox' ? 256 : 0), cpu: base.cpu + (wizard.serviceKey === 'linux-sandbox' ? 0.5 : 0)};
  const available = capacity ? `<div class="meters">` +
    meter(t('resources.instances'), capacity.allocated.instances, capacity.policy.max_instances) +
    meter(t('resources.cpu'), capacity.allocated.cpu, capacity.policy.cpu_budget) +
    meter(t('resources.memory'), capacity.allocated.memory_mb, capacity.policy.memory_budget_mb, t('units.mb')) + `</div>` : '';
  return `<div class="form-section"><h3>${t('wizard.instanceLimits')}</h3>${fieldGrid([...SECTIONS.resources, 'max_connections', 'buffer_limit'], wizard.draft, plugin())}` +
    `<p class="hint">${t('wizard.overheadHint', {memory: formatNumber(extra.memory_mb), cpu: formatNumber(extra.cpu)})}</p></div>` +
    `<div class="form-section"><h3>${t('wizard.hostBudget', {name: host?.name || '—'})}</h3>${available || empty(t('wizard.hostRequired'))}</div>`;
}
function monitoringStep() {
  const rule = wizard.alert;
  const events = [...plugin().event_types, 'offline', 'queue_backlog'];
  return `<div class="form-section"><h3>${t('wizard.telemetry')}</h3>${fieldGrid(SECTIONS.monitoring, wizard.draft, plugin())}</div>` +
    `<div class="form-section"><h3>${t('wizard.updates')}</h3><div class="form-grid">` +
    selectField('update_policy', t('wizard.updatePolicy'), [['manual', label('policy', 'manual')], ['auto', label('policy', 'auto')]], wizard.updatePolicy) + `</div></div>` +
    `<div class="form-section"><h3>${t('wizard.alertProfile')}</h3>${checkField('alert_enabled', t('wizard.alertEnabled'), rule.enabled)}<div class="form-grid">` +
    selectField('alert_event', t('common.eventType'), events.map(type => [type, label('event', type)]), rule.event_type) +
    selectField('alert_severity', t('common.severity'), ['info', 'low', 'medium', 'high', 'critical'].map(level => [level, label('severity', level)]), rule.severity) +
    formField('alert_threshold', t('alerts.threshold'), rule.threshold, 'number', 'min="1" max="100000"') +
    formField('alert_window', t('alerts.windowSeconds'), rule.window_seconds, 'number', 'min="10" max="86400"') + `</div></div>`;
}
function reviewStep() {
  const result = wizard.validation;
  if (!result) return empty(t('wizard.validating'));
  const draft = result.configuration || wizard.draft;
  const host = selectedHost();
  const verdict = result.valid
    ? `<p class="notice ok">${t('wizard.valid')}</p>`
    : `<div class="notice error"><strong>${t('wizard.invalid')}</strong><ul>${result.errors.map(error => `<li>${esc(error)}</li>`).join('')}</ul></div>`;
  const monitoring = [draft.telemetry_enabled ? t('common.enabled') : t('common.disabled'),
    wizard.alert.enabled ? t('wizard.alertSummary', {event: label('event', wizard.alert.event_type), threshold: formatNumber(wizard.alert.threshold), seconds: plural('counts.seconds', wizard.alert.window_seconds)}) : t('wizard.noAlert')];
  return verdict + keyValues([
    [t('wizard.name'), esc(wizard.name)],
    [t('wizard.service'), esc(serviceName(wizard.serviceKey))],
    [t('wizard.profile'), esc(selectedProfile()?.name || t('wizard.newProfileNamed', {name: wizard.profileName || wizard.name}))],
    [t('wizard.host'), esc(host?.name || '—')],
    [t('wizard.endpoint'), esc(result.endpoint ? t('wizard.endpointSummary', {port: result.endpoint.port, network: result.endpoint.network, mode: label('portMode', result.endpoint.mode)}) : '—')],
    [t('wizard.requirements'), esc(result.runtime?.memory_mb ? t('wizard.requirementsValue', {memory: formatNumber(result.runtime.memory_mb), cpu: formatNumber(result.runtime.cpu), containers: result.runtime.containers}) : '—')],
    [tk('wizard.steps', 'monitoring'), esc(monitoring.join(' · '))],
    [t('wizard.behaviourExpected'), esc(t('wizard.behaviourText'))],
  ]) + rawDetails(result.configuration || wizard.draft, t('profiles.preview'));
}
function deployStep() {
  const valid = wizard.validation?.valid;
  return `<p>${t('wizard.deployIntro')}</p>` + (valid ? '' : `<p class="notice error">${t('wizard.fixFirst')}</p>`) +
    `<div class="actions wizard-final">${button(t('wizard.createAndDeploy'), 'wizard-create', 'deploy', 'primary', valid && !wizard.busy ? '' : 'disabled')}` +
    `${button(t('wizard.saveDraft'), 'wizard-create', 'draft', '', valid && !wizard.busy ? '' : 'disabled')}${button(t('wizard.cancel'), 'wizard-cancel')}</div>` +
    `<p class="hint">${t('wizard.deployHint')}</p>`;
}
const BODIES = {general: generalStep, service: serviceStep, network: networkStep, resources: resourcesStep,
  monitoring: monitoringStep, review: reviewStep, deploy: deployStep};

pages.constructor = async () => {
  if (!admin()) return heading(t('navigation.constructor'), t('wizard.description')) + empty(t('errors.adminRequired'));
  if (!wizard) {
    wizard = blank();
    const preset = state.profiles.find(profile => profile.id === state.param);
    const service = state.services.find(item => item.key === state.param);
    if (preset) Object.assign(wizard, {profileId: preset.id, serviceKey: preset.service_key});
    if (service) wizard.serviceKey = service.key;
  }
  if (!wizard.draft) await loadDraft();
  openEditor(wizard.draft, plugin());
  const step = STEPS[wizard.step];
  const footer = `<div class="wizard-nav">${wizard.step > 0 ? button(t('wizard.back'), 'wizard-back') : '<span></span>'}` +
    `${wizard.step < STEPS.length - 1 ? button(t('wizard.next'), 'wizard-next', '', 'primary') : ''}</div>`;
  return heading(t('navigation.constructor'), t('wizard.description'), button(t('wizard.reset'), 'wizard-cancel')) + stepper() +
    panel(tk('wizard.steps', step), `<form id="wizard-form" class="panel-body" novalidate>${BODIES[step]()}</form>${footer}`);
};

async function validate() {
  wizard.validation = null;
  try {
    wizard.validation = await post('/honeypots/validate', requestBody(true));
  } catch (error) {
    wizard.validation = {valid: false, errors: [error.message]};
  }
}
async function go(step) {
  wizard.step = step;
  if (STEPS[step] === 'review' || STEPS[step] === 'deploy') await validate();
  await rerender();
  document.querySelector('.main')?.scrollIntoView();
}
Object.assign(actions, {
  'wizard-next': async () => {
    collect();
    const problem = stepProblem();
    if (problem) return toast(problem, true);
    await go(wizard.step + 1);
  },
  'wizard-back': async () => { collect(); await go(wizard.step - 1); },
  'wizard-cancel': async () => { wizard = null; state.param = null; navigate('constructor'); await rerender(); },
  'wizard-check-endpoint': async () => {
    collect();
    wizard.endpointCheck = await post('/network-endpoints/validate', {host_id: wizard.hostId, mode: wizard.portMode,
      port: wizard.portMode === 'manual' ? Number(wizard.port) || null : null, preferred_port: wizard.draft.port});
    await rerender();
  },
  'wizard-create': async mode => {
    const deploy = mode === 'deploy';
    wizard.busy = true;
    try {
      if (!wizard.profileId) {
        const created = await post('/profiles', {...wizard.draft, name: wizard.profileName.trim() || wizard.name.trim()});
        state.profiles.push(created);
        wizard.profileId = created.id;
      }
      const pot = await post('/honeypots', requestBody(deploy));
      if (wizard.alert.enabled) {
        await post('/alerts/rules', {name: t('wizard.alertName', {name: pot.name}), honeypot_id: pot.id, enabled: true,
          event_type: wizard.alert.event_type, threshold: wizard.alert.threshold, window_seconds: wizard.alert.window_seconds, severity: wizard.alert.severity});
      }
      wizard = null;
      state.param = null;
      toast(deploy ? t('wizard.deployStarted') : t('wizard.draftSaved'));
      navigate('honeypot/' + pot.id);
    } catch (error) {
      wizard.busy = false;
      await validate();
      await rerender();
      throw error;
    }
  },
});
document.addEventListener('change', async event => {
  const kind = event.target.dataset?.wizard;
  if (!kind || !wizard) return;
  collect();
  if (kind === 'service') Object.assign(wizard, {serviceKey: event.target.value, profileId: '', draft: null});
  if (kind === 'profile') Object.assign(wizard, {profileId: event.target.value, draft: null});
  if (kind === 'host' || kind === 'mode') wizard.endpointCheck = null;
  await rerender();
});
export const startWizard = param => { wizard = null; state.param = param || null; navigate(param ? 'constructor/' + param : 'constructor'); };
