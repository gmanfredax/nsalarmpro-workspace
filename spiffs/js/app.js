import {
  apiGet,
  apiPost,
  clearSession,
  formatSystemId,
  getSystemSuffix,
  getToken,
  HttpError,
  onUnauthorized
} from './api.js';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const ROLE_ADMIN = 2;

const state = {
  currentUser: '',
  role: null,
  isAdmin: false,
  status: null,
  alarmZoneIds: [],
  tamperAlarm: false,
  zones: [],
  boards: [],
  scenes: null,
  logs: [],
  logsFrom: null,
  logsTo: null,
  logFilter: 'all',
  activeTab: '',
  sceneActiveMask: 0,
  sceneMaskKnown: false,
  sceneMaskSyncedForAlarm: false
};

const STATUS_POLL_INTERVAL = 2000;
const ZONESS_POLL_INTERVAL = 2000;
const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
let statusPollTimer = null;
let zonesPollTimer = null;
let idleTimer = null;
let idleTracking = false;
let idleTriggering = false;
let lastActivityTs = Date.now();
const idleEvents = ['pointerdown', 'pointermove', 'keydown', 'touchstart', 'wheel'];
const idleListenerOptions = { passive: true };

function stopIdleTracking(){
  if (!idleTracking) return;
  idleTracking = false;
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  idleEvents.forEach((eventName) => {
    document.removeEventListener(eventName, handleActivity, idleListenerOptions);
  });
  document.removeEventListener('visibilitychange', handleVisibilityChange);
  window.removeEventListener('focus', handleWindowFocus);
}

function handleVisibilityChange(){
  if (document.hidden) {
    scheduleIdleCheck();
  } else {
    resetIdleTimer();
  }
}

function handleWindowFocus(){
  resetIdleTimer();
}

function handleActivity(){
  if (!idleTracking || idleTriggering) return;
  lastActivityTs = Date.now();
  scheduleIdleCheck();
}

function resetIdleTimer(){
  if (!idleTracking || idleTriggering) return;
  lastActivityTs = Date.now();
  scheduleIdleCheck();
}

function scheduleIdleCheck(){
  if (!idleTracking || idleTriggering) return;
  const elapsed = Date.now() - lastActivityTs;
  const remaining = Math.max(IDLE_TIMEOUT_MS - elapsed, 1000);
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = window.setTimeout(checkIdleTimeout, remaining);
}

function checkIdleTimeout(){
  if (!idleTracking || idleTriggering) return;
  const inactiveFor = Date.now() - lastActivityTs;
  if (inactiveFor < IDLE_TIMEOUT_MS - 500) {
    scheduleIdleCheck();
    return;
  }
  triggerIdleLogout();
}

function triggerIdleLogout(){
  if (idleTriggering) return;
  idleTriggering = true;
  stopIdleTracking();
  stopStatusUpdates();
  stopZonesUpdates();
  (async () => {
    try {
      await apiPost('/api/logout', {});
    } catch (err) {
      console.warn('idle logout', err);
    }
    requireLogin();
  })();
}

function startIdleTracking(){
  if (idleTracking || idleTriggering) return;
  idleTracking = true;
  lastActivityTs = Date.now();
  idleEvents.forEach((eventName) => {
    document.addEventListener(eventName, handleActivity, idleListenerOptions);
  });
  document.addEventListener('visibilitychange', handleVisibilityChange);
  window.addEventListener('focus', handleWindowFocus);
  scheduleIdleCheck();
}

function stopStatusUpdates(){
  if (statusPollTimer) {
    clearInterval(statusPollTimer);
    statusPollTimer = null;
  }
}

function startStatusUpdates({ immediate = false } = {}){
  if (statusPollTimer || document.hidden || state.activeTab !== 'status') return;
  if (immediate) {
    refreshStatus();
  }
  statusPollTimer = window.setInterval(() => {
    if (document.hidden || state.activeTab !== 'status') {
      stopStatusUpdates();
      return;
    }
    refreshStatus();
  }, STATUS_POLL_INTERVAL);
}

function stopZonesUpdates(){
  if (zonesPollTimer) {
    clearInterval(zonesPollTimer);
    zonesPollTimer = null;
  }
}

function startZonesUpdates({ immediate = false } = {}){
  if (zonesPollTimer || document.hidden || state.activeTab !== 'zones') return;
  if (immediate) {
    refreshZones();
  }
  zonesPollTimer = window.setInterval(() => {
    if (document.hidden || state.activeTab !== 'zones') {
      stopZonesUpdates();
      return;
    }
    refreshZones();
  }, ZONESS_POLL_INTERVAL);
}

function setDisarmVisibility(visible){
  const btn = $('#disarmBtn');
  if (!btn) return;
  btn.classList.toggle('hidden', !visible);
}

const dateTimeFormatter = new Intl.DateTimeFormat('it-IT', {
  dateStyle: 'short',
  timeStyle: 'medium'
});

const modalsRoot = document.getElementById('modals-root');

const boardsCache = {
  list: [],
  map: new Map(),
  pending: null
};

const scenesCache = {
  data: null,
  pending: null
};

function normalizeBoard(node){
  if (!node) return null;
  const rawId = Number(node?.node_id);
  const nodeId = Number.isFinite(rawId) ? rawId : 0;
  const label = typeof node?.label === 'string' && node.label.trim()
    ? node.label.trim()
    : (nodeId === 0 ? 'Centrale' : `Scheda ${nodeId}`);
  const stateValue = (node?.state || (nodeId === 0 ? 'ONLINE' : 'UNKNOWN')).toString().toUpperCase();
  const inputs = Number(node?.inputs_count);
  return {
    node_id: nodeId,
    label,
    state: stateValue,
    kind: typeof node?.kind === 'string' ? node.kind : '',
    inputs_count: Number.isFinite(inputs) ? inputs : 0
  };
}

function setBoards(nodes){
  const normalized = [];
  if (Array.isArray(nodes)) {
    nodes.forEach((item) => {
      const norm = normalizeBoard(item);
      if (norm) normalized.push(norm);
    });
  }
  if (!normalized.some((item) => item.node_id === 0)) {
    normalized.unshift({ node_id: 0, label: 'Centrale', state: 'ONLINE', kind: 'master', inputs_count: 0 });
  }
  boardsCache.list = normalized;
  boardsCache.map = new Map(normalized.map((item) => [item.node_id, item]));
  state.boards = normalized;
}

function getBoardMeta(boardId){
  const id = Number(boardId);
  const safeId = Number.isFinite(id) ? id : 0;
  return boardsCache.map.get(safeId) || null;
}

function boardLabel(meta, boardId, zoneList){
  if (Array.isArray(zoneList)) {
    for (const zone of zoneList) {
      const zoneLabel = typeof zone?.board_label === 'string' ? zone.board_label.trim() : '';
      if (zoneLabel) return zoneLabel;
    }
  }
  if (meta?.label) return meta.label;
  return boardId === 0 ? 'Centrale' : `Scheda ${boardId}`;
}

function boardStatusDetails(meta){
  const raw = (meta?.state || '').toString().toUpperCase();
  switch (raw) {
    case 'ONLINE':
      return { className: 'online', label: 'Online' };
    case 'OFFLINE':
      return { className: 'offline', label: 'Offline' };
    case 'PREOP':
    case 'PRE-OP':
      return { className: 'preop', label: 'Pre-operativa' };
    default:
      return { className: 'unknown', label: raw && raw !== 'UNKNOWN' ? raw : 'Sconosciuto' };
  }
}

function resolveBoardStatus(meta, zones = []){
  const zoneFlags = Array.isArray(zones)
    ? zones
      .map((zone) => zone?.board_online)
      .filter((value) => typeof value === 'boolean')
    : [];

  if (zoneFlags.length) {
    const allOnline = zoneFlags.every((value) => value === true);
    const allOffline = zoneFlags.every((value) => value === false);
    if (allOnline) {
      return { className: 'online', label: 'Online', isOffline: false };
    }
    if (allOffline) {
      return { className: 'offline', label: 'Offline', isOffline: true };
    }
    if (zoneFlags.some((value) => value === false)) {
      return { className: 'offline', label: 'Offline', isOffline: true };
    }
    return { className: 'online', label: 'Online', isOffline: false };
  }

  const raw = (meta?.state || '').toString().toUpperCase();
  if (raw === 'ONLINE') {
    return { className: 'online', label: 'Online', isOffline: false };
  }
  if (raw === 'OFFLINE') {
    return { className: 'offline', label: 'Offline', isOffline: true };
  }

  const fallback = boardStatusDetails(meta);
  return {
    className: fallback.className,
    label: fallback.label,
    isOffline: fallback.className === 'offline'
  };
}

function renderBoardStatus(meta, zones = []){
  const info = resolveBoardStatus(meta, zones);
  const className = info?.className || 'unknown';
  const label = info?.label || 'Sconosciuto';
  return {
    info,
    html: `<span class="board-status ${className}">${escapeHtml(label)}</span>`
  };
}

function formatZoneCount(value){
  const count = Number(value) || 0;
  return count === 1 ? '1 zona' : `${count} zone`;
}

function sortBoardIds(a, b){
  if (a === b) return 0;
  if (a === 0) return -1;
  if (b === 0) return 1;
  return a - b;
}

async function ensureBoardsLoaded(force = false){
  if (!force && boardsCache.list.length && !boardsCache.pending) {
    return boardsCache.list;
  }
  if (boardsCache.pending) {
    return boardsCache.pending;
  }
  const request = apiGet('/api/can/nodes')
    .then((nodes) => {
      setBoards(nodes);
      boardsCache.pending = null;
      return boardsCache.list;
    })
    .catch((err) => {
      boardsCache.pending = null;
      throw err;
    });
  boardsCache.pending = request;
  return request;
}

setBoards([]);

function requireLogin(){
  stopIdleTracking();
  clearSession();
  window.location.replace('./login.html');
}

onUnauthorized(requireLogin);

function setBrandSystem(){
  const label = $('#systemLabel');
  if (label) {
    const suffix = getSystemSuffix();
    label.textContent = suffix ? formatSystemId(suffix) : '';
  }
}

function setBrandCentralName(name){
  const label = document.querySelector('.brand-label');
  if (!label) return;
  const trimmed = (name ?? '').toString().trim();
  label.textContent = trimmed ? `Alarm Pro • ${trimmed}` : 'Alarm Pro';
}

function setActiveTab(name){
  $$('.tab-btn').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
  $$('.tab').forEach((section) => section.classList.toggle('active', section.id === `tab-${name}`));
  state.activeTab = name;
  if (name !== 'status') {
    stopStatusUpdates();
  } else if (name !== 'zones') {
    stopZonesUpdates();
  }
  switch (name) {
    case 'status':
      refreshStatus();
      startStatusUpdates();
      break;
    case 'zones':
      refreshZones();
      startZonesUpdates();
      break;
    case 'scenes':
      refreshScenes();
      break;
    case 'log':
      refreshLogs();
      break;
    default:
      break;
  }
}

function setupTabs(){
  document.addEventListener('click', (event) => {
    const btn = event.target.closest('.tab-btn');
    if (btn && btn.dataset.tab) {
      setActiveTab(btn.dataset.tab);
    }
  });
}

function showNotice(text, type = 'info'){
  const el = $('#appNotice');
  if (!el) return;
  if (!text) {
    el.textContent = '';
    el.classList.add('hidden');
    return;
  }

  el.textContent = text;
  el.classList.remove('hidden');
  el.style.color = type === 'error' ? '#f87171' : '#a5f3fc';
}

function escapeHtml(str = ''){
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getZonesList(){
  if (Array.isArray(state.zones?.zones)) return state.zones.zones;
  if (Array.isArray(state.zones)) return state.zones;
  return [];
}

function getZoneLabel(id){
  const zones = getZonesList();
  const match = zones.find((item) => Number(item?.id) === id);
  const name = (match?.name ?? '').toString().trim();
  return name || `Z${id}`;
}

function parseMaskValue(raw){
  if (raw == null) {
    return { value: 0, valid: false };
  }
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const truncated = Math.trunc(raw);
    if (truncated < 0) {
      return { value: 0, valid: false };
    }
    return { value: truncated >>> 0, valid: true };
  }
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) {
      return { value: 0, valid: false };
    }
    const base = /^0x/i.test(trimmed) ? 16 : 10;
    const parsed = Number.parseInt(trimmed, base);
    if (!Number.isNaN(parsed) && Number.isFinite(parsed) && parsed >= 0) {
      return { value: parsed >>> 0, valid: true };
    }
    return { value: 0, valid: false };
  }
  if (typeof raw === 'boolean') {
    return { value: raw ? 1 : 0, valid: true };
  }
  const coerced = Number(raw);
  if (!Number.isNaN(coerced) && Number.isFinite(coerced) && coerced >= 0) {
    return { value: Math.trunc(coerced) >>> 0, valid: true };
  }
  return { value: 0, valid: false };
}

function setSceneMaskFromData(data){
  if (!data || typeof data !== 'object') {
    state.sceneActiveMask = 0;
    state.sceneMaskKnown = false;
    return;
  }
  const { value, valid } = parseMaskValue(data.active);
  state.sceneActiveMask = value;
  state.sceneMaskKnown = valid;
}

async function ensureScenesMeta({ force = false } = {}){
  if (!force && scenesCache.data) {
    state.scenes = scenesCache.data;
    setSceneMaskFromData(scenesCache.data);
    return scenesCache.data;
  }
  if (!force && scenesCache.pending) {
    return scenesCache.pending;
  }
  if (force && scenesCache.pending) {
    return scenesCache.pending;
  }
  const promise = apiGet('/api/scenes')
    .then((payload) => {
      scenesCache.data = payload;
      state.scenes = payload;
      setSceneMaskFromData(payload);
      return payload;
    })
    .finally(() => {
      if (scenesCache.pending === promise) {
        scenesCache.pending = null;
      }
    });
  scenesCache.pending = promise;
  return promise;
}

function normalizeActiveFlag(value){
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return false;
    const lowered = trimmed.toLowerCase();
    if (lowered === 'false' || lowered === 'no' || lowered === 'off') return false;
    if (lowered === 'true' || lowered === 'si' || lowered === 'on') return true;
    const numeric = Number(trimmed);
    return Number.isFinite(numeric) ? numeric !== 0 : true;
  }
  return Boolean(value);
}

function computeAlarmZoneIds(status, {
  sceneMask = 0,
  sceneMaskKnown = false,
  bypassMask = null,
  knownFlags = null
} = {}){
  if (!status || status.state !== 'ALARM') return [];
  if (!Array.isArray(status.zones_active)) return [];

  const flags = status.zones_active;
  const known = Array.isArray(knownFlags) ? knownFlags
    : (Array.isArray(status.zones_known) ? status.zones_known : null);
  const bypassInfo = parseMaskValue(bypassMask ?? status?.bypass_mask);
  const applyBypass = bypassInfo.valid && bypassInfo.value !== 0;
  const applySceneMask = sceneMaskKnown;

  const ids = [];
  for (let idx = 0; idx < flags.length; idx += 1) {
    if (!normalizeActiveFlag(flags[idx])) continue;
    if (known && !normalizeActiveFlag(known[idx])) continue;
    const bit = 2 ** idx;
    if (applySceneMask && (sceneMask & bit) === 0) continue;
    if (applyBypass && (bypassInfo.value & bit) !== 0) continue;
    ids.push(idx + 1);
  }
  return ids;
}

function renderAlarmZoneList(ids){
  if (!Array.isArray(ids) || !ids.length) {
    return '<span class="alarm-zone-empty">Nessuna zona segnalata.</span>';
  }
  return `<div class="alarm-zone-list">${ids
    .map((id) => `<span class="alarm-zone-pill">${escapeHtml(getZoneLabel(id))}</span>`)
    .join('')}</div>`;
}

function updateAlarmZonesSummary(){
  const el = document.getElementById('kpi-alarm-zones');
  if (!el) return;
  el.innerHTML = renderAlarmZoneList(state.alarmZoneIds);
}

function updateZonesAlarmHighlight(){
  const isAlarm = state.status?.state === 'ALARM';
  const activeIds = isAlarm ? new Set(state.alarmZoneIds) : new Set();
  $$('#zonesBoards .zone-card').forEach((card) => {
    const raw = card?.dataset?.zoneId ?? '';
    const zoneId = raw ? Number.parseInt(raw, 10) : NaN;
    const chip = card?.querySelector('.chip');
    if (!chip) return;
    const shouldHighlight = isAlarm && Number.isFinite(zoneId) && activeIds.has(zoneId);
    chip.classList.toggle('alarm', shouldHighlight);
  });
}

const STATE_LABELS = Object.freeze({
  DISARMED: 'Disarmato',
  ARMED_HOME: 'Attivo in casa',
  ARMED_AWAY: 'Attivo fuori casa',
  ARMED_NIGHT: 'Attivo notte',
  ARMED_CUSTOM: 'Attivo personalizzato',
  ALARM: 'Allarme',
  MAINT: 'Manutenzione',
  PRE_ARM: 'Attivazione in corso',
  PRE_DISARM: 'Pre allarme'
});

function renderAlarmState(el, status, { iconHTML = '' } = {}){
  if (!el || !status) return;
  if (el._blinkTimer) {
    clearInterval(el._blinkTimer);
    el._blinkTimer = null;
  }
  const stateName = status.state;
  const isPre = stateName === 'PRE_ARM' || stateName === 'PRE_DISARM';
  let label = STATE_LABELS[stateName] || stateName || '—';
  if (stateName === 'PRE_DISARM' && Number.isInteger(status.entry_zone)) {
    label += ` (Z${status.entry_zone})`;
  }
  if (!isPre) {
    el.innerHTML = `${iconHTML} ${escapeHtml(label)}`;
    return;
  }
  el.innerHTML = `${iconHTML} <span class="blink">${escapeHtml(label)}</span>`;
  const blinkEl = el.querySelector('.blink');
  el._blinkTimer = setInterval(() => {
    if (!blinkEl || !document.body.contains(blinkEl)) {
      clearInterval(el._blinkTimer);
      el._blinkTimer = null;
      return;
    }
    const on = (Math.floor(Date.now() / 500) % 2) === 0;
    blinkEl.style.opacity = on ? '1' : '0.35';
  }, 250);
}

function stateIcon(state){
  switch (state) {
    case 'DISARMED':
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s ok" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m9 12 2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>';
    case 'ALARM':
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
    default:
      return '<svg xmlns="http://www.w3.org/2000/svg" class="ico s" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="9"/></svg>';
  }
}

function kpiCard({ title, valueHTML }){
  return `<div class="card"><div class="kpi"><div class="kpi-title">${escapeHtml(title)}</div><div class="kpi-value">${valueHTML}</div></div></div>`;
}

async function refreshStatus(){
  try {
    const data = await apiGet('/api/status');
    const prevStateName = state.status?.state || '';
    const prevAlarmZoneIds = Array.isArray(state.alarmZoneIds) ? [...state.alarmZoneIds] : [];
    state.status = data;
    const stateName = typeof data?.state === 'string' ? data.state : '';
    const isAlarmState = stateName === 'ALARM';
    const isArmedState = stateName.startsWith('ARMED_');
    const isPendingState = stateName === 'PRE_ARM' || stateName === 'PRE_DISARM';
    const tamperAlarmActive = Boolean(data?.tamper_alarm && isAlarmState);

    if (isAlarmState) {
      if (!state.sceneMaskSyncedForAlarm) {
        try {
          await ensureScenesMeta({ force: true });
          state.sceneMaskSyncedForAlarm = state.sceneMaskKnown;
        } catch (scenesErr) {
          console.warn('scenes meta', scenesErr);
          state.sceneActiveMask = 0;
          state.sceneMaskKnown = false;
          state.sceneMaskSyncedForAlarm = false;
        }
      }
    } else if (prevStateName === 'ALARM' || state.sceneMaskSyncedForAlarm) {
      state.sceneMaskSyncedForAlarm = false;
    }

    let computedAlarmZoneIds = computeAlarmZoneIds(data, {
      sceneMask: state.sceneActiveMask,
      sceneMaskKnown: state.sceneMaskKnown,
      bypassMask: data?.bypass_mask,
      knownFlags: data?.zones_known
    });
    if (!isAlarmState) {
      computedAlarmZoneIds = [];
    } else if (tamperAlarmActive && !computedAlarmZoneIds.length && prevAlarmZoneIds.length) {
      computedAlarmZoneIds = prevAlarmZoneIds;
    }
    state.alarmZoneIds = computedAlarmZoneIds;
    state.tamperAlarm = tamperAlarmActive;
    setBrandCentralName(data?.central_name);
    setDisarmVisibility(isAlarmState || isArmedState || isPendingState);
    const wrap = $('#statusCards');
    if (!wrap) return;
    const zonesActive = Array.isArray(data?.zones_active) ? data.zones_active.filter(Boolean).length : (data?.zones_active || 0);
    const zonesCount = data?.zones_count || (Array.isArray(data?.zones_active) ? data.zones_active.length : zonesActive);
    const tamper = data?.tamper ? '<span class="tag">TAMPER</span>' : '<span class="tag ok">OK</span>';
    const cards = [
      kpiCard({ title: 'Stato', valueHTML: '<span id="kpi-state-val"></span>' }),
      kpiCard({ title: 'Tamper', valueHTML: tamper }),
      kpiCard({ title: 'Zone aperte', valueHTML: `${zonesActive} / ${zonesCount}` })
    ];
    if (isAlarmState && (!Array.isArray(state.zones) || !state.zones.length) && state.activeTab !== 'zones') {
      refreshZones();
    }
    if (isAlarmState) {
      cards.push(
        kpiCard({
          title: 'Zone violate',
          valueHTML: `<div id="kpi-alarm-zones" class="alarm-zone-value">${renderAlarmZoneList(state.alarmZoneIds)}</div>`
        })
      );
    }
    wrap.innerHTML = cards.join('');
    const tamperResetBtn = $('#tamperResetBtn');
    if (tamperResetBtn) {
      const shouldShow = state.tamperAlarm && Boolean(state.currentUser);
      tamperResetBtn.classList.toggle('hidden', !shouldShow);
    }
    const stateEl = document.getElementById('kpi-state-val');
    if (stateEl) renderAlarmState(stateEl, data, { iconHTML: stateIcon(data?.state) });
    updateAlarmZonesSummary();
    updateZonesAlarmHighlight();
    if (state.activeTab === 'zones' && !document.hidden) {
      refreshZones();
    }
  } catch (err) {
    console.error('refreshStatus', err);
    showNotice('Impossibile recuperare lo stato.', 'error');
  }
}

function buildZoneBadge(zone){
  const badges = [];
  if (zone?.auto_exclude) badges.push('<span class="badge" title="Autoesclusione">AE</span>');
  if (zone?.zone_delay) badges.push('<span class="badge" title="Ritardo">R</span>');
  const time = Number(zone?.zone_time);
  if (Number.isFinite(time) && time > 0) badges.push(`<span class="badge" title="Tempo">${time}s</span>`);
  return badges.join('');
}

function renderZoneChip(zone, options = {}){
  const offline = Boolean(options?.offline);
  const id = Number(zone?.id);
  const boardId = Number(zone?.board);
  const zoneIdLabel = Number.isFinite(id) ? `Z${id}` : 'Z?';
  const nameSuffix = zone?.name ? ` – ${escapeHtml(zone.name)}` : '';
  const display = `${escapeHtml(zoneIdLabel)}${nameSuffix}`;
  const classes = ['chip'];
  if (zone?.active) classes.push('on');
  if (offline) classes.push('offline');
  const cls = classes.join(' ');
  const badges = buildZoneBadge(zone);
  const titleParts = [zoneIdLabel];
  if (zone?.name) titleParts.push(zone.name);
  return `
    <div class="card mini zone-card" data-zone-id="${Number.isFinite(id) ? id : ''}" data-board-id="${Number.isFinite(boardId) ? boardId : 0}">
      <div class="${cls}" title="${escapeHtml(titleParts.join(' • '))}">
        ${display}
        ${badges ? `<span class="badges">${badges}</span>` : ''}
      </div>
    </div>`;
}

function renderBoardSection(boardId, zones){
  const meta = getBoardMeta(boardId);
  const label = escapeHtml(boardLabel(meta, boardId, zones));
  const { html: statusHtml, info: statusInfo } = renderBoardStatus(meta, zones);
  const zoneCount = escapeHtml(formatZoneCount(zones.length));
  const offline = statusInfo?.isOffline === true;
  const content = zones.length
    ? `<div class="zones-grid">${zones.map((zone) => renderZoneChip(zone, { offline })).join('')}</div>`
    : '<div class="log-empty small">Nessuna zona associata.</div>';
  const safeBoardId = Number.isFinite(boardId) ? boardId : 0;
  return `
    <section class="board-section" data-board="${safeBoardId}">
      <div class="board-header">
        <h4>${label}</h4>
        <div class="board-actions">
          <div class="board-meta">
            ${statusHtml}
            <span class="board-count">${zoneCount}</span>
          </div>
          <button type="button" class="btn tiny admin-only" data-board-config="${safeBoardId}">Configura zone</button>
        </div>
      </div>
      ${content}
    </section>`;
}

async function refreshZones(){
  try {
    const data = await apiGet('/api/zones');
    const zones = Array.isArray(data?.zones) ? data.zones : [];
    state.zones = zones;
    const container = $('#zonesBoards');
    if (!container) return;

    try {
      await ensureBoardsLoaded();
    } catch (metaErr) {
      console.warn('boards metadata', metaErr);
    }

    const groups = new Map();
    zones.forEach((zone) => {
      const bid = Number(zone?.board);
      const boardId = Number.isFinite(bid) ? bid : 0;
      const arr = groups.get(boardId) || [];
      arr.push(zone);
      groups.set(boardId, arr);
    });

    for (const arr of groups.values()) {
      arr.sort((a, b) => {
        const ida = Number(a?.id) || 0;
        const idb = Number(b?.id) || 0;
        return ida - idb;
      });
    }

    const boardIdsSet = new Set(boardsCache.list.map((board) => board.node_id));
    for (const boardId of groups.keys()) boardIdsSet.add(boardId);
    const boardIds = Array.from(boardIdsSet).sort(sortBoardIds);

    if (!boardIds.length) {
      container.innerHTML = '<div class="log-empty">Nessuna zona configurata.</div>';
      updateAlarmZonesSummary();
      updateZonesAlarmHighlight();
      return;
    }
    container.innerHTML = boardIds.map((boardId) => {
      const list = groups.get(boardId) || [];
      return renderBoardSection(boardId, list);
    }).join('');
    updateAlarmZonesSummary();
    updateZonesAlarmHighlight();
  } catch (err) {
    console.error('refreshZones', err);
    showNotice('Errore durante il caricamento delle zone.', 'error');
  }
}

function renderZoneConfigCard(zone){
  const id = Number(zone?.id);
  const boardId = Number(zone?.board);
  const nameValue = zone?.name ? escapeHtml(zone.name) : '';
  const delayChecked = zone?.zone_delay ? 'checked' : '';
  const autoChecked = zone?.auto_exclude ? 'checked' : '';
  const timeValue = Number(zone?.zone_time);
  const safeTime = Number.isFinite(timeValue) && timeValue > 0 ? timeValue : 0;
  const badges = buildZoneBadge(zone);
  return `
    <div class="zone-config-card" data-zone-id="${Number.isFinite(id) ? id : ''}" data-board-id="${Number.isFinite(boardId) ? boardId : 0}">
      <div class="zone-config-card-head">
        <strong>Z${Number.isFinite(id) ? id : '?'}</strong>
        ${badges ? `<span class="badges">${badges}</span>` : ''}
      </div>
      <label class="field"><span>Nome</span><input type="text" data-field="name" value="${nameValue}" placeholder="Z${Number.isFinite(id) ? id : ''}"></label>
      <div class="zone-config-options">
        <label class="chk compact"><input type="checkbox" data-field="zone_delay" ${delayChecked}> Ritardo ingresso/uscita</label>
        <label class="chk compact"><input type="checkbox" data-field="auto_exclude" ${autoChecked}> Autoesclusione se aperta</label>
      </div>
      <label class="field"><span>Tempo ritardo (s)</span><input type="number" min="0" max="600" step="1" data-field="zone_time" value="${safeTime}"></label>
    </div>
  `;
}

async function openZonesConfig({ boardId = null } = {}){
  try {
    const parsedBoard = Number.isFinite(boardId)
      ? boardId
      : (typeof boardId === 'string' ? Number.parseInt(boardId, 10) : NaN);
    if (!Number.isFinite(parsedBoard)) {
      showNotice('Scheda non valida per la configurazione delle zone.', 'warn');
      return;
    }

    const payload = await apiGet('/api/zones/config');
    const items = Array.isArray(payload?.items) ? payload.items : [];

    try {
      await ensureBoardsLoaded();
    } catch (metaErr) {
      console.warn('boards metadata', metaErr);
    }

    const boardItems = items.filter((item) => {
      const bid = Number(item?.board);
      const target = Number.isFinite(bid) ? bid : 0;
      return target === parsedBoard;
    });

    boardItems.sort((a, b) => (Number(a?.id) || 0) - (Number(b?.id) || 0));

    const meta = getBoardMeta(parsedBoard);
    const label = escapeHtml(boardLabel(meta, parsedBoard, boardItems));
    const { html: statusHtml } = renderBoardStatus(meta, boardItems);
    const zoneCount = escapeHtml(formatZoneCount(boardItems.length));

    const bodyHtml = boardItems.length
      ? `<div class="zone-config-grid">${boardItems.map((zone) => renderZoneConfigCard(zone)).join('')}</div>`
      : '<div class="log-empty small">Nessuna zona configurabile per questa scheda.</div>';

    const modal = showModal(`
      <div class="zones-config">
        <div class="zones-config-header">
          <div class="zones-config-title-row">
            <h3>Configurazione zone</h3>
            <button class="btn tiny outline" type="button" id="zonesCfgClose">Chiudi</button>
          </div>
          <div class="zones-config-subtitle">
            <span class="subtitle-label">Scheda: ${label}</span>
            <div class="zones-config-subtitle-meta">
              ${statusHtml}
              <span class="board-count">${zoneCount}</span>
            </div>
          </div>
        </div>
        <div class="zones-config-body" data-board="${parsedBoard}">
          ${bodyHtml}
        </div>
        <div id="zonesCfgMsg" class="msg small hidden"></div>
        <div class="row" style="justify-content:flex-end;gap:.5rem;margin-top:1rem">
          <button class="btn" type="button" id="zonesCfgCancel">Annulla</button>
          <button class="btn primary" type="button" id="zonesCfgSave">Salva</button>
        </div>
      </div>
    `, { modalClass: 'zones-config-modal' });

    if (!modal) return;

    const closeModal = () => { clearModals(); };
    $('#zonesCfgClose', modal)?.addEventListener('click', closeModal);
    $('#zonesCfgCancel', modal)?.addEventListener('click', closeModal);

    $('#zonesCfgSave', modal)?.addEventListener('click', async () => {
      const cards = $$('.zone-config-card', modal);
      const itemsPayload = cards.map((card) => {
        const id = Number(card.dataset.zoneId);
        if (!Number.isFinite(id)) return null;
        const nameInput = $('[data-field="name"]', card);
        const delayInput = $('[data-field="zone_delay"]', card);
        const timeInput = $('[data-field="zone_time"]', card);
        const autoInput = $('[data-field="auto_exclude"]', card);
        const cardBoardId = Number(card.dataset.boardId);
        return {
          id,
          name: nameInput?.value?.trim() || '',
          zone_delay: !!(delayInput && delayInput.checked),
          zone_time: Math.max(0, Number.parseInt(timeInput?.value ?? '0', 10) || 0),
          auto_exclude: !!(autoInput && autoInput.checked),
          board: Number.isFinite(cardBoardId) ? cardBoardId : parsedBoard
        };
      }).filter(Boolean);

      const msg = $('#zonesCfgMsg', modal);
      if (msg) {
        msg.textContent = '';
        msg.classList.add('hidden');
      }

      try {
        await apiPost('/api/zones/config', { items: itemsPayload });
        showNotice('Configurazione zone aggiornata.', 'info');
        clearModals();
        refreshZones();
      } catch (err) {
        console.error('saveZonesConfig', err);
        if (msg) {
          msg.textContent = err instanceof HttpError ? err.message : 'Errore durante il salvataggio.';
          msg.classList.remove('hidden');
          msg.style.color = '#f87171';
        }
      }
    });
  } catch (err) {
    console.error('openZonesConfig', err);
    showNotice('Impossibile leggere la configurazione delle zone.', 'error');
  }
}

function renderSceneCard(name, mask, totalZones){
  const checks = [];
  for (let i = 1; i <= totalZones; i += 1) {
    const bit = 1 << (i - 1);
    const checked = (mask & bit) !== 0 ? 'checked' : '';
    checks.push(`<label class="chk"><input type="checkbox" data-scene="${name}" data-zone="${i}" ${checked}>Z${i}</label>`);
  }
  return `
    <div class="card">
      <div class="card-head"><div class="title"><h2>${escapeHtml(name.toUpperCase())}</h2></div></div>
      <div class="checks">${checks.join('')}</div>
      <div class="actions"><button class="btn small primary" data-save="${name}">Salva</button></div>
    </div>`;
}

async function refreshScenes(){
  try {
    const data = await ensureScenesMeta({ force: true });
    const root = $('#scenesWrap');
    if (!root) return;
    const total = Number.isInteger(data?.zones) ? data.zones : 0;
    if (!total) {
      root.innerHTML = '<div class="log-empty">Configura almeno una zona per gestire gli scenari.</div>';
      return;
    }
    root.innerHTML = [
      renderSceneCard('home', data?.home ?? 0, total),
      renderSceneCard('night', data?.night ?? 0, total),
      renderSceneCard('custom', data?.custom ?? 0, total)
    ].join('');
    root.querySelectorAll('button[data-save]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const scene = btn.dataset.save;
        const boxes = root.querySelectorAll(`input[type="checkbox"][data-scene="${scene}"]`);
        const ids = Array.from(boxes)
          .filter((input) => input.checked)
          .map((input) => Number(input.dataset.zone))
          .filter((num) => Number.isFinite(num));
        try {
          await apiPost('/api/scenes', { scene, ids });
          showNotice('Scena aggiornata.', 'info');
          refreshScenes();
        } catch (err) {
          console.error('saveScene', err);
          showNotice('Errore durante il salvataggio della scena.', 'error');
        }
      });
    });
  } catch (err) {
    console.error('refreshScenes', err);
    showNotice('Impossibile caricare gli scenari.', 'error');
  }
}

function normalizeLogs(payload){
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.entries)) return payload.entries;
  if (payload && Array.isArray(payload.items)) return payload.items;
  return [];
}

function getLogTsUs(entry){
  if (!entry || typeof entry === 'string') return null;
  const raw = entry?.ts_us ?? entry?.tsUs ?? entry?.tsUS ?? entry?.timestamp_us ?? entry?.timestampUs;
  if (raw == null) return null;
  if (typeof raw === 'number') {
    return Number.isFinite(raw) ? Math.trunc(raw) : null;
  }
  if (typeof raw === 'string') {
    const parsed = Number.parseFloat(raw);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : null;
  }
  return null;
}

function getLogTimestampValue(entry){
  if (!entry || typeof entry === 'string') return Number.NEGATIVE_INFINITY;
  const iso = entry?.ts_iso ?? entry?.tsIso ?? entry?.iso ?? entry?.timestamp_iso ?? entry?.timestampIso;
  if (typeof iso === 'string' && iso) {
    const parsedIso = Date.parse(iso);
    if (!Number.isNaN(parsedIso)) {
      return parsedIso;
    }
  }
  const tsUs = getLogTsUs(entry);
  if (Number.isFinite(tsUs)) {
    return Math.trunc(tsUs / 1000);
  }
  const raw = entry?.ts ?? entry?.timestamp ?? entry?.time ?? entry?.date;
  if (!raw && raw !== 0) return Number.NEGATIVE_INFINITY;
  if (raw instanceof Date) {
    const value = raw.getTime();
    return Number.isNaN(value) ? Number.NEGATIVE_INFINITY : value;
  }
  if (typeof raw === 'number') {
    const ts = raw > 1e12 ? raw : raw * 1000;
    return Number.isFinite(ts) ? ts : Number.NEGATIVE_INFINITY;
  }
  const parsed = Date.parse(raw);
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
}

function sortLogEntries(entries){
  return entries
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => {
      const diff = getLogTimestampValue(b.entry) - getLogTimestampValue(a.entry);
      if (diff !== 0) return diff;
      return a.index - b.index;
    })
    .map(({ entry }) => entry);
}

function getLogLevel(entry){
  if (!entry || typeof entry === 'string') return '';
  const level = entry?.level ?? entry?.severity ?? entry?.type;
  return typeof level === 'string' ? level.toUpperCase() : String(level ?? '');
}

function hasCategory(entry, desired){
  if (!entry || !desired) return false;
  const target = desired.toString().toLowerCase();
  const single = entry?.category;
  if (typeof single === 'string' && single.toLowerCase() === target) {
    return true;
  }
  const categories = entry?.categories;
  if (Array.isArray(categories)) {
    return categories.some((item) => typeof item === 'string' && item.toLowerCase() === target);
  }
  return false;
}

function filterLogEntries(entries, filter){
  if (filter === 'all') return entries;
  return entries.filter((entry) => {
    if (filter === 'alarm') return hasCategory(entry, 'alarm');
    const level = getLogLevel(entry);
    if (!level) return false;
    if (filter === 'info') return level.includes('INFO');
    if (filter === 'warn') return level.includes('WARN');
    if (filter === 'error') return level.includes('ERR');
    return true;
  });
}

function filterLogsByDate(entries){
  const from = state.logsFrom;
  const to = state.logsTo;
  const hasFrom = from != null && Number.isFinite(from);
  const hasTo = to != null && Number.isFinite(to);
  if (!hasFrom && !hasTo) {
    return entries;
  }
  return entries.filter((entry) => {
    const value = getLogTimestampValue(entry);
    if (!Number.isFinite(value)) return false;
    if (hasFrom && value < from) return false;
    if (hasTo && value > to) return false;
    return true;
  });
}

function formatDateInputValue(ms){
  if (!Number.isFinite(ms)) return '';
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return '';
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function parseDateInputValue(value, { endOfDay = false } = {}){
  if (typeof value !== 'string' || !value) return null;
  const parts = value.split('-');
  if (parts.length !== 3) return null;
  const year = Number.parseInt(parts[0], 10);
  const month = Number.parseInt(parts[1], 10);
  const day = Number.parseInt(parts[2], 10);
  if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) return null;
  const date = endOfDay
    ? new Date(year, month - 1, day, 23, 59, 59, 999)
    : new Date(year, month - 1, day, 0, 0, 0, 0);
  const time = date.getTime();
  return Number.isNaN(time) ? null : time;
}

function updateLogDateInputs(){
  const fromInput = $('#logsDateFrom');
  const toInput = $('#logsDateTo');
  if (fromInput) {
    fromInput.value = state.logsFrom != null && Number.isFinite(state.logsFrom)
      ? formatDateInputValue(state.logsFrom)
      : '';
  }
  if (toInput) {
    toInput.value = state.logsTo != null && Number.isFinite(state.logsTo)
      ? formatDateInputValue(state.logsTo)
      : '';
  }
}

function updateLogFilterButtons(){
  $$('#logsFilterGroup button[data-filter]').forEach((btn) => {
    const filter = btn.dataset.filter || 'all';
    btn.classList.toggle('active', filter === state.logFilter);
  });
}

function formatLogTimestamp(value){
  if (!value && value !== 0) return '';
  if (value instanceof Date) return dateTimeFormatter.format(value);
  if (typeof value === 'number') {
    const ts = value > 1e12 ? value : value * 1000;
    const date = new Date(ts);
    return Number.isNaN(date.getTime()) ? '' : dateTimeFormatter.format(date);
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : dateTimeFormatter.format(date);
}

function renderLogEntries(entries){
  const list = $('#logsList');
  if (!list) return;
  if (!entries.length) {
    list.innerHTML = '<div class="log-empty">Nessun evento registrato.</div>';
    return;
  }
  const severityFiltered = filterLogEntries(entries, state.logFilter);
  const filtered = filterLogsByDate(severityFiltered);
  if (!filtered.length) {
    const hasDate = (state.logsFrom != null && Number.isFinite(state.logsFrom))
      || (state.logsTo != null && Number.isFinite(state.logsTo));
    let message = 'Nessun evento per il filtro selezionato.';
    if (severityFiltered.length === 0 && state.logFilter !== 'all') {
      message = 'Nessun evento per il filtro selezionato.';
    } else if (hasDate && state.logFilter !== 'all') {
      message = 'Nessun evento per il filtro/periodo selezionato.';
    } else if (hasDate) {
      message = 'Nessun evento per il periodo selezionato.';
    }
    list.innerHTML = `<div class="log-empty small">${message}</div>`;
    return;
  }
  list.innerHTML = filtered.map((entry) => {
    if (typeof entry === 'string') {
      return `<div class="log-entry"><div class="log-body">${escapeHtml(entry)}</div></div>`;
    }
    const message = escapeHtml(entry?.message || entry?.msg || entry?.text || JSON.stringify(entry));
    const level = getLogLevel(entry);
    const tsSource = entry?.ts_iso ?? entry?.ts ?? entry?.timestamp ?? entry?.time ?? entry?.date;
    const ts = formatLogTimestamp(tsSource);
    const levelTag = level ? `<span class="tag ${level.includes('ERR') ? 'err' : level.includes('WARN') ? 'warn' : ''}">${level}</span>` : '';
    const tags = [];
    const isAlarmCategory = hasCategory(entry, 'alarm');
    if (isAlarmCategory) {
      tags.push('<span class="tag alarm">Allarme</span>');
    }
    if (!isAlarmCategory && levelTag) {
      tags.push(levelTag);
    }
    const tagsHtml = tags.join(' ');
    const tsUs = getLogTsUs(entry);
    const deleteBtn = state.isAdmin && Number.isFinite(tsUs)
      ? `<button type="button" class="log-delete-btn" data-log-delete="${tsUs}" aria-label="Elimina evento"><span aria-hidden="true">🗑️</span></button>`
      : '';
    return `
      <div class="log-entry" data-ts="${Number.isFinite(tsUs) ? tsUs : ''}">
        <div class="log-meta">
          <span>${escapeHtml(ts || '—')}</span>
          ${tagsHtml}
        </div>
        <div class="log-body">${message}</div>
        ${deleteBtn}
      </div>`;
  }).join('');
}

async function refreshLogs(){
  try {
    const params = new URLSearchParams();
    if (state.logsFrom != null && Number.isFinite(state.logsFrom)) {
      params.set('since', String(Math.floor(state.logsFrom / 1000)));
    }
    if (state.logsTo != null && Number.isFinite(state.logsTo)) {
      params.set('until', String(Math.ceil(state.logsTo / 1000)));
    }
    const query = params.toString();
    const payload = await apiGet(query ? `/api/logs?${query}` : '/api/logs');
    const entries = sortLogEntries(normalizeLogs(payload));
    state.logs = entries;
    renderLogEntries(entries);
  } catch (err) {
    console.error('refreshLogs', err);
    showNotice('Impossibile recuperare il log eventi.', 'error');
  }
}

function setupLogFilters(){
  const group = $('#logsFilterGroup');
  if (group) {
    group.addEventListener('click', (event) => {
      const btn = event.target.closest('button[data-filter]');
      if (!btn) return;
      const filter = btn.dataset.filter || 'all';
      if (state.logFilter === filter) return;
      state.logFilter = filter;
      updateLogFilterButtons();
      if (state.logs.length) {
        renderLogEntries(state.logs);
      }
    });
  }

  const markInvalid = (input) => {
    if (!input) return;
    input.classList.add('input-error');
    window.setTimeout(() => input.classList.remove('input-error'), 1600);
  };

  $('#logsRefresh')?.addEventListener('click', () => refreshLogs());

  const fromInput = $('#logsDateFrom');
  const toInput = $('#logsDateTo');
  const resetBtn = $('#logsDateReset');

  fromInput?.addEventListener('change', () => {
    const value = fromInput.value;
    if (!value) {
      state.logsFrom = null;
      updateLogDateInputs();
      refreshLogs();
      return;
    }
    const parsed = parseDateInputValue(value, { endOfDay: false });
    if (parsed == null) {
      markInvalid(fromInput);
      updateLogDateInputs();
      return;
    }
    state.logsFrom = parsed;
    if (state.logsTo != null && Number.isFinite(state.logsTo) && state.logsTo < state.logsFrom) {
      const fallback = parseDateInputValue(value, { endOfDay: true });
      state.logsTo = fallback != null ? fallback : state.logsFrom;
    }
    updateLogDateInputs();
    refreshLogs();
  });

  toInput?.addEventListener('change', () => {
    const value = toInput.value;
    if (!value) {
      state.logsTo = null;
      updateLogDateInputs();
      refreshLogs();
      return;
    }
    const parsed = parseDateInputValue(value, { endOfDay: true });
    if (parsed == null) {
      markInvalid(toInput);
      updateLogDateInputs();
      return;
    }
    state.logsTo = parsed;
    if (state.logsFrom != null && Number.isFinite(state.logsFrom) && state.logsTo < state.logsFrom) {
      const fallback = parseDateInputValue(value, { endOfDay: false });
      state.logsFrom = fallback != null ? fallback : state.logsTo;
    }
    updateLogDateInputs();
    refreshLogs();
  });

  resetBtn?.addEventListener('click', () => {
    if (state.logsFrom == null && state.logsTo == null) {
      return;
    }
    state.logsFrom = null;
    state.logsTo = null;
    updateLogDateInputs();
    refreshLogs();
  });

  $('#logsList')?.addEventListener('click', async (event) => {
    const btn = event.target.closest('button[data-log-delete]');
    if (!btn) return;
    const tsValue = Number(btn.dataset.logDelete);
    if (!Number.isFinite(tsValue)) return;
    const confirmed = await showConfirm({
      title: 'Elimina evento',
      message: 'Confermi l’eliminazione di questo evento dal log?',
      confirmLabel: 'Elimina',
      confirmTone: 'danger'
    });
    if (!confirmed) return;
    btn.disabled = true;
    try {
      await apiPost('/api/logs/delete', { ts_us: tsValue.toString() });
      showNotice('Evento eliminato dal log.', 'info');
      await refreshLogs();
    } catch (err) {
      console.error('logDelete', err);
      if (err instanceof HttpError && err.status === 404) {
        showNotice('Evento non trovato o già rimosso.', 'warn');
      } else {
        showNotice('Impossibile eliminare l’evento.', 'error');
      }
      btn.disabled = false;
    }
  });

  updateLogFilterButtons();
  updateLogDateInputs();
}

function setupCommands(){
  $$('#commandCards button[data-arm]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const mode = btn.dataset.arm;
      const pin = await promptForPin({
        title: 'Inserisci PIN per attivare',
        confirmLabel: 'Attiva',
        description: mode ? `Modalità: ${mode.toUpperCase()}` : ''
      });
      if (pin == null) {
        return;
      }
      try {
        await apiPost('/api/arm', { mode, pin });
        showNotice(`Comando ${mode?.toUpperCase()} inviato.`, 'info');
        refreshStatus();
        if (state.activeTab === 'zones') {
          refreshZones();
        }
      } catch (err) {
        console.error('arm', err);
        if (err instanceof HttpError) {
          if (err.status === 401) {
            showNotice('PIN errato.', 'error');
          } else if (err.status === 409) {
            showNotice('Impossibile attivare: zone aperte.', 'error');
          } else {
            showNotice(err.message || 'Errore durante l’invio del comando.', 'error');
          }
        } else {
          showNotice('Errore durante l’invio del comando.', 'error');
        }
      }
    });
  });
  $('#disarmBtn')?.addEventListener('click', async () => {
    if (state.status?.state === 'DISARMED') {
      showNotice('La centrale è già disarmata.', 'info');
      return;
    }
    const pin = await promptForPin({
      title: 'Inserisci PIN per disattivare',
      confirmLabel: 'Disattiva'
    });
    if (pin == null) {
      return;
    }
    try {
      await apiPost('/api/disarm', { pin });
      showNotice('Centrale disarmata.', 'info');
      refreshStatus();
      if (state.activeTab === 'zones') {
        refreshZones();
      }
    } catch (err) {
      console.error('disarm', err);
      if (err instanceof HttpError) {
        if (err.status === 401) {
          showNotice('PIN errato.', 'error');
        } else if (err.status === 409) {
          showNotice('Impossibile disarmare: zone aperte.', 'error');
        } else {
          showNotice(err.message || 'Errore durante il comando di disarmo.', 'error');
        }
      } else {
        showNotice('Errore durante il comando di disarmo.', 'error');
      }
    }
  });

  $('#tamperResetBtn')?.addEventListener('click', async () => {
    const password = await promptForPassword({
      title: 'Reset allarme tamper',
      confirmLabel: 'Reset',
      description: 'Inserisci la tua password per ripristinare la centrale.'
    });
    if (password == null) {
      return;
    }
    if (state.status?.tamper) {
      showNotice('Linea tamper ancora aperta. Chiudi il contatto prima di resettare.', 'error');
      return;
    }
    try {
      await apiPost('/api/tamper/reset', { password });
      showNotice('Allarme tamper resettato.', 'info');
      refreshStatus();
    } catch (err) {
      console.error('tamperReset', err);
      if (err instanceof HttpError) {
        if (err.status === 403) {
          showNotice('Password errata.', 'error');
        } else if (err.status === 409) {
          showNotice(err.message || 'Impossibile resettare: verifica lo stato del tamper.', 'error');
        } else {
          showNotice(err.message || 'Errore durante il reset tamper.', 'error');
        }
      } else {
        showNotice('Errore durante il reset tamper.', 'error');
      }
    }
  });
}

function normalizeRole(roleValue){
  if (typeof roleValue === 'number') return Number.isNaN(roleValue) ? null : roleValue;
  if (typeof roleValue === 'string' && roleValue.trim() !== '') {
    const parsed = Number.parseInt(roleValue, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function updateAdminVisibility(){
  document.body.classList.toggle('is-admin', state.isAdmin);
  $$('.admin-only').forEach((el) => {
    el.classList.toggle('hidden', !state.isAdmin);
    el.style.removeProperty('display');
  });
  if (state.logs.length) {
    renderLogEntries(state.logs);
  }
}

function setupZonesConfig(){
  $('#zonesBoards')?.addEventListener('click', (event) => {
    if (!state.isAdmin) return;
    const btn = event.target.closest('button[data-board-config]');
    if (!btn) return;
    const boardId = Number.parseInt(btn.dataset.boardConfig ?? '', 10);
    if (Number.isNaN(boardId)) return;
    openZonesConfig({ boardId });
  });
}

function clearModals(){
  if (modalsRoot) modalsRoot.innerHTML = '';
  document.body.classList.remove('modal-open');
}

function showModal(innerHtml, options = {}){
  if (!modalsRoot) return null;
  clearModals();
  const { modalClass = '', onClose } = options;
  const modalClasses = ['card', 'modal'];
  if (modalClass) {
    modalClasses.push(modalClass);
  }
  modalsRoot.innerHTML = `<div class="modal-overlay"><div class="${modalClasses.join(' ')}">${innerHtml}</div></div>`;
  document.body.classList.add('modal-open');
  const overlay = modalsRoot.firstElementChild;
  overlay?.addEventListener('click', (event) => {
    if (event.target === overlay && !event.defaultPrevented) {
      if (typeof onClose === 'function') {
        onClose();
      } else {
        clearModals();
      }
    }
  });
  return overlay?.querySelector('.modal') || null;
}

function showConfirm({
  title = 'Conferma',
  message = '',
  confirmLabel = 'Conferma',
  cancelLabel = 'Annulla',
  confirmTone = 'primary'
} = {}){
  return new Promise((resolve) => {
    let settled = false;
    const cleanup = (modal, onKeyDown) => {
      if (modal) modal.removeEventListener('keydown', onKeyDown);
    };
    const close = (value, modal, onKeyDown) => {
      if (settled) return;
      settled = true;
      cleanup(modal, onKeyDown);
      clearModals();
      resolve(value);
    };

    const confirmClass = confirmTone === 'danger' ? 'btn danger' : 'btn primary';
    const modal = showModal(`
      <div class="modal-head">
        <h3>${escapeHtml(title)}</h3>
      </div>
      <div class="modal-body">
        <p class="modal-message">${escapeHtml(message)}</p>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn secondary" data-act="cancel">${escapeHtml(cancelLabel)}</button>
        <button type="button" class="${confirmClass}" data-act="confirm">${escapeHtml(confirmLabel)}</button>
      </div>
    `, {
      modalClass: 'confirm-modal',
      onClose: () => close(false, modal, onKeyDown)
    });

    if (!modal) {
      resolve(false);
      return;
    }

    const confirmBtn = modal.querySelector('[data-act="confirm"]');
    const cancelBtn = modal.querySelector('[data-act="cancel"]');
    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(false, modal, onKeyDown);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        close(true, modal, onKeyDown);
      }
    };

    modal.setAttribute('tabindex', '-1');
    modal.addEventListener('keydown', onKeyDown);

    cancelBtn?.addEventListener('click', () => close(false, modal, onKeyDown));
    confirmBtn?.addEventListener('click', () => close(true, modal, onKeyDown));

    window.requestAnimationFrame(() => {
      (confirmBtn || modal).focus({ preventScroll: true });
    });
  });
}

function promptForPin({
  title = 'Inserisci PIN',
  confirmLabel = 'Conferma',
  description = ''
} = {}){
  return new Promise((resolve) => {
    const modal = showModal(`
      <h3 class="title">${escapeHtml(title)}</h3>
      ${description ? `<p class="muted">${escapeHtml(description)}</p>` : ''}
      <form class="form" id="pin_form">
        <label class="field"><span>PIN</span><input id="pin_input" type="password" inputmode="numeric" autocomplete="one-time-code"></label>
        <div class="row" style="justify-content:flex-end;gap:.5rem">
          <button type="button" class="btn secondary" data-act="cancel">Annulla</button>
          <button type="submit" class="btn primary" data-act="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </form>
    `);
    if (!modal) {
      resolve(null);
      return;
    }

    const overlay = modal.parentElement;
    const form = modal.querySelector('#pin_form');
    const input = modal.querySelector('#pin_input');
    const cancelBtn = modal.querySelector('[data-act="cancel"]');
    let done = false;

    const cleanup = () => {
      modal.removeEventListener('keydown', onKeyDown);
      overlay?.removeEventListener('click', onOverlayClick, true);
      cancelBtn?.removeEventListener('click', onCancel);
      form?.removeEventListener('submit', onSubmit);
    };

    const close = (value) => {
      if (done) return;
      done = true;
      cleanup();
      clearModals();
      resolve(value);
    };

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(null);
      }
    };

    const onOverlayClick = (event) => {
      if (event.target === overlay) {
        event.preventDefault();
        close(null);
      }
    };

    const onCancel = (event) => {
      event.preventDefault();
      close(null);
    };

    const onSubmit = (event) => {
      event.preventDefault();
      const pin = (input?.value ?? '').trim();
      if (!pin) {
        input?.focus();
        return;
      }
      close(pin);
    };

    modal.addEventListener('keydown', onKeyDown);
    overlay?.addEventListener('click', onOverlayClick, true);
    cancelBtn?.addEventListener('click', onCancel);
    form?.addEventListener('submit', onSubmit);

    setTimeout(() => {
      input?.focus();
      input?.select();
    }, 0);
  });
}

function promptForPassword({
  title = 'Password utente',
  confirmLabel = 'Conferma',
  description = ''
} = {}){
  return new Promise((resolve) => {
    const modal = showModal(`
      <h3 class="title">${escapeHtml(title)}</h3>
      ${description ? `<p class="muted">${escapeHtml(description)}</p>` : ''}
      <form class="form" id="user_pw_form">
        <label class="field"><span>Password</span><input id="user_pw_input" type="password" autocomplete="current-password"></label>
        <div class="row" style="justify-content:flex-end;gap:.5rem">
          <button type="button" class="btn secondary" data-act="cancel">Annulla</button>
          <button type="submit" class="btn primary" data-act="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </form>
    `);
    if (!modal) {
      resolve(null);
      return;
    }

    const overlay = modal.parentElement;
    const form = modal.querySelector('#user_pw_form');
    const input = modal.querySelector('#user_pw_input');
    const cancelBtn = modal.querySelector('[data-act="cancel"]');
    let done = false;

    const cleanup = () => {
      modal.removeEventListener('keydown', onKeyDown);
      overlay?.removeEventListener('click', onOverlayClick, true);
      cancelBtn?.removeEventListener('click', onCancel);
      form?.removeEventListener('submit', onSubmit);
    };

    const close = (value) => {
      if (done) return;
      done = true;
      cleanup();
      clearModals();
      resolve(value);
    };

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        close(null);
      }
    };

    const onOverlayClick = (event) => {
      if (event.target === overlay) {
        event.preventDefault();
        close(null);
      }
    };

    const onCancel = (event) => {
      event.preventDefault();
      close(null);
    };

    const onSubmit = (event) => {
      event.preventDefault();
      const password = input?.value ?? '';
      if (!password) {
        input?.focus();
        return;
      }
      close(password);
    };

    modal.addEventListener('keydown', onKeyDown);
    overlay?.addEventListener('click', onOverlayClick, true);
    cancelBtn?.addEventListener('click', onCancel);
    form?.addEventListener('submit', onSubmit);

    setTimeout(() => {
      input?.focus();
      input?.select();
    }, 0);
  });
}

function ensureQRCode(target, text){
  if (!target) return;
  try {
    target.innerHTML = '';
    if (window.QRCode) {
      new window.QRCode(target, { text, width: 160, height: 160, correctLevel: window.QRCode.CorrectLevel.M });
    } else {
      target.textContent = text || '';
    }
  } catch (err) {
    console.warn('QRCode error', err);
    target.textContent = text || '';
  }
}

async function showUserSettings(){
  let totp = { enabled: false };
  try {
    totp = await apiGet('/api/user/totp');
  } catch (err) {
    console.warn('totp info', err);
  }
  const modal = showModal(`
    <h3 class="title">Impostazioni utente</h3>
    <div class="form">
      <h4>Cambia password</h4>
      <label class="field"><span>Password attuale</span><input id="pw_cur" type="password" autocomplete="current-password"></label>
      <label class="field"><span>Nuova password</span><input id="pw_new" type="password" autocomplete="new-password"></label>
      <div class="row" style="justify-content:flex-end"><button class="btn small primary" id="pw_save">Salva</button></div>
      <div id="pw_msg" class="msg small hidden"></div>
    </div>
    <hr style="border:0;border-top:1px solid rgba(255,255,255,.06);margin:1rem 0">
    <div class="form" id="totp_block">
      <h4>Autenticazione a due fattori</h4>
      <p class="muted" id="totp_state">${totp?.enabled ? '2FA attiva' : '2FA non attiva'}</p>
      <div class="row" id="totp_actions" style="gap:.5rem;justify-content:flex-end"></div>
      <div id="totp_setup" class="hidden"></div>
      <div id="totp_msg" class="msg small hidden"></div>
    </div>
    <div class="row" style="justify-content:flex-end;margin-top:1rem"><button class="btn secondary" id="settings_close">Chiudi</button></div>
  `);
  if (!modal) return;

  const pwMsg = $('#pw_msg', modal);
  $('#pw_save', modal)?.addEventListener('click', async () => {
    const current = $('#pw_cur', modal)?.value || '';
    const next = $('#pw_new', modal)?.value || '';
    if (!current || !next) {
      if (pwMsg) {
        pwMsg.textContent = 'Compila tutti i campi.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#f87171';
      }
      return;
    }
    try {
      await apiPost('/api/user/password', { current, newpass: next });
      if (pwMsg) {
        pwMsg.textContent = 'Password aggiornata.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#34d399';
      }
      $('#pw_cur', modal).value = '';
      $('#pw_new', modal).value = '';
    } catch (err) {
      if (pwMsg) {
        pwMsg.textContent = err instanceof HttpError ? err.message : 'Errore durante l’aggiornamento.';
        pwMsg.classList.remove('hidden');
        pwMsg.style.color = '#f87171';
      }
    }
  });

  function updateTotpActions(info){
    const actions = $('#totp_actions', modal);
    const setup = $('#totp_setup', modal);
    const msg = $('#totp_msg', modal);
    const stateLabel = $('#totp_state', modal);
    if (!actions || !stateLabel) return;
    actions.innerHTML = '';
    setup?.classList.add('hidden');
    if (msg) msg.classList.add('hidden');
    if (info?.enabled) {
      stateLabel.textContent = '2FA attiva';
      const btn = document.createElement('button');
      btn.className = 'btn small';
      btn.textContent = 'Disattiva 2FA';
      btn.addEventListener('click', async () => {
        try {
          await apiPost('/api/user/totp/disable', {});
          updateTotpActions({ enabled: false });
        } catch (err) {
          if (msg) {
            msg.textContent = 'Errore durante la disattivazione.';
            msg.classList.remove('hidden');
            msg.style.color = '#f87171';
          }
        }
      });
      actions.appendChild(btn);
    } else {
      stateLabel.textContent = '2FA non attiva';
      const btn = document.createElement('button');
      btn.className = 'btn small primary';
      btn.textContent = 'Abilita 2FA';
      btn.addEventListener('click', async () => {
        try {
          const info = await apiPost('/api/user/totp/enable', {});
          if (setup) {
            setup.classList.remove('hidden');
            setup.innerHTML = `
              <p>Scansiona il QR con la tua app di autenticazione.</p>
              <div class="row" style="align-items:flex-start;gap:1rem;margin:.75rem 0">
                <div id="totp_qr" class="card" style="padding:.6rem"></div>
                <div class="card" style="padding:.6rem;max-width:100%;overflow:auto"><code>${escapeHtml(info?.otpauth_uri || '')}</code></div>
              </div>
              <label class="field"><span>Codice OTP</span><input id="totp_code" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></label>
              <div class="row" style="justify-content:flex-end"><button class="btn small primary" id="totp_confirm">Conferma</button></div>
            `;
            ensureQRCode($('#totp_qr', setup), info?.otpauth_uri || '');
            $('#totp_confirm', setup)?.addEventListener('click', async () => {
              const otp = $('#totp_code', setup)?.value.trim();
              if (!otp) {
                if (msg) {
                  msg.textContent = 'Inserisci il codice OTP.';
                  msg.classList.remove('hidden');
                  msg.style.color = '#f87171';
                }
                return;
              }
              try {
                await apiPost('/api/user/totp/confirm', { otp });
                if (msg) {
                  msg.textContent = '2FA abilitata con successo.';
                  msg.classList.remove('hidden');
                  msg.style.color = '#34d399';
                }
                updateTotpActions({ enabled: true });
              } catch (err) {
                if (msg) {
                  const text = err instanceof HttpError && err.status === 409 ? 'Codice non valido o fuori tempo.' : 'Errore durante la conferma.';
                  msg.textContent = text;
                  msg.classList.remove('hidden');
                  msg.style.color = '#f87171';
                }
              }
            });
          }
        } catch (err) {
          if (msg) {
            msg.textContent = 'Errore durante l’abilitazione della 2FA.';
            msg.classList.remove('hidden');
            msg.style.color = '#f87171';
          }
        }
      });
      actions.appendChild(btn);
    }
  }

  updateTotpActions(totp);

  $('#settings_close', modal)?.addEventListener('click', () => {
    clearModals();
  });
}

function setupUserMenu(){
  const btn = $('#userBtn');
  const dropdown = $('#userDropdown');
  if (!btn || !dropdown) return;
  btn.addEventListener('click', (event) => {
    event.stopPropagation();
    dropdown.classList.toggle('hidden');
  });
  document.addEventListener('click', () => dropdown.classList.add('hidden'));
  dropdown.querySelector('[data-act="settings"]')?.addEventListener('click', () => {
    dropdown.classList.add('hidden');
    showUserSettings();
  });
  dropdown.querySelector('[data-act="sys_settings"]')?.addEventListener('click', () => {
    dropdown.classList.add('hidden');
    window.location.href = './admin.html';
  });
  dropdown.querySelector('[data-act="logout"]')?.addEventListener('click', async () => {
    dropdown.classList.add('hidden');
    try {
      await apiPost('/api/logout', {});
    } catch (err) {
      console.warn('logout', err);
    }
    requireLogin();
  });
}

async function loadSession(){
  const me = await apiGet('/api/me');
  state.currentUser = me?.user || '';
  const role = normalizeRole(me?.role);
  state.role = role;
  const fallbackAdmin = !!me?.is_admin;
  state.isAdmin = role != null ? role >= ROLE_ADMIN : fallbackAdmin;
  const label = $('#userLabel');
  if (label) {
    if (!state.currentUser) {
      label.textContent = '';
    } else {
      const userHtml = `<span class="user-name">${escapeHtml(state.currentUser)}</span>`;
      const roleHtml = state.isAdmin ? ' <span class="user-role tag warn">ADMIN</span>' : '';
      label.innerHTML = `${userHtml}${roleHtml}`;
    }
  }
  updateAdminVisibility();
}

async function init(){
  if (!getToken() || !getSystemSuffix()) {
    requireLogin();
    return;
  }

  document.getElementById('year').textContent = String(new Date().getFullYear());
  setBrandSystem();
  setupTabs();
  setupCommands();
  setupZonesConfig();
  setupUserMenu();
  setupLogFilters();

  $('#logsClear')?.addEventListener('click', async () => {
    if (!state.isAdmin) return;
    const confirmed = await showConfirm({
      title: 'Svuota log eventi',
      message: 'Vuoi cancellare definitivamente tutti gli eventi dal log?',
      confirmLabel: 'Cancella tutto',
      confirmTone: 'danger'
    });
    if (!confirmed) return;
    try {
      await apiPost('/api/logs/clear', {});
      state.logs = [];
      renderLogEntries([]);
      showNotice('Log cancellati con successo.', 'info');
    } catch (err) {
      console.error('logsClear', err);
      showNotice('Impossibile cancellare il log eventi.', 'error');
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      stopStatusUpdates();
      stopZonesUpdates();
    } else if (state.activeTab === 'status') {
      startStatusUpdates({ immediate: true });
    } else if (state.activeTab === 'zones') {
      startZonesUpdates({ immediate: true });
    }
  });
  window.addEventListener('pagehide', () => {    
    stopStatusUpdates();
    stopZonesUpdates();    
  });
  window.addEventListener('beforeunload', () => {    
    stopStatusUpdates();
    stopZonesUpdates();    
  });

  try {
    await loadSession();
  } catch (err) {
    console.error('loadSession', err);
    requireLogin();
    return;
  }

  startIdleTracking();

  ensureBoardsLoaded().catch((err) => console.warn('boards metadata', err));

  $('#appRoot')?.classList.remove('hidden');
  setActiveTab('status');
}

init();