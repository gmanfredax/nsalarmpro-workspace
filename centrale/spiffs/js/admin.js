// /spiffs/js/admin.js — Admin UI (Utenti, Rete, MQTT)
(() => {
  const $  = (s, r=document) => r.querySelector(s);
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  // ========== FETCH shim: Authorization Bearer + cookie same-origin + redirect 401/403
  (function installAuthFetchShim(){
    const _fetch = window.fetch;
    window.fetch = (input, init = {}) => {
      const { __skipAuthRedirect, ...rest } = init || {};
      const headers = new Headers(rest.headers || {});
      const t = (()=>{
        try {
          return (
            localStorage.getItem("alarmpro.token") ||
            sessionStorage.getItem("alarmpro.token") ||
            localStorage.getItem("token") ||
            sessionStorage.getItem("token") ||
            ""
          );
        } catch {
          return "";
        }
      })();
      if (t && !headers.has("Authorization")) headers.set("Authorization", "Bearer " + t);
      const creds = rest.credentials ? rest.credentials : "same-origin";
      return _fetch(input, { ...rest, headers, credentials: creds }).then(resp => {
        if (!__skipAuthRedirect){
          if (resp.status === 401) { location.replace("/login.html"); }
          else if (resp.status === 403) { location.replace("/403.html"); }
        }
        return resp;
      });
    };
  })();

  // ========== Helpers UI / auth ==========
  function toast(msg, ok=true){
    let el = $("#toast");
    if (!el){
      el = document.createElement("div");
      el.id = "toast";
      el.className = "toast";
      Object.assign(el.style, {position:"fixed",bottom:"18px",left:"18px",padding:".6rem .8rem",borderRadius:"10px",background:"rgba(20,28,44,.95)",border:"1px solid var(--border)",color:"var(--text)",zIndex:2000,boxShadow:"0 6px 24px rgba(0,0,0,.35)",maxWidth:"80%"});
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.borderColor = ok ? "rgba(16,185,129,.45)" : "rgba(239,68,68,.55)";
    el.style.background = ok ? "rgba(10,20,24,.95)" : "rgba(32,12,12,.95)";
    clearTimeout(el._t); el._t = setTimeout(()=>{ el.remove(); }, 2400);
  }
  const needLogin = () => location.replace("/login.html");

  let currentUser = "";
  let isAdmin = false;

  async function apiGet(url){
    const r = await fetch(url, { headers: { "Accept":"application/json" } });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(await r.text());
    try {
      return await r.json();
    } catch (err) {
      throw new Error("Risposta JSON non valida");
    }
  }
  async function apiPost(url, body, opts = {}){
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body!=null ? JSON.stringify(body) : undefined,
      __skipAuthRedirect: opts.skipAuthRedirect === true
    });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok) throw new Error(await r.text());
    try { return await r.json(); } catch { return {}; }
  }

  async function apiDelete(url){
    const r = await fetch(url, { method:"DELETE", headers:{ "Accept":"application/json" } });
    if (r.status === 401) { needLogin(); throw new Error("401"); }
    if (!r.ok){
      let detail = "";
      try {
        const ct = r.headers.get("content-type") || "";
        if (ct.includes("application/json")){
          const data = await r.json();
          detail = data?.error || data?.message || JSON.stringify(data);
        } else {
          detail = await r.text();
        }
      } catch(err){
        detail = err?.message || await r.text();
      }
      throw new Error(detail || `${r.status} ${r.statusText}`);
    }
    try { return await r.json(); } catch { return {}; }
  }

  const escapeHtml = (value = "") => (value ?? "").toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  const fileToBase64 = (file) => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("lettura"));
    reader.onload = () => {
      try {
        const bytes = new Uint8Array(reader.result);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        resolve(btoa(binary));
      } catch (e) {
        reject(e);
      }
    };
    reader.readAsArrayBuffer(file);
  });

  const WEB_TLS_MAX_PEM_LEN = 4096;
  const ROLE_ADMIN = 2;

  const expansionsState = {
    items: [],
    loading: false,
    error: "",
    lastScan: null,
  };
  const CAN_MAX_NODE_ID = 127;
  const CAN_NODE_LABEL_MAX = 31;

  const canTestBroadcastState = {
    sending: false,
    pendingState: null,
    lastState: null,
    lastError: "",
    lastRequestAt: 0,
  };

  const TELEMETRY_REFRESH_MS = 1500;
  let telemetryTimer = null;
  let telemetryNodeId = null;
  let telemetryFetchPending = false;
  const modalCleanupHandlers = new Set();

  const analogState = {
    globals: null,
    zones: [],
    backend: '',
    diagnostics: null,
  };

  function formatDateTime(ts){
    if (ts == null) return "";
    let date;
    if (ts instanceof Date) date = ts;
    else if (typeof ts === "number") date = new Date(ts);
    else if (typeof ts === "string" && ts) date = new Date(ts);
    else return "";
    if (Number.isNaN(date.getTime())) return "";
    try { return date.toLocaleString("it-IT"); }
    catch { return date.toISOString(); }
  }

  function formatInteger(value){
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    try {
      return num.toLocaleString("it-IT");
    } catch {
      return String(num);
    }
  }

  function formatVoltage(value){
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    return num.toFixed(3).replace(/\.000$/, '.0');
  }

  function formatOhms(value){
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    if (Math.abs(num) >= 1000) {
      try {
        return `${num.toLocaleString('it-IT', { maximumFractionDigits: 0 })}`;
      } catch {
        return String(Math.round(num));
      }
    }
    return num.toFixed(0);
  }

  const MODE_LABELS = Object.freeze({
    digital: 'Digitale',
    eol1: 'EOL1',
    eol2: '2EOL',
    eol3: '3EOL',
    unknown: 'Sconosciuto',
  });

  const CONTACT_LABELS = Object.freeze({
    nc: 'NC',
    no: 'NO',
  });

  const STATUS_LABELS = Object.freeze({
    normal: 'Normale',
    alarm: 'Allarme',
    tamper: 'Tamper',
    fault_short: 'Corto',
    fault_open: 'Interruzione',
    unknown: 'Sconosciuto',
  });

  const normalizeRole = (roleValue) => {
    if (typeof roleValue === 'number') return Number.isNaN(roleValue) ? null : roleValue;
    if (typeof roleValue === 'string' && roleValue.trim() !== '') {
      const parsed = Number.parseInt(roleValue, 10);
      return Number.isNaN(parsed) ? null : parsed;
    }
    return null;
  };

    // -------------- Header / menu utente --------------
  function syncHeader(){
    const label = $("#userLabel");
    if (!label) return;
    if (!currentUser) {
      label.textContent = "";
      return;
    }
    const nameHtml = `<span class="user-name">${escapeHtml(currentUser)}</span>`;
    const roleHtml = isAdmin ? ' <span class="user-role tag warn">ADMIN</span>' : '';
    label.innerHTML = `${nameHtml}${roleHtml}`;
  }
  
  function updateAdminVisibility(){
    document.body.classList.toggle('is-admin', isAdmin);
    $$('.admin-only').forEach(el => {
      el.classList.toggle('hidden', !isAdmin);
      el.style.removeProperty('display');
    });
    const zBtn = $('#btnZonesCfg');
    if (zBtn) {
      zBtn.classList.toggle('hidden', !isAdmin);
      zBtn.style.removeProperty('display');
    }
  }

  function mountUserMenu(){
    const btn = $("#userBtn"), dd = $("#userDropdown");
    if (!btn || !dd) return;
    btn.onclick = (e)=>{ e.stopPropagation(); dd.classList.toggle("hidden"); };
    document.addEventListener("click", ()=>dd.classList.add("hidden"));
    dd.querySelector("[data-act=logout]")?.addEventListener("click", async ()=>{
      dd.classList.add("hidden");
      try{ await apiPost("/api/logout",{});}catch{}
      try {
        localStorage.removeItem("alarmpro.token");
        localStorage.removeItem("token");
      } catch(_){}
      try {
        sessionStorage.removeItem("alarmpro.token");
        sessionStorage.removeItem("token");
      } catch(_){}
      needLogin();
    });
  }

  // ========== Gate client-side (semplificato)
  // Il server decide già se servire admin.html o 403.html.
  // Qui sblocchiamo solo la UI e lasciamo al fetch-shim il redirect quando il token scade.
  async function ensureAdminOr403(){
    document.getElementById("appRoot")?.classList.remove("hidden");
    return true;
  }
  async function ensureAdmin(){ return ensureAdminOr403(); }

  // ========== Sidebar / Views
  function setupSidebar(){
    $$(".side button").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-view");
        const targetView = id ? document.getElementById(id) : null;
        const views = $$(".view");
        $$(".side button").forEach(b => b.classList.toggle("active", b===btn));
        if (targetView){
          views.forEach(view => view.classList.toggle("active", view === targetView));
        }
        if (!targetView){
          const current = views.find(view => view.classList.contains("active"));
          if (current) current.classList.add("active");
        }
        if (id !== "view-mqtt") maskMqttPassword();
      });
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) maskMqttPassword();
  });

  function getExpansionItems(){
    const items = Array.isArray(expansionsState.items) ? expansionsState.items : [];
    return items.slice().sort((a, b) => {
      const aId = Number(a?.node_id ?? 0);
      const bId = Number(b?.node_id ?? 0);
      return aId - bId;
    });
  }

    function upsertExpansionNode(updated){
    if (!updated || typeof updated !== "object") return;
    const nodeId = Number(updated?.node_id ?? updated?.nodeId);
    if (!Number.isFinite(nodeId) || nodeId <= 0) return;
    const current = Array.isArray(expansionsState.items) ? expansionsState.items.slice() : [];
    let replaced = false;
    for (let idx = 0; idx < current.length; ++idx){
      const itemId = Number(current[idx]?.node_id);
      if (itemId === nodeId){
        current[idx] = { ...current[idx], ...updated };
        replaced = true;
        break;
      }
    }
    if (!replaced){
      current.push(updated);
    }
    expansionsState.items = current;
    expansionsState.lastScan = Date.now();
    expansionsState.error = "";
    renderExpansionsSection();
  }

  function nodeTitle(node){
    if (!node) return "Nodo CAN";
    const label = (node.label && String(node.label).trim()) || "";
    if (label) return label;
    const kind = (node.kind && String(node.kind).trim()) || "";
    if (kind) return `${kind}${node.node_id != null ? ` #${node.node_id}` : ""}`;
    if (node.node_id != null) return `Nodo ${node.node_id}`;
    return "Nodo CAN";
  }

  function formatNodeStateLabel(node){
    const raw = (node?.state || "").toString().toUpperCase();
    switch (raw) {
      case "ONLINE": return "Online";
      case "OFFLINE": return "Offline";
      case "PREOP":
      case "PRE-OP": return "Pre-operativa";
      case "UNKNOWN":
      case "": return "Sconosciuto";
      default: return raw;
    }
  }

  function formatUid(value){
    if (value == null) return "—";
    const cleaned = String(value).replace(/[^0-9a-fA-F]/g, "").toUpperCase();
    if (!cleaned) return "—";
    return cleaned.replace(/(.{2})/g, "$1 ").trim();
  }

  const WALL_TIME_MIN_MS = Date.UTC(2000, 0, 1);

  function coerceTimestampMs(value){
    if (value == null) return null;
    let raw = null;
    if (typeof value === "number") {
      raw = value;
    } else if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return null;
      const parsed = Number(trimmed);
      raw = Number.isFinite(parsed) ? parsed : null;
    } else {
      raw = Number(value);
    }
    if (!Number.isFinite(raw) || raw <= 0) return null;
    if (raw < WALL_TIME_MIN_MS) return null;
    return raw;
  }

  function formatNodeAssociation(node){
    if (!node) return "—";
    const nodeId = Number(node?.node_id ?? -1);
    const raw = coerceTimestampMs(nodeId === 0
      ? (node?.registered_at_ms ?? node?.registered_at)
      : (node?.associated_at_ms ?? node?.associated_at)
    );
    if (!Number.isFinite(raw)) return "—";
    return formatDateTime(raw);
  }

  function formatNodeLastSeen(node){
    const raw = Number(node?.last_seen_ms ?? node?.last_seen);
    if (!Number.isFinite(raw) || raw <= 0) return "—";
    return formatDateTime(raw);
  }

  function renderExpansionsSection(){
    const nodes = getExpansionItems();
    const list = $("#adminExpansionList");
    if (list){
      list.innerHTML = nodes.map((node) => {
        if (!node) return "";
        const nodeId = Number(node.node_id ?? -1);
        const title = escapeHtml(nodeTitle(node));
        const stateLabel = formatNodeStateLabel(node);
        const uidDisplay = formatUid(node?.uid);
        const association = formatNodeAssociation(node);
        const metaParts = [];
        if (nodeId >= 0) metaParts.push(`ID ${nodeId}`);
        if (stateLabel) metaParts.push(`Stato: ${stateLabel}`);
        if (node.kind) metaParts.push(String(node.kind));
        const ioParts = [];
        if (node.inputs_count != null) ioParts.push(`${node.inputs_count} ingressi`);
        if (node.outputs_count != null) ioParts.push(`${node.outputs_count} uscite`);
        if (ioParts.length) metaParts.push(ioParts.join(' · '));
        const assocLabel = nodeId === 0 ? "Registrata il" : "Associata il";
        if (association !== "—") metaParts.push(`${assocLabel}: ${association}`);
        const meta = metaParts.filter(Boolean).map((part)=>escapeHtml(String(part))).join(' · ');
        const telemetryBtn = nodeId === 0
          ? ''
          : `<button class="btn btn-sm" type="button" data-node-telemetry="${nodeId}">Telemetria</button>`;
        const actions = nodeId === 0
          ? '<span class="muted">Master</span>'
          : `${telemetryBtn}<button class="btn btn-sm outline" type="button" data-node-actions="${nodeId}">Azioni</button>`;
        return `<li class="expansion-item" data-node-id="${nodeId}">
            <div class="expansion-info">
              <div class="expansion-title">${title}</div>
              ${meta ? `<div class="expansion-meta">${meta}</div>` : ''}
              ${uidDisplay ? `<div class="expansion-meta">UID ${uidDisplay}</div>` : ''}
            </div>
            <div class="expansion-actions">${actions}</div>
          </li>`;
      }).join("");
    }
    const empty = $("#adminExpansionEmpty");
    if (empty){
      const showEmpty = !expansionsState.loading && !expansionsState.error && nodes.length === 0;
      empty.classList.toggle("hidden", !showEmpty);
    }
    const status = $("#adminExpansionStatus");
    if (status){
      status.classList.remove("error", "success", "muted", "hidden");
      let text = "";
      if (expansionsState.loading){
        text = "Caricamento nodi CAN…";
        status.classList.add("muted");
      } else if (expansionsState.error){
        text = expansionsState.error;
        status.classList.add("error");
      } else if (nodes.length){
        const when = formatDateTime(expansionsState.lastScan);
        text = when ? `Ultimo aggiornamento: ${when}` : "Elenco aggiornato.";
        status.classList.add("success");
      } else {
        text = "Nessuna scheda registrata.";
        status.classList.add("muted");
      }
      status.textContent = text;
      status.classList.toggle("hidden", !text);
    }
    const disableActions = !!expansionsState.loading;
    const scanBtn = $("#adminExpansionScanBtn");
    if (scanBtn) scanBtn.disabled = disableActions;
    const refreshBtn = $("#adminExpansionRefreshBtn");
    if (refreshBtn) refreshBtn.disabled = disableActions;
  }

  function setTelemetryValue(key, value, { warn = false } = {}){
    const el = document.querySelector(`[data-telemetry="${key}"]`);
    if (!el) return;
    const display = (value == null || value === '') ? '—' : value;
    el.textContent = display;
    el.classList.toggle('warn', !!warn);
  }

  function formatTelemetryTimestamp(ts){
    if (ts == null) return '—';
    const num = Number(ts);
    if (!Number.isFinite(num) || num <= 0) return '—';
    return formatDateTime(num);
  }

  function updateTelemetryUI(payload){
    if (!payload || typeof payload !== 'object') {
      return;
    }
    const node = payload.node || {};
    const bus = payload.bus || {};
    const exists = node.exists !== false;
    const online = !!node.online;
    setTelemetryValue('node_state', exists ? (online ? 'Online' : 'Offline') : 'Non registrato', { warn: exists && !online });
    setTelemetryValue('node_last_seen', formatTelemetryTimestamp(node.last_seen_ms));
    setTelemetryValue('node_last_online', formatTelemetryTimestamp(node.last_online_ms));
    setTelemetryValue('node_heartbeat', formatInteger(node.heartbeat_count));
    setTelemetryValue('node_info', formatInteger(node.info_count));
    setTelemetryValue('node_commands', formatInteger(node.command_count));
    setTelemetryValue('node_command_errors', formatInteger(node.command_errors), { warn: Number(node.command_errors) > 0 });
    setTelemetryValue('node_offline_events', formatInteger(node.offline_events), { warn: Number(node.offline_events) > 0 });

    const supported = !!bus.supported;
    setTelemetryValue('bus_supported', supported ? 'Disponibile' : 'Non disponibile', { warn: !supported });
    if (supported) {
      setTelemetryValue('bus_driver', bus.driver_started ? 'Attivo' : 'Spento', { warn: !bus.driver_started });
      setTelemetryValue('bus_last_activity', formatTelemetryTimestamp(bus.last_activity_ms));
      setTelemetryValue('bus_packets_sent', formatInteger(bus.packets_sent));
      setTelemetryValue('bus_packets_received', formatInteger(bus.packets_received));
      setTelemetryValue('bus_packets_lost', formatInteger(bus.packets_lost), { warn: Number(bus.packets_lost) > 0 });
      setTelemetryValue('bus_tx_errors', formatInteger(bus.tx_errors), { warn: Number(bus.tx_errors) > 0 });
      setTelemetryValue('bus_rx_errors', formatInteger(bus.rx_errors), { warn: Number(bus.rx_errors) > 0 });
      setTelemetryValue('bus_offline_events', formatInteger(bus.offline_events), { warn: Number(bus.offline_events) > 0 });
      setTelemetryValue('bus_nodes_online', formatInteger(bus.nodes_online));
      setTelemetryValue('bus_nodes_known', formatInteger(bus.nodes_known));
    } else {
      [
        'bus_driver',
        'bus_last_activity',
        'bus_packets_sent',
        'bus_packets_received',
        'bus_packets_lost',
        'bus_tx_errors',
        'bus_rx_errors',
        'bus_offline_events',
        'bus_nodes_online',
        'bus_nodes_known',
      ].forEach((key) => setTelemetryValue(key, '—', { warn: false }));
    }
  }

  async function fetchNodeTelemetry(nodeId){
    if (!telemetryNodeId || telemetryNodeId !== nodeId) {
      telemetryFetchPending = false;
      return;
    }
    if (telemetryFetchPending) return;
    telemetryFetchPending = true;
    const statusEl = $("#telemetryStatus");
    try {
      const payload = await apiGet(`/api/can/node/${nodeId}/telemetry`);
      if (!telemetryNodeId || telemetryNodeId !== nodeId) {
        return;
      }
      updateTelemetryUI(payload);
      if (statusEl && document.body.contains(statusEl)) {
        statusEl.textContent = `Aggiornato alle ${formatDateTime(Date.now())}`;
        statusEl.classList.remove("error");
      }
    } catch (err){
      const message = err?.message || "telemetria non disponibile";
      if (statusEl && document.body.contains(statusEl)) {
        statusEl.textContent = `Errore: ${message}`;
        statusEl.classList.add("error");
      }
      if (err?.status === 404 && telemetryNodeId === nodeId) {
        stopTelemetryWatcher();
      }
    } finally {
      if (telemetryNodeId === nodeId) {
        telemetryFetchPending = false;
      }
    }
  }

  function stopTelemetryWatcher(){
    if (telemetryTimer) {
      clearInterval(telemetryTimer);
      telemetryTimer = null;
    }
    telemetryNodeId = null;
    telemetryFetchPending = false;
  }

  function startTelemetryWatcher(nodeId){
    stopTelemetryWatcher();
    const normalized = Number(nodeId);
    if (!Number.isFinite(normalized) || normalized <= 0) {
      telemetryNodeId = null;
      return;
    }
    telemetryNodeId = normalized;
    const statusEl = $("#telemetryStatus");
    if (statusEl) {
      statusEl.textContent = "Caricamento telemetria…";
      statusEl.classList.remove("error");
    }
    fetchNodeTelemetry(telemetryNodeId);
    telemetryTimer = window.setInterval(() => {
      if (telemetryNodeId) {
        fetchNodeTelemetry(telemetryNodeId);
      }
    }, TELEMETRY_REFRESH_MS);
  }

  function openNodeTelemetry(nodeId){
    const nodes = getExpansionItems();
    const node = nodes.find((item) => Number(item?.node_id) === nodeId) || null;
    const title = escapeHtml(nodeTitle(node) || `Nodo ${nodeId}`);
    const metaParts = [];
    if (node?.kind) metaParts.push(escapeHtml(String(node.kind)));
    const inputsCount = Number(node?.inputs_count);
    const outputsCount = Number(node?.outputs_count);
    const ioParts = [];
    if (Number.isFinite(inputsCount)) ioParts.push(`${inputsCount} ingressi`);
    if (Number.isFinite(outputsCount)) ioParts.push(`${outputsCount} uscite`);
    if (ioParts.length) metaParts.push(ioParts.join(' · '));
    const metaLine = metaParts.length ? `<p class="muted small">${metaParts.join(' · ')}</p>` : '';
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Telemetria nodo CAN</h3>
        <button class="btn" id="telemetryCloseBtn" type="button">Chiudi</button>
      </div>
      <p class="muted">Monitoraggio in tempo reale per <strong>${title}</strong> (ID ${escapeHtml(String(nodeId))}).</p>
      ${metaLine}
      <div id="telemetryStatus" class="telemetry-status">Caricamento telemetria…</div>
      <div class="telemetry-grid">
        <section class="telemetry-card">
          <h4>Stato nodo</h4>
          <div class="telemetry-metric">
            <span>Stato</span>
            <strong data-telemetry="node_state">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultimo pacchetto</span>
            <strong data-telemetry="node_last_seen">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultimo online</span>
            <strong data-telemetry="node_last_online">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Heartbeat ricevuti</span>
            <strong data-telemetry="node_heartbeat">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Info ricevute</span>
            <strong data-telemetry="node_info">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Comandi inviati</span>
            <strong data-telemetry="node_commands">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori comando</span>
            <strong data-telemetry="node_command_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Offline rilevati</span>
            <strong data-telemetry="node_offline_events">—</strong>
          </div>
        </section>
        <section class="telemetry-card">
          <h4>Bus CAN</h4>
          <div class="telemetry-metric">
            <span>Supporto</span>
            <strong data-telemetry="bus_supported">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Driver</span>
            <strong data-telemetry="bus_driver">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Ultima attività</span>
            <strong data-telemetry="bus_last_activity">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti inviati</span>
            <strong data-telemetry="bus_packets_sent">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti ricevuti</span>
            <strong data-telemetry="bus_packets_received">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Pacchetti perduti</span>
            <strong data-telemetry="bus_packets_lost">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori TX</span>
            <strong data-telemetry="bus_tx_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Errori RX</span>
            <strong data-telemetry="bus_rx_errors">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Offline bus</span>
            <strong data-telemetry="bus_offline_events">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Nodi online</span>
            <strong data-telemetry="bus_nodes_online">—</strong>
          </div>
          <div class="telemetry-metric">
            <span>Nodi totali</span>
            <strong data-telemetry="bus_nodes_known">—</strong>
          </div>
        </section>
      </div>
    `);
    $("#telemetryCloseBtn")?.addEventListener("click", () => closeModal());
    registerModalCleanup(() => stopTelemetryWatcher());
    startTelemetryWatcher(nodeId);
  }

  function updateCanTestBroadcastUI(){
    const onBtn = $("#canTestBroadcastOnBtn");
    const offBtn = $("#canTestBroadcastOffBtn");
    const { sending, pendingState, lastState } = canTestBroadcastState;
    if (onBtn){
      const busy = sending && pendingState === true;
      onBtn.disabled = sending;
      onBtn.textContent = busy ? "Invio…" : "BUS ON";
      onBtn.classList.toggle("outline", lastState !== true);
      onBtn.setAttribute("aria-pressed", lastState === true ? "true" : "false");
    }
    if (offBtn){
      const busy = sending && pendingState === false;
      offBtn.disabled = sending;
      offBtn.textContent = busy ? "Invio…" : "BUS OFF";
      offBtn.classList.toggle("outline", lastState !== false);
      offBtn.setAttribute("aria-pressed", lastState === false ? "true" : "false");
    }
    const status = $("#canTestBroadcastStatus");
    if (status){
      status.classList.remove("error", "success");
      if (sending){
        status.textContent = `Invio comando CAN ${pendingState ? "ON" : "OFF"}…`;
        status.classList.remove("muted");
      } else if (canTestBroadcastState.lastError){
        status.textContent = canTestBroadcastState.lastError;
        status.classList.remove("muted");
        status.classList.add("error");
      } else if (lastState === true || lastState === false){
        status.textContent = `Ultimo broadcast: ${lastState ? "ON" : "OFF"}.`;
        status.classList.remove("muted");
        status.classList.add("success");
      } else {
        status.textContent = "Premi per inviare \"ON\" o \"OFF\" sul bus CAN.";
        status.classList.add("muted");
      }
    }
  }

  async function sendCanBroadcast(nextState){
    const now = Date.now();
    if (now - canTestBroadcastState.lastRequestAt < 200){
      return;
    }
    canTestBroadcastState.lastRequestAt = now;
    if (canTestBroadcastState.sending){
      return;
    }
    canTestBroadcastState.sending = true;
    canTestBroadcastState.pendingState = nextState;
    canTestBroadcastState.lastError = "";
    updateCanTestBroadcastUI();
    try {
      const endpoint = nextState ? "/api/can/test/broadcast/on" : "/api/can/test/broadcast/off";
      const resp = await apiPost(endpoint, null);
      const isOn = typeof resp?.on === "boolean" ? resp.on : nextState;
      canTestBroadcastState.lastState = isOn;
      toast(`CAN: broadcast ${isOn ? "ON" : "OFF"} inviato`);
    } catch (err){
      const message = err?.message || "Invio comando CAN fallito";
      canTestBroadcastState.lastError = `Errore: ${message}`;
      toast(`CAN: ${message}`, false);
    } finally {
      canTestBroadcastState.sending = false;
      canTestBroadcastState.pendingState = null;
      updateCanTestBroadcastUI();
    }
  }

  function renderAnalogConfig(){
    const globals = analogState.globals || {};
    const fields = [
      ['#analog_r_normal', globals.r_normal],
      ['#analog_r_alarm', globals.r_alarm],
      ['#analog_r_tamper', globals.r_tamper],
      ['#analog_r_eol', globals.r_eol],
      ['#analog_short_threshold', globals.short_threshold],
      ['#analog_open_threshold', globals.open_threshold],
      ['#analog_debounce_ms', globals.debounce_ms],
      ['#analog_hysteresis_pct', globals.hysteresis_pct],
    ];
    fields.forEach(([selector, value]) => {
      const input = $(selector);
      if (!input) return;
      const num = Number(value);
      if (Number.isFinite(num)) {
        input.value = String(num);
      }
    });

    const tbody = $("#analogZoneConfigBody");
    if (!tbody) return;
    if (!Array.isArray(analogState.zones) || analogState.zones.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4">Configurazione non disponibile</td></tr>';
      return;
    }
    tbody.innerHTML = analogState.zones.map((zone) => {
      const id = Number(zone?.id);
      const name = escapeHtml(zone?.name || `Zona ${id}`);
      const mode = typeof zone?.mode === 'string' ? zone.mode : 'digital';
      const contact = typeof zone?.contact === 'string' ? zone.contact : 'nc';
      const modeOptions = ['digital','eol1','eol2','eol3']
        .map((value) => {
          const label = MODE_LABELS[value] || value.toUpperCase();
          const selected = value === mode ? ' selected' : '';
          return `<option value="${value}"${selected}>${label}</option>`;
        }).join('');
      const contactOptions = ['nc','no']
        .map((value) => {
          const label = CONTACT_LABELS[value] || value.toUpperCase();
          const selected = value === contact ? ' selected' : '';
          return `<option value="${value}"${selected}>${label}</option>`;
        }).join('');
      return `<tr data-zone-id="${id}">
        <td>${id}</td>
        <td>${name}</td>
        <td><select data-zone-mode="${id}">${modeOptions}</select></td>
        <td><select data-zone-contact="${id}">${contactOptions}</select></td>
      </tr>`;
    }).join('');
  }

  async function loadAnalogConfig(){
    try {
      const data = await apiGet('/api/zones/analog');
      analogState.globals = data?.globals || null;
      analogState.zones = Array.isArray(data?.zones) ? data.zones : [];
      renderAnalogConfig();
    } catch (err) {
      toast(`Configurazione zone: ${err.message}`, false);
    }
  }

  async function submitAnalogConfig(ev){
    ev.preventDefault();
    const status = $('#analogConfigStatus');
    if (status) {
      status.textContent = 'Salvataggio in corso…';
      status.classList.remove('error', 'success');
    }
    const readFloat = (selector, fallback = 0) => {
      const input = $(selector);
      const value = input ? Number.parseFloat(input.value) : NaN;
      return Number.isFinite(value) ? value : fallback;
    };
    const readInt = (selector, fallback = 0) => {
      const input = $(selector);
      const value = input ? Number.parseInt(input.value, 10) : NaN;
      return Number.isFinite(value) ? value : fallback;
    };

    const payload = {
      globals: {
        r_normal: readFloat('#analog_r_normal', analogState.globals?.r_normal ?? 4700),
        r_alarm: readFloat('#analog_r_alarm', analogState.globals?.r_alarm ?? 2200),
        r_tamper: readFloat('#analog_r_tamper', analogState.globals?.r_tamper ?? 8200),
        r_eol: readFloat('#analog_r_eol', analogState.globals?.r_eol ?? 4700),
        short_threshold: readFloat('#analog_short_threshold', analogState.globals?.short_threshold ?? 1000),
        open_threshold: readFloat('#analog_open_threshold', analogState.globals?.open_threshold ?? 20000),
        debounce_ms: readInt('#analog_debounce_ms', analogState.globals?.debounce_ms ?? 150),
        hysteresis_pct: readFloat('#analog_hysteresis_pct', analogState.globals?.hysteresis_pct ?? 12),
      },
      zones: [],
    };

    const rows = $$('#analogZoneConfigBody tr');
    rows.forEach((row) => {
      const zoneId = Number(row?.dataset?.zoneId);
      if (!Number.isFinite(zoneId) || zoneId <= 0) return;
      const mode = row.querySelector(`select[data-zone-mode="${zoneId}"]`)?.value || 'digital';
      const contact = row.querySelector(`select[data-zone-contact="${zoneId}"]`)?.value || 'nc';
      payload.zones.push({ id: zoneId, mode, contact });
    });

    try {
      await apiPost('/api/zones/analog', payload);
      if (status) {
        status.textContent = 'Configurazione salvata.';
        status.classList.add('success');
      }
      toast('Configurazione zone salvata');
      await loadAnalogConfig();
    } catch (err) {
      if (status) {
        status.textContent = `Errore: ${err.message}`;
        status.classList.add('error');
      }
      toast(`Configurazione zone: ${err.message}`, false);
    }
  }

  function renderDiagnostics(data){
    analogState.diagnostics = data || null;
    if (data?.backend) {
      analogState.backend = data.backend;
    }
    const expectedBox = $('#diagExpected');
    if (expectedBox) {
      const expected = data?.expected || null;
      if (!expected) {
        expectedBox.innerHTML = '<p class="muted">Soglie non disponibili.</p>';
      } else {
        const cards = [];
        const makeEntry = (title, entries) => {
          if (!entries) return '';
          const rows = Object.entries(entries)
            .filter(([, value]) => value && typeof value === 'object')
            .map(([key, value]) => {
              const label = key.toUpperCase();
              const vz = formatVoltage(value?.vz);
              const counts = formatInteger(value?.counts);
              const r = value?.resistance != null ? `${formatOhms(value.resistance)} Ω` : '—';
              return `<div class="diag-expected-row"><span>${label}</span><strong>${vz} V</strong><em>${counts} cnt</em><small>${r}</small></div>`;
            }).join('');
          return `<div class="diag-expected-card"><h4>${title}</h4>${rows || '<div class="muted">N/A</div>'}</div>`;
        };
        if (expected.eol1) cards.push(makeEntry('EOL1', expected.eol1));
        if (expected.eol2) cards.push(makeEntry('2EOL', expected.eol2));
        if (expected.eol3) cards.push(makeEntry('3EOL', expected.eol3));
        expectedBox.innerHTML = `<div class="diag-expected-grid">${cards.join('')}</div>`;
      }
    }

    const backendLabel = $('#diagBackend');
    if (backendLabel) {
      backendLabel.textContent = analogState.backend ? analogState.backend.toUpperCase() : 'Sconosciuto';
    }

    const tbody = $('#diagZonesTable tbody');
    if (tbody) {
      const zones = Array.isArray(data?.zones) ? data.zones : [];
      if (zones.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10">Nessun dato disponibile</td></tr>';
      } else {
        tbody.innerHTML = zones.map((zone) => {
          const id = Number(zone?.id);
          const name = escapeHtml(zone?.name || `Zona ${id}`);
          const statusKey = typeof zone?.status === 'string' ? zone.status : 'unknown';
          const statusLabel = STATUS_LABELS[statusKey] || statusKey;
          const present = zone?.present === true ? 'Sì' : (zone?.present === false ? 'No' : '—');
          const mode = MODE_LABELS[zone?.measure_mode] || (zone?.measure_mode || '').toUpperCase() || '—';
          const contact = CONTACT_LABELS[zone?.contact] || (zone?.contact || '').toUpperCase() || '—';
          const vz = zone?.vz != null ? `${formatVoltage(zone.vz)} V` : '—';
          const vbias = zone?.vbias != null ? `${formatVoltage(zone.vbias)} V` : '—';
          const rloop = zone?.rloop != null ? `${formatOhms(zone.rloop)} Ω` : '—';
          const boardLabel = zone?.board_label ? escapeHtml(zone.board_label) : (Number(zone?.board) > 0 ? `Nodo ${zone.board}` : 'Centrale');
          const rowClass = `status-${statusKey}`;
          return `<tr class="${rowClass}">
            <td>${id}</td>
            <td>${name}</td>
            <td>${statusLabel}</td>
            <td>${present}</td>
            <td>${mode}</td>
            <td>${contact}</td>
            <td>${vz}</td>
            <td>${vbias}</td>
            <td>${rloop}</td>
            <td>${boardLabel}</td>
          </tr>`;
        }).join('');
      }
    }
  }

  async function refreshDiagnostics(){
    const status = $('#diagStatus');
    if (status) {
      status.textContent = 'Caricamento diagnostica…';
      status.classList.remove('error', 'success');
    }
    try {
      const data = await apiGet('/api/diagnostics/system');
      renderDiagnostics(data);
      if (status) {
        const ts = new Date();
        status.textContent = `Aggiornato alle ${ts.toLocaleTimeString('it-IT')}`;
        status.classList.add('success');
      }
    } catch (err) {
      if (status) {
        status.textContent = `Errore: ${err.message}`;
        status.classList.add('error');
      }
      toast(`Diagnostica: ${err.message}`, false);
    }
  }

  async function loadExpansionNodes(){
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const nodes = await apiGet("/api/can/nodes");
      expansionsState.items = Array.isArray(nodes) ? nodes : [];
      expansionsState.lastScan = Date.now();
    } catch(err){
      expansionsState.items = [];
      expansionsState.error = err?.message || "Impossibile recuperare le schede CAN.";
    }
    expansionsState.loading = false;
    renderExpansionsSection();
    if (expansionsState.error){
      toast(`Nodo CAN: ${expansionsState.error}`, false);
    }
  }

  async function scanExpansionBus(){
    if (expansionsState.loading) return;
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      await apiPost("/api/can/scan", {});
      toast("Scansione CAN avviata");
    } catch(err){
      expansionsState.loading = false;
      expansionsState.error = err?.message || "Impossibile avviare la scansione del bus CAN.";
      renderExpansionsSection();
      toast(`Nodo CAN: ${expansionsState.error}`, false);
      return;
    }
    await loadExpansionNodes();
  }

    async function updateExpansionLabel(nodeId, nextLabel, options = {}){
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      throw new Error("invalid_node");
    }
    const { reset = false } = options;
    let labelPayload = "";
    if (typeof nextLabel === "string") {
      labelPayload = nextLabel.trim();
    }
    if (labelPayload.length > CAN_NODE_LABEL_MAX) {
      labelPayload = labelPayload.slice(0, CAN_NODE_LABEL_MAX);
    }

    try {
      const resp = await apiPost(`/api/can/node/${nodeId}/label`, { label: labelPayload });
      const updatedLabel = (resp && typeof resp.label === "string") ? resp.label : labelPayload;
      if (resp && typeof resp === "object") {
        upsertExpansionNode(resp);
      } else {
        await loadExpansionNodes();
      }
      toast(reset ? "Nome scheda ripristinato" : "Nome scheda aggiornato");
      return { label: updatedLabel, node: resp };
    } catch (err){
      const message = err?.message || "Impossibile aggiornare il nome della scheda.";
      toast(`Nodo CAN: ${message}`, false);
      throw err;
    }
  }

  function openExpansionActions(nodeId){
    const node = getExpansionItems().find((item) => Number(item?.node_id) === nodeId);
    if (!node){
      toast("Nodo non trovato", false);
      return;
    }
    const title = escapeHtml(nodeTitle(node));
    const labelValue = typeof node?.label === "string" ? node.label : "";
    const stateLabel = escapeHtml(formatNodeStateLabel(node));
    const uidDisplay = escapeHtml(formatUid(node?.uid));
    const associationLabel = nodeId === 0 ? "Registrata il" : "Associata il";
    const association = escapeHtml(formatNodeAssociation(node));
    const lastSeen = escapeHtml(formatNodeLastSeen(node));
    const inputsCount = Number.isFinite(Number(node?.inputs_count)) ? Number(node.inputs_count) : "—";
    const outputsCount = Number.isFinite(Number(node?.outputs_count)) ? Number(node.outputs_count) : "—";
    const assignDefault = nodeId > 0 ? nodeId : "";
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Gestisci nodo CAN</h3>
        <button class="btn" id="mClose">Chiudi</button>
      </div>
      <div class="form" style="padding-bottom:.5rem">
        <p class="muted">Dettagli per <strong id="expModalName">${title}</strong>.</p>
        <form id="expLabelForm" class="form" style="margin:1rem 0;">
          <label class="field" style="width:100%;max-width:360px;">
            <span>Nome scheda</span>
            <input id="expLabelInput" type="text" maxlength="${CAN_NODE_LABEL_MAX}" value="${escapeHtml(labelValue)}" placeholder="Nome descrittivo" />
          </label>
          <div class="row" style="gap:.5rem;flex-wrap:wrap;margin-top:.5rem;">
            <button class="btn primary" type="submit">Salva nome</button>
            <button class="btn outline" type="button" id="expLabelResetBtn">Ripristina predefinito</button>
          </div>
          <p class="muted small" style="margin-top:.4rem;">Personalizza il nome visualizzato nelle dashboard.</p>
        </form>
        <div class="meta-grid" style="display:grid;grid-template-columns:160px 1fr;gap:.35rem .75rem;margin-bottom:1rem;">
          <span class="muted">ID nodo</span><span>${escapeHtml(String(nodeId))}</span>
          <span class="muted">UID</span><span>${uidDisplay}</span>
          <span class="muted">Stato</span><span>${stateLabel}</span>
          <span class="muted">Ingressi</span><span>${escapeHtml(String(inputsCount))}</span>
          <span class="muted">Uscite</span><span>${escapeHtml(String(outputsCount))}</span>
          <span class="muted">${associationLabel}</span><span>${association}</span>
          <span class="muted">Ultimo contatto</span><span>${lastSeen}</span>
        </div>
        <div class="row" style="gap:.5rem;flex-wrap:wrap;margin-bottom:1rem;">
          <button class="btn outline" type="button" data-exp-action="offline" data-node-id="${nodeId}">Segna offline</button>
          <button class="btn btn-danger" type="button" data-exp-action="forget" data-node-id="${nodeId}">Dimentica nodo</button>
        </div>
        <form id="expAssignForm" class="form" style="border-top:1px solid var(--border);padding-top:1rem;margin-top:1rem;">
          <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end;">
            <label class="field" style="min-width:160px;max-width:220px;">
              <span>Nuovo ID nodo</span>
              <input id="expAssignInput" type="number" min="1" max="${CAN_MAX_NODE_ID}" value="${assignDefault}" required />
            </label>
            <button class="btn primary" type="submit">Riassegna ID</button>
          </div>
          <p class="muted small" style="margin-top:.4rem;">Assegna questo nodo a un ID specifico, utile quando sostituisci una scheda mantenendo la configurazione.</p>
        </form>
      </div>
    `);
    $("#mClose")?.addEventListener("click", () => closeModal());
    $$("[data-exp-action]").forEach((btn) => {
      btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        const mode = btn.getAttribute("data-exp-action");
        const id = Number(btn.getAttribute("data-node-id"));
        await handleExpansionAction(id, mode);
      });
    });
    const assignForm = $("#expAssignForm");
    if (assignForm){
      const input = assignForm.querySelector("#expAssignInput");
      const submitBtn = assignForm.querySelector('button[type="submit"]');
      assignForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const newId = Number(input?.value);
        if (!Number.isFinite(newId) || newId <= 0 || newId > CAN_MAX_NODE_ID){
          toast(`Inserisci un ID tra 1 e ${CAN_MAX_NODE_ID}`, false);
          return;
        }
        if (submitBtn) submitBtn.disabled = true;
        await assignExpansionNode(nodeId, newId);
        if (submitBtn && document.body.contains(submitBtn)) {
          submitBtn.disabled = false;
        }
      });
    }

    const labelForm = $("#expLabelForm");
    if (labelForm){
      const labelInput = labelForm.querySelector("#expLabelInput");
      const saveBtn = labelForm.querySelector('button[type="submit"]');
      const resetBtn = labelForm.querySelector("#expLabelResetBtn");
      labelForm.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        if (!labelInput) return;
        const raw = String(labelInput.value ?? "");
        const trimmed = raw.trim();
        if (!trimmed){
          toast("Inserisci un nome valido", false);
          return;
        }
        if (saveBtn) saveBtn.disabled = true;
        if (resetBtn) resetBtn.disabled = true;
        try {
          const { label } = await updateExpansionLabel(nodeId, trimmed);
          const finalLabel = (typeof label === "string" && label) ? label : trimmed.slice(0, CAN_NODE_LABEL_MAX);
          if (labelInput) labelInput.value = finalLabel;
          const nameEl = $("#expModalName");
          if (nameEl) nameEl.textContent = finalLabel;
        } catch (_) {
          // errore già mostrato da updateExpansionLabel
        } finally {
          if (saveBtn) saveBtn.disabled = false;
          if (resetBtn) resetBtn.disabled = false;
        }
      });
      if (resetBtn){
        resetBtn.addEventListener("click", async (ev) => {
          ev.preventDefault();
          if (saveBtn) saveBtn.disabled = true;
          resetBtn.disabled = true;
          try {
            const { label } = await updateExpansionLabel(nodeId, "", { reset: true });
            const fallback = (typeof label === "string" && label) ? label : `Exp ${nodeId}`;
            if (labelInput) labelInput.value = fallback;
            const nameEl = $("#expModalName");
            if (nameEl) nameEl.textContent = fallback;
          } catch (_) {
            // errore già notificato
          } finally {
            if (saveBtn) saveBtn.disabled = false;
            resetBtn.disabled = false;
          }
        });
      }
    }
  }

  async function handleExpansionAction(nodeId, mode){
    closeModal();
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      return;
    }
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const query = mode === "forget" ? "?hard=1" : "";
      await apiDelete(`/api/can/nodes/${nodeId}${query}`);
      toast(mode === "forget" ? "Nodo dimenticato" : "Nodo segnato offline");
      await loadExpansionNodes();
    } catch(err){
      expansionsState.loading = false;
      const message = err?.message || "Operazione CAN fallita";
      expansionsState.error = message;
      renderExpansionsSection();
      toast(`Nodo CAN: ${message}`, false);
    }
  }

  async function assignExpansionNode(nodeId, newId){
    if (!Number.isFinite(nodeId) || nodeId <= 0){
      toast("Operazione non valida", false);
      return;
    }
    if (!Number.isFinite(newId) || newId <= 0 || newId > CAN_MAX_NODE_ID){
      toast(`ID valido tra 1 e ${CAN_MAX_NODE_ID}`, false);
      return;
    }
    expansionsState.loading = true;
    expansionsState.error = "";
    renderExpansionsSection();
    try {
      const resp = await apiPost(`/api/can/node/${nodeId}/assign`, { new_id: newId });
      const assignedId = Number.isFinite(Number(resp?.node_id)) ? Number(resp.node_id) : newId;
      toast(`Nodo CAN assegnato all'ID ${assignedId}`);
      closeModal();
      await loadExpansionNodes();
    } catch(err){
      let message = err?.message || "Operazione CAN fallita";
      if (typeof message === "string"){
        const normalized = message.trim().toLowerCase();
        if (normalized === "uid"){
          message = "UID non disponibile. Accendi la scheda o attendi che invii le informazioni.";
        } else if (normalized === "busy"){
          message = "ID già assegnato ad un'altra scheda. Dimentica o riassegna prima quel nodo.";
        } else if (normalized === "can"){
          message = "Errore CAN durante l'invio del comando.";
        }
      }
      expansionsState.loading = false;
      expansionsState.error = message;
      renderExpansionsSection();
      toast(`Nodo CAN: ${message}`, false);
    }
  }

  async function setupAnalogSection(){
    const form = $('#analogConfigForm');
    if (form){
      form.addEventListener('submit', submitAnalogConfig);
    }
    $('#diagRefreshBtn')?.addEventListener('click', () => refreshDiagnostics());
    renderAnalogConfig();
    return loadAnalogConfig();
  }

  async function setupExpansionsSection(){
    const scanBtn = $("#adminExpansionScanBtn");
    if (scanBtn){
      scanBtn.addEventListener("click", () => { scanExpansionBus(); });
    }
    const refreshBtn = $("#adminExpansionRefreshBtn");
    if (refreshBtn){
      refreshBtn.addEventListener("click", () => { loadExpansionNodes(); });
    }
    const list = $("#adminExpansionList");
    if (list){
      list.addEventListener("click", (event) => {
        const telemetryBtn = event.target.closest("[data-node-telemetry]");
        if (telemetryBtn){
          const telemetryId = Number(telemetryBtn.getAttribute("data-node-telemetry"));
          if (!Number.isFinite(telemetryId) || telemetryId <= 0){
            toast("Telemetria disponibile solo per le espansioni", false);
            return;
          }
          event.preventDefault();
          openNodeTelemetry(telemetryId);
          return;
        }
        const actionsBtn = event.target.closest("[data-node-actions]");
        if (!actionsBtn) return;
        const nodeId = Number(actionsBtn.getAttribute("data-node-actions"));
        if (!Number.isFinite(nodeId) || nodeId <= 0){
          toast("Nodo master non modificabile", false);
          return;
        }
        openExpansionActions(nodeId);
      });
    }
    const broadcastOnBtn = $("#canTestBroadcastOnBtn");
    if (broadcastOnBtn){
      broadcastOnBtn.addEventListener("click", () => { sendCanBroadcast(true); });
    }
    const broadcastOffBtn = $("#canTestBroadcastOffBtn");
    if (broadcastOffBtn){
      broadcastOffBtn.addEventListener("click", () => { sendCanBroadcast(false); });
    }
    updateCanTestBroadcastUI();
    renderExpansionsSection();
    await loadExpansionNodes();
  }

  // ========== USERS
  function renderUsers(list){
    const tb = $("#usersTbody");
    if (!tb){ return; }
    tb.innerHTML = "";
    if (!Array.isArray(list)){
      tb.innerHTML = `<tr><td colspan="7" class="muted">Impossibile leggere la lista utenti</td></tr>`;
      return;
    }
    if (list.length === 0){
      tb.innerHTML = `<tr><td colspan="7" class="muted">Nessun utente</td></tr>`;
      return;
    }
    const frag = document.createDocumentFragment();
    for(const u of list){
      const tr = document.createElement("tr");
      const username = (u && typeof u.username === "string") ? u.username : "";
      const firstName = (u && typeof u.first_name === "string") ? u.first_name : "";
      const lastName = (u && typeof u.last_name === "string") ? u.last_name : "";
      const hasPin = !!(u && u.has_pin);
      const hasRfid = !!(u && u.has_rfid);
      const rfidValue = hasRfid ? ((u && typeof u.rfid_uid === "string" && u.rfid_uid) ? u.rfid_uid : "✅") : "—";
      const totpValue = !!(u && u.totp_enabled) ? "✅" : "—";
      const cells = [
        username,
        firstName,
        lastName,
        hasPin ? "✅" : "—",
        rfidValue,
        totpValue
      ];
      for (const value of cells){
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      const actionTd = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = "btn btn-sm";
      btn.dataset.edit = username;
      btn.textContent = "Modifica";
      actionTd.appendChild(btn);
      tr.appendChild(actionTd);
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    tb.querySelectorAll("[data-edit]").forEach(btn => btn.addEventListener("click", () => openEditUser(btn.getAttribute("data-edit"))));
  }

  async function loadUsers(){
    try{
      const list = await apiGet("/api/admin/users");
      if (!Array.isArray(list)) throw new Error("formato inatteso");
      renderUsers(list);
    }catch(e){
      renderUsers(null);
      toast("Errore caricando utenti: " + e.message, false);
    }
  }

  // ---- Modals
  function registerModalCleanup(fn){
    if (typeof fn === "function") {
      modalCleanupHandlers.add(fn);
    }
  }

  function runModalCleanup(){
    if (!modalCleanupHandlers.size) return;
    modalCleanupHandlers.forEach((fn) => {
      try { fn(); } catch (err) { console.warn('modal cleanup', err); }
    });
    modalCleanupHandlers.clear();
  }

  function closeModal(){
    runModalCleanup();
    const root = $("#modals-root");
    if (root) {
      root.innerHTML = "";
    }
  }

  function modal(html){
    const root = $("#modals-root");
    if (!root) return;
    closeModal();
    root.innerHTML = `
      <div class="modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,.45);backdrop-filter:blur(1px);display:grid;place-items:center;z-index:1500">
        <div class="modal card" style="width:min(720px, 96vw);max-height:88vh;overflow:auto">
          ${html}
        </div>
      </div>`;
    const overlay = root.querySelector(".modal-overlay");
    if (overlay){
      const handleClick = (e) => {
        if (e.target.classList.contains("modal-overlay")) {
          closeModal();
        }
      };
      overlay.addEventListener("click", handleClick);
      registerModalCleanup(() => overlay.removeEventListener("click", handleClick));
    }
    function onKey(e){
      if (e.key === "Escape") {
        closeModal();
      }
    }
    window.addEventListener("keydown", onKey);
    registerModalCleanup(() => window.removeEventListener("keydown", onKey));
  }

  function newUserModal(){
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center"><h3>Nuovo utente</h3><button class="btn" id="mClose">Chiudi</button></div>
      <form class="form" id="newUserForm">
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Username</span><input required id="nu_user" type="text" autocomplete="off"></div>          
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Nome</span><input id="nu_fn" type="text"></div>
          <div class="field"><span>Cognome</span><input id="nu_ln" type="text"></div>
        </div>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <div class="field"><span>Password</span><input id="nu_pw" type="password" autocomplete="new-password"></div>
          <div class="field"><span>PIN (Allarme)</span><input id="nu_pin" type="password" pattern="\\d{4,8}" placeholder="4–8 cifre"></div>
        </div>
        <div class="row" style="justify-content:flex-end;margin-top:.6rem">
          <button class="btn" type="submit">Crea</button>
        </div>
      </form>
    `);
    $("#mClose").addEventListener("click", closeModal);
    $("#newUserForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        user: $("#nu_user").value.trim(),
        first_name: $("#nu_fn").value.trim(),
        last_name: $("#nu_ln").value.trim(),
        password: $("#nu_pw").value,
        pin: $("#nu_pin").value
      };
      if (!payload.user){ toast("Username obbligatorio", false); return; }
      try{
        await apiPost("/api/users/create", payload);
        toast("Utente creato");
        closeModal();
        await loadUsers();
      }catch(err){
        toast("Errore creazione utente: " + err.message, false);
      }
    });
  }

  // HOME tab -> torna alla dashboard
  document.addEventListener("click", (e)=>{
    const b = e.target.closest(".tab-btn");
    if (b && b.dataset.tab === 'home') {
      e.preventDefault();
      location.replace("/");
    }
  });

  // async function openEditUser(username){
  //   // Recupera record corrente
  //   let list = [];
  //   try{ list = await apiGet("/api/admin/users"); }catch{}
  //   const rec = list.find(x => x.username === username) || { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };

  //   modal(`
  //     <div class="card-head row" style="justify-content:space-between;align-items:center">
  //       <h3>Modifica utente — <span class="muted">${username}</span></h3>
  //       <button class="btn" id="mClose">Chiudi</button>
  //     </div>
  //     <div class="form">
  //       <div class="row" style="gap:1rem;flex-wrap:wrap">
  //         <div class="field"><span>Nome</span><input id="ed_fn" type="text" value="${(rec.first_name||"").replace(/"/g,'&quot;')}"></div>
  //         <div class="field"><span>Cognome</span><input id="ed_ln" type="text" value="${(rec.last_name||"").replace(/"/g,'&quot;')}"></div>
  //       </div>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
  //         <div class="field" style="min-width:260px">
  //           <span>Tag RFID</span>
  //           <div id="rfidBox">
  //             ${rec.has_rfid ? `<div class="tag">UID: <strong>${rec.rfid_uid||"—"}</strong></div>` : `<div class="muted">Nessun tag associato</div>`}
  //           </div>
  //         </div>
  //         <div class="row" style="gap:.4rem">
  //           <button class="btn" id="btnRfidLearn">Aggiungi</button>
  //           <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid?"":" disabled"}>Rimuovi</button>
  //         </div>
  //         <div class="row" style="margin-left:auto;gap:.4rem">
  //           <button class="btn" id="btnSave">Salva</button>
  //         </div>
  //       </div>
  //       <small class="muted">Nota: l'aggiornamento di Nome/Cognome richiede supporto firmware.</small>
  //       <div class="row" style="gap:1rem;flex-wrap:wrap;margin-top:.6rem">
  //         <div class="field"><span>Nuova password</span><input id="ed_pw1" type="password" autocomplete="new-password"></div>
  //         <div class="field"><span>Conferma</span><input id="ed_pw2" type="password" autocomplete="new-password"></div>
  //         <div class="row" style="align-items:flex-end">
  //           <button class="btn" id="btnSetPw">Aggiorna password</button>
  //         </div>
  //       </div>
  //       <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
  //     </div>
  //   `);
  //   $("#mClose").addEventListener("click", closeModal);

  //   $("#btnSave").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const payload = { user: username, first_name: $("#ed_fn").value.trim(), last_name: $("#ed_ln").value.trim() };
  //     try{
  //       await apiPost("/api/users/name", payload); // se non supportato -> errore gestito
  //       toast("Dati salvati");
  //       closeModal();
  //       await loadUsers();
  //     }catch(err){
  //       toast("Salvataggio Nome/Cognome non supportato dal firmware: " + err.message, false);
  //     }
  //   });

  //   $("#btnSetPw")?.addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const p1 = $("#ed_pw1")?.value || "";
  //     const p2 = $("#ed_pw2")?.value || "";
  //     if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
  //     if (p1 !== p2) { toast("Le password non coincidono", false); return; }
  //     try{
  //       await apiPost("/api/users/password", { user: username, newpass: p1 });
  //       toast("Password aggiornata");
  //       if ($("#ed_pw1")) $("#ed_pw1").value = "";
  //       if ($("#ed_pw2")) $("#ed_pw2").value = "";
  //     }catch(err){
  //       toast("Errore aggiornando la password: " + err.message, false);
  //     }
  //   });

  //   $("#btnRfidClear").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     try{
  //       await apiPost("/api/users/rfid/clear", { user: username });
  //       toast("Tag rimosso");
  //       closeModal(); await loadUsers();
  //     }catch(err){ toast("Errore rimozione tag: "+err.message, false); }
  //   });

  //   $("#btnRfidLearn").addEventListener("click", async (e) => {
  //     e.preventDefault();
  //     const overlay = document.createElement("div");
  //     overlay.className = "modal-overlay";
  //     overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,35);display:grid;place-items:center;z-index:1600";
  //     overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem"><strong>Scansione RFID in corso…</strong><div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div></div>`;
  //     document.body.appendChild(overlay);
  //     try{
  //       const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
  //       toast("Tag associato: " + (res?.uid_hex || "OK"));
  //       closeModal(); await loadUsers();
  //     }catch(err){
  //       toast("RFID: " + err.message, false);
  //     }finally{
  //       overlay.remove();
  //     }
  //   });
  // }

  // Sostituisci integralmente la tua funzione con questa versione
  async function openEditUser(username){
    const esc = (s) => (s ?? "").toString()
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;").replace(/'/g,"&#39;");

    // Prova a recuperare il record dalla lista admin; fallback a valori vuoti
    let rec = { username, first_name:"", last_name:"", has_rfid:false, rfid_uid:"" };
    try {
      const list = await apiGet("/api/admin/users");
      const found = Array.isArray(list) ? list.find(u => u.username === username) : null;
      if (found) rec = { ...rec, ...found };
    } catch {}

    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Modifica utente — <span class="muted">${esc(username)}</span></h3>
        <button class="btn" id="mClose">Chiudi</button>
      </div>

      <div class="form" style="padding-bottom:.5rem">
        <!-- ===== Dati anagrafici ===== -->
        <h4>Dati</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap">
          <label class="field"><span>Nome</span>
            <input id="ed_fn" type="text" value="${esc(rec.first_name)}">
          </label>
          <label class="field"><span>Cognome</span>
            <input id="ed_ln" type="text" value="${esc(rec.last_name)}">
          </label>
          <div class="row" style="align-items:flex-end;margin-left:auto">
            <button class="btn" id="btnSave">Salva</button>
          </div>
        </div>

        <!-- ===== RFID ===== -->
        <h4 style="margin-top:1rem">RFID</h4>
        <div class="row" style="gap:.6rem;align-items:center;flex-wrap:wrap">
          <div id="rfidBox">
            ${
              rec.has_rfid
                ? `<div class="tag">UID: <strong>${esc(rec.rfid_uid || "—")}</strong></div>`
                : `<div class="muted">Nessun tag associato</div>`
            }
          </div>
          <div class="row" style="gap:.4rem">
            <button class="btn" id="btnRfidLearn">Aggiungi</button>
            <button class="btn btn-danger" id="btnRfidClear"${rec.has_rfid ? "" : " disabled"}>Rimuovi</button>
          </div>
        </div>

        <!-- ===== PIN ===== -->
        <h4 style="margin-top:1rem">PIN (Allarme)</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field" style="min-width:240px"><span>Nuovo PIN</span>
            <input id="ed_pin" type="password" inputmode="numeric" pattern="\\d*" maxlength="12" autocomplete="off">
          </label>
          <button class="btn" id="btnSetPin">Aggiorna PIN</button>
        </div>

        <!-- ===== Password ===== -->
        <h4 style="margin-top:1rem">Password</h4>
        <div class="row" style="gap:1rem;flex-wrap:wrap;align-items:flex-end">
          <label class="field"><span>Nuova password</span>
            <input id="ed_pw1" type="password" autocomplete="new-password">
          </label>
          <label class="field"><span>Conferma</span>
            <input id="ed_pw2" type="password" autocomplete="new-password">
          </label>
          <button class="btn" id="btnSetPw">Aggiorna password</button>
        </div>
        <small class="muted">Come amministratore puoi resettare la password di questo utente senza conoscere quella attuale.</small>
      </div>
    `);

    // --- Handlers ---
    $("#mClose")?.addEventListener("click", () => closeModal());

    // Salva Nome/Cognome
    $("#btnSave")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const payload = {
        user: username,
        first_name: $("#ed_fn")?.value?.trim() || "",
        last_name:  $("#ed_ln")?.value?.trim() || ""
      };
      try {
        await apiPost("/api/users/name", payload);
        toast("Dati salvati");
        closeModal(); // se preferisci non chiudere, rimuovi questa riga
        try { await loadUsers(); } catch {}
      } catch(err) {
        toast("Salvataggio Nome/Cognome non supportato o errore: " + err.message, false);
      }
    });

    // Aggiorna PIN
    $("#btnSetPin")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const pin = ($("#ed_pin")?.value || "").trim();
      if (pin.length < 4) { toast("PIN troppo corto (min 4 cifre)", false); return; }
      if (!/^[0-9]{4,12}$/.test(pin)) { toast("PIN deve contenere solo cifre (4–12)", false); return; }
      try {
        await apiPost("/api/users/pin", { user: username, pin });
        toast("PIN aggiornato");
        if ($("#ed_pin")) $("#ed_pin").value = "";
      } catch(err) {
        toast("Errore aggiornando il PIN: " + err.message, false);
      }
    });

    // Aggiorna Password
    $("#btnSetPw")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const p1 = $("#ed_pw1")?.value || "";
      const p2 = $("#ed_pw2")?.value || "";
      if (p1.length < 6) { toast("Password troppo corta (min 6 caratteri)", false); return; }
      if (p1 !== p2) { toast("Le password non coincidono", false); return; }
      try {
        await apiPost("/api/users/password", { user: username, newpass: p1 });
        toast("Password aggiornata");
        if ($("#ed_pw1")) $("#ed_pw1").value = "";
        if ($("#ed_pw2")) $("#ed_pw2").value = "";
      } catch(err) {
        toast("Errore aggiornando la password: " + err.message, false);
      }
    });

    // Rimuovi RFID
    $("#btnRfidClear")?.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        await apiPost("/api/users/rfid/clear", { user: username });
        toast("Tag rimosso");
        closeModal(); await loadUsers();
      } catch(err) {
        toast("Errore rimozione tag: " + err.message, false);
      }
    });

    // Apprendimento RFID
    $("#btnRfidLearn")?.addEventListener("click", async (e) => {
      e.preventDefault();
      const overlay = document.createElement("div");
      overlay.className = "modal-overlay";
      overlay.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,.35);display:grid;place-items:center;z-index:1600";
      overlay.innerHTML = `<div class="card" style="padding:1rem 1.2rem">
          <strong>Scansione RFID in corso…</strong>
          <div class="muted" style="margin-top:.4rem">Avvicina il tag al lettore</div>
        </div>`;
      document.body.appendChild(overlay);
      try{
        const res = await apiPost("/api/users/rfid/learn", { user: username, timeout: 10 });
        toast("Tag associato: " + (res?.uid_hex || "OK"));
        closeModal(); await loadUsers();
      } catch(err) {
        toast("RFID: " + err.message, false);
      } finally {
        overlay.remove();
      }
    });
  }


  function attachNewUser(){
    $("#btnNewUser")?.addEventListener("click", newUserModal);
  }

  const MQTT_PASS_PLACEHOLDER = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";
  const MQTT_REVEAL_TIMEOUT_MS = 30000;
  let mqttRevealTimer = null;

  function getMqttPassField(){ return $("#mq_pass"); }

  function clearMqttRevealTimer(){
    if (mqttRevealTimer){
      clearTimeout(mqttRevealTimer);
      mqttRevealTimer = null;
    }
  }

  function initMqttPasswordField(hasSecret){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "password";
    field.dataset.hasSecret = hasSecret ? "1" : "0";
    field.dataset.userEdited = "0";
    field.dataset.visible = "0";
    if (hasSecret){
      field.value = MQTT_PASS_PLACEHOLDER;
      field.dataset.masked = "1";
    } else {
      field.value = "";
      field.dataset.masked = "0";
    }
    if (!field._mqttBound){
      field.addEventListener("input", () => {
        field.dataset.userEdited = "1";
        field.dataset.hasSecret = field.value ? "1" : "0";
        field.dataset.masked = "0";
        field.dataset.visible = "0";
        field.type = "password";
        clearMqttRevealTimer();
      });
      field.addEventListener("blur", () => {
        if (!field.value){ field.dataset.hasSecret = "0"; }
      });
      field._mqttBound = true;
    }
  }

  function maskMqttPassword(){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "password";
    field.dataset.visible = "0";
    if (field.dataset.userEdited === "1") return;
    if (field.dataset.hasSecret === "1"){
      field.value = MQTT_PASS_PLACEHOLDER;
      field.dataset.masked = "1";
    } else {
      field.value = "";
      field.dataset.masked = "0";
    }
  }

  function revealMqttPassword(secret){
    const field = getMqttPassField();
    if (!field) return;
    clearMqttRevealTimer();
    field.type = "text";
    field.value = secret || "";
    field.dataset.hasSecret = secret ? "1" : "0";
    field.dataset.masked = "0";
    field.dataset.visible = "1";
    field.dataset.userEdited = "0";
    mqttRevealTimer = setTimeout(() => {
      maskMqttPassword();
    }, MQTT_REVEAL_TIMEOUT_MS);
  }

  function ensureMqttRevealButton(){
    const saveBtn = $("#btnMqttSave");
    if (!saveBtn) return;
    let revealBtn = $("#btnMqttReveal");
    if (!revealBtn){
      revealBtn = document.createElement("button");
      revealBtn.type = "button";
      revealBtn.id = "btnMqttReveal";
      revealBtn.className = "btn";
      revealBtn.textContent = "Mostra password";
      revealBtn.style.marginRight = ".5rem";
      saveBtn.parentElement?.insertBefore(revealBtn, saveBtn);
    }
    if (!revealBtn._bound){
      revealBtn.addEventListener("click", openMqttRevealModal);
      revealBtn._bound = true;
    }
  }

  function openMqttRevealModal(){
    modal(`
      <div class="card-head row" style="justify-content:space-between;align-items:center">
        <h3>Mostra password MQTT</h3>
        <button class="btn" id="mqttRevealClose" type="button">Chiudi</button>
      </div>
      <form class="form" id="mqttRevealForm">
        <div class="field"><span>Password amministratore</span><input id="mqttRevealAdminPass" type="password" autocomplete="current-password" required></div>
        <small class="muted">La password verrà mostrata per 30 secondi oppure finché non lasci questa vista.</small>
        <div id="mqttRevealError" class="muted" style="color:#ef4444;margin-top:.4rem;display:none"></div>
        <div class="row" style="justify-content:flex-end;margin-top:.8rem;gap:.5rem">
          <button class="btn" type="submit" id="mqttRevealSubmit">Mostra</button>
        </div>
      </form>
    `);
    $("#mqttRevealClose")?.addEventListener("click", closeModal);
    const form = $("#mqttRevealForm");
    const input = $("#mqttRevealAdminPass");
    const errorEl = $("#mqttRevealError");
    const submitBtn = $("#mqttRevealSubmit");
    input?.focus();
    form?.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!input) return;
      const adminPw = input.value;
      if (!adminPw){
        if (errorEl){ errorEl.textContent = "Inserisci la password amministratore."; errorEl.style.display = "block"; }
        input.focus();
        return;
      }
      if (errorEl) errorEl.style.display = "none";
      if (submitBtn){ submitBtn.disabled = true; submitBtn.textContent = "Verifica…"; }
      try {
        const resp = await apiPost("/api/sys/mqtt/reveal", { password: adminPw }, { skipAuthRedirect: true });
        const secret = resp?.pass ?? "";
        revealMqttPassword(secret);
        const field = getMqttPassField();
        if (field) field.dataset.hasSecret = secret ? "1" : "0";
        closeModal();
        toast("Password MQTT visibile per 30 secondi");
      } catch (err){
        let msg = err?.message || "Errore";
        if (msg.toLowerCase().includes("bad pass")) msg = "Password amministratore non corretta.";
        if (errorEl){ errorEl.textContent = msg; errorEl.style.display = "block"; }
        input.select();
      } finally {
        if (submitBtn){ submitBtn.disabled = false; submitBtn.textContent = "Mostra"; }
      }
    });
  }

  // ========== RETE / MQTT (placeholder salva)
  async function loadNetwork(){
    const updateStaticVisibility = () => {
      const select = $("#net_dhcp");
      const row = $("#net_static");
      if (!row) return;
      const show = (select?.value || "1") === "0";
      row.style.display = show ? "flex" : "none";
    };
    try{
      const c = await apiGet("/api/sys/net");
      $("#net_host") && ($("#net_host").value = c.hostname || "");
      $("#net_dhcp") && ($("#net_dhcp").value = c.dhcp ? "1" : "0");
      updateStaticVisibility();
      $("#net_ip")   && ($("#net_ip").value   = c.ip   || "");
      $("#net_gw")   && ($("#net_gw").value   = c.gw   || "");
      $("#net_mask") && ($("#net_mask").value = c.mask || "");
      $("#net_dns")  && ($("#net_dns").value  = c.dns  || "");
    }catch(e){ toast("Errore caricando rete: " + e.message, false); }
    $("#net_dhcp")?.addEventListener("change", updateStaticVisibility);
    $("#btnNetSave")?.addEventListener("click", async ()=>{
      const body = {
        hostname: $("#net_host")?.value || "",
        dhcp: ($("#net_dhcp")?.value || "1") === "1",
        ip:   $("#net_ip")?.value || "",
        gw:   $("#net_gw")?.value || "",
        mask: $("#net_mask")?.value || "",
        dns:  $("#net_dns")?.value || "",
      };
      try{ await apiPost("/api/sys/net", body); toast("Rete salvata"); }
      catch(e){ toast("Errore salvataggio rete: " + e.message, false); }
    });
  }

  async function loadMqtt(){
    try{
      const c = await apiGet("/api/sys/mqtt");
      $("#mq_uri")  && ($("#mq_uri").value  = c.uri  || "");
      $("#mq_cid")  && ($("#mq_cid").value  = c.cid  || "");
      $("#mq_user") && ($("#mq_user").value = c.user || "");
      const hasSecret = (typeof c.has_pass === "boolean") ? c.has_pass : (typeof c.pass === "string" && c.pass.length > 0);
      initMqttPasswordField(!!hasSecret);
      $("#mq_keep") && ($("#mq_keep").value = (c.keepalive ?? 60));
    }catch(e){ toast("Errore caricando MQTT: " + e.message, false); }
    ensureMqttRevealButton();
    const saveBtn = $("#btnMqttSave");
    if (saveBtn && !saveBtn._mqttBound){
      saveBtn.addEventListener("click", async ()=>{
        const body = {
          uri:  $("#mq_uri")?.value  || "",
          cid:  $("#mq_cid")?.value  || "",
          user: $("#mq_user")?.value || "",
          keepalive: parseInt($("#mq_keep")?.value || "60", 10) || 60,
        };
        const passField = getMqttPassField();
        const passEdited = passField?.dataset.userEdited === "1";
        if (passEdited){
          body.pass = passField?.value ?? "";
        }
        try{
          await apiPost("/api/sys/mqtt", body);
          if (passField){
            if (passEdited){ passField.dataset.hasSecret = body.pass ? "1" : "0"; }
            initMqttPasswordField(passField.dataset.hasSecret === "1");
          }
          toast("MQTT salvato");
        }
        catch(e){ toast("Errore salvataggio MQTT: " + e.message, false); }
      });
      saveBtn._mqttBound = true;
    }
  }

  // ---- Wrapper come da tua init() originale
  async function setupNetMqttForms(){
    await Promise.all([loadNetwork(), loadMqtt()]);
  }

  function renderWebSecStatus(data){
    const box = $("#websecStatus");
    const fb = $("#websecFeedback");
    if (!box) return;
    if (!data){
      box.textContent = "Stato non disponibile";
      if (fb) fb.textContent = "";
      return;
    }
    const activeLabel = data.using_builtin ? "Certificato predefinito incorporato" : "Certificato personalizzato";
    let html = `<div><strong>Attivo:</strong> ${escapeHtml(activeLabel)}</div>`;
    if (data.active_subject) html += `<div class="muted">Soggetto: ${escapeHtml(data.active_subject)}</div>`;
    if (data.active_not_after) html += `<div class="muted">Valido fino al: ${escapeHtml(data.active_not_after)}</div>`;
    if (data.active_fingerprint) html += `<div class="muted">SHA-256: <code>${escapeHtml(data.active_fingerprint)}</code></div>`;
    if (data.custom_available){
      if (data.custom_valid){
        const subj = data.custom_subject ? escapeHtml(data.custom_subject) : "";
        const installed = data.custom_installed_iso ? ` (${escapeHtml(data.custom_installed_iso)})` : "";
        html += `<div class="muted" style="margin-top:.4rem">Ultimo certificato installato: ${subj}${installed}</div>`;
        if (data.custom_not_after) html += `<div class="muted">Scadenza personalizzato: ${escapeHtml(data.custom_not_after)}</div>`;
      } else {
        html += `<div class="muted" style="margin-top:.4rem">Il certificato personalizzato salvato non è valido.</div>`;
      }
    } else {
      html += `<div class="muted" style="margin-top:.4rem">Nessun certificato personalizzato installato.</div>`;
    }
    if (data.restart_pending){
      html += `<div class="muted" style="margin-top:.4rem">Riavvio HTTPS in corso…</div>`;
    }
    box.innerHTML = html;
    if (fb){
      if (data.last_error){
        fb.textContent = `Ultimo errore: ${data.last_error}`;
      } else if (data.restart_pending){
        fb.textContent = "Il server si riavvierà automaticamente per applicare il certificato.";
      } else {
        fb.textContent = "";
      }
    }
  }

  async function loadWebSecStatus(){
    try{
      const data = await apiGet("/api/sys/websec");
      renderWebSecStatus(data);
      return data;
    }catch(err){
      const box = $("#websecStatus");
      if (box) box.textContent = "Errore caricando stato: " + err.message;
      const fb = $("#websecFeedback");
      if (fb) fb.textContent = "";
      throw err;
    }
  }

  async function setupWebSecForm(){
    const btn = $("#btnWebsecUpload");
    if (btn){
      btn.addEventListener("click", async () => {
        const certInput = $("#websecCert");
        const keyInput = $("#websecKey");
        const certFile = certInput?.files?.[0];
        const keyFile = keyInput?.files?.[0];
        if (!certFile || !keyFile){ toast("Seleziona certificato e chiave", false); return; }
        if (certFile.size > WEB_TLS_MAX_PEM_LEN || keyFile.size > WEB_TLS_MAX_PEM_LEN){
          toast("File troppo grandi (max 4 KB)", false);
          return;
        }
        const prevText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Caricamento…";
        const fb = $("#websecFeedback");
        if (fb) fb.textContent = "Caricamento in corso…";
        try{
          const [certB64, keyB64] = await Promise.all([fileToBase64(certFile), fileToBase64(keyFile)]);
          await apiPost("/api/sys/websec", { cert_b64: certB64, key_b64: keyB64 });
          toast("Certificato aggiornato. Riavvio in corso…");
          if (fb) fb.textContent = "Aggiornamento completato, il server HTTPS si riavvierà automaticamente.";
          setTimeout(() => { loadWebSecStatus().catch(()=>{}); }, 1500);
        }catch(err){
          toast("Aggiornamento certificato: " + err.message, false);
          const fb2 = $("#websecFeedback");
          if (fb2) fb2.textContent = "Errore: " + err.message;
        }finally{
          btn.disabled = false;
          btn.textContent = prevText;
          if ($("#websecCert")) $("#websecCert").value = "";
          if ($("#websecKey")) $("#websecKey").value = "";
        }
      });
    }
    try { await loadWebSecStatus(); } catch {}
  }

  // ========== Logout (eventuale)
  $("#btnLogout")?.addEventListener("click", async () => {
    try{ await apiPost("/api/logout"); }catch{}
    needLogin();
  });

  document.addEventListener('DOMContentLoaded', () => {
    const y = document.getElementById('year');
    if (y) y.textContent = new Date().getFullYear();
  });

  // ========== Init
  (async function init(){
    const me = await apiGet("/api/me");
    currentUser = me.user || "";
    const role = normalizeRole(me.role);
    isAdmin = role != null ? role >= ROLE_ADMIN : !!me.is_admin;
    syncHeader();
    mountUserMenu();
    updateAdminVisibility();
    setupSidebar();
    const setupPromises = [
      setupNetMqttForms(),
      setupWebSecForm(),
      setupExpansionsSection(),
      setupAnalogSection(),
    ];
    document.querySelector('[data-tab="home"]')?.addEventListener('click', (e) => {
      e.preventDefault();
      location.href = "/index.html";
    });
    if (!(await ensureAdmin())) return;     // ora è un no-op che sblocca la UI
    attachNewUser();
//    await Promise.all([loadUsers(), loadNetwork(), loadMqtt()]);
    await Promise.all([loadUsers(), ...setupPromises]);
  })();
})();