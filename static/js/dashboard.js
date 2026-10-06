/* NekoWatch dashboard: filters -> API -> Chart.js + live WebSocket feed.
   One filter object drives every request, so charts, table, correlation and
   export always describe the same selection. */
"use strict";

const API = "/api/v1";
const state = { offset: 0, limit: 50, paused: false, selected: new Set(), charts: {} };
const $ = (id) => document.getElementById(id);
const css = (name) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const SEV = { low: css("--low"), medium: css("--medium"), high: css("--high"), critical: css("--critical") };
const SEV_LABEL = {
  low: "Низкий",
  medium: "Средний",
  high: "Высокий",
  critical: "Критический",
};
const TRIAGE_LABEL = {
  new: "Новый",
  in_progress: "В работе",
  resolved: "Закрыт",
  false_positive: "Ложное",
};
const CONF_LABEL = { high: "высокая", medium: "средняя", low: "низкая" };
const labelSev = (s) => SEV_LABEL[s] || s || "—";
const labelTriage = (s) => TRIAGE_LABEL[s] || String(s || "").replaceAll("_", " ") || "—";
const labelConf = (s) => CONF_LABEL[s] || s || "—";

/* ------------------------------------------------------------------ helpers */
function multi(id) {
  return Array.from($(id).selectedOptions).map((o) => o.value).filter(Boolean);
}

/** Collect the current filter UI into URLSearchParams (shared by all calls). */
function filterParams() {
  const p = new URLSearchParams();
  const range = $("f-range").value;
  if (range) p.set("from", new Date(Date.now() - Number(range) * 1000).toISOString());
  if ($("f-q").value.trim()) p.set("q", $("f-q").value.trim());
  multi("f-severity").forEach((v) => p.append("severity", v));
  multi("f-triage").forEach((v) => p.append("triage_status", v));
  if ($("f-technique").value) p.set("mitre_technique", $("f-technique").value);
  if ($("f-tactic").value) p.set("mitre_tactic", $("f-tactic").value);
  if ($("f-rule").value.trim()) p.set("rule_id", $("f-rule").value.trim());
  if ($("f-src").value.trim()) p.set("src_ip", $("f-src").value.trim());
  if ($("f-level-min").value) p.set("min_level", $("f-level-min").value);
  if ($("f-level-max").value) p.set("max_level", $("f-level-max").value);
  return p;
}

async function api(path, params) {
  const res = await fetch(`${API}${path}?${params || ""}`);
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
}

function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2200);
}

const fmt = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString());
const time = (iso) => (iso ? new Date(iso).toLocaleTimeString() : "—");
const stamp = (iso) => (iso ? new Date(iso).toLocaleString() : "—");
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ------------------------------------------------------------------- charts */
Chart.defaults.color = css("--dim");
Chart.defaults.borderColor = css("--border");
Chart.defaults.font.family = '"IBM Plex Sans", "Segoe UI", sans-serif';
Chart.defaults.animation.duration = 300;
Chart.defaults.maintainAspectRatio = false;

/* Charts read SEV/css(...) at render time, but nothing re-rendered them when
 * the theme (and so every CSS color variable) changed — switching from the
 * dark theme to Lemongrass left every chart in the old palette until the
 * next unrelated refresh. Recompute the palette and redraw on
 * "nekowatch-theme-changed" (dispatched by theme.js). */
document.addEventListener("nekowatch-theme-changed", () => {
  SEV.low = css("--low");
  SEV.medium = css("--medium");
  SEV.high = css("--high");
  SEV.critical = css("--critical");
  Chart.defaults.color = css("--dim");
  Chart.defaults.borderColor = css("--border");
  if (typeof renderEpsChart === "function") renderEpsChart();
  if (typeof refresh === "function") refresh();
});

/** Create or update a chart in place (updating avoids canvas flicker). */
function draw(key, canvasId, config) {
  const existing = state.charts[key];
  if (!existing) {
    state.charts[key] = new Chart($(canvasId), config);
    return;
  }
  existing.data = config.data;
  if (config.options) existing.options = { ...existing.options, ...config.options };
  existing.update();
}

const noLegend = { plugins: { legend: { display: false } } };
const barX = {
  ...noLegend,
  indexAxis: "y",
  scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
};

function renderTimeline(tl) {
  const labels = tl.points.map((p) => new Date(p.bucket).toLocaleTimeString());
  draw("timeline", "chart-timeline", {
    type: "bar",
    data: {
      labels,
      datasets: ["low", "medium", "high", "critical"].map((s) => ({
        label: labelSev(s),
        data: tl.points.map((p) => p[s]),
        backgroundColor: SEV[s],
        stack: "sev",
        borderWidth: 0,
      })),
    },
    options: {
      scales: { x: { stacked: true, ticks: { maxTicksLimit: 12 } }, y: { stacked: true, beginAtZero: true } },
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } },
    },
  });
}

function renderSeverity(dist) {
  draw("severity", "chart-severity", {
    type: "doughnut",
    data: {
      labels: dist.items.map((i) => `${labelSev(i.severity)} (${i.percentage}%)`),
      datasets: [{
        data: dist.items.map((i) => i.count),
        backgroundColor: dist.items.map((i) => SEV[i.severity]),
        borderColor: css("--panel"),
        borderWidth: 2,
      }],
    },
    options: { cutout: "58%", plugins: { legend: { position: "bottom", labels: { boxWidth: 10 } } } },
  });
}

function renderRules(rules) {
  draw("rules", "chart-rules", {
    type: "bar",
    data: {
      labels: rules.map((r) => `${r.rule_id} ${(r.description || "").slice(0, 28)}`),
      datasets: [{
        data: rules.map((r) => r.count),
        backgroundColor: rules.map((r) => SEV[r.severity]),
        borderWidth: 0,
      }],
    },
    options: barX,
  });
}

function renderIps(key, canvas, ips) {
  draw(key, canvas, {
    type: "bar",
    data: {
      labels: ips.map((i) => i.ip),
      datasets: [{
        data: ips.map((i) => i.count),
        backgroundColor: ips.map((i) => SEV[i.severity]),
        borderWidth: 0,
      }],
    },
    options: barX,
  });
}

function renderMitre(mitre) {
  draw("mitre", "chart-mitre", {
    type: "bar",
    data: {
      labels: mitre.tactics.map((t) => `${t.id} ${t.name || ""}`),
      datasets: [{ data: mitre.tactics.map((t) => t.count), backgroundColor: css("--accent"), borderWidth: 0 }],
    },
    options: barX,
  });
}

function renderUsers(users, services) {
  draw("users", "chart-users", {
    type: "bar",
    data: {
      labels: users.map((u) => u.key),
      datasets: [
        { label: "пользователь", data: users.map((u) => u.count), backgroundColor: css("--low"), borderWidth: 0 },
      ],
    },
    options: barX,
  });
  const canvas = $("chart-users");
  if (canvas?.parentElement) {
    canvas.parentElement.title = services.map((s) => `${s.key}: ${s.count}`).join(" · ");
  }
}

/* --------------------------------------------------------------- EPS chart
 * X = wall-clock seconds, Y = JSON events accepted that second.
 * Source: WebSocket ``json_arrival`` (emitted before SQL). Never SQL/analytics.
 */
const EPS_MAX_SECONDS = 60;
const EPS_HISTORY_KEY = "nekowatch.eps.history";
/** Map: unix second → count of JSON events that arrived in that second. */
const epsBuckets = new Map();

function formatEpsSecond(epochSec) {
  const d = new Date(Math.floor(Number(epochSec) || 0) * 1000);
  return d.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function loadEpsHistory() {
  try {
    const raw = sessionStorage.getItem(EPS_HISTORY_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    const buckets = data?.buckets;
    if (!buckets || typeof buckets !== "object") {
      // Migrate legacy {labels,values,epochs} → empty (schema changed).
      return;
    }
    epsBuckets.clear();
    for (const [k, v] of Object.entries(buckets)) {
      const sec = Number(k);
      const n = Number(v);
      if (Number.isFinite(sec) && Number.isFinite(n) && n > 0) {
        epsBuckets.set(sec, n);
      }
    }
    pruneEpsBuckets();
  } catch (_) {
    /* ignore corrupt storage */
  }
}

function saveEpsHistory() {
  try {
    const buckets = {};
    for (const [sec, n] of epsBuckets.entries()) {
      buckets[String(sec)] = n;
    }
    sessionStorage.setItem(EPS_HISTORY_KEY, JSON.stringify({ buckets }));
  } catch (_) {
    /* quota / private mode */
  }
}

function pruneEpsBuckets(nowSec = Math.floor(Date.now() / 1000)) {
  const cutoff = nowSec - EPS_MAX_SECONDS + 1;
  for (const sec of [...epsBuckets.keys()]) {
    if (sec < cutoff) epsBuckets.delete(sec);
  }
}

/** Record JSON arrivals into the second bucket (SQL-free path only). */
function noteJsonArrivals(count, epochSec) {
  const n = Math.max(0, Math.round(Number(count) || 0));
  if (n <= 0) return;
  const sec = Math.floor(Number(epochSec) || Date.now() / 1000);
  epsBuckets.set(sec, (epsBuckets.get(sec) || 0) + n);
  pruneEpsBuckets(sec);
  saveEpsHistory();
  renderEpsChart();
  const liveCount = epsBuckets.get(sec) || 0;
  const live = $("eps-live-label");
  if (live) live.textContent = `${liveCount} JSON/с`;
  if ($("stat-eps")) $("stat-eps").textContent = String(liveCount);
}

/** Build a continuous series of the last N seconds (zeros for quiet seconds). */
function epsSeries() {
  const nowSec = Math.floor(Date.now() / 1000);
  pruneEpsBuckets(nowSec);
  const labels = [];
  const values = [];
  const epochs = [];
  for (let i = EPS_MAX_SECONDS - 1; i >= 0; i -= 1) {
    const sec = nowSec - i;
    labels.push(formatEpsSecond(sec));
    values.push(epsBuckets.get(sec) || 0);
    epochs.push(sec);
  }
  return { labels, values, epochs };
}

function renderEpsChart() {
  const canvas = $("chart-eps");
  if (!canvas) return;
  const accent = css("--accent");
  const series = epsSeries();
  draw("eps", "chart-eps", {
    type: "line",
    data: {
      labels: series.labels,
      datasets: [{
        label: "JSON-события / с",
        data: series.values,
        borderColor: accent,
        backgroundColor: "rgba(45, 212, 191, .12)",
        fill: true,
        tension: 0.2,
        pointRadius: 0,
        borderWidth: 2,
      }],
    },
    options: {
      animation: false,
      scales: {
        x: {
          title: {
            display: true,
            text: "Время (секунды)",
            color: css("--muted") || "#888",
          },
          ticks: { maxTicksLimit: 10, maxRotation: 0, autoSkip: true },
          grid: { display: false },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 5,
          title: {
            display: true,
            text: "События (JSON)",
            color: css("--muted") || "#888",
          },
          ticks: { precision: 0, stepSize: 1 },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title(items) {
              const i = items?.[0]?.dataIndex ?? 0;
              return series.epochs[i]
                ? `${formatEpsSecond(series.epochs[i])} (сек)`
                : "";
            },
            label(ctx) {
              return ` ${Math.round(ctx.parsed.y)} JSON-событий`;
            },
          },
        },
      },
    },
  });
}

/* --------------------------------------------------------------------- KPIs */
function renderKpis(ov) {
  const by = Object.fromEntries(ov.severity.map((s) => [s.severity, s.count]));
  $("kpi-total").textContent = fmt(ov.total_events);
  $("kpi-critical").textContent = fmt(by.critical || 0);
  $("kpi-high").textContent = fmt(by.high || 0);
  $("kpi-open").textContent = `${fmt(ov.open_critical)} открытых`;
  $("kpi-ips").textContent = fmt(ov.unique_source_ips);
  $("kpi-users").textContent = fmt(ov.unique_users);
  $("kpi-rules").textContent = fmt(ov.unique_rules);
  $("kpi-mail").textContent = fmt(ov.mail_flagged);
  $("kpi-window").textContent = ov.first_event
    ? `${stamp(ov.first_event)} → ${stamp(ov.last_event)}`
    : "нет событий";
  const chartsMeta = $("charts-meta");
  if (chartsMeta) {
    chartsMeta.textContent = ov.total_events != null
      ? `${fmt(ov.total_events)} событий в выборке`
      : "";
  }
}

/* ------------------------------------------------------------------- tables */
function renderAlerts(page) {
  $("alerts-count").textContent = `${fmt(page.total)} совпадений · ${page.took_ms} мс`;
  const body = $("alerts-body");
  if (!page.items.length) {
    body.innerHTML = '<tr><td colspan="10" class="empty">Нет алертов по этому фильтру.</td></tr>';
    return;
  }
  body.innerHTML = page.items
    .map((r) => `
      <tr data-seq="${r.seq}">
        <td><input type="checkbox" class="chk" value="${r.seq}"></td>
        <td class="mono">${time(r.timestamp)}</td>
        <td class="num">${r.rule_level ?? "—"}</td>
        <td><span class="badge ${r.severity}">${labelSev(r.severity)}</span></td>
        <td class="mono">${esc(r.rule_id)}</td>
        <td class="msg" title="${esc(r.message || r.rule_description)}">${esc(r.rule_description)}</td>
        <td class="mono">${esc(r.src_ip)}</td>
        <td>${esc(r.user_name)}</td>
        <td>${(r.mitre_techniques || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</td>
        <td><span class="badge ${r.triage.status}">${labelTriage(r.triage.status)}</span></td>
      </tr>`)
    .join("");

  body.querySelectorAll("tr").forEach((tr) => {
    tr.addEventListener("click", (event) => {
      if (event.target.classList.contains("chk")) return;
      openDrawer(tr.dataset.seq);
    });
  });
  body.querySelectorAll(".chk").forEach((box) => {
    box.addEventListener("change", () => {
      box.checked ? state.selected.add(box.value) : state.selected.delete(box.value);
      $("triage-hint").textContent = state.selected.size
        ? `выбрано: ${state.selected.size}`
        : "выберите строки";
    });
  });
}

function renderGroups(groups) {
  const body = $("groups-body");
  body.innerHTML = groups.length
    ? groups.map((g) => `
        <tr>
          <td class="mono">${esc(g.signature)}</td>
          <td class="msg">${esc(g.description)}</td>
          <td class="num">${fmt(g.count)}</td>
          <td class="mono">${stamp(g.first_seen)}</td>
          <td class="mono">${stamp(g.last_seen)}</td>
          <td class="num">${fmt(g.duration_seconds)}</td>
          <td class="num">${fmt(g.unique_src_ips)}</td>
          <td class="num">${fmt(g.unique_users)}</td>
        </tr>`).join("")
    : '<tr><td colspan="8" class="empty">Нет повторяющихся событий в этой выборке.</td></tr>';
}

function renderBruteForce(items) {
  $("bf-body").innerHTML = items.length
    ? items.map((i) => `
        <tr title="${fmt(i.attempts)} попыток за ${i.window_seconds}с, пользователей: ${i.unique_users}">
          <td class="mono">${esc(i.src_ip || "—")}</td>
          <td class="num">${fmt(i.attempts)}</td>
          <td><span class="badge ${i.confidence === "high" ? "critical" : "medium"}">${labelConf(i.confidence)}</span></td>
        </tr>`).join("")
    : '<tr><td colspan="3" class="empty">Всплесков не найдено.</td></tr>';
}

/* ------------------------------------------------------------------- drawer */
async function openDrawer(seq) {
  const detail = await api(`/logs/${seq}`, "");
  const r = detail.record;
  $("drawer").innerHTML = `
    <div class="row" style="justify-content:space-between">
      <h3>#${r.seq} · ${esc(r.rule_description)}</h3>
      <button class="sm" id="drawer-close">Закрыть</button>
    </div>
    <div class="row" style="margin:6px 0">
      <span class="badge ${r.severity}">${labelSev(r.severity)}</span>
      <span class="badge ${r.triage.status}">${labelTriage(r.triage.status)}</span>
      ${(r.mitre_techniques || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}
    </div>
    <div class="row">
      ${["in_progress", "resolved", "false_positive"]
        .map((s) => `<button class="sm" data-one="${s}">${labelTriage(s)}</button>`).join("")}
    </div>
    <dl class="kv">
      <dt>Время</dt><dd class="mono">${stamp(r.timestamp)}</dd>
      <dt>Правило / уровень</dt><dd class="mono">${esc(r.rule_id)} · ${r.rule_level}</dd>
      <dt>Группы</dt><dd>${(r.rule_groups || []).map((g) => `<span class="tag">${esc(g)}</span>`).join("")}</dd>
      <dt>Источник → назначение</dt><dd class="mono">${esc(r.src_ip)} → ${esc(r.dst_ip)}</dd>
      <dt>Пользователь / сервис</dt><dd>${esc(r.user_name)} · ${esc(r.service)}</dd>
      <dt>Агент</dt><dd class="mono">${esc(r.agent_name)} (${esc(r.agent_id)}) ${esc(r.agent_ip)}</dd>
      <dt>Отпечаток</dt><dd class="mono">${esc(r.device_fingerprint)}</dd>
      <dt>Расположение</dt><dd class="mono">${esc(r.location)}</dd>
      <dt>Сообщение</dt><dd>${esc(r.message)}</dd>
      ${r.amount ? `<dt>Сумма</dt><dd>${fmt(r.amount)} ${esc(r.currency)} → ${esc(r.recipient)}</dd>` : ""}
      ${r.country ? `<dt>Гео</dt><dd>${esc(r.country)} (было ${esc(r.prev_country)})</dd>` : ""}
    </dl>
    <h2>Документ ECS</h2>
    <pre>${esc(JSON.stringify(detail.ecs, null, 2))}</pre>
    <h2>Исходный алерт Wazuh</h2>
    <pre>${esc(JSON.stringify(detail.payload, null, 2))}</pre>`;

  $("drawer").classList.add("open");
  $("backdrop").classList.add("open");
  $("drawer-close").onclick = closeDrawer;
  $("drawer").querySelectorAll("[data-one]").forEach((btn) => {
    btn.onclick = async () => {
      await triage([seq], btn.dataset.one);
      closeDrawer();
    };
  });
}

function closeDrawer() {
  $("drawer").classList.remove("open");
  $("backdrop").classList.remove("open");
}

/* ------------------------------------------------------------------- triage */
async function triage(seqs, status) {
  const res = await fetch(`${API}/triage/bulk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ seqs: seqs.map(Number), status, analyst: "console" }),
  });
  if (!res.ok) {
    toast("Ошибка смены статуса");
    return;
  }
  const data = await res.json();
  toast(`${data.updated} алерт(ов) → ${labelTriage(status)}`);
  state.selected.clear();
  $("chk-all").checked = false;
  await refresh();
}

/* ------------------------------------------------------------------ refresh */
// setInterval(refresh, 15000) fires on a fixed clock regardless of whether
// the previous call is still in flight. On a slow connection or a big
// result set this stacked overlapping requests indefinitely (and, since
// state.offset/limit are read at call time, each overlapping call could
// render over a newer one's result once it resolved later). refreshing
// guards against that: a tick that lands mid-request is simply skipped.
let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    await refreshOnce();
  } finally {
    refreshing = false;
  }
}

async function refreshOnce() {
  const params = filterParams();
  const interval = $("f-interval").value;

  const dashParams = new URLSearchParams(params);
  dashParams.set("interval", interval);
  const listParams = new URLSearchParams(params);
  listParams.set("limit", state.limit);
  listParams.set("offset", state.offset);
  const groupParams = new URLSearchParams(params);
  groupParams.set("min_count", "2");
  groupParams.set("limit", "25");

  try {
    const [dash, page, groups] = await Promise.all([
      api("/analytics/dashboard", dashParams),
      api("/logs", listParams),
      api("/correlation/groups", groupParams),
    ]);
    renderKpis(dash.overview);
    renderTimeline(dash.timeline);
    renderSeverity(dash.severity);
    renderRules(dash.top_rules);
    renderIps("src", "chart-src", dash.top_source_ips);
    renderIps("dst", "chart-dst", dash.top_destination_ips);
    renderMitre(dash.mitre);
    renderUsers(dash.top_users, dash.top_services);
    renderAlerts(page);
    renderGroups(groups);
  } catch (err) {
    toast(`Ошибка обновления: ${err.message.slice(0, 80)}`);
  }
}

async function detectBruteForce() {
  const params = filterParams();
  params.set("window_seconds", $("bf-window").value || "60");
  params.set("threshold", $("bf-threshold").value || "5");
  renderBruteForce(await api("/correlation/brute-force", params));
}

/* --------------------------------------------------------------- live feed */
// Fixed 3s reconnect meant a backend restart or outage got hammered with a
// reconnect attempt every 3 seconds, indefinitely, from every open tab.
// Back off exponentially (3s, 6s, 12s, ... capped at 30s) and reset to the
// fast 3s delay as soon as a connection actually opens, so a brief blip
// still recovers quickly but a real outage doesn't get DDoS'd by its own
// clients.
let liveReconnectDelay = 3000;
const LIVE_RECONNECT_MAX = 30000;

function scheduleReconnect() {
  const delay = liveReconnectDelay;
  liveReconnectDelay = Math.min(liveReconnectDelay * 2, LIVE_RECONNECT_MAX);
  setTimeout(connectLive, delay);
}

function connectLive() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}${API}/stream/logs`;
  let ws;
  try {
    ws = new WebSocket(url);
  } catch (err) {
    $("live-dot").className = "dot down";
    $("live-text").textContent = "ошибка WS";
    scheduleReconnect();
    return;
  }

  let pingTimer = null;
  const clearPing = () => {
    if (pingTimer) {
      clearInterval(pingTimer);
      pingTimer = null;
    }
  };

  ws.onopen = () => {
    liveReconnectDelay = 3000;
    $("live-dot").className = "dot live";
    $("live-text").textContent = "онлайн";
    clearPing();
    pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify({ action: "ping" })); } catch (_) { /* ignore */ }
      }
    }, 25000);
  };
  ws.onerror = () => {
    $("live-dot").className = "dot down";
    $("live-text").textContent = "ошибка WS";
  };
  ws.onclose = () => {
    clearPing();
    $("live-dot").className = "dot down";
    $("live-text").textContent = "переподключение…";
    scheduleReconnect();
  };
  ws.onmessage = (event) => {
    let frame;
    try {
      frame = JSON.parse(event.data);
    } catch (_) {
      return;
    }
    if (frame.type === "hello") {
      if (frame.message === "subscribed" || frame.message === "pong" || frame.message === "keepalive") {
        $("live-dot").className = "dot live";
        $("live-text").textContent = "онлайн";
      }
      return;
    }
    if (frame.type === "json_arrival" && frame.data) {
      // Y = JSON arrivals (pre-SQL). X bucketed by wall-clock second.
      noteJsonArrivals(frame.data.n, frame.data.epoch);
    } else if (frame.type === "stats" && frame.stats) {
      // Pipeline gauges only — never feed the EPS chart from ingested/stored.
      $("stat-stored").textContent = fmt(frame.stats.stored_events);
      $("stat-queue").textContent = fmt(frame.stats.queue_depth);
      $("stat-errors").textContent = fmt(frame.stats.parse_errors);
      const nowSec = Math.floor(Date.now() / 1000);
      const liveCount = epsBuckets.get(nowSec) || 0;
      $("stat-eps").textContent = String(liveCount);
      const live = $("eps-live-label");
      if (live) live.textContent = `${liveCount} JSON/с`;
    } else if (frame.type === "status_alert" && frame.data) {
      const title = frame.data.title || frame.message || "Статус";
      if (typeof toast === "function") {
        toast(`${frame.data.severity || "alert"}: ${title}`);
      }
      if (typeof refreshStatusBoard === "function") {
        refreshStatusBoard();
      }
    } else if (frame.type === "alert" && frame.alert && !state.paused) {
      pushFeed(frame.alert);
    } else if (frame.type === "error") {
      console.warn("live stream error", frame.message, frame.data);
    } else if (frame.type === "shutdown") {
      $("live-text").textContent = "остановлен";
    }
  };
}

function pushFeed(alert) {
  const feed = $("feed");
  if (feed.firstElementChild?.classList.contains("empty")) feed.innerHTML = "";
  const row = document.createElement("div");
  row.className = `fr ${alert.severity}`;
  row.innerHTML = `<span class="t">${time(alert.timestamp)}</span>
    <span class="b" title="${esc(alert.message)}">
      <b>${alert.rule_level}</b> ${esc(alert.rule_id)} ${esc(alert.src_ip)} — ${esc(alert.rule_description)}
    </span>`;
  row.onclick = () => openDrawer(alert.seq);
  feed.prepend(row);
  while (feed.childElementCount > 200) feed.lastElementChild.remove();
}

/* ----------------------------------------------------------------- wiring */
$("btn-apply").onclick = () => {
  state.offset = 0;
  refresh();
};
$("btn-reset").onclick = () => {
  ["f-q", "f-rule", "f-src", "f-level-min", "f-level-max"].forEach((id) => ($(id).value = ""));
  ["f-severity", "f-triage"].forEach((id) =>
    Array.from($(id).options).forEach((o) => (o.selected = false)));
  $("f-range").value = "";
  $("f-technique").value = "";
  $("f-tactic").value = "";
  state.offset = 0;
  refresh();
};
$("f-interval").onchange = refresh;
$("btn-next").onclick = () => {
  state.offset += state.limit;
  refresh();
};
$("btn-prev").onclick = () => {
  state.offset = Math.max(0, state.offset - state.limit);
  refresh();
};
$("chk-all").onchange = (event) => {
  document.querySelectorAll(".chk").forEach((box) => {
    box.checked = event.target.checked;
    box.checked ? state.selected.add(box.value) : state.selected.delete(box.value);
  });
  $("triage-hint").textContent = state.selected.size
    ? `выбрано: ${state.selected.size}`
    : "выберите строки";
};
document.querySelectorAll("[data-triage]").forEach((btn) => {
  btn.onclick = () => {
    if (!state.selected.size) {
      toast("Выберите хотя бы один алерт");
      return;
    }
    triage(Array.from(state.selected), btn.dataset.triage);
  };
});
document.querySelectorAll("[data-export]").forEach((btn) => {
  btn.onclick = () => {
    const params = filterParams();
    params.set("format", btn.dataset.export);
    if (btn.dataset.export === "jsonl") params.set("ecs", "true");
    window.open(`${API}/export?${params}`, "_blank");
  };
});
$("btn-bf").onclick = detectBruteForce;
$("btn-pause").onclick = (event) => {
  state.paused = !state.paused;
  event.target.textContent = state.paused ? "Продолжить" : "Пауза";
};
$("backdrop").onclick = closeDrawer;
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});


/* ----------------------------------------------------------- GigaChat AI */
async function runGigaChatAnalysis() {
  const panel = $("ai-panel");
  const status = $("ai-status");
  const btn = $("btn-ai-analyze");
  if (!panel || !btn) return;

  const fold = $("fold-ai");
  if (fold?.classList.contains("collapsed")) {
    fold.classList.remove("collapsed");
    const toggle = fold.querySelector(".fold-toggle");
    if (toggle) toggle.setAttribute("aria-expanded", "true");
    localStorage.setItem("nekowatch.fold.ai", "0");
  }
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  status.textContent = "GigaChat анализирует текущую выборку…";
  $("ai-correlation").innerHTML = "";
  $("ai-recs").innerHTML = "";
  $("ai-raw").textContent = "";
  $("ai-meta").textContent = "";
  btn.disabled = true;

  const params = filterParams();
  params.set("limit", "40");
  params.set("offset", "0");
  params.set("timeout", "90");

  try {
    const res = await fetch(`${API}/ai/analyze/selection?${params}`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body);
      throw new Error(detail || `${res.status}`);
    }
    renderAiAnalysis(body);
    status.textContent = body.correlation_analysis?.attack_detected
      ? "Атака / цепочка обнаружена"
      : "Явной атаки не видно (шум / штатная активность)";
    toast("Анализ GigaChat готов");
  } catch (err) {
    const msg = String(err.message || err).slice(0, 240);
    status.textContent = `Ошибка: ${msg}`;
    toast("Ошибка GigaChat");
    if (/GIGACHAT_CREDENTIALS|credentials|503|401/i.test(msg)) {
      alert("GigaChat не настроен.\n\nПоложи ключ в .env:\nGIGACHAT_CREDENTIALS=...\nGIGACHAT_SCOPE=GIGACHAT_API_PERS\n\nи перезапусти uvicorn.");
    }
  } finally {
    btn.disabled = false;
  }
}

function renderAiAnalysis(data) {
  const ca = data.correlation_analysis || {};
  $("ai-meta").textContent = [
    data.model_name || "",
    data.events_analyzed ? `${data.events_analyzed} событий` : "",
    ca.confidence_score != null ? `доверие ${Number(ca.confidence_score).toFixed(2)}` : "",
  ].filter(Boolean).join(" · ");

  const tactics = (ca.mitre_tactics || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ");
  const incidents = (ca.incidents || []).map((inc) => `
    <div class="card" style="margin:8px 0;padding:10px">
      <div class="row" style="gap:8px;margin-bottom:6px">
        <b class="mono">${esc(inc.incident_id)}</b>
        <span class="badge ${(inc.severity || "").toLowerCase()}">${esc(labelSev(String(inc.severity || "").toLowerCase()))}</span>
      </div>
      <div style="margin-bottom:6px">${esc(inc.root_cause)}</div>
      <div class="muted" style="margin-bottom:6px">Активы: ${(inc.affected_assets || []).map(esc).join(", ") || "—"}</div>
      <ol style="margin:0;padding-left:18px">${(inc.attack_chain || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
    </div>`).join("") || '<div class="empty">Нет выделенных инцидентов</div>';

  $("ai-correlation").innerHTML = `
    <p><b>${esc(ca.summary || "")}</b></p>
    <div class="row" style="gap:6px;flex-wrap:wrap;margin:8px 0">${tactics || '<span class="muted">нет тактик</span>'}</div>
    ${incidents}`;

  const recs = (data.infrastructure_recommendations || []).map((r) => `
    <div class="card" style="margin:8px 0;padding:10px">
      <div class="row" style="gap:8px;margin-bottom:6px">
        <b>${esc(r.target)}</b>
        <span class="badge ${r.priority === "IMMEDIATE" ? "critical" : "medium"}">${esc(r.priority)}</span>
        <span class="tag">${esc(r.action_type)}</span>
      </div>
      <div style="margin-bottom:6px">${esc(r.recommendation)}</div>
      <pre style="margin:0;white-space:pre-wrap">${esc(r.commands_or_config || "")}</pre>
    </div>`).join("") || '<div class="empty">Нет рекомендаций</div>';
  $("ai-recs").innerHTML = recs;
  $("ai-raw").textContent = JSON.stringify(data, null, 2);
}

window.runGigaChatAnalysis = runGigaChatAnalysis;
if ($("btn-ai-analyze")) {
  $("btn-ai-analyze").onclick = runGigaChatAnalysis;
}
window.runGigaChatAnalysis = runGigaChatAnalysis;

/* -------------------------------------------------------- collapsible folds */
(function initFolds() {
  const KEY = "nekowatch.fold.";
  document.querySelectorAll(".fold[data-fold]").forEach((fold) => {
    const id = fold.dataset.fold;
    const toggle = fold.querySelector(".fold-toggle");
    if (!toggle) return;
    const stored = localStorage.getItem(KEY + id);
    if (stored === "1") {
      fold.classList.add("collapsed");
      toggle.setAttribute("aria-expanded", "false");
    }
    toggle.addEventListener("click", () => {
      const collapsed = fold.classList.toggle("collapsed");
      toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
      localStorage.setItem(KEY + id, collapsed ? "1" : "0");
      // Charts need a resize pass after becoming visible again.
      if (!collapsed) {
        requestAnimationFrame(() => {
          Object.values(state.charts).forEach((c) => {
            try { c.resize(); } catch (_) { /* ignore */ }
          });
        });
      }
    });
  });
})();

/* -------------------------------------------------- status monitoring board */
const DEMO_KEY = "nekowatch.demo.mode";
const statusState = {
  demo:
    localStorage.getItem(DEMO_KEY) === "1" ||
    localStorage.getItem("nekowatch.dashboard.demo") === "1" ||
    localStorage.getItem("nekowatch.logener.demo") === "1",
  demoExtras: [],
};

function renderSourceCards(sources) {
  const root = $("status-source-cards");
  if (!root) return;
  if (!sources.length) {
    root.innerHTML = statusState.demo
      ? '<div class="muted">В демо нет карточек.</div>'
      : '<div class="muted">Нет источников. Они появятся из событий агентов или через регистрацию.</div>';
    return;
  }
  root.innerHTML = sources.map((s) => {
    const title = esc(s.name || s.agent_id);
    const connDot = s.connection_ok ? "connected" : "disconnected";
    const regDot = s.registration === "own" ? "own" : "foreign";
    const regBadge = s.registration === "own" ? "badge-own" : "badge-foreign";
    const regShort = s.registration === "own" ? "свой" : "чужой";
    const demoBadge = s.is_demo || statusState.demo
      ? '<span class="badge badge-demo">демо</span>'
      : "";
    const age = s.seconds_since_event != null
      ? `${Math.round(s.seconds_since_event)}с назад`
      : "нет событий";
    const claimBtn = s.registration !== "own" && !statusState.demo
      ? `<button type="button" class="sm claim-btn" data-id="${s.id}">Сделать «своим»</button>`
      : "";
    return `
      <article class="status-card ${s.is_demo || statusState.demo ? "demo-card" : ""} ${s.event_status === "problematic" ? "problematic" : ""} ${s.connection_ok ? "" : "offline"}">
        <header>
          <strong>${title}</strong>
          <span class="row" style="gap:4px;align-items:center">
            ${demoBadge}
            <span class="badge ${regBadge}">${regShort}</span>
          </span>
        </header>
        <div class="status-row">
          <span class="status-dot ${connDot}"></span>
          <span>${esc(s.connection_label)}</span>
          <span class="event-pill ${esc(s.event_status)}">${s.event_status === "healthy" ? "события OK" : "проблемный"}</span>
        </div>
        <div class="status-row muted">
          <span class="status-dot ${regDot}"></span>
          <span>${esc(s.registration_label)}</span>
        </div>
        <footer class="muted">agent ${esc(s.agent_id)} · ${esc(s.ip_address || "—")} · ${age}</footer>
        ${claimBtn}
      </article>`;
  }).join("");

  root.querySelectorAll(".claim-btn").forEach((btn) => {
    btn.onclick = async () => {
      try {
        const res = await fetch(`${API}/status/sources/${btn.dataset.id}/claim`, { method: "POST" });
        if (!res.ok) throw new Error(await res.text());
        toast("Устройство зарегистрировано как «свой»");
        refreshStatusBoard();
      } catch (_) {
        toast("Не удалось зарегистрировать");
      }
    };
  });
}

function renderUserCards(users) {
  const root = $("status-user-cards");
  if (!root) return;
  if (!users.length) {
    root.innerHTML = statusState.demo
      ? '<div class="muted">В демо нет пользователей.</div>'
      : '<div class="muted">Нет пользователей LAN.</div>';
    return;
  }
  root.innerHTML = users.map((u) => {
    const title = esc(u.display_name || u.username);
    const connDot = u.connection_ok ? "connected" : "disconnected";
    const regDot = u.registration === "own" ? "own" : "foreign";
    const regBadge = u.registration === "own" ? "badge-own" : "badge-foreign";
    const regShort = u.registration === "own" ? "свой" : "чужой";
    const demoBadge = u.is_demo || statusState.demo
      ? '<span class="badge badge-demo">демо</span>'
      : "";
    const rtt = u.last_rtt_ms != null ? `${Number(u.last_rtt_ms).toFixed(0)} ms` : "—";
    return `
      <article class="status-card ${u.is_demo || statusState.demo ? "demo-card" : ""}">
        <header>
          <strong>${title}</strong>
          <span class="row" style="gap:4px;align-items:center">
            ${demoBadge}
            <span class="badge ${regBadge}">${regShort}</span>
          </span>
        </header>
        <div class="status-row">
          <span class="status-dot ${connDot}"></span>
          <span>${esc(u.connection_label)}</span>
        </div>
        <div class="status-row muted">
          <span class="status-dot ${regDot}"></span>
          <span>${esc(u.registration_label)}</span>
        </div>
        <footer class="muted">${esc(u.username)} · ${esc(u.ip_address)} · RTT ${rtt}</footer>
      </article>`;
  }).join("");
}

function renderStatusNotifications(items) {
  const root = $("status-notifications");
  if (!root) return;
  if (!items.length) {
    root.innerHTML = '<li class="muted">Нет уведомлений</li>';
    return;
  }
  root.innerHTML = items.map((n) => `
    <li class="${esc(n.severity)}">
      <div class="alert-title">${esc(n.title)}</div>
      <div>${esc(n.message)}</div>
      <div class="alert-meta">${esc(n.kind)} · ${stamp(n.created_at)}${n.acknowledged ? " · ack" : ""}</div>
    </li>`).join("");
}

async function refreshStatusBoard() {
  try {
    const params = new URLSearchParams({ demo: statusState.demo ? "true" : "false" });
    const board = await api("/status/board", params);
    if (statusState.demo && statusState.demoExtras.length) {
      board.sources = [...statusState.demoExtras, ...board.sources];
    }
    renderSourceCards(board.sources || []);
    renderUserCards(board.users || []);
    renderStatusNotifications(board.notifications || []);
    const meta = $("status-board-meta");
    if (meta) {
      const mode = board.demo
        ? "ДЕМО · учебный сценарий (не БД)"
        : board.mock
          ? "LIVE · источники из БД (mock-пинг)"
          : "LIVE · источники из БД (ICMP)";
      const counts = `${(board.sources || []).length} источников · ${(board.notifications || []).length} уведомлений`;
      meta.textContent = `${mode} · ${counts} · таймаут ${board.source_timeout_seconds}с · ${stamp(board.generated_at)}`;
    }
  } catch (err) {
    console.warn("status board", err);
    const meta = $("status-board-meta");
    if (meta) meta.textContent = "ошибка загрузки — нажмите «Обновить»";
  }
}

/* demo mode is toggled on /logener; dashboard only reflects the flag */
const demoBanner = $("demo-banner");
function applyDemoChrome() {
  document.body.classList.toggle("demo-on", statusState.demo);
  if (demoBanner) demoBanner.hidden = !statusState.demo;
}
applyDemoChrome();
// Keep shared key in sync if an old key was used.
if (statusState.demo && localStorage.getItem(DEMO_KEY) !== "1") {
  localStorage.setItem(DEMO_KEY, "1");
}

/* register modal */
const registerModal = $("register-modal");
function openRegisterModal() {
  if (!registerModal) return;
  registerModal.hidden = false;
  document.body.classList.add("modal-open");
  $("register-form").agent_id.focus();
}
function closeRegisterModal() {
  if (!registerModal) return;
  registerModal.hidden = true;
  document.body.classList.remove("modal-open");
}
if ($("btn-register-open")) $("btn-register-open").onclick = openRegisterModal;
if ($("btn-register-close")) $("btn-register-close").onclick = closeRegisterModal;
if ($("btn-register-cancel")) $("btn-register-cancel").onclick = closeRegisterModal;
if (registerModal) {
  registerModal.addEventListener("click", (e) => {
    if (e.target === registerModal) closeRegisterModal();
  });
}
if ($("register-form")) {
  $("register-form").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      agent_id: String(fd.get("agent_id") || "").trim(),
      name: String(fd.get("name") || "").trim() || null,
      ip_address: String(fd.get("ip_address") || "").trim(),
      timeout_seconds: Number(fd.get("timeout_seconds") || 60),
      registration: "own",
    };
    if (!payload.agent_id || !payload.ip_address) {
      toast("Укажите Agent ID и IP");
      return;
    }
    if (statusState.demo) {
      const now = new Date().toISOString();
      statusState.demoExtras.unshift({
        id: Date.now(),
        agent_id: payload.agent_id,
        name: payload.name || payload.agent_id,
        ip_address: payload.ip_address,
        registration: "own",
        registration_label: 'Зарегистрирован как "свой"',
        event_status: "healthy",
        network_status: "connected",
        connection_ok: true,
        connection_label: "Подключён",
        last_event_at: now,
        last_ping_at: now,
        seconds_since_event: 0,
        timeout_seconds: payload.timeout_seconds,
        event_count: 0,
        is_demo: true,
      });
      toast("Добавлено в демо-инвентарь");
      closeRegisterModal();
      e.target.reset();
      e.target.timeout_seconds.value = 60;
      refreshStatusBoard();
      return;
    }
    try {
      const res = await fetch(`${API}/status/sources`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(await res.text());
      toast("Устройство зарегистрировано как «свой»");
      closeRegisterModal();
      e.target.reset();
      e.target.timeout_seconds.value = 60;
      refreshStatusBoard();
    } catch (_) {
      toast("Ошибка регистрации");
    }
  };
}

if ($("btn-status-refresh")) {
  $("btn-status-refresh").onclick = () => refreshStatusBoard();
}
if ($("btn-status-ping")) {
  $("btn-status-ping").onclick = async () => {
    if (statusState.demo) {
      toast("В демо пинг симулирован");
      refreshStatusBoard();
      return;
    }
    try {
      await fetch(`${API}/status/ping-now`, { method: "POST" });
      await refreshStatusBoard();
      toast("Пинг выполнен");
    } catch (err) {
      toast("Ошибка пинга");
    }
  };
}

/* ------------------------------------------- custom correlation rules UI */
const rulesState = { catalogue: null, editingId: null };

function fillSelect(select, items, selected) {
  if (!select) return;
  select.innerHTML = (items || [])
    .map(
      (item) =>
        `<option value="${esc(item.value)}"${item.value === selected ? " selected" : ""}>${esc(item.label)}</option>`
    )
    .join("");
}

function applyRulesCatalogue(catalogue) {
  rulesState.catalogue = catalogue || {};
  fillSelect($("rule-field"), rulesState.catalogue.fields, "rule_id");
  fillSelect($("rule-operator"), rulesState.catalogue.operators, "in");
  fillSelect($("rule-group-by"), rulesState.catalogue.group_by, "src_ip");
  fillSelect($("rule-severity"), rulesState.catalogue.severities, "high");
}

function resetRuleForm() {
  rulesState.editingId = null;
  if ($("rule-edit-id")) $("rule-edit-id").value = "";
  if ($("rules-form")) $("rules-form").reset();
  if ($("rule-enabled")) $("rule-enabled").checked = true;
  if ($("rule-window")) $("rule-window").value = 60;
  if ($("rule-threshold")) $("rule-threshold").value = 5;
  if ($("rule-cooldown")) $("rule-cooldown").value = 60;
  if ($("btn-rule-save")) $("btn-rule-save").textContent = "Создать правило";
  if (rulesState.catalogue) applyRulesCatalogue(rulesState.catalogue);
}

function openRulesModal() {
  const modal = $("rules-modal");
  if (!modal) return;
  modal.hidden = false;
  document.body.classList.add("modal-open");
  loadRulesManager();
}

function closeRulesModal() {
  const modal = $("rules-modal");
  if (!modal) return;
  modal.hidden = true;
  document.body.classList.remove("modal-open");
  resetRuleForm();
}

function renderRulesTable(items) {
  const body = $("rules-body");
  const count = $("rules-count");
  if (count) count.textContent = `(${items.length})`;
  if (!body) return;
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty">Правил пока нет — создайте первое.</td></tr>';
    return;
  }
  body.innerHTML = items
    .map((rule) => {
      const condition = `${esc(rule.field)} ${esc(rule.operator)} «${esc(rule.value)}»`;
      return `
        <tr data-id="${rule.id}">
          <td>
            <b>${esc(rule.name)}</b>
            <div class="muted" style="font-size:11px">${esc(rule.description || "")}</div>
          </td>
          <td class="mono" style="font-size:11px">${condition}<br><span class="muted">${esc(rule.group_by)}</span></td>
          <td class="num">${rule.window_seconds}с</td>
          <td class="num">${rule.threshold}</td>
          <td>
            <button type="button" class="sm rule-toggle" data-id="${rule.id}" data-enabled="${rule.enabled ? "1" : "0"}">
              ${rule.enabled ? "вкл" : "выкл"}
            </button>
          </td>
          <td class="row" style="gap:4px">
            <button type="button" class="sm rule-edit" data-id="${rule.id}">изм.</button>
            <button type="button" class="sm danger rule-del" data-id="${rule.id}">×</button>
          </td>
        </tr>`;
    })
    .join("");

  body.querySelectorAll(".rule-toggle").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.dataset.id;
      const enabled = btn.dataset.enabled === "1";
      const path = enabled ? "disable" : "enable";
      const res = await fetch(`${API}/rules/${id}/${path}`, { method: "POST" });
      if (!res.ok) {
        toast("Не удалось переключить правило");
        return;
      }
      toast(enabled ? "Правило выключено" : "Правило включено");
      loadRulesManager();
    };
  });
  body.querySelectorAll(".rule-del").forEach((btn) => {
    btn.onclick = async () => {
      if (!confirm("Удалить это правило?")) return;
      const res = await fetch(`${API}/rules/${btn.dataset.id}`, { method: "DELETE" });
      if (!res.ok && res.status !== 204) {
        toast("Ошибка удаления");
        return;
      }
      toast("Правило удалено");
      resetRuleForm();
      loadRulesManager();
    };
  });
  body.querySelectorAll(".rule-edit").forEach((btn) => {
    btn.onclick = () => {
      const rule = items.find((r) => String(r.id) === String(btn.dataset.id));
      if (!rule) return;
      rulesState.editingId = rule.id;
      $("rule-edit-id").value = rule.id;
      $("rule-name").value = rule.name;
      $("rule-description").value = rule.description || "";
      $("rule-field").value = rule.field;
      $("rule-operator").value = rule.operator;
      $("rule-value").value = rule.value;
      $("rule-window").value = rule.window_seconds;
      $("rule-threshold").value = rule.threshold;
      $("rule-cooldown").value = rule.cooldown_seconds;
      $("rule-group-by").value = rule.group_by;
      $("rule-severity").value = rule.severity;
      $("rule-enabled").checked = !!rule.enabled;
      $("btn-rule-save").textContent = "Сохранить изменения";
    };
  });
}

function renderRuleHits(hits) {
  const root = $("rules-hits");
  if (!root) return;
  if (!hits.length) {
    root.innerHTML = '<li class="muted">Пока нет</li>';
    return;
  }
  root.innerHTML = hits
    .slice(0, 8)
    .map(
      (hit) => `
      <li class="${esc(hit.severity)}">
        <div class="alert-title">${esc(hit.title)}</div>
        <div>${esc(hit.message)}</div>
        <div class="alert-meta">${stamp(hit.fired_at)} · ${hit.match_count} совп.</div>
      </li>`
    )
    .join("");
}

async function loadRulesManager() {
  try {
    const [list, hits] = await Promise.all([
      api("/rules", ""),
      fetch(`${API}/rules/hits`).then((r) => r.json()),
    ]);
    if (!rulesState.catalogue) applyRulesCatalogue(list.catalogue);
    renderRulesTable(list.items || []);
    renderRuleHits(Array.isArray(hits) ? hits : []);
  } catch (err) {
    toast(`Ошибка загрузки правил: ${String(err.message || err).slice(0, 80)}`);
  }
}

if ($("btn-rules-open")) $("btn-rules-open").onclick = openRulesModal;
if ($("btn-rules-close")) $("btn-rules-close").onclick = closeRulesModal;
if ($("rules-modal")) {
  $("rules-modal").addEventListener("click", (e) => {
    if (e.target === $("rules-modal")) closeRulesModal();
  });
}
if ($("btn-rule-reset-form")) $("btn-rule-reset-form").onclick = resetRuleForm;
if ($("rules-form")) {
  $("rules-form").onsubmit = async (e) => {
    e.preventDefault();
    const payload = {
      name: $("rule-name").value.trim(),
      description: $("rule-description").value.trim() || null,
      enabled: $("rule-enabled").checked,
      field: $("rule-field").value,
      operator: $("rule-operator").value,
      value: $("rule-value").value.trim(),
      window_seconds: Number($("rule-window").value || 60),
      threshold: Number($("rule-threshold").value || 5),
      cooldown_seconds: Number($("rule-cooldown").value || 60),
      group_by: $("rule-group-by").value,
      severity: $("rule-severity").value,
    };
    if (!payload.name || !payload.value) {
      toast("Укажите название и значение");
      return;
    }
    const editing = rulesState.editingId;
    const url = editing ? `${API}/rules/${editing}` : `${API}/rules`;
    const method = editing ? "PATCH" : "POST";
    try {
      const res = await fetch(url, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail || body));
      }
      toast(editing ? "Правило обновлено" : "Правило создано");
      resetRuleForm();
      loadRulesManager();
    } catch (err) {
      toast(`Ошибка сохранения: ${String(err.message || err).slice(0, 120)}`);
    }
  };
}

refresh();
refreshStatusBoard();
loadEpsHistory();
renderEpsChart();
connectLive();
// Slide the X axis every second even when idle (zeros for quiet seconds).
// All three intervals used to run at full rate in a backgrounded/minimized
// tab too — three HTTP round-trips every 1/10/15s with nobody watching, on
// every open tab. Skip the work while hidden and catch up with one refresh
// the moment the tab becomes visible again, so the data isn't stale when
// the analyst comes back to it.
setInterval(() => {
  if (document.hidden) return;
  pruneEpsBuckets();
  renderEpsChart();
  const nowSec = Math.floor(Date.now() / 1000);
  const liveCount = epsBuckets.get(nowSec) || 0;
  if ($("stat-eps")) $("stat-eps").textContent = String(liveCount);
  const live = $("eps-live-label");
  if (live) live.textContent = `${liveCount} JSON/с`;
}, 1000);
setInterval(() => {
  if (!document.hidden) refresh();
}, 15000);
setInterval(() => {
  if (!document.hidden) refreshStatusBoard();
}, 10000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    refresh();
    refreshStatusBoard();
  }
});
