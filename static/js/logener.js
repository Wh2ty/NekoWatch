/* Logener page: generator controls + demo toggle + destructive full reset. */
"use strict";

const $ = (id) => document.getElementById(id);
const DEMO_KEY = "nekowatch.demo.mode";
const EPS_HISTORY_KEY = "nekowatch.eps.history";
const EPS_MAX_SECONDS = 60;
const FULL_RESET_PHRASE = "УДАЛИТЬ ВСЁ";

/** Keep dashboard JSON-EPS buckets growing while the user is on this page. */
function pushSharedEpsSample(count, epochSec) {
  try {
    const n = Math.max(0, Math.round(Number(count) || 0));
    if (n <= 0) return;
    const sec = Math.floor(Number(epochSec) || Date.now() / 1000);
    let buckets = {};
    const raw = sessionStorage.getItem(EPS_HISTORY_KEY);
    if (raw) {
      const data = JSON.parse(raw);
      if (data?.buckets && typeof data.buckets === "object") {
        buckets = data.buckets;
      }
    }
    buckets[String(sec)] = (Number(buckets[String(sec)]) || 0) + n;
    const cutoff = sec - EPS_MAX_SECONDS + 1;
    for (const key of Object.keys(buckets)) {
      if (Number(key) < cutoff) delete buckets[key];
    }
    sessionStorage.setItem(EPS_HISTORY_KEY, JSON.stringify({ buckets }));
  } catch (_) {
    /* ignore */
  }
}

function toast(text) {
  const el = $("toast");
  el.textContent = text;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 2800);
}

async function call(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail =
      typeof data.detail === "string"
        ? data.detail
        : data.detail
          ? JSON.stringify(data.detail)
          : `HTTP ${res.status}`;
    toast(detail);
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function refresh() {
  try {
    const [gen, ing] = await Promise.all([
      call("/logener/status"),
      call("/api/v1/ingestion/status"),
    ]);
    $("gen-json").textContent = JSON.stringify(gen, null, 2);
    $("ing-json").textContent = JSON.stringify(ing, null, 2);
    $("k-generated").textContent = (gen.generated ?? 0).toLocaleString();
    const recentRate = gen.recent_rate ?? gen.avg_rate ?? 0;
    $("k-rate").textContent = String(Math.round(Number(recentRate) || 0));
    $("k-ingested").textContent = (ing.ingested ?? 0).toLocaleString();
    const ingRate = ing.events_per_second ?? ing.events_last_window ?? 0;
    if ($("k-ing-rate")) {
      $("k-ing-rate").textContent = String(Math.round(Number(ingRate) || 0));
    }
    $("k-stored").textContent = (ing.stored_events ?? 0).toLocaleString();
    $("dot").className = "dot " + (gen.running ? "live" : "down");
    $("state").textContent = gen.running ? "генерация" : "остановлен";
  } catch (_) {
    /* toast already shown */
  }
}

$("btn-start").onclick = async () => {
  try {
    await call("/logener/start?reset=false", { method: "POST" });
    refresh();
  } catch (_) { /* ignore */ }
};
$("btn-stop").onclick = async () => {
  try {
    await call("/logener/stop", { method: "POST" });
    refresh();
  } catch (_) { /* ignore */ }
};
$("btn-refresh").onclick = refresh;

async function runFullReset() {
  if (
    !confirm(
      "Полный сброс удалит ВСЕ данные:\n• SQLite база (алерты, источники, уведомления)\n• JSON/NDJSON файл алертов\n\nПродолжить? (1/3)"
    )
  ) {
    return;
  }
  if (
    !confirm(
      "Это необратимо. Восстановить данные будет нельзя.\n\nТочно продолжить? (2/3)"
    )
  ) {
    return;
  }
  const typed = prompt(
    `Последний шаг (3/3).\nВведите точно:\n\n${FULL_RESET_PHRASE}\n\n(без кавычек, с пробелом и буквой Ё)`,
    ""
  );
  if (typed === null) {
    toast("Сброс отменён");
    return;
  }
  if (typed.trim() !== FULL_RESET_PHRASE) {
    toast("Фраза не совпала — сброс отменён");
    return;
  }
  const btn = $("btn-full-reset");
  if (btn) btn.disabled = true;
  try {
    const result = await call("/logener/full-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: FULL_RESET_PHRASE }),
    });
    toast("Полный сброс выполнен");
    console.info("full-reset", result);
    try {
      sessionStorage.removeItem(EPS_HISTORY_KEY);
    } catch (_) {
      /* ignore */
    }
    await refresh();
  } catch (_) {
    /* toast already shown */
  } finally {
    if (btn) btn.disabled = false;
  }
}

if ($("btn-full-reset")) {
  $("btn-full-reset").onclick = runFullReset;
}

const demoToggle = $("demo-mode");
if (demoToggle) {
  const legacy =
    localStorage.getItem("nekowatch.dashboard.demo") === "1" ||
    localStorage.getItem("nekowatch.logener.demo") === "1";
  if (localStorage.getItem(DEMO_KEY) == null && legacy) {
    localStorage.setItem(DEMO_KEY, "1");
  }
  demoToggle.checked = localStorage.getItem(DEMO_KEY) === "1";
  document.body.classList.toggle("demo-on", demoToggle.checked);
  demoToggle.onchange = () => {
    const on = demoToggle.checked;
    localStorage.setItem(DEMO_KEY, on ? "1" : "0");
    localStorage.removeItem("nekowatch.dashboard.demo");
    localStorage.removeItem("nekowatch.logener.demo");
    document.body.classList.toggle("demo-on", on);
    toast(
      on
        ? "Демо включено — откройте панель"
        : "Демо выключено — панель покажет live"
    );
  };
}

refresh();
setInterval(refresh, 3000);

(function connectJsonEps() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${location.host}/api/v1/stream/logs`;
  let ws;
  try {
    ws = new WebSocket(url);
  } catch (_) {
    setTimeout(connectJsonEps, 3000);
    return;
  }
  ws.onmessage = (event) => {
    let frame;
    try {
      frame = JSON.parse(event.data);
    } catch (_) {
      return;
    }
    if (frame.type === "json_arrival" && frame.data) {
      pushSharedEpsSample(frame.data.n, frame.data.epoch);
    }
  };
  ws.onclose = () => setTimeout(connectJsonEps, 3000);
})();
