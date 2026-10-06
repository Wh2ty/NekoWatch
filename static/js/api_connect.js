/* Dedicated /api page: connect external alert sources. */
"use strict";

const $ = (id) => document.getElementById(id);
const API_FORM_KEY = "nekowatch.api.connect";

function toast(text) {
  const el = $("toast");
  if (!el) return;
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
    throw err;
  }
  return data;
}

function syncApiTypeFields() {
  const type = $("api-type")?.value || "generic";
  const auth = $("api-wazuh-auth");
  if (auth) auth.hidden = type !== "wazuh";
}

function saveApiForm() {
  try {
    localStorage.setItem(
      API_FORM_KEY,
      JSON.stringify({
        url: $("api-url")?.value || "",
        type: $("api-type")?.value || "generic",
        interval: $("api-interval")?.value || "5",
        user: $("api-user")?.value || "",
      })
    );
  } catch (_) {
    /* ignore */
  }
}

function restoreApiForm() {
  try {
    const raw = localStorage.getItem(API_FORM_KEY);
    if (!raw) return;
    const data = JSON.parse(raw);
    if ($("api-url") && data.url) $("api-url").value = data.url;
    if ($("api-type") && data.type) $("api-type").value = data.type;
    if ($("api-interval") && data.interval) $("api-interval").value = data.interval;
    if ($("api-user") && data.user) $("api-user").value = data.user;
  } catch (_) {
    /* ignore */
  }
  syncApiTypeFields();
}

function renderStatus(api) {
  const pre = $("api-json");
  if (pre) pre.textContent = JSON.stringify(api ?? {}, null, 2);

  const live = (api?.sources || []).find((s) => s.name === "live");
  const connected = Boolean(live?.running);
  const dot = $("api-dot");
  const text = $("api-live-text");
  const status = $("api-connect-status");
  const btnDisc = $("btn-api-disconnect");

  if (dot) dot.className = "dot " + (connected ? "live" : "down");
  if (text) text.textContent = connected ? "подключено" : "не подключено";
  if (btnDisc) btnDisc.disabled = !live;

  if (status) {
    if (!live) {
      status.textContent = "Нет активного подключения.";
    } else {
      const parts = [
        live.url,
        `тип: ${live.type}`,
        `принято: ${live.accepted ?? 0}`,
        `ошибки: ${live.errors ?? 0}`,
      ];
      if (live.last_error) parts.push(`ошибка: ${live.last_error}`);
      status.textContent = parts.join(" · ");
      status.className = "api-status-line" + (live.last_error ? " err" : " ok");
    }
  }

  if (live?.url && $("api-url") && !$("api-url").value) {
    $("api-url").value = live.url;
  }
  if (live?.type && $("api-type")) {
    $("api-type").value = live.type;
    syncApiTypeFields();
  }
}

async function refresh() {
  try {
    const api = await call("/api/v1/ingest/status");
    renderStatus(api);
  } catch (_) {
    /* toast already shown */
  }
}

if ($("api-type")) {
  $("api-type").onchange = syncApiTypeFields;
}

const connectBtn = $("btn-api-connect");
if (connectBtn) {
  connectBtn.onclick = async () => {
    const url = ($("api-url")?.value || "").trim();
    if (!url) {
      toast("Введите URL API");
      $("api-url")?.focus();
      return;
    }
    connectBtn.disabled = true;
    saveApiForm();
    try {
      const st = await call("/api/v1/ingest/connect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          type: $("api-type")?.value || "generic",
          token: $("api-token")?.value || "",
          username: $("api-user")?.value || "",
          password: $("api-pass")?.value || "",
          poll_interval: Number($("api-interval")?.value || 5),
          verify_ssl: false,
          name: "live",
        }),
      });
      toast(
        st.last_error
          ? `Подключено, ошибка опроса: ${st.last_error}`
          : `Подключено · принято ${st.accepted ?? 0}`
      );
      await refresh();
    } catch (_) {
      /* toast already shown */
    } finally {
      connectBtn.disabled = false;
    }
  };
}

const disconnectBtn = $("btn-api-disconnect");
if (disconnectBtn) {
  disconnectBtn.onclick = async () => {
    disconnectBtn.disabled = true;
    try {
      await call("/api/v1/ingest/disconnect?name=live", { method: "POST" });
      toast("API отключено");
      await refresh();
    } catch (_) {
      /* toast already shown */
    }
  };
}

if ($("btn-api-refresh")) {
  $("btn-api-refresh").onclick = refresh;
}

restoreApiForm();
refresh();
setInterval(refresh, 3000);
