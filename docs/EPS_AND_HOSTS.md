# EPS real-time + host alerting — архитектура

## 1. EPS без SQL

```
JSON line (Wazuh/Logener)
        │  parse
        ▼
IngestionService._enqueue_parsed
        │  EpsMeter.observe()   ← только память
        ▼
bounded queue ──► batch writer ──► SQLite (отдельный путь)
        │
        ▼
live_stats()  ──► LiveHub.broadcast_stats ──► WebSocket ``stats``
        │
        ▼
dashboard.js Chart.js (ось X = время HH:MM:SS, Y = события/с)
```

- Метрика EPS считается в `services/eps_meter.py` (скользящее окно 1 с).
- WebSocket `stats` помечается `eps_sql_free=true`; `stored_events` — редкий кэш, не участвует в EPS.
- История графика переживает навигацию через `sessionStorage`.

## 2. Контроль хостов (production)

```
ingest batch
   → StatusMonitorService.touch_from_records
        ├─ asyncio.Lock + _RuntimeHost (память)
        ├─ StatusRepository.touch_source_event (persist)
        └─ если created & foreign → alert ``foreign_device``

timeout loop (interval)
   → evaluate_timeouts (память last_seen + DB fallback)
        └─ flip problematic → alert ``source_timeout`` (+ cooldown)

ping loop (bounded concurrency)
   → asyncio.gather + Semaphore
        └─ network connected/disconnected (ICMP или mock)
```

Алерты пишутся в `status_notifications` и пушатся в WebSocket как
`type=status_alert` для мгновенного UI.

| kind | Смысл |
| --- | --- |
| `foreign_device` | чужой/незарегистрированный агент |
| `source_timeout` | нет событий дольше timeout |
| `source_recovery` | источник снова шлёт события (опционально) |
