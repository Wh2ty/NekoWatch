# NekoWatch

SOC-анализатор логов в формате **Wazuh**: принимает поток алертов (реальный
Wazuh или демо-генератор **Logener**), нормализует события, обогащает
**MITRE ATT&CK**, сохраняет в SQLite и отдаёт поиск, аналитику, корреляцию,
triage, экспорт и live-дашборд.

## Быстрый старт

```bash
py -3 -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

| URL | Назначение |
| --- | --- |
| http://127.0.0.1:8000/ | SOC-панель |
| http://127.0.0.1:8000/logener | Управление генератором логов |
| http://127.0.0.1:8000/docs | OpenAPI |

Генератор по умолчанию **выключен** — запускайте на странице `/logener`.

## Источники логов (реальный Wazuh)

Пути задаются в отдельном файле **`config/sources.yaml`** (не в коде).

Поддерживаемые пресеты:

| Имя | Путь | Формат |
| --- | --- | --- |
| `alerts_json` | `/var/ossec/logs/alerts/alerts.json` | NDJSON |
| `alerts_log` | `/var/ossec/logs/alerts/alerts.log` | текст Wazuh |
| `archives_json` | `/var/ossec/logs/archives/archives.json` | NDJSON |
| `logener` | `/tmp/wazuh_logs/wazuh_alerts.json` | NDJSON (демо) |

Пример для продакшен-Wazuh:

```yaml
active:
  - alerts_json
  # при необходимости параллельно:
  # - archives_json
  # - alerts_log

sources:
  alerts_json:
    path: /var/ossec/logs/alerts/alerts.json
    format: ndjson
```

Можно указать несколько `active` сразу — у каждого файла свой checkpoint в БД.
Если `active` пуст или файл конфига отсутствует, используется
`NEKOWATCH_LOG_FILE`.

Переопределение пути к YAML: `NEKOWATCH_SOURCES_CONFIG=...`.

Подробнее: [docs/UI_GUIDE.md](docs/UI_GUIDE.md), план показа комиссии —
[docs/COMMISSION.md](docs/COMMISSION.md), текст презентации —
[docs/PRESENTATION.md](docs/PRESENTATION.md).

## Архитектура

```
Wazuh / Logener ──► file(s) ──► IngestionService ──► SqlAlchemy + SQLite
   sources.yaml        tail/parse      batch + FTS5
                              └──► LiveHub (WebSocket)
                              └──► RuleEngine / StatusMonitor
                              └──► Query / Analytics / Correlation / Triage / Export
```

| Слой | Содержимое |
| --- | --- |
| `config/` | `sources.yaml` — какие файлы слушать |
| `core/` | settings, MITRE, DI-контейнер, загрузка источников |
| `db/` | async SQLAlchemy ORM, WAL SQLite |
| `domain/` | Pydantic-модели алертов, фильтров, ответов API |
| `services/` | parser, ingestion, live, query, analytics, correlation, rules, triage… |
| `repositories/` | протокол хранилища + SQLAlchemy-реализация |
| `routers/` | REST, WebSocket, Jinja2-страницы |
| `templates/` + `static/` | дашборд на русском |

### Ingestion

Один или несколько async-хвостов (`aiofiles`) читают файлы, переживают
ротацию/усечение, парсят NDJSON или `alerts.log`, кладут события в очередь с
backpressure. Writer пишет батчами (`insert` Core + FTS5) и в **той же
транзакции** сохраняет checkpoint offset — после сбоя батч перечитается, а не
теряется.

### Хранилище и `aiosqlite`

Используется **SQLAlchemy 2.0 asyncio** с URL `sqlite+aiosqlite://...`.
Пакет **`aiosqlite` обязателен**: это драйвер async-диалекта SQLite у
SQLAlchemy. Без него async-сессии не работают. Синхронный `sqlite3` здесь не
подходит — заблокировал бы event loop FastAPI при записи/агрегациях.

Оптимизации записи: WAL, `synchronous=NORMAL`, bulk `insert()`, общий
write-lock, checkpoint в одной TX с алертами, индексы по времени/severity/
IP/rule/triage.

## API (кратко)

`GET /api/v1/logs`, `/analytics/dashboard`, `/correlation/*`, `/triage/*`,
`/export`, `WS /api/v1/stream/logs`, `GET /api/v1/ingestion/status`, `/health`.

Общие фильтры: `from`, `to`, `severity`, `min_level`/`max_level`, `rule_id`,
`src_ip`, `user`, `mitre_*`, `triage_status`, `q`, …

## Конфигурация окружения

Префикс `NEKOWATCH_` (см. `.env.example`).

| Переменная | Смысл |
| --- | --- |
| `SOURCES_CONFIG` | Путь к YAML источников |
| `LOG_FILE` | Fallback, если YAML пуст |
| `DATABASE_PATH` | Файл SQLite |
| `INGEST_*` | Очередь, батч, flush, читать с начала |
| `GENERATOR_AUTOSTART` | Автостарт Logener (`false` по умолчанию) |
| `STATUS_*` | Мониторинг источников / ping |

## Тесты

```bash
py -3 -m pytest
```

## Документы для защиты / комиссии

1. [docs/COMMISSION.md](docs/COMMISSION.md) — план показа, типичные вопросы  
2. [docs/UI_GUIDE.md](docs/UI_GUIDE.md) — все элементы интерфейса и метрики  
3. [docs/PRESENTATION.md](docs/PRESENTATION.md) — текст на ~8 минут + глоссарий  
