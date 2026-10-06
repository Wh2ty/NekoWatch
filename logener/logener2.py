#!/usr/bin/env python3
"""
Автономный генератор Wazuh-алертов для банковского SOC.
Не требует внешних файлов — все шаблоны встроены.
Скорость: ~4-5 событий/сек (настраивается). Лимит: 3 500 000 событий (настраивается).

Модуль умеет работать в двух режимах:

  1) Как обычный CLI-скрипт (блокирует терминал, Ctrl+C — остановка):
         python -m logener.logener2

  2) Как фоновая служба внутри FastAPI-приложения (см. app.py):
         from logener.logener2 import WazuhGenerator

         generator = WazuhGenerator()
         generator.start()          # неблокирующий запуск в отдельном потоке
         ...
         generator.status()         # {"running": True, "generated": 1234, ...}
         ...
         generator.stop()           # корректная остановка с ожиданием потока
"""

import json
import random
import threading
import time
import os
from datetime import datetime, timezone
from pathlib import Path

# ------------------- КОНФИГ ПО УМОЛЧАНИЮ -------------------
DEFAULT_LIMIT = 3_500_000
DEFAULT_RATE_MIN = 4.0
DEFAULT_RATE_MAX = 5.0

DEFAULT_OUTPUT_FILE = "wazuh_alerts.json"
DEFAULT_OUTPUT_DIR = "/tmp/wazuh_logs"
# -------------------------------------------------------------

# ------------------- ПУЛЫ ДАННЫХ -------------------
USERS = [
    "user_ekaterina", "user_dmitry", "user_olga", "user_maria",
    "user_alexey", "user_ivan", "user_sergey", "user_anna",
    "user_nikolay", "user_elena", "user_andrey", "user_tatiana"
]

IPS_NORMAL = (
    [f"81.200.64.{i}" for i in range(10, 60)] +
    [f"95.79.{random.randint(10,49)}.{random.randint(1,254)}" for _ in range(300)] +
    [f"92.53.124.{i}" for i in range(10, 60)]
)
IPS_SUSPICIOUS = [
    "89.58.32.15", "185.220.101.44", "45.155.205.10",
    "194.87.234.12", "185.225.17.89", "23.106.215.77"
]

def make_fingerprints():
    fps = []
    for name in ["ekaterina", "dmitry", "olga", "maria", "alexey", "ivan",
                 "sergey", "anna", "nikolay", "elena"]:
        for i in range(1, 8):
            fps.append(f"fp_{name}_{i:03d}")
    fps.extend(["fp_moscow_001", "fp_spb_002", "fp_kazan_003",
                "fp_hacker_999", "fp_suspicious_777", "fp_tor_node_404"])
    return fps

FINGERPRINTS = make_fingerprints()

SERVICES = ["user-db", "api-gateway", "auth-service", "payment-service", "otp-service"]

AGENTS = [
    {"id": "001", "name": "bank-core-01",    "ip": "10.10.1.11"},
    {"id": "002", "name": "bank-core-02",    "ip": "10.10.1.12"},
    {"id": "003", "name": "bank-auth-01",    "ip": "10.10.2.21"},
    {"id": "004", "name": "bank-payment-01", "ip": "10.10.3.31"},
    {"id": "005", "name": "bank-gw-01",      "ip": "10.10.4.41"},
    {"id": "006", "name": "bank-otp-01",     "ip": "10.10.5.51"},
]

RECIPIENTS = [
    "ООО Ромашка", "ИП Иванов А.А.", "Анна Смирнова",
    "ПАО Сбербанк", "ООО Техносервис", "МТС", "Ростелеком",
    "Мосэнерго", "МОЭК", "EUROPA_GMBH", "GLOBAL_TRADE_LTD",
    "user_boris", "user_natalia", "user_victor"
]

CURRENCIES = ["RUB", "USD", "EUR", "CNY"]

# ------------------- ШАБЛОНЫ СОБЫТИЙ -------------------
# Вес определяет вероятность выбора типа события
EVENT_TEMPLATES = [
    # --- Обычные операции (большинство) ---
    {"type": "health_check",       "weight": 10, "level": "INFO",
     "msg": "Health check passed"},
    {"type": "session_refresh",    "weight": 8,  "level": "INFO",
     "msg": "Session refreshed"},
    {"type": "logout",             "weight": 6,  "level": "INFO",
     "msg": "User logged out"},
    {"type": "db_pool_ok",         "weight": 10, "level": "INFO",
     "msg": "DB connection pool status: OK"},
    {"type": "cache_refresh",      "weight": 7,  "level": "INFO",
     "msg": "Cache refreshed"},
    {"type": "api_request",        "weight": 12, "level": "INFO",
     "msg": "API request processed"},
    {"type": "balance_inquiry",    "weight": 10, "level": "INFO",
     "msg": "Balance inquiry"},
    {"type": "auth_pwd_success",   "weight": 8,  "level": "INFO",
     "msg": "User authenticated successfully via password"},
    {"type": "auth_otp_success",   "weight": 3,  "level": "INFO",
     "msg": "User authenticated successfully via OTP"},
    {"type": "otp_sent",           "weight": 3,  "level": "INFO",
     "msg": "OTP code sent to {user} via SMS/Push"},
    {"type": "otp_validated",      "weight": 3,  "level": "INFO",
     "msg": "OTP validation successful"},
    {"type": "transfer_small",     "weight": 8,  "level": "INFO",
     "msg": "Transfer completed: {amount} {currency} to {recipient}"},
    {"type": "transfer_medium",    "weight": 4,  "level": "INFO",
     "msg": "Transfer completed: {amount} {currency} to {recipient}"},
    {"type": "utility_payment",    "weight": 6,  "level": "INFO",
     "msg": "Utility payment completed"},
    {"type": "mobile_payment",     "weight": 4,  "level": "INFO",
     "msg": "Mobile payment completed: {amount} {currency}"},
    {"type": "loan_payment",       "weight": 2,  "level": "INFO",
     "msg": "Loan payment completed: {amount} {currency}"},

    # --- Предупреждения ---
    {"type": "auth_fail",          "weight": 3,  "level": "WARN",
     "msg": "Authentication failed: invalid credentials"},
    {"type": "new_device",         "weight": 2,  "level": "WARN",
     "msg": "Login attempt from new device. OTP required"},
    {"type": "rate_limit_warn",    "weight": 2,  "level": "WARN",
     "msg": "Rate limit threshold approaching for API endpoint"},
    {"type": "slow_query",         "weight": 2,  "level": "WARN",
     "msg": "Slow database query detected (>500ms)"},
    {"type": "session_expire",     "weight": 2,  "level": "WARN",
     "msg": "Session expired due to inactivity"},
    {"type": "large_transfer_warn","weight": 1,  "level": "WARN",
     "msg": "Large transfer initiated: {amount} {currency}"},

    # --- Ошибки ---
    {"type": "service_error",      "weight": 2,  "level": "ERROR",
     "msg": "Internal service error: {error_code}"},
    {"type": "db_timeout",         "weight": 1,  "level": "ERROR",
     "msg": "Database connection timeout after 30s"},
    {"type": "payment_fail",       "weight": 1,  "level": "ERROR",
     "msg": "Payment processing failed: {error_code}"},
    {"type": "auth_overload",      "weight": 1,  "level": "ERROR",
     "msg": "Authentication service overloaded"},

    # --- Безопасность (редкие, но важные) ---
    {"type": "balance_anomaly",    "weight": 1,  "level": "ERROR",
     "msg": "ERROR: Balance anomaly detected. Expected {expected}, actual {actual}"},
    {"type": "security_incident",  "weight": 1,  "level": "ERROR",
     "msg": "SECURITY INCIDENT: {incident_type}. Incident ID: {incident_id}"},
    {"type": "brute_force",        "weight": 1,  "level": "ERROR",
     "msg": "Brute force attack detected: {count} failed attempts in {seconds}s"},
    {"type": "geo_anomaly",        "weight": 1,  "level": "ERROR",
     "msg": "Geolocation anomaly: login from {country} after {minutes}min from {prev_country}"},
]

# Веса для выбора уровня (INFO ~75%, WARN ~18%, ERROR ~7%)
LEVEL_WEIGHTS = {"INFO": 75, "WARN": 18, "ERROR": 7}

# Коды ошибок
ERROR_CODES = [
    "ERR_1001", "ERR_1002", "ERR_2003", "ERR_3004", "ERR_4005",
    "TIMEOUT_DB", "TIMEOUT_API", "CONN_REFUSED", "INVALID_TOKEN",
    "PAYMENT_DECLINED", "INSUFFICIENT_FUNDS"
]

INCIDENT_TYPES = [
    "Unauthorized transaction reported",
    "Suspicious login pattern detected",
    "Account takeover attempt",
    "Fraudulent transfer blocked",
    "Credential stuffing detected",
    "Money laundering pattern identified"
]

COUNTRIES = ["Russia", "USA", "Germany", "China", "Nigeria", "Turkey", "Ukraine"]

# Глобальный счётчик инцидентов
_incident_counter = 0
def next_incident_id():
    global _incident_counter
    _incident_counter += 1
    return f"INC-{_incident_counter:04d}"


# ------------------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ -------------------
def pick_service_for_type(etype: str) -> str:
    """Выбирает наиболее подходящий сервис для типа события."""
    mapping = {
        "health_check":    ["user-db", "api-gateway", "auth-service", "otp-service"],
        "session_refresh": ["api-gateway", "auth-service", "user-db", "otp-service"],
        "logout":          ["auth-service", "api-gateway", "user-db", "otp-service"],
        "db_pool_ok":      ["user-db", "api-gateway", "auth-service"],
        "cache_refresh":   ["api-gateway", "user-db", "otp-service"],
        "api_request":     ["api-gateway", "otp-service", "auth-service", "user-db"],
        "balance_inquiry": ["user-db", "api-gateway", "payment-service", "otp-service"],
        "auth_pwd_success":["auth-service", "api-gateway", "otp-service", "user-db"],
        "auth_otp_success":["auth-service", "otp-service"],
        "otp_sent":        ["otp-service"],
        "otp_validated":   ["otp-service", "auth-service"],
        "transfer_small":  ["payment-service"],
        "transfer_medium": ["payment-service"],
        "utility_payment": ["payment-service"],
        "mobile_payment":  ["payment-service"],
        "loan_payment":    ["payment-service"],
        "auth_fail":       ["auth-service", "api-gateway"],
        "new_device":      ["auth-service"],
        "rate_limit_warn": ["api-gateway"],
        "slow_query":      ["user-db"],
        "session_expire":  ["auth-service", "api-gateway"],
        "large_transfer_warn": ["payment-service"],
        "service_error":   SERVICES,
        "db_timeout":      ["user-db"],
        "payment_fail":    ["payment-service"],
        "auth_overload":   ["auth-service"],
        "balance_anomaly": ["payment-service", "api-gateway"],
        "security_incident":["api-gateway", "auth-service"],
        "brute_force":     ["auth-service"],
        "geo_anomaly":     ["auth-service", "api-gateway"],
    }
    return random.choice(mapping.get(etype, SERVICES))


def weighted_choice(items, weight_key="weight"):
    """Взвешенный случайный выбор."""
    total = sum(it[weight_key] for it in items)
    r = random.uniform(0, total)
    acc = 0
    for it in items:
        acc += it[weight_key]
        if r <= acc:
            return it
    return items[-1]


def format_amount(amt: int, currency: str) -> str:
    """Форматирует сумму с разделителями."""
    if currency == "RUB":
        return f"{amt:,}".replace(",", " ")
    return f"{amt:,}"


def generate_amount(etype: str):
    """Генерирует сумму в зависимости от типа транзакции."""
    if etype == "transfer_small":
        return random.randint(100, 49_999)
    if etype == "transfer_medium":
        return random.randint(50_000, 2_000_000)
    if etype == "large_transfer_warn":
        return random.randint(1_000_000, 15_000_000)
    if etype == "utility_payment":
        return random.randint(500, 15_000)
    if etype == "mobile_payment":
        return random.randint(100, 5_000)
    if etype == "loan_payment":
        return random.randint(10_000, 500_000)
    return random.randint(100, 100_000)


def is_suspicious_context() -> bool:
    """1% шанс сгенерировать 'подозрительный' контекст."""
    return random.random() < 0.01


# ------------------- ГЕНЕРАЦИЯ СОБЫТИЯ -------------------
def generate_raw_event() -> dict:
    """Генерирует одно сырое банковское событие."""
    # Иногда (1%) — подозрительный контекст
    suspicious = is_suspicious_context()

    # 1. Выбираем тип события по весам
    tmpl = weighted_choice(EVENT_TEMPLATES)
    etype = tmpl["type"]
    level = tmpl["level"]

    # 2. Пользователь, IP, fingerprint
    user = random.choice(USERS)
    if suspicious:
        ip = random.choice(IPS_SUSPICIOUS)
        fp = random.choice(["fp_hacker_999", "fp_suspicious_777", "fp_tor_node_404"])
    else:
        ip = random.choice(IPS_NORMAL)
        # fingerprint обычно соответствует пользователю, но иногда — нет
        if random.random() < 0.7:
            uname = user.replace("user_", "")
            fp = f"fp_{uname}_{random.randint(1,7):03d}"
        else:
            fp = random.choice(FINGERPRINTS)

    # 3. Сервис
    service = pick_service_for_type(etype)

    # 4. Формируем сообщение с подстановками
    msg = tmpl["msg"]
    amount = None
    currency = None
    extra = {}

    if "{amount}" in msg:
        amount = generate_amount(etype)
        currency = random.choice(CURRENCIES) if etype != "utility_payment" else "RUB"
        msg = msg.replace("{amount}", format_amount(amount, currency))
        msg = msg.replace("{currency}", currency)
        extra["amount"] = amount
        extra["currency"] = currency

    if "{recipient}" in msg:
        recipient = random.choice(RECIPIENTS)
        msg = msg.replace("{recipient}", recipient)
        extra["recipient"] = recipient

    if "{user}" in msg:
        msg = msg.replace("{user}", user)

    if "{error_code}" in msg:
        msg = msg.replace("{error_code}", random.choice(ERROR_CODES))

    if "{incident_type}" in msg:
        msg = msg.replace("{incident_type}", random.choice(INCIDENT_TYPES))
    if "{incident_id}" in msg:
        msg = msg.replace("{incident_id}", next_incident_id())

    if "{count}" in msg:
        count = random.randint(10, 200)
        seconds = random.randint(5, 60)
        msg = msg.replace("{count}", str(count)).replace("{seconds}", str(seconds))
        extra["failed_attempts"] = count
        extra["window_seconds"] = seconds

    if "{country}" in msg:
        c1, c2 = random.sample(COUNTRIES, 2)
        minutes = random.randint(5, 180)
        msg = msg.replace("{country}", c1).replace("{prev_country}", c2).replace("{minutes}", str(minutes))
        extra["country"] = c1
        extra["prev_country"] = c2

    if "{expected}" in msg:
        expected = random.randint(1_000_000, 10_000_000)
        actual = expected - random.randint(100_000, 5_000_000)
        msg = msg.replace("{expected}", f"{expected:,}").replace("{actual}", f"{actual:,}")
        extra["expected_balance"] = expected
        extra["actual_balance"] = actual

    # 5. Timestamp
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    event = {
        "timestamp": ts,
        "service": service,
        "level": level,
        "user_id": user,
        "ip": ip,
        "device_fingerprint": fp,
        "message": msg,
    }
    event.update(extra)
    return event


# ------------------- WAZUH RULES -------------------
RULES = {
    # --- INFO ---
    "health_check":       {"id": "5770", "level": 1,  "desc": "Service health check passed",
                           "groups": ["local","bank","health"]},
    "session_refresh":    {"id": "5721", "level": 1,  "desc": "Session refreshed",
                           "groups": ["local","session","bank"]},
    "logout":             {"id": "5720", "level": 2,  "desc": "User logged out",
                           "groups": ["local","session","bank"]},
    "db_pool_ok":         {"id": "5771", "level": 1,  "desc": "DB connection pool status OK",
                           "groups": ["local","bank","db"]},
    "cache_refresh":      {"id": "5772", "level": 1,  "desc": "Cache refreshed",
                           "groups": ["local","bank","cache"]},
    "api_request":        {"id": "5773", "level": 2,  "desc": "API request processed",
                           "groups": ["local","bank","api"]},
    "balance_inquiry":    {"id": "5730", "level": 2,  "desc": "Balance inquiry",
                           "groups": ["local","bank","inquiry"]},
    "auth_pwd_success":   {"id": "5710", "level": 3,  "desc": "User authenticated successfully via password",
                           "groups": ["local","authentication","bank","success"]},
    "auth_otp_success":   {"id": "5711", "level": 3,  "desc": "User authenticated successfully via OTP",
                           "groups": ["local","authentication","bank","otp","success"]},
    "otp_sent":           {"id": "5760", "level": 2,  "desc": "OTP code sent to user",
                           "groups": ["local","bank","otp"]},
    "otp_validated":      {"id": "5761", "level": 2,  "desc": "OTP validation successful",
                           "groups": ["local","bank","otp"]},
    "transfer_small":     {"id": "5740", "level": 4,  "desc": "Money transfer completed",
                           "groups": ["local","bank","payment","transfer"]},
    "transfer_medium":    {"id": "5741", "level": 6,  "desc": "Medium-value transfer completed",
                           "groups": ["local","bank","payment","transfer","medium_value"]},
    "utility_payment":    {"id": "5745", "level": 3,  "desc": "Utility payment completed",
                           "groups": ["local","bank","payment","utility"]},
    "mobile_payment":     {"id": "5746", "level": 3,  "desc": "Mobile payment completed",
                           "groups": ["local","bank","payment","mobile"]},
    "loan_payment":       {"id": "5747", "level": 4,  "desc": "Loan payment completed",
                           "groups": ["local","bank","payment","loan"]},
    # --- WARN ---
    "auth_fail":          {"id": "5712", "level": 7,  "desc": "Authentication failed",
                           "groups": ["local","authentication","bank","failed"]},
    "new_device":         {"id": "5713", "level": 6,  "desc": "Login from new device, OTP required",
                           "groups": ["local","authentication","bank","new_device"]},
    "rate_limit_warn":    {"id": "5782", "level": 5,  "desc": "API rate limit threshold approaching",
                           "groups": ["local","bank","api","warning"]},
    "slow_query":         {"id": "5783", "level": 5,  "desc": "Slow database query detected",
                           "groups": ["local","bank","db","performance"]},
    "session_expire":     {"id": "5722", "level": 3,  "desc": "Session expired due to inactivity",
                           "groups": ["local","session","bank"]},
    "large_transfer_warn":{"id": "5742", "level": 8,  "desc": "Large transfer initiated",
                           "groups": ["local","bank","payment","transfer","high_value"]},
    # --- ERROR ---
    "service_error":      {"id": "5780", "level": 8,  "desc": "Service error occurred",
                           "groups": ["local","bank","error"]},
    "db_timeout":         {"id": "5784", "level": 9,  "desc": "Database connection timeout",
                           "groups": ["local","bank","db","error","critical"]},
    "payment_fail":       {"id": "5785", "level": 7,  "desc": "Payment processing failed",
                           "groups": ["local","bank","payment","error"]},
    "auth_overload":      {"id": "5786", "level": 9,  "desc": "Authentication service overloaded",
                           "groups": ["local","bank","auth","error","critical"]},
    "balance_anomaly":    {"id": "5750", "level": 12, "desc": "Balance anomaly detected",
                           "groups": ["local","bank","anomaly","critical"]},
    "security_incident":  {"id": "5751", "level": 14, "desc": "SECURITY INCIDENT detected",
                           "groups": ["local","bank","security","incident","critical"]},
    "brute_force":        {"id": "5752", "level": 11, "desc": "Brute force attack detected",
                           "groups": ["local","bank","security","bruteforce"]},
    "geo_anomaly":        {"id": "5753", "level": 10, "desc": "Geolocation anomaly detected",
                           "groups": ["local","bank","security","geo"]},
}


# ------------------- СБОРКА WAZUH-АЛЕРТА -------------------
def build_wazuh_alert(event: dict, agent: dict, alert_id: str) -> dict:
    """Оборачивает событие в полноценный Wazuh-алерт."""
    # Определяем тип события по сообщению
    msg = event.get("message", "")
    etype = _detect_event_type(msg, event)
    rule = RULES.get(etype, RULES["api_request"]).copy()

    # Для крупных переводов повышаем уровень
    if etype == "transfer_medium" and event.get("amount", 0) >= 500_000:
        rule = RULES["large_transfer_warn"].copy()
        rule["desc"] = f"Large transfer: {event['amount']} {event.get('currency','RUB')}"

    full_log = json.dumps(event, ensure_ascii=False)

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "rule": {
            "level": rule["level"],
            "description": rule["desc"],
            "id": rule["id"],
            "firedtimes": random.randint(1, 500),
            "mail": rule["level"] >= 7,
            "groups": rule["groups"],
        },
        "agent": {
            "id": agent["id"],
            "name": agent["name"],
            "ip": agent["ip"],
        },
        "manager": {"name": "wazuh-manager-01"},
        "id": alert_id,
        "full_log": full_log,
        "predecoder": {
            "program_name": event.get("service", "unknown"),
            "timestamp": event.get("timestamp", ""),
            "hostname": agent["name"],
        },
        "decoder": {"name": "bank-json-decoder"},
        "data": {
            "srcip": event.get("ip", "0.0.0.0"),
            "dstip": agent["ip"],
            "user": event.get("user_id", "unknown"),
            "service": event.get("service", "unknown"),
            "level": event.get("level", "INFO"),
            "device_fingerprint": event.get("device_fingerprint", "unknown"),
            "message": event.get("message", ""),
            "amount": event.get("amount"),
            "currency": event.get("currency"),
            "recipient": event.get("recipient"),
        },
        "location": f"/var/log/bank/{event.get('service','unknown')}.log",
    }


def _detect_event_type(msg: str, event: dict) -> str:
    """Определяет тип события по тексту сообщения."""
    m = msg.lower()
    if "security incident" in m:           return "security_incident"
    if "balance anomaly" in m:             return "balance_anomaly"
    if "brute force" in m:                 return "brute_force"
    if "geolocation anomaly" in m:         return "geo_anomaly"
    if "authenticated successfully via otp" in m: return "auth_otp_success"
    if "authenticated successfully" in m:  return "auth_pwd_success"
    if "authentication failed" in m:       return "auth_fail"
    if "new device" in m:                  return "new_device"
    if "logged out" in m:                  return "logout"
    if "session refreshed" in m:           return "session_refresh"
    if "session expired" in m:             return "session_expire"
    if "balance inquiry" in m:             return "balance_inquiry"
    if "transfer completed" in m:
        amt = event.get("amount", 0)
        return "transfer_medium" if amt >= 50_000 else "transfer_small"
    if "large transfer initiated" in m:    return "large_transfer_warn"
    if "utility payment" in m:             return "utility_payment"
    if "mobile payment" in m:              return "mobile_payment"
    if "loan payment" in m:                return "loan_payment"
    if "otp code sent" in m:               return "otp_sent"
    if "otp validation" in m:              return "otp_validated"
    if "health check" in m:                return "health_check"
    if "db connection pool" in m:          return "db_pool_ok"
    if "cache refreshed" in m:             return "cache_refresh"
    if "api request" in m:                 return "api_request"
    if "rate limit" in m:                  return "rate_limit_warn"
    if "slow" in m and "query" in m:       return "slow_query"
    if "database connection timeout" in m: return "db_timeout"
    if "payment processing failed" in m:   return "payment_fail"
    if "overloaded" in m:                  return "auth_overload"
    if "internal service error" in m:      return "service_error"
    return "api_request"
# ------------------- ОСНОВНОЙ ГЕНЕРАТОР -------------------
class WazuhGenerator:
    """
    Генератор синтетических Wazuh-алертов.

    В отличие от исходной версии, генератор больше не блокирует поток,
    в котором его запустили: run()/start() крутит цикл в отдельном
    daemon-потоке, поэтому его можно безопасно поднимать прямо из
    FastAPI lifespan, не замораживая event loop.
    """

    def __init__(
        self,
        output_path=None,
        limit: int = DEFAULT_LIMIT,
        rate_min: float = DEFAULT_RATE_MIN,
        rate_max: float = DEFAULT_RATE_MAX,
    ):
        self.output_path = Path(output_path) if output_path else Path(DEFAULT_OUTPUT_DIR) / DEFAULT_OUTPUT_FILE
        self.limit = limit
        self.rate_min = rate_min
        self.rate_max = rate_max

        self.counter = 0
        self.start_ts = None
        self._recent_times: list[float] = []

        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.output_path.exists():
            self.output_path.touch()

    # ---------- публичное управление ----------
    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, reset: bool = True) -> bool:
        """
        Запускает генерацию в фоновом потоке (не блокирует вызывающий код).
        reset=True — очищает файл и счётчик перед стартом (свежий прогон).
        Возвращает False, если генератор уже запущен.
        """
        with self._lock:
            if self.is_running:
                return False
            if reset:
                self.counter = 0
                self._recent_times.clear()
                open(self.output_path, "w", encoding="utf-8").close()
            self._stop_event.clear()
            self.start_ts = time.time()
            self._recent_times.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="wazuh-generator", daemon=True
            )
            self._thread.start()
            return True

    def stop(self, wait: bool = True, timeout: float = 5.0) -> bool:
        """Сигнализирует остановку и (опционально) дожидается завершения потока."""
        if not self.is_running:
            return False
        self._stop_event.set()
        if wait and self._thread is not None:
            self._thread.join(timeout=timeout)
        return True

    def reset_counters(self) -> None:
        """Zero generation counters without starting/stopping the thread."""
        with self._lock:
            self.counter = 0
            self.start_ts = None
            self._recent_times.clear()

    def status(self) -> dict:
        elapsed = (time.time() - self.start_ts) if self.start_ts else 0.0
        rate = self.counter / elapsed if elapsed > 0 else 0.0
        now = time.time()
        cutoff = now - 1.0
        # Drop timestamps outside the trailing 1-second window.
        self._recent_times = [t for t in self._recent_times if t >= cutoff]
        recent_count = len(self._recent_times)
        # Instantaneous: events written in the last second.
        recent_rate = float(recent_count)
        return {
            "running": self.is_running,
            "generated": self.counter,
            "limit": self.limit,
            "elapsed_seconds": round(elapsed, 1),
            "avg_rate": round(rate, 2),
            "recent_rate": recent_rate,
            "recent_count": recent_count,
            "recent_window_seconds": 1.0,
            "output_path": str(self.output_path),
        }

    def run(self):
        """Блокирующий запуск в текущем потоке — удобно для CLI."""
        self._stop_event.clear()
        self.start_ts = time.time()
        self._run_loop()

    # ---------- внутренняя логика ----------
    def _rate_sleep(self):
        target_rate = random.uniform(self.rate_min, self.rate_max)
        sleep_for = 1.0 / target_rate
        sleep_for *= random.uniform(0.8, 1.2)  # джиттер ±20%
        # ждём через Event, а не time.sleep — так stop() срабатывает мгновенно,
        # а не только между итерациями
        self._stop_event.wait(timeout=max(0.0, sleep_for))

    def _run_loop(self):
        print(f"[*] Генератор Wazuh-алертов запущен")
        print(f"[*] Выход: {self.output_path}")
        print(f"[*] Лимит: {self.limit:,} событий, скорость: {self.rate_min}-{self.rate_max}/сек")

        fh = open(self.output_path, "a", encoding="utf-8")
        try:
            while self.counter < self.limit and not self._stop_event.is_set():
                event = generate_raw_event()
                agent = random.choice(AGENTS)
                alert_id = f"{int(time.time())}.{self.counter:06d}"
                alert = build_wazuh_alert(event, agent, alert_id)
                fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
                self.counter += 1
                self._recent_times.append(time.time())

                if self.counter % 50_000 == 0:
                    elapsed = time.time() - self.start_ts
                    rate = self.counter / elapsed if elapsed > 0 else 0
                    pct = (self.counter / self.limit) * 100
                    print(f"  [progress] {self.counter:>10,} / {self.limit:,} "
                          f"({pct:5.2f}%) | avg {rate:.2f} evt/sec")

                if self.counter % 10 == 0:
                    fh.flush()

                self._rate_sleep()

        finally:
            fh.flush()
            fh.close()
            elapsed = time.time() - self.start_ts if self.start_ts else 0
            avg = self.counter / elapsed if elapsed > 0 else 0
            print(f"\n[✓] Остановлено. Сгенерировано: {self.counter:,} событий "
                  f"за {elapsed:.1f} сек (avg {avg:.2f} evt/sec)")
            try:
                size_mb = os.path.getsize(self.output_path) / 1024 / 1024
                print(f"[✓] Файл: {self.output_path} ({size_mb:.1f} MB)")
            except OSError:
                pass


# ------------------- CLI ENTRYPOINT -------------------
def main():
    """Запуск как отдельного скрипта: python -m logener.logener2"""
    import signal

    gen = WazuhGenerator()

    def _sig_handler(sig, frame):
        print("\n[!] Получен сигнал остановки, завершаю корректно...")
        gen.stop(wait=False)

    # Обработчики сигналов регистрируем только здесь, а не на уровне модуля —
    # иначе при импорте внутри FastAPI/uvicorn они перебивали бы штатное
    # завершение веб-сервера по Ctrl+C.
    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    print("[*] Нажмите Ctrl+C для остановки.\n")
    gen.run()


if __name__ == "__main__":
    main()
