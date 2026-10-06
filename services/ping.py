"""ICMP reachability probe (async, cross-platform).

Uses the system ``ping`` binary so we avoid raw sockets / admin rights.
When ``mock=True``, returns a deterministic fake result (for demos / CI).
"""

from __future__ import annotations

import asyncio
import hashlib
import platform
import re
import time
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PingResult:
    """Outcome of a single ICMP probe."""

    host: str
    ok: bool
    rtt_ms: float | None = None
    detail: str = ""


_RTT_RE = re.compile(
    r"(?:time[=<]|время[=<]|Average\s*=\s*|Среднее\s*=\s*)(\d+(?:[.,]\d+)?)\s*ms",
    re.IGNORECASE,
)


def _ping_command(host: str, timeout_ms: int) -> list[str]:
    """Build an OS-specific one-shot ping argv."""
    system = platform.system().lower()
    if system == "windows":
        # -n 1: one echo; -w: timeout in milliseconds
        return ["ping", "-n", "1", "-w", str(max(timeout_ms, 200)), host]
    # Linux / macOS: -c 1 one packet; -W timeout in seconds (Linux)
    timeout_s = max(1, (timeout_ms + 999) // 1000)
    return ["ping", "-c", "1", "-W", str(timeout_s), host]


def _parse_rtt(output: str) -> float | None:
    match = _RTT_RE.search(output)
    if not match:
        return None
    raw = match.group(1).replace(",", ".")
    try:
        return float(raw)
    except ValueError:
        return None


def mock_ping(host: str) -> PingResult:
    """Deterministic mock: even hash → connected, odd → disconnected."""
    digest = hashlib.sha256(host.encode("utf-8")).digest()
    ok = digest[0] % 2 == 0 or host.startswith("127.") or host in {
        "192.168.1.10",
        "10.0.0.5",
        "10.0.0.11",
    }
    return PingResult(
        host=host,
        ok=ok,
        rtt_ms=12.0 + (digest[1] % 40) if ok else None,
        detail="mock",
    )


async def ping_host(
    host: str,
    *,
    timeout_ms: int = 1000,
    mock: bool = False,
) -> PingResult:
    """Probe ``host`` once. Never raises — failures become ``ok=False``."""
    if mock or not host:
        return mock_ping(host or "0.0.0.0")

    cmd = _ping_command(host, timeout_ms)
    started = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=(timeout_ms / 1000.0) + 2.0
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return PingResult(host=host, ok=False, detail="timeout")
    except FileNotFoundError:
        return PingResult(host=host, ok=False, detail="ping_binary_missing")
    except OSError as exc:
        return PingResult(host=host, ok=False, detail=str(exc))

    output = (stdout or b"").decode("utf-8", errors="replace")
    ok = proc.returncode == 0
    rtt = _parse_rtt(output)
    if ok and rtt is None:
        rtt = round((time.perf_counter() - started) * 1000.0, 1)
    return PingResult(host=host, ok=ok, rtt_ms=rtt if ok else None, detail="icmp")
