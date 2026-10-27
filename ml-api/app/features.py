from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

FEATURE_COLUMNS = [
    "rule_level",
    "rule_firedtimes",
    "hour_utc",
    "is_off_hours",
    "agent_is_windows",
    "agent_is_linux",
    "has_source_ip",
    "vt_malicious",
    "misp_hits",
]


def _number(value: Any, *, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if result >= 0 else default


def _hour_utc(alert: dict[str, Any]) -> int:
    timestamp = alert.get("timestamp")
    if isinstance(timestamp, str):
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).hour
        except ValueError:
            pass
    return 12


def alert_features(
    alert: dict[str, Any], enrichment: dict[str, Any] | None = None
) -> dict[str, float]:
    enrichment = enrichment or {}
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    os_info = agent.get("os") or {}
    os_name = str(os_info.get("name", "")).lower()
    agent_name = str(agent.get("name", "")).lower()
    hour = _hour_utc(alert)
    source_ip = (alert.get("data") or {}).get("srcip")

    return {
        "rule_level": min(_number(rule.get("level")), 15.0),
        "rule_firedtimes": min(_number(rule.get("firedtimes"), default=1.0), 1000.0),
        "hour_utc": float(hour),
        "is_off_hours": float(hour < 6 or hour >= 22),
        "agent_is_windows": float("windows" in os_name or "windows" in agent_name),
        "agent_is_linux": float(
            any(token in os_name or token in agent_name for token in ("linux", "ubuntu", "debian"))
        ),
        "has_source_ip": float(bool(source_ip)),
        "vt_malicious": min(_number(enrichment.get("vt_malicious")), 100.0),
        "misp_hits": min(_number(enrichment.get("misp_hits")), 1000.0),
    }


def feature_frame(
    alerts: list[dict[str, Any]],
    enrichments: list[dict[str, Any]] | None = None,
) -> Any:
    import pandas as pd

    enrichments = enrichments or [{} for _ in alerts]
    if len(enrichments) != len(alerts):
        raise ValueError("Le nombre d'enrichissements doit correspondre au nombre d'alertes.")
    rows = [alert_features(alert, enr) for alert, enr in zip(alerts, enrichments)]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS).astype(float)
