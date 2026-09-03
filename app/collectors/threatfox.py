import os
import requests

from app.processing.models import Indicator, IndicatorType
from app.processing.normalize import normalize_indicator


THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox(days: int = 1) -> list[Indicator]:
    """Fetch recent IOCs from ThreatFox."""

    auth_key = os.getenv("THREATFOX_AUTH_KEY")

    if not auth_key:
        raise RuntimeError("THREATFOX_AUTH_KEY is not configured")

    if not 1 <= days <= 7:
        raise ValueError("ThreatFox days must be between 1 and 7")

    response = requests.post(
        THREATFOX_URL,
        headers={"Auth-Key": auth_key},
        json={"query": "get_iocs", "days": days},
        timeout=30,
    )
    response.raise_for_status()

    payload = response.json()

    if payload.get("query_status") != "ok":
        raise RuntimeError(
            f"ThreatFox query failed: {payload.get('query_status')}"
        )

    indicators = []

    for item in payload.get("data") or []:
        value = (item.get("ioc") or "").strip()
        ioc_type = item.get("ioc_type")

        if not value:
            continue

        if ioc_type == "ip:port":
            value = _extract_ip(value)
            if not value:
                continue

        indicator_type = _map_indicator_type(ioc_type, value)

        if indicator_type is None:
            continue

        try:
            indicator = normalize_indicator(
                value=value,
                source="threatfox",
                indicator_type=indicator_type,
            )
        except ValueError:
            continue

        tags = list(item.get("tags") or [])

        malware = item.get("malware_printable")
        if malware:
            tags.append(f"malware:{malware}")

        threat_type = item.get("threat_type")
        if threat_type:
            tags.append(f"threat:{threat_type}")

        indicator.tags = sorted(set(tags))

        try:
            indicator.confidence = int(
                item.get("confidence_level") or 0
            )
        except (TypeError, ValueError):
            indicator.confidence = 0

        indicators.append(indicator)

    return indicators


def _extract_ip(value: str) -> str | None:
    """Extract the IP portion from an ip:port IOC."""

    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]

    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]

    return value


def _map_indicator_type(
    ioc_type: str | None,
    value: str,
) -> IndicatorType | None:
    mapping = {
        "url": IndicatorType.URL,
        "domain": IndicatorType.DOMAIN,
        "md5": IndicatorType.MD5,
        "sha1": IndicatorType.SHA1,
        "sha256": IndicatorType.SHA256,
    }

    if ioc_type in mapping:
        return mapping[ioc_type]

    if ioc_type == "ip:port":
        try:
            return normalize_indicator(
                value=value,
                source="threatfox",
            ).indicator_type
        except ValueError:
            return None

    return None
