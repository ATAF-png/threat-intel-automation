import hashlib
import ipaddress
from urllib.parse import urlparse

from .models import Indicator, IndicatorType


def detect_indicator_type(value: str) -> IndicatorType:
    value = value.strip()

    # Check for IPv4 or IPv6
    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return IndicatorType.IPV4

        return IndicatorType.IPV6

    except ValueError:
        pass

    # Check for URL
    parsed = urlparse(value)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        return IndicatorType.URL

    # Check for hashes
    if len(value) == 32 and all(
        c in "0123456789abcdefABCDEF" for c in value
    ):
        return IndicatorType.MD5

    if len(value) == 40 and all(
        c in "0123456789abcdefABCDEF" for c in value
    ):
        return IndicatorType.SHA1

    if len(value) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in value
    ):
        return IndicatorType.SHA256

    # Basic domain detection
    if "." in value and " " not in value:
        return IndicatorType.DOMAIN

    raise ValueError(f"Unable to determine IOC type: {value}")


def normalize_value(
    value: str,
    indicator_type: IndicatorType,
) -> str:

    value = value.strip()

    # Domains and hashes are case-insensitive
    if indicator_type in {
        IndicatorType.DOMAIN,
        IndicatorType.MD5,
        IndicatorType.SHA1,
        IndicatorType.SHA256,
    }:
        return value.lower()

    # Normalize URLs
    if indicator_type == IndicatorType.URL:
        parsed = urlparse(value)

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        port = ""

        if parsed.port:
            port = f":{parsed.port}"

        path = parsed.path or ""

        if parsed.query:
            path += f"?{parsed.query}"

        return f"{scheme}://{hostname}{port}{path}"

    return value


def normalize_indicator(
    value: str,
    source: str,
    indicator_type: IndicatorType | None = None,
) -> Indicator:

    value = value.strip()

    if not value:
        raise ValueError("IOC cannot be empty")

    if indicator_type is None:
        indicator_type = detect_indicator_type(value)

    normalized = normalize_value(
        value,
        indicator_type,
    )

    return Indicator(
        value=normalized,
        indicator_type=indicator_type,
        sources=[source],
    )


def indicator_key(indicator: Indicator) -> str:
    """
    Generate a deterministic SHA-256 key.

    The same IOC will produce the same key regardless
    of which feed supplied it.
    """

    raw = f"{indicator.indicator_type}:{indicator.value}"

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()