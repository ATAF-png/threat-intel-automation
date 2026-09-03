import pytest

from app.processing.models import IndicatorType
from app.processing.normalize import (
    indicator_key,
    normalize_indicator,
)


def test_ipv4_detection():
    indicator = normalize_indicator(
        "192.0.2.10",
        "test-feed",
    )

    assert indicator.indicator_type == IndicatorType.IPV4
    assert indicator.value == "192.0.2.10"


def test_domain_normalization():
    indicator = normalize_indicator(
        "Example.COM",
        "test-feed",
    )

    assert indicator.indicator_type == IndicatorType.DOMAIN
    assert indicator.value == "example.com"


def test_sha256_detection():
    value = "a" * 64

    indicator = normalize_indicator(
        value,
        "test-feed",
    )

    assert indicator.indicator_type == IndicatorType.SHA256


def test_empty_indicator_rejected():
    with pytest.raises(ValueError):
        normalize_indicator(
            "",
            "test-feed",
        )


def test_same_indicator_has_same_key():
    first = normalize_indicator(
        "Example.COM",
        "feed-a",
    )

    second = normalize_indicator(
        "example.com",
        "feed-b",
    )

    assert indicator_key(first) == indicator_key(second)