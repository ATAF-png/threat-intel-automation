import requests
import pytest

from app.collectors.threatfox import fetch_threatfox
from app.processing.models import IndicatorType


def test_threatfox_requires_api_key(monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)

    with pytest.raises(RuntimeError, match="THREATFOX_AUTH_KEY"):
        fetch_threatfox()


def test_threatfox_days_validation(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")

    with pytest.raises(ValueError):
        fetch_threatfox(days=0)

    with pytest.raises(ValueError):
        fetch_threatfox(days=8)


def test_threatfox_parses_iocs(monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")

    payload = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "evil.example.com",
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware_printable": "Example Malware",
                "confidence_level": 95,
                "tags": ["c2", "test"],
            },
            {
                "ioc": "https://evil.example.com/payload",
                "ioc_type": "url",
                "threat_type": "payload_delivery",
                "confidence_level": 80,
                "tags": ["malware"],
            },
            {
                "ioc": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "confidence_level": 90,
                "tags": ["c2"],
            },
            {
                "ioc": "44d88612fea8a8f36de82e1278abb02f",
                "ioc_type": "md5",
                "confidence_level": 70,
            },
            {
                "ioc": "0123456789abcdef0123456789abcdef01234567",
                "ioc_type": "sha1",
                "confidence_level": 75,
            },
            {
                "ioc": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "ioc_type": "sha256",
                "confidence_level": 85,
            },
            {
                "ioc": "ignored@example.com",
                "ioc_type": "email",
            },
        ],
    }

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return payload

    def fake_post(*args, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)

    indicators = fetch_threatfox()

    assert len(indicators) == 6

    types = {indicator.indicator_type for indicator in indicators}

    assert IndicatorType.DOMAIN in types
    assert IndicatorType.URL in types
    assert IndicatorType.IPV4 in types
    assert IndicatorType.MD5 in types
    assert IndicatorType.SHA1 in types
    assert IndicatorType.SHA256 in types

    domain = next(
        indicator
        for indicator in indicators
        if indicator.indicator_type == IndicatorType.DOMAIN
    )

    assert domain.value == "evil.example.com"
    assert domain.confidence == 95
    assert "c2" in domain.tags
    assert "malware:Example Malware" in domain.tags
    assert "threat:botnet_cc" in domain.tags

    ip = next(
        indicator
        for indicator in indicators
        if indicator.indicator_type == IndicatorType.IPV4
    )

    assert ip.value == "1.2.3.4"
    assert ip.confidence == 90
