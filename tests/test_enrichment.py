from app.enrichment.mock import MockEnrichmentProvider
from app.processing.models import Indicator, IndicatorType


def test_mock_enrichment_malicious_indicator():
    provider = MockEnrichmentProvider()

    indicator = Indicator(
        value="malicious.example",
        indicator_type=IndicatorType.DOMAIN,
    )

    result = provider.enrich(indicator)

    assert result.provider == "mock"
    assert result.reputation_score == 95
    assert result.classification == "malicious"
    assert "malware" in result.tags


def test_mock_enrichment_benign_indicator():
    provider = MockEnrichmentProvider()

    indicator = Indicator(
        value="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    result = provider.enrich(indicator)

    assert result.provider == "mock"
    assert result.reputation_score == 5
    assert result.classification == "benign"
