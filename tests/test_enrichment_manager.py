from app.enrichment.base import EnrichmentProvider
from app.enrichment.manager import EnrichmentManager
from app.enrichment.mock import MockEnrichmentProvider
from app.enrichment.models import EnrichmentResult
from app.processing.models import Indicator, IndicatorType


class FailingProvider(EnrichmentProvider):
    name = "failing-provider"

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        raise RuntimeError("Provider unavailable")


def test_manager_runs_multiple_providers():
    indicator = Indicator(
        value="malicious.example",
        indicator_type=IndicatorType.DOMAIN,
    )

    manager = EnrichmentManager(
        providers=[
            MockEnrichmentProvider(),
            MockEnrichmentProvider(),
        ]
    )

    results = manager.enrich(indicator)

    assert len(results) == 2
    assert all(result.available for result in results)


def test_manager_handles_provider_failure():
    indicator = Indicator(
        value="malicious.example",
        indicator_type=IndicatorType.DOMAIN,
    )

    manager = EnrichmentManager(
        providers=[
            MockEnrichmentProvider(),
            FailingProvider(),
        ]
    )

    results = manager.enrich(indicator)

    assert len(results) == 2

    assert results[0].available is True

    assert results[1].available is False
    assert results[1].provider == "failing-provider"
    assert "Provider unavailable" in results[1].error
