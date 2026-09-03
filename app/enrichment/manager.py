from app.enrichment.base import EnrichmentProvider
from app.enrichment.models import EnrichmentResult
from app.processing.models import Indicator


class EnrichmentManager:
    """Run multiple enrichment providers against an indicator."""

    def __init__(
        self,
        providers: list[EnrichmentProvider],
    ):
        self.providers = providers

    def enrich(
        self,
        indicator: Indicator,
    ) -> list[EnrichmentResult]:
        """Run all providers and return their results."""

        results = []

        for provider in self.providers:
            try:
                result = provider.enrich(indicator)

            except Exception as exc:
                result = EnrichmentResult(
                    provider=provider.name,
                    available=False,
                    error=str(exc),
                )

            results.append(result)

        return results
