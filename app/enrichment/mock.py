from app.enrichment.base import EnrichmentProvider
from app.enrichment.models import EnrichmentResult
from app.processing.models import Indicator


class MockEnrichmentProvider(EnrichmentProvider):
    """Fake provider used for development and testing."""

    name = "mock"

    def enrich(
        self,
        indicator: Indicator,
    ) -> EnrichmentResult:

        if indicator.value == "malicious.example":
            return EnrichmentResult(
                provider=self.name,
                reputation_score=95,
                classification="malicious",
                tags=["malware", "command-and-control"],
            )

        return EnrichmentResult(
            provider=self.name,
            reputation_score=5,
            classification="benign",
        )
