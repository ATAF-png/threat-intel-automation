from abc import ABC, abstractmethod

from app.processing.models import Indicator
from app.enrichment.models import EnrichmentResult


class EnrichmentProvider(ABC):
    """Base interface for all enrichment providers."""

    name: str = "unknown"

    @abstractmethod
    def enrich(
        self,
        indicator: Indicator,
    ) -> EnrichmentResult:
        """Enrich an indicator."""
        raise NotImplementedError
