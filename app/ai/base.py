from abc import ABC, abstractmethod

from app.ai.models import AnalystReport


class AIProvider(ABC):
    """Base interface for AI analyst providers."""

    name: str = "unknown"

    @abstractmethod
    def analyze(self, report: dict) -> AnalystReport:
        """Analyze a structured threat intelligence report."""
        raise NotImplementedError
