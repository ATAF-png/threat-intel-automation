import os

from app.ai.models import AnalystReport, IOCAssessment
from app.ai.mock import MockAIProvider
from app.ai.huggingface import HuggingFaceAIProvider


def get_ai_provider():
    """Return the configured AI analyst provider."""

    provider = os.getenv("AI_PROVIDER", "mock").lower()

    if provider == "mock":
        return MockAIProvider()

    if provider == "huggingface":
        return HuggingFaceAIProvider()

    raise ValueError(
        f"Unsupported AI_PROVIDER: {provider}. "
        "Use 'mock' or 'huggingface'."
    )


__all__ = [
    "AnalystReport",
    "IOCAssessment",
    "MockAIProvider",
    "HuggingFaceAIProvider",
    "get_ai_provider",
]
