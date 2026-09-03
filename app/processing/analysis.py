from app.enrichment.models import EnrichmentResult
from app.processing.models import Indicator
from app.processing.scoring import calculate_score, severity_from_score


def analyze_indicator(
    indicator: Indicator,
    enrichment_results: list[EnrichmentResult],
) -> Indicator:
    """
    Apply enrichment evidence and risk scoring to an indicator.
    """

    indicator.enrichment = {
        result.provider: {
            "available": result.available,
            "reputation_score": result.reputation_score,
            "classification": result.classification,
            "country": result.country,
            "asn": result.asn,
            "tags": result.tags,
            "details": result.details,
            "error": result.error,
        }
        for result in enrichment_results
    }

    score = calculate_score(enrichment_results)

    indicator.confidence = score
    indicator.severity = severity_from_score(score)

    # Combine tags from all available providers.
    provider_tags = {
        tag
        for result in enrichment_results
        if result.available
        for tag in result.tags
    }

    indicator.tags = sorted(
        set(indicator.tags).union(provider_tags)
    )

    return indicator
