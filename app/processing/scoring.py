from app.enrichment.models import EnrichmentResult
from app.processing.models import Severity


def calculate_score(
    results: list[EnrichmentResult],
) -> int:
    """
    Calculate an explainable risk score from enrichment results.

    The score is between 0 and 100.

    The strongest provider reputation score is used as the
    baseline. Independent malicious classifications add
    additional confidence.

    VirusTotal analysis statistics are also used when available.
    """

    available_results = [
        result
        for result in results
        if result.available
    ]

    if not available_results:
        return 0

    scores = [
        result.reputation_score
        for result in available_results
        if result.reputation_score is not None
    ]

    if not scores:
        return 0

    highest_score = max(scores)

    malicious_count = sum(
        1
        for result in available_results
        if result.classification == "malicious"
    )

    score = highest_score

    # Preserve the original provider-based scoring behavior.
    score += min(malicious_count * 5, 15)

    # Add VirusTotal detection evidence when available.
    for result in available_results:
        analysis_stats = result.details.get("analysis_stats", {})

        malicious_detections = int(
            analysis_stats.get("malicious", 0)
        )

        suspicious_detections = int(
            analysis_stats.get("suspicious", 0)
        )

        # Detection evidence supplements provider reputation.
        # It does not replace the existing scoring model.
        score += min(malicious_detections // 5, 20)
        score += min(suspicious_detections // 5, 5)

    return min(score, 100)


def severity_from_score(score: int) -> Severity:
    """Convert a numeric risk score into a severity."""

    if score >= 90:
        return Severity.CRITICAL

    if score >= 70:
        return Severity.HIGH

    if score >= 40:
        return Severity.MEDIUM

    return Severity.LOW
