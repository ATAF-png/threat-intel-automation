from app.enrichment.models import EnrichmentResult
from app.processing.models import Severity
from app.processing.scoring import (
    calculate_score,
    severity_from_score,
)


def test_high_reputation_score():
    results = [
        EnrichmentResult(
            provider="provider-a",
            reputation_score=80,
            classification="malicious",
        )
    ]

    score = calculate_score(results)

    assert score == 85


def test_multiple_malicious_sources_increase_score():
    results = [
        EnrichmentResult(
            provider="provider-a",
            reputation_score=80,
            classification="malicious",
        ),
        EnrichmentResult(
            provider="provider-b",
            reputation_score=75,
            classification="malicious",
        ),
    ]

    score = calculate_score(results)

    assert score == 90


def test_score_is_capped_at_100():
    results = [
        EnrichmentResult(
            provider="provider-a",
            reputation_score=100,
            classification="malicious",
        ),
        EnrichmentResult(
            provider="provider-b",
            reputation_score=100,
            classification="malicious",
        ),
        EnrichmentResult(
            provider="provider-c",
            reputation_score=100,
            classification="malicious",
        ),
    ]

    score = calculate_score(results)

    assert score == 100


def test_no_available_results_returns_zero():
    results = [
        EnrichmentResult(
            provider="provider-a",
            available=False,
            error="timeout",
        )
    ]

    assert calculate_score(results) == 0


def test_severity_mapping():
    assert severity_from_score(95) == Severity.CRITICAL
    assert severity_from_score(75) == Severity.HIGH
    assert severity_from_score(50) == Severity.MEDIUM
    assert severity_from_score(10) == Severity.LOW
