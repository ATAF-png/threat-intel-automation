from app.enrichment.models import EnrichmentResult
from app.processing.analysis import analyze_indicator
from app.processing.models import Indicator, IndicatorType, Severity


def test_analysis_updates_indicator():
    indicator = Indicator(
        value="malicious.example",
        indicator_type=IndicatorType.DOMAIN,
    )

    results = [
        EnrichmentResult(
            provider="provider-a",
            reputation_score=95,
            classification="malicious",
            tags=["malware"],
        ),
        EnrichmentResult(
            provider="provider-b",
            reputation_score=90,
            classification="malicious",
            tags=["c2"],
        ),
    ]

    analyzed = analyze_indicator(
        indicator,
        results,
    )

    assert analyzed.confidence == 100
    assert analyzed.severity == Severity.CRITICAL

    assert "malware" in analyzed.tags
    assert "c2" in analyzed.tags

    assert "provider-a" in analyzed.enrichment
    assert "provider-b" in analyzed.enrichment


def test_analysis_preserves_provider_failure():
    indicator = Indicator(
        value="example.com",
        indicator_type=IndicatorType.DOMAIN,
    )

    results = [
        EnrichmentResult(
            provider="working-provider",
            reputation_score=10,
            classification="benign",
        ),
        EnrichmentResult(
            provider="failed-provider",
            available=False,
            error="timeout",
        ),
    ]

    analyzed = analyze_indicator(
        indicator,
        results,
    )

    assert analyzed.confidence == 10
    assert analyzed.enrichment["failed-provider"]["available"] is False
    assert analyzed.enrichment["failed-provider"]["error"] == "timeout"
