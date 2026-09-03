from pathlib import Path
from time import sleep

from app.collectors.urlhaus import fetch_urlhaus
from app.enrichment.manager import EnrichmentManager
from app.processing.analysis import analyze_indicator
from app.storage.repository import save_indicator


def ingest_urlhaus(
    db_path: Path = Path("data/threat_intel.db"),
) -> int:
    """
    Fetch URLhaus indicators and store them in SQLite.

    Returns the number of indicators processed.
    """

    indicators = fetch_urlhaus()

    processed = 0

    for indicator in indicators:
        save_indicator(
            indicator,
            db_path=db_path,
        )

        processed += 1

    return processed


def ingest_urlhaus_with_summary(
    db_path: Path = Path("data/threat_intel.db"),
    enrichment_manager: EnrichmentManager | None = None,
    limit: int | None = None,
    delay_seconds: float = 0,
) -> dict:
    """
    Fetch URLhaus indicators, enrich them, analyze them,
    and store the results.

    Stops safely when an enrichment provider reports a
    rate-limit condition.
    """

    indicators = fetch_urlhaus()

    if limit is not None:
        indicators = indicators[:limit]

    if enrichment_manager is None:
        raise ValueError("enrichment_manager is required")

    summary = {
        "processed": 0,
        "enriched": 0,
        "enrichment_failed": 0,
        "malicious": 0,
        "suspicious": 0,
        "benign": 0,
        "unknown": 0,
        "rate_limited": False,
        "errors": [],
    }

    for indicator in indicators:
        enrichment_results = enrichment_manager.enrich(indicator)

        rate_limited = False

        for result in enrichment_results:
            classification = result.classification or "unknown"

            if result.available:
                summary["enriched"] += 1
            else:
                summary["enrichment_failed"] += 1

                error = {
                    "value": indicator.value,
                    "provider": result.provider,
                    "error": result.error,
                }

                summary["errors"].append(error)

                if (
                    result.details.get("status") == 429
                    or result.error == "VirusTotal rate limit exceeded"
                ):
                    rate_limited = True
                    summary["rate_limited"] = True

            if classification in summary:
                summary[classification] += 1

        indicator = analyze_indicator(
            indicator=indicator,
            enrichment_results=enrichment_results,
        )

        save_indicator(
            indicator,
            db_path=db_path,
        )

        summary["processed"] += 1

        if rate_limited:
            break

        if delay_seconds > 0:
            sleep(delay_seconds)

    return summary
