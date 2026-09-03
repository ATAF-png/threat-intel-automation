from pathlib import Path

from app.enrichment.manager import EnrichmentManager
from app.enrichment.mock import MockEnrichmentProvider
from app.processing.analysis import analyze_indicator
from app.processing.models import Indicator
from app.processing.normalize import normalize_indicator
from app.storage.repository import save_indicator


def ingest_ioc(
    value: str,
    source: str,
    db_path: Path = Path("data/threat_intel.db"),
    enrichment_manager: EnrichmentManager | None = None,
) -> Indicator:
    """
    Normalize, enrich, analyze, and save an IOC.
    """
    indicator = normalize_indicator(
        value=value,
        source=source,
    )

    if enrichment_manager is None:
        enrichment_manager = EnrichmentManager(
            providers=[MockEnrichmentProvider()]
        )

    enrichment_results = enrichment_manager.enrich(indicator)

    indicator = analyze_indicator(
        indicator=indicator,
        enrichment_results=enrichment_results,
    )

    save_indicator(
        indicator=indicator,
        db_path=db_path,
    )

    return indicator


def ingest_batch(
    values: list[str],
    source: str,
    db_path: Path = Path("data/threat_intel.db"),
    enrichment_manager: EnrichmentManager | None = None,
) -> dict:
    """
    Process multiple IOCs.

    A single invalid IOC will not stop the batch.
    """
    processed = 0
    failed = 0
    errors = []

    if enrichment_manager is None:
        enrichment_manager = EnrichmentManager(
            providers=[MockEnrichmentProvider()]
        )

    for value in values:
        try:
            ingest_ioc(
                value=value,
                source=source,
                db_path=db_path,
                enrichment_manager=enrichment_manager,
            )

            processed += 1

        except (ValueError, TypeError) as exc:
            failed += 1

            errors.append(
                {
                    "value": value,
                    "error": str(exc),
                }
            )

    return {
        "processed": processed,
        "failed": failed,
        "errors": errors,
    }
