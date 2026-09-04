from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from app.report import SEVERITY_ORDER, row_to_dict
from app.storage.repository import get_correlated_indicators, list_indicators

DEFAULT_DB_PATH = Path("data/threat_intel.db")


def build_report(
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = 10,
    since: str | None = None,
) -> dict:
    rows = list_indicators(db_path, since=since)
    indicators = [row_to_dict(row) for row in rows]

    severity_counts = Counter(
        indicator["severity"]
        for indicator in indicators
    )

    classification_counts = Counter(
        indicator["classification"]
        for indicator in indicators
    )

    source_counts = Counter()

    for indicator in indicators:
        for source in indicator["sources"]:
            source_counts[source] += 1

    ranked_indicators = sorted(
        indicators,
        key=lambda indicator: (
            SEVERITY_ORDER.get(indicator["severity"], 0),
            indicator["confidence"],
        ),
        reverse=True,
    )

    correlated = get_correlated_indicators(
        db_path=db_path,
        limit=limit,
        since=since,
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": str(db_path),
        "scope": {
            "since": since,
            "fresh": since is not None,
        },
        "summary": {
            "total_indicators": len(indicators),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "malicious": classification_counts.get("malicious", 0),
            "suspicious": classification_counts.get("suspicious", 0),
            "benign": classification_counts.get("benign", 0),
            "unknown": classification_counts.get("unknown", 0),
        },
        "sources": dict(source_counts.most_common()),
        "priority_indicators": ranked_indicators[:limit],
        "correlated_indicators": correlated,
    }
