import json
from pathlib import Path

from app.processing.models import Indicator


DEFAULT_DB_PATH = Path("data/threat_intel.db")


def save_indicator(
    indicator: Indicator,
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    """Save or update an Indicator."""

    sources_json = json.dumps(sorted(set(indicator.sources)))
    tags_json = json.dumps(sorted(set(indicator.tags)))
    enrichment_json = json.dumps(indicator.enrichment)

    first_seen = (
        indicator.first_seen.isoformat()
        if indicator.first_seen
        else None
    )

    last_seen = (
        indicator.last_seen.isoformat()
        if indicator.last_seen
        else None
    )

    created_at = indicator.created_at.isoformat()

    with _get_initialized_connection(db_path) as connection:
        existing = connection.execute(
            """
            SELECT *
            FROM indicators
            WHERE value = ?
              AND indicator_type = ?
            """,
            (
                indicator.value,
                indicator.indicator_type.value,
            ),
        ).fetchone()

        if existing:
            existing_sources = set(json.loads(existing["sources"]))
            existing_tags = set(json.loads(existing["tags"]))

            merged_sources = existing_sources.union(indicator.sources)
            merged_tags = existing_tags.union(indicator.tags)

            existing_confidence = existing["confidence"] or 0
            confidence = max(
                existing_confidence,
                indicator.confidence,
            )

            existing_first_seen = existing["first_seen"]

            if existing_first_seen and first_seen:
                first_seen = min(
                    existing_first_seen,
                    first_seen,
                )
            elif existing_first_seen:
                first_seen = existing_first_seen

            if not last_seen:
                last_seen = existing["last_seen"]

            connection.execute(
                """
                UPDATE indicators
                SET
                    sources = ?,
                    tags = ?,
                    confidence = ?,
                    severity = ?,
                    first_seen = ?,
                    last_seen = ?,
                    enrichment = ?
                WHERE id = ?
                """,
                (
                    json.dumps(sorted(merged_sources)),
                    json.dumps(sorted(merged_tags)),
                    confidence,
                    indicator.severity.value,
                    first_seen,
                    last_seen,
                    enrichment_json,
                    existing["id"],
                ),
            )

            connection.commit()
            return existing["id"]

        cursor = connection.execute(
            """
            INSERT INTO indicators (
                value,
                indicator_type,
                sources,
                tags,
                confidence,
                severity,
                first_seen,
                last_seen,
                enrichment,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                indicator.value,
                indicator.indicator_type.value,
                sources_json,
                tags_json,
                indicator.confidence,
                indicator.severity.value,
                first_seen,
                last_seen,
                enrichment_json,
                created_at,
            ),
        )

        connection.commit()
        return cursor.lastrowid


def get_indicator(
    value: str,
    indicator_type: str,
    db_path: Path = DEFAULT_DB_PATH,
):
    """Retrieve one indicator."""

    with _get_initialized_connection(db_path) as connection:
        return connection.execute(
            """
            SELECT *
            FROM indicators
            WHERE value = ?
              AND indicator_type = ?
            """,
            (value, indicator_type),
        ).fetchone()


def list_indicators(
    db_path: Path = DEFAULT_DB_PATH,
):
    """Return all stored indicators."""

    with _get_initialized_connection(db_path) as connection:
        return connection.execute(
            """
            SELECT *
            FROM indicators
            ORDER BY created_at DESC
            """
        ).fetchall()


def get_indicator_summary(
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """Return summary statistics for stored indicators."""

    rows = list_indicators(db_path)

    summary = {
        "total": len(rows),
        "severity": {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        },
        "types": {},
        "enrichment": {
            "enriched": 0,
            "not_enriched": 0,
        },
        "classification": {
            "malicious": 0,
            "suspicious": 0,
            "benign": 0,
            "unknown": 0,
        },
    }

    for row in rows:
        severity = row["severity"]

        if severity in summary["severity"]:
            summary["severity"][severity] += 1

        indicator_type = row["indicator_type"]

        summary["types"][indicator_type] = (
            summary["types"].get(indicator_type, 0) + 1
        )

        enrichment = json.loads(row["enrichment"])

        if enrichment:
            summary["enrichment"]["enriched"] += 1
        else:
            summary["enrichment"]["not_enriched"] += 1

        classifications = set()

        for result in enrichment.values():
            classification = result.get("classification")

            if classification:
                classifications.add(classification)

        if "malicious" in classifications:
            summary["classification"]["malicious"] += 1

        elif "suspicious" in classifications:
            summary["classification"]["suspicious"] += 1

        elif "benign" in classifications:
            summary["classification"]["benign"] += 1

        else:
            summary["classification"]["unknown"] += 1

    return summary


def _get_initialized_connection(db_path: Path):
    """Open the database and ensure its schema exists."""

    from app.storage.database import initialize_database

    initialize_database(db_path)

    return _connection(db_path)


def _connection(db_path: Path):
    from app.storage.database import get_connection

    return get_connection(db_path)
