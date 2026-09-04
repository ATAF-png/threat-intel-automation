import json
from datetime import datetime, timezone
from pathlib import Path

from app.processing.models import Indicator


DEFAULT_DB_PATH = Path("data/threat_intel.db")


SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


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

    last_ingested_at = datetime.now(timezone.utc).isoformat()

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

            existing_severity = existing["severity"] or "low"
            severity = (
                indicator.severity.value
                if SEVERITY_RANK[indicator.severity.value]
                > SEVERITY_RANK[existing_severity]
                else existing_severity
            )

            existing_first_seen = existing["first_seen"]

            if existing_first_seen and first_seen:
                first_seen = min(
                    existing_first_seen,
                    first_seen,
                )
            elif existing_first_seen:
                first_seen = existing_first_seen

            existing_last_seen = existing["last_seen"]

            if existing_last_seen and last_seen:
                last_seen = max(
                    existing_last_seen,
                    last_seen,
                )
            elif existing_last_seen:
                last_seen = existing_last_seen

            existing_enrichment = json.loads(
                existing["enrichment"] or "{}"
            )

            incoming_enrichment = indicator.enrichment or {}

            merged_enrichment = {
                **existing_enrichment,
                **incoming_enrichment,
            }

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
                    enrichment = ?,
                    last_ingested_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(sorted(merged_sources)),
                    json.dumps(sorted(merged_tags)),
                    confidence,
                    severity,
                    first_seen,
                    last_seen,
                    json.dumps(merged_enrichment),
                    last_ingested_at,
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
                created_at,
                last_ingested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                last_ingested_at,
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
    since: str | None = None,
):
    """Return stored indicators, optionally limited to a recent ingestion window."""

    with _get_initialized_connection(db_path) as connection:
        if since:
            return connection.execute(
                """
                SELECT *
                FROM indicators
                WHERE last_ingested_at >= ?
                ORDER BY last_ingested_at DESC, created_at DESC
                """,
                (since,),
            ).fetchall()

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


def get_correlated_indicators(
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = 50,
    since: str | None = None,
) -> list[dict]:
    """Return indicators observed by multiple intelligence sources."""

    from app.storage.database import get_connection

    conn = get_connection(db_path)

    try:
        if since:
            rows = conn.execute(
                """
                SELECT
                    id,
                    value,
                    indicator_type,
                    severity,
                    confidence,
                    sources,
                    tags,
                    enrichment
                FROM indicators
                WHERE last_ingested_at >= ?
                ORDER BY confidence DESC, id DESC
                """,
                (since,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    id,
                    value,
                    indicator_type,
                    severity,
                    confidence,
                    sources,
                    tags,
                    enrichment
                FROM indicators
                ORDER BY confidence DESC, id DESC
                """
            ).fetchall()
    finally:
        conn.close()

    results = []

    for row in rows:
        sources = json.loads(row["sources"] or "[]")

        if len(set(sources)) < 2:
            continue

        results.append(
            {
                "id": row["id"],
                "value": row["value"],
                "indicator_type": row["indicator_type"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "sources": sources,
                "tags": json.loads(row["tags"] or "[]"),
                "enrichment": json.loads(row["enrichment"] or "{}"),
            }
        )

        if len(results) >= limit:
            break

    return results
