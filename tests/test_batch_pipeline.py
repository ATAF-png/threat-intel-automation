from pathlib import Path

from app.pipeline import ingest_batch
from app.storage.database import initialize_database
from app.storage.repository import list_indicators


def test_batch_ingestion_processes_valid_iocs(
    tmp_path: Path,
):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    result = ingest_batch(
        values=[
            "192.0.2.10",
            "example.com",
            "https://example.com/test",
        ],
        source="test-feed",
        db_path=db_path,
    )

    assert result["processed"] == 3
    assert result["failed"] == 0

    indicators = list_indicators(db_path)

    assert len(indicators) == 3


def test_batch_ingestion_continues_after_invalid_ioc(
    tmp_path: Path,
):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    result = ingest_batch(
        values=[
            "192.0.2.10",
            "this is not a valid indicator",
            "example.com",
        ],
        source="test-feed",
        db_path=db_path,
    )

    assert result["processed"] == 2
    assert result["failed"] == 1

    assert len(result["errors"]) == 1

    indicators = list_indicators(db_path)

    assert len(indicators) == 2
