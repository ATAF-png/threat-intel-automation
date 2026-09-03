import json
from pathlib import Path

from app.pipeline import ingest_ioc
from app.storage.database import initialize_database
from app.storage.repository import get_indicator


def test_ingest_ioc_normalizes_and_stores(tmp_path: Path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    indicator = ingest_ioc(
        value="  EXAMPLE.COM  ",
        source="test-feed",
        db_path=db_path,
    )

    assert indicator.value == "example.com"
    assert indicator.indicator_type.value == "domain"
    assert indicator.sources == ["test-feed"]

    stored = get_indicator(
        "example.com",
        "domain",
        db_path,
    )

    assert stored is not None
    assert stored["value"] == "example.com"
    assert stored["indicator_type"] == "domain"

    sources = json.loads(stored["sources"])

    assert sources == ["test-feed"]
