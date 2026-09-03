from pathlib import Path
from unittest.mock import patch

from app.processing.ingest import ingest_urlhaus
from app.processing.models import Indicator, IndicatorType
from app.storage.database import get_connection


def test_ingest_urlhaus(tmp_path: Path):
    db_path = tmp_path / "threat_intel.db"

    with patch(
        "app.processing.ingest.fetch_urlhaus"
    ) as mock_fetch:

        mock_fetch.return_value = [
            Indicator(
                value="https://example.com/malware",
                indicator_type=IndicatorType.URL,
                sources=["urlhaus"],
            )
        ]

        processed = ingest_urlhaus(
            db_path=db_path
        )

    assert processed == 1

    with get_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM indicators
            WHERE value = ?
            """,
            ("https://example.com/malware",),
        ).fetchone()

    assert row is not None
    assert row["indicator_type"] == "url"

    assert row["sources"] == '["urlhaus"]'
