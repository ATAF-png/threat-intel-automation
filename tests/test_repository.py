from pathlib import Path

from app.processing.models import Indicator, IndicatorType
from app.storage.database import initialize_database
from app.storage.repository import (
    get_indicator,
    list_indicators,
    save_indicator,
)


def test_save_and_get_indicator(tmp_path: Path):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    indicator = Indicator(
        value="192.0.2.10",
        indicator_type=IndicatorType.IPV4,
        sources=["test"],
        confidence=90,
    )

    indicator_id = save_indicator(indicator, db_path)

    assert indicator_id > 0

    result = get_indicator(
        "192.0.2.10",
        "ipv4",
        db_path,
    )

    assert result is not None
    assert result["value"] == "192.0.2.10"
    assert result["confidence"] == 90


def test_same_indicator_from_multiple_sources_is_merged(
    tmp_path: Path,
):
    db_path = tmp_path / "test.db"

    initialize_database(db_path)

    indicator_one = Indicator(
        value="192.0.2.10",
        indicator_type=IndicatorType.IPV4,
        sources=["OTX"],
        confidence=50,
    )

    indicator_two = Indicator(
        value="192.0.2.10",
        indicator_type=IndicatorType.IPV4,
        sources=["URLhaus"],
        confidence=90,
    )

    first_id = save_indicator(indicator_one, db_path)
    second_id = save_indicator(indicator_two, db_path)

    assert first_id == second_id

    indicators = list_indicators(db_path)

    assert len(indicators) == 1

    assert set(
        __import__("json").loads(indicators[0]["sources"])
    ) == {"OTX", "URLhaus"}

    assert indicators[0]["confidence"] == 90
