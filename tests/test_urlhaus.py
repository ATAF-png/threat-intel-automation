from unittest.mock import Mock, patch

from app.collectors.urlhaus import fetch_urlhaus
from app.processing.models import IndicatorType


def test_urlhaus_collector():
    csv_data = """# URLhaus export
id,dateadded,url,url_status,threat
123,2025-06-14 12:00:00,https://example.com/test,online,malware
"""

    mock_response = Mock()
    mock_response.text = csv_data
    mock_response.raise_for_status.return_value = None

    with patch(
        "app.collectors.urlhaus.requests.get",
        return_value=mock_response,
    ):
        indicators = fetch_urlhaus()

    assert len(indicators) == 1

    indicator = indicators[0]

    assert indicator.indicator_type == IndicatorType.URL
    assert indicator.value == "https://example.com/test"
    assert indicator.sources == ["urlhaus"]


def test_urlhaus_skips_invalid_rows():
    csv_data = """# URLhaus export
bad
123,2025-06-14 12:00:00,,online,malware
"""

    mock_response = Mock()
    mock_response.text = csv_data
    mock_response.raise_for_status.return_value = None

    with patch(
        "app.collectors.urlhaus.requests.get",
        return_value=mock_response,
    ):
        indicators = fetch_urlhaus()

    assert indicators == []
