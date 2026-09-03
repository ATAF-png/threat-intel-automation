import csv
import io
import zipfile
import requests

from app.processing.normalize import normalize_indicator


URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"


def fetch_urlhaus():
    response = requests.get(URLHAUS_URL, timeout=30)
    response.raise_for_status()

    content = getattr(response, "content", None)

    # Real URLhaus response is a ZIP containing csv.txt.
    if isinstance(content, bytes) and content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            csv_text = archive.read("csv.txt").decode(
                "utf-8",
                errors="replace",
            )
    else:
        # Used by tests and for plain-text responses.
        csv_text = response.text

    indicators = []

    lines = [
        line
        for line in csv_text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    reader = csv.reader(lines)

    for row in reader:
        if not row:
            continue

        # Skip the CSV header.
        if row[0].strip().lower() in {"id", "dateadded"}:
            continue

        # URLhaus format:
        # id,dateadded,url,url_status,threat,...
        if len(row) < 3:
            continue

        url = row[2].strip()

        if not url:
            continue

        try:
            indicator = normalize_indicator(
                value=url,
                source="urlhaus",
            )
            indicators.append(indicator)
        except ValueError:
            continue

    return indicators
