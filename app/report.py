import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from app.storage.repository import list_indicators


DEFAULT_DB_PATH = Path("data/threat_intel.db")

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def get_classification(row) -> str:
    """Extract the primary enrichment classification."""

    enrichment = json.loads(row["enrichment"])

    if not enrichment:
        return "unknown"

    for result in enrichment.values():
        classification = result.get("classification")

        if classification:
            return classification

    return "unknown"


def row_to_dict(row) -> dict:
    """Convert a SQLite row into an export-friendly dictionary."""

    return {
        "id": row["id"],
        "value": row["value"],
        "indicator_type": row["indicator_type"],
        "sources": json.loads(row["sources"]),
        "tags": json.loads(row["tags"]),
        "confidence": row["confidence"],
        "severity": row["severity"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "enrichment": json.loads(row["enrichment"]),
        "created_at": row["created_at"],
        "classification": get_classification(row),
    }


def export_json(rows: list, path: Path) -> None:
    """Export indicators as JSON."""

    data = [
        row_to_dict(row)
        for row in rows
    ]

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
        )


def export_csv(rows: list, path: Path) -> None:
    """Export indicators as CSV."""

    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "id",
        "value",
        "indicator_type",
        "sources",
        "tags",
        "confidence",
        "severity",
        "classification",
        "first_seen",
        "last_seen",
        "created_at",
    ]

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in rows:
            data = row_to_dict(row)

            writer.writerow(
                {
                    "id": data["id"],
                    "value": data["value"],
                    "indicator_type": data["indicator_type"],
                    "sources": ",".join(data["sources"]),
                    "tags": ",".join(data["tags"]),
                    "confidence": data["confidence"],
                    "severity": data["severity"],
                    "classification": data["classification"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "created_at": data["created_at"],
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Threat intelligence database report."
    )

    parser.add_argument(
        "--severity",
        choices=("critical", "high", "medium", "low"),
        help="Only show indicators with this severity.",
    )

    parser.add_argument(
        "--classification",
        choices=("malicious", "suspicious", "benign", "unknown"),
        help="Only show indicators with this classification.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of priority indicators to display.",
    )

    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to the SQLite database.",
    )

    parser.add_argument(
        "--export",
        type=Path,
        help="Export matching indicators to a file.",
    )

    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        help="Export format.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.format and not args.export:
        raise SystemExit(
            "--format requires --export"
        )

    if args.export and not args.format:
        raise SystemExit(
            "--export requires --format"
        )

    rows = list_indicators(args.db)

    if args.severity:
        rows = [
            row
            for row in rows
            if row["severity"] == args.severity
        ]

    if args.classification:
        rows = [
            row
            for row in rows
            if get_classification(row) == args.classification
        ]

    print()
    print("Threat Intelligence Report")
    print("==========================")
    print()

    if args.severity:
        print(f"Severity filter: {args.severity}")

    if args.classification:
        print(f"Classification filter: {args.classification}")

    if args.severity or args.classification:
        print()

    print(f"Matching indicators: {len(rows)}")
    print()

    if not rows:
        print("No matching indicators found.")
    else:
        severity_counts = Counter(
            row["severity"]
            for row in rows
        )

        print("Severity:")
        for severity in (
            "critical",
            "high",
            "medium",
            "low",
        ):
            print(
                f"  {severity.capitalize():<10}"
                f"{severity_counts.get(severity, 0):>8}"
            )

        print()

        classifications = Counter(
            get_classification(row)
            for row in rows
        )

        print("Classification:")
        for classification in (
            "malicious",
            "suspicious",
            "benign",
            "unknown",
        ):
            print(
                f"  {classification.capitalize():<12}"
                f"{classifications.get(classification, 0):>8}"
            )

        print()

        sources = Counter()

        for row in rows:
            for source in json.loads(row["sources"]):
                sources[source] += 1

        print("Top sources:")
        for source, count in sources.most_common(10):
            print(
                f"  {source:<20}"
                f"{count:>8}"
            )

        print()

        ranked_rows = sorted(
            rows,
            key=lambda row: (
                SEVERITY_ORDER.get(
                    row["severity"],
                    0,
                ),
                row["confidence"],
            ),
            reverse=True,
        )

        print("Highest Priority Indicators")
        print("===========================")

        for row in ranked_rows[:args.limit]:
            classification = get_classification(row)

            print(
                f"{row['severity'].upper():<9} "
                f"{classification:<11} "
                f"confidence={row['confidence']:>3}  "
                f"{row['indicator_type']:<7} "
                f"{row['value']}"
            )

    if args.export:
        export_rows = rows[:args.limit]

        if args.format == "json":
            export_json(export_rows, args.export)
        else:
            export_csv(export_rows, args.export)

        print()
        print(
            f"[+] Exported {len(export_rows)} indicators "
            f"to {args.export}"
        )

    print()


if __name__ == "__main__":
    main()
