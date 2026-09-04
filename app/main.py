from dotenv import load_dotenv
load_dotenv(override=True)

from pathlib import Path
import argparse
import json

from app.enrichment.manager import EnrichmentManager
from app.enrichment.virustotal import VirusTotalProvider
from app.processing.ingest import ingest_urlhaus_with_summary, ingest_threatfox_with_summary, ingest_malwarebazaar_with_summary
from app.report import export_csv, export_json
from app.storage.repository import (
    get_indicator,
    get_indicator_summary,
    list_indicators,
    get_correlated_indicators,
)

DEFAULT_DB_PATH = Path("data/threat_intel.db")


def run_ingestion(
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = 10,
    delay_seconds: float = 1,
    source: str = "urlhaus",
    days: int = 1,
) -> None:
    print(f"[*] Starting threat intelligence ingestion: {source}")

    manager = EnrichmentManager(
        providers=[VirusTotalProvider()]
    )

    if source == "urlhaus":
        summary = ingest_urlhaus_with_summary(
            db_path=db_path,
            enrichment_manager=manager,
            limit=limit,
            delay_seconds=delay_seconds,
        )
    elif source == "threatfox":
        summary = ingest_threatfox_with_summary(
            db_path=db_path,
            enrichment_manager=manager,
            limit=limit,
            days=days,
            delay_seconds=delay_seconds,
        )
    elif source == "malwarebazaar":
        summary = ingest_malwarebazaar_with_summary(
            db_path=db_path,
            enrichment_manager=manager,
            limit=limit,
            delay_seconds=delay_seconds,
        )
    elif source == "all":
        summaries = {}

        feeds = {
            "urlhaus": lambda: ingest_urlhaus_with_summary(
                db_path=db_path,
                enrichment_manager=manager,
                limit=limit,
                delay_seconds=delay_seconds,
            ),
            "threatfox": lambda: ingest_threatfox_with_summary(
                db_path=db_path,
                enrichment_manager=manager,
                limit=limit,
                days=days,
                delay_seconds=delay_seconds,
            ),
            "malwarebazaar": lambda: ingest_malwarebazaar_with_summary(
                db_path=db_path,
                enrichment_manager=manager,
                limit=limit,
                delay_seconds=delay_seconds,
            ),
        }

        for feed, ingest_func in feeds.items():
            try:
                summaries[feed] = ingest_func()
            except Exception as exc:
                summaries[feed] = {
                    "processed": 0,
                    "enriched": 0,
                    "enrichment_failed": 0,
                    "malicious": 0,
                    "suspicious": 0,
                    "benign": 0,
                    "unknown": 0,
                    "rate_limited": False,
                    "errors": [{"error": str(exc)}],
                }

                print(f"[!] {feed.upper()} failed: {exc}")

        for feed, feed_summary in summaries.items():
            print()
            print(f"[*] {feed.upper()}")
            print(f"    Processed: {feed_summary.get('processed', 0)}")
            print(f"    Enriched:  {feed_summary.get('enriched', 0)}")
            print(f"    Malicious: {feed_summary.get('malicious', 0)}")
            print(f"    Suspicious: {feed_summary.get('suspicious', 0)}")
            print(f"    Benign:    {feed_summary.get('benign', 0)}")
            print(f"    Unknown:   {feed_summary.get('unknown', 0)}")
            print(f"    Errors:    {len(feed_summary.get('errors', []))}")

        return
    else:
        raise ValueError(f"Unsupported source: {source}")

    print(
        f"[+] Processed: {summary['processed']} | "
        f"Enriched: {summary['enriched']} | "
        f"Failures: {summary['enrichment_failed']}"
    )

    print(
        f"[+] Malicious: {summary['malicious']} | "
        f"Suspicious: {summary['suspicious']} | "
        f"Benign: {summary['benign']} | "
        f"Unknown: {summary['unknown']}"
    )

    if summary["rate_limited"]:
        print(
            "[!] VirusTotal rate limit reached. "
            "Ingestion stopped safely."
        )
    elif summary["errors"]:
        print(f"[!] Errors: {len(summary['errors'])}")


def show_indicators(
    db_path: Path = DEFAULT_DB_PATH,
    severity: str | None = None,
    indicator_type: str | None = None,
    limit: int = 20,
    as_json: bool = False,
) -> None:
    rows = list_indicators(db_path)

    filtered = []

    for row in rows:
        if severity and row["severity"] != severity:
            continue
        if indicator_type and row["indicator_type"] != indicator_type:
            continue
        filtered.append(row)

    filtered = filtered[:limit]

    if as_json:
        print(json.dumps([dict(row) for row in filtered], indent=2))
        return

    print(f"[*] Database: {db_path}")
    print(f"[*] Matching indicators: {len(filtered)}")

    if not filtered:
        print("[!] No matching indicators found.")
        return

    for row in filtered:
        print()
        print(f"ID:         {row['id']}")
        print(f"Value:      {row['value']}")
        print(f"Type:       {row['indicator_type']}")
        print(f"Severity:   {row['severity']}")
        print(f"Confidence: {row['confidence']}")

        sources = json.loads(row["sources"])
        tags = json.loads(row["tags"])
        enrichment = json.loads(row["enrichment"])

        print(f"Sources:    {', '.join(sources) or 'none'}")
        print(f"Tags:       {', '.join(tags) or 'none'}")
        print(
            "Enrichment: "
            f"{', '.join(enrichment.keys()) or 'none'}"
        )


def show_summary(
    db_path: Path = DEFAULT_DB_PATH,
    as_json: bool = False,
) -> None:
    summary = get_indicator_summary(db_path)

    if as_json:
        print(json.dumps(summary, indent=2))
        return

    print(f"[*] Database: {db_path}")
    print(f"[*] Total indicators: {summary['total']}")

    print()
    print("[+] Severity")
    print(f"    Low:      {summary['severity']['low']}")
    print(f"    Medium:   {summary['severity']['medium']}")
    print(f"    High:     {summary['severity']['high']}")
    print(f"    Critical: {summary['severity']['critical']}")

    print()
    print("[+] Classification")
    print(f"    Malicious:  {summary['classification']['malicious']}")
    print(f"    Suspicious: {summary['classification']['suspicious']}")
    print(f"    Benign:     {summary['classification']['benign']}")
    print(f"    Unknown:    {summary['classification']['unknown']}")

    print()
    print("[+] Enrichment")
    print(f"    Enriched:     {summary['enrichment']['enriched']}")
    print(f"    Not enriched: {summary['enrichment']['not_enriched']}")

    print()
    print("[+] Indicator types")

    if summary["types"]:
        for indicator_type, count in sorted(summary["types"].items()):
            print(f"    {indicator_type}: {count}")
    else:
        print("    None")


def show_indicator(
    value: str,
    indicator_type: str,
    db_path: Path = DEFAULT_DB_PATH,
    as_json: bool = False,
) -> None:
    row = get_indicator(
        value=value,
        indicator_type=indicator_type,
        db_path=db_path,
    )

    if row is None:
        print("[!] Indicator not found.")
        return

    if as_json:
        print(json.dumps(dict(row), indent=2))
        return

    sources = json.loads(row["sources"])
    tags = json.loads(row["tags"])
    enrichment = json.loads(row["enrichment"])

    print(f"[*] Database: {db_path}")
    print()
    print(f"ID:         {row['id']}")
    print(f"Value:      {row['value']}")
    print(f"Type:       {row['indicator_type']}")
    print(f"Severity:   {row['severity']}")
    print(f"Confidence: {row['confidence']}")
    print(f"Sources:    {', '.join(sources) or 'none'}")
    print(f"Tags:       {', '.join(tags) or 'none'}")
    print(f"First seen: {row['first_seen'] or 'unknown'}")
    print(f"Last seen:  {row['last_seen'] or 'unknown'}")

    print()
    print("[+] Enrichment")

    if not enrichment:
        print("    None")
        return

    for provider, result in enrichment.items():
        print()
        print(f"    Provider: {provider}")
        print(f"    Available: {result.get('available')}")
        print(f"    Classification: {result.get('classification')}")
        print(f"    Reputation score: {result.get('reputation_score')}")
        print(f"    Country: {result.get('country')}")
        print(f"    ASN: {result.get('asn')}")
        print(f"    Tags: {', '.join(result.get('tags', [])) or 'none'}")

        if result.get("error"):
            print(f"    Error: {result['error']}")

        details = result.get("details", {})

        if details:
            print("    Details:")
            print(json.dumps(details, indent=6, sort_keys=True))


def export_indicators(
    db_path: Path = DEFAULT_DB_PATH,
    output: Path = Path("data/export.json"),
    limit: int | None = None,
) -> None:
    rows = list_indicators(db_path)

    if limit is not None:
        rows = rows[:limit]

    data = [dict(row) for row in rows]

    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Exported {len(data)} indicators to {output}")


def report_indicators(
    db_path: Path = DEFAULT_DB_PATH,
    severity: str | None = None,
    classification: str | None = None,
    limit: int = 10,
    export: Path | None = None,
    export_format: str | None = None,
    as_json: bool = False,
) -> None:
    from collections import Counter

    from app.report import get_classification, row_to_dict

    rows = list_indicators(db_path)

    if severity:
        rows = [
            row
            for row in rows
            if row["severity"] == severity
        ]

    if classification:
        rows = [
            row
            for row in rows
            if get_classification(row) == classification
        ]

    ranked_rows = sorted(
        rows,
        key=lambda row: (
            {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
            }.get(row["severity"], 0),
            row["confidence"],
        ),
        reverse=True,
    )

    severity_counts = Counter(row["severity"] for row in rows)

    classifications = Counter(
        get_classification(row)
        for row in rows
    )

    if as_json:
        report = {
            "database": str(db_path),
            "filters": {
                "severity": severity,
                "classification": classification,
            },
            "matching_indicators": len(rows),
            "severity": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
            },
            "classification": {
                "malicious": classifications.get("malicious", 0),
                "suspicious": classifications.get("suspicious", 0),
                "benign": classifications.get("benign", 0),
                "unknown": classifications.get("unknown", 0),
            },
            "priority_indicators": [
                row_to_dict(row)
                for row in ranked_rows[:limit]
            ],
        }

        import json

        print(json.dumps(report, indent=2, default=str))
        return

    print()
    print("Threat Intelligence Report")
    print("==========================")
    print()
    print(f"Matching indicators: {len(rows)}")
    print()

    if not rows:
        print("No matching indicators found.")
        return

    print("Severity:")
    for value in ("critical", "high", "medium", "low"):
        print(
            f"  {value.capitalize():<10}"
            f"{severity_counts.get(value, 0):>8}"
        )

    print()

    print("Classification:")
    for value in ("malicious", "suspicious", "benign", "unknown"):
        print(
            f"  {value.capitalize():<12}"
            f"{classifications.get(value, 0):>8}"
        )

    print()

    print("Highest Priority Indicators")
    print("===========================")

    for row in ranked_rows[:limit]:
        print(
            f"{row['severity'].upper():<9} "
            f"{get_classification(row):<11} "
            f"confidence={row['confidence']:>3}  "
            f"{row['indicator_type']:<7} "
            f"{row['value']}"
        )

    if export:
        export_rows = ranked_rows[:limit]

        if export_format == "json":
            from app.report import export_json
            export_json(export_rows, export)
        else:
            from app.report import export_csv
            export_csv(export_rows, export)

        print()
        print(
            f"[+] Exported {len(export_rows)} indicators "
            f"to {export}"
        )

    print()

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threat intelligence automation CLI"
    )

    subparsers = parser.add_subparsers(dest="command")

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Fetch and enrich URLhaus indicators",
    )

    ingest_parser.add_argument("--limit", type=int, default=10)
    ingest_parser.add_argument("--delay", type=float, default=1)
    ingest_parser.add_argument(
        "--source",
        choices=["urlhaus", "threatfox", "malwarebazaar", "all"],
        default="urlhaus",
        help="Threat intelligence source",
    )
    ingest_parser.add_argument(
        "--days",
        type=int,
        default=1,
        help="ThreatFox lookback period in days (1-7)",
    )
    ingest_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )

    show_parser = subparsers.add_parser(
        "show",
        help="Display stored indicators",
    )

    show_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
    )
    show_parser.add_argument(
        "--type",
        dest="indicator_type",
        choices=[
            "ipv4",
            "ipv6",
            "domain",
            "url",
            "md5",
            "sha1",
            "sha256",
        ],
    )
    show_parser.add_argument("--limit", type=int, default=20)
    show_parser.add_argument("--json", action="store_true")
    show_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )

    correlated_parser = subparsers.add_parser(
        "correlated",
        help="Show indicators observed by multiple intelligence sources",
    )
    correlated_parser.add_argument("--limit", type=int, default=20)
    correlated_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )
    summary_parser = subparsers.add_parser(
        "summary",
        help="Display database threat intelligence summary",
    )
    summary_parser.add_argument("--json", action="store_true")
    summary_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )

    lookup_parser = subparsers.add_parser(
        "lookup",
        help="Look up one stored indicator",
    )
    lookup_parser.add_argument("value")
    lookup_parser.add_argument(
        "--type",
        dest="indicator_type",
        required=True,
        choices=[
            "ipv4",
            "ipv6",
            "domain",
            "url",
            "md5",
            "sha1",
            "sha256",
        ],
    )
    lookup_parser.add_argument("--json", action="store_true")
    lookup_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Export stored indicators to JSON",
    )
    export_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSON file",
    )
    export_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of indicators to export",
    )
    export_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="SQLite database path",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Generate a threat intelligence report",
    )
    report_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low"],
    )
    report_parser.add_argument(
        "--classification",
        choices=["malicious", "suspicious", "benign", "unknown"],
    )
    report_parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of priority indicators to display/export",
    )

    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON",
    )
    report_parser.add_argument(
        "--export",
        type=Path,
        help="Export report indicators to a file",
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "csv"],
        help="Export format",
    )
    report_parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="SQLite database path",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest":
        run_ingestion(
            db_path=args.db,
            limit=args.limit,
            delay_seconds=args.delay,
            source=args.source,
            days=args.days,
        )

    elif args.command == "show":
        show_indicators(
            db_path=args.db,
            severity=args.severity,
            indicator_type=args.indicator_type,
            limit=args.limit,
            as_json=args.json,
        )

    elif args.command == "correlated":
        indicators = get_correlated_indicators(
            db_path=args.db,
            limit=args.limit,
        )

        print(f"[*] Database: {args.db}")
        print(f"[*] Correlated indicators: {len(indicators)}")

        if not indicators:
            print("[+] No indicators found across multiple sources.")
        else:
            for indicator in indicators:
                print()
                print(f"ID:         {indicator['id']}")
                print(f"Value:      {indicator['value']}")
                print(f"Type:       {indicator['indicator_type']}")
                print(f"Severity:   {indicator['severity']}")
                print(f"Confidence: {indicator['confidence']}")
                print(f"Sources:    {', '.join(indicator['sources'])}")
                print(f"Tags:       {', '.join(indicator['tags'])}")
    elif args.command == "summary":
        show_summary(
            db_path=args.db,
            as_json=args.json,
        )

    elif args.command == "lookup":
        show_indicator(
            value=args.value,
            indicator_type=args.indicator_type,
            db_path=args.db,
            as_json=args.json,
        )

    elif args.command == "export":
        limit = args.limit

        if limit is None:
            limit = 1000
            print(
                "[!] No export limit supplied; "
                "capping export at 1000 indicators."
            )

        export_indicators(
            db_path=args.db,
            output=args.output,
            limit=limit,
        )

    elif args.command == "report":
        if args.format and not args.export:
            parser.error("--format requires --export")

        if args.export and not args.format:
            parser.error("--export requires --format")

        report_indicators(
            db_path=args.db,
            severity=args.severity,
            classification=args.classification,
            limit=args.limit,
            export=args.export,
            export_format=args.format,
            as_json=args.json,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
















