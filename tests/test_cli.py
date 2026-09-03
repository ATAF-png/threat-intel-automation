from pathlib import Path

from app.main import build_parser


def test_cli_builds():
    parser = build_parser()

    args = parser.parse_args(
        [
            "show",
            "--severity",
            "critical",
            "--limit",
            "10",
        ]
    )

    assert args.command == "show"
    assert args.severity == "critical"
    assert args.limit == 10


def test_cli_lookup():
    parser = build_parser()

    args = parser.parse_args(
        [
            "lookup",
            "example.com",
            "--type",
            "domain",
        ]
    )

    assert args.command == "lookup"
    assert args.value == "example.com"
    assert args.indicator_type == "domain"


def test_cli_ingest():
    parser = build_parser()

    args = parser.parse_args(
        [
            "ingest",
            "--limit",
            "5",
            "--delay",
            "2",
            "--db",
            "data/test.db",
        ]
    )

    assert args.command == "ingest"
    assert args.limit == 5
    assert args.delay == 2
    assert args.db == Path("data/test.db")
import json

from app.main import build_parser


def test_show_json_flag():
    parser = build_parser()

    args = parser.parse_args(
        ["show", "--json"]
    )

    assert args.json is True


def test_summary_json_flag():
    parser = build_parser()

    args = parser.parse_args(
        ["summary", "--json"]
    )

    assert args.json is True


def test_lookup_json_flag():
    parser = build_parser()

    args = parser.parse_args(
        [
            "lookup",
            "example.com",
            "--type",
            "domain",
            "--json",
        ]
    )

    assert args.json is True
from pathlib import Path

from app.main import build_parser


def test_cli_export_json():
    parser = build_parser()

    args = parser.parse_args(
        [
            "export",
            "--output",
            "data/export.json",
        ]
    )

    assert args.command == "export"
    assert args.output == Path("data/export.json")


def test_cli_export_limit():
    parser = build_parser()

    args = parser.parse_args(
        [
            "export",
            "--output",
            "data/export.json",
            "--limit",
            "5",
        ]
    )

    assert args.limit == 5

def test_cli_report():
    parser = build_parser()

    args = parser.parse_args(
        [
            "report",
            "--severity",
            "high",
            "--classification",
            "malicious",
            "--limit",
            "5",
            "--export",
            "data/report.csv",
            "--format",
            "csv",
            "--db",
            "data/test.db",
        ]
    )

    assert args.command == "report"
    assert args.severity == "high"
    assert args.classification == "malicious"
    assert args.limit == 5
    assert args.export == Path("data/report.csv")
    assert args.format == "csv"
    assert args.db == Path("data/test.db")


def test_cli_report_defaults():
    parser = build_parser()

    args = parser.parse_args(["report"])

    assert args.command == "report"
    assert args.severity is None
    assert args.classification is None
    assert args.limit == 10
    assert args.export is None
    assert args.format is None

def test_cli_report_json_flag():
    parser = build_parser()

    args = parser.parse_args(
        [
            "report",
            "--json",
        ]
    )

    assert args.command == "report"
    assert args.json is True
