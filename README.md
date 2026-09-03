# Threat Intelligence Automation

Python-based threat intelligence automation pipeline for collecting, normalizing, scoring, enriching, storing, and reporting on threat indicators.

## Features

- URLhaus threat-feed collection
- Indicator normalization and deduplication
- URL and domain detection
- Threat scoring and severity classification
- VirusTotal enrichment
- Graceful API rate-limit handling
- SQLite persistence
- Indicator lookup and summaries
- CSV and JSON exports
- Human-readable and machine-readable reports
- Mock enrichment provider for testing
- Batch processing
- Automated test suite

## Architecture

```text
URLhaus
   |
   v
Collection -> Normalization -> Analysis -> Scoring
                                       |
                                       v
                                   Enrichment
                                       |
                                       v
                                     SQLite
                                       |
                                       v
                               Reports / Export
```

## Project Structure

```text
app/
|-- collectors/       Threat-feed collectors
|-- enrichment/       External intelligence providers
|-- processing/       Ingestion, normalization, analysis, scoring
|-- storage/          SQLite database and repository layer
|-- pipeline.py       Pipeline orchestration
|-- report.py         Reporting and export logic
`-- main.py           CLI entry point

tests/                 Automated test suite
data/                  Local runtime data
```

## Requirements

- Python 3.11+
- Internet access for threat-feed collection
- Optional VirusTotal API key for enrichment

## Installation

```powershell
git clone https://github.com/ATAF-png/threat-intel-automation.git
cd threat-intel-automation
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Show available commands:

```powershell
python -m app.main --help
```

Collect threat indicators:

```powershell
python -m app.main ingest --limit 100
```

View stored indicators:

```powershell
python -m app.main show --limit 10
```

View a database summary:

```powershell
python -m app.main summary
```

## Reporting and Export

Generate a report:

```powershell
python -m app.main report --limit 10
python -m app.main report --severity high --limit 10
python -m app.main report --classification malicious --limit 10
python -m app.main report --json --limit 10
```

Export indicators:

```powershell
python -m app.main export --output data/export.json --limit 100
```

## Indicator Lookup

```powershell
python -m app.main lookup example.com --type domain
```

## VirusTotal Enrichment

VirusTotal enrichment is optional. Configure the API key through an environment variable:

```powershell
$env:VT_API_KEY="your_api_key_here"
```

The application handles VirusTotal API rate limits gracefully and records enrichment failures without crashing the pipeline.
API credentials should never be committed to source control.

## Testing

Run the complete automated test suite with:

```powershell
pytest -q
```

The current test suite covers collection, ingestion, normalization, scoring, enrichment, database persistence, repository operations, reporting, CLI behavior, and batch processing.

## Data Handling

Runtime databases and generated exports are intentionally excluded from Git.

Ignored runtime data includes:

- SQLite databases
- JSON exports
- CSV exports
- Environment files
- Python virtual environments

## Example Workflow

```text
Collect -> Normalize -> Analyze -> Score -> Enrich -> Store -> Report
```

The pipeline is designed to separate collection, processing, enrichment, persistence, and reporting so individual components can be tested and extended independently.

## Limitations and Future Improvements

- Additional threat-feed integrations
- More enrichment providers
- Configurable scoring rules
- Scheduled automated collection
- Dashboard and visualization support
- Improved historical tracking and indicator lifecycle management

## License

This project is intended for educational, research, and defensive cybersecurity purposes.

[![Tests](https://github.com/ATAF-png/threat-intel-automation/actions/workflows/tests.yml/badge.svg)](https://github.com/ATAF-png/threat-intel-automation/actions/workflows/tests.yml)
