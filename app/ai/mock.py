from app.ai.base import AIProvider
from app.ai.models import AnalystReport, IOCAssessment


class MockAIProvider(AIProvider):
    """Deterministic analyst used for testing and offline operation."""

    name = "mock"

    def analyze(self, report: dict) -> AnalystReport:
        summary = report["summary"]
        indicators = report.get("priority_indicators", [])

        assessments = []

        for indicator in indicators:
            classification = indicator.get(
                "classification",
                "unknown",
            )

            severity = indicator.get(
                "severity",
                "low",
            )

            confidence = indicator.get(
                "confidence",
                0,
            )

            sources = indicator.get(
                "sources",
                [],
            )

            tags = indicator.get(
                "tags",
                [],
            )

            evidence = []

            if sources:
                evidence.append(
                    "Observed by intelligence source(s): "
                    + ", ".join(sources)
                )

            if tags:
                evidence.append(
                    "Associated tags: "
                    + ", ".join(tags)
                )

            evidence.append(
                f"Feed/enrichment classification: {classification}"
            )

            evidence.append(
                f"Recorded severity: {severity}"
            )

            assessment = (
                "No malicious conclusion can be established "
                "from the supplied evidence."
            )

            if classification == "malicious":
                assessment = (
                    "The supplied intelligence classifies this "
                    "indicator as malicious."
                )
            elif classification == "suspicious":
                assessment = (
                    "The supplied intelligence classifies this "
                    "indicator as suspicious and warrants investigation."
                )
            elif classification == "benign":
                assessment = (
                    "The supplied intelligence currently classifies "
                    "this indicator as benign."
                )

            actions = []

            if classification == "malicious":
                actions = [
                    "Block or quarantine the indicator where appropriate.",
                    "Search security telemetry for historical activity.",
                    "Investigate related infrastructure and affected assets.",
                ]
            elif classification == "suspicious":
                actions = [
                    "Investigate related activity in security telemetry.",
                    "Validate the indicator with additional intelligence.",
                ]
            else:
                actions = [
                    "Continue monitoring the indicator."
                ]

            assessments.append(
                IOCAssessment(
                    value=indicator["value"],
                    indicator_type=indicator["indicator_type"],
                    assessment=assessment,
                    evidence=evidence,
                    associated_threats=[],
                    confidence=confidence,
                    recommended_actions=actions,
                )
            )

        key_findings = []

        if summary["malicious"]:
            key_findings.append(
                f"{summary['malicious']} indicator(s) are "
                "classified as malicious."
            )

        if summary["suspicious"]:
            key_findings.append(
                f"{summary['suspicious']} indicator(s) are "
                "classified as suspicious."
            )

        if summary["critical"]:
            key_findings.append(
                f"{summary['critical']} indicator(s) have critical severity."
            )

        if not key_findings:
            key_findings.append(
                "No malicious or critical indicators were identified "
                "in the supplied report."
            )

        recommended_actions = [
            "Prioritize investigation of malicious and critical indicators.",
            "Correlate indicators against endpoint, DNS, proxy, firewall, "
            "and authentication telemetry.",
            "Validate high-confidence findings before taking disruptive action.",
        ]

        limitations = [
            "This assessment uses only evidence supplied in the report.",
            "No attribution or malware-family claim is made without explicit evidence.",
            "Unknown information is intentionally left unknown.",
            "The AI assessment does not replace analyst validation.",
        ]

        return AnalystReport(
            executive_summary=(
                f"The report contains {summary['total_indicators']} "
                f"indicators, including {summary['malicious']} malicious "
                f"and {summary['suspicious']} suspicious indicators."
            ),
            key_findings=key_findings,
            ioc_assessments=assessments,
            recommended_actions=recommended_actions,
            limitations=limitations,
        )
