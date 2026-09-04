from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph as ReportLabParagraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

from app.ai import get_ai_provider
from app.reporting.builder import build_report


DEFAULT_REPORT_DIR = Path("reports")
DEFAULT_DB_PATH = Path("data/threat_intel.db")


def pdf_safe_text(value) -> str:
    """Normalize generated Unicode to characters supported by Helvetica."""
    if value is None:
        return ""

    text = str(value)

    replacements = {
        "\u2022": "-",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
        "\u00ad": "",
        "\u00a0": " ",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text


def Paragraph(text, style, *args, **kwargs):
    return ReportLabParagraph(
        pdf_safe_text(text),
        style,
        *args,
        **kwargs,
    )


def _fmt(value, default="Not available"):
    if value is None or value == "":
        return default
    return pdf_safe_text(value)


def _join(values, default="Not available"):
    if not values:
        return default
    return ", ".join(pdf_safe_text(v) for v in values)


def _vt_details(indicator: dict) -> dict:
    enrichment = indicator.get("enrichment", {})

    if not isinstance(enrichment, dict):
        return {}

    vt = enrichment.get("virustotal", {})

    if not isinstance(vt, dict):
        return {}

    details = vt.get("details", {})

    if not isinstance(details, dict):
        return {}

    return details


def _vt_result(indicator: dict) -> dict:
    enrichment = indicator.get("enrichment", {})

    if not isinstance(enrichment, dict):
        return {}

    vt = enrichment.get("virustotal", {})

    if not isinstance(vt, dict):
        return {}

    return vt


def _format_unix_timestamp(value) -> str:
    if value in (None, "", 0):
        return "Unknown"

    try:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(
            float(value),
            tz=timezone.utc,
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value)


def _malware_names(indicator: dict) -> list[str]:
    details = _vt_details(indicator)

    names = details.get("malware_names", [])
    if not isinstance(names, list):
        return []

    generic = {
        "malware",
        "malicious",
        "phishing",
        "suspicious",
        "unknown",
        "unknown malware",
    }

    result = []

    for name in names:
        if not isinstance(name, str):
            continue

        cleaned = name.strip()

        if not cleaned or cleaned.lower() in generic:
            continue

        if cleaned not in result:
            result.append(cleaned)

    return result


def _malicious_detections(indicator: dict) -> list[dict]:
    details = _vt_details(indicator)

    detections = details.get(
        "malicious_detections",
        [],
    )

    if not isinstance(detections, list):
        return []

    return [
        detection
        for detection in detections
        if isinstance(detection, dict)
    ]


def _find_indicator(
    report: dict,
    value: str,
) -> dict | None:
    for indicator in report.get(
        "priority_indicators",
        [],
    ):
        if indicator.get("value") == value:
            return indicator

    return None


def _add_bullet_list(
    story,
    title: str,
    values: list[str],
    body_style,
    empty_text: str = "Not established from supplied evidence.",
):
    story.append(
        Paragraph(
            f"<b>{title}</b>",
            body_style,
        )
    )

    if values:
        for value in values:
            story.append(
                Paragraph(
                    f"- {value}",
                    body_style,
                )
            )
    else:
        story.append(
            Paragraph(
                empty_text,
                body_style,
            )
        )


def _build_vt_evidence_table(
    indicator: dict,
    small_style,
):
    vt = _vt_result(indicator)
    details = _vt_details(indicator)

    stats = details.get(
        "analysis_stats",
        {},
    )

    if not isinstance(stats, dict):
        stats = {}

    rows = [
        ["VirusTotal Evidence", "Value"],
        [
            "Classification",
            _fmt(vt.get("classification")),
        ],
        [
            "Detection Ratio",
            (
                f"{stats.get('malicious', 0)} malicious / "
                f"{stats.get('total', 0)} total"
            ),
        ],
        [
            "Detection Percentage",
            _fmt(
                details.get("detection_ratio"),
                "Not available",
            )
            if details.get("detection_ratio") is not None
            else "Not available",
        ],
        [
            "VT Reputation",
            _fmt(
                details.get("reputation"),
                "Not available",
            ),
        ],
        [
            "Malicious Detections",
            stats.get("malicious", 0),
        ],
        [
            "Suspicious Detections",
            stats.get("suspicious", 0),
        ],
        [
            "Harmless Detections",
            stats.get("harmless", 0),
        ],
        [
            "Undetected",
            stats.get("undetected", 0),
        ],
        [
            "First Submitted",
            _format_unix_timestamp(
                details.get("first_submission_date")
            ),
        ],
        [
            "Last Submitted",
            _format_unix_timestamp(
                details.get("last_submission_date")
            ),
        ],
        [
            "Last Analysed",
            _format_unix_timestamp(
                details.get("last_analysis_date")
            ),
        ],
        [
            "HTTP Response",
            _fmt(
                details.get(
                    "last_http_response_code"
                )
            ),
        ],
        [
            "Final URL",
            _fmt(
                details.get("last_final_url")
            ),
        ],
        [
            "Content SHA256",
            _fmt(
                details.get(
                    "last_http_response_content_sha256"
                )
            ),
        ],
        [
            "Content Length",
            _fmt(
                details.get(
                    "last_http_response_content_length"
                )
            ),
        ],
        [
            "Page Title",
            _fmt(
                details.get("title")
            ),
        ],
        [
            "Categories",
            _join(
                list(
                    details.get(
                        "categories",
                        {},
                    ).values()
                )
                if isinstance(
                    details.get(
                        "categories",
                        {},
                    ),
                    dict,
                )
                else []
            ),
        ],
        [
            "Tags",
            _join(
                details.get(
                    "tags",
                    [],
                )
            ),
        ],
    ]

    table = Table(
        [
            [
                Paragraph(
                    row[0],
                    small_style,
                ),
                Paragraph(
                    str(row[1]),
                    small_style,
                ),
            ]
            for row in rows
        ],
        colWidths=[
            45 * mm,
            120 * mm,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (0, -1),
                    colors.HexColor("#f3f4f6"),
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    return table


def _build_detection_table(
    indicator: dict,
    small_style,
):
    detections = _malicious_detections(
        indicator
    )

    if not detections:
        return None

    rows = [
        ["Engine", "Category", "Detection"]
    ]

    for detection in detections[:20]:
        rows.append(
            [
                Paragraph(
                    _fmt(
                        detection.get("engine"),
                        "Unknown",
                    ),
                    small_style,
                ),
                _fmt(
                    detection.get("category"),
                    "Unknown",
                ),
                Paragraph(
                    _fmt(
                        detection.get("result"),
                        "No detection name",
                    ),
                    small_style,
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            45 * mm,
            30 * mm,
            90 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    return table


def _build_ioc_section(
    story,
    assessment,
    indicator,
    styles,
):
    if "Small" not in styles:
        styles.add(
            ParagraphStyle(
                "Small",
                parent=styles["BodyText"],
                fontSize=7.5,
                leading=9.5,
                spaceAfter=2,
            )
        )

    small_style = styles["Small"]
    body_style = styles["BodyText"]

    value = assessment.value

    story.append(
        Paragraph(
            f"<b>{pdf_safe_text(value)}</b>",
            styles["Heading3"],
        )
    )

    metadata = [
        ["Field", "Assessment"],
        [
            "Type",
            pdf_safe_text(
                assessment.indicator_type
            ),
        ],
        [
            "Classification",
            pdf_safe_text(
                indicator.get(
                    "classification",
                    "unknown",
                )
            ),
        ],
        [
            "Severity",
            pdf_safe_text(
                indicator.get(
                    "severity",
                    "unknown",
                ).upper()
            ),
        ],
        [
            "Confidence",
            f"{assessment.confidence}/100",
        ],
        [
            "Source",
            _join(
                indicator.get(
                    "sources",
                    [],
                )
            ),
        ],
        [
            "First Seen",
            _fmt(
                indicator.get(
                    "first_seen"
                )
            ),
        ],
        [
            "Last Seen",
            _fmt(
                indicator.get(
                    "last_seen"
                )
            ),
        ],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            40 * mm,
            125 * mm,
        ],
    )

    metadata_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "BACKGROUND",
                    (0, 1),
                    (0, -1),
                    colors.HexColor("#f3f4f6"),
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (0, -1),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(metadata_table)
    story.append(Spacer(1, 5))

    # -----------------------------------------------------
    # Analyst Assessment
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Analyst Assessment</b>",
            body_style,
        )
    )

    story.append(
        Paragraph(
            assessment.assessment,
            body_style,
        )
    )

    story.append(Spacer(1, 4))

    # -----------------------------------------------------
    # Threat / Malware Family
    # -----------------------------------------------------

    # Only use explicit malware-family evidence here.
    # Do not use AI associated_threats because those may contain
    # generic source tags such as "ip", "downloads-elf", or "ns-port".
    threats = _malware_names(indicator)

    _add_bullet_list(
        story,
        "Threat / Malware Family",
        threats,
        body_style,
        (
            "No specific malware family was established from "
            "the supplied evidence."
        ),
    )

    story.append(Spacer(1, 4))

    # -----------------------------------------------------
    # Why malicious
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "<b>Why This IOC Is Malicious / Suspicious</b>",
            body_style,
        )
    )

    for evidence in assessment.evidence:
        story.append(
            Paragraph(
                f"- {evidence}",
                body_style,
            )
        )

    # -----------------------------------------------------
    # VirusTotal
    # -----------------------------------------------------

    vt = _vt_result(indicator)

    if vt:
        story.append(Spacer(1, 4))
        story.append(
            Paragraph(
                "<b>VirusTotal Evidence</b>",
                body_style,
            )
        )

        story.append(
            _build_vt_evidence_table(
                indicator,
                small_style,
            )
        )

        detection_table = _build_detection_table(
            indicator,
            small_style,
        )

        if detection_table:
            story.append(Spacer(1, 4))
            story.append(
                Paragraph(
                    "<b>Malicious Scanner Detections</b>",
                    body_style,
                )
            )
            story.append(detection_table)

    # -----------------------------------------------------
    # Infrastructure
    # -----------------------------------------------------

    details = _vt_details(indicator)

    infrastructure = []

    final_url = details.get(
        "last_final_url"
    )

    if final_url:
        infrastructure.append(
            f"Final URL: {final_url}"
        )

    redirects = details.get(
        "redirection_chain",
        [],
    )

    if redirects:
        infrastructure.append(
            "Redirect chain: "
            + " -> ".join(
                str(x)
                for x in redirects[:10]
            )
        )

    http_code = details.get(
        "last_http_response_code"
    )

    if http_code:
        infrastructure.append(
            f"HTTP response: {http_code}"
        )

    categories = details.get(
        "categories",
        {},
    )

    if isinstance(categories, dict):
        category_values = [
            str(value)
            for value in categories.values()
            if value
        ]

        if category_values:
            infrastructure.append(
                "Categories: "
                + ", ".join(
                    category_values
                )
            )

    _add_bullet_list(
        story,
        "Infrastructure / Delivery Context",
        infrastructure,
        body_style,
    )

    # -----------------------------------------------------
    # Recommended Actions
    # -----------------------------------------------------

    _add_bullet_list(
        story,
        "Recommended Mitigation",
        assessment.recommended_actions,
        body_style,
    )

    story.append(Spacer(1, 4))

    # -----------------------------------------------------
    # IOC limitations
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "<b>IOC Limitations</b>",
            body_style,
        )
    )

    if not threats:
        story.append(
            Paragraph(
                "- Malware family is not established by the supplied evidence.",
                small_style,
            )
        )

    story.append(
        Paragraph(
            "- Threat actor attribution should not be assumed without supporting intelligence.",
            small_style,
        )
    )

    story.append(Spacer(1, 10))


def generate_pdf_report(
    db_path: Path = DEFAULT_DB_PATH,
    output_dir: Path = DEFAULT_REPORT_DIR,
    limit: int = 10,
    since: str | None = None,
) -> Path:
    """Generate a customer-facing threat intelligence PDF."""

    report = build_report(
        db_path=db_path,
        limit=limit,
        since=since,
    )

    analyst = get_ai_provider().analyze(report)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = (
        report["generated_at"]
        .replace(":", "")
        .replace("-", "")
        .replace("+00:00", "Z")
    )

    output_path = (
        output_dir
        / f"threat_intelligence_{timestamp}.pdf"
    )

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title="Threat Intelligence Report",
        author="Threat Intelligence Automation",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        leading=26,
        spaceAfter=12,
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=17,
        spaceBefore=12,
        spaceAfter=7,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=3,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=7.5,
        leading=9.5,
        spaceAfter=2,
    )

    story = []

    # =====================================================
    # COVER / EXECUTIVE SUMMARY
    # =====================================================

    story.append(
        Paragraph(
            "Threat Intelligence Report",
            title_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Generated:</b> "
            f"{pdf_safe_text(report['generated_at'])}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Database:</b> "
            f"{pdf_safe_text(report['database'])}",
            body_style,
        )
    )

    story.append(Spacer(1, 8))

    story.append(
        Paragraph(
            "Executive Summary",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            analyst.executive_summary,
            body_style,
        )
    )

    summary = report["summary"]

    summary_data = [
        ["Metric", "Count"],
        [
            "Total Indicators",
            summary["total_indicators"],
        ],
        ["Critical", summary["critical"]],
        ["High", summary["high"]],
        ["Medium", summary["medium"]],
        ["Low", summary["low"]],
        ["Malicious", summary["malicious"]],
        ["Suspicious", summary["suspicious"]],
        ["Benign", summary["benign"]],
        ["Unknown", summary["unknown"]],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            80 * mm,
            35 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "RIGHT",
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
            ]
        )
    )

    story.append(summary_table)

    # =====================================================
    # KEY FINDINGS
    # =====================================================

    story.append(
        Paragraph(
            "Key Findings",
            heading_style,
        )
    )

    for finding in analyst.key_findings:
        story.append(
            Paragraph(
                f"- {finding}",
                body_style,
            )
        )

    # =====================================================
    # SOURCES
    # =====================================================

    story.append(
        Paragraph(
            "Intelligence Sources",
            heading_style,
        )
    )

    source_data = [
        ["Source", "Indicators"]
    ]

    for source, count in report["sources"].items():
        source_data.append(
            [
                pdf_safe_text(source),
                count,
            ]
        )

    if len(source_data) == 1:
        source_data.append(
            ["None", 0]
        )

    source_table = Table(
        source_data,
        colWidths=[
            100 * mm,
            35 * mm,
        ],
    )

    source_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "RIGHT",
                ),
            ]
        )
    )

    story.append(source_table)

    # =====================================================
    # PRIORITY SUMMARY
    # =====================================================

    story.append(
        Paragraph(
            "Highest Priority Indicators",
            heading_style,
        )
    )

    indicator_data = [
        [
            "Severity",
            "Class",
            "Conf.",
            "Type",
            "IOC",
            "Sources",
        ]
    ]

    for indicator in report[
        "priority_indicators"
    ]:
        indicator_data.append(
            [
                pdf_safe_text(
                    indicator["severity"].upper()
                ),
                pdf_safe_text(
                    indicator["classification"]
                ),
                str(
                    indicator["confidence"]
                ),
                pdf_safe_text(
                    indicator["indicator_type"]
                ),
                Paragraph(
                    indicator["value"],
                    small_style,
                ),
                Paragraph(
                    _join(
                        indicator["sources"]
                    ),
                    small_style,
                ),
            ]
        )

    if len(indicator_data) == 1:
        indicator_data.append(
            [
                "-",
                "-",
                "-",
                "-",
                "No indicators",
                "-",
            ]
        )

    indicator_table = Table(
        indicator_data,
        colWidths=[
            20 * mm,
            22 * mm,
            15 * mm,
            18 * mm,
            55 * mm,
            35 * mm,
        ],
        repeatRows=1,
    )

    indicator_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    story.append(indicator_table)

    # =====================================================
    # IOC DETAIL ASSESSMENTS
    # =====================================================

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Detailed IOC Assessments",
            heading_style,
        )
    )

    for assessment in analyst.ioc_assessments:
        indicator = _find_indicator(
            report,
            assessment.value,
        )

        if not indicator:
            continue

        _build_ioc_section(
            story,
            assessment,
            indicator,
            styles,
        )

    # =====================================================
    # CROSS-SOURCE CORRELATION
    # =====================================================

    story.append(
        Paragraph(
            "Cross-Source Correlation",
            heading_style,
        )
    )

    correlated = report[
        "correlated_indicators"
    ]

    correlation_data = [
        [
            "IOC",
            "Type",
            "Severity",
            "Confidence",
            "Sources",
        ]
    ]

    for indicator in correlated:
        correlation_data.append(
            [
                Paragraph(
                    indicator["value"],
                    small_style,
                ),
                pdf_safe_text(
                    indicator["indicator_type"]
                ),
                pdf_safe_text(
                    indicator["severity"]
                ),
                str(
                    indicator["confidence"]
                ),
                Paragraph(
                    _join(
                        indicator["sources"]
                    ),
                    small_style,
                ),
            ]
        )

    if len(correlation_data) == 1:
        correlation_data.append(
            [
                "No cross-source indicators found",
                "-",
                "-",
                "-",
                "-",
            ]
        )

    correlation_table = Table(
        correlation_data,
        colWidths=[
            55 * mm,
            20 * mm,
            25 * mm,
            25 * mm,
            50 * mm,
        ],
        repeatRows=1,
    )

    correlation_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1f2937"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    story.append(correlation_table)

    # =====================================================
    # GLOBAL RECOMMENDATIONS
    # =====================================================

    story.append(
        Paragraph(
            "Recommended Actions",
            heading_style,
        )
    )

    for action in analyst.recommended_actions:
        story.append(
            Paragraph(
                f"- {action}",
                body_style,
            )
        )

    # =====================================================
    # LIMITATIONS
    # =====================================================

    story.append(
        Paragraph(
            "Analyst Limitations",
            heading_style,
        )
    )

    for limitation in analyst.limitations:
        story.append(
            Paragraph(
                f"- {limitation}",
                small_style,
            )
        )

    document.build(story)

    return output_path
