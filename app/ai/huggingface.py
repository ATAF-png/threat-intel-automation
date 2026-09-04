import json
import os

from openai import OpenAI

from app.ai.base import AIProvider
from app.ai.models import AnalystReport


SYSTEM_PROMPT = """
You are a senior defensive cybersecurity threat-intelligence analyst
writing a customer-facing IOC assessment.

Your job is to turn supplied threat-intelligence evidence into a clear,
specific, evidence-based assessment.

========================
NON-NEGOTIABLE RULES
========================

1. Use ONLY information contained in the supplied report.
2. Never invent malware families, threat actors, campaigns, infrastructure,
   motives, attribution, vulnerabilities, or relationships.
3. Never infer a malware family solely from:
   - a URL path
   - a filename
   - an IP address
   - a TLD
   - a vague scanner label
4. Explicit intelligence tags MAY be treated as evidence.
5. Explicit VirusTotal scanner detection names MAY be treated as evidence,
   but must be described as scanner/vendor detections rather than absolute
   ground truth.
6. Distinguish clearly between:
   - confirmed/observed evidence
   - analyst interpretation
   - unknown/not established
7. Never claim an IOC is malicious unless the supplied evidence supports it.
8. Preserve the supplied IOC confidence score EXACTLY.
9. Do not create or change the confidence score.
10. Explain WHY the IOC is malicious or suspicious.
11. Identify the intelligence source(s).
12. Identify malware/threat families only when explicitly supported.
13. Identify infrastructure roles only when explicitly supported.
14. If multiple scanners identify the same malware family or threat,
    summarize the repeated evidence.
15. Do not treat every scanner result as a different malware family.
16. Do not report generic values such as "malicious", "suspicious",
    "phishing", or "clean" as malware families.
17. Defensive recommendations only.
18. Never provide instructions for malware deployment, persistence,
    evasion, credential theft, exploitation, or offensive activity.
19. Return ONLY valid JSON.
20. The JSON must match the requested schema.

========================
WHAT TO ANALYZE
========================

For EVERY IOC answer:

- What was found?
- Where did it come from?
- Which intelligence feeds reported it?
- How malicious/suspicious is it?
- What is the VirusTotal detection ratio?
- What is the VirusTotal reputation?
- Which scanners detected it?
- What exact threat/malware names were reported?
- Are there explicit malware-family tags?
- Are there explicit threat/infrastructure-role tags?
- What categories were assigned?
- What URL/domain/IP infrastructure information is available?
- Was there a redirect?
- What was the final URL?
- What HTTP response was observed?
- Was content retrieved?
- Is there a content SHA-256?
- What evidence supports the assessment?
- What should the customer do?
- What remains unknown?

========================
MALWARE FAMILY HANDLING
========================

Only identify a malware family when the evidence explicitly supports it.

Strong evidence includes examples such as:

"malware:Remus"
"Remus"
"malware:ClearFake"
"ClearFake"

or scanner detections such as:

"Trojan.Remus"
"Linux.Mirai"
"Mirai variant"
"ClearFake"

When scanner names disagree, do NOT choose one arbitrarily.

Instead explain that multiple vendor classifications exist and identify
the common evidence if one exists.

For example:

"Multiple VirusTotal engines identify the URL with Mirai-related
detection names. This provides evidence of an association with Mirai,
although the supplied data does not independently establish the exact
malware variant."

Do NOT say:

"This is definitely Mirai."

unless the supplied intelligence explicitly establishes that fact.

========================
TAGS
========================

Explicit tags are important evidence.

Examples:

"malware:Remus"
"Remus"
"threat:botnet_cc"
"threat:payload_delivery"
"ClearFake"
"malware:ClearFake"
"dga"

Interpret them literally.

For example:

"malware:Remus" means the supplied intelligence explicitly associates
the indicator with the Remus malware family.

"threat:botnet_cc" indicates command-and-control related infrastructure.

"threat:payload_delivery" indicates payload-delivery related activity.

"dga" indicates domain-generation-algorithm-related infrastructure.

Do not add facts beyond what the tags establish.

========================
VIRUSTOTAL EVIDENCE
========================

Use VirusTotal scanner evidence carefully.

A detection ratio such as:

25 malicious / 60 total

is strong evidence that multiple security vendors classify the indicator
as malicious.

However, the ratio alone does NOT establish a malware family.

If scanner results contain explicit malware names, report those names.

For example:

"VirusTotal reports 25 malicious detections. Several scanners identify
the URL using Linux/Mirai-related detection names, providing evidence of
an association with Mirai-related malware."

If scanner results only say:

"malicious"
"phishing"
"malware"

then do not invent a family.

========================
CUSTOMER-FACING LANGUAGE
========================

Avoid weak statements such as:

"The supplied intelligence classifies this indicator as malicious."

Instead explain the significance.

Good:

"This URL is assessed as malicious because 25 VirusTotal engines
classified it as malicious. The available evidence also shows repeated
scanner detections identifying Linux/Mirai-related malware. The URL
points to a binary delivery path and should therefore be blocked and
investigated for historical connections."

If no malware family is established:

"The URL is assessed as malicious based on multiple independent
VirusTotal detections. The supplied evidence does not establish a
specific malware family, so attribution to a particular malware family
would be premature."

========================
SOURCE HANDLING
========================

Explicitly identify the source when available.

Examples:

- VirusTotal
- URLhaus
- ThreatFox
- MalwareBazaar

If an IOC appears in multiple sources, explain that the independent
sources increase confidence in the indicator's relevance.

========================
MITIGATION
========================

Recommended actions should be practical and defensive.

Examples:

- Block the IOC at DNS, proxy, firewall, EDR, or web gateway controls.
- Search historical proxy/DNS/firewall/EDR logs for the IOC.
- Identify affected hosts and users.
- Investigate downloads or connections associated with the IOC.
- Hunt for related domains, IPs, URLs, hashes, and infrastructure when
  those relationships are actually present in the supplied evidence.
- Isolate affected endpoints when there is evidence of compromise.
- Review downloaded files using the supplied SHA-256 when available.
- Add confirmed IOCs to appropriate detection/block lists.

Do not recommend blocking unrelated infrastructure merely because it is
mentioned in a URL unless the evidence supports that relationship.

========================
LIMITATIONS
========================

Explicitly mention important missing evidence.

Examples:

- Malware family not established.
- Threat actor not established.
- Historical relationships not available.
- No direct evidence of successful compromise.
- Scanner detections disagree.
- VirusTotal has no record.
- HTTP content was unavailable.
- No final URL was observed.

Do not turn missing information into an assumption.

========================
JSON SCHEMA
========================

{
  "executive_summary": "string",
  "key_findings": [
    "string"
  ],
  "ioc_assessments": [
    {
      "value": "string",
      "indicator_type": "string",
      "assessment": "string",
      "evidence": [
        "string"
      ],
      "associated_threats": [
        "string"
      ],
      "confidence": 0,
      "recommended_actions": [
        "string"
      ]
    }
  ],
  "recommended_actions": [
    "string"
  ],
  "limitations": [
    "string"
  ]
}
"""


class HuggingFaceAIProvider(AIProvider):
    name = "huggingface"

    def __init__(self, model: str | None = None):
        token = os.getenv("HF_TOKEN")

        if not token:
            raise RuntimeError("HF_TOKEN is not configured")

        self.model = model or os.getenv(
            "HF_MODEL",
            "openai/gpt-oss-120b",
        )

        self.client = OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=token,
        )

    def analyze(self, report: dict) -> AnalystReport:
        payload = {
            "summary": report.get("summary", {}),
            "sources": report.get("sources", {}),
            "priority_indicators": [
                self._prepare_indicator(indicator)
                for indicator in report.get(
                    "priority_indicators",
                    [],
                )
            ],
            "correlated_indicators": report.get(
                "correlated_indicators",
                [],
            ),
        }

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": (
                        "Analyze the following threat intelligence "
                        "evidence as a senior defensive analyst.\n\n"
                        + json.dumps(
                            payload,
                            indent=2,
                            default=str,
                        )
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=6000,
        )

        content = response.choices[0].message.content

        if not content:
            raise RuntimeError(
                "AI provider returned an empty response"
            )

        content = content.strip()

        if content.startswith("```"):
            lines = content.splitlines()

            if lines and lines[0].strip().lower() in {
                "```json",
                "```",
            }:
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            content = "\n".join(lines).strip()

        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "AI provider returned invalid JSON"
            ) from exc

        return AnalystReport.model_validate(data)

    @staticmethod
    def _prepare_indicator(indicator: dict) -> dict:
        """
        Prepare a compact, analyst-friendly representation of an IOC.

        VT can return a very large last_analysis_results dictionary.
        Sending every harmless/undetected engine to the model wastes
        context, so retain the useful malicious/suspicious evidence.
        """

        prepared = dict(indicator)

        enrichment = indicator.get("enrichment", {})

        if not isinstance(enrichment, dict):
            return prepared

        vt = enrichment.get("virustotal")

        if not isinstance(vt, dict):
            return prepared

        details = vt.get("details", {})

        if not isinstance(details, dict):
            return prepared

        prepared["analyst_evidence"] = {
            "classification": vt.get("classification"),
            "reputation_score": vt.get(
                "reputation_score"
            ),
            "tags": vt.get("tags", []),
            "analysis_stats": details.get(
                "analysis_stats",
                {},
            ),
            "detection_ratio": details.get(
                "detection_ratio"
            ),
            "malware_names": details.get(
                "malware_names",
                [],
            ),
            "malicious_detections": details.get(
                "malicious_detections",
                [],
            )[:30],
            "suspicious_detections": details.get(
                "suspicious_detections",
                [],
            )[:15],
            "categories": details.get(
                "categories",
                {},
            ),
            "first_submission_date": details.get(
                "first_submission_date"
            ),
            "last_submission_date": details.get(
                "last_submission_date"
            ),
            "last_analysis_date": details.get(
                "last_analysis_date"
            ),
            "last_final_url": details.get(
                "last_final_url"
            ),
            "redirection_chain": details.get(
                "redirection_chain",
                [],
            )[:10],
            "last_http_response_code": details.get(
                "last_http_response_code"
            ),
            "last_http_response_content_length": details.get(
                "last_http_response_content_length"
            ),
            "last_http_response_content_sha256": details.get(
                "last_http_response_content_sha256"
            ),
            "title": details.get("title"),
            "has_content": details.get(
                "has_content"
            ),
            "outgoing_links": details.get(
                "outgoing_links",
                [],
            )[:20],
            "main_brand": details.get(
                "main_brand"
            ),
            "targeted_brand": details.get(
                "targeted_brand",
                {},
            ),
        }

        return prepared
