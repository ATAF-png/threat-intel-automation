import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from app.enrichment.base import EnrichmentProvider
from app.enrichment.models import EnrichmentResult
from app.processing.models import Indicator


class VirusTotalProvider(EnrichmentProvider):
    """Enrich indicators using the VirusTotal API."""

    name = "virustotal"

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.getenv("VT_API_KEY")

    def enrich(
        self,
        indicator: Indicator,
    ) -> EnrichmentResult:
        if not self.api_key:
            return EnrichmentResult(
                provider=self.name,
                available=False,
                error="VT_API_KEY is not configured",
            )

        endpoint = self._build_endpoint(indicator)

        request = urllib.request.Request(
            endpoint,
            headers={
                "X-Apikey": self.api_key,
                "Accept": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                payload = json.loads(
                    response.read().decode("utf-8")
                )

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return EnrichmentResult(
                    provider=self.name,
                    available=True,
                    classification="unknown",
                    details={
                        "status": 404,
                        "message": "VirusTotal has no record for this indicator.",
                    },
                )

            if exc.code == 429:
                return EnrichmentResult(
                    provider=self.name,
                    available=False,
                    error="VirusTotal rate limit exceeded",
                    details={
                        "status": 429,
                        "retry_after": exc.headers.get("Retry-After"),
                    },
                )

            return EnrichmentResult(
                provider=self.name,
                available=False,
                error=f"VirusTotal HTTP {exc.code}",
                details={"status": exc.code},
            )

        except (urllib.error.URLError, TimeoutError) as exc:
            return EnrichmentResult(
                provider=self.name,
                available=False,
                error=f"VirusTotal request failed: {exc}",
            )

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return EnrichmentResult(
                provider=self.name,
                available=False,
                error=f"Invalid VirusTotal response: {exc}",
            )

        return self._parse_response(payload)

    def _build_endpoint(self, indicator: Indicator) -> str:
        base_url = "https://www.virustotal.com/api/v3"

        if indicator.indicator_type.value == "url":
            encoded = base64.urlsafe_b64encode(
                indicator.value.encode("utf-8")
            ).decode("ascii").rstrip("=")

            return f"{base_url}/urls/{encoded}"

        indicator_type = indicator.indicator_type.value

        plural_map = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "file": "files",
        }

        collection = plural_map.get(
            indicator_type,
            f"{indicator_type}s",
        )

        return (
            f"{base_url}/{collection}/"
            f"{urllib.parse.quote(indicator.value, safe='')}"
        )

    def _parse_response(
        self,
        payload: dict,
    ) -> EnrichmentResult:
        data = payload.get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = self._safe_int(stats.get("malicious"))
        suspicious = self._safe_int(stats.get("suspicious"))
        harmless = self._safe_int(stats.get("harmless"))
        undetected = self._safe_int(stats.get("undetected"))
        timeout = self._safe_int(stats.get("timeout"))

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
            + timeout
        )

        if total:
            detection_ratio = round(
                ((malicious + suspicious) / total) * 100,
                1,
            )
        else:
            detection_ratio = None

        if malicious > 0:
            classification = "malicious"
        elif suspicious > 0:
            classification = "suspicious"
        elif harmless > 0:
            classification = "benign"
        else:
            classification = "unknown"

        tags = self._clean_list(
            attributes.get("tags", [])
        )

        scanner_detections = self._extract_detections(
            attributes.get(
                "last_analysis_results",
                {},
            )
        )

        malware_names = self._extract_threat_names(
            scanner_detections
        )

        categories = attributes.get(
            "categories",
            {},
        )

        details = {
            # Core VT assessment
            "status": 200,
            "analysis_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "timeout": timeout,
                "total": total,
            },
            "detection_ratio": detection_ratio,
            "reputation": attributes.get("reputation"),
            "total_votes": attributes.get("total_votes", {}),

            # Explicit intelligence labels
            "tags": tags,
            "categories": categories,
            "malware_names": malware_names,

            # Scanner-level evidence
            "scanner_detections": scanner_detections,
            "malicious_detections": [
                detection
                for detection in scanner_detections
                if detection["category"] == "malicious"
            ],
            "suspicious_detections": [
                detection
                for detection in scanner_detections
                if detection["category"] == "suspicious"
            ],

            # Timing
            "first_submission_date": attributes.get(
                "first_submission_date"
            ),
            "last_submission_date": attributes.get(
                "last_submission_date"
            ),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
            "last_modification_date": attributes.get(
                "last_modification_date"
            ),
            "times_submitted": attributes.get(
                "times_submitted"
            ),

            # URL/web infrastructure
            "original_url": attributes.get("url"),
            "last_final_url": attributes.get(
                "last_final_url"
            ),
            "redirection_chain": self._clean_list(
                attributes.get(
                    "redirection_chain",
                    [],
                )
            ),
            "last_http_response_code": attributes.get(
                "last_http_response_code"
            ),
            "last_http_response_content_length": attributes.get(
                "last_http_response_content_length"
            ),
            "last_http_response_content_sha256": attributes.get(
                "last_http_response_content_sha256"
            ),
            "title": attributes.get("title"),
            "has_content": attributes.get("has_content"),

            # Web content/context
            "outgoing_links": self._clean_list(
                attributes.get(
                    "outgoing_links",
                    [],
                )
            ),
            "html_meta": attributes.get(
                "html_meta",
                {},
            ),
            "main_brand": attributes.get(
                "main_brand"
            ),
            "targeted_brand": attributes.get(
                "targeted_brand",
                {},
            ),

            # Tracking/context
            "trackers": attributes.get(
                "trackers",
                {},
            ),
        }

        return EnrichmentResult(
            provider=self.name,
            available=True,
            reputation_score=self._normalise_reputation(
                attributes.get("reputation")
            ),
            classification=classification,
            tags=tags,
            details=details,
        )

    @staticmethod
    def _safe_int(value) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalise_reputation(
        value,
    ) -> int | None:
        """
        Convert VT's community reputation score into
        the existing 0-100 enrichment field.

        VT reputation itself may be negative or positive,
        so it is preserved separately in details.
        """
        if value is None:
            return None

        try:
            reputation = int(value)
        except (TypeError, ValueError):
            return None

        if reputation <= 0:
            return 0

        return min(reputation, 100)

    @staticmethod
    def _clean_list(value) -> list[str]:
        if not isinstance(value, list):
            return []

        return [
            str(item)
            for item in value
            if item is not None
        ]

    @staticmethod
    def _extract_detections(
        results: dict,
    ) -> list[dict]:
        detections = []

        if not isinstance(results, dict):
            return detections

        for engine_name, result in results.items():
            if not isinstance(result, dict):
                continue

            category = result.get(
                "category",
                "unknown",
            )

            detections.append(
                {
                    "engine": result.get(
                        "engine_name",
                        engine_name,
                    ),
                    "category": category,
                    "method": result.get(
                        "method"
                    ),
                    "result": result.get(
                        "result"
                    ),
                }
            )

        detections.sort(
            key=lambda item: (
                item["category"] != "malicious",
                item["engine"],
            )
        )

        return detections

    @staticmethod
    def _extract_threat_names(
        detections: list[dict],
    ) -> list[str]:
        """
        Extract explicit threat/malware names returned
        by scanners.

        This intentionally does NOT infer a family from
        an IOC path, filename, or vague wording.
        """
        names = []

        for detection in detections:
            if detection["category"] not in {
                "malicious",
                "suspicious",
            }:
                continue

            result = detection.get("result")

            if not result:
                continue

            result = str(result).strip()

            if not result:
                continue

            if result.lower() in {
                "malicious",
                "suspicious",
                "phishing",
                "clean",
                "unrated",
            }:
                continue

            if result not in names:
                names.append(result)

        return names[:50]
