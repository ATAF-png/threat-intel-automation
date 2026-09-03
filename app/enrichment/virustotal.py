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
                    details={"status": 404},
                )

            if exc.code == 429:
                return EnrichmentResult(
                    provider=self.name,
                    available=False,
                    error="VirusTotal rate limit exceeded",
                    details={
                        "status": 429,
                        "retry_after": exc.headers.get(
                            "Retry-After"
                        ),
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

        return (
            f"{base_url}/{indicator.indicator_type.value}s/"
            f"{urllib.parse.quote(indicator.value, safe='')}"
        )

    def _parse_response(
        self,
        payload: dict,
    ) -> EnrichmentResult:
        data = payload.get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        if total:
            reputation_score = round(
                ((malicious + suspicious) / total) * 100
            )
        else:
            reputation_score = None

        if malicious > 0:
            classification = "malicious"
        elif suspicious > 0:
            classification = "suspicious"
        elif harmless > 0:
            classification = "benign"
        else:
            classification = "unknown"

        tags = attributes.get("tags", [])

        details = {
            "analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get(
                "last_analysis_date"
            ),
        }

        return EnrichmentResult(
            provider=self.name,
            available=True,
            reputation_score=reputation_score,
            classification=classification,
            tags=tags,
            details=details,
        )
