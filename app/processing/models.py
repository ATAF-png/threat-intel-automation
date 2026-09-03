from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Indicator(BaseModel):
    value: str
    indicator_type: IndicatorType

    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    confidence: int = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.LOW

    enrichment: dict = Field(default_factory=dict)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )