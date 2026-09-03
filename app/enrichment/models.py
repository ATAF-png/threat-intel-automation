from pydantic import BaseModel, Field


class EnrichmentResult(BaseModel):
    """Normalized result returned by an enrichment provider."""

    provider: str
    available: bool = True

    reputation_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    classification: str | None = None

    country: str | None = None
    asn: str | None = None

    tags: list[str] = Field(default_factory=list)

    details: dict = Field(default_factory=dict)

    error: str | None = None
