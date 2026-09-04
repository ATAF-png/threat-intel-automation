from pydantic import BaseModel, Field


class IOCAssessment(BaseModel):
    value: str
    indicator_type: str
    assessment: str
    evidence: list[str] = Field(default_factory=list)
    associated_threats: list[str] = Field(default_factory=list)
    confidence: int = Field(ge=0, le=100)
    recommended_actions: list[str] = Field(default_factory=list)


class AnalystReport(BaseModel):
    executive_summary: str
    key_findings: list[str] = Field(default_factory=list)
    ioc_assessments: list[IOCAssessment] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
