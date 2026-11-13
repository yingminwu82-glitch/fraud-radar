from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class AIReportBody(BaseModel):
    regenerate: bool = False

class AIReportContent(BaseModel):
    executive_summary: str
    overall_interpretation: str
    sections: dict[str,str]
    multi_source_analysis: str
    risk_contribution_analysis: str
    user_preference_impact: str
    positive_signals: list[str]
    limitations: list[str]
    recommended_actions: list[str]
    key_risk_drivers: list[str]
    confidence_explanation: str

    @model_validator(mode="after")
    def requires_all_risk_sections(self):
        required={"ip_reputation","network_anonymity","malicious_infrastructure","geographic_risk","transaction_behavior","account_characteristics"}
        if not required.issubset(self.sections): raise ValueError("AI report is missing required category sections")
        values=[self.executive_summary,self.overall_interpretation,self.multi_source_analysis,self.risk_contribution_analysis,self.user_preference_impact,self.confidence_explanation,*self.sections.values(),*self.positive_signals,*self.limitations,*self.recommended_actions,*self.key_risk_drivers]
        if any(len(value)>4000 for value in values) or any(len(items)>30 for items in (self.positive_signals,self.limitations,self.recommended_actions,self.key_risk_drivers)):
            raise ValueError("AI report content exceeds the allowed size")
        return self

class AIReportRead(BaseModel):
    id: int
    analysis_id: int
    model_name: str
    report: dict
    created_at: datetime
    updated_at: datetime

class ChatRequest(BaseModel):
    question: str = Field(min_length=1,max_length=1000)
    session_id: int | None = None
    context_type: Literal["report", "provider_evidence"] = "report"

class ChatResponse(BaseModel):
    analysis_id: int
    session_id: int
    answer: str
    created_at: datetime

class ChatHistoryItem(BaseModel):
    role: Literal["user","assistant"]
    content: str
    created_at: datetime

class ChatHistoryRead(BaseModel):
    analysis_id: int
    session_id: int
    messages: list[ChatHistoryItem]
