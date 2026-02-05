from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, Union

class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    conversation_id: Optional[str] = Field(default="default")
    turn: Optional[Union[int, str]] = Field(default=1)
    message: str = Field(default="")
    execution_mode: Optional[str] = Field(default="live")


class HoneypotResponse(BaseModel):
    scam_detected: bool
    risk_score: str
    decision_confidence: str
    agent_reply: Optional[str] = None

    extracted_intelligence: Dict[str, Any] = Field(default_factory=dict)
    engagement_metrics: Dict[str, Any] = Field(default_factory=dict)
    explanation: Dict[str, Any] = Field(default_factory=dict)

    termination_reason: Optional[str] = None