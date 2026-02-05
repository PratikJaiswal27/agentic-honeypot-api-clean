# app/schemas.py
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, Dict, Any, Union

class HoneypotRequest(BaseModel):
    model_config = ConfigDict(extra="allow")  # 🔥 accept unknown fields

    conversation_id: Optional[str] = None
    turn: Optional[Union[int, str]] = None    # 🔥 NOT required
    message: str                              # 🔥 ONLY required field
    execution_mode: Optional[str] = "live"


class HoneypotResponse(BaseModel):
    scam_detected: bool
    risk_score: str
    decision_confidence: str
    agent_reply: Optional[str] = None

    extracted_intelligence: Dict[str, Any] = Field(default_factory=dict)
    engagement_metrics: Dict[str, Any] = Field(default_factory=dict)
    explanation: Dict[str, Any] = Field(default_factory=dict)

    termination_reason: Optional[str] = None
