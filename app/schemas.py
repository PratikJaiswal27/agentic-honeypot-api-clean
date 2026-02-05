# app/schemas.py
from pydantic import BaseModel
from typing import Optional, Dict, Any, Union

class HoneypotRequest(BaseModel):
    conversation_id: Optional[str] = None   # 🔥 tolerant for testers
    turn: Union[int, str]                   # 🔥 testers sometimes send string
    message: str
    execution_mode: Optional[str] = "live"


class HoneypotResponse(BaseModel):
    scam_detected: bool
    risk_score: str                         # LOW / MEDIUM / HIGH / CRITICAL
    decision_confidence: str
    agent_reply: Optional[str] = None
    extracted_intelligence: Dict[str, Any] = {}
    engagement_metrics: Dict[str, Any] = {}
    explanation: Dict[str, Any] = {}
    termination_reason: Optional[str] = None
