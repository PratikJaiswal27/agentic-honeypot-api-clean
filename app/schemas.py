from pydantic import BaseModel
from typing import Optional, Dict, Any

class HoneypotRequest(BaseModel):
    conversation_id: str
    turn: int
    message: str
    execution_mode: Optional[str] = "live"  # live | shadow


class HoneypotResponse(BaseModel):
    scam_detected: bool

    # 🔥 FIX IS HERE
    risk_score: str                 # was float, NOW STRING

    decision_confidence: str
    agent_reply: Optional[str] = None
    extracted_intelligence: Dict[str, Any] = {}
    engagement_metrics: Dict[str, Any] = {}
    explanation: Dict[str, Any] = {}
    termination_reason: Optional[str] = None
