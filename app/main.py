from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
load_dotenv()

from .schemas import HoneypotRequest, HoneypotResponse
from .memory import get_history, append_message
from .signals import hard_signal_scan, soft_signal_placeholder
from .policy import policy_gate
from .agent import generate_agent_reply
from .extractor import extract_intel
from .validator import extract_authority_claim, validate_authority_claim

app = FastAPI(title="Agentic Honeypot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "agentic-honeypot-api",
        "message": "API is live. Use POST /honeypot"
    }

@app.post("/", response_model=HoneypotResponse)
def root_post(req: HoneypotRequest):
    return honeypot_endpoint_logic(req)

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(req: HoneypotRequest):
    return honeypot_endpoint_logic(req)

def honeypot_endpoint_logic(req: HoneypotRequest):
    history = get_history(req.conversation_id)
    append_message(req.conversation_id, "scammer", req.message)
    history = get_history(req.conversation_id)
    
    hard = hard_signal_scan(req.message)
    soft = soft_signal_placeholder(req.message)
    
    claimed = extract_authority_claim(req.message)
    validation = validate_authority_claim(claimed)
    
    decision = policy_gate(hard=hard, soft=soft, validation=validation)
    
    agent_reply = None
    if req.execution_mode == "live":
        history = get_history(req.conversation_id)
        agent_reply = generate_agent_reply(history)
        append_message(req.conversation_id, "agent", agent_reply)
    
    intel = extract_intel(req.message)
    
    return HoneypotResponse(
        scam_detected=decision.get("scam", False),
        risk_score=decision.get("risk", "UNKNOWN"),
        decision_confidence=decision.get("confidence", "low"),
        agent_reply=agent_reply,
        extracted_intelligence=intel,
        engagement_metrics={
            "turn": req.turn,
            "history_length": len(history)
        },
        explanation={
            "risk_band": decision.get("risk_band"),
            "reasons": decision.get("reasons", []),
            "hard_signals": hard,
            "soft_signals": soft,
            "validation": validation
        }
    )
    