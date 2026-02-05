from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
load_dotenv()

from .schemas import HoneypotRequest
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

# 🔥 ROOT POST - /debug jaisa loose validation
@app.post("/")
async def root_post(request: Request):
    """
    Universal handler - kuch bhi accept karega
    """
    try:
        body = await request.json()
    except:
        body = {}
    
    # Extract fields manually with defaults
    req_data = HoneypotRequest(
        conversation_id=body.get("conversation_id", "default"),
        turn=body.get("turn", 1),
        message=body.get("message", ""),
        execution_mode=body.get("execution_mode", "live")
    )
    
    return honeypot_endpoint_logic(req_data)

# 🔥 HONEYPOT - same loose validation
@app.post("/honeypot")
async def honeypot_endpoint(request: Request):
    try:
        body = await request.json()
    except:
        body = {}
    
    req_data = HoneypotRequest(
        conversation_id=body.get("conversation_id", "default"),
        turn=body.get("turn", 1),
        message=body.get("message", ""),
        execution_mode=body.get("execution_mode", "live")
    )
    
    return honeypot_endpoint_logic(req_data)

@app.post("/debug")
async def debug_endpoint(request: Request):
    """Debugging endpoint"""
    body = await request.body()
    headers = dict(request.headers)
    
    return {
        "received_body": body.decode('utf-8'),
        "content_type": headers.get("content-type"),
        "all_headers": headers,
        "method": request.method
    }

def honeypot_endpoint_logic(req: HoneypotRequest):
    """Core logic - dict return (no Pydantic validation)"""
    
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
    
    # Plain dict return
    return {
        "scam_detected": decision.get("scam", False),
        "risk_score": decision.get("risk", "UNKNOWN"),
        "decision_confidence": decision.get("confidence", "low"),
        "agent_reply": agent_reply,
        "extracted_intelligence": intel if isinstance(intel, dict) else {},
        "engagement_metrics": {
            "turn": req.turn if req.turn else 1,
            "history_length": len(history) if history else 0
        },
        "explanation": {
            "risk_band": decision.get("risk_band", "unknown"),
            "reasons": decision.get("reasons", []) if decision.get("reasons") else [],
            "hard_signals": hard if isinstance(hard, dict) else {},
            "soft_signals": soft if isinstance(soft, dict) else {},
            "validation": validation if isinstance(validation, dict) else {}
        }
    }