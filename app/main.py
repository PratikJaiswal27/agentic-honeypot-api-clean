from fastapi import FastAPI, Request
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

# 🔥 response_model REMOVED
@app.post("/")
async def root_post(req: HoneypotRequest):
    result = honeypot_endpoint_logic(req)
    return result  # Direct dict return, no Pydantic validation

# 🔥 response_model REMOVED
@app.post("/honeypot")
async def honeypot_endpoint(req: HoneypotRequest):
    result = honeypot_endpoint_logic(req)
    return result

@app.post("/debug")
async def debug_endpoint(request: Request):
    """GUVI ka raw payload capture karne ke liye"""
    body = await request.body()
    headers = dict(request.headers)
    
    return {
        "received_body": body.decode('utf-8'),
        "content_type": headers.get("content-type"),
        "all_headers": headers,
        "method": request.method
    }

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
    
    # 🔥 Return plain dict instead of HoneypotResponse object
    return {
        "scam_detected": decision.get("scam", False),
        "risk_score": decision.get("risk", "UNKNOWN"),
        "decision_confidence": decision.get("confidence", "low"),
        "agent_reply": agent_reply,
        "extracted_intelligence": intel or {},  # 🔥 Ensure dict, not None
        "engagement_metrics": {
            "turn": req.turn,
            "history_length": len(history)
        },
        "explanation": {
            "risk_band": decision.get("risk_band"),
            "reasons": decision.get("reasons", []) or [],  # 🔥 Ensure list
            "hard_signals": hard or {},
            "soft_signals": soft or {},
            "validation": validation or {}
        }
    }