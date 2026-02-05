from fastapi import FastAPI, Depends
from dotenv import load_dotenv
load_dotenv()

from .schemas import HoneypotRequest, HoneypotResponse
from .auth import verify_api_key
from .memory import get_history, append_message
from .signals import hard_signal_scan, soft_signal_placeholder
from .policy import policy_gate
from .agent import generate_agent_reply
from .extractor import extract_intel
from .validator import extract_authority_claim, validate_authority_claim

app = FastAPI(title="Agentic Honeypot API")

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "agentic-honeypot-api",
        "message": "API is live. Use POST /honeypot"
    }
# ✅ 2️⃣ Root POST (GUVI evaluator hits THIS)
@app.post("/", response_model=HoneypotResponse)
def root_post(
    req: HoneypotRequest,
    _=Depends(verify_api_key)
):
    # 🔥 SAME logic as /honeypot
    return honeypot_endpoint(req)

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot_endpoint(
    req: HoneypotRequest,
    _=Depends(verify_api_key)
):
    

    # 0️⃣ Fetch current history
    history = get_history(req.conversation_id)

    # 1️⃣ Append SCAMMER message FIRST
    append_message(req.conversation_id, "scammer", req.message)

    # 2️⃣ Re-fetch UPDATED history
    history = get_history(req.conversation_id)

    # 3️⃣ Signal extraction
    hard = hard_signal_scan(req.message)
    soft = soft_signal_placeholder(req.message)

    # 4️⃣ Authority validation
    claimed = extract_authority_claim(req.message)
    validation = validate_authority_claim(claimed)

    # 5️⃣ Final decision
    decision = policy_gate(
        hard=hard,
        soft=soft,
        validation=validation
    )

    # 6️⃣ Agent engagement
    agent_reply = None
    if req.execution_mode == "live":
        history = get_history(req.conversation_id)   # 🔥 IMPORTANT
        agent_reply = generate_agent_reply(history)
        append_message(req.conversation_id, "agent", agent_reply)

    # 7️⃣ Intelligence extraction
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
