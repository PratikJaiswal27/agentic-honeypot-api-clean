from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import logging
import traceback

load_dotenv()

from .schemas import HoneypotRequest
from .memory import get_history, append_message
from .signals import hard_signal_scan, soft_signal_placeholder
from .policy import policy_gate
from .agent import generate_agent_reply
from .extractor import extract_intel
from .validator import extract_authority_claim, validate_authority_claim

# ============================================================
# LOGGING SETUP
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Agentic Honeypot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# REQUEST LOGGING MIDDLEWARE
# ============================================================
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests for debugging"""
    try:
        body = await request.body()
        logger.info("="*60)
        logger.info(f"📥 INCOMING: {request.method} {request.url.path}")
        logger.info(f"Headers: {dict(request.headers)}")
        logger.info(f"Body: {body.decode('utf-8', errors='ignore')}")
        logger.info("="*60)
        
        response = await call_next(request)
        
        logger.info(f"📤 RESPONSE: Status {response.status_code}")
        return response
        
    except Exception as e:
        logger.error(f"🔥 MIDDLEWARE ERROR: {type(e).__name__}: {str(e)}")
        logger.error(traceback.format_exc())
        return JSONResponse(
            status_code=500,
            content={"error": "Middleware error", "detail": str(e)}
        )

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
def root():
    logger.info("✅ Health check endpoint hit")
    return {
        "status": "ok",
        "service": "agentic-honeypot-api",
        "message": "API is live. Use POST /honeypot"
    }


@app.post("/")
async def root_post(request: Request):
    """Main endpoint - GUVI hits this"""
    logger.info("🎯 ROOT POST endpoint called")
    
    try:
        # Parse request body
        try:
            body = await request.json()
            logger.info(f"✅ Parsed JSON: {body}")
        except Exception as e:
            logger.warning(f"⚠️ JSON parse failed: {e}, using empty dict")
            body = {}
        
        # Create request object safely
        try:
            req_data = HoneypotRequest(
                conversation_id=body.get("conversation_id", "default"),
                turn=body.get("turn", 1),
                message=body.get("message", ""),
                execution_mode=body.get("execution_mode", "live")
            )
            logger.info(f"✅ Created HoneypotRequest: conv_id={req_data.conversation_id}, turn={req_data.turn}")
        except Exception as e:
            logger.error(f"❌ Failed to create HoneypotRequest: {e}")
            raise
        
        # Process request
        result = honeypot_endpoint_logic(req_data)
        logger.info(f"✅ Logic completed, returning response")
        
        return result
        
    except Exception as e:
        logger.error(f"🔥 FATAL ERROR in root_post: {type(e).__name__}: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return safe fallback response
        return JSONResponse(
            status_code=200,  # Return 200 to prevent GUVI rejection
            content={
                "scam_detected": False,
                "risk_score": "ERROR",
                "decision_confidence": "none",
                "agent_reply": None,
                "extracted_intelligence": {},
                "engagement_metrics": {"turn": 1, "history_length": 0},
                "explanation": {
                    "error": str(e),
                    "error_type": type(e).__name__
                }
            }
        )


@app.post("/honeypot")
async def honeypot_endpoint(request: Request):
    """Secondary endpoint"""
    logger.info("🎯 HONEYPOT endpoint called")
    
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
    """Debugging endpoint - works because no processing"""
    logger.info("🔍 DEBUG endpoint called")
    body = await request.body()
    headers = dict(request.headers)
    
    return {
        "received_body": body.decode('utf-8'),
        "content_type": headers.get("content-type"),
        "all_headers": headers,
        "method": request.method,
        "status": "debug_ok"
    }


# ============================================================
# CORE LOGIC WITH ERROR HANDLING
# ============================================================

def honeypot_endpoint_logic(req: HoneypotRequest):
    """Core processing logic with comprehensive error handling"""
    
    try:
        logger.info(f"🔧 Processing message: '{req.message[:50]}...'")
        
        # Step 1: Get history
        try:
            history = get_history(req.conversation_id)
            logger.info(f"✅ Retrieved history: {len(history)} messages")
        except Exception as e:
            logger.error(f"❌ get_history failed: {e}")
            history = []
        
        # Step 2: Append scammer message
        try:
            append_message(req.conversation_id, "scammer", req.message)
            history = get_history(req.conversation_id)
            logger.info(f"✅ Appended scammer message, new history length: {len(history)}")
        except Exception as e:
            logger.error(f"❌ append_message failed: {e}")
        
        # Step 3: Signal extraction
        try:
            hard = hard_signal_scan(req.message)
            soft = soft_signal_placeholder(req.message)
            logger.info(f"✅ Signals extracted - hard: {list(hard.keys())}, soft: {list(soft.keys())}")
        except Exception as e:
            logger.error(f"❌ Signal extraction failed: {e}")
            hard = {}
            soft = {}
        
        # Step 4: Authority validation
        try:
            claimed = extract_authority_claim(req.message)
            validation = validate_authority_claim(claimed)
            logger.info(f"✅ Authority validation complete")
        except Exception as e:
            logger.error(f"❌ Validation failed: {e}")
            claimed = {}
            validation = {}
        
        # Step 5: Policy decision
        try:
            decision = policy_gate(hard=hard, soft=soft, validation=validation)
            logger.info(f"✅ Policy decision: scam={decision.get('scam')}, risk={decision.get('risk')}")
        except Exception as e:
            logger.error(f"❌ Policy gate failed: {e}")
            logger.error(traceback.format_exc())
            decision = {
                "scam": False,
                "risk": "UNKNOWN",
                "confidence": "low",
                "risk_band": "unknown",
                "reasons": [f"Policy error: {str(e)}"]
            }
        
        # Step 6: Agent reply (only if live mode)
        agent_reply = None
        if req.execution_mode == "live":
            try:
                logger.info(f"🤖 Generating agent reply...")
                history = get_history(req.conversation_id)
                agent_reply = generate_agent_reply(history)
                logger.info(f"✅ Agent reply generated: '{agent_reply[:50]}...'")
                append_message(req.conversation_id, "agent", agent_reply)
            except Exception as e:
                logger.error(f"❌ Agent reply failed: {e}")
                logger.error(traceback.format_exc())
                agent_reply = "I didn't understand. Can you repeat?"
        
        # Step 7: Intelligence extraction
        try:
            intel = extract_intel(req.message)
            logger.info(f"✅ Intel extracted: {list(intel.keys()) if isinstance(intel, dict) else 'not a dict'}")
        except Exception as e:
            logger.error(f"❌ Intel extraction failed: {e}")
            intel = {}
        
        # Step 8: Build response
        response = {
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
        
        logger.info(f"✅ Response built successfully")
        return response
        
    except Exception as e:
        logger.error(f"🔥 CRITICAL ERROR in honeypot_endpoint_logic: {type(e).__name__}: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return minimal safe response
        return {
            "scam_detected": False,
            "risk_score": "ERROR",
            "decision_confidence": "none",
            "agent_reply": None,
            "extracted_intelligence": {},
            "engagement_metrics": {"turn": 1, "history_length": 0},
            "explanation": {
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc()
            }
        }