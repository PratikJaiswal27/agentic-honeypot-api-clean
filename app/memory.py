# -------------------------------------------------------------------
# In-memory conversation store (Hackathon / Demo safe)
# -------------------------------------------------------------------

from typing import Dict, List

# Structure:
# CONVERSATIONS = {
#   conversation_id: [
#       {
#           "role": "scammer" | "agent",
#           "message": str,
#           "signals": dict   # snapshot of signals at that turn
#       },
#       ...
#   ]
# }

CONVERSATIONS: Dict[str, List[dict]] = {}

MAX_HISTORY = 6  # keep last N turns only (prevents memory bloat)

# -------------------------------------------------------------------
# Get conversation history
# -------------------------------------------------------------------

def get_history(conversation_id: str) -> List[dict]:
    return CONVERSATIONS.get(conversation_id, [])

# -------------------------------------------------------------------
# Append message with optional signal snapshot
# -------------------------------------------------------------------

def append_message(
    conversation_id: str,
    role: str,
    message: str,
    signals: dict = None
):
    entry = {
        "role": role,
        "message": message,
        "signals": signals or {}
    }

    CONVERSATIONS.setdefault(conversation_id, []).append(entry)

    # Trim history to last N turns
    if len(CONVERSATIONS[conversation_id]) > MAX_HISTORY:
        CONVERSATIONS[conversation_id] = CONVERSATIONS[conversation_id][-MAX_HISTORY:]

# -------------------------------------------------------------------
# Escalation Detection Logic
# -------------------------------------------------------------------

def detect_escalation(conversation_id: str) -> dict:
    """
    Detects escalation based on signal progression across turns.

    Returns structured escalation signal (policy-friendly).
    """

    history = CONVERSATIONS.get(conversation_id, [])
    if len(history) < 2:
        return {
            "escalation": False,
            "reason": "Insufficient conversation history"
        }

    urgency_scores = []
    irreversible_turns = []

    for idx, entry in enumerate(history):
        signals = entry.get("signals", {})

        urgency = signals.get("urgency_score")
        if isinstance(urgency, (int, float)):
            urgency_scores.append(urgency)

        actions = signals.get("irreversible_actions", [])
        if actions:
            irreversible_turns.append(idx)

    # ---- Condition 1: sustained urgency increase ----
    urgency_escalating = False
    if len(urgency_scores) >= 3:
        urgency_escalating = urgency_scores[-1] > urgency_scores[-2] > urgency_scores[0]

    # ---- Condition 2: irreversible introduced AFTER start ----
    irreversible_late = (
        len(irreversible_turns) > 0 and
        irreversible_turns[0] > 0
    )

    if urgency_escalating and irreversible_late:
        return {
            "escalation": True,
            "reason": "Urgency increased across turns and irreversible action introduced later",
            "urgency_trend": urgency_scores,
            "irreversible_first_seen_at_turn": irreversible_turns[0]
        }

    return {
        "escalation": False,
        "reason": "No sustained escalation pattern detected"
    }
