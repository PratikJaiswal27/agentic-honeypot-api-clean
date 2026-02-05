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

def detect_escalation(conversation_id: str) -> bool:
    """
    Detects escalation based on signal progression across turns.

    Escalation definition (deterministic):
    - Pressure indicators increase over time OR
    - New irreversible action appears after initial benign turns
    """

    history = CONVERSATIONS.get(conversation_id, [])
    if len(history) < 2:
        return False

    urgency_scores = []
    irreversible_seen = set()

    for entry in history:
        signals = entry.get("signals", {})

        # Track urgency trend
        urgency = signals.get("urgency_score")
        if isinstance(urgency, (int, float)):
            urgency_scores.append(urgency)

        # Track irreversible actions
        actions = signals.get("irreversible_actions", [])
        for action in actions:
            irreversible_seen.add(action)

    # Condition 1: urgency increasing over turns
    urgency_increasing = False
    if len(urgency_scores) >= 2:
        urgency_increasing = urgency_scores[-1] > urgency_scores[0]

    # Condition 2: irreversible action appears after conversation started
    irreversible_present = len(irreversible_seen) > 0

    # Escalation occurs if BOTH hold true
    return urgency_increasing and irreversible_present
