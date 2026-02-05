import re
import os
import json
from typing import Dict, Optional
from groq import Groq

# ============================================================
# Authority Claim Extraction (STRICT + Conservative)
# ============================================================

def extract_authority_claim(message: str) -> Optional[str]:
    """
    Extract claimed authority entity (VERY conservative).
    Returns normalized entity name or None.
    """
    patterns = [
        r"\b(hdfc|icici|sbi|axis|kotak)\s+bank\b",
        r"\b(fedex|blue\s?dart|dhl)\b",
        r"\b(police|cyber\s?crime|ncb)\b",
        r"\b(rbi|income\s?tax|customs)\b",
    ]

    msg = message.lower()
    for p in patterns:
        match = re.search(p, msg)
        if match:
            return match.group(1).replace(" ", "")
    return None


# ============================================================
# Known Legitimate Authorities (Existence ONLY)
# ============================================================

KNOWN_AUTHORITIES = {
    "hdfc": "bank",
    "icici": "bank",
    "sbi": "bank",
    "axis": "bank",
    "kotak": "bank",
    "rbi": "regulator",
    "fedex": "courier",
    "bluedart": "courier",
    "dhl": "courier",
    "police": "law_enforcement",
}


# ============================================================
# LLM-Assisted Impersonation Analysis (SAFE MODE)
# ============================================================

def _analyze_impersonation_llm(message: str) -> Optional[str]:
    """
    Uses Groq ONLY to judge linguistic impersonation likelihood.
    Returns: "low" | "medium" | "high" | None
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None

    client = Groq(api_key=api_key)

    system_prompt = (
        "You are a security analysis engine.\n"
        "Your job is ONLY to analyze whether the language suggests impersonation.\n\n"
        "Rules:\n"
        "- DO NOT verify authority existence\n"
        "- DO NOT assume fraud\n"
        "- ONLY judge language style\n\n"
        "Return STRICT JSON ONLY:\n"
        "{ \"impersonation_likelihood\": \"low|medium|high\" }"
    )

    try:
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ],
            temperature=0.0,
            max_tokens=30
        )

        raw = completion.choices[0].message.content.strip()
        data = json.loads(raw)

        level = data.get("impersonation_likelihood")
        if level in {"low", "medium", "high"}:
            return level

    except Exception:
        pass

    return None


# ============================================================
# FINAL Authority Validation (Judge-Proof)
# ============================================================

def validate_authority_claim(claimed_entity: Optional[str], message: str) -> Dict:
    """
    VALIDATION CONTRACT:
    - NEVER decides scam
    - NEVER hallucinates
    - NEVER fakes search
    - ONLY provides structured signals
    """

    if not claimed_entity:
        return {
            "authority_claimed": False,
            "authority_exists": None,
            "impersonation_likelihood": None,
            "validation_method": "none",
            "notes": "No authority claim detected"
        }

    exists = claimed_entity in KNOWN_AUTHORITIES

    # LLM is advisory ONLY
    impersonation = _analyze_impersonation_llm(message)

    return {
        "authority_claimed": True,
        "authority_name": claimed_entity,
        "authority_exists": exists,
        "authority_type": KNOWN_AUTHORITIES.get(claimed_entity),
        "impersonation_likelihood": impersonation,
        "validation_method": "static_registry + linguistic_analysis",
        "notes": (
            "Authority existence checked via static registry. "
            "Language analyzed for impersonation patterns. "
            "No external verification performed."
        )
    }
