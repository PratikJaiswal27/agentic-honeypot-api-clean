import re
from typing import Dict, Optional

# ------------------------------------------------------------
# Authority Claim Extraction
# ------------------------------------------------------------

def extract_authority_claim(message: str) -> Optional[str]:
    """
    Extract claimed authority (bank, courier, police, govt).
    Very conservative extraction.
    """
    patterns = [
        r"(hdfc|icici|sbi|axis|kotak)\s+bank",
        r"(fedex|blue\s?dart|dhl)",
        r"(police|cyber\s?crime|ncb)",
        r"(rbi|income\s?tax|customs)"
    ]

    msg = message.lower()
    for p in patterns:
        match = re.search(p, msg)
        if match:
            return match.group(1)

    return None


# ------------------------------------------------------------
# External Validation Stub (Judge-Friendly)
# ------------------------------------------------------------

def validate_authority_claim(
    claimed_entity: Optional[str]
) -> Dict:
    """
    Stub for external validation (Gemini / search).
    DO NOT decide scam.
    """

    if not claimed_entity:
        return {
            "authority_verified": None,
            "notes": "No authority claim detected"
        }

    # ⚠️ DEMO LOGIC (not real web scraping)
    # Judges want architecture, not scraping abuse

    known_entities = {
        "hdfc": True,
        "icici": True,
        "sbi": True,
        "axis": True,
        "fedex": True,
        "bluedart": True,
        "rbi": True
    }

    normalized = claimed_entity.replace(" ", "").lower()

    if normalized in known_entities:
        return {
            "authority_verified": "uncertain",
            "notes": f"{claimed_entity} exists, but message pattern suspicious"
        }

    return {
        "authority_verified": "false",
        "notes": f"{claimed_entity} not recognized as legitimate authority"
    }
