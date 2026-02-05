"""
signals.py — Signal Extraction Module for Agentic Honeypot System

PURPOSE:
This module extracts objective, structured signals from incoming messages.
It does NOT make decisions about scam vs legitimate.
It does NOT compute risk scores.
It does NOT trigger actions.

It simply observes and reports facts that a policy engine can later use.

DESIGN PHILOSOPHY:
Signals are grouped by analyst reasoning categories:
- IRREVERSIBLE ACTIONS: What the sender is asking the victim to do that cannot be undone
- PSYCHOLOGICAL TACTICS: How the sender is applying pressure
- LINGUISTIC PATTERNS: Communication style markers common in Indian scam operations
- CONTEXTUAL MARKERS: Sequencing and escalation hints
"""

import re
from typing import List, Dict, Set
from dataclasses import dataclass, field, asdict


# ═══════════════════════════════════════════════════════════════════════════
# IRREVERSIBLE ACTIONS (Human-Curated, Frozen List)
# ═══════════════════════════════════════════════════════════════════════════

IRREVERSIBLE_ACTIONS: Dict[str, List[str]] = {

    "credential_sharing": [
        "otp", "one time password", "one-time password",
        "pin", "password", "cvv", "cvc", "card number",
        "login code", "verification code", "security code",
        "mpin", "atm pin", "debit card", "credit card"
    ],

    "remote_access_installation": [
        "anydesk", "teamviewer", "remote desktop", "screen sharing",
        "screen share", "remote access", "remote control",
        "install app", "download app", "apk install"
    ],

    "immediate_payment": [
        "upi collect", "pay now", "transfer money", "send money",
        "payment request", "gpay", "paytm", "phonepe",
        "bank transfer", "neft", "rtgs", "imps"
    ],

    "qr_code_action": [
        "scan qr", "qr code", "scan this", "barcode"
    ],

    "untraceable_payment": [
        "gift card", "google play card", "amazon card",
        "crypto", "bitcoin", "usdt", "wallet address"
    ],

    "link_interaction": [
        "click link", "open link", "visit link",
        "verify account", "confirm identity"
    ],

    "account_access_sharing": [
        "share screen", "give access",
        "safe account", "secure account"
    ]
}


# ═══════════════════════════════════════════════════════════════════════════
# PSYCHOLOGICAL TACTICS
# ═══════════════════════════════════════════════════════════════════════════

URGENCY_INDICATORS = [
    "urgent", "immediately", "right now", "asap",
    "today", "within minutes", "expire",
    "turant", "abhi", "jaldi", "der mat karo"
]

AUTHORITY_CLAIMS = [
    "bank", "rbi", "sbi", "hdfc", "icici",
    "police", "officer", "cyber cell",
    "government", "court", "income tax"
]

FEAR_TACTICS = [
    "blocked", "suspended", "frozen",
    "arrest", "fir", "court case",
    "penalty", "fraud", "illegal"
]

REWARD_BAITS = [
    "refund", "cashback", "reward",
    "prize", "lottery", "bonus"
]

VERIFICATION_REQUESTS = [
    "verify", "confirm", "authenticate",
    "kyc", "update details"
]


# ═══════════════════════════════════════════════════════════════════════════
# LINGUISTIC PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

HINDI_ROMANIZED_WORDS = [
    "hai", "hain", "aap", "aapka", "aapko",
    "karo", "kijiye", "sir", "madam", "ji"
]

FORMAL_HINDI_PHRASES = [
    "namaste", "namaskar", "kripya"
]

EXCESSIVE_RESPECT_MARKERS = [
    "sir", "madam", "sirji", "madamji"
]

IMPERSONATION_SIGNALS = [
    "calling from", "i am from",
    "representing", "on behalf of",
    "executive", "officer", "agent"
]

INFORMATION_EXTRACTION = [
    "what is your", "share your",
    "send your", "confirm your",
    "pan", "aadhaar", "account number"
]


# ═══════════════════════════════════════════════════════════════════════════
# STRUCTURED OUTPUT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class IrreversibleActionSignals:
    requested_actions: Set[str] = field(default_factory=set)
    explicit_phrases: List[str] = field(default_factory=list)

    def has_any(self) -> bool:
        return bool(self.requested_actions)

    def has_high_risk(self) -> bool:
        return bool(self.requested_actions & {
            "credential_sharing",
            "remote_access_installation",
            "immediate_payment",
            "account_access_sharing"
        })


@dataclass
class PsychologicalTacticSignals:
    urgency_present: bool = False
    urgency_phrases: List[str] = field(default_factory=list)
    urgency_intensity: str = "none"

    authority_claimed: bool = False
    authority_entities: List[str] = field(default_factory=list)

    fear_tactics_present: bool = False
    fear_phrases: List[str] = field(default_factory=list)

    reward_baiting: bool = False
    reward_phrases: List[str] = field(default_factory=list)

    verification_requested: bool = False
    verification_phrases: List[str] = field(default_factory=list)


@dataclass
class LinguisticSignals:
    language_mixing: bool = False
    hindi_word_count: int = 0
    english_word_count: int = 0

    excessive_respect: bool = False
    respect_marker_count: int = 0

    formal_hindi_present: bool = False

    impersonation_language: bool = False
    impersonation_phrases: List[str] = field(default_factory=list)


@dataclass
class ContextualSignals:
    information_extraction_attempt: bool = False
    data_fields_requested: List[str] = field(default_factory=list)

    multiple_urgency_layers: bool = False
    combined_tactics: List[str] = field(default_factory=list)

    # NEW — escalation indicator (OBSERVATIONAL)
    escalation_detected: bool = False


@dataclass
class ExtractedSignals:
    irreversible: IrreversibleActionSignals = field(default_factory=IrreversibleActionSignals)
    psychological: PsychologicalTacticSignals = field(default_factory=PsychologicalTacticSignals)
    linguistic: LinguisticSignals = field(default_factory=LinguisticSignals)
    contextual: ContextualSignals = field(default_factory=ContextualSignals)

    def to_dict(self) -> dict:
        return {
            "irreversible": asdict(self.irreversible),
            "psychological": asdict(self.psychological),
            "linguistic": asdict(self.linguistic),
            "contextual": asdict(self.contextual)
        }


# ═══════════════════════════════════════════════════════════════════════════
# EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def extract_irreversible_actions(text: str) -> IrreversibleActionSignals:
    text_lower = text.lower()
    signals = IrreversibleActionSignals()

    for category, phrases in IRREVERSIBLE_ACTIONS.items():
        for phrase in phrases:
            if re.search(rf"\b{re.escape(phrase)}\b", text_lower):
                signals.requested_actions.add(category)
                signals.explicit_phrases.append(phrase)

    return signals


def extract_psychological_tactics(text: str) -> PsychologicalTacticSignals:
    text_lower = text.lower()
    signals = PsychologicalTacticSignals()

    urgency_matches = [w for w in URGENCY_INDICATORS if w in text_lower]
    if urgency_matches:
        signals.urgency_present = True
        signals.urgency_phrases = urgency_matches
        signals.urgency_intensity = (
            "high" if len(urgency_matches) >= 3 else
            "medium" if len(urgency_matches) == 2 else
            "low"
        )

    authority_matches = [w for w in AUTHORITY_CLAIMS if w in text_lower]
    if authority_matches:
        signals.authority_claimed = True
        signals.authority_entities = authority_matches

    fear_matches = [w for w in FEAR_TACTICS if w in text_lower]
    if fear_matches:
        signals.fear_tactics_present = True
        signals.fear_phrases = fear_matches

    reward_matches = [w for w in REWARD_BAITS if w in text_lower]
    if reward_matches:
        signals.reward_baiting = True
        signals.reward_phrases = reward_matches

    verification_matches = [w for w in VERIFICATION_REQUESTS if w in text_lower]
    if verification_matches:
        signals.verification_requested = True
        signals.verification_phrases = verification_matches

    return signals


def extract_linguistic_signals(text: str) -> LinguisticSignals:
    text_lower = text.lower()
    words = text_lower.split()
    signals = LinguisticSignals()

    signals.hindi_word_count = sum(1 for w in words if w in HINDI_ROMANIZED_WORDS)
    signals.english_word_count = sum(
        1 for w in words if w.isascii() and w.isalpha() and w not in HINDI_ROMANIZED_WORDS
    )

    signals.language_mixing = signals.hindi_word_count > 0 and signals.english_word_count > 0

    respect_markers = [w for w in EXCESSIVE_RESPECT_MARKERS if w in text_lower]
    signals.respect_marker_count = len(respect_markers)
    signals.excessive_respect = signals.respect_marker_count >= 2

    signals.formal_hindi_present = any(p in text_lower for p in FORMAL_HINDI_PHRASES)

    impersonation_matches = [p for p in IMPERSONATION_SIGNALS if p in text_lower]
    if impersonation_matches:
        signals.impersonation_language = True
        signals.impersonation_phrases = impersonation_matches

    return signals


def extract_contextual_signals(
    text: str,
    psychological: PsychologicalTacticSignals
) -> ContextualSignals:

    text_lower = text.lower()
    signals = ContextualSignals()

    info_matches = [p for p in INFORMATION_EXTRACTION if p in text_lower]
    if info_matches:
        signals.information_extraction_attempt = True
        signals.data_fields_requested = info_matches

    tactics = []
    if psychological.urgency_present:
        tactics.append("urgency")
    if psychological.authority_claimed:
        tactics.append("authority")
    if psychological.fear_tactics_present:
        tactics.append("fear")
    if psychological.reward_baiting:
        tactics.append("reward")

    if len(tactics) >= 2:
        signals.multiple_urgency_layers = True
        signals.combined_tactics = tactics
        signals.escalation_detected = True

    if psychological.verification_requested and (
        psychological.urgency_present or psychological.authority_claimed
    ):
        signals.escalation_detected = True

    return signals


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def extract_signals(text: str) -> ExtractedSignals:
    signals = ExtractedSignals()

    signals.irreversible = extract_irreversible_actions(text)
    signals.psychological = extract_psychological_tactics(text)
    signals.linguistic = extract_linguistic_signals(text)
    signals.contextual = extract_contextual_signals(text, signals.psychological)

    return signals

# ============================================================
# BACKWARD-COMPATIBILITY LAYER (for main.py)
# ============================================================

def hard_signal_scan(text: str) -> dict:
    """
    Legacy-compatible hard signal scan.
    Maps to irreversible + psychological signals.
    """
    signals = extract_signals(text)
    return {
        "irreversible_actions": list(signals.irreversible.requested_actions),
        "high_risk": signals.irreversible.has_high_risk(),
        "urgency": signals.psychological.urgency_present,
        "authority": signals.psychological.authority_claimed,
        "fear": signals.psychological.fear_tactics_present,
    }


def soft_signal_placeholder(text: str) -> dict:
    """
    Legacy-compatible soft signals.
    Maps to linguistic + contextual hints.
    """
    signals = extract_signals(text)
    return {
        "language_mixing": signals.linguistic.language_mixing,
        "excessive_respect": signals.linguistic.excessive_respect,
        "information_extraction": signals.contextual.information_extraction_attempt,
        "combined_tactics": signals.contextual.combined_tactics,
    }
