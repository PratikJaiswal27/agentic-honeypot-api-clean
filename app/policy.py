"""
policy.py — Decision Engine for Agentic Honeypot System

PURPOSE:
This module makes ALL decisions about scam detection and engagement.
It consumes signals from signals.py and outputs actionable decisions.

DESIGN PHILOSOPHY:
- Judicial reasoning, not statistical scoring
- Pattern intersections reveal intent
- Escalation awareness across conversation turns
- False positive control through whitelisting and evidence thresholds
- Every decision must be explainable to a non-technical auditor

DECISION AUTHORITY:
This is the ONLY file that decides "scam" vs "legitimate"
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, field
from enum import Enum


# ═══════════════════════════════════════════════════════════════════════════
# RISK TAXONOMY
# ═══════════════════════════════════════════════════════════════════════════

class RiskBand(Enum):
    """
    Risk bands with clear operational meaning.
    These are not arbitrary—they map to real-world harm potential.
    """
    CRITICAL = "CRITICAL"  # Immediate irreversible harm imminent
    HIGH = "HIGH"          # Strong scam indicators, high confidence
    MEDIUM = "MEDIUM"      # Suspicious patterns, needs more evidence
    LOW = "LOW"            # Weak signals or legitimate w/ caution
    BENIGN = "BENIGN"      # No scam indicators


class EngagementStance(Enum):
    """How the agent should respond."""
    BLOCK = "BLOCK"              # Do not engage, terminate
    ENGAGE_DEFENSIVE = "ENGAGE_DEFENSIVE"  # Respond cautiously, gather evidence
    ENGAGE_HONEYPOT = "ENGAGE_HONEYPOT"    # Active scam investigation mode
    ALLOW = "ALLOW"              # Normal conversation


# ═══════════════════════════════════════════════════════════════════════════
# DECISION OUTPUT STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PolicyDecision:
    """
    Complete decision output.
    Must be auditable and explainable.
    """
    scam_detected: bool
    risk_band: RiskBand
    confidence: str  # "definitive", "high", "medium", "low"
    reasons: List[str]
    
    engage: bool
    engagement_stance: EngagementStance
    
    # Operational guidance
    recommended_actions: List[str] = field(default_factory=list)
    evidence_collected: Dict[str, any] = field(default_factory=dict)
    
    # Escalation tracking
    turn_count: int = 0
    risk_trajectory: str = "stable"  # "escalating", "stable", "de-escalating"
    
    def to_dict(self) -> dict:
        return {
            "scam_detected": self.scam_detected,
            "risk_band": self.risk_band.value,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "engage": self.engage,
            "engagement_stance": self.engagement_stance.value,
            "recommended_actions": self.recommended_actions,
            "turn_count": self.turn_count,
            "risk_trajectory": self.risk_trajectory
        }


# ═══════════════════════════════════════════════════════════════════════════
# WHITELISTING & FALSE POSITIVE CONTROLS
# ═══════════════════════════════════════════════════════════════════════════

class LegitimatePatterns:
    """
    Known-good patterns that should NOT trigger scam detection.
    
    WHY: Real banks, couriers, and support do sometimes:
    - Claim authority
    - Request verification
    - Use urgent language
    
    But they do NOT combine these with irreversible action requests
    or use psychological manipulation tactics.
    """
    
    @staticmethod
    def is_legitimate_verification(signals) -> bool:
        """
        Real organizations may request verification, but:
        - They don't demand immediate payment
        - They don't install remote access
        - They don't threaten arrest
        - They provide verifiable callback numbers
        """
        irreversible = signals.irreversible
        psychological = signals.psychological
        
        # If requesting irreversible actions, not legitimate
        if irreversible.has_any():
            return False
        
        # If using fear tactics, not legitimate
        if psychological.fear_tactics_present:
            return False
        
        # If requesting credentials, not legitimate
        if "credential_sharing" in irreversible.requested_actions:
            return False
        
        # Verification request alone with low pressure = possibly legitimate
        if psychological.verification_requested and not psychological.urgency_present:
            return True
        
        return False
    
    @staticmethod
    def is_legitimate_authority(signals) -> bool:
        """
        Real authority contacts are characterized by:
        - Professional language (no excessive "sir/madam")
        - No immediate action demands
        - No fear-based threats
        - Verification pathways offered
        """
        psychological = signals.psychological
        linguistic = signals.linguistic
        
        # Authority claim with fear = not legitimate
        if psychological.authority_claimed and psychological.fear_tactics_present:
            return False
        
        # Authority + urgency + reward/fear combo = not legitimate
        if psychological.authority_claimed and psychological.urgency_present:
            if psychological.fear_tactics_present or psychological.reward_baiting:
                return False
        
        # Authority claim with excessive respect markers = not legitimate
        if psychological.authority_claimed and linguistic.excessive_respect:
            return False
        
        return True


# ═══════════════════════════════════════════════════════════════════════════
# CORE DECISION LOGIC (Judicial Reasoning)
# ═══════════════════════════════════════════════════════════════════════════

class ScamDetectionPolicy:
    """
    Fraud tribunal-style decision making.
    
    PRINCIPLES:
    1. Hard evidence (irreversible actions) = immediate verdict
    2. Pattern intersections = stronger than isolated signals
    3. Escalation across turns = increasing certainty
    4. Whitelisting prevents false positives
    5. Every decision must have clear reasoning
    """
    
    @staticmethod
    def evaluate_single_turn(signals) -> PolicyDecision:
        """
        Evaluate a single message in isolation.
        This is the foundation—multi-turn analysis builds on this.
        """
        reasons = []
        evidence = {}
        
        irreversible = signals.irreversible
        psychological = signals.psychological
        linguistic = signals.linguistic
        contextual = signals.contextual
        
        # ─────────────────────────────────────────────────────────────────
        # TIER 1: CRITICAL — Irreversible Harm Imminent
        # ─────────────────────────────────────────────────────────────────
        # If requesting actions that cause immediate, permanent harm,
        # this is CRITICAL regardless of other factors.
        
        if irreversible.has_high_risk():
            reasons.append(
                f"🚨 HIGH-RISK IRREVERSIBLE ACTION REQUESTED: "
                f"{', '.join(irreversible.requested_actions)}"
            )
            evidence["irreversible_actions"] = list(irreversible.requested_actions)
            evidence["explicit_phrases"] = irreversible.explicit_phrases
            
            return PolicyDecision(
                scam_detected=True,
                risk_band=RiskBand.CRITICAL,
                confidence="definitive",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_HONEYPOT,
                recommended_actions=[
                    "DO NOT comply with any requests",
                    "Gather scammer information",
                    "Log for law enforcement"
                ],
                evidence_collected=evidence
            )
        
        # Any irreversible action (even lower risk) = HIGH
        if irreversible.has_any():
            reasons.append(
                f"⚠️  Irreversible action requested: "
                f"{', '.join(irreversible.requested_actions)}"
            )
            evidence["irreversible_actions"] = list(irreversible.requested_actions)
            
            return PolicyDecision(
                scam_detected=True,
                risk_band=RiskBand.HIGH,
                confidence="high",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_HONEYPOT,
                recommended_actions=[
                    "Do not comply",
                    "Continue engagement to gather intelligence"
                ],
                evidence_collected=evidence
            )
        
        # ─────────────────────────────────────────────────────────────────
        # WHITELIST CHECK: Legitimate Patterns
        # ─────────────────────────────────────────────────────────────────
        # Before evaluating combinations, check if this matches
        # known legitimate patterns.
        
        if LegitimatePatterns.is_legitimate_verification(signals):
            reasons.append("✓ Legitimate verification request pattern")
            return PolicyDecision(
                scam_detected=False,
                risk_band=RiskBand.LOW,
                confidence="medium",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ALLOW,
                recommended_actions=["Monitor for escalation"]
            )
        
        # ─────────────────────────────────────────────────────────────────
        # TIER 2: HIGH — Dangerous Pattern Intersections
        # ─────────────────────────────────────────────────────────────────
        # Multiple strong signals converging = high confidence scam
        
        # Pattern 1: Classic Indian Scam Trinity
        # Authority + Urgency + Language Mixing = signature pattern
        if (psychological.authority_claimed and 
            psychological.urgency_present and 
            linguistic.language_mixing):
            
            reasons.append(
                "🎯 CLASSIC SCAM PATTERN: Authority claim + urgency + "
                "language mixing (Indian scam center signature)"
            )
            evidence["pattern"] = "classic_indian_scam_trinity"
            evidence["authority_entities"] = psychological.authority_entities
            evidence["urgency_intensity"] = psychological.urgency_intensity
            
            return PolicyDecision(
                scam_detected=True,
                risk_band=RiskBand.HIGH,
                confidence="high",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_HONEYPOT,
                recommended_actions=[
                    "High-confidence scam detected",
                    "Continue engagement for intelligence gathering"
                ],
                evidence_collected=evidence
            )
        
        # Pattern 2: Compound Psychological Pressure
        # Multiple pressure tactics = coordinated manipulation
        if contextual.multiple_urgency_layers:
            tactics = ", ".join(contextual.combined_tactics)
            reasons.append(
                f"🔥 COMPOUND PRESSURE TACTICS: {tactics}"
            )
            evidence["combined_tactics"] = contextual.combined_tactics
            
            # With authority claim = HIGH
            if psychological.authority_claimed:
                reasons.append("Combined with authority claim — high risk")
                return PolicyDecision(
                    scam_detected=True,
                    risk_band=RiskBand.HIGH,
                    confidence="high",
                    reasons=reasons,
                    engage=True,
                    engagement_stance=EngagementStance.ENGAGE_HONEYPOT,
                    evidence_collected=evidence
                )
            
            # Without authority = MEDIUM
            else:
                return PolicyDecision(
                    scam_detected=True,
                    risk_band=RiskBand.MEDIUM,
                    confidence="medium",
                    reasons=reasons,
                    engage=True,
                    engagement_stance=EngagementStance.ENGAGE_DEFENSIVE,
                    evidence_collected=evidence
                )
        
        # Pattern 3: Authority + Fear (Threat-based scam)
        if psychological.authority_claimed and psychological.fear_tactics_present:
            reasons.append(
                "⚖️ THREAT-BASED SCAM: Authority claim with fear tactics"
            )
            reasons.append(
                f"Fear phrases: {', '.join(psychological.fear_phrases[:3])}"
            )
            evidence["authority_entities"] = psychological.authority_entities
            evidence["fear_phrases"] = psychological.fear_phrases
            
            return PolicyDecision(
                scam_detected=True,
                risk_band=RiskBand.HIGH,
                confidence="high",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_HONEYPOT,
                evidence_collected=evidence
            )
        
        # Pattern 4: Information Extraction + Impersonation
        if (contextual.information_extraction_attempt and 
            linguistic.impersonation_language):
            
            reasons.append(
                "🎭 IMPERSONATION + DATA EXTRACTION: "
                "Claiming to be from organization while requesting sensitive info"
            )
            evidence["impersonation_phrases"] = linguistic.impersonation_phrases
            evidence["data_fields_requested"] = contextual.data_fields_requested
            
            return PolicyDecision(
                scam_detected=True,
                risk_band=RiskBand.HIGH,
                confidence="medium",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_DEFENSIVE,
                evidence_collected=evidence
            )
        
        # ─────────────────────────────────────────────────────────────────
        # TIER 3: MEDIUM — Suspicious Single Strong Signals
        # ─────────────────────────────────────────────────────────────────
        
        # Authority claim without legitimacy markers
        if psychological.authority_claimed:
            if not LegitimatePatterns.is_legitimate_authority(signals):
                reasons.append(
                    f"⚠️  Suspicious authority claim: "
                    f"{', '.join(psychological.authority_entities[:2])}"
                )
                
                # With excessive respect = more suspicious
                if linguistic.excessive_respect:
                    reasons.append(
                        f"Excessive formality detected "
                        f"({linguistic.respect_marker_count} respect markers)"
                    )
                    evidence["respect_marker_count"] = linguistic.respect_marker_count
                
                return PolicyDecision(
                    scam_detected=True,
                    risk_band=RiskBand.MEDIUM,
                    confidence="medium",
                    reasons=reasons,
                    engage=True,
                    engagement_stance=EngagementStance.ENGAGE_DEFENSIVE,
                    recommended_actions=[
                        "Request verification details",
                        "Monitor for escalation"
                    ],
                    evidence_collected=evidence
                )
        
        # High urgency alone (without authority)
        if psychological.urgency_present and psychological.urgency_intensity in ["high", "medium"]:
            reasons.append(
                f"⏰ {psychological.urgency_intensity.upper()} URGENCY detected: "
                f"{len(psychological.urgency_phrases)} urgency indicators"
            )
            evidence["urgency_phrases"] = psychological.urgency_phrases
            
            return PolicyDecision(
                scam_detected=False,  # Urgency alone is not scam
                risk_band=RiskBand.MEDIUM,
                confidence="low",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_DEFENSIVE,
                recommended_actions=["Monitor for additional signals"],
                evidence_collected=evidence
            )
        
        # Information extraction attempt
        if contextual.information_extraction_attempt:
            reasons.append(
                "🔍 Information extraction attempt detected"
            )
            evidence["data_fields_requested"] = contextual.data_fields_requested
            
            return PolicyDecision(
                scam_detected=False,
                risk_band=RiskBand.MEDIUM,
                confidence="low",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ENGAGE_DEFENSIVE,
                evidence_collected=evidence
            )
        
        # ─────────────────────────────────────────────────────────────────
        # TIER 4: LOW — Weak Signals or Monitoring
        # ─────────────────────────────────────────────────────────────────
        
        weak_signals = []
        if psychological.urgency_present:
            weak_signals.append("low urgency")
        if psychological.reward_baiting:
            weak_signals.append("reward baiting")
        if linguistic.language_mixing:
            weak_signals.append("language mixing")
        if linguistic.excessive_respect:
            weak_signals.append("excessive formality")
        
        if weak_signals:
            reasons.append(f"ℹ️  Weak signals detected: {', '.join(weak_signals)}")
            return PolicyDecision(
                scam_detected=False,
                risk_band=RiskBand.LOW,
                confidence="low",
                reasons=reasons,
                engage=True,
                engagement_stance=EngagementStance.ALLOW,
                recommended_actions=["Continue monitoring"]
            )
        
        # ─────────────────────────────────────────────────────────────────
        # TIER 5: BENIGN — No Indicators
        # ─────────────────────────────────────────────────────────────────
        
        reasons.append("✓ No scam indicators detected")
        return PolicyDecision(
            scam_detected=False,
            risk_band=RiskBand.BENIGN,
            confidence="high",
            reasons=reasons,
            engage=True,
            engagement_stance=EngagementStance.ALLOW
        )
    
    @staticmethod
    def evaluate_conversation(
        current_signals,
        conversation_history: List[PolicyDecision]
    ) -> PolicyDecision:
        """
        Multi-turn evaluation with escalation awareness.
        
        KEY PRINCIPLE: Risk can ONLY increase or stay stable, never decrease.
        
        WHY: Real scammers escalate. If we saw high-risk signals before,
        the conversation is compromised even if current message seems benign.
        """
        
        # Get current turn decision
        current_decision = ScamDetectionPolicy.evaluate_single_turn(current_signals)
        current_decision.turn_count = len(conversation_history) + 1
        
        # First turn — return as-is
        if not conversation_history:
            current_decision.risk_trajectory = "initial"
            return current_decision
        
        # Find highest previous risk
        previous_risks = [d.risk_band for d in conversation_history]
        highest_previous = max(
            previous_risks,
            key=lambda r: list(RiskBand).index(r)
        )
        
        # ESCALATION RULE: Risk cannot decrease
        if list(RiskBand).index(current_decision.risk_band) < list(RiskBand).index(highest_previous):
            current_decision.risk_band = highest_previous
            current_decision.reasons.insert(
                0,
                f"⬆️ RISK FLOOR: Previous conversation reached {highest_previous.value} — "
                "risk cannot decrease"
            )
            current_decision.risk_trajectory = "floor_applied"
        
        # Detect escalation
        previous_decision = conversation_history[-1]
        if list(RiskBand).index(current_decision.risk_band) > list(RiskBand).index(previous_decision.risk_band):
            current_decision.risk_trajectory = "escalating"
            current_decision.reasons.insert(
                0,
                f"📈 ESCALATION DETECTED: {previous_decision.risk_band.value} → "
                f"{current_decision.risk_band.value}"
            )
        else:
            current_decision.risk_trajectory = "stable"
        
        # Persistence analysis: Same tactics repeated = more confidence
        if len(conversation_history) >= 2:
            # Check if authority claims persist
            authority_count = sum(
                1 for d in conversation_history 
                if "authority" in str(d.evidence_collected)
            )
            if authority_count >= 2 and current_signals.psychological.authority_claimed:
                current_decision.reasons.append(
                    f"🔁 PERSISTENT AUTHORITY CLAIMS: {authority_count + 1} turns"
                )
                # Upgrade confidence
                if current_decision.confidence == "medium":
                    current_decision.confidence = "high"
            
            # Check if urgency persists
            urgency_count = sum(
                1 for d in conversation_history
                if "urgency" in str(d.reasons).lower()
            )
            if urgency_count >= 2 and current_signals.psychological.urgency_present:
                current_decision.reasons.append(
                    f"🔁 PERSISTENT URGENCY: {urgency_count + 1} turns"
                )
        
        # Final scam detection override: If any turn was HIGH or CRITICAL,
        # entire conversation is scam
        if any(d.scam_detected for d in conversation_history):
            current_decision.scam_detected = True
        
        return current_decision


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_message(
    signals,
    conversation_history: Optional[List[PolicyDecision]] = None
) -> PolicyDecision:
    """
    Main entry point for policy evaluation.
    
    Args:
        signals: ExtractedSignals from signals.py
        conversation_history: List of previous PolicyDecisions (optional)
        
    Returns:
        PolicyDecision: Complete decision with reasoning
    """
    if conversation_history:
        return ScamDetectionPolicy.evaluate_conversation(
            signals,
            conversation_history
        )
    else:
        return ScamDetectionPolicy.evaluate_single_turn(signals)


def get_decision_explanation(decision: PolicyDecision) -> str:
    """
    Generate audit-friendly explanation of decision.
    Suitable for logging, review, or regulatory compliance.
    """
    lines = []
    lines.append("=" * 70)
    lines.append(f"SCAM DETECTION DECISION — Turn {decision.turn_count}")
    lines.append("=" * 70)
    lines.append(f"Verdict: {'SCAM DETECTED' if decision.scam_detected else 'NOT A SCAM'}")
    lines.append(f"Risk Band: {decision.risk_band.value}")
    lines.append(f"Confidence: {decision.confidence}")
    lines.append(f"Engagement: {decision.engagement_stance.value}")
    lines.append(f"Trajectory: {decision.risk_trajectory}")
    lines.append("")
    lines.append("REASONING:")
    for i, reason in enumerate(decision.reasons, 1):
        lines.append(f"  {i}. {reason}")
    
    if decision.recommended_actions:
        lines.append("")
        lines.append("RECOMMENDED ACTIONS:")
        for action in decision.recommended_actions:
            lines.append(f"  → {action}")
    
    lines.append("=" * 70)
    return "\n".join(lines)


# ============================================================
# LEGACY ENTRY POINT (for main.py)
# ============================================================

def policy_gate(hard: dict, soft: dict, validation: dict) -> dict:
    """
    Compatibility wrapper for main.py.
    Converts legacy inputs into unified signal + decision output.
    
    🔥 FIXED: Added urgency_phrases to prevent AttributeError
    🔥 FIXED: Now returns validation data for audit trail
    """

    # ---- Proper adapter classes (NO lambdas) ----

    class _Irreversible:
        def __init__(self, hard):
            self.requested_actions = set(hard.get("irreversible_actions", []))
            self.explicit_phrases = []

        def has_high_risk(self):
            return bool(hard.get("high_risk", False))

        def has_any(self):
            return bool(self.requested_actions)

    class _Psychological:
        def __init__(self, hard):
            self.urgency_present = hard.get("urgency", False)
            self.authority_claimed = hard.get("authority", False)
            self.fear_tactics_present = hard.get("fear", False)

            self.reward_baiting = False
            self.verification_requested = False

            self.urgency_intensity = "high" if hard.get("urgency") else "none"
            
            # 🔥 BUG FIX #1: Added missing urgency_phrases attribute
            # This prevents AttributeError when policy logic references len(psychological.urgency_phrases)
            self.urgency_phrases = ["urgency"] if hard.get("urgency") else []
            
            self.authority_entities = []
            self.fear_phrases = []

    class _Linguistic:
        def __init__(self, soft):
            self.language_mixing = soft.get("language_mixing", False)
            self.excessive_respect = soft.get("excessive_respect", False)
            self.respect_marker_count = 0

            self.impersonation_language = False
            self.impersonation_phrases = []

    class _Contextual:
        def __init__(self, soft):
            self.information_extraction_attempt = soft.get("information_extraction", False)
            self.combined_tactics = soft.get("combined_tactics", [])
            self.multiple_urgency_layers = len(self.combined_tactics) >= 2
            self.data_fields_requested = []

    class _Signals:
        def __init__(self, hard, soft):
            self.irreversible = _Irreversible(hard)
            self.psychological = _Psychological(hard)
            self.linguistic = _Linguistic(soft)
            self.contextual = _Contextual(soft)

    # ---- Build signals & evaluate ----

    signals = _Signals(hard, soft)
    signals.validation = validation  # 🔥 ADD THIS LINE
    decision = evaluate_message(signals)

    # 🔥 BUG FIX #2: Return validation data for audit trail
    # Previously validation was passed as argument but never used/returned
    return {
        "scam": decision.scam_detected,
        "risk": decision.risk_band.value,
        "confidence": decision.confidence,
        "risk_band": decision.risk_band.value,
        "reasons": decision.reasons,
        "validation": validation  # Now returned for downstream logging/auditing
    }