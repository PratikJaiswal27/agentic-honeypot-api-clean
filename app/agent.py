import os
import re
from groq import Groq
from typing import Optional, Tuple

# ============================================================
# Lazy Groq client initialization
# ============================================================

_groq_client: Optional[Groq] = None

def _get_groq_client() -> Optional[Groq]:
    """Initialize Groq client lazily with API key validation"""
    global _groq_client

    if _groq_client is not None:
        return _groq_client

    api_key = os.getenv("GROQ_API_KEY")
    print(f"🔑 GROQ API KEY: {'✅ FOUND' if api_key else '❌ MISSING'}")

    if not api_key:
        print("⚠️ Set GROQ_API_KEY environment variable for LLM responses")
        return None

    try:
        _groq_client = Groq(api_key=api_key)
        print("✅ Groq client initialized successfully")
        return _groq_client
    except Exception as e:
        print(f"❌ Groq client init failed: {type(e).__name__}: {str(e)}")
        return None


# ============================================================
# Language detection system
# ============================================================

def _detect_language(text: str) -> str:
    """
    Detect if message is in English, Hinglish, or Hindi
    Returns: 'english', 'hinglish', or 'hindi'
    """
    text_lower = text.lower()
    
    # Hindi script detection (Devanagari Unicode range)
    hindi_chars = len(re.findall(r'[\u0900-\u097F]', text))
    total_chars = len(re.findall(r'[a-zA-Z\u0900-\u097F]', text))
    
    if total_chars == 0:
        return 'english'
    
    hindi_ratio = hindi_chars / total_chars if total_chars > 0 else 0
    
    # Pure Hindi (>80% Devanagari)
    if hindi_ratio > 0.8:
        return 'hindi'
    
    # Common Hinglish markers
    hinglish_words = [
        'bhai', 'yaar', 'kya', 'hai', 'haan', 'nahi', 'theek', 'accha',
        'arre', 'beta', 'ji', 'aapka', 'mera', 'karo', 'bolo', 'suno',
        'abhi', 'phir', 'kab', 'kahan', 'kyun', 'kaise', 'aap', 'aapne',
        'mujhe', 'mere', 'tumhara', 'humara', 'wala', 'wali', 'kar', 'ho'
    ]
    
    # Check for Hinglish patterns
    words = re.findall(r'\b\w+\b', text_lower)
    hinglish_count = sum(1 for word in words if word in hinglish_words)
    
    # Hinglish if contains Hindi words or mixed script
    if hinglish_count > 0 or (hindi_ratio > 0.1 and hindi_ratio < 0.8):
        return 'hinglish'
    
    return 'english'


# ============================================================
# Enhanced intent detection
# ============================================================

def _detect_intent(msg: str) -> str:
    """
    Detect scammer's intent from message keywords
    Enhanced with more patterns and multilingual support
    """
    msg_lower = msg.lower()
    
    # Credential theft patterns
    if any(word in msg_lower for word in [
        'otp', 'pin', 'password', 'cvv', 'code', 'verify', 'verification',
        'passcode', 'security code', 'आओटीपी', 'पासवर्ड', 'कोड'
    ]):
        return "credential_trap"
    
    # Money/payment patterns
    if any(word in msg_lower for word in [
        'upi', 'payment', 'refund', 'amount', 'rs', 'money', 'rupees',
        'paytm', 'phonepe', 'gpay', 'transfer', 'account', 'रुपये', 'पैसे'
    ]):
        return "money_trap"
    
    # Authority impersonation
    if any(word in msg_lower for word in [
        'bank', 'police', 'officer', 'department', 'rbi', 'government',
        'official', 'cybercrime', 'पुलिस', 'बैंक', 'सरकार'
    ]):
        return "authority_trap"
    
    # Device access attempts
    if any(word in msg_lower for word in [
        'install', 'download', 'anydesk', 'teamviewer', 'remote',
        'app', 'link', 'click', 'डाउनलोड', 'इंस्टॉल'
    ]):
        return "device_trap"
    
    # Panic/urgency tactics
    if any(word in msg_lower for word in [
        'urgent', 'block', 'suspend', 'arrest', 'immediately', 'now',
        'hurry', 'quick', 'emergency', 'जल्दी', 'तुरंत'
    ]):
        return "panic_trap"
    
    # Greeting/introduction
    if any(word in msg_lower for word in [
        'hello', 'hi', 'good morning', 'good afternoon', 'good evening',
        'this is', 'i am calling from', 'नमस्ते', 'हेलो'
    ]):
        return "greeting"
    
    return "unknown"


# ============================================================
# Strategy selector - smooth transition
# ============================================================

def _response_strategy(intent: str, agent_count: int) -> str:
    """
    Decide between manual scripted responses and LLM generation
    First 2 replies: Always manual (builds context)
    After that: LLM for realistic conversation
    """
    if agent_count < 2:
        return "manual"
    return "llm"


# ============================================================
# Enhanced manual responses - multilingual
# ============================================================

MANUAL_RESPONSES = {
    "credential_trap": {
        "english": [
            "I didn't receive any code yet",
            "Which code are you referring to?",
            "Can you send it again?"
        ],
        "hinglish": [
            "Mujhe koi code nahi aaya abhi tak",
            "Kaun sa code ki baat kar rahe ho?",
            "Dobara bhej sakte ho kya?"
        ],
        "hindi": [
            "मुझे अभी तक कोई कोड नहीं मिला",
            "आप किस कोड की बात कर रहे हैं?",
            "फिर से भेज सकते हो?"
        ]
    },
    "money_trap": {
        "english": [
            "Which amount exactly?",
            "I have two accounts, which one?",
            "How much money are we talking about?"
        ],
        "hinglish": [
            "Kitna amount hai exactly?",
            "Mere do accounts hain, kaun sa?",
            "Kitne paise ki baat ho rahi hai?"
        ],
        "hindi": [
            "कितनी रकम है?",
            "मेरे दो खाते हैं, कौन सा?",
            "कितने पैसे की बात हो रही है?"
        ]
    },
    "authority_trap": {
        "english": [
            "Which branch are you calling from?",
            "Can you share the official number?",
            "What is your employee ID?"
        ],
        "hinglish": [
            "Aap kaun se branch se call kar rahe ho?",
            "Official number share kar sakte ho?",
            "Aapki employee ID kya hai?"
        ],
        "hindi": [
            "आप किस ब्रांच से कॉल कर रहे हो?",
            "आधिकारिक नंबर शेयर कर सकते हो?",
            "आपकी कर्मचारी आईडी क्या है?"
        ]
    },
    "device_trap": {
        "english": [
            "My phone storage is full",
            "Is it really necessary?",
            "Can we do this without downloading?"
        ],
        "hinglish": [
            "Mere phone ki storage full hai",
            "Ye zaruri hai kya really?",
            "Bina download kiye ho sakta hai?"
        ],
        "hindi": [
            "मेरे फोन की स्टोरेज भरी है",
            "क्या यह सच में जरूरी है?",
            "बिना डाउनलोड किए हो सकता है?"
        ]
    },
    "panic_trap": {
        "english": [
            "Please explain slowly",
            "What happened exactly?",
            "I'm getting confused, start from beginning"
        ],
        "hinglish": [
            "Dhire dhire samjhao please",
            "Hua kya exactly?",
            "Main confuse ho raha hoon, shuru se batao"
        ],
        "hindi": [
            "कृपया धीरे-धीरे समझाओ",
            "हुआ क्या?",
            "मैं भ्रमित हो रहा हूं, शुरू से बताओ"
        ]
    },
    "greeting": {
        "english": [
            "Hello, who is this?",
            "Yes, how can I help?"
        ],
        "hinglish": [
            "Hello, kaun bol raha hai?",
            "Haan, kaise madad kar sakta hoon?"
        ],
        "hindi": [
            "नमस्ते, कौन बोल रहा है?",
            "हां, कैसे मदद कर सकता हूं?"
        ]
    },
    "unknown": {
        "english": [
            "I didn't understand",
            "Can you explain again?",
            "What do you mean?"
        ],
        "hinglish": [
            "Main samjha nahi",
            "Phir se samjha sakte ho?",
            "Matlab kya hai?"
        ],
        "hindi": [
            "मैं समझा नहीं",
            "फिर से समझा सकते हो?",
            "मतलब क्या है?"
        ]
    }
}


# ============================================================
# Groq LLM engine with language-aware prompts
# ============================================================

def _groq_generate_reply(history: list, language: str) -> str:
    """
    Generate realistic reply using Groq LLM
    Adapts persona and language based on detected language
    """
    client = _get_groq_client()
    if client is None:
        print("⚠️ GROQ CLIENT UNAVAILABLE - Using fallback")
        fallbacks = {
            "english": "Sorry, can you repeat that?",
            "hinglish": "Thoda repeat kariye please",
            "hindi": "क्षमा करें, फिर से बोलिए?"
        }
        return fallbacks.get(language, "Can you say that again?")

    # Build conversation history (last 6 messages for context)
    messages = []
    for msg in history[-6:]:
        role = "assistant" if msg.get("role") == "agent" else "user"
        content = msg.get("message", "").strip()
        if content:
            messages.append({"role": role, "content": content})

    # Language-specific system prompts
    system_prompts = {
        "english": (
            "You are a 60-year-old Indian person who gets confused by phone calls. "
            "Reply ONLY in English with a confused, hesitant tone. "
            "Use phrases like 'excuse me', 'sorry', 'I don't understand', 'what do you mean'. "
            "Keep replies SHORT (under 15 words), casual, and slightly confused. "
            "Ask innocent questions showing you don't fully understand. "
            "NEVER mention: scam, fraud, police, AI, bot, suspicious, fake. "
            "Sound like a real confused elderly person."
        ),
        "hinglish": (
            "You are a 60-year-old Indian person who gets confused by phone calls. "
            "Reply in HINGLISH (Hindi-English mix) with a confused tone. "
            "Use phrases like 'arre beta', 'haan ji', 'accha', 'samajh nahi aaya', 'kya matlab'. "
            "Keep replies SHORT (under 15 words), casual, and slightly confused. "
            "Mix Hindi words naturally with English. Ask innocent questions. "
            "NEVER mention: scam, fraud, police, AI, bot, suspicious, fake, dhoka. "
            "Sound like a real confused Indian elder speaking casually."
        ),
        "hindi": (
            "आप एक 60 वर्षीय भारतीय व्यक्ति हैं जो फोन कॉल से भ्रमित हो जाते हैं। "
            "केवल हिंदी में भ्रमित स्वर में जवाब दें। "
            "'अरे बेटा', 'हां जी', 'अच्छा', 'समझ नहीं आया', 'क्या मतलब' जैसे शब्द इस्तेमाल करें। "
            "जवाब छोटे रखें (15 शब्दों से कम), सहज और थोड़े भ्रमित। "
            "मासूम सवाल पूछें। कभी न कहें: घोटाला, धोखा, पुलिस, AI, बॉट, संदिग्ध। "
            "असली भ्रमित बुजुर्ग की तरह बोलें।"
        )
    }

    system_prompt = system_prompts.get(language, system_prompts["english"])

    try:
        print(f"🤖 CALLING GROQ | Language: {language.upper()} | History: {len(messages)} messages")
        
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                *messages
            ],
            temperature=0.8,  # Higher for more natural variation
            max_tokens=60,    # Enough for complete thoughts
            top_p=0.9
        )

        response_text = completion.choices[0].message.content.strip()
        print(f"✅ GROQ RESPONSE: '{response_text}'")

        # Validate response
        if not response_text:
            print("❌ Empty response from Groq")
            return _get_fallback_response(language)

        # Block AI self-identification
        forbidden_phrases = [
            "i am an ai", "i'm an ai", "i am a bot", "i'm a bot",
            "as an ai", "as a language model", "मैं एक AI हूं"
        ]
        if any(phrase in response_text.lower() for phrase in forbidden_phrases):
            print("❌ Groq tried to self-identify as AI - using fallback")
            return _get_fallback_response(language)

        return response_text

    except Exception as e:
        print(f"🔥 GROQ ERROR: {type(e).__name__}: {str(e)}")
        return _get_fallback_response(language)


def _get_fallback_response(language: str) -> str:
    """Fallback responses when Groq fails"""
    fallbacks = {
        "english": "Sorry, I didn't catch that. Can you repeat?",
        "hinglish": "Thoda network issue hai, dobara boliye",
        "hindi": "नेटवर्क खराब है, फिर से बोलिए"
    }
    return fallbacks.get(language, "Can you say that again?")


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def generate_agent_reply(history: list) -> str:
    """
    Main function to generate agent's reply based on conversation history
    
    Args:
        history: List of message dicts with 'role' and 'message' keys
        
    Returns:
        str: Agent's response message
    """
    print("\n" + "="*60)
    print("🎯 GENERATING AGENT REPLY")
    print("="*60)
    
    # Handle empty history
    if not history:
        print("📭 Empty history - returning default greeting")
        return "Hello?"

    # Find last scammer message
    last_scammer_msg = None
    for msg in reversed(history):
        if msg.get("role") == "scammer":
            last_scammer_msg = msg.get("message", "").strip()
            break

    if not last_scammer_msg:
        print("❌ No scammer message found")
        return "Yes, I'm listening?"

    print(f"📨 Last scammer message: '{last_scammer_msg}'")

    # Detect language
    language = _detect_language(last_scammer_msg)
    print(f"🌐 Detected language: {language.upper()}")

    # Count agent messages
    agent_count = sum(1 for m in history if m.get("role") == "agent")
    print(f"📊 Agent message count: {agent_count}")

    # Detect intent
    intent = _detect_intent(last_scammer_msg)
    print(f"🎯 Detected intent: {intent}")

    # Choose strategy
    strategy = _response_strategy(intent, agent_count)
    print(f"🔀 Selected strategy: {strategy.upper()}")

    # Generate response
    if strategy == "manual":
        # Get language-specific manual response
        intent_responses = MANUAL_RESPONSES.get(intent, MANUAL_RESPONSES["unknown"])
        lang_responses = intent_responses.get(language, intent_responses.get("english", ["I see"]))
        response = lang_responses[agent_count % len(lang_responses)]
        print(f"📝 Manual response: '{response}'")
        print("="*60 + "\n")
        return response
    
    else:  # strategy == "llm"
        print("🚀 Switching to LLM generation...")
        response = _groq_generate_reply(history, language)
        print(f"🎯 Final LLM response: '{response}'")
        print("="*60 + "\n")
        return response


# ============================================================
# Testing utility
# ============================================================

if __name__ == "__main__":
    # Test language detection
    print("\n🧪 TESTING LANGUAGE DETECTION:")
    test_cases = [
        "Hello sir, I am calling from State Bank",
        "Namaste ji, main RBI se bol raha hoon",
        "आपका अकाउंट ब्लॉक हो गया है"
    ]
    for test in test_cases:
        lang = _detect_language(test)
        print(f"  '{test}' → {lang}")
    
    # Test conversation flow
    print("\n🧪 TESTING CONVERSATION FLOW:")
    test_history = [
        {"role": "scammer", "message": "Hello sir, this is from SBI"},
        {"role": "agent", "message": "Hello, who is this?"},
        {"role": "scammer", "message": "We need your OTP to verify account"},
    ]
    
    response = generate_agent_reply(test_history)
    print(f"\n✅ Generated response: '{response}'")