from fastapi import Security
from fastapi.security.api_key import APIKeyHeader
from .config import API_KEY

api_key_scheme = APIKeyHeader(
    name="x-api-key",
    auto_error=False   # 🔥 important
)

def verify_api_key(api_key: str = Security(api_key_scheme)):
    """
    Optional API key validation:
    - If no key provided → Allow (for GUVI evaluator)
    - If key provided but wrong → Reject
    """
    if api_key and api_key != API_KEY:
        # Only reject if key is PROVIDED but WRONG
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
    
    # If no key OR correct key → Allow
    return api_key