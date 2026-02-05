from fastapi import HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from .config import API_KEY

api_key_scheme = APIKeyHeader(
    name="x-api-key",
    auto_error=False   # 🔥 important
)

def verify_api_key(api_key: str = Security(api_key_scheme)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key missing"
        )

    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )
