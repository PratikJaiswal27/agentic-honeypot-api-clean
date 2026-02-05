import re

def extract_intel(text: str) -> dict:
    return {
        "upi_id": re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text),
        "urls": re.findall(r"https?://\S+", text)
    }
