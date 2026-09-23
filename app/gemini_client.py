"""
Thin wrapper around the Gemini API (google-genai SDK).
Returns: {"text": str, "usage": {prompt_tokens, output_tokens, total_tokens}, "error": str|None}
Includes exponential backoff on 429 / RESOURCE_EXHAUSTED (free tier ~10 req/min).
"""
import time
from google import genai
from app import config

_client = genai.Client(api_key=config.GEMINI_API_KEY)

_EMPTY_USAGE = {"prompt_tokens": None, "output_tokens": None, "total_tokens": None}


def generate(prompt: str, max_retries: int = 3) -> dict:
    delay = 2.0
    last_err = None
    for _ in range(max_retries):
        try:
            resp = _client.models.generate_content(model=config.GEMINI_MODEL, contents=prompt)
            um = getattr(resp, "usage_metadata", None)
            usage = {
                "prompt_tokens": getattr(um, "prompt_token_count", None) if um else None,
                "output_tokens": getattr(um, "candidates_token_count", None) if um else None,
                "total_tokens": getattr(um, "total_token_count", None) if um else None,
            }
            return {"text": resp.text or "", "usage": usage, "error": None}
        except Exception as exc:
            last_err = str(exc)
            if any(code in last_err for code in ("429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE")):
                time.sleep(delay)
                delay *= 2
                continue
            break
    return {"text": "", "usage": dict(_EMPTY_USAGE), "error": last_err}
