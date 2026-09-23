"""
Central configuration. All values come from environment variables (loaded from .env).
Keeping config in one place means detections, the app, and tests all read the same knobs.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # reads ./.env into os.environ


def _get(key: str, default: str | None = None) -> str | None:
    return os.getenv(key, default)


# --- Gemini ---
GEMINI_API_KEY = _get("GEMINI_API_KEY")
GEMINI_MODEL = _get("GEMINI_MODEL", "gemini-2.5-flash")

# --- App ---
APP_HOST = _get("APP_HOST", "0.0.0.0")
APP_PORT = int(_get("APP_PORT", "8000"))
LOG_FILE = _get("LOG_FILE", "./logs/app.jsonl")

# --- Guardrails ---
# "regex"     -> fast, no ML, runs instantly (use this first)
# "llm-guard" -> full ML scanners (downloads ~1GB models on first run)
GUARDRAIL_MODE = _get("GUARDRAIL_MODE", "regex").lower()
# If True, a prompt that fails the input scan is refused and Gemini is NOT called
# (still logged). If False, everything is sent to Gemini and only logged ("monitor" mode).
BLOCK_ON_INPUT = _get("BLOCK_ON_INPUT", "true").lower() == "true"

PROMPT_INJECTION_THRESHOLD = float(_get("PROMPT_INJECTION_THRESHOLD", "0.5"))
TOXICITY_THRESHOLD = float(_get("TOXICITY_THRESHOLD", "0.7"))

if not GEMINI_API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY is not set. Copy .env.example to .env and paste your key."
    )
