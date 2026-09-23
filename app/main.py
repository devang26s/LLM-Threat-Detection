"""
FastAPI service. One endpoint, /chat, that runs the full pipeline per request:
  1. Scan the INPUT prompt.
  2. Block (if BLOCK_ON_INPUT) or call Gemini.
  3. Scan the OUTPUT.
  4. Emit ONE structured JSON log line.

Run (from llm-siem/, venv active):
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""
import time
import uuid

from fastapi import FastAPI, Request
from pydantic import BaseModel

from app import config, guardrails
from app.gemini_client import generate
from app.logging_setup import EventLogger

app = FastAPI(title="LLM Threat Detection App", version="0.1.0")
logger = EventLogger(config.LOG_FILE)

REFUSAL_MSG = "This request was blocked by the input guardrail."


class ChatRequest(BaseModel):
    prompt: str
    session_id: str | None = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "guardrail_mode": config.GUARDRAIL_MODE,
        "block_on_input": config.BLOCK_ON_INPUT,
        "model": config.GEMINI_MODEL,
    }


@app.post("/chat")
async def chat(req: ChatRequest, request: Request):
    request_id = str(uuid.uuid4())
    session_id = req.session_id or str(uuid.uuid4())
    source_ip = request.client.host if request.client else None
    t0 = time.perf_counter()

    in_scan = guardrails.scan_input(req.prompt)

    gen = {"text": "", "usage": {"prompt_tokens": None, "output_tokens": None, "total_tokens": None}, "error": None}
    out_scan = {"valid": True, "flagged": [], "scores": {}}

    if config.BLOCK_ON_INPUT and not in_scan["valid"]:
        action = "blocked_input"
        response_text = REFUSAL_MSG
    else:
        gen = generate(in_scan.get("sanitized") or req.prompt)
        response_text = gen["text"]
        if gen["error"]:
            action = "error"
        else:
            out_scan = guardrails.scan_output(req.prompt, response_text)
            action = "flagged_output" if not out_scan["valid"] else "allowed"

    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    event = {
        "event_type": "llm_request",
        "request_id": request_id,
        "session_id": session_id,
        "source_ip": source_ip,
        "model": config.GEMINI_MODEL,
        "guardrail_mode": config.GUARDRAIL_MODE,
        "action": action,
        "prompt": req.prompt,
        "response": response_text,
        "prompt_chars": len(req.prompt),
        "response_chars": len(response_text),
        "tokens": gen["usage"],
        "latency_ms": latency_ms,
        "input_scan": {
            "valid": in_scan["valid"],
            "flagged": in_scan["flagged"],
            "scores": in_scan["scores"],
        },
        "output_scan": {
            "valid": out_scan["valid"],
            "flagged": out_scan["flagged"],
            "scores": out_scan["scores"],
        },
        "error": gen["error"],
    }
    logger.log(event)

    return {
        "request_id": request_id,
        "action": action,
        "response": response_text,
        "input_flagged": in_scan["flagged"],
        "output_flagged": out_scan["flagged"],
    }

# --- AWS Lambda entrypoint (Phase 2) ---
try:
    from mangum import Mangum
    handler = Mangum(app)
except ImportError:
    handler = None
