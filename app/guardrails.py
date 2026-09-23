"""
Guardrails: produce the `guardrail_verdict` that drives most detections.

Two interchangeable backends, selected by GUARDRAIL_MODE:
  - "regex"     : fast, dependency-light pattern checks. Runs instantly.
  - "llm-guard" : ML scanners from Protect AI's LLM Guard (downloads models on first run).

Both expose the SAME shape:
    scan_input(prompt)            -> {valid, sanitized, flagged, scores}
    scan_output(prompt, response) -> {valid, sanitized, flagged, scores}
"""
import re
from app import config

# ---------------- REGEX BACKEND (fast fallback) ----------------
_INJECTION_PATTERNS = {
    "instruction_override": r"(?i)\b(ignore|disregard|forget)\b.{0,20}\b(previous|above|all|prior)\b.{0,20}\b(instructions?|prompts?)\b",
    "role_hijack": r"(?i)\byou are now\b|\bact as\b|\bpretend to be\b",
    "system_prompt_leak": r"(?i)(reveal|show|print|repeat).{0,20}(system )?prompt",
    "dan_jailbreak": r"(?i)\bdo anything now\b|\bDAN\b|developer mode",
    "delimiter_injection": r"</?(system|assistant|user)>",
}

_SENSITIVE_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "generic_api_key": r"(?i)(api[_-]?key|secret|token)[\"':=\s]{1,3}[A-Za-z0-9_\-]{16,}",
    "email": r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    "credit_card": r"\b(?:\d[ -]?){13,16}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

_REFUSAL_PATTERNS = r"(?i)\b(i can't|i cannot|i'm sorry|i am unable|i won't|i will not)\b"


def _regex_scan(text: str, pattern_map: dict) -> dict:
    scores, flagged = {}, []
    for name, pat in pattern_map.items():
        hit = bool(re.search(pat, text))
        scores[name] = 1.0 if hit else 0.0
        if hit:
            flagged.append(name)
    return {"flagged": flagged, "scores": scores}


def _regex_input(prompt: str) -> dict:
    inj = _regex_scan(prompt, _INJECTION_PATTERNS)
    sec = _regex_scan(prompt, _SENSITIVE_PATTERNS)
    flagged = inj["flagged"] + [f"secret:{s}" for s in sec["flagged"]]
    scores = {**inj["scores"], **{f"secret_{k}": v for k, v in sec["scores"].items()}}
    return {"valid": len(flagged) == 0, "sanitized": prompt, "flagged": flagged, "scores": scores}


def _regex_output(prompt: str, response: str) -> dict:
    sens = _regex_scan(response, _SENSITIVE_PATTERNS)
    refused = bool(re.search(_REFUSAL_PATTERNS, response))
    flagged = [f"leak:{s}" for s in sens["flagged"]]
    scores = {**{f"leak_{k}": v for k, v in sens["scores"].items()}, "refusal": 1.0 if refused else 0.0}
    return {"valid": len(flagged) == 0, "sanitized": response, "flagged": flagged, "scores": scores}


# ---------------- LLM-GUARD BACKEND (ML) ----------------
_lg_input_scanners = None
_lg_output_scanners = None


def _init_llm_guard():
    global _lg_input_scanners, _lg_output_scanners
    if _lg_input_scanners is not None:
        return
    from llm_guard.input_scanners import PromptInjection, Secrets, Toxicity, TokenLimit
    from llm_guard.input_scanners.prompt_injection import MatchType
    from llm_guard.output_scanners import Sensitive, NoRefusal

    _lg_input_scanners = [
        PromptInjection(threshold=config.PROMPT_INJECTION_THRESHOLD, match_type=MatchType.FULL),
        Secrets(),
        Toxicity(threshold=config.TOXICITY_THRESHOLD),
        TokenLimit(),
    ]
    _lg_output_scanners = [
        Sensitive(),
        NoRefusal(),
    ]


def _llmguard_input(prompt: str) -> dict:
    from llm_guard import scan_prompt
    _init_llm_guard()
    sanitized, results_valid, results_score = scan_prompt(_lg_input_scanners, prompt)
    flagged = [name for name, ok in results_valid.items() if not ok]
    return {"valid": all(results_valid.values()), "sanitized": sanitized,
            "flagged": flagged, "scores": results_score}


def _llmguard_output(prompt: str, response: str) -> dict:
    from llm_guard import scan_output
    _init_llm_guard()
    sanitized, results_valid, results_score = scan_output(_lg_output_scanners, prompt, response)
    flagged = [name for name, ok in results_valid.items() if not ok]
    return {"valid": all(results_valid.values()), "sanitized": sanitized,
            "flagged": flagged, "scores": results_score}


# ---------------- PUBLIC INTERFACE ----------------
def scan_input(prompt: str) -> dict:
    if config.GUARDRAIL_MODE == "llm-guard":
        return _llmguard_input(prompt)
    return _regex_input(prompt)


def scan_output(prompt: str, response: str) -> dict:
    if config.GUARDRAIL_MODE == "llm-guard":
        return _llmguard_output(prompt, response)
    return _regex_output(prompt, response)
