"""Thin Ollama client.

Every call degrades gracefully: if Ollama is not running, the caller gets
None and the pipeline continues. The LLM is an accelerant, never a
dependency.
"""

from __future__ import annotations

import json
import logging

import httpx

from .config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

log = logging.getLogger(__name__)


async def available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_BASE_URL}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


async def list_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_BASE_URL}/api/tags")
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


async def complete(prompt: str, *, system: str = "", json_mode: bool = False,
                   temperature: float = 0.1, model: str | None = None) -> str | None:
    payload = {
        "model": model or OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": 8192},
    }
    if system:
        payload["system"] = system
    if json_mode:
        payload["format"] = "json"

    try:
        async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT) as c:
            r = await c.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload)
            r.raise_for_status()
            return r.json().get("response", "").strip()
    except Exception as exc:  # noqa: BLE001
        log.warning("Ollama call failed: %s", exc)
        return None


async def complete_json(prompt: str, *, system: str = "", **kw) -> dict | None:
    raw = await complete(prompt, system=system, json_mode=True, **kw)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Small models sometimes wrap JSON in prose or fences.
        start, end = raw.find("{"), raw.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except json.JSONDecodeError:
                pass
        log.warning("Could not parse model output as JSON")
        return None
