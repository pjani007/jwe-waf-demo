#!/usr/bin/env python3
"""
Backend API for the JWE-WAF lab. Runs on api-backend (10.1.10.20:8080).

Deliberately trusting: it performs NO JWE decryption and NO input validation.
That is the point — every security outcome in the test matrix must be
attributable to the BIG-IP, so the origin must not accidentally save us.

Endpoints
  GET  /healthz                  liveness for the BIG-IP monitor
  POST /api/v1/echo              reports exactly what arrived (the proof instrument)
  POST /api/v1/orders            realistic typed endpoint for ASM to learn
  GET  /.well-known/jwks.json    public recipient keys, so the client can discover them

Run:
  uvicorn app:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import json
import os
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="JWE-WAF lab backend", version="1.0.0")

JWKS_PATH = os.environ.get("JWKS_PATH", "/opt/jwe-lab/jwks.json")

# A compact JWE is five base64url segments. If the backend sees THIS, the
# BIG-IP did not decrypt and the WAF was inspecting ciphertext.
JWE_COMPACT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\."
                         r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _describe(request: Request, raw: bytes) -> dict:
    text = raw.decode("utf-8", errors="replace")
    looks_encrypted = bool(JWE_COMPACT.match(text.strip()))

    parsed, parse_error = None, None
    try:
        parsed = json.loads(text) if text.strip() else None
    except json.JSONDecodeError as e:
        parse_error = str(e)

    h = request.headers
    return {
        "content_type": h.get("content-type"),
        "original_content_type": h.get("x-original-content-type"),
        "jwe_decrypted_header": h.get("x-jwe-decrypted"),
        "jwe_kid": h.get("x-jwe-kid"),
        "req_id": h.get("x-jwe-req-id"),
        "body_bytes": len(raw),
        # The single most diagnostic field in the whole lab.
        "looks_like_undecrypted_jwe": looks_encrypted,
        "body_parsed": parsed,
        "body_parse_error": parse_error,
        "body_preview": text[:200],
    }


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/api/v1/echo")
async def echo(request: Request):
    """
    Returns a description of what actually arrived. Compare across the three VS:
    on the decrypting VS, content_type is application/json and
    looks_like_undecrypted_jwe is false; on the blind VS the reverse, which is
    the blind spot made visible.
    """
    return {"received": _describe(request, await request.body())}


@app.post("/api/v1/orders")
async def create_order(request: Request):
    """
    Realistic endpoint so the ASM policy has named parameters to learn and
    enforce. Values are echoed back unsanitised on purpose.
    """
    raw = await request.body()
    desc = _describe(request, raw)
    body = desc["body_parsed"] if isinstance(desc["body_parsed"], dict) else {}
    return {
        "order_id": "ord-10042",
        "status": "accepted",
        "note": body.get("note"),
        "qty": body.get("qty"),
        "received": desc,
    }


@app.get("/.well-known/jwks.json")
async def jwks():
    """
    Public recipient keys. Only asymmetric keys appear here — the profile A
    `dir` key is a shared secret and publishing it would hand out the
    decryption key. tools/keygen.py enforces that split.
    """
    try:
        with open(JWKS_PATH) as fh:
            return JSONResponse(content=json.load(fh))
    except FileNotFoundError:
        return JSONResponse(
            status_code=503,
            content={"error": "jwks_unavailable", "detail": f"{JWKS_PATH} not present"},
        )
