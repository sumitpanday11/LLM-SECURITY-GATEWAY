from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import asyncio
import logging
import os
import uuid

from pydantic import BaseModel, Field

from app.security import (
    detect_prompt_injection,
    detect_pii,
    redact_pii,
    detect_phi,
    redact_phi,
    verify_api_key,
    generate_api_key,
    add_api_key,
    revoke_api_key,
    rotate_api_key,
    get_api_key_metadata,
)

from app.rbac import require_permission

from app.rate_limit import is_rate_limited

from app.auth_protection import (
    is_auth_blocked,
    record_failed_attempt,
    clear_failed_attempts,
)

from app.audit_log import log_security_event

from app.threat_intelligence import is_ip_threatened

from app.output_filter import filter_unsafe_output


app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for enterprise LLM and GenAI requests",
    version="0.3.0",
)


# ============================================================
# CORS SECURITY
# ============================================================

allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173",
).split(",")

allowed_origins = [
    origin.strip()
    for origin in allowed_origins
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


logger = logging.getLogger("llm-security-gateway")


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

MAX_REQUEST_SIZE = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10


# ============================================================
# REQUEST SIZE LIMIT
# ============================================================

@app.middleware("http")
async def enforce_request_size(request: Request, call_next):

    if request.method == "POST" and request.url.path == "/chat":

        content_length = request.headers.get("content-length")

        if content_length:

            try:
                request_size = int(content_length)
            except ValueError:
                request_size = 0

            if request_size > MAX_REQUEST_SIZE:

                request_id = getattr(
                    request.state,
                    "request_id",
                    "unknown",
                )

                logger.warning(
                    "Request body too large | request_id=%s | content_length=%s",
                    request_id,
                    content_length,
                )

                log_security_event(
                    event="PAYLOAD_TOO_LARGE",
                    request_id=request_id,
                    details="Request body exceeded 1 MB limit",
                )

                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "Payload Too Large",
                        "message": "Request body must not exceed 1 MB",
                        "request_id": request_id,
                    },
                )

    return await call_next(request)


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def add_security_headers(request: Request, call_next):

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


# ============================================================
# CONTENT TYPE ENFORCEMENT
# ============================================================

@app.middleware("http")
async def enforce_content_type(request: Request, call_next):

    if request.method == "POST" and request.url.path == "/chat":

        content_type = (
            request.headers.get("content-type", "")
            .split(";")[0]
            .strip()
            .lower()
        )

        if content_type != "application/json":

            request_id = getattr(
                request.state,
                "request_id",
                "unknown",
            )

            logger.warning(
                "Invalid content type | request_id=%s | content_type=%s",
                request_id,
                content_type,
            )

            log_security_event(
                event="INVALID_CONTENT_TYPE",
                request_id=request_id,
                details="Content-Type must be application/json",
            )

            return JSONResponse(
                status_code=415,
                content={
                    "error": "Unsupported Media Type",
                    "message": "Content-Type must be application/json",
                    "request_id": request_id,
                },
            )

    return await call_next(request)


# ============================================================
# REQUEST ID
# ============================================================

@app.middleware("http")
async def add_request_id(request: Request, call_next):

    request_id = str(uuid.uuid4())

    request.state.request_id = request_id

    logger.info(
        "Request started | request_id=%s | method=%s | path=%s",
        request_id,
        request.method,
        request.url.path,
    )

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id

    logger.info(
        "Request completed | request_id=%s | status_code=%s",
        request_id,
        response.status_code,
    )

    return response


# ============================================================
# REQUEST TIMEOUT
# ============================================================

@app.middleware("http")
async def enforce_request_timeout(request: Request, call_next):

    if request.method == "POST" and request.url.path == "/chat":

        try:

            return await asyncio.wait_for(
                call_next(request),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

        except asyncio.TimeoutError:

            request_id = getattr(
                request.state,
                "request_id",
                "unknown",
            )

            logger.warning(
                "Request timeout | request_id=%s | timeout=%ss",
                request_id,
                REQUEST_TIMEOUT_SECONDS,
            )

            log_security_event(
                event="REQUEST_TIMEOUT",
                request_id=request_id,
                details="Request processing exceeded 10 seconds",
            )

            return JSONResponse(
                status_code=504,
                content={
                    "error": "Gateway Timeout",
                    "message": "Request processing exceeded the allowed time",
                    "request_id": request_id,
                },
            )

    return await call_next(request)


# ============================================================
# GLOBAL EXCEPTION HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    request_id = getattr(
        request.state,
        "request_id",
        "unknown",
    )

    logger.exception(
        "Unhandled exception | request_id=%s | path=%s",
        request_id,
        request.url.path,
    )

    log_security_event(
        event="UNHANDLED_EXCEPTION",
        request_id=request_id,
        details="Internal server error",
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "request_id": request_id,
        },
    )


# ============================================================
# REQUEST MODELS
# ============================================================

class ChatRequest(BaseModel):

    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="User prompt for the LLM",
    )


class RotateKeyRequest(BaseModel):

    old_api_key: str = Field(
        ...,
        min_length=1,
    )


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "LLM Security Gateway is running",
        "version": "0.3.0",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "llm-security-gateway",
    }


# ============================================================
# API KEY INFORMATION
# ============================================================

@app.get("/keys/info")
def get_key_info(
    request: Request,
    x_api_key: str | None = Header(default=None),
):

    request_id = request.state.request_id

    # Authentication
    if not x_api_key or not verify_api_key(x_api_key):

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    # RBAC
    role = require_permission(
        x_api_key,
        "key_info",
    )

    metadata = get_api_key_metadata(x_api_key)

    if metadata is None:

        raise HTTPException(
            status_code=404,
            detail="API key not found",
        )

    log_security_event(
        event="API_KEY_INFO_ACCESSED",
        request_id=request_id,
        details=f"API key metadata accessed | role={role}",
    )

    return {
        "key_id": metadata["key_id"],
        "created_at": metadata["created_at"],
        "active": metadata["active"],
        "role": role,
        "request_id": request_id,
    }


# ============================================================
# API KEY GENERATION
# ============================================================

@app.post("/keys/generate")
def create_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
):

    request_id = request.state.request_id

    # Authentication
    if not x_api_key or not verify_api_key(x_api_key):

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    # RBAC - ADMIN ONLY
    role = require_permission(
        x_api_key,
        "key_generate",
    )

    new_api_key = generate_api_key()

    # New keys are USER keys by default.
    add_api_key(
        new_api_key,
        role="user",
    )

    log_security_event(
        event="API_KEY_GENERATED",
        request_id=request_id,
        details=(
            f"New user API key generated by role={role}"
        ),
    )

    return {
        "message": "API key generated successfully",
        "api_key": new_api_key,
        "role": "user",
        "created_by_role": role,
        "request_id": request_id,
    }


# ============================================================
# API KEY REVOCATION
# ============================================================

@app.post("/keys/revoke")
def revoke_key(
    request: Request,
    old_api_key: str,
    x_api_key: str | None = Header(default=None),
):

    request_id = request.state.request_id

    # Authentication
    if not x_api_key or not verify_api_key(x_api_key):

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    # RBAC - ADMIN ONLY
    role = require_permission(
        x_api_key,
        "key_revoke",
    )

    if not revoke_api_key(old_api_key):

        raise HTTPException(
            status_code=404,
            detail="API key not found",
        )

    log_security_event(
        event="API_KEY_REVOKED",
        request_id=request_id,
        details=f"API key revoked by role={role}",
    )

    return {
        "message": "API key revoked successfully",
        "performed_by_role": role,
        "request_id": request_id,
    }


# ============================================================
# API KEY ROTATION
# ============================================================

@app.post("/keys/rotate")
def rotate_key(
    request: Request,
    rotate_request: RotateKeyRequest,
    x_api_key: str | None = Header(default=None),
):

    request_id = request.state.request_id

    # Authentication
    if not x_api_key or not verify_api_key(x_api_key):

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    # RBAC - ADMIN ONLY
    role = require_permission(
        x_api_key,
        "key_rotate",
    )

    new_api_key = rotate_api_key(
        rotate_request.old_api_key
    )

    if new_api_key is None:

        raise HTTPException(
            status_code=404,
            detail="Old API key not found",
        )

    log_security_event(
        event="API_KEY_ROTATED",
        request_id=request_id,
        details=f"API key rotated by role={role}",
    )

    return {
        "message": "API key rotated successfully",
        "new_api_key": new_api_key,
        "role": "user",
        "rotated_by_role": role,
        "request_id": request_id,
    }


# ============================================================
# CHAT SECURITY PIPELINE
# ============================================================

@app.post("/chat")
def chat(
    request: Request,
    chat_request: ChatRequest,
    x_api_key: str | None = Header(default=None),
):

    request_id = request.state.request_id

    client_id = (
        request.client.host
        if request.client
        else "unknown"
    )

    # ========================================================
    # 1. THREAT INTELLIGENCE
    # ========================================================

    if is_ip_threatened(client_id):

        logger.warning(
            "Threat intelligence block | request_id=%s | client_ip=%s",
            request_id,
            client_id,
        )

        log_security_event(
            event="THREAT_INTELLIGENCE_BLOCK",
            request_id=request_id,
            details="Client IP matched threat-intelligence blocklist",
        )

        raise HTTPException(
            status_code=403,
            detail="Request blocked by threat intelligence policy",
        )

    # ========================================================
    # 2. FAILED AUTHENTICATION PROTECTION
    # ========================================================

    if is_auth_blocked(client_id):

        logger.warning(
            "Authentication temporarily blocked | request_id=%s | client_id=%s",
            request_id,
            client_id,
        )

        log_security_event(
            event="AUTHENTICATION_BLOCKED",
            request_id=request_id,
            details="Too many failed API key attempts",
        )

        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed authentication attempts. "
                "Please try again later."
            ),
        )

    # ========================================================
    # 3. API KEY AUTHENTICATION
    # ========================================================

    if not x_api_key or not verify_api_key(x_api_key):

        blocked = record_failed_attempt(client_id)

        logger.warning(
            "Unauthorized request | request_id=%s",
            request_id,
        )

        log_security_event(
            event="UNAUTHORIZED_REQUEST",
            request_id=request_id,
            details="Invalid or missing API key",
        )

        if blocked:

            raise HTTPException(
                status_code=429,
                detail=(
                    "Too many failed authentication attempts. "
                    "Please try again later."
                ),
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    clear_failed_attempts(client_id)

    # ========================================================
    # 4. RBAC
    # ========================================================

    role = require_permission(
        x_api_key,
        "chat",
    )

    # ========================================================
    # 5. RATE LIMITING
    # ========================================================

    if is_rate_limited(x_api_key):

        logger.warning(
            "Rate limit exceeded | request_id=%s",
            request_id,
        )

        log_security_event(
            event="RATE_LIMIT_EXCEEDED",
            request_id=request_id,
            details="API request limit exceeded",
        )

        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
        )

    # ========================================================
    # 6. PII DETECTION AND REDACTION
    # ========================================================

    detected_pii = detect_pii(
        chat_request.prompt
    )

    if detected_pii:

        logger.warning(
            "PII detected | request_id=%s | types=%s",
            request_id,
            ",".join(detected_pii),
        )

        log_security_event(
            event="PII_DETECTED",
            request_id=request_id,
            details=(
                f"PII detected: "
                f"{','.join(detected_pii)}"
            ),
        )

        sanitized_prompt = redact_pii(
            chat_request.prompt
        )

    else:

        sanitized_prompt = chat_request.prompt

    # ========================================================
    # 7. PHI DETECTION AND REDACTION
    # ========================================================

    detected_phi = detect_phi(
        sanitized_prompt
    )

    if detected_phi:

        logger.warning(
            "PHI detected | request_id=%s | types=%s",
            request_id,
            ",".join(detected_phi),
        )

        log_security_event(
            event="PHI_DETECTED",
            request_id=request_id,
            details=(
                f"PHI detected: "
                f"{','.join(detected_phi)}"
            ),
        )

        sanitized_prompt = redact_phi(
            sanitized_prompt
        )

    # ========================================================
    # 8. ADVANCED PROMPT INJECTION DETECTION
    # ========================================================

    if detect_prompt_injection(
        sanitized_prompt
    ):

        logger.warning(
            "Prompt injection detected | request_id=%s",
            request_id,
        )

        log_security_event(
            event="PROMPT_INJECTION_DETECTED",
            request_id=request_id,
            details=(
                "Potential advanced prompt injection detected"
            ),
        )

        raise HTTPException(
            status_code=403,
            detail="Potential prompt injection detected",
        )

    # ========================================================
    # 9. SIMULATED LLM OUTPUT
    # ========================================================

    llm_output = (
        "Request processed successfully. "
        "The gateway did not expose any internal credentials."
    )

    # ========================================================
    # 10. UNSAFE OUTPUT FILTERING
    # ========================================================

    sanitized_output, detected_output_threats = (
        filter_unsafe_output(llm_output)
    )

    if detected_output_threats:

        logger.warning(
            "Unsafe output detected | request_id=%s | types=%s",
            request_id,
            ",".join(detected_output_threats),
        )

        log_security_event(
            event="UNSAFE_OUTPUT_DETECTED",
            request_id=request_id,
            details=(
                f"Unsafe output detected: "
                f"{','.join(detected_output_threats)}"
            ),
        )

    # ========================================================
    # 11. REQUEST ACCEPTED
    # ========================================================

    logger.info(
        "Request accepted successfully | request_id=%s | role=%s",
        request_id,
        role,
    )

    log_security_event(
        event="REQUEST_ACCEPTED",
        request_id=request_id,
        details=(
            f"Chat request passed security checks | role={role}"
        ),
    )

    return {
        "blocked": False,
        "prompt": sanitized_prompt,
        "output": sanitized_output,
        "output_threats": detected_output_threats,
        "role": role,
        "message": "Request processed by LLM Security Gateway",
        "request_id": request_id,
    }