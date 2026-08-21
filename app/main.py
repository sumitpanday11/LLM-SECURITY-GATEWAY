from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import logging
import uuid
import asyncio
from pydantic import BaseModel, Field

from app.security import (
    detect_prompt_injection,
    verify_api_key,
    generate_api_key,
    add_api_key,
    revoke_api_key,
    rotate_api_key,
    get_api_key_metadata,
)
from app.rate_limit import is_rate_limited
from app.auth_protection import (
    is_auth_blocked,
    record_failed_attempt,
    clear_failed_attempts,
)
from app.audit_log import log_security_event


app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for enterprise LLM and GenAI requests",
    version="0.2.0",
)


allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5173",
).split(",")


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)


logger = logging.getLogger("llm-security-gateway")


MAX_REQUEST_SIZE = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10


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


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


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


class ChatRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="User prompt for the LLM",
    )


class RotateKeyRequest(BaseModel):
    old_api_key: str = Field(..., min_length=1)


@app.get("/")
def root():
    return {
        "message": "LLM Security Gateway is running",
        "version": "0.2.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "llm-security-gateway",
    }


@app.get("/keys/info")
def get_key_info(
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
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
        details="API key metadata accessed",
    )

    return {
        "key_id": metadata["key_id"],
        "created_at": metadata["created_at"],
        "active": metadata["active"],
        "request_id": request_id,
    }


@app.post("/keys/generate")
def create_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    new_api_key = generate_api_key()
    add_api_key(new_api_key)

    log_security_event(
        event="API_KEY_GENERATED",
        request_id=request_id,
        details="New API key generated",
    )

    return {
        "message": "API key generated successfully",
        "api_key": new_api_key,
        "request_id": request_id,
    }


@app.post("/keys/revoke")
def revoke_key(
    request: Request,
    old_api_key: str,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    if not revoke_api_key(old_api_key):
        raise HTTPException(
            status_code=404,
            detail="API key not found",
        )

    log_security_event(
        event="API_KEY_REVOKED",
        request_id=request_id,
        details="API key revoked",
    )

    return {
        "message": "API key revoked successfully",
        "request_id": request_id,
    }


@app.post("/keys/rotate")
def rotate_key(
    request: Request,
    rotate_request: RotateKeyRequest,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    new_api_key = rotate_api_key(rotate_request.old_api_key)

    if new_api_key is None:
        raise HTTPException(
            status_code=404,
            detail="Old API key not found",
        )

    log_security_event(
        event="API_KEY_ROTATED",
        request_id=request_id,
        details="API key rotated successfully",
    )

    return {
        "message": "API key rotated successfully",
        "new_api_key": new_api_key,
        "request_id": request_id,
    }


@app.post("/chat")
def chat(
    request: Request,
    chat_request: ChatRequest,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    client_id = request.client.host if request.client else "unknown"

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
            detail="Too many failed authentication attempts. Please try again later.",
        )

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
                detail="Too many failed authentication attempts. Please try again later.",
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    clear_failed_attempts(client_id)

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

    if detect_prompt_injection(chat_request.prompt):
        logger.warning(
            "Prompt injection detected | request_id=%s",
            request_id,
        )

        log_security_event(
            event="PROMPT_INJECTION_DETECTED",
            request_id=request_id,
            details="Potential prompt injection detected",
        )

        raise HTTPException(
            status_code=403,
            detail="Potential prompt injection detected",
        )

    logger.info(
        "Request accepted successfully | request_id=%s",
        request_id,
    )

    log_security_event(
        event="REQUEST_ACCEPTED",
        request_id=request_id,
        details="Chat request passed security checks",
    )

    return {
        "blocked": False,
        "prompt": chat_request.prompt,
        "message": "Request received by LLM Security Gateway",
        "request_id": request_id,
    }