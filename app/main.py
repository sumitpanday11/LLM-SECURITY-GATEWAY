from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import logging
import uuid
import asyncio
from pydantic import BaseModel, Field

from app.security import detect_prompt_injection, verify_api_key
from app.rate_limit import is_rate_limited
from app.audit_log import log_security_event


app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for enterprise LLM and GenAI requests",
    version="0.1.0",
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


MAX_REQUEST_SIZE = 1024 * 1024  # 1 MB
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


@app.get("/")
def root():
    return {
        "message": "LLM Security Gateway is running",
        "version": "0.1.0",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "llm-security-gateway",
    }


@app.post("/chat")
def chat(
    request: Request,
    chat_request: ChatRequest,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        logger.warning(
            "Unauthorized request | request_id=%s",
            request_id,
        )

        log_security_event(
            event="UNAUTHORIZED_REQUEST",
            request_id=request_id,
            details="Invalid or missing API key",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

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