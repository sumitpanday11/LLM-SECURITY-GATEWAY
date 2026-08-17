from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
import logging
import uuid
from pydantic import BaseModel, Field
from app.security import detect_prompt_injection, verify_api_key
from app.rate_limit import is_rate_limited

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
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", "unknown")

    logger.exception(
        "Unhandled exception | request_id=%s | path=%s",
        request_id,
        request.url.path,
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
    request: ChatRequest,
    x_api_key: str | None = Header(default=None),
):
    request_id = request.state.request_id

    if not x_api_key or not verify_api_key(x_api_key):
        logger.warning(
            "Unauthorized request | request_id=%s",
            request_id,
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
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
        )

    if detect_prompt_injection(request.prompt):
        logger.warning(
            "Prompt injection detected | request_id=%s",
            request_id,
        )
        raise HTTPException(
            status_code=403,
            detail="Potential prompt injection detected",
        )

    logger.info(
        "Request accepted successfully | request_id=%s",
        request_id,
    )

    return {
        "blocked": False,
        "prompt": request.prompt,
        "message": "Request received by LLM Security Gateway",
        "request_id": request_id,
    }