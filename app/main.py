from fastapi import FastAPI, HTTPException, Header, Request
import logging
from pydantic import BaseModel, Field
from app.security import detect_prompt_injection, verify_api_key
from app.rate_limit import is_rate_limited

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for enterprise LLM and GenAI requests",
    version="0.1.0",
)

logger = logging.getLogger("llm-security-gateway")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


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
    if not x_api_key or not verify_api_key(x_api_key):
        logger.warning("Unauthorized request: invalid or missing API key")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
        )

    if is_rate_limited(x_api_key):
        logger.warning("Rate limit exceeded for API key")
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
        )

    if detect_prompt_injection(request.prompt):
        logger.warning("Request blocked: prompt injection detected")
        raise HTTPException(
            status_code=403,
            detail="Potential prompt injection detected",
        )

    logger.info("Request accepted successfully")

    return {
        "blocked": False,
        "prompt": request.prompt,
        "message": "Request received by LLM Security Gateway",
    }