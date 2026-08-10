from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy gateway for enterprise LLM and GenAI requests",
    version="0.1.0",
)


class ChatRequest(BaseModel):
    prompt: str


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
def chat(request: ChatRequest):
    return {
        "prompt": request.prompt,
        "message": "Request received by LLM Security Gateway",
    }