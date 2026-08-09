from fastapi import FastAPI

app = FastAPI(title="LLM Security Gateway")


@app.get("/")
def root():
    return {
        "message": "LLM Security Gateway is running"
    }