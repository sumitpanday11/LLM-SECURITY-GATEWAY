\# LLM Security Gateway - API Documentation



\## Overview



The LLM Security Gateway provides security controls for LLM and GenAI applications through a FastAPI-based API.



The gateway provides authentication, authorization, API key management, rate limiting, security validation, audit logging, monitoring, and protected LLM request processing.



\## Base URL



```text

http://127.0.0.1:8000

```



\---



\## API Endpoints



\### 1. Gateway Information



\*\*Endpoint\*\*



```http

GET /

```



\*\*Description\*\*



Returns basic information about the LLM Security Gateway.



\*\*Example\*\*



```powershell

curl.exe http://127.0.0.1:8000/

```



\---



\### 2. Health Check



\*\*Endpoint\*\*



```http

GET /health

```



\*\*Description\*\*



Checks whether the gateway application is running correctly.



\*\*Example\*\*



```powershell

curl.exe http://127.0.0.1:8000/health

```



\*\*Example Response\*\*



```json

{

&#x20; "status": "healthy",

&#x20; "service": "llm-security-gateway"

}

```



\---



\### 3. Prometheus Metrics



\*\*Endpoint\*\*



```http

GET /metrics

```



\*\*Description\*\*



Returns application metrics in Prometheus-compatible format.



\*\*Example\*\*



```powershell

curl.exe http://127.0.0.1:8000/metrics

```



\---



\### 4. Database Health Check



\*\*Endpoint\*\*



```http

GET /health/database

```



\*\*Description\*\*



Checks the connectivity and health of the PostgreSQL database used by the gateway.



\*\*Example\*\*



```powershell

curl.exe http://127.0.0.1:8000/health/database

```



\---



\## API Key Management



\### 5. API Key Information



\*\*Endpoint\*\*



```http

GET /keys/info

```



\*\*Description\*\*



Returns information related to API key management.



\*\*Authentication\*\*



This endpoint requires valid API key authentication and appropriate authorization.



\*\*Header\*\*



```text

x-api-key: <API\_KEY>

```



\*\*Example\*\*



```powershell

curl.exe -X GET "http://127.0.0.1:8000/keys/info" `

\-H "x-api-key: dev-secret-key"

```



\---



\### 6. Generate API Key



\*\*Endpoint\*\*



```http

POST /keys/generate

```



\*\*Description\*\*



Generates a new API key for authorized users.



\*\*Authentication\*\*



Requires a valid API key and appropriate authorization.



\*\*Header\*\*



```text

x-api-key: <API\_KEY>

```



\*\*Example\*\*



```powershell

curl.exe -X POST "http://127.0.0.1:8000/keys/generate" `

\-H "x-api-key: dev-secret-key"

```



\---



\### 7. Revoke API Key



\*\*Endpoint\*\*



```http

POST /keys/revoke

```



\*\*Description\*\*



Revokes an existing API key so that it can no longer be used for authentication.



\*\*Authentication\*\*



Requires a valid API key and appropriate authorization.



\*\*Header\*\*



```text

x-api-key: <API\_KEY>

```



\*\*Example\*\*



```powershell

curl.exe -X POST "http://127.0.0.1:8000/keys/revoke" `

\-H "x-api-key: dev-secret-key" `

\-H "Content-Type: application/json"

```



> The request body must contain the parameters required by the current API implementation.



\---



\### 8. Rotate API Key



\*\*Endpoint\*\*



```http

POST /keys/rotate

```



\*\*Description\*\*



Rotates an existing API key and creates a replacement key.



\*\*Authentication\*\*



Requires a valid API key and appropriate authorization.



\*\*Header\*\*



```text

x-api-key: <API\_KEY>

```



\*\*Example\*\*



```powershell

curl.exe -X POST "http://127.0.0.1:8000/keys/rotate" `

\-H "x-api-key: dev-secret-key" `

\-H "Content-Type: application/json"

```



> The request body must contain the parameters required by the current API implementation.



\---



\## LLM Chat Endpoint



\### 9. Chat



\*\*Endpoint\*\*



```http

POST /chat

```



\*\*Description\*\*



Processes an LLM request through the security gateway.



Before processing the request, the gateway applies multiple security controls including authentication, authorization, rate limiting, input validation, prompt injection detection, and security monitoring.



\*\*Authentication\*\*



Requires a valid API key.



\*\*Headers\*\*



```text

x-api-key: <API\_KEY>

Content-Type: application/json

```



\*\*Request Body\*\*



```json

{

&#x20; "prompt": "Hello gateway"

}

```



\*\*Example Request\*\*



```powershell

curl.exe -X POST "http://127.0.0.1:8000/chat" `

\-H "x-api-key: dev-secret-key" `

\-H "Content-Type: application/json" `

\-d "{\\"prompt\\":\\"Hello gateway\\"}"

```



\*\*Example Response\*\*



```json

{

&#x20; "blocked": false,

&#x20; "prompt": "Hello gateway",

&#x20; "output": "Request processed successfully."

}

```



> The exact response fields may vary depending on the security checks and current application implementation.



\---



\## Authentication



Protected endpoints use API key authentication.



The API key must be supplied using the following HTTP header:



```text

x-api-key: <API\_KEY>

```



Requests with missing or invalid API keys are rejected by the gateway.



\---



\## Security Controls



The API layer is protected by multiple security controls.



\### API Key Authentication



Validates API keys before allowing access to protected resources.



\### API Key Rotation and Revocation



Provides mechanisms to rotate and revoke API keys.



\### Role-Based Access Control



RBAC restricts sensitive operations based on user roles and permissions.



\### Redis-Based Rate Limiting



Limits excessive requests and helps protect the gateway against abuse.



\### Input Validation



Validates incoming request data and enforces prompt length and format restrictions.



\### Prompt Injection Detection



Analyzes incoming prompts for suspicious patterns associated with prompt injection attacks.



\### Output Filtering



Security checks are also applied to generated output before it is returned to the client.



\### Content-Type Enforcement



Protected JSON endpoints require the appropriate `Content-Type` header.



\### Request Payload Size Limiting



Large request payloads are rejected to reduce abuse and resource exhaustion risks.



\### CORS Security



Cross-Origin Resource Sharing is configured with security restrictions.



\### Security Response Headers



The gateway applies security headers including:



```text

X-Content-Type-Options: nosniff

X-Frame-Options: DENY

Referrer-Policy: no-referrer

Cache-Control: no-store

```



\### Request Correlation IDs



Requests are assigned correlation identifiers to improve tracing and security investigation.



\### Global Exception Handling



Unhandled application exceptions are processed through centralized exception handling.



\### Audit Logging



Security-related events are recorded for auditing and investigation.



\### PostgreSQL Integration



PostgreSQL is used for persistent audit and security-related data.



\### Prometheus Metrics



The `/metrics` endpoint exposes application metrics in Prometheus-compatible format.



\---



\## Common HTTP Status Codes



| Status Code | Meaning                            |

| ----------- | ---------------------------------- |

| `200`       | Request successful                 |

| `201`       | Resource successfully created      |

| `400`       | Bad request                        |

| `401`       | Authentication required or invalid |

| `403`       | Access forbidden                   |

| `404`       | Resource not found                 |

| `415`       | Unsupported Media Type             |

| `422`       | Validation error                   |

| `429`       | Rate limit exceeded                |

| `500`       | Internal server error              |

| `413`       | Request payload too large          |



\---



\## Testing the API



Start the application:



```powershell

uvicorn app.main:app --reload

```



Run the automated test suite:



```powershell

pytest -q

```



Health check:



```powershell

curl.exe http://127.0.0.1:8000/health

```



Protected chat request:



```powershell

curl.exe -X POST "http://127.0.0.1:8000/chat" `

\-H "x-api-key: dev-secret-key" `

\-H "Content-Type: application/json" `

\-d "{\\"prompt\\":\\"Hello gateway\\"}"

```



\---



\## API Documentation Interface



FastAPI automatically provides interactive API documentation.



\### Swagger UI



```text

http://127.0.0.1:8000/docs

```



\### ReDoc



```text

http://127.0.0.1:8000/redoc

```



These interfaces can be used to inspect and test available API endpoints.



\---



\## Security Testing



The gateway should be tested for:



\* Invalid API keys

\* Missing API keys

\* Unauthorized RBAC operations

\* API key revocation

\* API key rotation

\* Rate limit enforcement

\* Prompt injection attempts

\* Invalid request payloads

\* Oversized requests

\* Unsupported content types

\* CORS restrictions

\* Database connectivity

\* Audit logging

\* Metrics availability

\* Output security filtering



\---



\## Project



\*\*LLM Security Gateway\*\*



Cyber Security Internship Project



\*\*Author:\*\* Sumit Panday



\*\*Organization:\*\* Zaalima Development Pvt Ltd



