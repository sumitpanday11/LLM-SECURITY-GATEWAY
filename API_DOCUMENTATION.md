# LLM Security Gateway API Documentation

## Overview

The LLM Security Gateway provides a FastAPI-based security layer for LLM and GenAI applications.

The API applies authentication, authorization, rate limiting, input validation, threat detection, prompt security, output filtering, auditing, monitoring, and security incident correlation.

## Base URL

```text
http://127.0.0.1:8000
```

---

## 1. Gateway Information

### Endpoint

```http
GET /
```

### Description

Returns basic information about the LLM Security Gateway.

### Example

```powershell
curl.exe http://127.0.0.1:8000/
```

### Example Response

```json
{
  "message": "LLM Security Gateway is running",
  "version": "0.5.0"
}
```

---

## 2. Health Check

### Endpoint

```http
GET /health
```

### Description

Checks whether the gateway application is running correctly.

### Example

```powershell
curl.exe http://127.0.0.1:8000/health
```

### Example Response

```json
{
  "status": "healthy",
  "service": "llm-security-gateway"
}
```

---

## 3. Prometheus Metrics

### Endpoint

```http
GET /metrics
```

### Description

Returns application and security metrics in Prometheus-compatible format.

### Example

```powershell
curl.exe http://127.0.0.1:8000/metrics
```

---

## 4. Database Health Check

### Endpoint

```http
GET /health/database
```

### Description

Checks PostgreSQL database connectivity.

### Example

```powershell
curl.exe http://127.0.0.1:8000/health/database
```

### Success Response

```json
{
  "status": "healthy",
  "database": [
    "llm_security_gateway",
    "postgres"
  ]
}
```

### Failure

If PostgreSQL is unavailable, the endpoint returns HTTP `503`.

---

# API Key Management

## 5. API Key Information

### Endpoint

```http
GET /keys/info
```

### Authentication

Requires a valid API key with the appropriate `key_info` permission.

### Header

```text
x-api-key: <API_KEY>
```

### Example

```powershell
curl.exe -X GET "http://127.0.0.1:8000/keys/info" `
-H "x-api-key: dev-secret-key"
```

### Response

```json
{
  "key_id": "example-key-id",
  "created_at": "timestamp",
  "active": true,
  "role": "admin",
  "request_id": "request-uuid"
}
```

---

## 6. Generate API Key

### Endpoint

```http
POST /keys/generate
```

### Description

Generates a new user API key.

### Authentication

Requires a valid API key with the appropriate `key_generate` permission.

### Header

```text
x-api-key: <API_KEY>
```

### Example

```powershell
curl.exe -X POST "http://127.0.0.1:8000/keys/generate" `
-H "x-api-key: dev-secret-key"
```

### Response

```json
{
  "message": "API key generated successfully",
  "api_key": "<GENERATED_API_KEY>",
  "role": "user",
  "created_by_role": "admin",
  "request_id": "request-uuid"
}
```

> Generated API keys should be treated as secrets and must not be committed to source control.

---

## 7. Revoke API Key

### Endpoint

```http
POST /keys/revoke
```

### Description

Revokes an existing API key.

### Authentication

Requires a valid API key with the appropriate `key_revoke` permission.

### Header

```text
x-api-key: <API_KEY>
```

### Query Parameter

```text
old_api_key=<API_KEY_TO_REVOKE>
```

### Example

```powershell
curl.exe -X POST "http://127.0.0.1:8000/keys/revoke?old_api_key=<API_KEY_TO_REVOKE>" `
-H "x-api-key: dev-secret-key"
```

### Success Response

```json
{
  "message": "API key revoked successfully",
  "performed_by_role": "admin",
  "request_id": "request-uuid"
}
```

---

## 8. Rotate API Key

### Endpoint

```http
POST /keys/rotate
```

### Description

Revokes/replaces an existing API key and returns a new API key.

### Authentication

Requires a valid API key with the appropriate `key_rotate` permission.

### Header

```text
x-api-key: <API_KEY>
```

### Request Body

```json
{
  "old_api_key": "<API_KEY_TO_ROTATE>"
}
```

### Example

```powershell
curl.exe -X POST "http://127.0.0.1:8000/keys/rotate" `
-H "x-api-key: dev-secret-key" `
-H "Content-Type: application/json" `
-d '{"old_api_key":"<API_KEY_TO_ROTATE>"}'
```

### Success Response

```json
{
  "message": "API key rotated successfully",
  "new_api_key": "<NEW_API_KEY>",
  "role": "user",
  "rotated_by_role": "admin",
  "request_id": "request-uuid"
}
```

---

# LLM Chat Endpoint

## 9. Chat

### Endpoint

```http
POST /chat
```

### Description

Processes an LLM request through the security gateway.

The request passes through multiple security controls including:

1. Threat intelligence check
2. Authentication protection
3. API key authentication
4. RBAC authorization
5. Semantic cache lookup
6. Redis rate limiting
7. PII detection and redaction
8. PHI detection and redaction
9. Prompt risk scoring
10. LLM firewall policy inspection
11. Prompt injection detection
12. LLM/application processing
13. Unsafe output filtering
14. Secret/credential leak detection
15. Security incident correlation
16. Security event logging
17. Semantic cache storage

### Authentication

Requires a valid API key.

### Headers

```text
x-api-key: <API_KEY>
Content-Type: application/json
```

### Request Body

```json
{
  "prompt": "Hello gateway"
}
```

### Prompt Restrictions

The `prompt` field:

* Must contain at least 1 character.
* Must not exceed 4000 characters.
* Must be provided as a valid JSON request.

### Example Request

```powershell
curl.exe -X POST "http://127.0.0.1:8000/chat" `
-H "x-api-key: dev-secret-key" `
-H "Content-Type: application/json" `
-d '{"prompt":"Hello gateway"}'
```

### Example Successful Response

```json
{
  "blocked": false,
  "prompt": "Hello gateway",
  "risk_score": 0,
  "risk_level": "Low",
  "risk_reasons": [],
  "output": "Request processed successfully. The gateway did not expose any internal credentials.",
  "output_threats": [],
  "role": "user",
  "message": "Request processed by LLM Security Gateway",
  "cached": false,
  "request_id": "request-uuid"
}
```

### Cached Response

If a matching semantic cache entry is available, the gateway can return a cached response with:

```json
{
  "cached": true
}
```

The response also includes the current request ID and role.

---

# Security Controls

## API Key Authentication

Validates API keys before allowing access to protected resources.

The gateway supports API key persistence, validation, rotation, and revocation.

## RBAC

Role-Based Access Control restricts protected operations according to assigned permissions.

## Redis Rate Limiting

Redis-based rate limiting controls excessive requests and helps reduce abuse.

## Authentication Protection

Repeated failed authentication attempts can temporarily block a client.

## Request Validation

Pydantic validation enforces request structure and prompt length restrictions.

## Payload Size Limiting

`/chat` requests larger than 1 MB are rejected.

### Response

```text
413 Payload Too Large
```

## Content-Type Enforcement

The `/chat` endpoint requires:

```text
Content-Type: application/json
```

Invalid content types return:

```text
415 Unsupported Media Type
```

## CORS Security

CORS is configured with restricted origins and allowed HTTP methods and headers.

## Security Response Headers

The gateway applies:

```text
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cache-Control: no-store
```

## Request Correlation IDs

Each request receives a unique request identifier.

The identifier is returned using:

```text
X-Request-ID
```

The same request ID is also included in relevant response and security event data.

## Threat Intelligence

Client IP addresses can be checked against configured threat-intelligence rules.

Threatened clients can be blocked with HTTP `403`.

## PII Detection and Redaction

Incoming prompts are inspected for personally identifiable information.

Detected PII can be redacted before further processing.

## PHI Detection and Redaction

Incoming prompts are inspected for protected health information.

Detected PHI can be redacted before further processing.

## Prompt Risk Scoring

Prompts receive a security risk score and severity classification.

Risk levels include:

* Low
* Medium
* High
* Critical

## LLM Firewall / Policy Engine

Incoming prompts are inspected against configurable security policies.

A blocked request returns HTTP `403` with firewall and risk information.

## Prompt Injection Detection

Prompts are inspected for suspicious patterns associated with prompt injection attacks.

Detected prompt injection attempts can be blocked.

## Jailbreak Detection

The project includes jailbreak detection capability as part of its LLM security controls.

Jailbreak-style attempts are treated as suspicious prompt behavior and can contribute to security risk evaluation.

## Secret / Credential Leak Detection

LLM output is inspected for sensitive credential patterns including:

* API keys
* Tokens
* Bearer tokens
* Passwords
* Other secret-like values

Detected secrets can be redacted before the response is returned.

## Unsafe Output Filtering

Generated output is inspected for unsafe or sensitive content before being returned to the client.

Detected output threats are included in the response metadata where applicable.

## Semantic Cache

Semantically similar requests can use cached responses where applicable.

Cached responses include a `cached` indicator.

## Security Event Logging

Security-relevant events are recorded for monitoring and investigation.

## PostgreSQL Audit Logging

Security and audit information can be stored persistently in PostgreSQL.

## Security Incident Correlation

Related security events can be correlated using API-key and client-IP context to identify potentially connected suspicious activity.

## Prometheus Monitoring

Prometheus-compatible metrics are exposed through:

```text
GET /metrics
```

---

# Common HTTP Status Codes

| Status Code | Meaning                                           |
| ----------- | ------------------------------------------------- |
| `200`       | Request successful                                |
| `201`       | Resource successfully created                     |
| `400`       | Bad request                                       |
| `401`       | Invalid or missing authentication                 |
| `403`       | Request blocked or access forbidden               |
| `404`       | Resource not found                                |
| `413`       | Request payload too large                         |
| `415`       | Unsupported media type                            |
| `422`       | Request validation error                          |
| `429`       | Rate limit or authentication protection triggered |
| `500`       | Internal server error                             |
| `503`       | PostgreSQL database unavailable                   |
| `504`       | Request processing timeout                        |

---

# Error Response Examples

## Invalid API Key

```json
{
  "detail": "Invalid or missing API key"
}
```

## Rate Limit

```json
{
  "detail": "Too many requests. Please try again later."
}
```

## Prompt Injection

```json
{
  "detail": "Potential prompt injection detected"
}
```

## Firewall Block

```json
{
  "detail": {
    "message": "Request blocked by security policy",
    "rule": "example-rule",
    "risk_score": 80,
    "risk_level": "High",
    "risk_reasons": [],
    "request_id": "request-uuid"
  }
}
```

## Payload Too Large

```json
{
  "error": "Payload Too Large",
  "message": "Request body must not exceed 1 MB",
  "request_id": "request-uuid"
}
```

---

# Testing the API

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
-H "x-api-key: dev-secret-key" `
-H "Content-Type: application/json" `
-d '{"prompt":"Hello gateway"}'
```

---

# Interactive API Documentation

FastAPI automatically provides interactive API documentation.

### Swagger UI

```text
http://127.0.0.1:8000/docs
```

### ReDoc

```text
http://127.0.0.1:8000/redoc
```

These interfaces can be used to inspect and test the available API endpoints.

---

# Security Testing Checklist

The API should be tested for:

* Invalid API keys
* Missing API keys
* Failed authentication protection
* Unauthorized RBAC operations
* API key generation
* API key revocation
* API key rotation
* Rate limit enforcement
* PII detection and redaction
* PHI detection and redaction
* Prompt injection attempts
* Prompt risk scoring
* LLM firewall policies
* Jailbreak-style prompts
* Secret and credential detection
* Unsafe output filtering
* Semantic cache behavior
* Threat intelligence blocking
* Invalid request payloads
* Oversized requests
* Unsupported content types
* Database connectivity
* Audit logging
* Security incident correlation
* Prometheus metrics
* Security response headers
* Request correlation IDs

---

# Project Information

**LLM Security Gateway**

Cyber Security Internship Project

**Author:** Sumit Panday

**Program:** B.Tech CSE Cyber Security

**Organization:** Zaalima Development Pvt Ltd
