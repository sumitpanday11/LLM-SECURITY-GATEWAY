# LLM Security Gateway

An enterprise-focused security gateway built with FastAPI to protect LLM and GenAI applications from common security threats.

The gateway provides multiple security layers for authentication, authorization, request validation, prompt protection, secret detection, threat intelligence, output filtering, auditing, monitoring, and security incident correlation.

## Features

### Authentication & Authorization

* API Key Authentication
* API Key Rotation and Revocation
* Redis-Based API Key Persistence
* Role-Based Access Control (RBAC)

### Request & API Security

* Redis-Based Rate Limiting
* Input Validation
* Request Payload Size Limiting
* Content-Type Enforcement
* CORS Security Configuration
* Security Response Headers
* Request Correlation IDs
* Global Exception Handling

### LLM Security

* LLM Firewall / Policy Engine
* Prompt Injection Detection
* Prompt Risk Scoring
* Jailbreak Detection
* Threat Intelligence Checks
* Secret / Credential Leak Detection
* Unsafe Output Filtering
* Semantic Cache

### Monitoring & Auditing

* Security Event Logging
* Security Incident Correlation
* PostgreSQL Audit Logging
* Prometheus Metrics
* Database Health Monitoring

### Testing & Deployment

* Automated Security Tests
* Docker Support
* Docker Compose Configuration

## Security Architecture

The gateway applies multiple security controls before allowing requests to reach the LLM or application backend.

```text
                         Client
                           |
                           v
                  +-------------------+
                  |   FastAPI Gateway  |
                  +-------------------+
                           |
                           v
                  API Key Authentication
                           |
                           v
                    RBAC Authorization
                           |
                           v
                  Redis Rate Limiting
                           |
                           v
                   Request Validation
                           |
                           v
                LLM Firewall / Policies
                           |
                           v
                 Prompt Risk Scoring
                           |
                           v
                 Jailbreak Detection
                           |
                           v
              Prompt Injection Detection
                           |
                           v
               Threat Intelligence
                           |
                           v
                    LLM / Backend
                           |
                           v
              Secret / Credential Detection
                           |
                           v
                Unsafe Output Filtering
                           |
                           v
                 Security Event Logging
                           |
              +------------+-------------+
              |                          |
              v                          v
       PostgreSQL Audit            Prometheus
           Storage                  Metrics
              |
              v
       Incident Correlation
```

For detailed architecture information, see `docs/ARCHITECTURE.md`.

## Project Structure

```text
LLM-SECURITY-GATEWAY/
│
├── app/
│   ├── main.py
│   ├── security.py
│   ├── auth_protection.py
│   ├── api_key_store.py
│   ├── rate_limit.py
│   ├── rbac.py
│   ├── prompt_risk.py
│   ├── jailbreak_detection.py
│   ├── secret_detection.py
│   ├── threat_intelligence.py
│   ├── output_filter.py
│   ├── semantic_cache.py
│   ├── database.py
│   ├── audit_log.py
│   ├── metrics.py
│   └── ...
│
├── tests/
│   └── ...
│
├── docs/
│   └── ARCHITECTURE.md
│
├── logs/
│
├── API_DOCUMENTATION.md
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── .dockerignore
└── .gitignore
```

## Requirements

* Python 3.13+
* FastAPI
* Uvicorn
* Redis or Memurai
* PostgreSQL
* Prometheus Client
* Docker (optional)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/sumitpanday11/LLM-SECURITY-GATEWAY.git
cd LLM-SECURITY-GATEWAY
```

### 2. Create and Activate a Virtual Environment

**Windows PowerShell:**

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

## Configuration

Configure the required environment variables according to the local development environment.

Example:

```text
API_KEY=dev-secret-key
REDIS_HOST=localhost
REDIS_PORT=6379
```

PostgreSQL connection settings should also be configured according to the local database environment.

> Do not commit real API keys, passwords, tokens, or other credentials to the repository.

## Running the Application

Start the FastAPI application:

```powershell
uvicorn app.main:app --reload
```

The application will be available at:

```text
http://127.0.0.1:8000
```

## API Endpoints

| Method | Endpoint           | Description                    |
| ------ | ------------------ | ------------------------------ |
| GET    | `/`                | Gateway information            |
| GET    | `/health`          | Application health check       |
| GET    | `/metrics`         | Prometheus metrics             |
| GET    | `/health/database` | Database health check          |
| GET    | `/keys/info`       | API key information            |
| POST   | `/keys/generate`   | Generate a new API key         |
| POST   | `/keys/revoke`     | Revoke an API key              |
| POST   | `/keys/rotate`     | Rotate an API key              |
| POST   | `/chat`            | Protected LLM request endpoint |

## API Documentation

Detailed API documentation is available in:

```text
API_DOCUMENTATION.md
```

Interactive FastAPI documentation is also available:

```text
Swagger UI: http://127.0.0.1:8000/docs
ReDoc:      http://127.0.0.1:8000/redoc
```

## Authentication

Protected endpoints require an API key.

Example header:

```text
x-api-key: dev-secret-key
```

### Example Request

```powershell
curl.exe -X POST "http://127.0.0.1:8000/chat" `
-H "x-api-key: dev-secret-key" `
-H "Content-Type: application/json" `
-d '{"prompt":"Hello gateway"}'
```

## Security Controls

### API Key Security

API keys authenticate requests to protected endpoints. The gateway supports API key persistence, rotation, revocation, and validation.

### Rate Limiting

Redis-based rate limiting helps protect the gateway against excessive requests and abuse.

### RBAC

Role-Based Access Control restricts protected operations according to assigned permissions and user roles.

### LLM Firewall / Policy Engine

The LLM Firewall applies configurable security policies to incoming requests and determines whether a request should be allowed or blocked.

### Prompt Injection Detection

Incoming prompts are inspected for suspicious patterns associated with prompt injection attacks.

### Prompt Risk Scoring

Prompts receive a security risk score and severity classification based on detected suspicious behavior.

Risk levels include:

* Low
* Medium
* High
* Critical

### Jailbreak Detection

The gateway detects common jailbreak-style attempts designed to bypass model safety instructions or security policies.

### Secret / Credential Leak Detection

Sensitive credentials and secret-like values such as API keys, tokens, passwords, and other credential patterns are detected and protected from being exposed through the gateway.

### Threat Intelligence

Security-related indicators and suspicious content can be checked against threat intelligence rules to improve detection of potentially malicious requests.

### Unsafe Output Filtering

LLM responses are inspected for unsafe or sensitive content before being returned to the client.

### Semantic Cache

Semantically similar requests can use cached responses where applicable, reducing unnecessary processing while maintaining gateway security controls.

### Request Validation

Pydantic-based validation enforces valid request formats and input restrictions.

### Security Headers

The gateway applies security-focused HTTP response headers including:

* `X-Content-Type-Options: nosniff`
* `X-Frame-Options: DENY`
* `Referrer-Policy: no-referrer`
* `Cache-Control: no-store`

### Audit Logging

Security-relevant events and requests can be recorded in PostgreSQL for auditing and investigation.

### Security Incident Correlation

Related security events can be correlated to help identify repeated or connected suspicious activity associated with the same request context.

### Monitoring

Prometheus metrics are exposed through the `/metrics` endpoint for monitoring gateway activity.

## Testing

Run the automated test suite:

```powershell
pytest -q
```

The test suite covers authentication, authorization, rate limiting, input validation, prompt security, jailbreak detection, secret detection, firewall policies, and other gateway security functionality.

## Docker

The project includes Docker support for running the gateway with its supporting services.

Build the application:

```powershell
docker compose build
```

Start the services:

```powershell
docker compose up
```

Docker Compose can be used to run the application together with PostgreSQL and Redis.

## Documentation

Project documentation includes:

* `README.md` — Project overview and setup
* `API_DOCUMENTATION.md` — API reference
* `docs/ARCHITECTURE.md` — Security architecture
* `tests/` — Automated security and integration tests

## Project Objectives

The main objectives of the LLM Security Gateway are:

1. Protect LLM applications from common security threats.
2. Authenticate and authorize API clients securely.
3. Detect malicious or suspicious prompts.
4. Prevent credential and secret leakage.
5. Filter unsafe model outputs.
6. Maintain security audit records.
7. Monitor gateway activity.
8. Correlate security incidents for investigation.
9. Provide a modular security architecture that can be extended with additional controls.

## Future Improvements

Potential future enhancements include:

* CI/CD pipeline integration
* JWT/OAuth authentication
* Advanced ML-based threat detection
* External threat intelligence integrations
* Distributed production deployment
* Advanced security dashboards
* Cloud deployment and centralized monitoring

## Author

**Sumit Panday**

Cyber Security Internship Project

B.Tech CSE Cyber Security

**Organization:** Zaalima Development Pvt Ltd

## License

This project was developed for educational and internship purposes as part of the Cyber Security Internship at Zaalima Development Pvt Ltd.
