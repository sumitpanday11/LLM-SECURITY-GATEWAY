# LLM Security Gateway

An enterprise-focused security gateway built with FastAPI to protect LLM and GenAI applications from common security threats.

## Features

* API Key Authentication
* API Key Rotation and Revocation
* Redis-Based API Key Persistence
* Redis-Based Rate Limiting
* Role-Based Access Control (RBAC)
* Prompt Injection Detection
* Input Validation
* Request Payload Size Limiting
* Content-Type Enforcement
* CORS Security Configuration
* Security Response Headers
* Request Correlation IDs
* Global Exception Handling
* Security Event Logging
* Audit Logging with PostgreSQL
* Prometheus Metrics
* Automated Security Tests

## Security Architecture

The gateway validates and secures incoming requests before forwarding them for processing.

```text
Client
   |
   v
FastAPI Security Gateway
   |
   +--> API Key Authentication
   |
   +--> RBAC Authorization
   |
   +--> Rate Limiting (Redis)
   |
   +--> Input Validation
   |
   +--> Prompt Injection Detection
   |
   +--> Security Middleware
   |
   +--> Audit Logging (PostgreSQL)
   |
   +--> Metrics (Prometheus)
   |
   v
LLM / Application Backend
```

For detailed architecture information, see [Architecture Documentation](docs/ARCHITECTURE.md).

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
│   ├── database.py
│   ├── audit_log.py
│   ├── metrics.py
│   ├── output_filter.py
│   ├── semantic_cache.py
│   ├── threat_intelligence.py
│   └── ...
│
├── tests/
│   └── ...
│
├── logs/
│
├── docs/
│   └── ARCHITECTURE.md
│
├── API_DOCUMENTATION.md
├── README.md
└── .gitignore
```

## Requirements

* Python 3.13+
* FastAPI
* Uvicorn
* Redis or Memurai
* PostgreSQL
* Prometheus Client

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
pip install fastapi uvicorn redis psycopg2-binary prometheus-client pytest
```

## Configuration

Configure the required environment variables before running the application:

```text
API_KEY=dev-secret-key
REDIS_HOST=localhost
REDIS_PORT=6379
```

Configure PostgreSQL connection settings according to your local environment.

## Running the Application

Start the FastAPI application:

```powershell
uvicorn app.main:app --reload
```

The application will start locally at:

```text
http://127.0.0.1:8000
```

## API Endpoints

| Method | Endpoint           | Description                    |
| ------ | ------------------ | ------------------------------ |
| GET    | `/`                | Gateway information            |
| GET    | `/health`          | Health check                   |
| GET    | `/metrics`         | Prometheus metrics             |
| GET    | `/health/database` | Database health check          |
| GET    | `/keys/info`       | API key information            |
| POST   | `/keys/generate`   | Generate a new API key         |
| POST   | `/keys/revoke`     | Revoke an API key              |
| POST   | `/keys/rotate`     | Rotate an API key              |
| POST   | `/chat`            | Protected LLM request endpoint |

## API Documentation

Detailed API documentation is available in [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

The project also provides interactive FastAPI documentation:

* Swagger UI: `/docs`
* ReDoc: `/redoc`

## Authentication

Protected endpoints require an API key.

```text
x-api-key: dev-secret-key
```

### Example Request

```powershell
curl.exe -X POST "http://127.0.0.1:8000/chat" `
-H "x-api-key: dev-secret-key" `
-H "Content-Type: application/json" `
-d "{\"prompt\":\"Hello gateway\"}"
```

## Security Controls

### API Key Security

API keys are used to authenticate incoming requests. The project includes support for API key storage, rotation, and revocation.

### Rate Limiting

Redis-based rate limiting protects the gateway against excessive requests and abuse.

### Prompt Injection Protection

Incoming prompts are checked against suspicious patterns associated with prompt injection attempts.

### Role-Based Access Control

RBAC restricts access to protected resources based on assigned user roles.

### Request Validation

Requests are validated using Pydantic to enforce valid input formats and size restrictions.

### Security Headers

The gateway applies the following security headers:

* `X-Content-Type-Options: nosniff`
* `X-Frame-Options: DENY`
* `Referrer-Policy: no-referrer`
* `Cache-Control: no-store`

### Audit Logging

Security-relevant events and requests can be recorded in PostgreSQL for auditing and investigation.

### Monitoring

Prometheus metrics are exposed through the `/metrics` endpoint for monitoring application activity.

## Testing

Run the automated test suite:

```powershell
pytest -q
```

The project includes automated tests covering authentication, rate limiting, input validation, security controls, and other gateway functionality.

## Future Improvements

* Docker containerization
* CI/CD pipeline
* JWT/OAuth authentication
* Advanced prompt injection detection
* Distributed rate limiting
* Production deployment configuration

## Author

**Sumit Panday**

Cyber Security Internship Project

**Organization:** Zaalima Development Pvt Ltd

## License

This project was developed for educational and internship purposes as part of the Cyber Security Internship at Zaalima Development Pvt Ltd.
