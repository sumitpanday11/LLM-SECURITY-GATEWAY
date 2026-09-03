# LLM Security Gateway Architecture

## Overview

The LLM Security Gateway is a FastAPI-based security layer designed to protect LLM and GenAI applications from common security threats.

The gateway follows a defense-in-depth approach by applying multiple security controls before and after LLM processing.

## High-Level Architecture

```text
                              +----------------------+
                              |        CLIENT        |
                              |   API / Application  |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              |   FASTAPI GATEWAY    |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | API Key Authentication|
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              |  RBAC Authorization  |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              |   Redis Rate Limit  |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Request Validation  |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | LLM Firewall /      |
                              | Policy Engine       |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Prompt Risk Scoring |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Jailbreak Detection |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Prompt Injection    |
                              | Detection            |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Threat Intelligence |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              |   LLM / Backend     |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Secret / Credential |
                              | Leak Detection      |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Unsafe Output       |
                              | Filtering            |
                              +----------+-----------+
                                         |
                                         v
                              +----------------------+
                              | Security Event      |
                              | Logging              |
                              +----------+-----------+
                                         |
                              +----------+----------+
                              |                     |
                              v                     v
                       +-------------+       +-------------+
                       | PostgreSQL  |       | Prometheus  |
                       | Audit Data  |       | Metrics     |
                       +------+------+       +-------------+
                              |
                              v
                    +----------------------+
                    | Incident Correlation |
                    +----------------------+
                              |
                              v
                            CLIENT
```

## Core Components

### Client

The client sends requests to the LLM Security Gateway.

Requests must satisfy authentication, authorization, validation, and security policy requirements before reaching the protected LLM or backend.

### FastAPI Security Gateway

The FastAPI application acts as the central security enforcement layer.

It coordinates authentication, authorization, request validation, threat detection, output security, auditing, and monitoring.

### API Key Authentication

API keys are used to authenticate clients accessing protected endpoints.

The gateway supports API key validation, persistence, rotation, and revocation.

### RBAC Authorization

Role-Based Access Control restricts operations according to assigned roles and permissions.

This prevents unauthorized users from accessing protected gateway functionality.

### Redis / Memurai

Redis-compatible storage is used for:

* API key persistence
* Rate limiting state
* Fast key lookups and updates
* Temporary security-related state where required

### Request Validation

Incoming requests are validated before security processing.

Validation includes request structure, input restrictions, content type enforcement, and payload size limits.

### LLM Firewall / Policy Engine

The LLM Firewall applies configurable security policies to incoming requests.

It determines whether requests should be allowed or blocked based on defined security rules.

### Prompt Risk Scoring

Prompts are analyzed and assigned a security risk score.

The risk score is classified into:

* Low
* Medium
* High
* Critical

This allows suspicious prompts to be handled according to their security severity.

### Jailbreak Detection

Jailbreak detection identifies common attempts to bypass model safety instructions or gateway security policies.

Detected jailbreak patterns contribute to the overall prompt security assessment.

### Prompt Injection Detection

Incoming prompts are inspected for patterns associated with prompt injection attacks, including attempts to override instructions or manipulate the model's intended behavior.

### Threat Intelligence

Security-related indicators and suspicious content are evaluated against configured threat intelligence rules.

This provides an additional detection layer for potentially malicious requests.

### LLM / Application Backend

Requests that pass the required security checks can proceed to the LLM or protected application backend.

The gateway remains responsible for applying output-side security controls before returning the response.

### Secret / Credential Leak Detection

Generated responses are inspected for sensitive credential patterns.

The detection layer helps identify values such as:

* API keys
* Access tokens
* Bearer tokens
* Passwords
* Cloud credentials
* Other secret-like values

Detected secrets can be protected according to the configured security behavior.

### Unsafe Output Filtering

LLM responses are inspected before being returned to the client.

The output security layer helps prevent unsafe or sensitive content from being exposed through the gateway.

### Semantic Cache

The gateway can use semantically similar cached responses where applicable.

This can reduce unnecessary processing while keeping requests within the gateway's security pipeline.

### PostgreSQL Audit Storage

PostgreSQL provides persistent storage for security and audit information.

Audit records can be used for:

* Security investigation
* Request tracing
* Event analysis
* Compliance-oriented record keeping

### Security Incident Correlation

Security events can be correlated using request and security context to identify repeated or related suspicious activity.

This helps transform individual security events into a more meaningful incident view.

### Prometheus Metrics

Prometheus-compatible metrics are exposed through the `/metrics` endpoint.

These metrics provide visibility into gateway activity and security-related operations.

### Logging

Application and security events are logged for:

* Debugging
* Monitoring
* Security investigation
* Incident analysis

## Security Request Flow

```text
Client Request
      |
      v
API Key Authentication
      |
      v
RBAC Authorization
      |
      v
Rate Limiting
      |
      v
Request Validation
      |
      v
LLM Firewall / Policy Engine
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
LLM / Application Processing
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
      v
Client Response
```

## Data and Monitoring Flow

```text
                    API Requests
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       Redis         PostgreSQL     Prometheus
          |              |              |
          v              v              v
    API Keys       Audit Events    Gateway Metrics
    Rate Limits    Security Data
                         |
                         v
                 Incident Correlation

                         +
                         |
                         v
                       Logs
                         |
                         v
              Security / Application
                     Events
```

## Defense-in-Depth Security Model

The gateway uses multiple independent security layers.

```text
Layer 1  -> Authentication
Layer 2  -> Authorization
Layer 3  -> Rate Limiting
Layer 4  -> Request Validation
Layer 5  -> Firewall Policies
Layer 6  -> Prompt Risk Scoring
Layer 7  -> Jailbreak Detection
Layer 8  -> Prompt Injection Detection
Layer 9  -> Threat Intelligence
Layer 10 -> Secret Detection
Layer 11 -> Unsafe Output Filtering
Layer 12 -> Audit Logging
Layer 13 -> Incident Correlation
Layer 14 -> Monitoring and Metrics
```

If one security layer does not identify a threat, additional layers provide further protection.

## Security Objective

The primary objective of the LLM Security Gateway is to provide a centralized and modular security layer between clients and LLM applications.

The architecture is designed to:

1. Authenticate and authorize API clients.
2. Control request frequency and abuse.
3. Validate incoming requests.
4. Detect malicious and suspicious prompts.
5. Identify jailbreak and prompt injection attempts.
6. Apply configurable LLM security policies.
7. Detect credential and secret leakage.
8. Filter unsafe model outputs.
9. Maintain security audit records.
10. Correlate related security incidents.
11. Provide monitoring and observability.
12. Support a modular architecture for future security enhancements.
