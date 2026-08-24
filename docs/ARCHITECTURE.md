\# LLM Security Gateway Architecture



\## Overview



The LLM Security Gateway is a FastAPI-based security layer designed to protect LLM and GenAI applications from common security threats.



\## Architecture Flow



```text

&#x20;                        +----------------------+

&#x20;                        |        CLIENT        |

&#x20;                        | API / Web Application|

&#x20;                        +----------+-----------+

&#x20;                                   |

&#x20;                                   v

&#x20;                +--------------------------------------+

&#x20;                |       FASTAPI SECURITY GATEWAY       |

&#x20;                |                                      |

&#x20;                |  +-------------------------------+   |

&#x20;                |  | API Key Authentication        |   |

&#x20;                |  | RBAC Authorization            |   |

&#x20;                |  | Input Validation              |   |

&#x20;                |  | Rate Limiting                 |   |

&#x20;                |  | Prompt Injection Detection    |   |

&#x20;                |  | Security Middleware           |   |

&#x20;                |  | Correlation IDs               |   |

&#x20;                |  | Exception Handling             |   |

&#x20;                |  +-------------------------------+   |

&#x20;                +------------------+-------------------+

&#x20;                                   |

&#x20;                      Security checks passed

&#x20;                                   |

&#x20;                                   v

&#x20;                +--------------------------------------+

&#x20;                |          LLM / APPLICATION           |

&#x20;                |             BACKEND                  |

&#x20;                +------------------+-------------------+

&#x20;                                   |

&#x20;                                   v

&#x20;                           Protected Output

&#x20;                                   |

&#x20;                                   v

&#x20;                +--------------------------------------+

&#x20;                |          OUTPUT FILTER              |

&#x20;                |   Security / Threat Validation      |

&#x20;                +------------------+-------------------+

&#x20;                                   |

&#x20;                                   v

&#x20;                                 CLIENT





&#x20;     +----------------+       +-------------------------+

&#x20;     | Redis / Memurai|<------| API Keys + Rate Limits |

&#x20;     +----------------+       +-------------------------+



&#x20;     +----------------+       +-------------------------+

&#x20;     |  PostgreSQL    |<------| Audit / Security Events|

&#x20;     +----------------+       +-------------------------+



&#x20;     +----------------+       +-------------------------+

&#x20;     |  Prometheus    |<------| Gateway Metrics         |

&#x20;     +----------------+       +-------------------------+



&#x20;     +----------------+       +-------------------------+

&#x20;     |     Logs       |<------| Security / App Logging |

&#x20;     +----------------+       +-------------------------+

```



\## Core Components



\### Client



The client sends requests to the security gateway. Requests must satisfy the gateway's authentication and security requirements.



\### FastAPI Security Gateway



The FastAPI application acts as the central security enforcement layer.



It performs:



\* API key authentication

\* Role-based authorization

\* Request validation

\* Rate limiting

\* Prompt injection detection

\* Content-type enforcement

\* Request size validation

\* Security response headers

\* Request correlation

\* Exception handling



\### Redis / Memurai



Redis-compatible storage is used for:



\* API key persistence

\* Rate limiting state

\* Fast key lookups and updates



\### PostgreSQL



PostgreSQL provides persistent storage for audit and security-related records.



\### Output Filter



Generated responses are checked by the gateway's output security layer before being returned to the client.



\### Prometheus



Prometheus-compatible metrics are exposed through the `/metrics` endpoint for monitoring gateway activity.



\### Logging



Application and security events are logged for debugging, monitoring, and security investigation.



\## Security Request Flow



```text

Client Request

&#x20;     |

&#x20;     v

API Key Authentication

&#x20;     |

&#x20;     v

RBAC Authorization

&#x20;     |

&#x20;     v

Rate Limiting

&#x20;     |

&#x20;     v

Input Validation

&#x20;     |

&#x20;     v

Prompt Injection Detection

&#x20;     |

&#x20;     v

Security Middleware

&#x20;     |

&#x20;     v

LLM / Application Processing

&#x20;     |

&#x20;     v

Output Security Filtering

&#x20;     |

&#x20;     v

Client Response

```



\## Data and Monitoring Flow



```text

API Requests

&#x20;    |

&#x20;    +----> Redis / Memurai

&#x20;    |        |

&#x20;    |        +--> API Key Storage

&#x20;    |        +--> Rate Limit State

&#x20;    |

&#x20;    +----> PostgreSQL

&#x20;    |        |

&#x20;    |        +--> Audit Events

&#x20;    |        +--> Security Records

&#x20;    |

&#x20;    +----> Prometheus

&#x20;    |        |

&#x20;    |        +--> Application Metrics

&#x20;    |

&#x20;    +----> Logs

&#x20;             |

&#x20;             +--> Security Events

&#x20;             +--> Application Events

```



\## Security Objective



The architecture follows a defense-in-depth approach where authentication, authorization, request validation, threat detection, rate limiting, auditing, and monitoring are applied as multiple security layers before and after LLM processing.



