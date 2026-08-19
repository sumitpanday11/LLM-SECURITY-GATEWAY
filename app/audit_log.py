import logging
import os


LOG_DIR = "logs"
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "security_audit.log")

os.makedirs(LOG_DIR, exist_ok=True)


audit_logger = logging.getLogger("security-audit")
audit_logger.setLevel(logging.INFO)

if not audit_logger.handlers:
    file_handler = logging.FileHandler(
        AUDIT_LOG_FILE,
        encoding="utf-8",
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    file_handler.setFormatter(formatter)
    audit_logger.addHandler(file_handler)


def log_security_event(
    event: str,
    request_id: str,
    details: str = "",
):
    audit_logger.warning(
        "SECURITY_EVENT | event=%s | request_id=%s | details=%s",
        event,
        request_id,
        details,
    )