import logging
import os
from logging.handlers import RotatingFileHandler


LOG_DIR = "logs"
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "security_audit.log")

MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
BACKUP_COUNT = 5


os.makedirs(LOG_DIR, exist_ok=True)


audit_logger = logging.getLogger("security-audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False


if not audit_logger.handlers:
    file_handler = RotatingFileHandler(
        AUDIT_LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
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