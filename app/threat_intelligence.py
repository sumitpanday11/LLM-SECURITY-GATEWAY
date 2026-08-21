import logging
from typing import Set


logger = logging.getLogger("llm-security-gateway")


# Local threat-intelligence blocklist.
# These are reserved documentation/test IP addresses.
BLOCKED_IPS: Set[str] = {
    "192.0.2.10",
    "198.51.100.20",
    "203.0.113.50",
}


def is_ip_threatened(client_ip: str) -> bool:
    """
    Check whether the client IP exists
    in the local threat-intelligence blocklist.
    """

    if not client_ip:
        return False

    return client_ip in BLOCKED_IPS


def add_blocked_ip(client_ip: str) -> None:
    """
    Add an IP to the local threat-intelligence blocklist.
    """

    if not client_ip:
        return

    BLOCKED_IPS.add(client_ip)

    logger.warning(
        "Threat intelligence IP added | client_ip=%s",
        client_ip,
    )


def remove_blocked_ip(client_ip: str) -> None:
    """
    Remove an IP from the local threat-intelligence blocklist.
    """

    BLOCKED_IPS.discard(client_ip)

    logger.info(
        "Threat intelligence IP removed | client_ip=%s",
        client_ip,
    )


def get_blocked_ips() -> list[str]:
    """
    Return the current local threat-intelligence blocklist.
    """

    return sorted(BLOCKED_IPS)