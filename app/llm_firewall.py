import logging
import re
from dataclasses import dataclass, field


logger = logging.getLogger("llm-security-gateway")


# ============================================================
# FIREWALL POLICY CONFIGURATION
# ============================================================

MAX_PROMPT_LENGTH = 4000


# ============================================================
# FIREWALL RULES
# ============================================================

FIREWALL_RULES = {
    "SYSTEM_PROMPT_EXTRACTION": [
        r"\b(show|reveal|print|dump|display|output)\b.{0,80}"
        r"\b(system\s+prompt|hidden\s+prompt|system\s+instructions?)\b",
        r"\b(what\s+is|tell\s+me)\b.{0,80}"
        r"\b(your\s+system\s+prompt|hidden\s+instructions?)\b",
    ],

    "SECURITY_BYPASS": [
        r"\b(bypass|disable|remove|circumvent)\b.{0,80}"
        r"\b(security|safety|filter|restriction|control)s?\b",
    ],

    "INSTRUCTION_OVERRIDE": [
        r"\b(ignore|disregard|override)\b.{0,80}"
        r"\b(previous|prior|above|system|developer)\s+"
        r"\b(instruction|message|rule|policy)s?\b",
    ],

    "ROLE_MANIPULATION": [
        r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|"
        r"roleplay\s+as)\b",
    ],

    "ENCODING_OBFUSCATION": [
        r"\b(base64|rot13|hexadecimal|hex)\b.{0,40}"
        r"\b(decode|encoded|decode\s+this)\b",
    ],

    "PROMPT_BOUNDARY_ATTACK": [
        r"```(?:system|developer|assistant)\b",
        r"<\|(?:system|developer|assistant)\|>",
        r"\[\[(?:system|developer|assistant)\]\]",
    ],
}


# Compile rules once during application startup.
COMPILED_FIREWALL_RULES = {
    category: [
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
        for pattern in patterns
    ]
    for category, patterns in FIREWALL_RULES.items()
}


# ============================================================
# FIREWALL RESULT
# ============================================================

@dataclass
class FirewallResult:
    allowed: bool
    reason: str = ""
    rule: str | None = None
    matched_text: str | None = None
    violations: list[str] = field(default_factory=list)


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_firewall_input(prompt: str) -> str:
    """
    Normalize input before firewall inspection.
    """

    normalized = prompt.replace("\x00", " ")

    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    return normalized.strip()


# ============================================================
# FIREWALL INSPECTION
# ============================================================

def inspect_prompt(prompt: str) -> FirewallResult:
    """
    Inspect a prompt against all configured firewall policies.
    """

    if not isinstance(prompt, str):
        return FirewallResult(
            allowed=False,
            reason="Invalid prompt type",
            rule="INVALID_INPUT",
            violations=["INVALID_INPUT"],
        )

    normalized_prompt = normalize_firewall_input(prompt)

    # --------------------------------------------------------
    # Prompt length policy
    # --------------------------------------------------------

    if len(normalized_prompt) > MAX_PROMPT_LENGTH:
        return FirewallResult(
            allowed=False,
            reason="Prompt exceeds firewall length policy",
            rule="MAX_PROMPT_LENGTH",
            violations=["MAX_PROMPT_LENGTH"],
        )

    if not normalized_prompt:
        return FirewallResult(
            allowed=False,
            reason="Prompt cannot be empty",
            rule="EMPTY_PROMPT",
            violations=["EMPTY_PROMPT"],
        )

    # --------------------------------------------------------
    # Security rule inspection
    # --------------------------------------------------------

    violations = []

    for category, patterns in COMPILED_FIREWALL_RULES.items():

        for pattern in patterns:

            match = pattern.search(normalized_prompt)

            if match:
                violations.append(category)

                logger.warning(
                    "LLM firewall rule matched | "
                    "rule=%s | matched=%s",
                    category,
                    match.group(0)[:100],
                )

                return FirewallResult(
                    allowed=False,
                    reason=(
                        f"Prompt blocked by firewall policy: "
                        f"{category}"
                    ),
                    rule=category,
                    matched_text=match.group(0)[:100],
                    violations=violations,
                )

    # --------------------------------------------------------
    # Prompt allowed
    # --------------------------------------------------------

    return FirewallResult(
        allowed=True,
        reason="Prompt passed firewall policies",
    )


# ============================================================
# FIREWALL POLICY CHECK
# ============================================================

def is_prompt_allowed(prompt: str) -> bool:
    """
    Return True when the prompt passes firewall policies.
    """

    return inspect_prompt(prompt).allowed