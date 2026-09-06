"""Product-defined constant strings and enumerations."""
from __future__ import annotations

# The exact text an administrator must type to add a public target (PRD 6.2).
PUBLIC_TARGET_ATTESTATION = (
    "I confirm this team owns or has written authorization to scan this target"
)

# The exact text a requester must type to submit any active scan (PRD 8.1).
ACTIVE_SCAN_ATTESTATION = (
    "I attest this scan is authorized and will be used only for ethical, "
    "non-exploitative reconnaissance"
)

PROFILES = ("PASSIVE", "SAFE_ACTIVE", "STANDARD_ACTIVE")

SCAN_STATES = (
    "DRAFT",
    "AWAITING_APPROVAL",
    "APPROVED",
    "QUEUED",
    "RUNNING",
    "CANCELLING",
    "COMPLETED",
    "FAILED",
    "TIMED_OUT",
    "DENIED",
    "EXPIRED",
    "CANCELLED",
)
