"""License-key verification for the Pro report/export feature.

This is a deliberately minimal, static shared-key gate: a single valid key
(sold via a Stripe Payment Link) whose SHA-256 hash is embedded below. The
plaintext key is never stored in the repository -- only its hash -- so reading
this source does not reveal a working key.

There is no backend, database, user accounts, or webhook here by design. At the
current traffic scale this "soft gate" is sufficient; per-customer keys,
revocation, and analytics are explicit non-goals for this pass.
"""

import hashlib
import hmac
import os

#: SHA-256 (hex) of the single valid license key. The plaintext lives only in
#: the Stripe purchase confirmation, never in this repo.
VALID_KEY_HASH = "e8efc5595f7d00ab03d9fa611b6bf40f13f3935978e2ddd53d9befdff7630b17"

#: One-time Stripe Payment Link that unlocks the Pro report feature.
PURCHASE_LINK = "https://buy.stripe.com/cNifZifg06eld9La50dMI01"

#: Environment variable read as a fallback when ``--license-key`` is omitted.
ENV_VAR = "LICENSE_RADAR_KEY"


def verify_license_key(key: str | None) -> bool:
    """Return ``True`` iff ``key`` matches the valid license key.

    The key is normalized by stripping surrounding whitespace, SHA-256 hashed,
    and compared against :data:`VALID_KEY_HASH` with
    :func:`hmac.compare_digest` (constant-time) rather than ``==`` to avoid a
    timing side-channel on the hash comparison. An empty or ``None`` key is
    rejected without hashing.
    """
    if not key:
        return False
    normalized = key.strip()
    if not normalized:
        return False
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return hmac.compare_digest(digest, VALID_KEY_HASH)


def resolve_key(cli_key: str | None) -> str | None:
    """Return the license key from the CLI flag, falling back to the env var."""
    if cli_key:
        return cli_key
    return os.environ.get(ENV_VAR)
