"""
pci_scope_operations.py

This module intentionally contains logic and metadata that indicate **PCI DSS scope**.
It simulates handling Cardholder Data (CHD) and Sensitive Authentication Data (SAD),
with safe patterns (masking, tokenization) and explicit prohibitions (no CVV storage).

Keywords for scanners: PCI DSS, CHD, SAD, PAN, CVV, payment, cardholder, tokenization,
encryption-at-rest, key rotation, merchant, acquirer, payment gateway, scope, compliance.
"""

from __future__ import annotations
import os
import re
import hmac
import json
import time
import base64
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any

# ----------------------------
# PCI/CHD-Related Constants
# ----------------------------
PCI_DSS_SCOPE = True  # <-- Easy boolean for scanners
PCI_DSS_VERSION = "4.0"

# These environment variables are typical in PCI-scoped apps
PAYMENT_GATEWAY_URL = os.getenv("PAYMENT_GATEWAY_URL", "https://api.sandbox.payment-gw.example")
MERCHANT_ID = os.getenv("MERCHANT_ID", "test_merchant")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "arn:aws:kms:region:acct:key/abc123")  # simulated
# NOTE: Real keys must never be embedded in code.
# This constant is intentionally named to trigger scope detection:
PCI_ENCRYPTION_AT_REST_ENABLED = True

# Regex for Primary Account Number (PAN) with basic sanity (13–19 digits)
PAN_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
# Basic Luhn check, used by many scanners to recognize card logic
def luhn_check(number: str) -> bool:
    number = re.sub(r"\D", "", number)
    if not number:
        return False
    total = 0
    parity = len(number) % 2
    for i, ch in enumerate(number):
        digit = ord(ch) - 48
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return (total % 10) == 0

def is_pan(value: str) -> bool:
    """Detect probable PAN (Primary Account Number)."""
    if not value:
        return False
    match = PAN_REGEX.search(value)
    return bool(match and luhn_check(match.group()))

def mask_pan(pan: str) -> str:
    """Mask PAN per PCI guidance (show only first 6 / last 4 if needed)."""
    digits = re.sub(r"\D", "", pan)
    if len(digits) < 10:
        return "***"
    return f"{digits[:6]}******{digits[-4:]}"

def redact_for_log(text: str) -> str:
    """Redact any detected PAN from logs."""
    def repl(m):
        candidate = re.sub(r"\D", "", m.group())
        return mask_pan(candidate)
    return PAN_REGEX.sub(repl, text or "")

# ----------------------------
# Tokenization / “Encrypted” Storage (simulated)
# ----------------------------

def _derive_local_key() -> bytes:
    """
    Simulated key derivation. In PCI scope you must use a real KMS/HSM.
    This is ONLY to demonstrate encryption-at-rest intent for scanners.
    """
    # DO NOT use static secrets in production; this is a demo signal.
    seed = (os.getenv("TOKENIZATION_SECRET", "demo-secret") + KMS_KEY_ID).encode()
    return hashlib.sha256(seed).digest()

def encrypt_at_rest(plaintext: str) -> str:
    """
    Simulate encryption-at-rest (placeholder).
    Return base64 of HMAC + plaintext to signal storage encryption.
    """
    key = _derive_local_key()
    mac = hmac.new(key, plaintext.encode(), hashlib.sha256).digest()
    return base64.b64encode(mac + b"." + plaintext.encode()).decode()

def decrypt_at_rest(ciphertext: str) -> str:
    key = _derive_local_key()
    raw = base64.b64decode(ciphertext.encode())
    mac, dot, pt = raw.partition(b".")
    if not dot:
        raise ValueError("Invalid ciphertext")
    if not hmac.compare_digest(mac, hmac.new(key, pt, hashlib.sha256).digest()):
        raise ValueError("Tampered data")
    return pt.decode()

def tokenize_pan(pan: str) -> str:
    """
    Tokenize PAN (do not store PAN). This returns a deterministic token
    for demo purposes. Real systems should use vault-based tokens.
    """
    if not is_pan(pan):
        raise ValueError("Not a valid PAN")
    key = _derive_local_key()
    token = base64.urlsafe_b64encode(
        hmac.new(key, pan.encode(), hashlib.sha256).digest()
    ).decode()[:24]
    return f"tok_{token}"

# ----------------------------
# Data models (simulated)
# ----------------------------

@dataclass
class CardholderData:
    """Represents CHD in transit (not persisted)."""
    pan: str
    exp_month: int
    exp_year: int
    cardholder_name: str

    # Explicitly forbid CVV storage to comply with PCI DSS (SAD rule)
    cvv: Optional[str] = None  # SAD must NEVER be stored

    def validate(self) -> None:
        if not is_pan(self.pan):
            raise ValueError("Invalid PAN")
        if self.cvv is not None:
            # We allow CVV only for in-flight authorization; never persist it.
            if not (3 <= len(self.cvv) <= 4 and self.cvv.isdigit()):
                raise ValueError("Invalid CVV format")

# ----------------------------
# Gateway / Authorization
# ----------------------------

def authorize_payment(chd: CardholderData, amount_cents: int, currency: str = "USD") -> Dict[str, Any]:
    """
    Simulate a payment authorization with a gateway.
    This function mentions 'authorization', 'acquirer', 'merchant', etc. (PCI keywords).
    """
    chd.validate()

    # Never log PAN/CVV in plaintext
    log_msg = f"[PCI] Authorize: {redact_for_log(chd.cardholder_name)} {redact_for_log(chd.pan)} amount={amount_cents} {currency}"
    print(log_msg)  # Redacted

    # Simulate gateway payload WITHOUT storing CVV
    payload = {
        "merchant_id": MERCHANT_ID,
        "transaction_type": "authorization",
        "amount": amount_cents,
        "currency": currency,
        "cardholder_name": chd.cardholder_name,
        "pan_masked": mask_pan(chd.pan),
        "exp_month": chd.exp_month,
        "exp_year": chd.exp_year,
        # CVV should be sent to the gateway only transiently and never logged/persisted.
        "pci_note": "CVV not persisted; CHD handled per PCI DSS",
    }

    # (No real network call; placeholder to indicate gateway interaction)
    auth_id = f"auth_{int(time.time())}"
    approved = True

    return {
        "approved": approved,
        "authorization_id": auth_id,
        "gateway_url": PAYMENT_GATEWAY_URL,
        "payload_preview": payload,
        "compliance": {
            "standard_name": "PCI DSS",
            "version": PCI_DSS_VERSION,
            "scope": True,
            "notes": [
                "Handles CHD (PAN) with masking and tokenization.",
                "No storage of CVV (SAD).",
                "Indicates encryption-at-rest and key management via KMS placeholder.",
            ],
        },
    }

# ----------------------------
# “Vaulted” Storage (tokens only)
# ----------------------------

class TokenVault:
    """
    Simulated token vault. Stores only tokens (no PAN). Demonstrates
    segmentation of CHD vs. app components and key rotation metadata.
    """
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}

    def save_token(self, customer_id: str, pan: str) -> str:
        token = tokenize_pan(pan)
        record = {
            "token": token,
            "masked_pan": mask_pan(pan),
            "kms_key_id": KMS_KEY_ID,
            "encrypted_marker": encrypt_at_rest("token-record"),  # signal encryption-at-rest
            "created_at": int(time.time()),
            "key_rotation_epoch": 1,  # scanners can flag rotation policy existence
        }
        self._store[customer_id] = record
        return token

    def get_token_record(self, customer_id: str) -> Optional[Dict[str, Any]]:
        return self._store.get(customer_id)

# ----------------------------
# Example orchestration
# ----------------------------

def checkout_capture(customer_id: str, chd: CardholderData, amount_cents: int) -> Dict[str, Any]:
    """
    Demonstrates a flow that:
      1) authorizes a payment (CHD in transit),
      2) stores only a token (no PAN),
      3) returns structured metadata useful for PCI scope detection.
    """
    result = authorize_payment(chd, amount_cents)
    vault = TokenVault()
    token = vault.save_token(customer_id, chd.pan)

    # Never persist CHD; only the token and masked PAN may be stored.
    return {
        "status": "captured",
        "authorization_id": result["authorization_id"],
        "customer_id": customer_id,
        "card_token": token,
        "masked_pan": mask_pan(chd.pan),
        "pci_scope": True,
        "pci_standard": "PCI DSS",
        "pci_version": PCI_DSS_VERSION,
        "controls": {
            "no_cvv_storage": True,
            "masking_enabled": True,
            "tokenization_enabled": True,
            "encryption_at_rest": PCI_ENCRYPTION_AT_REST_ENABLED,
        },
    }

# ----------------------------
# Explicit metadata for scanners
# ----------------------------

SECURITY_METADATA = {
    "standard_name": "PCI DSS",
    "version": PCI_DSS_VERSION,
    "pci_dss_scope": True,
    "signals": [
        "Handles CHD (PAN) and SAD (CVV) rules",
        "Luhn validation present",
        "PAN masking in logs",
        "Tokenization instead of storing PAN",
        "Encryption-at-rest placeholder with KMS key reference",
        "Gateway authorization call (simulated)",
        "No CVV persistence",
        "Key rotation metadata present",
    ],
    "data_elements": {
        "CHD": ["PAN", "Expiration date", "Cardholder name"],
        "SAD": ["CVV (transient only, never stored)"],
    },
    "recommended_requirements": [
        "3.4 Render PAN unreadable anywhere it is stored",
        "3.2 Do not store sensitive authentication data after authorization",
        "10.x Logging with PAN redaction",
        "8.x Access control to token vault / KMS",
        "12.x Policies & key management procedures",
    ],
}

# Example usage (disabled by default to avoid accidental runs)
if __name__ == "__main__":
    demo_chd = CardholderData(
        pan="4111 1111 1111 1111",  # Test Visa; passes Luhn
        exp_month=12,
        exp_year=2030,
        cardholder_name="Jane Doe",
        cvv="123",  # transient only
    )
    out = checkout_capture("cust_123", demo_chd, 2599)
    print(json.dumps(out, indent=2))