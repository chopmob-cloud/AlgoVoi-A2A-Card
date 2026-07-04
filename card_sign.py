# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Open A2A primitive, Apache-2.0.
"""card_sign: an A2A section 8.4 detached-JWS signature over an AgentCard.

Signs the same canonical form that card_ref content-addresses:

    payload   = AgentCard without the signatures field
    canonical = JCS(payload)                       (RFC 8785)
    protected = {"alg":"EdDSA","typ":"JOSE","kid":..., "jku":...}
    signature = Ed25519( BASE64URL(protected) + "." + BASE64URL(canonical) )
    card["signatures"] = [{"protected": ..., "signature": ...}]

A verifier resolves the key by its `kid` from the JWKS at `jku` and recomputes
the same canonical form. Keyless verification stays available via card_ref: the
JWS signature and the content address sign over identical bytes.

`kid` is the SHA-256 thumbprint of the raw Ed25519 public key (first 32 hex
chars), so the JWKS key is self-identifying.
"""
import base64
import hashlib
import json

from algovoi_substrate import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CARD_SIGN_VERSION = "card_sign_v1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def signing_payload(agent_card: dict) -> bytes:
    """The A2A section 8.4 canonical form: JCS of the card without signatures."""
    prepared = {k: v for k, v in agent_card.items() if k != "signatures"}
    return canonicalize(prepared).encode("utf-8")


def public_jwk(sk: Ed25519PrivateKey) -> dict:
    """Public JWK for the signing key, with a SHA-256-thumbprint kid."""
    pk_raw = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = hashlib.sha256(pk_raw).hexdigest()[:32]
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64u(pk_raw),
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    }


def sign_card(agent_card: dict, sk: Ed25519PrivateKey, jku: str) -> dict:
    """Return the AgentCard with an A2A section 8.4 detached JWS in signatures[]."""
    payload = {k: v for k, v in agent_card.items() if k != "signatures"}
    canonical = canonicalize(payload).encode("utf-8")
    kid = public_jwk(sk)["kid"]
    protected = {"alg": "EdDSA", "typ": "JOSE", "kid": kid, "jku": jku}
    p_b64 = _b64u(json.dumps(protected, separators=(",", ":"), sort_keys=True).encode())
    y_b64 = _b64u(canonical)
    sig = sk.sign(f"{p_b64}.{y_b64}".encode("ascii"))
    return {**payload, "signatures": [{"protected": p_b64, "signature": _b64u(sig)}]}


def verify_card(agent_card: dict, jwks: dict) -> bool:
    """Verify the first signature on the card against a JWKS. Returns True/False."""
    sigs = agent_card.get("signatures") or []
    if not sigs:
        return False
    protected = sigs[0]["protected"]
    header = json.loads(_b64u_decode(protected))
    jwk = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if jwk is None or jwk.get("crv") != "Ed25519":
        return False
    pub = Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"]))
    signing_input = f"{protected}.{_b64u(signing_payload(agent_card))}".encode("ascii")
    try:
        pub.verify(_b64u_decode(sigs[0]["signature"]), signing_input)
        return True
    except Exception:
        return False
