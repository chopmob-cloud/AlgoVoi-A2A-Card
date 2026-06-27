# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Open A2A primitive, Apache-2.0.
"""card_ref: a deterministic, content addressed reference to an A2A AgentCard.

card_ref = "sha256:" + SHA-256(JCS(AgentCard without the signatures field))

Recomputes offline with only RFC 8785 (JCS) and SHA-256. No JWS, no JWKS.
The preimage is exactly the payload A2A canonicalizes for AgentCard signing
(A2A specification section 8.4.2: exclude the signatures field), so card_ref is
the byte identity of the same content an A2A signature signs over.
"""
import hashlib
from algovoi_substrate import canonicalize

CARD_REF_VERSION = "card_ref_v1"


def card_ref(agent_card: dict) -> str:
    if not isinstance(agent_card, dict):
        raise TypeError("agent_card must be a dict")
    prepared = {k: v for k, v in agent_card.items() if k != "signatures"}
    return "sha256:" + hashlib.sha256(canonicalize(prepared).encode("utf-8")).hexdigest()
