# card_ref

A deterministic, content addressed reference to an A2A AgentCard.

    card_ref = "sha256:" + SHA-256(JCS(AgentCard without the signatures field))

It recomputes offline with only RFC 8785 (JCS) and SHA-256. No JWS, no JWKS, no key infrastructure.

## Why

A2A lets an agent optionally sign its AgentCard (specification section 8.4). A signature proves a key signed a blob, and verifying it needs JWKS key infrastructure. It does not give a stable, offline reference that says "the agent I dealt with advertised exactly these bytes." Change one skill or one security scheme and a consumer cannot tell. card_ref closes that gap: it is the byte identity of the card itself.

## Construction

The preimage is exactly the payload A2A canonicalizes for AgentCard signing (specification section 8.4.2: exclude the signatures field). So card_ref is the content address of the same bytes an A2A signature signs over.

Properties:

- including or excluding the signatures field does not change card_ref
- key order does not change it (RFC 8785 JCS)
- changing any advertised field (a skill, a scheme, the url, the version) changes it

## Use

Python:

    from card_ref import card_ref
    ref = card_ref(agent_card_dict)

Node:

    import { cardRef } from "./card_ref.mjs";
    const ref = cardRef(agentCard);

CLI:

    python cli.py path/to/agent-card.json
    cat agent-card.json | python cli.py

## Conformance

Vectors live in the algovoi-jcs-conformance-vectors corpus, set card_ref_v1: positives, invariants (signature exclusion, key reorder), and negatives (changed skill, changed scheme), verified byte for byte across independent Python and Node runners.

## Open Licence for A2A Partners

card_ref carries an open licence for A2A partners.

### Under Apache 2.0 Licence

Implementers may adopt, implement, and build on it freely under Apache 2.0. Retain the NOTICE file and licence header in derivative works.

## Licence

Apache 2.0. Copyright (c) 2026 AlgoVoi (chopmob-cloud).
