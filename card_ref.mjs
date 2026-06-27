// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 AlgoVoi (chopmob-cloud). Open A2A primitive, Apache-2.0.
// card_ref = "sha256:" + SHA-256(JCS(AgentCard without the signatures field)).
// Recomputes offline with only RFC 8785 (JCS) and SHA-256, no JWS or JWKS.
import { createHash } from "node:crypto";
import { canonicalize } from "@algovoi/substrate";

export function cardRef(agentCard) {
  if (agentCard === null || typeof agentCard !== "object" || Array.isArray(agentCard)) {
    throw new TypeError("agentCard must be an object");
  }
  const prepared = {};
  for (const k of Object.keys(agentCard)) if (k !== "signatures") prepared[k] = agentCard[k];
  return "sha256:" + createHash("sha256").update(Buffer.from(canonicalize(prepared), "utf-8")).digest("hex");
}
