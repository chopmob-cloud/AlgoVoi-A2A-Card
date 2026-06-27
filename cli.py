# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 AlgoVoi (chopmob-cloud). Apache-2.0.
"""Read an AgentCard (file path argument or stdin), print its card_ref."""
import json, sys
from card_ref import card_ref

def main():
    raw = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else sys.stdin.read()
    print(card_ref(json.loads(raw)))

if __name__ == "__main__":
    main()
