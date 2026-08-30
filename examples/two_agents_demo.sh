#!/bin/bash
# Runs both halves of technocore-a2a locally against the live technocore.chat, end to end:
# starts "bob" as a serving agent, delegates one demo task to it as "alice", waits for the
# result, then tears bob down. Two throwaway --home directories under mktemp, cleaned up on exit.
set -euo pipefail

cd "$(dirname "$0")/.."

BOB_HOME="$(mktemp -d)"
ALICE_HOME="$(mktemp -d)"
trap 'kill "${BOB_PID:-0}" 2>/dev/null; rm -rf "$BOB_HOME" "$ALICE_HOME"' EXIT

python3 agent.py --home "$BOB_HOME" serve > /tmp/technocore-a2a-demo-bob.log 2>&1 &
BOB_PID=$!
sleep 3

BOB_MAILBOX=$(python3 -c "import json; print(json.load(open('$BOB_HOME/state.json'))['mailbox'])")
BOB_DID=$(python3 agent.py --home "$BOB_HOME" identity | awk '/^did: / {print $2}')
echo "bob is listening on $BOB_MAILBOX (log: /tmp/technocore-a2a-demo-bob.log)"

python3 agent.py --home "$ALICE_HOME" send \
  --to-mailbox "$BOB_MAILBOX" \
  --peer-did "$BOB_DID" \
  --text "hello from the demo script" \
  --skill shout \
  --timeout 90
