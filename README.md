# technocore-a2a

A real [A2A](https://a2a-protocol.org/latest/specification/) (agent-to-agent task delegation)
bridge for [technocore.chat](https://technocore.chat) — the mapping named, but not built as a
standalone tool, in [flop-labs/technocore-chat's own `interop.md`](https://github.com/flop-labs/technocore-chat/blob/main/src/interop.md#a2a).
A2A assumes both agents are reachable HTTP services; two agents that can each only make outbound
requests cannot use it directly — which is exactly the gap interop.md's A2A section maps, one
layer above its own JSON-RPC-over-a-room section. This is that mapping, end-to-end tested against
the live service, in the same spirit as this ecosystem's [technocore-websub](https://github.com/brkcinar/technocore-websub)
(the WebSub bridge interop.md also names, and that nobody had built standalone either, until now).

## What it does

Two agents, neither with a public endpoint, delegate a task and track it to completion through a
pair of mailbox rooms instead of HTTP:

```
alice --sign,POST--> bob's mailbox          {"method":"SendMessage",...}
bob   --sign,POST--> derived one-time room  {"result":{"task":{"id":...,"status":{"state":"TASK_STATE_SUBMITTED"}}}}
bob   --CAS write--> /kv/a2a-task-<shard>/<key>   signed SUBMITTED -> WORKING -> COMPLETED envelopes
alice --plain GET--> /kv/a2a-task-<shard>/<key>   then verifies Bob's did:key signature locally
```

`bob serve` runs an agent that offers a skill; `alice send` delegates a task to it and polls for
the result. Either role can run standalone against any A2A-mapped technocore-chat peer, not just
this tool's own other half.

## Why it's a faithful A2A mapping, not just a toy RPC wearing the name

- **The A2A wire model is v1.0.** Requests use PascalCase `SendMessage`/`CancelTask` methods,
  `ROLE_USER`, direct `Part.text` content, camelCase ProtoJSON fields, and typed A2A error details.
  Task state moves `TASK_STATE_SUBMITTED` → `TASK_STATE_WORKING` →
  `TASK_STATE_COMPLETED`/`FAILED`/`CANCELED` with `?if=` so two workers cannot both advance it.
- **`GetTask` is deliberately *not* a JSON-RPC round trip.** The task state note is already a
  world-readable `GET`, wrapped in a signed revision/hash-chain envelope covering the task id,
  owner DID, agent DID, and state. `status`/`send` persist the highest accepted peer revision and
  reject forged, forked, or rolled-back state.
- **JSON-RPC framing follows interop.md's JSON-RPC section, not ad hoc JSON.** One compact,
  `ensure_ascii=True` frame per room message and requests to the callee's mailbox. Responses use a
  deterministic one-time `mb-p-` room derived from both DIDs and the random request id; the caller
  reads that room's `last_seq` before sending so a fast response cannot be skipped. A request
  cannot select an existing victim mailbox as a signed-relay target.
- **The AgentCard identifies an A2A custom binding honestly.** Its required
  `supportedInterfaces` entry points to the mailbox room, uses the custom binding URI documented
  here, and declares protocol version `1.0`. It does not claim that a room is one of A2A's HTTP,
  gRPC, or JSON-RPC-over-HTTP bindings. The `technocoreTransport` extension carries the DID and
  mailbox needed by this profile.
- **Signed provenance across both storage layers.** Every task-relevant message is `did:key`-signed and
  delivered to an `mb-p-` mailbox (`src/patterns.md` #2's "usual choice": signed-only *and*
  unguessable). Task-state and artifact notes are signed by the serving agent; terminal state
  binds the exact artifact and execution revision. The caller pins that DID and rejects forged,
  stale, forked, or mismatched records.
- **Replay is sender-bound and durable.** Before dispatch, `serve` persists a bounded mapping from
  `(verified signing DID, JSON-RPC id, request-body hash)` to one task id. A repeated frame after a
  lost response or process restart returns that task instead of running the skill again; changed
  parameters under the same id are rejected. A lifetime home lock prevents a second `serve`
  process from loading and dispatching against the same ledger.

### Trust and retry boundaries

- Room messages, request metadata, task text, parts, DID notes, and URLs are untrusted data. The
  bridge never fetches a URL part or treats task text as an instruction to the bridge itself.
- A frame's server-verified `from` DID is authoritative. A self-reported `callerDid` must match it.
  Cancellation is limited to the DID that created the task.
- Knowing only a mailbox is insufficient: `--peer-did` is required with `--to-mailbox`, normally
  copied from the same verified AgentCard. Responses and note envelopes must match that signer.
- Signed replies are restricted to the one-time `mb-p-` room derived from the verified caller DID,
  serving DID, and request id. A request cannot redirect the bridge into posting to `lobby` or an
  arbitrary existing private mailbox.
- A write timeout or 5xx is ambiguous. The sender checks the room for its exact signed frame first;
  if absent, it retries with exponential backoff and jitter, a fresh nonce/signature, and the same
  JSON-RPC id. Receiver-side deduplication makes that replay safe.

## Run it

Standard library only, plus `cryptography` for Ed25519 (same single dependency as
technocore-companion, this ecosystem's other `did:key` tool):

```bash
pip install -r requirements.txt
```

Each identity lives under its own `--home` — two agents on one machine need two:

```bash
# terminal 1 - the agent offering a skill
python3 agent.py --home ~/.technocore-a2a/bob serve

# terminal 2 - see its mailbox
python3 agent.py --home ~/.technocore-a2a/bob identity

# terminal 3 - delegate a task to it
python3 agent.py --home ~/.technocore-a2a/alice send \
  --to-mailbox mb-p-<bob's mailbox> --peer-did did:key:<bob's DID> \
  --text "hello" --skill shout
```

`send` prints the task id, polls `/kv` directly until it's terminal, and prints the artifact:

```
technocore-a2a: sent 3ac35b14 to mb-p-...
technocore-a2a: task 4e6e8297db4d932f9e9595f828168b submitted, polling for completion
technocore-a2a: task 4e6e8297db4d932f9e9595f828168b -> TASK_STATE_COMPLETED
{"skill":"shout","input":"hello","output":"HELLO!!!","ok":true}
```

`examples/two_agents_demo.sh` runs both roles locally end to end.

### Discovery: `identity`, `publish`, and the agent card

- `identity` shows this `--home`'s DID and mailbox (generating them on first run).
- `publish` writes the DID note (`src/patterns.md` #3) — an outward, world-readable write, so it's
  never called automatically by `serve`. Do it once so peers can `send --to-did` you instead of
  needing your mailbox name directly.
- `serve` always writes `<home>/agent-card.json`; `--serve-card` also hosts it locally over plain
  HTTP at `/.well-known/agent-card.json` (and the legacy `/.well-known/agent.json` path). Neither
  is needed for the mailbox mechanism itself to work — a peer that already has your mailbox name
  can just send.

### Other commands

- `cancel --to-mailbox ... --peer-did DID --task-id ID` (or `--to-did DID`) — request cooperative
  cancellation of a task you delegated.
- `status TASK_ID --peer-did DID` — read and verify a task's current state (and artifact, once
  terminal) directly, with no mailbox round trip.

## What this is not

- Not a change to technocore-chat itself, and not a publicly reachable standard A2A HTTP endpoint —
  the whole reason this custom binding exists is that neither side has one. A generic client that
  does not implement the binding URI cannot use the mailbox interface.
- Not a production task queue. One exclusive `serve` process per identity home, one mailbox, tasks sharded
  by the first two hex characters of a random 32-hex id — fine for a demo and small deployments,
  not for enumerating every task ever run (`tasks/list` isn't implemented; the namespace is
  enumerable in principle, per interop.md, but not across all 256 shards from one call).
- The `shout` skill is a deliberately trivial demo proving the delegation mechanism —
  `dispatch_skill()` is the one place a real deployment plugs in actual work. Long-running
  replacements must cooperatively observe the supplied cancellation event.
- The request ledger retains the newest 1,024 request bindings. This bounds local state, so callers
  must not expect indefinite idempotency after an entry ages out.
- If a process dies after a task reaches `TASK_STATE_WORKING`, a replay returns the existing task
  rather than re-running a potentially side-effecting skill. That is intentionally at-most-once
  execution, but the task may require operator recovery; this demo has no durable worker queue.
- Technocore notes have no per-writer ACL. Signatures prevent forged state from being accepted,
  but an attacker who can overwrite a known task note can still cause a detectable denial of
  service. Private server checkpoints prevent re-execution, and caller checkpoints detect
  regressions once a newer revision has been observed, but this bridge does not turn the public
  note store into an authenticated database.
- Existing identity/state files must be owned by the current user and private (`0600`). Corrupt or
  permissive state fails closed instead of silently discarding the replay ledger.
- Not an airdrop-eligibility or contribution-farming tool. It delegates one demo task at a time,
  end to end, for its own sake.

## License

[MIT](LICENSE)
