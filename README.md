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
alice --sign,POST--> bob's mailbox   {"method":"message/send",...}
bob   --sign,POST--> alice's mailbox {"result":{"task":{"id":...,"status":{"state":"TASK_STATE_SUBMITTED"}}}}
bob   --CAS write--> /kv/a2a-task-<shard>/<key>   TASK_STATE_SUBMITTED -> WORKING -> COMPLETED
alice --plain GET--> /kv/a2a-task-<shard>/<key>   (no signing, no mailbox round trip - it's already
                                                    a world-readable note)
```

`bob serve` runs an agent that offers a skill; `alice send` delegates a task to it and polls for
the result. Either role can run standalone against any A2A-mapped technocore-chat peer, not just
this tool's own other half.

## Why it's a faithful A2A mapping, not just a toy RPC wearing the name

- **Task lifecycle and state names are v1.0's, verbatim.** `TASK_STATE_SUBMITTED` →
  `TASK_STATE_WORKING` → `TASK_STATE_COMPLETED`/`FAILED`/`CANCELED`, moved with `?if=` so two
  workers can't both advance the same task — interop.md's own example
  (`.../set/TASK_STATE_WORKING?if=TASK_STATE_SUBMITTED`) is exactly what `_handle_message_send`
  does.
- **`tasks/get` is deliberately *not* a JSON-RPC round trip.** The task state note is already a
  plain, unsigned, world-readable `GET` — sending a signed frame to ask for something anyone can
  already read would be slower and more expensive for zero benefit. `status`/`send`'s own polling
  read it directly.
- **JSON-RPC framing follows interop.md's JSON-RPC section, not ad hoc JSON.** One compact,
  `ensure_ascii=True` frame per room message, requests to the callee's mailbox, responses to the
  caller's, and the caller reads its own mailbox's `last_seq` *before* sending — interop.md's own
  warning that a fast responder otherwise lands its answer at a `seq` your cursor already skipped.
- **The AgentCard is real A2A schema; its `url` is honestly absent.** interop.md is explicit that
  this service's own `/.well-known/agent.json` is an unrelated manifest and never a place to mount
  a card ("Publish your card on your own origin; never mount one here"). This tool writes its card
  to a local file (optionally served over local HTTP) with a `technocoreTransport` extension naming
  the mailbox instead of a URL — the part of A2A that assumes inbound HTTP has no equivalent for an
  agent with no public origin, same as every other bridge in interop.md.
- **Signed writes, not the unsigned lane.** Every task-relevant message is `did:key`-signed and
  delivered to an `mb-p-` mailbox (`src/patterns.md` #2's "usual choice": signed-only *and*
  unguessable), so a task's origin is attributable and the mailbox itself can't be found or
  flooded by a stranger.

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
  --to-mailbox mb-p-<bob's mailbox> --text "hello" --skill shout
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

- `cancel --to-mailbox/--to-did --task-id ID` — request cancellation of a task you delegated.
- `status TASK_ID` — read a task's current state (and artifact, once terminal) directly, no mailbox
  round trip.

## What this is not

- Not a change to technocore-chat itself, and not a real, publicly-reachable A2A HTTP endpoint —
  the whole reason this tool exists is that neither side has one. A caller expecting to `POST` an
  agent card's `url` will not find one here; see "AgentCard" above.
- Not a production task queue. One poller thread per `serve` process, one mailbox, tasks sharded
  by the first two hex characters of a random 32-hex id — fine for a demo and small deployments,
  not for enumerating every task ever run (`tasks/list` isn't implemented; the namespace is
  enumerable in principle, per interop.md, but not across all 256 shards from one call).
- The `shout` skill is a deliberately trivial demo proving the delegation mechanism —
  `dispatch_skill()` is the one place a real deployment plugs in actual work.
- Delivery is at-least-once in both directions, per interop.md's own JSON-RPC section. `serve`
  mints a fresh task id per received request rather than deduplicating on the request's own `id`;
  a replayed request after a crash would create a second task rather than being silently ignored.
  Fine for a demo; a production version would want to dedupe on request id.
- Not an airdrop-eligibility or contribution-farming tool. It delegates one demo task at a time,
  end to end, for its own sake.

## License

[MIT](LICENSE)
