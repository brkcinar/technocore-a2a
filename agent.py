#!/usr/bin/env python3
"""
technocore-a2a - agent-to-agent task delegation over technocore.chat, per the A2A
mapping in flop-labs/technocore-chat's own docs/interop.md.

A2A (https://a2a-protocol.org/latest/specification/) is agent-to-agent task delegation:
an agent publishes a card describing its skills, a caller sends it a message, that
becomes a Task with a lifecycle (submitted -> working -> completed/failed/canceled), and
the caller collects artifacts when it's done. The spec assumes both sides are reachable
HTTP services. Two agents that can each only make outbound requests cannot do that
directly - which is exactly the gap interop.md's A2A section describes, one layer above
its own JSON-RPC section:

    "The mapping is small. A room is the contextId; a note under a sharded task
    namespace is the task state, moved with ?if= so two workers cannot both advance
    it; artifacts are notes or a p- room."

This tool is that mapping, built and end-to-end tested against the live service, in the
same spirit as this ecosystem's technocore-websub (the WebSub bridge interop.md also
names). Nobody had built the A2A one as a standalone, spec-literate tool either, as of
this tool's first commit - most third-party "A2A adapters" in this ecosystem bolt A2A's
HTTP transport onto a technocore.chat client instead of using interop.md's actual
room-based mapping, which defeats the reason A2A needs a mapping here at all.

What is and isn't real A2A here, precisely:

- Task lifecycle, states, and JSON-RPC method names are v1.0's, verbatim
  (https://a2a-protocol.org/latest/specification/). `TASK_STATE_*` matches the
  interop.md example exactly (`TASK_STATE_WORKING?if=TASK_STATE_SUBMITTED`).
- The AgentCard schema is real A2A. What is NOT real A2A: the `url` a card would
  normally advertise for HTTP `POST`s. interop.md is explicit that this service's own
  `/.well-known/agent.json` is an unrelated manifest and never a place to mount a card
  ("Publish your card on your own origin; never mount one here"). This tool writes its
  card to a local file (and can optionally serve it over plain local HTTP) with a
  `technocoreTransport` extension field naming the mailbox instead of a URL - the part
  of A2A that assumes inbound HTTP has no equivalent for an agent with no public origin,
  same as every other bridge in interop.md.
- Message delivery replaces HTTP POST with the JSON-RPC-over-a-room binding from
  interop.md's own JSON-RPC section: one compact, ASCII-escaped frame per room message,
  requests to the callee's mailbox, responses to the caller's. `tasks/get` is
  deliberately NOT sent as a JSON-RPC round trip - the task state note is already a
  plain, unsigned, world-readable GET, and sending a signed frame to ask for something
  anyone can already read would just be slower and more expensive for no benefit.

Dependency: only "cryptography" (same as technocore-companion, this ecosystem's other
did:key tool) - the rest is standard library, matching technocore-websub's own choice to
keep this kind of bridge auditable and dependency-light.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

APP_NAME = "technocore-a2a"
APP_VERSION = "0.1.0"
A2A_PROTOCOL_VERSION = "1.0.1"

TECHNOCORE_BASE = "https://technocore.chat"
DEFAULT_HOME = Path.home() / ".technocore-a2a"
MULTICODEC_ED25519 = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MESSAGE_MAX_CHARS = 4096
NOTE_MAX_CHARS = 8192
POLL_WAIT_SECONDS = 10
DEFAULT_CARD_PORT = 8735

# A2A v1.0 task states (interop.md: "Names are v1.0's; v0.3.0 spelled them ... lowercase").
TASK_STATE_SUBMITTED = "TASK_STATE_SUBMITTED"
TASK_STATE_WORKING = "TASK_STATE_WORKING"
TASK_STATE_COMPLETED = "TASK_STATE_COMPLETED"
TASK_STATE_FAILED = "TASK_STATE_FAILED"
TASK_STATE_CANCELED = "TASK_STATE_CANCELED"
TERMINAL_STATES = {TASK_STATE_COMPLETED, TASK_STATE_FAILED, TASK_STATE_CANCELED}

UA = f"{APP_NAME}/{APP_VERSION}"


class A2AError(Exception):
    """Something the caller did wrong, or the peer refused - never a bug to retry past."""


def _backoff(attempt: int, cap: float = 5.0) -> float:
    """Exponential backoff for a transient (5xx / network) failure, capped so a sustained
    bad patch on the live service still gets several tries within a bounded total wait."""
    return min(0.5 * (2**attempt), cap)


# ----------------------------------------------------------------------- did:key identity


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519 + public_bytes)


def sign_message(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")


def did_fingerprint(did: str) -> tuple[str, str]:
    """(shard, key) for the public DID directory - src/patterns.md #3: first 16 hex chars
    of SHA-256(did), split 2/14 so the directory stays spread across bounded namespaces."""
    digest = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return digest[:2], digest[2:]


def load_or_create_identity(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)
    return key


def new_mailbox_name() -> str:
    """mb-p-<16 hex> - signed-only (mb-) AND unguessable (p-), src/patterns.md #2's "usual
    choice": every request lands attributable to a did:key, and nobody can find or flood
    it who wasn't handed the name (via the card or the DID note)."""
    return "mb-p-" + secrets.token_hex(8)


# ------------------------------------------------------------------------------ home state


def load_state(home: Path) -> dict:
    state_path = home / "state.json"
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(home: Path, state: dict) -> None:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = home / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(home / "state.json")


class Agent:
    """One identity + mailbox, loaded from --home. Both `serve` and `send` are just
    different things done with one of these - an A2A peer is symmetric until it decides
    to offer a skill or place a call."""

    def __init__(self, home: Path, base: str):
        self.home = home
        self.base = base.rstrip("/")
        self.key = load_or_create_identity(home / "identity.pem")
        self.did = did_from_private_key(self.key)
        state = load_state(home)
        if "mailbox" not in state:
            state["mailbox"] = new_mailbox_name()
            save_state(home, state)
        self.mailbox = state["mailbox"]
        self.state = state

    def save(self) -> None:
        save_state(self.home, self.state)

    # --------------------------------------------------------------- technocore.chat client

    def _url(self, path: str, params: dict | None = None) -> str:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def _get(
        self, path: str, params: dict | None = None, timeout: float = 15, retries: int = 5, deadline: float | None = None
    ) -> bytes:
        # With a `deadline` (an absolute time.time()), retries continue until it arrives,
        # not just for `retries` attempts - a fast-failing burst of 503s would otherwise
        # exhaust a fixed attempt count in a couple of seconds and give up, when the
        # caller's own --timeout budget still had 50+ seconds left to wait out the burst.
        # Without a deadline, `retries` is the only bound (used by callers with no overall
        # timeout of their own, e.g. `serve`'s poll loop, which retries again next cycle
        # regardless).
        attempt = 0
        while True:
            request_timeout = timeout
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise A2AError(f"GET {path} timed out waiting for a healthy response")
                request_timeout = min(timeout, remaining)
            request = urllib.request.Request(self._url(path, params), headers={"User-Agent": UA})
            try:
                with urllib.request.urlopen(request, timeout=request_timeout) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise
                if exc.code < 500:
                    raise A2AError(f"GET {path} -> {exc.code} {exc.read().decode('utf-8', 'replace')}") from exc
                error = A2AError(f"GET {path} -> {exc.code} {exc.read().decode('utf-8', 'replace')}")
                error.__cause__ = exc
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                # A transient network hiccup (DNS, TLS, a dropped long-poll connection) -
                # worth retrying rather than becoming the caller's problem immediately.
                error = A2AError(f"GET {path} failed: {exc}")
                error.__cause__ = exc
            backoff = _backoff(attempt)
            if deadline is not None:
                if time.time() + backoff >= deadline:
                    raise error
            elif attempt >= retries:
                raise error
            time.sleep(backoff)
            attempt += 1

    def read_room(self, room: str, since: int, wait: int = 0, deadline: float | None = None) -> dict:
        body = self._get(
            f"/r/{room}", {"since": since, "wait": wait, "format": "json"}, timeout=wait + 5, deadline=deadline
        )
        return json.loads(body.decode("utf-8"))

    def read_room_tail(self, room: str, deadline: float | None = None) -> dict:
        """A cursor-free read - interop.md's way to detect a reaped/recreated room."""
        return json.loads(self._get(f"/r/{room}", {"format": "json"}, deadline=deadline).decode("utf-8"))

    def say_signed(self, room: str, text: str, deadline: float | None = None) -> int:
        if len(text) > MESSAGE_MAX_CHARS:
            raise A2AError(f"frame is {len(text)} chars, over the {MESSAGE_MAX_CHARS}-char message cap")
        nonce = str(time.time_ns())
        payload = f"{room}|{nonce}|{text}".encode("utf-8")
        signature = sign_message(self.key, payload)
        body = json.dumps({"did": self.did, "sig": signature, "nonce": nonce, "text": text}).encode("utf-8")
        # Without ?format=json a write response is the same plain-text room render a read
        # gets - there is no bare {"seq":...} reply. With it, the response is the ordinary
        # room-view JSON plus one extra top-level "posted" object: the just-written record,
        # seq included. Confirmed against the live service; undocumented in /llms.txt.
        request = urllib.request.Request(
            self._url(f"/r/{room}?format=json"),
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": UA},
            method="POST",
        )
        # A retry here reuses the SAME nonce/signature, which makes it safe rather than
        # merely convenient: if the first attempt actually landed and only its response
        # was lost, the retry is a replay of an already-used nonce and the server 403s it
        # instead of double-posting - see README's "Signed writes" / anti-replay note. Same
        # deadline-vs-attempt-count reasoning as _get() above: with a deadline, keep trying
        # until it arrives rather than giving up after a fixed count into a fast-failing burst.
        retries = 5
        attempt = 0
        while True:
            request_timeout = 15
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise A2AError(f"signed write to {room} timed out waiting for a healthy response")
                request_timeout = min(request_timeout, remaining)
            try:
                with urllib.request.urlopen(request, timeout=request_timeout) as response:
                    return json.loads(response.read().decode("utf-8"))["posted"]["seq"]
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    raise A2AError(f"signed write to {room} -> {exc.code} {exc.read().decode('utf-8', 'replace')}") from exc
                error = A2AError(f"signed write to {room} -> {exc.code} {exc.read().decode('utf-8', 'replace')}")
                error.__cause__ = exc
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                error = A2AError(f"signed write to {room} failed: {exc}")
                error.__cause__ = exc
            backoff = _backoff(attempt)
            if deadline is not None:
                if time.time() + backoff >= deadline:
                    raise error
            elif attempt >= retries:
                raise error
            time.sleep(backoff)
            attempt += 1

    def kv_get(self, ns: str, key: str, deadline: float | None = None) -> str | None:
        # _get() already turns any non-404 HTTPError into A2AError, so the only HTTPError
        # that can reach here is a 404 - "no such note yet", not a failure to report.
        try:
            return self._get(f"/kv/{ns}/{key}", deadline=deadline).decode("utf-8")
        except urllib.error.HTTPError:
            return None

    def kv_set(
        self,
        ns: str,
        key: str,
        value: str,
        if_expected: str | None = None,
        if_absent: bool = False,
        deadline: float | None = None,
    ) -> bool:
        if len(value) > NOTE_MAX_CHARS:
            raise A2AError(f"note is {len(value)} chars, over the {NOTE_MAX_CHARS}-char note cap")
        params = {}
        if if_expected is not None:
            params["if"] = if_expected
        if if_absent:
            params["if_absent"] = "1"
        path = f"/kv/{ns}/{key}/set/{urllib.parse.quote(value, safe='')}"
        try:
            self._get(path, params, deadline=deadline)
            return True
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                return False
            raise A2AError(f"note write {ns}/{key} -> {exc.code} {exc.read().decode('utf-8', 'replace')}") from exc

    def publish_did_note(self) -> None:
        """src/patterns.md #3: the public DID directory. Explicit opt-in (never called from
        `serve` automatically) because it's an outward, world-readable write, not something
        to do on every process start."""
        shard, key = did_fingerprint(self.did)
        value = f"{self.did} mailbox:{self.mailbox}"
        self.kv_set(f"did-{shard}", key, value)

    def resolve_peer(self, did: str) -> str:
        """Look up a peer's mailbox from its published DID note. Only needed if you weren't
        handed the mailbox name directly (e.g. via their agent card). Tries the sharded
        path first, then the legacy `/kv/did/<fingerprint>` path per src/patterns.md #3
        ("identities published before this convention changed")."""
        shard, key = did_fingerprint(did)
        note = self.kv_get(f"did-{shard}", key) or self.kv_get("did", shard + key)
        if note is None:
            raise A2AError(f"no published DID note for {did} - ask them for their mailbox name directly")
        for token in note.split():
            if token.startswith("mailbox:"):
                return token[len("mailbox:"):]
        raise A2AError(f"DID note for {did} has no mailbox: field")


# ------------------------------------------------------------------------------- task store


def task_shard(task_id: str) -> tuple[str, str]:
    return task_id[:2], task_id[2:]


def task_state_ns(task_id: str) -> tuple[str, str]:
    shard, key = task_shard(task_id)
    return f"a2a-task-{shard}", key


def task_artifact_ns(task_id: str) -> tuple[str, str]:
    shard, key = task_shard(task_id)
    return f"a2a-artifact-{shard}", key


# -------------------------------------------------------------------------------- JSON-RPC
#
# interop.md's JSON-RPC section, verbatim: "One frame per message, compact. Serialise with
# separators=(',', ':') and ensure_ascii=True - the latter escapes every non-ASCII
# character, so nothing in the payload can be altered by the single-line sweep, which also
# keeps the frame verifiable against its signature."


def _dumps(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def rpc_request(method: str, params: dict, req_id: str | None = None) -> tuple[str, str]:
    req_id = req_id or secrets.token_hex(4)
    return req_id, _dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})


def rpc_result(req_id: str, result: dict) -> str:
    return _dumps({"jsonrpc": "2.0", "id": req_id, "result": result})


def rpc_error(req_id: str, code: int, message: str) -> str:
    return _dumps({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def parse_rpc(text: str) -> dict | None:
    try:
        frame = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(frame, dict) or frame.get("jsonrpc") != "2.0" or "id" not in frame:
        return None
    return frame


# ------------------------------------------------------------------------------ agent card
#
# interop.md, read-this-before-anything-else: "This service serves /.well-known/agent.json,
# and it is not a card ... Publish your card on your own origin; never mount one here." This
# writes the card to a local file on THIS tool's own home, never to technocore.chat.


def build_agent_card(agent: Agent, name: str, description: str) -> dict:
    return {
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "name": name,
        "description": description,
        # No "url": a real AgentCard's is where a caller POSTs. This agent has none to
        # give - see "technocoreTransport" below instead, and the module docstring.
        "skills": [
            {
                "id": "shout",
                "name": "shout",
                "description": "Upper-cases the given text and appends emphasis. Demo skill "
                "proving the delegation mechanism; swap dispatch_skill() for real work.",
                "tags": ["demo"],
            }
        ],
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "technocoreTransport": {
            "note": "This agent has no public HTTP origin. Per flop-labs/technocore-chat's "
            "docs/interop.md (A2A section), task requests are delivered as signed "
            "JSON-RPC-over-a-room frames instead of HTTP POST - see technocore-a2a's README.",
            "base": TECHNOCORE_BASE,
            "did": agent.did,
            "mailbox": agent.mailbox,
        },
    }


class _CardHandler(BaseHTTPRequestHandler):
    card_bytes: bytes = b"{}"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/.well-known/agent-card.json", "/.well-known/agent.json"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(self.card_bytes)))
            self.end_headers()
            self.wfile.write(self.card_bytes)
            return
        self.send_response(404)
        self.end_headers()


def serve_card(card: dict, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("_Handler", (_CardHandler,), {"card_bytes": json.dumps(card, indent=2).encode("utf-8")})
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ------------------------------------------------------------------------------ demo skill


def dispatch_skill(skill: str, text: str) -> tuple[bool, str]:
    """(ok, result_or_error). The one place a real deployment would plug in actual work -
    everything above this line is the delegation mechanism, not the task."""
    if skill == "shout":
        return True, text.upper() + "!!!"
    return False, f"unknown skill {skill!r} - this agent only offers 'shout'"


# ------------------------------------------------------------------------------------ serve


def cmd_serve(agent: Agent, args: argparse.Namespace) -> int:
    card = build_agent_card(agent, args.name, args.description)
    card_path = agent.home / "agent-card.json"
    card_path.write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(f"{APP_NAME}: did={agent.did}", file=sys.stderr)
    print(f"{APP_NAME}: mailbox={agent.mailbox}", file=sys.stderr)
    print(f"{APP_NAME}: card written to {card_path}", file=sys.stderr)

    server = None
    if args.serve_card:
        server = serve_card(card, args.card_host, args.card_port)
        print(f"{APP_NAME}: card served on http://{args.card_host}:{args.card_port}/.well-known/agent-card.json", file=sys.stderr)

    since = agent.state.get("cursor", 0)
    print(f"{APP_NAME}: listening on {agent.mailbox} from seq {since}", file=sys.stderr)
    try:
        while True:
            try:
                view = agent.read_room(agent.mailbox, since, wait=POLL_WAIT_SECONDS)
            except A2AError as exc:
                print(f"{APP_NAME}: poll error, retrying: {exc}", file=sys.stderr)
                time.sleep(2)
                continue
            for message in view.get("messages", []):
                since = message["seq"]
                try:
                    _handle_inbound(agent, message)
                except A2AError as exc:
                    # A network hiccup mid-handling (e.g. the reply write failed) - the
                    # caller times out and can retry; don't let one bad message wedge
                    # the poller on a seq it will only ever fail the same way on.
                    print(f"{APP_NAME}: error handling seq {since}: {exc}", file=sys.stderr)
                agent.state["cursor"] = since
                agent.save()
            if view.get("last_seq", since) != since:
                since = view["last_seq"]
                agent.state["cursor"] = since
                agent.save()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.shutdown()
    return 0


def _handle_inbound(agent: Agent, message: dict) -> None:
    frame = parse_rpc(message.get("text", ""))
    if frame is None or "method" not in frame:
        return  # not a request frame (e.g. a stray or malformed message) - ignore, don't crash the loop
    req_id = frame["id"]
    method = frame["method"]
    params = frame.get("params") or {}

    if method == "message/send":
        _handle_message_send(agent, message, req_id, params)
    elif method == "tasks/cancel":
        _handle_tasks_cancel(agent, message, req_id, params)
    else:
        _reply(agent, params.get("replyMailbox"), rpc_error(req_id, -32601, f"method not found: {method}"))


def _reply(agent: Agent, reply_mailbox: str | None, text: str) -> None:
    if not reply_mailbox:
        return
    try:
        agent.say_signed(reply_mailbox, text)
    except A2AError as exc:
        print(f"{APP_NAME}: could not deliver reply to {reply_mailbox}: {exc}", file=sys.stderr)


def _handle_message_send(agent: Agent, message: dict, req_id: str, params: dict) -> None:
    reply_mailbox = params.get("replyMailbox")
    caller_did = params.get("callerDid")
    if caller_did is not None and caller_did != message.get("from"):
        # The frame claims a different identity than the signature it actually arrived
        # under - never trust a self-reported DID over the one the server verified.
        _reply(agent, reply_mailbox, rpc_error(req_id, -32600, "callerDid does not match the signing key"))
        return

    text_parts = [p.get("text", "") for p in params.get("message", {}).get("parts", []) if p.get("kind") == "text"]
    input_text = " ".join(text_parts)
    skill = params.get("skill", "shout")

    task_id = secrets.token_hex(16)  # 32 lowercase hex chars: fits the key grammar directly
    ns, key = task_state_ns(task_id)
    agent.kv_set(ns, key, TASK_STATE_SUBMITTED, if_absent=True)
    _reply(
        agent,
        reply_mailbox,
        rpc_result(req_id, {"task": {"id": task_id, "contextId": agent.mailbox, "status": {"state": TASK_STATE_SUBMITTED}}}),
    )

    agent.kv_set(ns, key, TASK_STATE_WORKING, if_expected=TASK_STATE_SUBMITTED)
    ok, result = dispatch_skill(skill, input_text)
    artifact_ns, artifact_key = task_artifact_ns(task_id)
    agent.kv_set(artifact_ns, artifact_key, _dumps({"skill": skill, "input": input_text, "output": result, "ok": ok}))
    agent.kv_set(ns, key, TASK_STATE_COMPLETED if ok else TASK_STATE_FAILED, if_expected=TASK_STATE_WORKING)
    print(f"{APP_NAME}: task {task_id} ({skill!r}) -> {'completed' if ok else 'failed'}", file=sys.stderr)


def _handle_tasks_cancel(agent: Agent, message: dict, req_id: str, params: dict) -> None:
    reply_mailbox = params.get("replyMailbox")
    task_id = params.get("taskId", "")
    ns, key = task_state_ns(task_id)
    current = agent.kv_get(ns, key)
    if current is None:
        _reply(agent, reply_mailbox, rpc_error(req_id, -32001, f"no such task: {task_id}"))
        return
    if current in TERMINAL_STATES:
        _reply(agent, reply_mailbox, rpc_result(req_id, {"task": {"id": task_id, "status": {"state": current}}}))
        return
    agent.kv_set(ns, key, TASK_STATE_CANCELED, if_expected=current)
    _reply(agent, reply_mailbox, rpc_result(req_id, {"task": {"id": task_id, "status": {"state": TASK_STATE_CANCELED}}}))


# ------------------------------------------------------------------------------------- send


def cmd_send(agent: Agent, args: argparse.Namespace) -> int:
    # One overall deadline, threaded through every network call below - a caller who asked
    # for --timeout 60 gets a hard cap near 60s even if the service is having a bad patch,
    # rather than up to --timeout PER retrying call (six-plus times over, once per call).
    deadline = time.time() + args.timeout
    target_mailbox = args.to_mailbox or agent.resolve_peer(args.to_did)

    # interop.md: "Read the reply room's last_seq before writing a request - a fast
    # responder otherwise lands its answer at a seq your cursor skips past."
    cursor = agent.read_room_tail(agent.mailbox, deadline=deadline).get("last_seq", 0)

    req_id, frame = rpc_request(
        "message/send",
        {
            "message": {"messageId": secrets.token_hex(8), "role": "user", "parts": [{"kind": "text", "text": args.text}]},
            "skill": args.skill,
            "replyMailbox": agent.mailbox,
            "callerDid": agent.did,
        },
    )
    agent.say_signed(target_mailbox, frame, deadline=deadline)
    print(f"{APP_NAME}: sent {req_id} to {target_mailbox}", file=sys.stderr)

    response = _await_response(agent, cursor, req_id, deadline)
    if "error" in response:
        raise A2AError(f"peer refused: {response['error']}")
    task_id = response["result"]["task"]["id"]
    print(f"{APP_NAME}: task {task_id} submitted, polling for completion", file=sys.stderr)

    while time.time() < deadline:
        ns, key = task_state_ns(task_id)
        state = agent.kv_get(ns, key, deadline=deadline)
        if state in TERMINAL_STATES:
            _print_result(agent, task_id, state)
            return 0 if state == TASK_STATE_COMPLETED else 1
        time.sleep(1)
    raise A2AError(f"task {task_id} did not reach a terminal state within {args.timeout}s")


def cmd_cancel(agent: Agent, args: argparse.Namespace) -> int:
    deadline = time.time() + args.timeout
    target_mailbox = args.to_mailbox or agent.resolve_peer(args.to_did)
    cursor = agent.read_room_tail(agent.mailbox, deadline=deadline).get("last_seq", 0)
    req_id, frame = rpc_request(
        "tasks/cancel", {"taskId": args.task_id, "replyMailbox": agent.mailbox, "callerDid": agent.did}
    )
    agent.say_signed(target_mailbox, frame, deadline=deadline)
    response = _await_response(agent, cursor, req_id, deadline)
    print(_dumps(response))
    return 0 if "result" in response else 1


def cmd_status(agent: Agent, args: argparse.Namespace) -> int:
    ns, key = task_state_ns(args.task_id)
    state = agent.kv_get(ns, key)
    if state is None:
        print(f"no such task: {args.task_id}", file=sys.stderr)
        return 1
    print(f"state: {state}")
    if state in TERMINAL_STATES:
        artifact_ns, artifact_key = task_artifact_ns(args.task_id)
        artifact = agent.kv_get(artifact_ns, artifact_key)
        if artifact:
            print(f"artifact: {artifact}")
    return 0


def _await_response(agent: Agent, cursor: int, req_id: str, deadline: float) -> dict:
    since = cursor
    while time.time() < deadline:
        remaining = max(1, min(POLL_WAIT_SECONDS, int(deadline - time.time())))
        view = agent.read_room(agent.mailbox, since, wait=remaining, deadline=deadline)
        for message in view.get("messages", []):
            since = message["seq"]
            frame = parse_rpc(message.get("text", ""))
            if frame is not None and frame.get("id") == req_id and ("result" in frame or "error" in frame):
                return frame
        since = max(since, view.get("last_seq", since))
    raise A2AError(f"no response to {req_id}")


def _print_result(agent: Agent, task_id: str, state: str) -> None:
    artifact_ns, artifact_key = task_artifact_ns(task_id)
    artifact = agent.kv_get(artifact_ns, artifact_key)
    print(f"{APP_NAME}: task {task_id} -> {state}")
    if artifact:
        print(artifact)


def cmd_identity(agent: Agent, args: argparse.Namespace) -> int:
    print(f"did: {agent.did}")
    print(f"mailbox: {agent.mailbox}")
    return 0


def cmd_publish(agent: Agent, args: argparse.Namespace) -> int:
    agent.publish_did_note()
    shard, key = did_fingerprint(agent.did)
    print(f"published: /kv/did-{shard}/{key} -> {agent.did} mailbox:{agent.mailbox}")
    return 0


# --------------------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=__doc__.strip().splitlines()[0])
    parser.add_argument("--home", type=Path, default=DEFAULT_HOME, help=f"identity + state directory (default: {DEFAULT_HOME})")
    parser.add_argument("--base", default=TECHNOCORE_BASE, help="technocore.chat base URL")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("identity", help="show this agent's DID and mailbox")
    p.set_defaults(func=cmd_identity)

    p = sub.add_parser("publish", help="publish the DID note (src/patterns.md #3) - an outward, world-readable write")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser("serve", help="run as an agent offering skills; long-polls its own mailbox")
    p.add_argument("--name", default="technocore-a2a demo agent")
    p.add_argument("--description", default="Demo A2A agent bridged over a technocore.chat mailbox.")
    p.add_argument("--serve-card", action="store_true", help="also host the agent card over local HTTP")
    p.add_argument("--card-host", default="0.0.0.0")
    p.add_argument("--card-port", type=int, default=DEFAULT_CARD_PORT)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("send", help="delegate a task to a peer and wait for the result")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--to-mailbox", help="peer's mailbox room, if you already have it (e.g. from their agent card)")
    target.add_argument("--to-did", help="peer's DID - looked up via their published DID note")
    p.add_argument("--text", required=True, help="the task input")
    p.add_argument("--skill", default="shout")
    p.add_argument("--timeout", type=float, default=45.0)
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("cancel", help="request cancellation of a task you delegated")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--to-mailbox")
    target.add_argument("--to-did")
    p.add_argument("--task-id", required=True)
    p.add_argument("--timeout", type=float, default=30.0)
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("status", help="read a task's current state directly - no signing, no mailbox round trip")
    p.add_argument("task_id")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    agent = Agent(args.home, args.base)
    try:
        return args.func(agent, args)
    except A2AError as exc:
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
