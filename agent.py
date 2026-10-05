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

What is and isn't A2A here, precisely:

- Task lifecycle, states, PascalCase JSON-RPC methods, ProtoJSON roles/parts, errors,
  and AgentCard fields follow A2A v1.0. `TASK_STATE_*` matches interop.md's example
  exactly (`TASK_STATE_WORKING?if=TASK_STATE_SUBMITTED`).
- The AgentCard advertises an A2A custom binding in `supportedInterfaces`, whose URL is
  the mailbox room and whose binding URI identifies this profile. It does not pretend
  that the room is A2A's HTTP, gRPC, or JSON-RPC-over-HTTP binding. interop.md is
  explicit that technocore.chat's own `/.well-known/agent.json` is unrelated and never
  a place to mount an A2A card.
- Message delivery replaces HTTP POST with the JSON-RPC-over-a-room binding from
  interop.md's own JSON-RPC section: one compact, ASCII-escaped frame per room message,
  requests to the callee's mailbox, responses to a deterministic one-time room derived
  from both DIDs and the request id. `tasks/get` is
  deliberately NOT sent as a JSON-RPC round trip - the task state is already a
  world-readable, signer-verifiable note, and sending a signed frame to ask for
  something anyone can read and verify would add no security.

Dependency: only "cryptography" (same as technocore-companion, this ecosystem's other
did:key tool) - the rest is standard library, matching technocore-websub's own choice to
keep this kind of bridge auditable and dependency-light.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import random
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

APP_NAME = "technocore-a2a"
APP_VERSION = "0.3.0"
A2A_PROTOCOL_VERSION = "1.0"
A2A_BINDING_URI = "https://github.com/brkcinar/technocore-a2a#technocore-room-v1"

TECHNOCORE_BASE = "https://technocore.chat"
DEFAULT_HOME = Path.home() / ".technocore-a2a"
MULTICODEC_ED25519 = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MESSAGE_MAX_CHARS = 4096
NOTE_MAX_CHARS = 8192
POLL_WAIT_SECONDS = 10
DEFAULT_CARD_PORT = 8735
REQUEST_LEDGER_MAX = 1024
ACTIVE_TASK_MAX = 64

SEND_MESSAGE_METHOD = "SendMessage"
CANCEL_TASK_METHOD = "CancelTask"

MAILBOX_RE = re.compile(r"^mb-p-[a-z0-9][a-z0-9_-]{0,42}$")
TASK_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DID_KEY_RE = re.compile(r"^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$")

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


class CapacityError(A2AError):
    """A frame or note would exceed the service's size cap - retrying the same bytes can't help."""


def _backoff(attempt: int, cap: float = 5.0) -> float:
    """Exponential backoff for a transient (5xx / network) failure, capped so a sustained
    bad patch on the live service still gets several tries within a bounded total wait."""
    base = min(0.5 * (2**attempt), cap)
    return random.uniform(0.75 * base, 1.25 * base)


# ----------------------------------------------------------------------- did:key identity


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def base58btc_decode(text: str) -> bytes:
    number = 0
    for char in text:
        try:
            value = BASE58BTC_ALPHABET.index(char)
        except ValueError as exc:
            raise A2AError("invalid base58btc value") from exc
        number = number * 58 + value
    decoded = (
        number.to_bytes((number.bit_length() + 7) // 8, "big")
        if number
        else b""
    )
    return (b"\x00" * (len(text) - len(text.lstrip("1")))) + decoded


def did_from_private_key(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519 + public_bytes)


def sign_message(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not valid_did_key(did):
        raise A2AError("expected an Ed25519 did:key")
    decoded = base58btc_decode(did.removeprefix("did:key:z"))
    if not decoded.startswith(MULTICODEC_ED25519) or len(decoded) != 34:
        raise A2AError("did:key is not an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def did_fingerprint(did: str) -> tuple[str, str]:
    """(shard, key) for the public DID directory - src/patterns.md #3: first 16 hex chars
    of SHA-256(did), split 2/14 so the directory stays spread across bounded namespaces."""
    digest = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return digest[:2], digest[2:]


def load_or_create_identity(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            stat = os.fstat(fd)
            if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                raise A2AError(
                    f"refusing permissive or foreign-owned identity file: {path}"
                )
            with os.fdopen(fd, "rb", closefd=False) as handle:
                pem = handle.read()
        finally:
            os.close(fd)
        return serialization.load_pem_private_key(pem, password=None)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return load_or_create_identity(path)
    try:
        os.write(fd, pem)
        os.fsync(fd)
    finally:
        os.close(fd)
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
        stat = state_path.stat()
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise A2AError(f"refusing permissive or foreign-owned state file: {state_path}")
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise A2AError(f"could not safely load state from {state_path}: {exc}") from exc
    if not isinstance(state, dict):
        raise A2AError(f"state file must contain a JSON object: {state_path}")
    return state


def save_state(home: Path, state: dict) -> None:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=".state-", dir=home)
    tmp = Path(tmp_name)
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8")
    except Exception:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    try:
        with handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(home / "state.json")
    finally:
        tmp.unlink(missing_ok=True)
    directory = os.open(home, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def acquire_serve_lock(home: Path) -> int:
    lock_path = home / "serve.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise A2AError(
                f"refusing permissive or foreign-owned serve lock: {lock_path}"
            )
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise A2AError(f"another serve process already uses {home}") from exc
    except Exception:
        os.close(fd)
        raise
    return fd


def acquire_state_lock(home: Path) -> int:
    lock_path = home / "state.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise A2AError(
                f"refusing permissive or foreign-owned state lock: {lock_path}"
            )
        fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception:
        os.close(fd)
        raise
    return fd


def _merge_revision_map(current: object, incoming: object) -> dict:
    merged = dict(current) if isinstance(current, dict) else {}
    if not isinstance(incoming, dict):
        return merged
    for key, value in incoming.items():
        existing = merged.get(key)
        if not isinstance(existing, dict) or not isinstance(value, dict):
            merged.setdefault(key, value)
            continue
        old_revision = existing.get("revision", -1)
        new_revision = value.get("revision", -1)
        if isinstance(new_revision, int) and (
            not isinstance(old_revision, int) or new_revision > old_revision
        ):
            merged[key] = value
        elif new_revision == old_revision:
            merged[key] = {**value, **existing}
    return merged


def _merge_state(current: dict, incoming: dict) -> dict:
    merged = {**current, **incoming}
    current_generation = current.get("serverGeneration", 0)
    incoming_generation = incoming.get("serverGeneration", 0)
    if not isinstance(current_generation, int):
        current_generation = 0
    if not isinstance(incoming_generation, int):
        incoming_generation = 0
    server_state = (
        incoming
        if incoming_generation > current_generation
        else current
    )
    for field in ("serverGeneration", "requests", "tasks", "cursor"):
        if field in server_state:
            merged[field] = server_state[field]
    merged["peerTaskStates"] = _merge_revision_map(
        current.get("peerTaskStates"),
        incoming.get("peerTaskStates"),
    )
    return merged


def merge_and_save_state(home: Path, state: dict) -> dict:
    fd = acquire_state_lock(home)
    try:
        merged = _merge_state(load_state(home), state)
        save_state(home, merged)
        return merged
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


UNTRUSTED_BANNER_PREFIX = "!! UNTRUSTED CONTENT"


def _strip_untrusted_banner(body: str) -> str:
    """A plain (non-`?format=json`) `/kv/<ns>/<key>` read always prepends a one-line
    warning plus a blank line before the actual note value - unlike `/r/<room>`, where
    `?format=json` gives clean JSON with no banner, `?format=json` on `/kv` makes no
    difference (confirmed against the live service; undocumented in /llms.txt). Since
    note values are single-line by the service's own invariant, splitting on the first
    blank line is safe and exact."""
    if body.startswith(UNTRUSTED_BANNER_PREFIX):
        _, _, rest = body.partition("\n\n")
        return rest.rstrip("\n")
    return body.rstrip("\n")


class Agent:
    """One identity + mailbox, loaded from --home. Both `serve` and `send` are just
    different things done with one of these - an A2A peer is symmetric until it decides
    to offer a skill or place a call."""

    def __init__(self, home: Path, base: str):
        self.home = home
        self.base = base.rstrip("/")
        if home.exists():
            stat = home.stat()
            if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
                raise A2AError(
                    f"refusing permissive or foreign-owned identity home: {home}"
                )
        else:
            home.mkdir(parents=True, mode=0o700)
        bootstrap_fd = acquire_state_lock(home)
        try:
            self.key = load_or_create_identity(home / "identity.pem")
            self.did = did_from_private_key(self.key)
            state = load_state(home)
            if "mailbox" not in state:
                state["mailbox"] = new_mailbox_name()
                save_state(home, state)
        finally:
            fcntl.flock(bootstrap_fd, fcntl.LOCK_UN)
            os.close(bootstrap_fd)
        self.mailbox = state["mailbox"]
        self.state = state
        self.state_save_lock = threading.RLock()
        self.task_cancel_events: dict[str, threading.Event] = {}
        self.task_threads: dict[str, threading.Thread] = {}
        self.task_waiters: dict[str, list[tuple[str, str | int]]] = {}
        self.task_runtime_lock = threading.Lock()

    def save(self) -> None:
        with self.state_save_lock:
            self.state = merge_and_save_state(self.home, self.state)

    def save_server_state(self) -> None:
        with self.state_save_lock:
            generation = self.state.get("serverGeneration", 0)
            self.state["serverGeneration"] = (
                generation + 1 if isinstance(generation, int) else 1
            )
            self.state = merge_and_save_state(self.home, self.state)

    # --------------------------------------------------------------- technocore.chat client

    def _url(self, path: str, params: dict | None = None) -> str:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def _get(
        self,
        path: str,
        params: dict | None = None,
        timeout: float = 15,
        retries: int = 5,
        deadline: float | None = None,
        passthrough_statuses: tuple[int, ...] = (),
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
                if exc.code == 404 or exc.code in passthrough_statuses:
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
            f"/r/{room}",
            {"since": since, "wait": wait, "limit": 200, "format": "json"},
            timeout=wait + 5,
            deadline=deadline,
        )
        view = json.loads(body.decode("utf-8"))
        messages = view.get("messages", [])
        last_seq = view.get("last_seq", since)
        reset = isinstance(last_seq, int) and last_seq < since
        gap = messages and messages[0].get("seq", since + 1) > since + 1
        omitted = not messages and isinstance(last_seq, int) and last_seq > since
        if reset or gap or omitted:
            reason = "room epoch reset" if reset else "unread sequence gap"
            raise A2AError(
                f"room {room} has a {reason} after cursor {since}; "
                "stop serve and run recover-cursor --skip-lost to acknowledge "
                "the cursor change"
            )
        return view

    def read_room_tail(self, room: str, deadline: float | None = None) -> dict:
        """A cursor-free read - interop.md's way to detect a reaped/recreated room."""
        return json.loads(
            self._get(
                f"/r/{room}",
                {"limit": 200, "format": "json"},
                deadline=deadline,
            ).decode("utf-8")
        )

    def say_signed(self, room: str, text: str, deadline: float | None = None) -> int:
        if len(text) > MESSAGE_MAX_CHARS:
            raise CapacityError(f"frame is {len(text)} chars, over the {MESSAGE_MAX_CHARS}-char message cap")
        retries = 5
        attempt = 0
        while True:
            # Every transport retry uses a fresh signed envelope but preserves ``text``.
            # For JSON-RPC requests, that means the request id remains the idempotency key.
            nonce = str(time.time_ns())
            payload = f"{room}|{nonce}|{text}".encode("utf-8")
            signature = sign_message(self.key, payload)
            body = json.dumps(
                {"did": self.did, "sig": signature, "nonce": nonce, "text": text}
            ).encode("utf-8")
            request = urllib.request.Request(
                self._url(f"/r/{room}?format=json"),
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": UA},
                method="POST",
            )
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
                    detail = exc.read().decode("utf-8", "replace")
                    raise A2AError(
                        f"signed write to {room} -> {exc.code} {detail}"
                    ) from exc
                error = A2AError(f"signed write to {room} -> {exc.code} {exc.read().decode('utf-8', 'replace')}")
                error.__cause__ = exc
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                error = A2AError(f"signed write to {room} failed: {exc}")
                error.__cause__ = exc

            # A timeout or 5xx is ambiguous: the write may have landed while only the
            # response was lost. Verify before retrying. If this read also fails, retrying
            # the same JSON-RPC frame is safe because the receiver binds its request id to
            # one task before dispatching work.
            try:
                view = self.read_room_tail(room, deadline=deadline)
                for message in view.get("messages", []):
                    if message.get("from") == self.did and message.get("text") == text:
                        return message["seq"]
            except (A2AError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
                pass

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
            body = self._get(f"/kv/{ns}/{key}", deadline=deadline).decode("utf-8")
        except urllib.error.HTTPError:
            return None
        return _strip_untrusted_banner(body)

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
            raise CapacityError(f"note is {len(value)} chars, over the {NOTE_MAX_CHARS}-char note cap")
        params = {}
        if if_expected is not None:
            params["if"] = if_expected
        if if_absent:
            params["if_absent"] = "1"
        path = f"/kv/{ns}/{key}/set/{urllib.parse.quote(value, safe='')}"
        try:
            self._get(
                path,
                params,
                deadline=deadline,
                passthrough_statuses=(409,),
            )
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
                mailbox = token[len("mailbox:"):]
                if not valid_mailbox(mailbox):
                    raise A2AError(f"DID note for {did} contains an unsafe mailbox: field")
                return mailbox
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


def valid_mailbox(value: object) -> bool:
    """Only private, signed-only mailboxes are valid bridge destinations."""
    return isinstance(value, str) and MAILBOX_RE.fullmatch(value) is not None


def reply_mailbox_for(
    caller_did: str,
    agent_did: str,
    req_id: str | int,
) -> str:
    canonical = _dumps(
        {
            "callerDid": caller_did,
            "agentDid": agent_did,
            "requestId": req_id,
        }
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"mb-p-a2a-{digest[:32]}"


def valid_did_key(value: object) -> bool:
    return isinstance(value, str) and DID_KEY_RE.fullmatch(value) is not None


def valid_task_id(value: object) -> bool:
    return isinstance(value, str) and TASK_ID_RE.fullmatch(value) is not None


# -------------------------------------------------------------------------------- JSON-RPC
#
# interop.md's JSON-RPC section, verbatim: "One frame per message, compact. Serialise with
# separators=(',', ':') and ensure_ascii=True - the latter escapes every non-ASCII
# character, so nothing in the payload can be altered by the single-line sweep, which also
# keeps the frame verifiable against its signature."


def _dumps(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def rpc_request(
    method: str,
    params: dict,
    req_id: str | int | None = None,
) -> tuple[str | int, str]:
    if req_id is None:
        req_id = secrets.token_hex(4)
    return req_id, _dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})


def rpc_result(req_id: str | int, result: dict) -> str:
    return _dumps({"jsonrpc": "2.0", "id": req_id, "result": result})


def rpc_error(
    req_id: str | int,
    code: int,
    message: str,
    *,
    reason: str | None = None,
    metadata: dict[str, str] | None = None,
    field: str | None = None,
) -> str:
    error: dict = {"code": code, "message": message}
    if reason is not None:
        error["data"] = [
            {
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": reason,
                "domain": "a2a-protocol.org",
                "metadata": metadata or {},
            }
        ]
    elif field is not None:
        error["data"] = [
            {
                "@type": "type.googleapis.com/google.rpc.BadRequest",
                "fieldViolations": [{"field": field, "description": message}],
            }
        ]
    return _dumps({"jsonrpc": "2.0", "id": req_id, "error": error})


def parse_rpc(text: str) -> dict | None:
    try:
        frame = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(frame, dict) or frame.get("jsonrpc") != "2.0" or "id" not in frame:
        return None
    if isinstance(frame["id"], bool) or not isinstance(frame["id"], (str, int)):
        return None
    return frame


def _signed_record(agent: Agent, payload: dict) -> str:
    signature = sign_message(agent.key, _dumps(payload).encode("utf-8"))
    return _dumps({**payload, "signature": signature})


def _record_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _verify_record(
    raw: str,
    *,
    kind: str,
    task_id: str,
    expected_agent_did: str,
    expected_owner_did: str,
) -> dict:
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise A2AError(f"{kind} record for {task_id} is not valid JSON") from exc
    if not isinstance(record, dict):
        raise A2AError(f"{kind} record for {task_id} is not an object")
    # PROFILE.md section 3, raw form rule: the stored bytes must already be canonical. Hashes
    # chain over raw bytes while signatures cover the re-serialization, so a whitespace
    # variant or a duplicate member (which parsers resolve differently) must not verify.
    if _dumps(record) != raw:
        raise A2AError(f"{kind} record for {task_id} is not in canonical form")
    signature = record.pop("signature", None)
    if not isinstance(signature, str):
        raise A2AError(f"{kind} record for {task_id} has no signature")
    expected = {
        "kind": kind,
        "taskId": task_id,
        "ownerDid": expected_owner_did,
        "agentDid": expected_agent_did,
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise A2AError(
                f"{kind} record for {task_id} has unexpected {field}"
            )
    if kind == "task-state":
        if not isinstance(record.get("revision"), int) or record["revision"] < 0:
            raise A2AError(f"{kind} record for {task_id} has an invalid revision")
        if not isinstance(record.get("previousHash"), str):
            raise A2AError(f"{kind} record for {task_id} has an invalid previousHash")
        if record["revision"] == 0:
            if record["previousHash"] != "" or record.get("previousRecord") is not None:
                raise A2AError(f"{kind} record for {task_id} has an invalid genesis")
        elif (
            not re.fullmatch(r"[0-9a-f]{64}", record["previousHash"])
            or not isinstance(record.get("previousRecord"), dict)
        ):
            raise A2AError(f"{kind} record for {task_id} has an invalid predecessor")
    elif kind == "task-artifact" and not isinstance(
        record.get("workingStateHash"),
        str,
    ):
        raise A2AError(f"{kind} record for {task_id} has no workingStateHash")
    try:
        signature_bytes = base64.urlsafe_b64decode(
            signature + ("=" * (-len(signature) % 4))
        )
        public_key_from_did(expected_agent_did).verify(
            signature_bytes,
            _dumps(record).encode("utf-8"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise A2AError(f"{kind} record for {task_id} has an invalid signature") from exc
    record["_raw"] = raw
    return record


def _task_state_lock(agent: Agent) -> threading.RLock:
    if not hasattr(agent, "task_state_lock"):
        agent.task_state_lock = threading.RLock()
    return agent.task_state_lock


def task_state_get(
    agent: Agent,
    task_id: str,
    *,
    expected_agent_did: str,
    expected_owner_did: str,
    deadline: float | None = None,
) -> dict | None:
    with _task_state_lock(agent):
        namespace, key = task_state_ns(task_id)
        raw = agent.kv_get(namespace, key, deadline=deadline)
        if raw is None:
            return None
        record = _verify_record(
            raw,
            kind="task-state",
            task_id=task_id,
            expected_agent_did=expected_agent_did,
            expected_owner_did=expected_owner_did,
        )
        ownership = agent.state.get("tasks", {}).get(task_id)
        if expected_agent_did == agent.did and isinstance(ownership, dict):
            checkpoint = ownership.get("stateHash")
            if checkpoint is not None and checkpoint != _record_hash(raw):
                raise A2AError(
                    f"task-state record for {task_id} does not match the private checkpoint"
                )
        return record


def _checkpoint_task_state(agent: Agent, record: dict) -> None:
    ownership = agent.state.get("tasks", {}).get(record["taskId"])
    if not isinstance(ownership, dict):
        raise A2AError(f"no durable owner record for task {record['taskId']}")
    ownership["stateHash"] = _record_hash(record["_raw"])
    ownership["revision"] = record["revision"]
    ownership["state"] = record["state"]
    _prune_server_state(agent)
    agent.save_server_state()


def task_state_set(
    agent: Agent,
    task_id: str,
    owner_did: str,
    state: str,
    *,
    previous: dict | None = None,
    if_absent: bool = False,
    artifact_hash: str | None = None,
) -> tuple[bool, dict]:
    with _task_state_lock(agent):
        ownership = agent.state.get("tasks", {}).get(task_id)
        if not isinstance(ownership, dict):
            raise A2AError(f"no durable owner record for task {task_id}")
        checkpoint = ownership.get("stateHash")
        if previous is None:
            if checkpoint is not None:
                raise A2AError(f"task {task_id} already has a private state checkpoint")
        elif checkpoint != _record_hash(previous["_raw"]):
            raise A2AError(
                f"task {task_id} transition does not advance the private checkpoint"
            )
        revision = 0 if previous is None else previous["revision"] + 1
        payload = {
            "kind": "task-state",
            "taskId": task_id,
            "ownerDid": owner_did,
            "agentDid": agent.did,
            "state": state,
            "revision": revision,
            "previousHash": (
                "" if previous is None else _record_hash(previous["_raw"])
            ),
            "previousRecord": (
                None if previous is None else json.loads(previous["_raw"])
            ),
        }
        if artifact_hash is not None:
            payload["artifactHash"] = artifact_hash
        raw = _signed_record(agent, payload)
        namespace, key = task_state_ns(task_id)
        written = agent.kv_set(
            namespace,
            key,
            raw,
            if_expected=previous["_raw"] if previous is not None else None,
            if_absent=if_absent,
        )
        record = {**payload, "_raw": raw}
        if written:
            _checkpoint_task_state(agent, record)
        return written, record


def task_artifact_get(
    agent: Agent,
    task_id: str,
    *,
    expected_agent_did: str,
    expected_owner_did: str,
    deadline: float | None = None,
) -> dict | None:
    namespace, key = task_artifact_ns(task_id)
    raw = agent.kv_get(namespace, key, deadline=deadline)
    if raw is None:
        return None
    return _verify_record(
        raw,
        kind="task-artifact",
        task_id=task_id,
        expected_agent_did=expected_agent_did,
        expected_owner_did=expected_owner_did,
    )


def task_artifact_set(
    agent: Agent,
    task_id: str,
    owner_did: str,
    artifact: dict,
    working_state: dict,
) -> dict:
    payload = {
        "kind": "task-artifact",
        "taskId": task_id,
        "ownerDid": owner_did,
        "agentDid": agent.did,
        "artifact": artifact,
        "workingStateHash": _record_hash(working_state["_raw"]),
    }
    namespace, key = task_artifact_ns(task_id)
    raw = _signed_record(agent, payload)
    if len(raw) > NOTE_MAX_CHARS:
        raise CapacityError(
            f"artifact for {task_id} is {len(raw)} chars, over the {NOTE_MAX_CHARS}-char note cap"
        )
    agent.kv_set(namespace, key, raw)
    return {**payload, "_raw": raw}


# ------------------------------------------------------------------------------ agent card
#
# interop.md, read-this-before-anything-else: "This service serves /.well-known/agent.json,
# and it is not a card ... Publish your card on your own origin; never mount one here." This
# writes the card to a local file on THIS tool's own home, never to technocore.chat.


def build_agent_card(agent: Agent, name: str, description: str) -> dict:
    return {
        "name": name,
        "description": description,
        "supportedInterfaces": [
            {
                "url": f"{agent.base}/r/{agent.mailbox}",
                "protocolBinding": A2A_BINDING_URI,
                "protocolVersion": A2A_PROTOCOL_VERSION,
            }
        ],
        "version": APP_VERSION,
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


def dispatch_skill(
    skill: str,
    text: str,
    cancel_event: threading.Event | None = None,
) -> tuple[bool, str]:
    """(ok, result_or_error). The one place a real deployment would plug in actual work -
    everything above this line is the delegation mechanism, not the task."""
    if cancel_event is not None and cancel_event.is_set():
        return False, "task canceled"
    if skill == "shout":
        return True, text.upper() + "!!!"
    return False, f"unknown skill {skill!r} - this agent only offers 'shout'"


# ------------------------------------------------------------------------------------ serve


def cmd_serve(agent: Agent, args: argparse.Namespace) -> int:
    lock_fd = acquire_serve_lock(agent.home)
    card = build_agent_card(agent, args.name, args.description)
    card_path = agent.home / "agent-card.json"
    card_path.write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(f"{APP_NAME}: did={agent.did}", file=sys.stderr)
    print(f"{APP_NAME}: mailbox={agent.mailbox}", file=sys.stderr)
    print(f"{APP_NAME}: card written to {card_path}", file=sys.stderr)

    server = None
    if args.serve_card:
        server = serve_card(card, args.card_host, args.card_port)
        print(
            f"{APP_NAME}: card served on "
            f"http://{args.card_host}:{args.card_port}/.well-known/agent-card.json",
            file=sys.stderr,
        )

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
                agent.save_server_state()
            if view.get("last_seq", since) != since:
                since = view["last_seq"]
                agent.state["cursor"] = since
                agent.save_server_state()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.shutdown()
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return 0


def _transport_metadata(params: dict) -> dict:
    metadata = params.get("metadata")
    if isinstance(metadata, dict):
        transport = metadata.get("technocoreTransport")
        if isinstance(transport, dict):
            return transport
    # Accept the original bridge's top-level extension fields on inbound frames,
    # but all newly emitted requests use A2A v1's metadata field.
    return params


def _safe_reply_mailbox(params: dict) -> str | None:
    value = _transport_metadata(params).get("replyMailbox")
    return value if valid_mailbox(value) else None


def _verified_caller(message: dict, params: dict) -> tuple[str | None, str | None]:
    signed_did = message.get("from")
    if not valid_did_key(signed_did):
        return None, "request was not attributed to a verified did:key signer"
    claimed_did = _transport_metadata(params).get("callerDid")
    if claimed_did is not None and claimed_did != signed_did:
        return None, "callerDid does not match the signing key"
    return signed_did, None


def _authorized_reply_mailbox(
    agent: Agent,
    caller_did: str,
    req_id: str | int,
    params: dict,
) -> str | None:
    candidate = _safe_reply_mailbox(params)
    expected = reply_mailbox_for(caller_did, agent.did, req_id)
    return candidate if candidate == expected else None


def _request_key(caller_did: str, req_id: str | int) -> str:
    canonical = _dumps({"callerDid": caller_did, "requestId": req_id})
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _prune_server_state(agent: Agent) -> None:
    requests = agent.state.setdefault("requests", {})
    tasks = agent.state.setdefault("tasks", {})
    retained_task_ids = {
        entry.get("taskId")
        for entry in requests.values()
        if isinstance(entry, dict)
    }
    for task_id, ownership in list(tasks.items()):
        if (
            task_id not in retained_task_ids
            and isinstance(ownership, dict)
            and ownership.get("state") in TERMINAL_STATES
        ):
            tasks.pop(task_id, None)


def _remember_request(
    agent: Agent,
    caller_did: str,
    req_id: str | int,
    request_hash: str,
) -> tuple[str, bool]:
    """Persist the request-to-task binding before dispatching any skill.

    The signing DID is part of the key, so two callers may use the same JSON-RPC
    id without colliding. Replays from one caller always recover the same task.
    """
    request_key = _request_key(caller_did, req_id)
    requests = agent.state.setdefault("requests", {})
    existing = requests.get(request_key)
    if isinstance(existing, dict) and valid_task_id(existing.get("taskId")):
        if existing.get("requestHash") != request_hash:
            raise A2AError("JSON-RPC id was reused with different request parameters")
        return existing["taskId"], False

    active_tasks = sum(
        1
        for ownership in agent.state.setdefault("tasks", {}).values()
        if not isinstance(ownership, dict)
        or ownership.get("state") not in TERMINAL_STATES
    )
    if active_tasks >= ACTIVE_TASK_MAX:
        raise A2AError("agent is at its active task limit")

    task_id = secrets.token_hex(16)
    requests[request_key] = {
        "taskId": task_id,
        "callerDid": caller_did,
        "requestId": req_id,
        "requestHash": request_hash,
    }
    tasks = agent.state.setdefault("tasks", {})
    tasks[task_id] = {"callerDid": caller_did, "requestKey": request_key}

    while len(requests) > REQUEST_LEDGER_MAX:
        requests.pop(next(iter(requests)))
    _prune_server_state(agent)
    agent.save_server_state()
    return task_id, True


def _task_result(agent: Agent, state_record: dict) -> dict:
    task_id = state_record["taskId"]
    state = state_record["state"]
    owner_did = state_record["ownerDid"]
    task = {
        "id": task_id,
        "contextId": agent.mailbox,
        "status": {"state": state},
        "metadata": {
            "technocoreTransport": {
                "stateRecord": json.loads(state_record["_raw"]),
            }
        },
    }
    if state in (TASK_STATE_COMPLETED, TASK_STATE_FAILED):
        artifact_record = task_artifact_get(
            agent,
            task_id,
            expected_agent_did=agent.did,
            expected_owner_did=owner_did,
        )
        if artifact_record is None:
            raise A2AError(f"terminal task {task_id} has no signed artifact")
        if state_record.get("artifactHash") != _record_hash(artifact_record["_raw"]):
            raise A2AError(f"terminal task {task_id} does not bind its artifact")
        if artifact_record["workingStateHash"] != state_record["previousHash"]:
            raise A2AError(f"artifact for {task_id} belongs to another execution")
        task["artifacts"] = [
            {
                "artifactId": f"{task_id}-result",
                "name": "result",
                "parts": [
                    {
                        "data": artifact_record["artifact"],
                        "mediaType": "application/json",
                    }
                ],
            }
        ]
    return {"task": task}


def _task_runtime(agent: Agent) -> tuple[dict, dict, threading.Lock]:
    if not hasattr(agent, "task_cancel_events"):
        agent.task_cancel_events = {}
        agent.task_threads = {}
        agent.task_waiters = {}
        agent.task_runtime_lock = threading.Lock()
    return agent.task_cancel_events, agent.task_threads, agent.task_runtime_lock


def _add_task_waiter(
    agent: Agent,
    task_id: str,
    reply_mailbox: str,
    req_id: str | int,
) -> None:
    _, _, lock = _task_runtime(agent)
    with lock:
        agent.task_waiters.setdefault(task_id, []).append(
            (reply_mailbox, req_id)
        )


def _notify_task_waiters(agent: Agent, state_record: dict) -> None:
    _, _, lock = _task_runtime(agent)
    with lock:
        waiters = agent.task_waiters.pop(state_record["taskId"], [])
    result = _task_result(agent, state_record)
    for reply_mailbox, req_id in waiters:
        _reply(agent, reply_mailbox, rpc_result(req_id, result))


def _execute_task(
    agent: Agent,
    task_id: str,
    owner_did: str,
    skill: str,
    input_text: str,
    cancel_event: threading.Event,
) -> None:
    try:
        try:
            ok, result = dispatch_skill(skill, input_text, cancel_event)
        except Exception as exc:  # a real deployment may replace the demo dispatcher
            ok, result = False, f"skill execution failed: {type(exc).__name__}"

        if cancel_event.is_set():
            return

        current = task_state_get(
            agent,
            task_id,
            expected_agent_did=agent.did,
            expected_owner_did=owner_did,
        )
        if current is None or current["state"] != TASK_STATE_WORKING:
            if current is not None:
                _notify_task_waiters(agent, current)
            return
        if cancel_event.is_set():
            return
        artifact = {
            "skill": skill,
            "input": input_text,
            "output": result,
            "ok": ok,
        }
        try:
            artifact_record = task_artifact_set(
                agent,
                task_id,
                owner_did,
                artifact,
                current,
            )
        except CapacityError:
            # PROFILE.md section 9.3: an output that cannot be stored must still end the task,
            # not leave it WORKING forever. Report it as a typed failure instead.
            ok = False
            artifact = {
                "skill": skill,
                "ok": False,
                "error": "skill output exceeds the note size cap",
                "reason": "ARTIFACT_TOO_LARGE",
                "limit": NOTE_MAX_CHARS,
            }
            artifact_record = task_artifact_set(
                agent,
                task_id,
                owner_did,
                artifact,
                current,
            )
        if cancel_event.is_set():
            return
        terminal = TASK_STATE_COMPLETED if ok else TASK_STATE_FAILED
        written, terminal_record = task_state_set(
            agent,
            task_id,
            owner_did,
            terminal,
            previous=current,
            artifact_hash=_record_hash(artifact_record["_raw"]),
        )
        if not written:
            terminal_record = task_state_get(
                agent,
                task_id,
                expected_agent_did=agent.did,
                expected_owner_did=owner_did,
            )
        if terminal_record is not None:
            _notify_task_waiters(agent, terminal_record)
        print(
            f"{APP_NAME}: task {task_id} ({skill!r}) -> "
            f"{'completed' if ok else 'failed'}",
            file=sys.stderr,
        )
    except A2AError as exc:
        print(f"{APP_NAME}: task {task_id} failed safely: {exc}", file=sys.stderr)
    finally:
        cancel_events, threads, lock = _task_runtime(agent)
        with lock:
            cancel_events.pop(task_id, None)
            threads.pop(task_id, None)


def _start_task(
    agent: Agent,
    task_id: str,
    owner_did: str,
    skill: str,
    input_text: str,
) -> None:
    cancel_events, threads, lock = _task_runtime(agent)
    cancel_event = threading.Event()
    thread = threading.Thread(
        target=_execute_task,
        args=(
            agent,
            task_id,
            owner_did,
            skill,
            input_text,
            cancel_event,
        ),
        daemon=True,
        name=f"a2a-{task_id[:8]}",
    )
    with lock:
        cancel_events[task_id] = cancel_event
        threads[task_id] = thread
    thread.start()


def _handle_inbound(agent: Agent, message: dict) -> None:
    frame = parse_rpc(message.get("text", ""))
    if frame is None or "method" not in frame:
        return  # not a request frame (e.g. a stray or malformed message) - ignore, don't crash the loop
    req_id = frame["id"]
    method = frame["method"]
    signed_did = message.get("from")
    if not isinstance(method, str):
        if valid_did_key(signed_did):
            _reply(
                agent,
                reply_mailbox_for(signed_did, agent.did, req_id),
                rpc_error(req_id, -32600, "invalid request"),
            )
        return
    params = frame.get("params")
    if not isinstance(params, dict):
        if valid_did_key(signed_did):
            _reply(
                agent,
                reply_mailbox_for(signed_did, agent.did, req_id),
                rpc_error(
                    req_id,
                    -32602,
                    "params must be an object",
                    field="params",
                ),
            )
        return

    if method in (SEND_MESSAGE_METHOD, "message/send"):
        _handle_message_send(agent, message, req_id, params)
    elif method in (CANCEL_TASK_METHOD, "tasks/cancel"):
        _handle_tasks_cancel(agent, message, req_id, params)
    else:
        caller_did, caller_error = _verified_caller(message, params)
        if caller_error is None and caller_did is not None:
            reply_mailbox = _authorized_reply_mailbox(
                agent,
                caller_did,
                req_id,
                params,
            )
            _reply(
                agent,
                reply_mailbox,
                rpc_error(req_id, -32601, "method not found"),
            )


def _reply(agent: Agent, reply_mailbox: str | None, text: str) -> None:
    if not valid_mailbox(reply_mailbox):
        return
    try:
        agent.say_signed(reply_mailbox, text)
    except A2AError as exc:
        print(f"{APP_NAME}: could not deliver reply to {reply_mailbox}: {exc}", file=sys.stderr)


def _handle_message_send(agent: Agent, message: dict, req_id: str | int, params: dict) -> None:
    caller_did, caller_error = _verified_caller(message, params)
    if caller_error is not None:
        signed_did = message.get("from")
        if valid_did_key(signed_did):
            reply_mailbox = _authorized_reply_mailbox(
                agent,
                signed_did,
                req_id,
                params,
            )
            _reply(
                agent,
                reply_mailbox,
                rpc_error(
                    req_id,
                    -32602,
                    caller_error,
                    field="metadata.technocoreTransport.callerDid",
                ),
            )
        return
    assert caller_did is not None
    reply_mailbox = _authorized_reply_mailbox(
        agent,
        caller_did,
        req_id,
        params,
    )
    if reply_mailbox is None:
        print(f"{APP_NAME}: refusing unbound reply mailbox", file=sys.stderr)
        return

    request_message = params.get("message")
    if not isinstance(request_message, dict) or not isinstance(request_message.get("messageId"), str):
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32602,
                "message.messageId is required",
                field="message.messageId",
            ),
        )
        return
    if request_message.get("role") not in ("ROLE_USER", "user"):
        _reply(agent, reply_mailbox, rpc_error(req_id, -32602, "message.role must be ROLE_USER", field="message.role"))
        return
    parts = request_message.get("parts")
    if not isinstance(parts, list) or not parts:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32602,
                "at least one message part is required",
                field="message.parts",
            ),
        )
        return
    text_parts = [
        part["text"]
        for part in parts
        if isinstance(part, dict)
        and isinstance(part.get("text"), str)
        and (part.get("kind") in (None, "text"))
    ]
    if not text_parts:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32005,
                "only text parts are supported",
                reason="CONTENT_TYPE_NOT_SUPPORTED",
                metadata={"supportedMediaType": "text/plain"},
            ),
        )
        return

    input_text = " ".join(text_parts)
    skill = _transport_metadata(params).get("skill", "shout")
    if not isinstance(skill, str):
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32602,
                "skill must be a string",
                field="metadata.technocoreTransport.skill",
            ),
        )
        return

    configuration = params.get("configuration")
    return_immediately = (
        isinstance(configuration, dict)
        and configuration.get("returnImmediately") is True
    )
    request_hash = _record_hash(_dumps(params))
    try:
        task_id, is_new = _remember_request(
            agent,
            caller_did,
            req_id,
            request_hash,
        )
    except A2AError as exc:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(req_id, -32600, str(exc)),
        )
        return
    current = task_state_get(
        agent,
        task_id,
        expected_agent_did=agent.did,
        expected_owner_did=caller_did,
    )
    if not is_new and current is not None and current["state"] != TASK_STATE_SUBMITTED:
        if return_immediately or current["state"] in TERMINAL_STATES:
            _reply(
                agent,
                reply_mailbox,
                rpc_result(req_id, _task_result(agent, current)),
            )
        else:
            _add_task_waiter(agent, task_id, reply_mailbox, req_id)
        return

    if current is None:
        created, submitted = task_state_set(
            agent,
            task_id,
            caller_did,
            TASK_STATE_SUBMITTED,
            if_absent=True,
        )
        current = (
            submitted
            if created
            else task_state_get(
                agent,
                task_id,
                expected_agent_did=agent.did,
                expected_owner_did=caller_did,
            )
        )
    if current is None or current["state"] != TASK_STATE_SUBMITTED:
        if current is not None:
            _reply(
                agent,
                reply_mailbox,
                rpc_result(req_id, _task_result(agent, current)),
            )
        return

    if return_immediately:
        _reply(
            agent,
            reply_mailbox,
            rpc_result(req_id, _task_result(agent, current)),
        )
    else:
        _add_task_waiter(agent, task_id, reply_mailbox, req_id)

    started, working = task_state_set(
        agent,
        task_id,
        caller_did,
        TASK_STATE_WORKING,
        previous=current,
    )
    if not started:
        current = task_state_get(
            agent,
            task_id,
            expected_agent_did=agent.did,
            expected_owner_did=caller_did,
        )
        if not return_immediately and current is not None:
            if current["state"] in TERMINAL_STATES:
                _notify_task_waiters(agent, current)
        return

    _start_task(
        agent,
        task_id,
        caller_did,
        skill,
        input_text,
    )


def _handle_tasks_cancel(agent: Agent, message: dict, req_id: str | int, params: dict) -> None:
    caller_did, caller_error = _verified_caller(message, params)
    if caller_error is not None:
        signed_did = message.get("from")
        if valid_did_key(signed_did):
            reply_mailbox = _authorized_reply_mailbox(
                agent,
                signed_did,
                req_id,
                params,
            )
            _reply(
                agent,
                reply_mailbox,
                rpc_error(
                    req_id,
                    -32602,
                    caller_error,
                    field="metadata.technocoreTransport.callerDid",
                ),
            )
        return
    assert caller_did is not None
    reply_mailbox = _authorized_reply_mailbox(
        agent,
        caller_did,
        req_id,
        params,
    )
    if reply_mailbox is None:
        print(f"{APP_NAME}: refusing unbound reply mailbox", file=sys.stderr)
        return

    task_id = params.get("id", params.get("taskId"))
    if not valid_task_id(task_id):
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32602,
                "id must be a 32-character lowercase hex task id",
                field="id",
            ),
        )
        return

    ownership = agent.state.get("tasks", {}).get(task_id)
    if not isinstance(ownership, dict) or ownership.get("callerDid") != caller_did:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32001,
                "task not found",
                reason="TASK_NOT_FOUND",
                metadata={"taskId": task_id},
            ),
        )
        return

    current = task_state_get(
        agent,
        task_id,
        expected_agent_did=agent.did,
        expected_owner_did=caller_did,
    )
    if current is None:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32001,
                "task not found",
                reason="TASK_NOT_FOUND",
                metadata={"taskId": task_id},
            ),
        )
        return
    if current["state"] == TASK_STATE_CANCELED:
        _reply(
            agent,
            reply_mailbox,
            rpc_result(req_id, _task_result(agent, current)),
        )
        return
    if current["state"] in TERMINAL_STATES:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32002,
                "task is not cancelable",
                reason="TASK_NOT_CANCELABLE",
                metadata={"taskId": task_id, "state": current["state"]},
            ),
        )
        return

    cancel_events, _, lock = _task_runtime(agent)
    with lock:
        cancel_event = cancel_events.get(task_id)
        if cancel_event is not None:
            cancel_event.set()
    canceled, canceled_record = task_state_set(
        agent,
        task_id,
        caller_did,
        TASK_STATE_CANCELED,
        previous=current,
    )
    if not canceled:
        canceled_record = task_state_get(
            agent,
            task_id,
            expected_agent_did=agent.did,
            expected_owner_did=caller_did,
        )
    if canceled_record is not None and canceled_record["state"] == TASK_STATE_CANCELED:
        _notify_task_waiters(agent, canceled_record)
        _reply(
            agent,
            reply_mailbox,
            rpc_result(req_id, _task_result(agent, canceled_record)),
        )
    else:
        _reply(
            agent,
            reply_mailbox,
            rpc_error(
                req_id,
                -32002,
                "task is not cancelable",
                reason="TASK_NOT_CANCELABLE",
                metadata={
                    "taskId": task_id,
                    "state": (
                        canceled_record["state"]
                        if canceled_record is not None
                        else "unknown"
                    ),
                },
            ),
        )


# ------------------------------------------------------------------------------------- send


def _resolve_target(agent: Agent, args: argparse.Namespace) -> tuple[str, str]:
    peer_did = getattr(args, "peer_did", None)
    if args.to_did is not None:
        if peer_did is not None and peer_did != args.to_did:
            raise A2AError("--peer-did must match --to-did")
        peer_did = args.to_did
        target_mailbox = agent.resolve_peer(peer_did)
    else:
        target_mailbox = args.to_mailbox
    if not valid_did_key(peer_did):
        raise A2AError("--peer-did is required with --to-mailbox")
    if not valid_mailbox(target_mailbox):
        raise A2AError("target must be a private, signed-only mb-p- mailbox")
    return target_mailbox, peer_did


def _state_record_from_task(
    task: dict,
    *,
    expected_agent_did: str,
    expected_owner_did: str,
) -> dict:
    task_id = task.get("id")
    if not valid_task_id(task_id):
        raise A2AError("peer response has an invalid task id")
    metadata = task.get("metadata")
    transport = (
        metadata.get("technocoreTransport")
        if isinstance(metadata, dict)
        else None
    )
    envelope = transport.get("stateRecord") if isinstance(transport, dict) else None
    if not isinstance(envelope, dict):
        raise A2AError(f"peer response for {task_id} has no signed state record")
    return _verify_record(
        _dumps(envelope),
        kind="task-state",
        task_id=task_id,
        expected_agent_did=expected_agent_did,
        expected_owner_did=expected_owner_did,
    )


def _accept_peer_state(agent: Agent, record: dict) -> None:
    task_id = record["taskId"]
    state_hash = _record_hash(record["_raw"])
    peer_states = agent.state.setdefault("peerTaskStates", {})
    previous = peer_states.get(task_id)
    if isinstance(previous, dict):
        if previous.get("agentDid") != record["agentDid"]:
            raise A2AError(f"peer identity changed for task {task_id}")
        if previous.get("ownerDid") != record["ownerDid"]:
            raise A2AError(f"task owner changed for task {task_id}")
        previous_revision = previous.get("revision")
        if not isinstance(previous_revision, int):
            raise A2AError(f"local peer checkpoint is corrupt for task {task_id}")
        if record["revision"] < previous_revision:
            raise A2AError(f"peer task {task_id} rolled back to an older revision")
        if record["revision"] == previous_revision:
            if previous.get("stateHash") != state_hash:
                raise A2AError(f"peer task {task_id} forked at one revision")
            return
        cursor = record
        while cursor["revision"] > previous_revision + 1:
            predecessor = _verify_record(
                _dumps(cursor["previousRecord"]),
                kind="task-state",
                task_id=task_id,
                expected_agent_did=record["agentDid"],
                expected_owner_did=record["ownerDid"],
            )
            if (
                predecessor["revision"] != cursor["revision"] - 1
                or _record_hash(predecessor["_raw"]) != cursor["previousHash"]
            ):
                raise A2AError(f"peer task {task_id} broke its state hash chain")
            cursor = predecessor
        if cursor["previousHash"] != previous.get("stateHash"):
            raise A2AError(f"peer task {task_id} broke its state hash chain")
    else:
        cursor = record
        while cursor["revision"] > 0:
            predecessor = _verify_record(
                _dumps(cursor["previousRecord"]),
                kind="task-state",
                task_id=task_id,
                expected_agent_did=record["agentDid"],
                expected_owner_did=record["ownerDid"],
            )
            if (
                predecessor["revision"] != cursor["revision"] - 1
                or _record_hash(predecessor["_raw"]) != cursor["previousHash"]
            ):
                raise A2AError(f"peer task {task_id} broke its state hash chain")
            cursor = predecessor
    peer_states[task_id] = {
        "agentDid": record["agentDid"],
        "ownerDid": record["ownerDid"],
        "revision": record["revision"],
        "stateHash": state_hash,
        "state": record["state"],
    }
    agent.save()


def cmd_send(agent: Agent, args: argparse.Namespace) -> int:
    # One overall deadline, threaded through every network call below - a caller who asked
    # for --timeout 60 gets a hard cap near 60s even if the service is having a bad patch,
    # rather than up to --timeout PER retrying call (six-plus times over, once per call).
    deadline = time.time() + args.timeout
    target_mailbox, peer_did = _resolve_target(agent, args)

    req_id = secrets.token_hex(16)
    reply_mailbox = reply_mailbox_for(agent.did, peer_did, req_id)
    # Read the one-time reply room before writing so a fast response is not skipped.
    cursor = agent.read_room_tail(reply_mailbox, deadline=deadline).get("last_seq", 0)
    req_id, frame = rpc_request(
        SEND_MESSAGE_METHOD,
        {
            "message": {
                "messageId": secrets.token_hex(8),
                "role": "ROLE_USER",
                "parts": [{"text": args.text, "mediaType": "text/plain"}],
            },
            "configuration": {"acceptedOutputModes": ["text/plain"], "returnImmediately": True},
            "metadata": {
                "technocoreTransport": {
                    "skill": args.skill,
                    "replyMailbox": reply_mailbox,
                    "callerDid": agent.did,
                }
            },
        },
        req_id,
    )
    agent.say_signed(target_mailbox, frame, deadline=deadline)
    print(f"{APP_NAME}: sent {req_id} to {target_mailbox}", file=sys.stderr)

    response = _await_response(
        agent,
        reply_mailbox,
        cursor,
        req_id,
        deadline,
        expected_did=peer_did,
    )
    if "error" in response:
        raise A2AError(f"peer refused: {response['error']}")
    task = response.get("result", {}).get("task")
    if not isinstance(task, dict):
        raise A2AError("peer response has no task")
    initial_state = _state_record_from_task(
        task,
        expected_agent_did=peer_did,
        expected_owner_did=agent.did,
    )
    _accept_peer_state(agent, initial_state)
    task_id = initial_state["taskId"]
    print(f"{APP_NAME}: task {task_id} submitted, polling for completion", file=sys.stderr)

    while time.time() < deadline:
        state_record = task_state_get(
            agent,
            task_id,
            expected_agent_did=peer_did,
            expected_owner_did=agent.did,
            deadline=deadline,
        )
        if state_record is not None:
            _accept_peer_state(agent, state_record)
        if state_record is not None and state_record["state"] in TERMINAL_STATES:
            _print_result(agent, state_record, peer_did)
            return 0 if state_record["state"] == TASK_STATE_COMPLETED else 1
        time.sleep(1)
    raise A2AError(f"task {task_id} did not reach a terminal state within {args.timeout}s")


def cmd_cancel(agent: Agent, args: argparse.Namespace) -> int:
    deadline = time.time() + args.timeout
    target_mailbox, peer_did = _resolve_target(agent, args)
    req_id = secrets.token_hex(16)
    reply_mailbox = reply_mailbox_for(agent.did, peer_did, req_id)
    cursor = agent.read_room_tail(reply_mailbox, deadline=deadline).get("last_seq", 0)
    req_id, frame = rpc_request(
        CANCEL_TASK_METHOD,
        {
            "id": args.task_id,
            "metadata": {
                "technocoreTransport": {
                    "replyMailbox": reply_mailbox,
                    "callerDid": agent.did,
                }
            },
        },
        req_id,
    )
    agent.say_signed(target_mailbox, frame, deadline=deadline)
    response = _await_response(
        agent,
        reply_mailbox,
        cursor,
        req_id,
        deadline,
        expected_did=peer_did,
    )
    if "result" in response:
        task = response.get("result", {}).get("task")
        if not isinstance(task, dict):
            raise A2AError("peer response has no task")
        state_record = _state_record_from_task(
            task,
            expected_agent_did=peer_did,
            expected_owner_did=agent.did,
        )
        _accept_peer_state(agent, state_record)
    print(_dumps(response))
    return 0 if "result" in response else 1


def cmd_status(agent: Agent, args: argparse.Namespace) -> int:
    state_record = task_state_get(
        agent,
        args.task_id,
        expected_agent_did=args.peer_did,
        expected_owner_did=agent.did,
    )
    if state_record is None:
        print(f"no such task: {args.task_id}", file=sys.stderr)
        return 1
    _accept_peer_state(agent, state_record)
    print(f"state: {state_record['state']}")
    if state_record["state"] in (TASK_STATE_COMPLETED, TASK_STATE_FAILED):
        artifact_record = task_artifact_get(
            agent,
            args.task_id,
            expected_agent_did=args.peer_did,
            expected_owner_did=agent.did,
        )
        _validate_artifact_binding(state_record, artifact_record)
        print(f"artifact: {_dumps(artifact_record['artifact'])}")
    return 0


def _await_response(
    agent: Agent,
    reply_mailbox: str,
    cursor: int,
    req_id: str | int,
    deadline: float,
    expected_did: str,
) -> dict:
    since = cursor
    while time.time() < deadline:
        remaining = max(1, min(POLL_WAIT_SECONDS, int(deadline - time.time())))
        view = agent.read_room(reply_mailbox, since, wait=remaining, deadline=deadline)
        for message in view.get("messages", []):
            since = message["seq"]
            sender = message.get("from")
            if not valid_did_key(sender):
                continue
            if sender != expected_did:
                continue
            frame = parse_rpc(message.get("text", ""))
            if frame is not None and frame.get("id") == req_id and ("result" in frame or "error" in frame):
                return frame
        since = max(since, view.get("last_seq", since))
    raise A2AError(f"no response to {req_id}")


def _print_result(agent: Agent, state_record: dict, peer_did: str) -> None:
    task_id = state_record["taskId"]
    state = state_record["state"]
    artifact_record = task_artifact_get(
        agent,
        task_id,
        expected_agent_did=peer_did,
        expected_owner_did=agent.did,
    )
    print(f"{APP_NAME}: task {task_id} -> {state}")
    if state in (TASK_STATE_COMPLETED, TASK_STATE_FAILED):
        _validate_artifact_binding(state_record, artifact_record)
        print(_dumps(artifact_record["artifact"]))


def _validate_artifact_binding(
    state_record: dict,
    artifact_record: dict | None,
) -> None:
    task_id = state_record["taskId"]
    if artifact_record is None:
        raise A2AError(f"terminal task {task_id} has no signed artifact")
    if state_record.get("artifactHash") != _record_hash(artifact_record["_raw"]):
        raise A2AError(f"terminal task {task_id} does not bind its artifact")
    if artifact_record["workingStateHash"] != state_record["previousHash"]:
        raise A2AError(f"artifact for {task_id} belongs to another execution")


def cmd_identity(agent: Agent, args: argparse.Namespace) -> int:
    print(f"did: {agent.did}")
    print(f"mailbox: {agent.mailbox}")
    return 0


def cmd_publish(agent: Agent, args: argparse.Namespace) -> int:
    agent.publish_did_note()
    shard, key = did_fingerprint(agent.did)
    print(f"published: /kv/did-{shard}/{key} -> {agent.did} mailbox:{agent.mailbox}")
    return 0


def cmd_recover_cursor(agent: Agent, args: argparse.Namespace) -> int:
    lock_fd = acquire_serve_lock(agent.home)
    try:
        since = agent.state.get("cursor", 0)
        view = agent.read_room_tail(agent.mailbox)
        messages = view.get("messages", [])
        if messages:
            first_seq = messages[0].get("seq")
            if not isinstance(first_seq, int):
                raise A2AError("the mailbox tail has an invalid first sequence")
            target = first_seq - 1
        else:
            last_seq = view.get("last_seq")
            if not isinstance(last_seq, int) or last_seq >= since:
                raise A2AError("the mailbox has no cursor gap to recover")
            target = last_seq
            first_seq = target + 1
        if target == since:
            print(f"{APP_NAME}: cursor {since} already reaches the retained window")
            return 0
        agent.state["cursor"] = target
        agent.save_server_state()
        if target > since:
            detail = f"acknowledged lost mailbox sequences {since + 1}..{target}"
        else:
            detail = f"acknowledged room epoch reset from cursor {since} to {target}"
        print(f"{APP_NAME}: {detail}; resume serve from {first_seq}")
        return 0
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


# --------------------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--home",
        type=Path,
        default=DEFAULT_HOME,
        help=f"identity + state directory (default: {DEFAULT_HOME})",
    )
    parser.add_argument("--base", default=TECHNOCORE_BASE, help="technocore.chat base URL")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("identity", help="show this agent's DID and mailbox")
    p.set_defaults(func=cmd_identity)

    p = sub.add_parser("publish", help="publish the DID note (src/patterns.md #3) - an outward, world-readable write")
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser(
        "recover-cursor",
        help="acknowledge a reported mailbox retention gap while serve is stopped",
    )
    p.add_argument(
        "--skip-lost",
        action="store_true",
        required=True,
        help="confirm that missing mailbox sequences may be skipped",
    )
    p.set_defaults(func=cmd_recover_cursor)

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
    p.add_argument(
        "--peer-did",
        help="expected signing DID (required with --to-mailbox; normally from the agent card)",
    )
    p.add_argument("--text", required=True, help="the task input")
    p.add_argument("--skill", default="shout")
    p.add_argument("--timeout", type=float, default=45.0)
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("cancel", help="request cancellation of a task you delegated")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--to-mailbox")
    target.add_argument("--to-did")
    p.add_argument(
        "--peer-did",
        help="expected signing DID (required with --to-mailbox; normally from the agent card)",
    )
    p.add_argument("--task-id", required=True)
    p.add_argument("--timeout", type=float, default=30.0)
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("status", help="read a task's current state directly - no signing, no mailbox round trip")
    p.add_argument("task_id")
    p.add_argument(
        "--peer-did",
        required=True,
        help="signing DID from the peer's verified agent card or DID resolution",
    )
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
