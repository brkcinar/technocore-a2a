#!/usr/bin/env python3
"""
Generate the technocore-room-v1 conformance fixtures from PROFILE.md alone.

This file deliberately does not import agent.py. Everything below - canonical JSON, did:key,
derivations, envelopes - is written from the profile text, so that tests/test_conformance.py
checking agent.py against these fixtures tests the implementation against the profile rather
than against itself. Ed25519 signatures are deterministic, so the output is byte-stable.

    python3 conformance/gen_fixtures.py          # rewrite conformance/fixtures/v1/
    python3 conformance/gen_fixtures.py --check  # exit 1 if the files are stale

The identities use published seeds. They are test vectors, not keys: never use them for a
real agent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROFILE = "technocore-room-v1"
BINDING_URI = "https://github.com/brkcinar/technocore-a2a#technocore-room-v1"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "v1"
BASE58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

SUBMITTED = "TASK_STATE_SUBMITTED"
WORKING = "TASK_STATE_WORKING"
COMPLETED = "TASK_STATE_COMPLETED"
FAILED = "TASK_STATE_FAILED"
CANCELED = "TASK_STATE_CANCELED"


# ------------------------------------------------------------------- PROFILE.md section 3

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _c_string(text: str) -> str:
    out = ['"']
    for char in text:
        point = ord(char)
        if char in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[char])
        elif 0x20 <= point <= 0x7E:
            out.append(char)
        elif point <= 0xFFFF:
            out.append(f"\\u{point:04x}")
        else:
            point -= 0x10000
            out.append(f"\\u{0xD800 | (point >> 10):04x}\\u{0xDC00 | (point & 0x3FF):04x}")
    out.append('"')
    return "".join(out)


def C(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _c_string(value)
    if isinstance(value, list):
        return "[" + ",".join(C(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_c_string(k) + ":" + C(v) for k, v in value.items()) + "}"
    raise TypeError(f"{type(value).__name__} is not allowed in canonical JSON")


def H(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def B64U(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# ------------------------------------------------------------------- PROFILE.md section 4


class Identity:
    def __init__(self, label: str):
        self.label = label
        self.seed = hashlib.sha256(f"{PROFILE}/insecure-test-identity/{label}".encode()).digest()
        self.key = Ed25519PrivateKey.from_private_bytes(self.seed)
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.did = "did:key:z" + _base58btc(b"\xed\x01" + public)

    def sign(self, record: dict) -> str:
        """Append the signature as the last member and return the raw record."""
        signature = B64U(self.key.sign(C(record).encode("utf-8")))
        return C({**record, "signature": signature})


def _base58btc(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = BASE58BTC[remainder] + out
    return "1" * zeroes + out


ALICE = Identity("alice")  # caller
BOB = Identity("bob")  # serving agent
CAROL = Identity("carol")  # another caller, or an attacker with her own key
MAILBOX = "mb-p-0123456789abcdef"


# ---------------------------------------------------------------- PROFILE.md sections 7-11


def reply_room(caller_did: str, agent_did: str, request_id: str | int) -> str:
    return "mb-p-a2a-" + H(C({"callerDid": caller_did, "agentDid": agent_did, "requestId": request_id}))[:32]


def request_key(caller_did: str, request_id: str | int) -> str:
    return H(C({"callerDid": caller_did, "requestId": request_id}))


def task_id(label: str) -> str:
    return H(f"{PROFILE}/task/{label}")[:32]


def state_note(task: str) -> list[str]:
    return [f"a2a-task-{task[:2]}", task[2:]]


def artifact_note(task: str) -> list[str]:
    return [f"a2a-artifact-{task[:2]}", task[2:]]


def state_record(
    signer: Identity,
    task: str,
    owner: str,
    state: str,
    previous_raw: str | None,
    artifact_hash: str | None = None,
    *,
    agent_did: str | None = None,
    revision: int | None = None,
    previous_hash: str | None = None,
) -> str:
    previous = None if previous_raw is None else json.loads(previous_raw)
    record = {
        "kind": "task-state",
        "taskId": task,
        "ownerDid": owner,
        "agentDid": agent_did or signer.did,
        "state": state,
        "revision": revision if revision is not None else (0 if previous is None else previous["revision"] + 1),
        "previousHash": previous_hash if previous_hash is not None else ("" if previous_raw is None else H(previous_raw)),
        "previousRecord": previous,
    }
    if artifact_hash is not None:
        record["artifactHash"] = artifact_hash
    return signer.sign(record)


def artifact_record(signer: Identity, task: str, owner: str, artifact: dict, working_hash: str) -> str:
    return signer.sign(
        {
            "kind": "task-artifact",
            "taskId": task,
            "ownerDid": owner,
            "agentDid": signer.did,
            "artifact": artifact,
            "workingStateHash": working_hash,
        }
    )


def rpc(request_id: str | int, **member: object) -> str:
    return C({"jsonrpc": "2.0", "id": request_id, **member})


def task_object(raw_state: str, raw_artifact: str | None = None) -> dict:
    record = json.loads(raw_state)
    task = {
        "id": record["taskId"],
        "contextId": MAILBOX,
        "status": {"state": record["state"]},
        "metadata": {"technocoreTransport": {"stateRecord": record}},
    }
    if raw_artifact is not None:
        task["artifacts"] = [
            {
                "artifactId": f"{record['taskId']}-result",
                "name": "result",
                "parts": [{"data": json.loads(raw_artifact)["artifact"], "mediaType": "application/json"}],
            }
        ]
    return task


def error_info(request_id: str, code: int, message: str, reason: str, metadata: dict) -> str:
    detail = {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason, "domain": "a2a-protocol.org", "metadata": metadata}
    return rpc(request_id, error={"code": code, "message": message, "data": [detail]})


def bad_request(request_id: str, code: int, message: str, field: str) -> str:
    detail = {"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [{"field": field, "description": message}]}
    return rpc(request_id, error={"code": code, "message": message, "data": [detail]})


# ---------------------------------------------------------------------------- fixture sets


def build() -> dict[str, dict]:
    T = task_id("completed")
    T_CANCEL = task_id("canceled")
    T_OTHER = task_id("other")
    request_id = H(f"{PROFILE}/request/1")[:32]
    reply = reply_room(ALICE.did, BOB.did, request_id)

    submitted = state_record(BOB, T, ALICE.did, SUBMITTED, None)
    working = state_record(BOB, T, ALICE.did, WORKING, submitted)
    output = {"skill": "shout", "input": "hello", "output": "HELLO!!!", "ok": True}
    artifact = artifact_record(BOB, T, ALICE.did, output, H(working))
    completed = state_record(BOB, T, ALICE.did, COMPLETED, working, H(artifact))

    c_submitted = state_record(BOB, T_CANCEL, ALICE.did, SUBMITTED, None)
    c_working = state_record(BOB, T_CANCEL, ALICE.did, WORKING, c_submitted)
    c_canceled = state_record(BOB, T_CANCEL, ALICE.did, CANCELED, c_working)

    request_params = {
        "message": {
            "messageId": H(f"{PROFILE}/message/1")[:16],
            "role": "ROLE_USER",
            "parts": [{"text": "hello", "mediaType": "text/plain"}],
        },
        "configuration": {"acceptedOutputModes": ["text/plain"], "returnImmediately": True},
        "metadata": {"technocoreTransport": {"skill": "shout", "replyMailbox": reply, "callerDid": ALICE.did}},
    }

    canonical_inputs = [
        {"name": "empty object", "value": {}},
        {"name": "member order is preserved, not sorted", "value": {"z": 1, "a": 2}},
        {"name": "integers and literals", "value": [0, -1, 1234567890123, True, False, None]},
        {"name": "short escapes", "value": "quote\" backslash\\ \b\f\n\r\t"},
        {"name": "other controls and DEL use lowercase \\u", "value": "\x00\x1f\x7f"},
        {"name": "slash is not escaped", "value": "a/b"},
        {"name": "non-ASCII BMP", "value": "çğışöü Ā €"},
        {"name": "astral plane uses a surrogate pair", "value": "\U0001F600"},
        {"name": "nested", "value": {"k": [{"ç": " "}, []]}},
    ]

    valid = {
        "profile": PROFILE,
        "bindingUri": BINDING_URI,
        "note": "Generated by conformance/gen_fixtures.py from PROFILE.md. Identity seeds are public test vectors; never use them for a real agent.",
        "canonicalJson": [{**case, "canonical": C(case["value"])} for case in canonical_inputs],
        "identities": {
            identity.label: {"seedHex": identity.seed.hex(), "did": identity.did}
            for identity in (ALICE, BOB, CAROL)
        },
        "derivations": {
            "replyRoom": [
                {"callerDid": ALICE.did, "agentDid": BOB.did, "requestId": request_id, "room": reply},
                {"callerDid": ALICE.did, "agentDid": BOB.did, "requestId": 7, "room": reply_room(ALICE.did, BOB.did, 7)},
                {"callerDid": ALICE.did, "agentDid": BOB.did, "requestId": "7", "room": reply_room(ALICE.did, BOB.did, "7")},
            ],
            "requestKey": [
                {"callerDid": ALICE.did, "requestId": request_id, "key": request_key(ALICE.did, request_id)},
                {"callerDid": CAROL.did, "requestId": request_id, "key": request_key(CAROL.did, request_id)},
            ],
            "requestHash": {"params": request_params, "hash": H(C(request_params))},
            "notes": [
                {"taskId": T, "state": state_note(T), "artifact": artifact_note(T)},
            ],
            "didNote": {"did": BOB.did, "namespace": f"did-{H(BOB.did)[:2]}", "key": H(BOB.did)[2:16], "value": f"{BOB.did} mailbox:{MAILBOX}"},
        },
        "taskChains": {
            "completed": {
                "taskId": T,
                "agentDid": BOB.did,
                "ownerDid": ALICE.did,
                "records": [
                    {"kind": "task-state", "raw": submitted, "hash": H(submitted)},
                    {"kind": "task-state", "raw": working, "hash": H(working)},
                    {"kind": "task-artifact", "raw": artifact, "hash": H(artifact)},
                    {"kind": "task-state", "raw": completed, "hash": H(completed)},
                ],
            },
            "canceled": {
                "taskId": T_CANCEL,
                "agentDid": BOB.did,
                "ownerDid": ALICE.did,
                "records": [
                    {"kind": "task-state", "raw": c_submitted, "hash": H(c_submitted)},
                    {"kind": "task-state", "raw": c_working, "hash": H(c_working)},
                    {"kind": "task-state", "raw": c_canceled, "hash": H(c_canceled)},
                ],
            },
        },
        "frames": {
            "mailbox": MAILBOX,
            "sendMessageRequest": {"requestId": request_id, "params": request_params, "frame": rpc(request_id, method="SendMessage", params=request_params)},
            "submittedResponse": rpc(request_id, result={"task": task_object(submitted)}),
            "completedResponse": rpc(request_id, result={"task": task_object(completed, artifact)}),
            "errors": [
                {"case": "unsupported content", "frame": error_info(request_id, -32005, "only text parts are supported", "CONTENT_TYPE_NOT_SUPPORTED", {"supportedMediaType": "text/plain"})},
                {"case": "missing messageId", "frame": bad_request(request_id, -32602, "message.messageId is required", "message.messageId")},
                {"case": "task not found", "frame": error_info(request_id, -32001, "task not found", "TASK_NOT_FOUND", {"taskId": T})},
                {"case": "task not cancelable", "frame": error_info(request_id, -32002, "task is not cancelable", "TASK_NOT_CANCELABLE", {"taskId": T, "state": COMPLETED})},
            ],
        },
    }

    def reject(name: str, why: str, raw: str, *, kind: str = "task-state", task: str = T) -> dict:
        return {"name": name, "why": why, "kind": kind, "taskId": task, "expectedAgentDid": BOB.did, "expectedOwnerDid": ALICE.did, "raw": raw}

    submitted_obj = json.loads(submitted)
    tampered_sig = dict(submitted_obj)
    tampered_sig["signature"] = ("A" if submitted_obj["signature"][0] != "A" else "B") + submitted_obj["signature"][1:]
    unsigned = {k: v for k, v in submitted_obj.items() if k != "signature"}

    invalid = {
        "profile": PROFILE,
        "note": "Every case MUST be rejected by record verification (PROFILE.md section 10) for the expected kind, task, agent, and owner.",
        "cases": [
            reject("bad signature", "signature does not verify", C(tampered_sig)),
            reject("unsigned", "no signature member, e.g. an attacker-written note", C(unsigned)),
            reject("value changed after signing", "state edited, signature kept", submitted.replace(SUBMITTED, COMPLETED)),
            reject("wrong owner", "validly signed by the agent, but for another caller's task", state_record(BOB, T, CAROL.did, SUBMITTED, None)),
            reject("wrong task", "validly signed record for another task copied into this task's note", state_record(BOB, T_OTHER, ALICE.did, SUBMITTED, None)),
            reject("wrong agent", "signed by a different key that names itself as agentDid", state_record(CAROL, T, ALICE.did, SUBMITTED, None)),
            reject("agent impersonation", "names the expected agent but is signed by another key", state_record(CAROL, T, ALICE.did, SUBMITTED, None, agent_did=BOB.did)),
            reject("kind confusion", "an artifact record presented as task state", artifact),
            reject("non-canonical whitespace", "raw form rule: valid signature, non-canonical bytes", json.dumps(json.loads(submitted))),
            reject("duplicate member", "raw form rule: parsers disagree on which value wins", submitted.replace('"state":', '"state":"' + COMPLETED + '","state":', 1)),
            reject("invalid genesis", "revision 0 with a predecessor hash", state_record(BOB, T, ALICE.did, SUBMITTED, None, previous_hash=H("x"))),
            reject("negative revision", "revision must be a non-negative integer", state_record(BOB, T, ALICE.did, SUBMITTED, None, revision=-1)),
            reject("missing predecessor", "revision > 0 without previousRecord", state_record(BOB, T, ALICE.did, WORKING, None, revision=1, previous_hash=H(submitted))),
        ],
    }

    forked_working = state_record(BOB, T, ALICE.did, CANCELED, submitted)  # also revision 1
    broken_chain = state_record(BOB, T, ALICE.did, COMPLETED, working, H(artifact), previous_hash=H(forked_working))
    other_execution_artifact = artifact_record(BOB, T, ALICE.did, output, H(forked_working))
    unbound_terminal = state_record(BOB, T, ALICE.did, COMPLETED, working, H(other_execution_artifact))
    wrong_hash_terminal = state_record(BOB, T, ALICE.did, COMPLETED, working, H("not the artifact"))

    checkpoints = {
        "profile": PROFILE,
        "note": "Feed each 'accept' record to a caller with an empty checkpoint for the task, in order. The final 'expect' applies to the last record; a rejected record MUST leave the checkpoint unchanged.",
        "taskId": T,
        "agentDid": BOB.did,
        "ownerDid": ALICE.did,
        "sequences": [
            {"name": "in order", "records": [submitted, working, completed], "expect": "accept"},
            {"name": "skip ahead by walking the embedded chain", "records": [submitted, completed], "expect": "accept"},
            {"name": "first sight of a later record verifies back to genesis", "records": [completed], "expect": "accept"},
            {"name": "same record twice is a no-op", "records": [working, working], "expect": "accept"},
            {"name": "rollback", "records": [completed, working], "expect": "reject"},
            {"name": "fork at one revision", "records": [working, forked_working], "expect": "reject"},
            {"name": "broken hash chain", "records": [submitted, broken_chain], "expect": "reject"},
        ],
        "artifactBinding": [
            {"name": "bound", "state": completed, "artifact": artifact, "expect": "accept"},
            {"name": "artifact from another execution", "state": unbound_terminal, "artifact": other_execution_artifact, "expect": "reject"},
            {"name": "artifactHash does not match", "state": wrong_hash_terminal, "artifact": artifact, "expect": "reject"},
        ],
    }

    return {"valid.json": valid, "invalid-records.json": invalid, "caller-checkpoints.json": checkpoints}


def render(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str]) -> int:
    documents = build()
    if "--check" in argv:
        stale = [name for name, doc in documents.items() if not (FIXTURE_DIR / name).exists() or (FIXTURE_DIR / name).read_text() != render(doc)]
        if stale:
            print(f"stale fixtures: {', '.join(stale)} - run conformance/gen_fixtures.py", file=sys.stderr)
            return 1
        return 0
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, doc in documents.items():
        (FIXTURE_DIR / name).write_text(render(doc))
        print(f"wrote {FIXTURE_DIR / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
