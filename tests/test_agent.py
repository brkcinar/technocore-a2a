import argparse
import copy
import io
import json
import tempfile
import time
import unittest
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock
from unittest.mock import patch

import agent as bridge
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ALICE_KEY = Ed25519PrivateKey.generate()
BOB_KEY = Ed25519PrivateKey.generate()
CAROL_KEY = Ed25519PrivateKey.generate()
ALICE_DID = bridge.did_from_private_key(ALICE_KEY)
BOB_DID = bridge.did_from_private_key(BOB_KEY)
CAROL_DID = bridge.did_from_private_key(CAROL_KEY)
ALICE_MAILBOX = "mb-p-alice123"
BOB_MAILBOX = "mb-p-bob123"
CAROL_MAILBOX = "mb-p-carol123"
AUTO_REPLY = object()


class FakeAgent:
    def __init__(self, key=BOB_KEY, mailbox=BOB_MAILBOX):
        self.base = "https://technocore.chat"
        self.key = key
        self.did = bridge.did_from_private_key(key)
        self.mailbox = mailbox
        self.state = {}
        self.notes = {}
        self.note_history = []
        self.sent = []
        self.saved = 0

    def save(self):
        self.saved += 1

    def save_server_state(self):
        generation = self.state.get("serverGeneration", 0)
        self.state["serverGeneration"] = generation + 1
        self.save()

    def kv_get(self, namespace, key, deadline=None):
        return self.notes.get((namespace, key))

    def kv_set(
        self,
        namespace,
        key,
        value,
        if_expected=None,
        if_absent=False,
        deadline=None,
    ):
        note_key = (namespace, key)
        if if_absent and note_key in self.notes:
            return False
        if if_expected is not None and self.notes.get(note_key) != if_expected:
            return False
        self.notes[note_key] = value
        self.note_history.append((note_key, value))
        return True

    def say_signed(self, mailbox, text, deadline=None):
        self.sent.append((mailbox, text))
        return len(self.sent)

    def read_room_tail(self, mailbox, deadline=None):
        return {"last_seq": 0}

    def resolve_peer(self, did):
        return {
            ALICE_DID: ALICE_MAILBOX,
            BOB_DID: BOB_MAILBOX,
            CAROL_DID: CAROL_MAILBOX,
        }[did]


def wait_for_tasks(fake):
    while True:
        _, threads, lock = bridge._task_runtime(fake)
        with lock:
            running = list(threads.values())
        if not running:
            return
        for thread in running:
            thread.join(timeout=1)


def send_frame(
    request_id="request-1",
    *,
    sender=ALICE_DID,
    claimed_sender=ALICE_DID,
    reply_mailbox=AUTO_REPLY,
    return_immediately=True,
    parts=None,
    role="ROLE_USER",
):
    if reply_mailbox is AUTO_REPLY:
        reply_mailbox = bridge.reply_mailbox_for(
            sender,
            BOB_DID,
            request_id,
        )
    params = {
        "message": {
            "messageId": "message-1",
            "role": role,
            "parts": parts if parts is not None else [{"text": "hello"}],
        },
        "configuration": {"returnImmediately": return_immediately},
        "metadata": {
            "technocoreTransport": {
                "replyMailbox": reply_mailbox,
                "callerDid": claimed_sender,
                "skill": "shout",
            }
        },
    }
    return {
        "from": sender,
        "text": bridge.rpc_request(bridge.SEND_MESSAGE_METHOD, params, request_id)[1],
    }


def response_body(fake):
    return json.loads(fake.sent[-1][1])


class AgentCardTests(unittest.TestCase):
    def test_card_uses_v1_custom_interface_shape(self):
        card = bridge.build_agent_card(FakeAgent(), "Bob", "Test agent")

        self.assertEqual(card["version"], bridge.APP_VERSION)
        self.assertNotIn("protocolVersion", card)
        self.assertEqual(
            card["supportedInterfaces"],
            [
                {
                    "url": f"https://technocore.chat/r/{BOB_MAILBOX}",
                    "protocolBinding": bridge.A2A_BINDING_URI,
                    "protocolVersion": "1.0",
                }
            ],
        )


class InboundRequestTests(unittest.TestCase):
    def test_replay_recovers_same_task_without_dispatching_twice(self):
        fake = FakeAgent()
        frame = send_frame()

        with patch.object(bridge, "dispatch_skill", wraps=bridge.dispatch_skill) as dispatch:
            bridge._handle_inbound(fake, frame)
            wait_for_tasks(fake)
            first_task = json.loads(fake.sent[0][1])["result"]["task"]["id"]
            restarted = FakeAgent(BOB_KEY, BOB_MAILBOX)
            restarted.state = copy.deepcopy(fake.state)
            restarted.notes = copy.deepcopy(fake.notes)
            bridge._handle_inbound(restarted, frame)
            wait_for_tasks(restarted)
            replay_task = response_body(restarted)["result"]["task"]["id"]

        self.assertEqual(first_task, replay_task)
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(
            response_body(restarted)["result"]["task"]["status"]["state"],
            bridge.TASK_STATE_COMPLETED,
        )
        self.assertGreaterEqual(fake.saved, 4)
        self.assertEqual(restarted.saved, 0)

    def test_request_id_is_scoped_to_verified_sender(self):
        fake = FakeAgent()

        with patch.object(bridge, "dispatch_skill", wraps=bridge.dispatch_skill) as dispatch:
            bridge._handle_inbound(fake, send_frame(request_id="same"))
            wait_for_tasks(fake)
            alice_task = json.loads(fake.sent[0][1])["result"]["task"]["id"]
            bridge._handle_inbound(
                fake,
                send_frame(
                    request_id="same",
                    sender=CAROL_DID,
                    claimed_sender=CAROL_DID,
                ),
            )
            wait_for_tasks(fake)
            bob_task = json.loads(fake.sent[1][1])["result"]["task"]["id"]

        self.assertNotEqual(alice_task, bob_task)
        self.assertEqual(dispatch.call_count, 2)

    def test_spoofed_caller_did_is_rejected_before_dispatch(self):
        fake = FakeAgent()

        with patch.object(bridge, "dispatch_skill") as dispatch:
            bridge._handle_inbound(
                fake,
                send_frame(sender=ALICE_DID, claimed_sender=BOB_DID),
            )

        self.assertFalse(dispatch.called)
        self.assertEqual(response_body(fake)["error"]["code"], -32602)
        self.assertEqual(fake.state, {})

    def test_unsigned_attribution_is_rejected(self):
        fake = FakeAgent()
        bridge._handle_inbound(
            fake,
            send_frame(sender="alice", claimed_sender=None),
        )

        self.assertEqual(fake.sent, [])
        self.assertEqual(fake.state, {})

    def test_unsafe_reply_room_is_not_used_as_signed_relay(self):
        fake = FakeAgent()

        with patch.object(bridge, "dispatch_skill") as dispatch:
            bridge._handle_inbound(fake, send_frame(reply_mailbox="lobby"))

        self.assertFalse(dispatch.called)
        self.assertEqual(fake.sent, [])
        self.assertEqual(fake.state, {})

    def test_arbitrary_valid_reply_mailbox_is_rejected(self):
        fake = FakeAgent()

        with patch.object(bridge, "dispatch_skill") as dispatch:
            bridge._handle_inbound(
                fake,
                send_frame(reply_mailbox=ALICE_MAILBOX),
            )

        dispatch.assert_not_called()
        self.assertEqual(fake.sent, [])

    def test_unknown_method_returns_method_not_found_on_derived_reply_room(self):
        fake = FakeAgent()
        req_id = "unknown-method"
        reply_mailbox = bridge.reply_mailbox_for(ALICE_DID, BOB_DID, req_id)
        params = {
            "metadata": {
                "technocoreTransport": {
                    "replyMailbox": reply_mailbox,
                    "callerDid": ALICE_DID,
                }
            }
        }
        frame = bridge.rpc_request("GetTask", params, req_id)[1]

        bridge._handle_inbound(fake, {"from": ALICE_DID, "text": frame})

        response = response_body(fake)
        self.assertEqual(fake.sent[0][0], reply_mailbox)
        self.assertEqual(response["id"], req_id)
        self.assertEqual(response["error"]["code"], -32601)

    def test_non_text_parts_return_typed_a2a_error(self):
        fake = FakeAgent()
        bridge._handle_inbound(fake, send_frame(parts=[{"url": "https://example.test/side-effect"}]))

        error = response_body(fake)["error"]
        self.assertEqual(error["code"], -32005)
        self.assertEqual(error["data"][0]["reason"], "CONTENT_TYPE_NOT_SUPPORTED")
        self.assertEqual(fake.state, {})

    def test_malformed_params_do_not_crash_or_write(self):
        fake = FakeAgent()
        malformed = {"jsonrpc": "2.0", "id": "bad", "method": bridge.SEND_MESSAGE_METHOD, "params": []}

        bridge._handle_inbound(fake, {"from": ALICE_DID, "text": json.dumps(malformed)})

        response = response_body(fake)
        self.assertEqual(
            fake.sent[0][0],
            bridge.reply_mailbox_for(ALICE_DID, BOB_DID, "bad"),
        )
        self.assertEqual(response["id"], "bad")
        self.assertEqual(response["error"]["code"], -32602)
        self.assertEqual(response["error"]["data"][0]["@type"], "type.googleapis.com/google.rpc.BadRequest")
        self.assertEqual(fake.state, {})

    def test_non_string_method_returns_invalid_request(self):
        fake = FakeAgent()
        malformed = {"jsonrpc": "2.0", "id": "bad-method", "method": 7, "params": {}}

        bridge._handle_inbound(fake, {"from": ALICE_DID, "text": json.dumps(malformed)})

        response = response_body(fake)
        self.assertEqual(response["id"], "bad-method")
        self.assertEqual(response["error"]["code"], -32600)

    def test_blocking_send_returns_terminal_task_with_artifact(self):
        fake = FakeAgent()
        bridge._handle_inbound(fake, send_frame(return_immediately=False))
        wait_for_tasks(fake)

        task = response_body(fake)["result"]["task"]
        self.assertEqual(task["status"]["state"], bridge.TASK_STATE_COMPLETED)
        self.assertEqual(task["artifacts"][0]["parts"][0]["data"]["output"], "HELLO!!!")

    def test_blocking_replay_waits_for_same_terminal_task(self):
        fake = FakeAgent()
        started = bridge.threading.Event()
        release = bridge.threading.Event()
        frame = send_frame(request_id="blocking-replay", return_immediately=False)

        def blocked_skill(skill, text, cancel_event):
            started.set()
            release.wait(timeout=1)
            return True, text.upper()

        with patch.object(bridge, "dispatch_skill", side_effect=blocked_skill) as dispatch:
            bridge._handle_inbound(fake, frame)
            self.assertTrue(started.wait(timeout=1))
            bridge._handle_inbound(fake, frame)
            self.assertEqual(fake.sent, [])
            self.assertEqual(dispatch.call_count, 1)
            release.set()
            wait_for_tasks(fake)

        self.assertEqual(len(fake.sent), 2)
        tasks = [json.loads(text)["result"]["task"] for _, text in fake.sent]
        self.assertEqual(tasks[0]["id"], tasks[1]["id"])
        self.assertTrue(
            all(
                task["status"]["state"] == bridge.TASK_STATE_COMPLETED
                for task in tasks
            )
        )

    def test_valid_older_state_cannot_trigger_duplicate_execution(self):
        fake = FakeAgent()
        frame = send_frame(request_id="rollback")

        with patch.object(bridge, "dispatch_skill", wraps=bridge.dispatch_skill) as dispatch:
            bridge._handle_inbound(fake, frame)
            wait_for_tasks(fake)
            task_id = json.loads(fake.sent[0][1])["result"]["task"]["id"]
            state_key = bridge.task_state_ns(task_id)
            state_records = [
                raw
                for key, raw in fake.note_history
                if key == state_key
            ]
            submitted = next(
                raw
                for raw in state_records
                if json.loads(raw)["state"] == bridge.TASK_STATE_SUBMITTED
            )
            fake.notes[state_key] = submitted

            with self.assertRaises(bridge.A2AError):
                bridge._handle_inbound(fake, frame)

        self.assertEqual(dispatch.call_count, 1)

    def test_request_id_reuse_with_changed_body_is_rejected(self):
        fake = FakeAgent()
        original = send_frame(request_id="changed")
        changed = send_frame(
            request_id="changed",
            parts=[{"text": "different"}],
        )

        with patch.object(bridge, "dispatch_skill", wraps=bridge.dispatch_skill) as dispatch:
            bridge._handle_inbound(fake, original)
            wait_for_tasks(fake)
            bridge._handle_inbound(fake, changed)

        self.assertEqual(response_body(fake)["error"]["code"], -32600)
        self.assertEqual(dispatch.call_count, 1)


class CancellationTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAgent()
        bridge._handle_inbound(self.fake, send_frame())
        wait_for_tasks(self.fake)
        self.task_id = json.loads(self.fake.sent[0][1])["result"]["task"]["id"]
        self.fake.sent.clear()

    def cancel_frame(self, sender, claimed_sender):
        reply_mailbox = bridge.reply_mailbox_for(
            sender,
            BOB_DID,
            "cancel-1",
        )
        params = {
            "id": self.task_id,
            "metadata": {
                "technocoreTransport": {
                    "replyMailbox": reply_mailbox,
                    "callerDid": claimed_sender,
                }
            },
        }
        return {
            "from": sender,
            "text": bridge.rpc_request(bridge.CANCEL_TASK_METHOD, params, "cancel-1")[1],
        }

    def test_non_owner_cannot_cancel_or_probe_task(self):
        bridge._handle_inbound(self.fake, self.cancel_frame(CAROL_DID, CAROL_DID))

        error = response_body(self.fake)["error"]
        self.assertEqual(error["code"], -32001)
        self.assertEqual(error["data"][0]["reason"], "TASK_NOT_FOUND")

    def test_terminal_task_returns_task_not_cancelable(self):
        bridge._handle_inbound(self.fake, self.cancel_frame(ALICE_DID, ALICE_DID))

        error = response_body(self.fake)["error"]
        self.assertEqual(error["code"], -32002)
        self.assertEqual(error["data"][0]["reason"], "TASK_NOT_CANCELABLE")

    def test_canceled_task_is_idempotent_for_owner(self):
        current = bridge.task_state_get(
            self.fake,
            self.task_id,
            expected_agent_did=BOB_DID,
            expected_owner_did=ALICE_DID,
        )
        bridge.task_state_set(
            self.fake,
            self.task_id,
            ALICE_DID,
            bridge.TASK_STATE_CANCELED,
            previous=current,
        )

        frame = self.cancel_frame(ALICE_DID, ALICE_DID)
        bridge._handle_inbound(self.fake, frame)
        bridge._handle_inbound(self.fake, frame)

        for _, text in self.fake.sent:
            self.assertEqual(json.loads(text)["result"]["task"]["status"]["state"], bridge.TASK_STATE_CANCELED)

    def test_in_flight_task_is_cooperatively_canceled(self):
        fake = FakeAgent()
        started = bridge.threading.Event()

        def blocking_dispatch(skill, text, cancel_event):
            started.set()
            cancel_event.wait(timeout=1)
            return False, "task canceled"

        with patch.object(bridge, "dispatch_skill", side_effect=blocking_dispatch):
            bridge._handle_inbound(fake, send_frame(request_id="long-task"))
            self.assertTrue(started.wait(timeout=1))
            task_id = json.loads(fake.sent[0][1])["result"]["task"]["id"]
            params = {
                "id": task_id,
                "metadata": {
                    "technocoreTransport": {
                        "replyMailbox": bridge.reply_mailbox_for(
                            ALICE_DID,
                            BOB_DID,
                            "cancel-long-task",
                        ),
                        "callerDid": ALICE_DID,
                    }
                },
            }
            cancel = {
                "from": ALICE_DID,
                "text": bridge.rpc_request(
                    bridge.CANCEL_TASK_METHOD,
                    params,
                    "cancel-long-task",
                )[1],
            }
            bridge._handle_inbound(fake, cancel)
            wait_for_tasks(fake)

        cancel_response = json.loads(fake.sent[-1][1])
        self.assertEqual(
            cancel_response["result"]["task"]["status"]["state"],
            bridge.TASK_STATE_CANCELED,
        )
        state = bridge.task_state_get(
            fake,
            task_id,
            expected_agent_did=BOB_DID,
            expected_owner_did=ALICE_DID,
        )
        self.assertEqual(state["state"], bridge.TASK_STATE_CANCELED)

    def test_stale_working_replay_cannot_overwrite_cancellation(self):
        fake = FakeAgent()
        task_id = "d" * 32
        fake.state["tasks"] = {task_id: {"callerDid": ALICE_DID}}
        _, submitted = bridge.task_state_set(
            fake,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_SUBMITTED,
            if_absent=True,
        )
        _, working = bridge.task_state_set(
            fake,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_WORKING,
            previous=submitted,
        )
        bridge.task_state_set(
            fake,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_CANCELED,
            previous=working,
        )
        fake.notes[bridge.task_state_ns(task_id)] = working["_raw"]

        with self.assertRaises(bridge.A2AError):
            bridge.task_state_set(
                fake,
                task_id,
                ALICE_DID,
                bridge.TASK_STATE_COMPLETED,
                previous=working,
                artifact_hash="0" * 64,
            )


class CallerTests(unittest.TestCase):
    def test_kv_set_returns_false_on_http_409(self):
        agent = object.__new__(bridge.Agent)
        agent.base = "https://example.test"
        conflict = urllib.error.HTTPError(
            "https://example.test/kv/ns/key",
            409,
            "Conflict",
            {},
            io.BytesIO(b"compare-and-set failed"),
        )
        with mock.patch("urllib.request.urlopen", side_effect=conflict):
            self.assertFalse(agent.kv_set("ns", "key", "value"))

    def test_room_read_requests_maximum_limit_and_rejects_gap(self):
        agent = object.__new__(bridge.Agent)
        captured = {}

        def fake_get(path, params=None, **kwargs):
            captured.update(params or {})
            return json.dumps(
                {"messages": [{"seq": 3, "text": "late"}], "last_seq": 3}
            ).encode()

        agent._get = fake_get
        with self.assertRaisesRegex(bridge.A2AError, "unread sequence gap"):
            agent.read_room("mb-p-test", 1)
        self.assertEqual(captured["limit"], 200)

    def test_concurrent_first_run_uses_one_persisted_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            with ThreadPoolExecutor(max_workers=2) as pool:
                agents = list(
                    pool.map(
                        lambda _: bridge.Agent(home, "https://example.test"),
                        range(2),
                    )
                )
            persisted = bridge.load_or_create_identity(home / "identity.pem")
            persisted_did = bridge.did_from_private_key(persisted)

        self.assertEqual({agent.did for agent in agents}, {persisted_did})
        self.assertEqual(len({agent.mailbox for agent in agents}), 1)

    def test_stale_client_save_preserves_server_ledger(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            server = bridge.Agent(home, "https://example.test")
            client = bridge.Agent(home, "https://example.test")
            task_id = "e" * 32
            server.state["requests"] = {"request": {"taskId": task_id}}
            server.state["tasks"] = {
                task_id: {
                    "callerDid": ALICE_DID,
                    "revision": 2,
                    "stateHash": "a" * 64,
                }
            }
            server.save_server_state()
            client.state["peerTaskStates"] = {
                "f" * 32: {
                    "agentDid": BOB_DID,
                    "ownerDid": ALICE_DID,
                    "revision": 1,
                    "stateHash": "b" * 64,
                }
            }
            client.save()

            merged = bridge.load_state(home)

        self.assertIn("request", merged["requests"])
        self.assertIn(task_id, merged["tasks"])
        self.assertIn("f" * 32, merged["peerTaskStates"])

    def test_evicted_requests_and_terminal_tasks_stay_evicted_on_disk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            agent = bridge.Agent(home, "https://example.test")
            agent.state["requests"] = {}
            agent.state["tasks"] = {}
            for index in range(bridge.REQUEST_LEDGER_MAX + 1):
                request_key = f"request-{index}"
                task_id = f"{index:032x}"
                agent.state["requests"][request_key] = {"taskId": task_id}
                agent.state["tasks"][task_id] = {
                    "callerDid": ALICE_DID,
                    "state": bridge.TASK_STATE_COMPLETED,
                    "revision": 2,
                }
            while len(agent.state["requests"]) > bridge.REQUEST_LEDGER_MAX:
                agent.state["requests"].pop(next(iter(agent.state["requests"])))
            bridge._prune_server_state(agent)
            agent.save_server_state()
            restarted = bridge.Agent(home, "https://example.test")

        self.assertEqual(
            len(restarted.state["requests"]),
            bridge.REQUEST_LEDGER_MAX,
        )
        self.assertEqual(
            len(restarted.state["tasks"]),
            bridge.REQUEST_LEDGER_MAX,
        )
        self.assertNotIn("request-0", restarted.state["requests"])
        self.assertNotIn(f"{0:032x}", restarted.state["tasks"])

    def test_second_serve_lock_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            first = bridge.acquire_serve_lock(home)
            try:
                with self.assertRaises(bridge.A2AError):
                    bridge.acquire_serve_lock(home)
            finally:
                bridge.fcntl.flock(first, bridge.fcntl.LOCK_UN)
                bridge.os.close(first)

    def test_cmd_send_emits_v1_protojson_shape(self):
        fake = FakeAgent(ALICE_KEY, ALICE_MAILBOX)
        server = FakeAgent(BOB_KEY, BOB_MAILBOX)
        task_id = "a" * 32
        server.state["tasks"] = {task_id: {"callerDid": ALICE_DID}}
        _, submitted = bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_SUBMITTED,
            if_absent=True,
        )
        _, working = bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_WORKING,
            previous=submitted,
        )
        artifact = bridge.task_artifact_set(
            server,
            task_id,
            ALICE_DID,
            {},
            working,
        )
        _, terminal = bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_COMPLETED,
            previous=working,
            artifact_hash=bridge._record_hash(artifact["_raw"]),
        )
        fake.notes = copy.deepcopy(server.notes)
        args = argparse.Namespace(
            timeout=5,
            to_mailbox=BOB_MAILBOX,
            to_did=None,
            peer_did=BOB_DID,
            text="hello",
            skill="shout",
        )

        with patch.object(
            bridge,
            "_await_response",
            return_value={"result": bridge._task_result(server, terminal)},
        ):
            result = bridge.cmd_send(fake, args)

        request = json.loads(fake.sent[0][1])
        self.assertEqual(result, 0)
        self.assertEqual(request["method"], "SendMessage")
        self.assertEqual(request["params"]["message"]["role"], "ROLE_USER")
        self.assertEqual(request["params"]["message"]["parts"], [{"text": "hello", "mediaType": "text/plain"}])
        self.assertNotIn("replyMailbox", request["params"])
        self.assertEqual(
            request["params"]["metadata"]["technocoreTransport"]["replyMailbox"],
            bridge.reply_mailbox_for(
                ALICE_DID,
                BOB_DID,
                request["id"],
            ),
        )

    def test_await_response_ignores_unattributed_and_wrong_signer(self):
        request_id = "response-1"
        good = bridge.rpc_result(request_id, {"task": {"id": "a" * 32}})

        class ReplyAgent(FakeAgent):
            def read_room(self, room, since, wait=0, deadline=None):
                return {
                    "messages": [
                        {"seq": 1, "from": "nickname", "text": good},
                        {"seq": 2, "from": BOB_DID, "text": good},
                        {"seq": 3, "from": ALICE_DID, "text": good},
                    ],
                    "last_seq": 3,
                }

        response = bridge._await_response(
            ReplyAgent(ALICE_KEY, ALICE_MAILBOX),
            "mb-p-a2a-test",
            0,
            request_id,
            time.time() + 1,
            expected_did=ALICE_DID,
        )

        self.assertIn("result", response)

    def test_save_state_is_private(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            bridge.save_state(home, {"mailbox": ALICE_MAILBOX})
            mode = (home / "state.json").stat().st_mode & 0o777

        self.assertEqual(mode, 0o600)

    def test_corrupt_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            state_path = home / "state.json"
            state_path.write_text("{not-json", encoding="utf-8")
            state_path.chmod(0o600)

            with self.assertRaises(bridge.A2AError):
                bridge.load_state(home)

    def test_forged_task_state_is_rejected(self):
        server = FakeAgent()
        task_id = "b" * 32
        server.state["tasks"] = {task_id: {"callerDid": ALICE_DID}}
        bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_SUBMITTED,
            if_absent=True,
        )
        namespace, key = bridge.task_state_ns(task_id)
        forged = json.loads(server.notes[(namespace, key)])
        forged["state"] = bridge.TASK_STATE_COMPLETED
        server.notes[(namespace, key)] = json.dumps(forged)

        with self.assertRaises(bridge.A2AError):
            bridge.task_state_get(
                server,
                task_id,
                expected_agent_did=BOB_DID,
                expected_owner_did=ALICE_DID,
            )

    def test_caller_rejects_valid_older_signed_state(self):
        server = FakeAgent()
        caller = FakeAgent(ALICE_KEY, ALICE_MAILBOX)
        task_id = "c" * 32
        server.state["tasks"] = {task_id: {"callerDid": ALICE_DID}}
        _, submitted = bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_SUBMITTED,
            if_absent=True,
        )
        _, working = bridge.task_state_set(
            server,
            task_id,
            ALICE_DID,
            bridge.TASK_STATE_WORKING,
            previous=submitted,
        )

        bridge._accept_peer_state(caller, working)
        with self.assertRaises(bridge.A2AError):
            bridge._accept_peer_state(caller, submitted)

    def test_mailbox_target_requires_pinned_peer_did(self):
        caller = FakeAgent(ALICE_KEY, ALICE_MAILBOX)
        args = argparse.Namespace(
            to_mailbox=BOB_MAILBOX,
            to_did=None,
            peer_did=None,
        )

        with self.assertRaises(bridge.A2AError):
            bridge._resolve_target(caller, args)


class SignedWriteTests(unittest.TestCase):
    def make_agent(self):
        test_agent = bridge.Agent.__new__(bridge.Agent)
        test_agent.base = "https://technocore.chat"
        test_agent.key = Ed25519PrivateKey.generate()
        test_agent.did = bridge.did_from_private_key(test_agent.key)
        return test_agent

    def test_ambiguous_failure_verifies_landed_frame_before_retry(self):
        test_agent = self.make_agent()
        frame = bridge.rpc_request(bridge.SEND_MESSAGE_METHOD, {}, "stable-id")[1]
        test_agent.read_room_tail = lambda room, deadline=None: {
            "messages": [{"seq": 17, "from": test_agent.did, "text": frame}]
        }

        with patch("agent.urllib.request.urlopen", side_effect=bridge.urllib.error.URLError("lost response")) as post:
            sequence = test_agent.say_signed(BOB_MAILBOX, frame)

        self.assertEqual(sequence, 17)
        self.assertEqual(post.call_count, 1)

    def test_transport_retry_uses_fresh_nonce_for_same_rpc_frame(self):
        test_agent = self.make_agent()
        frame = bridge.rpc_request(bridge.SEND_MESSAGE_METHOD, {}, "stable-id")[1]
        test_agent.read_room_tail = lambda room, deadline=None: {"messages": []}
        posted_bodies = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"posted":{"seq":23}}'

        def urlopen(request, timeout=None):
            posted_bodies.append(json.loads(request.data))
            if len(posted_bodies) == 1:
                raise bridge.urllib.error.URLError("connection reset")
            return Response()

        with (
            patch("agent.urllib.request.urlopen", side_effect=urlopen),
            patch("agent.time.time_ns", side_effect=[101, 202]),
            patch("agent.time.sleep"),
            patch("agent._backoff", return_value=0),
        ):
            sequence = test_agent.say_signed(BOB_MAILBOX, frame)

        self.assertEqual(sequence, 23)
        self.assertEqual([body["nonce"] for body in posted_bodies], ["101", "202"])
        self.assertEqual([body["text"] for body in posted_bodies], [frame, frame])


if __name__ == "__main__":
    unittest.main()