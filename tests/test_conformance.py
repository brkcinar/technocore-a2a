"""agent.py against the technocore-room-v1 profile.

FixtureTests check agent.py against conformance/fixtures/v1/, which conformance/gen_fixtures.py
writes from PROFILE.md without importing agent.py. The *MatrixTests classes are the rows of
CONFORMANCE.md; each test name there maps to one method here or in test_agent.py.
"""

import argparse
import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent as bridge
import test_agent as helpers
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "conformance" / "fixtures" / "v1"


def load(name):
    return json.loads((FIXTURES / name).read_text())


VALID = load("valid.json")
INVALID = load("invalid-records.json")
CHECKPOINTS = load("caller-checkpoints.json")


def fixture_key(label):
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(VALID["identities"][label]["seedHex"])
    )


def fixture_agent(label, mailbox=VALID["frames"]["mailbox"]):
    return helpers.FakeAgent(fixture_key(label), mailbox)


def verified(raw, *, kind, task_id, agent_did, owner_did):
    return bridge._verify_record(
        raw,
        kind=kind,
        task_id=task_id,
        expected_agent_did=agent_did,
        expected_owner_did=owner_did,
    )


class FixtureTests(unittest.TestCase):
    def test_fixtures_are_fresh(self):
        spec = importlib.util.spec_from_file_location(
            "gen_fixtures", ROOT / "conformance" / "gen_fixtures.py"
        )
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        for name, document in generator.build().items():
            self.assertEqual(
                (FIXTURES / name).read_text(),
                generator.render(document),
                f"{name} is stale - run conformance/gen_fixtures.py",
            )

    def test_canonical_json(self):
        for case in VALID["canonicalJson"]:
            with self.subTest(case["name"]):
                self.assertEqual(bridge._dumps(case["value"]), case["canonical"])

    def test_identities(self):
        for label, identity in VALID["identities"].items():
            with self.subTest(label):
                did = bridge.did_from_private_key(fixture_key(label))
                self.assertEqual(did, identity["did"])
                self.assertTrue(bridge.valid_did_key(did))
                bridge.public_key_from_did(did)

    def test_derivations(self):
        derivations = VALID["derivations"]
        for case in derivations["replyRoom"]:
            with self.subTest(requestId=case["requestId"]):
                room = bridge.reply_mailbox_for(
                    case["callerDid"], case["agentDid"], case["requestId"]
                )
                self.assertEqual(room, case["room"])
                self.assertTrue(bridge.valid_mailbox(room))
        for case in derivations["requestKey"]:
            self.assertEqual(
                bridge._request_key(case["callerDid"], case["requestId"]), case["key"]
            )
        request_hash = derivations["requestHash"]
        self.assertEqual(
            bridge._record_hash(bridge._dumps(request_hash["params"])),
            request_hash["hash"],
        )
        for case in derivations["notes"]:
            self.assertEqual(list(bridge.task_state_ns(case["taskId"])), case["state"])
            self.assertEqual(list(bridge.task_artifact_ns(case["taskId"])), case["artifact"])
        did_note = derivations["didNote"]
        self.assertEqual(
            ("did-" + bridge.did_fingerprint(did_note["did"])[0], bridge.did_fingerprint(did_note["did"])[1]),
            (did_note["namespace"], did_note["key"]),
        )

    def test_reference_server_produces_fixture_records_byte_for_byte(self):
        for name, chain in VALID["taskChains"].items():
            with self.subTest(name):
                server = fixture_agent("bob")
                task_id = chain["taskId"]
                server.state["tasks"] = {task_id: {"callerDid": chain["ownerDid"]}}
                previous = None
                produced = []
                for record in chain["records"]:
                    if record["kind"] == "task-artifact":
                        artifact = json.loads(record["raw"])["artifact"]
                        artifact_record = bridge.task_artifact_set(
                            server, task_id, chain["ownerDid"], artifact, previous
                        )
                        produced.append(artifact_record["_raw"])
                        continue
                    state = json.loads(record["raw"])
                    written, previous = bridge.task_state_set(
                        server,
                        task_id,
                        chain["ownerDid"],
                        state["state"],
                        previous=previous,
                        if_absent=previous is None,
                        artifact_hash=state.get("artifactHash"),
                    )
                    self.assertTrue(written)
                    produced.append(previous["_raw"])
                self.assertEqual(produced, [record["raw"] for record in chain["records"]])
                self.assertEqual(
                    [bridge._record_hash(raw) for raw in produced],
                    [record["hash"] for record in chain["records"]],
                )

    def test_valid_chains_verify_and_bind(self):
        chain = VALID["taskChains"]["completed"]
        for record in chain["records"]:
            verified(
                record["raw"],
                kind=record["kind"],
                task_id=chain["taskId"],
                agent_did=chain["agentDid"],
                owner_did=chain["ownerDid"],
            )
        terminal = verified(
            chain["records"][3]["raw"],
            kind="task-state",
            task_id=chain["taskId"],
            agent_did=chain["agentDid"],
            owner_did=chain["ownerDid"],
        )
        artifact = verified(
            chain["records"][2]["raw"],
            kind="task-artifact",
            task_id=chain["taskId"],
            agent_did=chain["agentDid"],
            owner_did=chain["ownerDid"],
        )
        bridge._validate_artifact_binding(terminal, artifact)

    def test_frames(self):
        frames = VALID["frames"]
        request = frames["sendMessageRequest"]
        _, frame = bridge.rpc_request(
            bridge.SEND_MESSAGE_METHOD, request["params"], request["requestId"]
        )
        self.assertEqual(frame, request["frame"])

        chain = VALID["taskChains"]["completed"]
        server = fixture_agent("bob")
        namespace, key = bridge.task_artifact_ns(chain["taskId"])
        server.notes[(namespace, key)] = chain["records"][2]["raw"]
        for index, name in ((0, "submittedResponse"), (3, "completedResponse")):
            with self.subTest(name):
                record = verified(
                    chain["records"][index]["raw"],
                    kind="task-state",
                    task_id=chain["taskId"],
                    agent_did=chain["agentDid"],
                    owner_did=chain["ownerDid"],
                )
                self.assertEqual(
                    bridge.rpc_result(request["requestId"], bridge._task_result(server, record)),
                    frames[name],
                )
                task = json.loads(frames[name])["result"]["task"]
                bridge._state_record_from_task(
                    task,
                    expected_agent_did=chain["agentDid"],
                    expected_owner_did=chain["ownerDid"],
                )

        expected_errors = {case["case"]: case["frame"] for case in frames["errors"]}
        request_id = request["requestId"]
        task_id = chain["taskId"]
        self.assertEqual(
            bridge.rpc_error(
                request_id,
                -32005,
                "only text parts are supported",
                reason="CONTENT_TYPE_NOT_SUPPORTED",
                metadata={"supportedMediaType": "text/plain"},
            ),
            expected_errors["unsupported content"],
        )
        self.assertEqual(
            bridge.rpc_error(
                request_id, -32602, "message.messageId is required", field="message.messageId"
            ),
            expected_errors["missing messageId"],
        )
        self.assertEqual(
            bridge.rpc_error(
                request_id, -32001, "task not found", reason="TASK_NOT_FOUND", metadata={"taskId": task_id}
            ),
            expected_errors["task not found"],
        )
        self.assertEqual(
            bridge.rpc_error(
                request_id,
                -32002,
                "task is not cancelable",
                reason="TASK_NOT_CANCELABLE",
                metadata={"taskId": task_id, "state": bridge.TASK_STATE_COMPLETED},
            ),
            expected_errors["task not cancelable"],
        )

    def test_invalid_records_are_rejected(self):
        for case in INVALID["cases"]:
            with self.subTest(case["name"]):
                with self.assertRaises(bridge.A2AError):
                    verified(
                        case["raw"],
                        kind=case["kind"],
                        task_id=case["taskId"],
                        agent_did=case["expectedAgentDid"],
                        owner_did=case["expectedOwnerDid"],
                    )

    def test_caller_checkpoint_sequences(self):
        for sequence in CHECKPOINTS["sequences"]:
            with self.subTest(sequence["name"]):
                caller = fixture_agent("alice")
                *prefix, last = sequence["records"]
                for raw in prefix:
                    bridge._accept_peer_state(caller, self._verify_state(raw))
                before = copy.deepcopy(caller.state.get("peerTaskStates"))
                record = self._verify_state(last)
                if sequence["expect"] == "accept":
                    bridge._accept_peer_state(caller, record)
                    checkpoint = caller.state["peerTaskStates"][CHECKPOINTS["taskId"]]
                    self.assertEqual(checkpoint["stateHash"], bridge._record_hash(last))
                else:
                    with self.assertRaises(bridge.A2AError):
                        bridge._accept_peer_state(caller, record)
                    self.assertEqual(caller.state.get("peerTaskStates"), before)

    def test_artifact_binding(self):
        for case in CHECKPOINTS["artifactBinding"]:
            with self.subTest(case["name"]):
                state = self._verify_state(case["state"])
                artifact = verified(
                    case["artifact"],
                    kind="task-artifact",
                    task_id=CHECKPOINTS["taskId"],
                    agent_did=CHECKPOINTS["agentDid"],
                    owner_did=CHECKPOINTS["ownerDid"],
                )
                if case["expect"] == "accept":
                    bridge._validate_artifact_binding(state, artifact)
                else:
                    with self.assertRaises(bridge.A2AError):
                        bridge._validate_artifact_binding(state, artifact)

    def _verify_state(self, raw):
        return verified(
            raw,
            kind="task-state",
            task_id=CHECKPOINTS["taskId"],
            agent_did=CHECKPOINTS["agentDid"],
            owner_did=CHECKPOINTS["ownerDid"],
        )


def state_of(fake, task_id):
    return json.loads(fake.notes[bridge.task_state_ns(task_id)])


def first_task_id(fake):
    return json.loads(fake.sent[0][1])["result"]["task"]["id"]


class RecoveryMatrixTests(unittest.TestCase):
    def test_gap_stops_serve_without_advancing_cursor(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir)
            agent = bridge.Agent(home, "https://example.test")
            agent.state["cursor"] = 5
            agent.save_server_state()
            agent.read_room = unittest.mock.Mock(
                side_effect=[bridge.A2AError("unread sequence gap"), KeyboardInterrupt]
            )
            args = argparse.Namespace(
                name="n", description="d", serve_card=False, card_host="", card_port=0
            )
            with patch.object(bridge, "_handle_inbound") as handle, patch.object(bridge.time, "sleep"):
                bridge.cmd_serve(agent, args)

            self.assertEqual(bridge.load_state(home)["cursor"], 5)
            handle.assert_not_called()

    def test_restart_before_submitted_completes_exactly_once(self):
        fake = helpers.FakeAgent()
        frame = helpers.send_frame(request_id="bound-not-submitted")
        params = json.loads(frame["text"])["params"]
        task_id, _ = bridge._remember_request(
            fake,
            helpers.ALICE_DID,
            "bound-not-submitted",
            bridge._record_hash(bridge._dumps(params)),
        )
        restarted = helpers.FakeAgent()
        restarted.state = copy.deepcopy(fake.state)

        with patch.object(bridge, "dispatch_skill", wraps=bridge.dispatch_skill) as dispatch:
            bridge._handle_inbound(restarted, frame)
            helpers.wait_for_tasks(restarted)
            bridge._handle_inbound(restarted, frame)
            helpers.wait_for_tasks(restarted)

        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(state_of(restarted, task_id)["state"], bridge.TASK_STATE_COMPLETED)
        self.assertEqual({first_task_id(restarted)}, {json.loads(t)["result"]["task"]["id"] for _, t in restarted.sent})


class CrashMatrixTests(unittest.TestCase):
    def test_death_in_working_is_at_most_once_and_stays_working(self):
        fake = helpers.FakeAgent()
        frame = helpers.send_frame(request_id="dies-in-working")
        with patch.object(bridge, "_start_task"):  # the process dies before the skill runs
            bridge._handle_inbound(fake, frame)
        task_id = first_task_id(fake)
        self.assertEqual(state_of(fake, task_id)["state"], bridge.TASK_STATE_WORKING)

        restarted = helpers.FakeAgent()
        restarted.state = copy.deepcopy(fake.state)
        restarted.notes = copy.deepcopy(fake.notes)
        with patch.object(bridge, "dispatch_skill") as dispatch:
            bridge._handle_inbound(restarted, frame)
            helpers.wait_for_tasks(restarted)

        dispatch.assert_not_called()
        replay = helpers.response_body(restarted)["result"]["task"]
        self.assertEqual(replay["id"], task_id)
        self.assertEqual(replay["status"]["state"], bridge.TASK_STATE_WORKING)
        self.assertEqual(state_of(restarted, task_id)["state"], bridge.TASK_STATE_WORKING)


class AdversarialMatrixTests(unittest.TestCase):
    def _working_task(self):
        fake = helpers.FakeAgent()
        with patch.object(bridge, "_start_task"):
            bridge._handle_inbound(fake, helpers.send_frame(request_id="victim"))
        return fake, first_task_id(fake)

    def test_attacker_written_note_is_refused_by_server(self):
        fake, task_id = self._working_task()
        checkpoint = copy.deepcopy(fake.state["tasks"][task_id])
        note_key = bridge.task_state_ns(task_id)
        forged = dict(state_of(fake, task_id), state=bridge.TASK_STATE_COMPLETED)
        forged.pop("signature")
        fake.notes[note_key] = bridge._dumps(forged)
        writes_before = len(fake.note_history)

        with self.assertRaises(bridge.A2AError):
            bridge._handle_inbound(fake, helpers.send_frame(request_id="victim"))
        cancel = {
            "from": helpers.ALICE_DID,
            "text": bridge.rpc_request(
                bridge.CANCEL_TASK_METHOD,
                {
                    "id": task_id,
                    "metadata": {
                        "technocoreTransport": {
                            "replyMailbox": bridge.reply_mailbox_for(helpers.ALICE_DID, helpers.BOB_DID, "c1"),
                            "callerDid": helpers.ALICE_DID,
                        }
                    },
                },
                "c1",
            )[1],
        }
        with self.assertRaises(bridge.A2AError):
            bridge._handle_inbound(fake, cancel)

        self.assertEqual(len(fake.note_history), writes_before)
        self.assertEqual(fake.state["tasks"][task_id], checkpoint)

    def test_signed_state_for_wrong_tuple_is_refused_by_caller(self):
        fake, task_id = self._working_task()
        caller = helpers.FakeAgent(helpers.ALICE_KEY, helpers.ALICE_MAILBOX)
        caller.notes = fake.notes  # both read the same public note store
        bridge._accept_peer_state(
            caller,
            bridge.task_state_get(
                fake, task_id, expected_agent_did=helpers.BOB_DID, expected_owner_did=helpers.ALICE_DID
            ),
        )
        before = copy.deepcopy(caller.state["peerTaskStates"])

        other = "d" * 32
        fake.state["tasks"][other] = {"callerDid": helpers.CAROL_DID}
        _, carols = bridge.task_state_set(fake, other, helpers.CAROL_DID, bridge.TASK_STATE_SUBMITTED, if_absent=True)
        fake.notes[bridge.task_state_ns(task_id)] = carols["_raw"]

        with self.assertRaisesRegex(bridge.A2AError, "unexpected taskId"):
            bridge.task_state_get(
                caller, task_id, expected_agent_did=helpers.BOB_DID, expected_owner_did=helpers.ALICE_DID
            )
        self.assertEqual(caller.state["peerTaskStates"], before)


class OversizeMatrixTests(unittest.TestCase):
    def test_oversize_request_is_refused_before_any_write(self):
        sender = object.__new__(bridge.Agent)
        with patch("urllib.request.urlopen") as urlopen:
            with self.assertRaises(bridge.CapacityError):
                sender.say_signed("mb-p-target", "x" * (bridge.MESSAGE_MAX_CHARS + 1))
        urlopen.assert_not_called()

    def test_non_text_part_creates_no_task(self):
        fake = helpers.FakeAgent()
        bridge._handle_inbound(fake, helpers.send_frame(parts=[{"url": "https://example.test/x"}]))

        self.assertEqual(helpers.response_body(fake)["error"]["code"], -32005)
        self.assertEqual(fake.notes, {})
        self.assertEqual(fake.state.get("requests", {}), {})

    def test_oversize_skill_output_fails_the_task_instead_of_wedging_it(self):
        fake = helpers.FakeAgent()
        with patch.object(bridge, "dispatch_skill", return_value=(True, "x" * bridge.NOTE_MAX_CHARS)):
            bridge._handle_inbound(fake, helpers.send_frame(request_id="huge"))
            helpers.wait_for_tasks(fake)
        task_id = first_task_id(fake)

        terminal = bridge.task_state_get(
            fake, task_id, expected_agent_did=helpers.BOB_DID, expected_owner_did=helpers.ALICE_DID
        )
        artifact = bridge.task_artifact_get(
            fake, task_id, expected_agent_did=helpers.BOB_DID, expected_owner_did=helpers.ALICE_DID
        )
        self.assertEqual(terminal["state"], bridge.TASK_STATE_FAILED)
        self.assertEqual(artifact["artifact"]["reason"], "ARTIFACT_TOO_LARGE")
        bridge._validate_artifact_binding(terminal, artifact)
        self.assertLessEqual(len(artifact["_raw"]), bridge.NOTE_MAX_CHARS)


if __name__ == "__main__":
    unittest.main()
