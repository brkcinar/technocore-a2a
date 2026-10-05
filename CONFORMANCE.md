# technocore-room-v1 results matrix

Outcomes of the reference implementation (`agent.py` 0.3.0) against [PROFILE.md](PROFILE.md)
revision 1. Every row names the test that demonstrates it; run them with:

```bash
python3 -m unittest tests.test_conformance tests.test_agent
python3 conformance/gen_fixtures.py --check   # fixtures still match the profile generator
```

The outcome categories are deliberately distinct, so that a passing run cannot hide one behind
another:

- **completes once**: the task reaches a terminal state, and the skill ran exactly once.
- **dedup**: a repeated request returns the existing task without running the skill again.
- **fail closed**: the bridge stops or refuses, reports the exact uncertainty, and advances no
  cursor, checkpoint, or task state. Nothing is claimed about task completion.
- **at-most-once (stuck)**: no duplicate side effect, but the task does not finish without an
  operator. This is a named limitation, not recovery.
- **unsupported**: refused with a typed error before any durable state is created.
- **open**: not handled by v1.

Tests in `tests/test_conformance.py` are written `Class.test`; the rest are in `tests/test_agent.py`.

## Fixtures

| Check | Outcome | Test |
|---|---|---|
| canonical JSON, identities, derivations match the profile | pass | `FixtureTests.test_canonical_json`, `test_identities`, `test_derivations` |
| the server produces the fixture records byte for byte | pass | `FixtureTests.test_reference_server_produces_fixture_records_byte_for_byte` |
| request/response/error frames match | pass | `FixtureTests.test_frames` |
| all 13 invalid records rejected | pass | `FixtureTests.test_invalid_records_are_rejected` |
| caller checkpoint sequences (accept and reject) | pass | `FixtureTests.test_caller_checkpoint_sequences` |
| artifact binding | pass | `FixtureTests.test_artifact_binding` |

## Recovery and restart

| Scenario | Required outcome | Bridge outcome | Test |
|---|---|---|---|
| mailbox read shows a sequence gap | fail closed, cursor unchanged | fail closed | `RecoveryMatrixTests.test_gap_stops_serve_without_advancing_cursor`, `test_room_read_requests_maximum_limit_and_reports_gap` |
| mailbox room reaped and recreated (sequence restarted) | fail closed until explicit resync | fail closed | `test_room_reset_requires_explicit_backward_recovery` |
| operator acknowledges loss (`recover-cursor --skip-lost`) | skip exactly the missing range, report it, claim nothing | as required | `test_recover_cursor_acknowledges_only_missing_range` |
| request is beyond the 200-message window but still retained by the service | recover it in order, no duplicate dispatch | **open**: treated as a gap (fail closed, then lossy skip). v1 reads only the room tail. | — |
| restart after the request binding, before `SUBMITTED` was written | completes once | completes once | `RecoveryMatrixTests.test_restart_before_submitted_completes_exactly_once` |
| restart after completion, request replayed | dedup | dedup | `test_replay_recovers_same_task_without_dispatching_twice` |
| lost response, blocking replay while running | dedup, same terminal task | dedup | `test_blocking_replay_waits_for_same_terminal_task` |
| ambiguous write (timeout/5xx) | verify landed frame, then same-frame retry | as required | `test_ambiguous_failure_verifies_landed_frame_before_retry`, `test_transport_retry_uses_fresh_nonce_for_same_rpc_frame` |
| request evicted from the 1024-entry ledger | no idempotency (documented) | as documented | `test_evicted_requests_and_terminal_tasks_stay_evicted_on_disk` |

## Crash

| Scenario | Required outcome | Bridge outcome | Test |
|---|---|---|---|
| process dies while the task is `WORKING`, request replayed | no duplicate side effect; reported honestly | **at-most-once (stuck)**: replay returns `WORKING`, skill not re-run, task stays `WORKING` | `CrashMatrixTests.test_death_in_working_is_at_most_once_and_stays_working` |
| recovery of an abandoned `WORKING` task | needs a lease/reconciliation policy | **open**: v1 defines none | — |
| two `serve` processes on one home | second refuses to start | as required | `test_second_serve_lock_is_rejected` |

## Adversarial ownership

| Scenario | Required outcome | Bridge outcome | Test |
|---|---|---|---|
| cancellation signed by a DID that is not the task owner | `TASK_NOT_FOUND`, no state change, no probing | as required | `test_non_owner_cannot_cancel_or_probe_task` |
| validly signed state for the wrong task/owner/agent tuple | reject; caller checkpoint unchanged | as required | `AdversarialMatrixTests.test_signed_state_for_wrong_tuple_is_refused_by_caller`, fixtures `wrong owner`, `wrong task`, `wrong agent`, `agent impersonation` |
| valid older revision replayed to the caller | reject (rollback) | as required | `test_caller_rejects_valid_older_signed_state`, fixture sequence `rollback` |
| valid older revision written back over the server's note | refuse; skill not re-run | as required | `test_valid_older_state_cannot_trigger_duplicate_execution` |
| two validly signed records at one revision | reject (fork) | as required | fixture sequence `fork at one revision` |
| unsigned or attacker-written note | refuse on both sides; no write, server checkpoint unchanged | as required: the task is denied service, not forged | `AdversarialMatrixTests.test_attacker_written_note_is_refused_by_server`, fixtures `unsigned`, `value changed after signing` |
| non-canonical bytes or duplicate member names | reject (raw form rule) | as required (since 0.3.0) | fixtures `non-canonical whitespace`, `duplicate member` |
| spoofed `callerDid` / unsigned request | refuse before dispatch | as required | `test_spoofed_caller_did_is_rejected_before_dispatch`, `test_unsigned_attribution_is_rejected` |
| request tries to redirect the reply into another room | no reply sent | as required | `test_unsafe_reply_room_is_not_used_as_signed_relay`, `test_arbitrary_valid_reply_mailbox_is_rejected` |

What CAS shows here: compare-and-set kept honest writers from both advancing a task, but every
rejection above came from signature, tuple, chain, or checkpoint verification, never from CAS.
CAS is concurrency control, and authority comes from the pinned signed envelope (PROFILE.md §5.3).

## Size and content

| Scenario | Required outcome | Bridge outcome | Test |
|---|---|---|---|
| request frame over 4096 characters | refused before any write | unsupported (sender refuses) | `OversizeMatrixTests.test_oversize_request_is_refused_before_any_write` |
| non-text part | `CONTENT_TYPE_NOT_SUPPORTED` before any task or ledger entry | unsupported | `OversizeMatrixTests.test_non_text_part_creates_no_task`, `test_non_text_parts_return_typed_a2a_error` |
| skill output too large for a note | terminal, typed failure; no task left `WORKING` | `FAILED` bound to an `ARTIFACT_TOO_LARGE` artifact (since 0.3.0; previously stuck in `WORKING`) | `OversizeMatrixTests.test_oversize_skill_output_fails_the_task_instead_of_wedging_it` |
| blocking (`returnImmediately: false`) response too large for one frame | delivered, or refused with a typed error | **open**: the response is dropped; the caller must read the records directly (the reference caller always does) | — |
| URL or file content | never fetched automatically | as required: not fetched; no integrity binding defined in v1 | — (no fetch code path exists) |

## Not yet covered

- **Second implementation.** These fixtures were written from the profile, but a client written
  independently from PROFILE.md (in another language, ideally) is the real test of whether
  the profile is complete.
- **Live interop run** of the matrix against technocore.chat, rather than the in-memory service.
- The four **open** rows above.
