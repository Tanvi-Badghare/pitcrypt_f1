
from copy import deepcopy


def test_pipeline_rejects_wrong_signature_length(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)

    candidate["signature_bytes"] = b"\x00" * 10

    result = validator.process_packet(candidate)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["sig_failed"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0


def test_pipeline_rejects_non_hex_signature(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)

    candidate.pop("signature_bytes", None)
    candidate["signature"] = "not-valid-hex"

    result = validator.process_packet(candidate)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["sig_failed"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0


def test_pipeline_rejects_unknown_signing_node(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)

    candidate["original_node"] = "unknown_test_car"

    result = validator.process_packet(candidate)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["sig_failed"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0

from copy import deepcopy


def test_rejected_signature_does_not_advance_sequence_state(
    validator_pipeline,
):
    validator, packet = validator_pipeline

    # Capture sequence state before processing either packet.
    sequence_state_before = deepcopy(
        validator.seq_checker._last_seq
    )

    # Corrupt one byte of the signature without changing its length.
    tampered_packet = deepcopy(packet)
    signature = tampered_packet["signature_bytes"]

    assert isinstance(signature, bytes)
    assert len(signature) > 0

    tampered_packet["signature_bytes"] = (
        bytes([signature[0] ^ 1]) + signature[1:]
    )

    # The tampered packet must fail signature verification.
    rejected_result = validator.process_packet(tampered_packet)

    assert rejected_result is None
    assert validator._stats["sig_failed"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0

    # Signature failure must occur before sequence state is updated.
    assert (
        validator.seq_checker._last_seq
        == sequence_state_before
    )

    # The original, valid packet should still be processable.
    valid_result = validator.process_packet(deepcopy(packet))

    assert valid_result is not None
    assert validator._stats["received"] == 2
    assert validator._stats["sig_failed"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 1

    # Confirm that the rejection was recorded in the audit trail.
    reject_events = validator.audit.get_reject_events()
    assert reject_events


from datetime import datetime

def test_invalid_signature_audit_contains_packet_context(
    validator_pipeline,
):
    validator, packet = validator_pipeline
    tampered_packet = deepcopy(packet)

    signature = tampered_packet["signature_bytes"]
    tampered_packet["signature_bytes"] = (
        bytes([signature[0] ^ 1]) + signature[1:]
    )

    result = validator.process_packet(tampered_packet)

    assert result is None

    reject_events = validator.audit.get_reject_events()
    assert len(reject_events) == 1

    event = reject_events[0]

    assert event.decision.value == "REJECT"
    assert event.reason == "signature_invalid"
    assert event.sequence_no == packet["sequence_no"]
    assert event.node_id == packet["original_node"]
    assert event.team == packet["team"]
    assert event.session == packet["session"]

    # The rejection should retain a useful verification error.
    assert isinstance(event.details, dict)
    assert event.details.get("error")

    # Confirm that the timestamp is parseable ISO-formatted time.
    parsed_timestamp = datetime.fromisoformat(event.timestamp)
    assert parsed_timestamp.tzinfo is not None


def test_audit_summary_matches_rejection_events(
    validator_pipeline,
):
    validator, packet = validator_pipeline

    tampered_packet = deepcopy(packet)
    signature = tampered_packet["signature_bytes"]
    tampered_packet["signature_bytes"] = (
        bytes([signature[0] ^ 1]) + signature[1:]
    )

    validator.process_packet(tampered_packet)

    events = validator.audit.get_events()
    rejects = validator.audit.get_reject_events()
    summary = validator.audit.summary()

    assert summary["total"] == len(events)
    assert summary["rejected"] == len(rejects)
    assert summary["rejected"] == 1
    assert summary["accepted"] == 0
    assert summary["flagged"] == 0
    assert summary["reject_rate"] == 1.0
