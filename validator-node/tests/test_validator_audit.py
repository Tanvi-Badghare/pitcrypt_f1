
from copy import deepcopy

from packet_builder import PacketBuilder


def test_header_mismatch_creates_rejection_audit_event(
    validator_pipeline,
):
    validator, packet = validator_pipeline
    tampered_packet = deepcopy(packet)

    fields = PacketBuilder.parse_header(tampered_packet["header"])
    header_sequence = fields["sequence_no"]

    # Alter outer metadata only, leaving the binary header unchanged.
    tampered_packet["sequence_no"] = header_sequence + 1

    result = validator.process_packet(tampered_packet)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["rejected"] == 1
    assert validator._stats["accepted"] == 0
    assert validator._stats["flagged"] == 0

    reject_events = validator.audit.get_reject_events()

    assert len(reject_events) == 1
    assert reject_events[0].reason == "header_metadata_mismatch"


def test_audit_rejection_count_matches_validator_counter(
    validator_pipeline,
):
    validator, packet = validator_pipeline
    tampered_packet = deepcopy(packet)

    fields = PacketBuilder.parse_header(tampered_packet["header"])
    tampered_packet["sequence_no"] = fields["sequence_no"] + 1

    validator.process_packet(tampered_packet)

    reject_events = validator.audit.get_reject_events()

    assert validator._stats["rejected"] == len(reject_events)


def test_audit_records_multiple_rejections(
    validator_pipeline,
):
    validator, packet = validator_pipeline

    # Two independent processing attempts with invalid outer metadata.
    for offset in (1, 2):
        tampered_packet = deepcopy(packet)
        fields = PacketBuilder.parse_header(tampered_packet["header"])
        tampered_packet["sequence_no"] = fields["sequence_no"] + offset

        validator.process_packet(tampered_packet)

    assert validator._stats["received"] == 2
    assert validator._stats["rejected"] == 2
    assert validator._stats["accepted"] == 0

    reject_events = validator.audit.get_reject_events()

    assert len(reject_events) == 2
    assert all(
        event.reason == "header_metadata_mismatch"
        for event in reject_events
    )
