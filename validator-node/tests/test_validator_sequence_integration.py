
from copy import deepcopy

from packet_builder import PacketBuilder


def test_out_of_order_packet_is_not_accepted(
    validator_multi_packet_pipeline,
):
    validator, packet1, packet2 = validator_multi_packet_pipeline

    # Read the sequence numbers embedded in the authenticated headers.
    header1 = PacketBuilder.parse_header(packet1["header"])
    header2 = PacketBuilder.parse_header(packet2["header"])

    seq1 = header1["sequence_no"]
    seq2 = header2["sequence_no"]

    assert seq2 > seq1, (
        f"Expected packet 2 to have a higher sequence number than packet 1; "
        f"got {seq1} and {seq2}"
    )

    # Deliver the newer packet first.
    validator.process_packet(deepcopy(packet2))

    accepted_after_newer = validator._stats["accepted"]
    rejected_after_newer = validator._stats["rejected"]

    assert accepted_after_newer == 1, (
        "The first delivered valid packet should be accepted by this test."
    )

    # Now deliver the older packet out of order.
    validator.process_packet(deepcopy(packet1))

    assert validator._stats["received"] == 2

    # Strict ordering must prevent the older packet from being accepted.
    assert validator._stats["accepted"] == accepted_after_newer

    # Under strict-ordering policy, the older packet should be rejected.
    assert validator._stats["rejected"] == rejected_after_newer + 1

    rejects = validator.audit.get_reject_events()
    assert rejects
