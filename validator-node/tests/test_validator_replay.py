
def test_replaying_same_packet_cannot_be_accepted_twice(
    validator_pipeline,
):
    validator, packet = validator_pipeline

    # Process the original packet.
    validator.process_packet(packet)

    accepted_after_first = validator._stats["accepted"]
    rejected_after_first = validator._stats["rejected"]

    # The test must establish that the original packet was accepted.
    assert accepted_after_first == 1, (
        "The original packet was not accepted; inspect the validator "
        "result before evaluating replay protection."
    )

    # Replay the identical packet.
    validator.process_packet(packet)

    assert validator._stats["received"] == 2

    # Replaying the same packet must not produce a second acceptance.
    assert validator._stats["accepted"] == accepted_after_first

    # The replay should be rejected.
    assert validator._stats["rejected"] == rejected_after_first + 1

    rejects = validator.audit.get_reject_events()

    assert len(rejects) >= 1
