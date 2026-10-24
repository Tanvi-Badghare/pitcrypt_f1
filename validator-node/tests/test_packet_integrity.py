
from copy import deepcopy
from unittest.mock import Mock

import pytest

from packet_builder import PacketBuilder


def test_modified_ciphertext_is_rejected(validator_pipeline):
    """A packet with modified ciphertext must not be accepted."""
    validator, packet = validator_pipeline

    tampered_packet = deepcopy(packet)
    ciphertext = tampered_packet["ciphertext_bytes"]

    assert ciphertext, "Test packet must contain ciphertext"

    # Change a ciphertext byte without changing the nonce or header.
    modified = bytearray(ciphertext)
    modified[-1] ^= 0x01
    tampered_packet["ciphertext_bytes"] = bytes(modified)

    result = validator.process_packet(tampered_packet)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["accepted"] == 0
    assert validator._stats["rejected"] == 1


def test_modified_authenticated_header_is_rejected(validator_pipeline):
    """Changing authenticated header data must invalidate the packet."""
    validator, packet = validator_pipeline

    tampered_packet = deepcopy(packet)
    header = tampered_packet["header"]

    assert header, "Test packet must contain a binary header"

    # Change a header byte without re-encrypting the packet.
    modified = bytearray(header)
    modified[-1] ^= 0x01
    tampered_packet["header"] = bytes(modified)

    result = validator.process_packet(tampered_packet)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["accepted"] == 0
    assert validator._stats["rejected"] == 1


def test_header_metadata_mismatch_stops_downstream_validation(
    validator_pipeline,
):
    """A mismatched outer sequence number must fail before later checks."""
    validator, packet = validator_pipeline

    tampered_packet = deepcopy(packet)
    fields = PacketBuilder.parse_header(tampered_packet["header"])

    tampered_packet["sequence_no"] = fields["sequence_no"] + 1

    validator.seq_checker.check = Mock(
        side_effect=AssertionError(
            "Sequence checker should not run after header mismatch"
        )
    )
    validator.zkp_verifier.verify_packet = Mock(
        side_effect=AssertionError(
            "ZKP verifier should not run after header mismatch"
        )
    )

    result = validator.process_packet(tampered_packet)

    assert result is None
    assert validator._stats["rejected"] == 1
    validator.seq_checker.check.assert_not_called()
    validator.zkp_verifier.verify_packet.assert_not_called()




from copy import deepcopy



from copy import deepcopy


def test_invalid_signature_is_not_accepted(validator_pipeline):
    validator, packet = validator_pipeline
    tampered_packet = deepcopy(packet)

    # The packet contains a 64-byte Ed25519 signature.
    assert isinstance(tampered_packet["signature_bytes"], bytes)
    assert len(tampered_packet["signature_bytes"]) == 64

    # Corrupt one bit in the signature.
    original_signature = tampered_packet["signature_bytes"]
    tampered_signature = (
        bytes([original_signature[0] ^ 0x01])
        + original_signature[1:]
    )
    tampered_packet["signature_bytes"] = tampered_signature

    # Keep the hexadecimal representation consistent with the tampering.
    tampered_packet["signature"] = tampered_signature.hex()

    result = validator.process_packet(tampered_packet)

    assert result is None
    assert validator._stats["received"] == 1
    assert validator._stats["accepted"] == 0
    assert validator._stats["rejected"] == 1
    assert validator._stats["flagged"] == 0

