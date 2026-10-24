
from copy import deepcopy

import pytest
from cryptography.exceptions import InvalidSignature

from signature_verifier import SignatureVerificationError


def test_missing_signature_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate.pop("signature_bytes", None)
    candidate.pop("signature", None)

    with pytest.raises(SignatureVerificationError, match="no signature"):
        validator.sig_verifier.verify(candidate)

    assert validator.sig_verifier.rejected_count >= 1


def test_non_hex_signature_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate.pop("signature_bytes", None)
    candidate["signature"] = "this-is-not-hex"

    with pytest.raises(
        SignatureVerificationError,
        match="valid hexadecimal",
    ):
        validator.sig_verifier.verify(candidate)


def test_wrong_signature_type_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate["signature_bytes"] = "not-bytes"

    with pytest.raises(
        SignatureVerificationError,
        match="bytes object",
    ):
        validator.sig_verifier.verify(candidate)


@pytest.mark.parametrize("signature", [b"", b"\x00" * 63, b"\x00" * 65])
def test_wrong_signature_length_is_rejected(
    validator_pipeline, signature
):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate["signature_bytes"] = signature

    with pytest.raises(
        SignatureVerificationError,
        match="Invalid signature size",
    ):
        validator.sig_verifier.verify(candidate)


def test_unregistered_node_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate["original_node"] = "unregistered_car"

    with pytest.raises(
        SignatureVerificationError,
        match="Unknown node",
    ):
        validator.sig_verifier.verify(candidate)


def test_missing_node_identity_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate.pop("original_node", None)
    candidate.pop("node_id", None)
    candidate.pop("signer_node_id", None)

    with pytest.raises(
        SignatureVerificationError,
        match="missing node identity",
    ):
        validator.sig_verifier.verify(candidate)


def test_missing_header_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate["header"] = b""

    with pytest.raises(
        SignatureVerificationError,
        match="Missing header bytes",
    ):
        validator.sig_verifier.verify(candidate)


def test_missing_payload_is_rejected(validator_pipeline):
    validator, packet = validator_pipeline
    candidate = deepcopy(packet)
    candidate["payload_bytes"] = b""

    with pytest.raises(
        SignatureVerificationError,
        match="Missing payload bytes",
    ):
        validator.sig_verifier.verify(candidate)
