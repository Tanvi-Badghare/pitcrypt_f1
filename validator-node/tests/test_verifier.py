import os
import sys
import json
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT     = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
VAL_SRC  = os.path.join(ROOT, 'validator-node', 'src')
CAR_SRC  = os.path.join(ROOT, 'car-producer',   'src')
REL_SRC  = os.path.join(ROOT, 'relay-node',     'src')

sys.path.insert(0, VAL_SRC)
sys.path.insert(0, CAR_SRC)
sys.path.insert(0, REL_SRC)

from signature_verifier   import (
    ValidatorSignatureVerifier,
    SignatureVerificationError,
)
from crypto_engine        import CryptoEngine
from sensor_simulator     import SensorSimulator
from packet_builder       import PacketBuilder
from signer               import PacketSigner
from encryptor            import PacketEncryptor
from decryptor            import RelayDecryptor
from reencryptor          import RelayReencryptor
from cryptography.exceptions import InvalidSignature


# ── Shared fixture ────────────────────────────────────────────────

@pytest.fixture(scope='module')
def full_pipeline():
    """
    Complete pipeline fixture:
    Car → Relay → Validator (decrypted and ready to verify)
    """
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False, inject_anomalies=False,
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    # Car → Relay ECDH
    car_eng   = CryptoEngine(node_id='mercedes_car')
    relay_eng = CryptoEngine(node_id='relay_01')
    cp        = car_eng.new_session()
    rp        = relay_eng.new_session()
    car_eng.complete_handshake(rp)
    relay_eng.complete_handshake(cp)

    # Relay → Validator ECDH
    relay_val = CryptoEngine(node_id='relay_val')
    val_eng   = CryptoEngine(node_id='validator')
    rvp       = relay_val.new_session()
    vp        = val_eng.new_session()
    relay_val.complete_handshake(vp)
    val_eng.complete_handshake(rvp)

    enc   = PacketEncryptor(
        crypto_engine=car_eng, node_id='mercedes_car'
    )
    dec   = RelayDecryptor(node_id='relay_01')
    dec.register_session('mercedes_car', relay_eng)

    reenc = RelayReencryptor(node_id='relay_01')
    reenc.register_validator_session(relay_val)

    return {
        'sim':      sim,
        'builder':  builder,
        'signer':   signer,
        'enc':      enc,
        'dec':      dec,
        'reenc':    reenc,
        'val_eng':  val_eng,
    }


@pytest.fixture
def val_packet(full_pipeline):
    """Build one complete validator-ready packet."""
    p       = full_pipeline
    frame   = p['sim'].get_next_frame()
    packet  = p['builder'].build(frame)
    signed  = p['signer'].sign_packet(packet)
    enc     = p['enc'].encrypt_packet(signed)
    dec     = p['dec'].decrypt(enc)
    reenc   = p['reenc'].reencrypt(dec)

    plaintext = p['val_eng'].decrypt(
        nonce=reenc['nonce_bytes'],
        ciphertext=reenc['ciphertext_bytes'],
        associated_data=reenc['header'],
    )
    result = dict(reenc)
    result['payload_bytes'] = plaintext
    result['original_node'] = 'mercedes_car'
    return result, signed


@pytest.fixture
def verifier(full_pipeline):
    """ValidatorSignatureVerifier with mercedes_car registered."""
    v = ValidatorSignatureVerifier(node_id='fia_validator')
    v.register_node(
        'mercedes_car',
        full_pipeline['signer'].public_key_bytes,
    )
    return v


# ── Registry tests ────────────────────────────────────────────────

class TestRegistry:

    def test_register_node(self, full_pipeline):
        v = ValidatorSignatureVerifier(
            node_id='test_validator'
        )
        v.register_node(
            'mercedes_car',
            full_pipeline['signer'].public_key_bytes,
        )
        assert v.is_registered('mercedes_car')

    def test_invalid_key_length_raises(self):
        v = ValidatorSignatureVerifier(node_id='test')
        with pytest.raises(ValueError):
            v.register_node('test_node', b'tooshort')

    def test_registered_nodes_list(self, verifier):
        assert 'mercedes_car' in verifier.registered_nodes

    def test_is_registered_false_for_unknown(self, verifier):
        assert verifier.is_registered('unknown_car') is False

    def test_deregister_node(self, full_pipeline):
        v = ValidatorSignatureVerifier(node_id='test')
        v.register_node(
            'mercedes_car',
            full_pipeline['signer'].public_key_bytes,
        )
        v.deregister_node('mercedes_car')
        assert not v.is_registered('mercedes_car')

    def test_register_two_teams(self, full_pipeline):
        v          = ValidatorSignatureVerifier(node_id='test')
        rbr_signer = PacketSigner(node_id='redbull_car')
        v.register_node(
            'mercedes_car',
            full_pipeline['signer'].public_key_bytes,
        )
        v.register_node(
            'redbull_car',
            rbr_signer.public_key_bytes,
        )
        assert len(v.registered_nodes) == 2
        assert 'mercedes_car' in v.registered_nodes
        assert 'redbull_car'  in v.registered_nodes


# ── Verification tests ────────────────────────────────────────────

class TestVerification:

    def test_valid_signature_verified(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        result = verifier.verify(pkt)
        assert result['verified'] is True

    def test_verify_returns_node_id(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        result = verifier.verify(pkt)
        assert result['node_id'] == 'mercedes_car'

    def test_verify_returns_reason(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        result = verifier.verify(pkt)
        assert result['reason'] == 'signature_valid'

    def test_verify_returns_timestamp(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        result = verifier.verify(pkt)
        assert 'verified_at' in result

    def test_verified_count_increments(
        self, verifier, full_pipeline
    ):
        p       = full_pipeline
        initial = verifier.verified_count
        for _ in range(3):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            dec    = p['dec'].decrypt(enc)
            reenc  = p['reenc'].reencrypt(dec)
            pt     = p['val_eng'].decrypt(
                nonce=reenc['nonce_bytes'],
                ciphertext=reenc['ciphertext_bytes'],
                associated_data=reenc['header'],
            )
            pkt = dict(reenc)
            pkt['payload_bytes'] = pt
            pkt['original_node'] = 'mercedes_car'
            verifier.verify(pkt)
        assert verifier.verified_count >= initial + 3


# ── Rejection tests ───────────────────────────────────────────────

class TestRejection:

    def test_unknown_node_raises(
        self, verifier, val_packet
    ):
        pkt, _          = val_packet
        bad             = dict(pkt)
        bad['original_node'] = 'unknown_car'
        with pytest.raises(SignatureVerificationError):
            verifier.verify(bad)

    def test_missing_node_id_raises(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        bad    = dict(pkt)
        bad.pop('original_node', None)
        bad.pop('node_id',       None)
        bad.pop('signer_node_id', None)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(bad)

    def test_tampered_payload_raises(
        self, verifier, val_packet
    ):
        pkt, _   = val_packet
        bad      = dict(pkt)
        tampered = bytearray(pkt['payload_bytes'])
        tampered[5] ^= 0xFF
        bad['payload_bytes'] = bytes(tampered)
        with pytest.raises(InvalidSignature):
            verifier.verify(bad)

    def test_tampered_header_raises(
        self, verifier, val_packet
    ):
        pkt, _   = val_packet
        bad      = dict(pkt)
        tampered = bytearray(pkt['header'])
        tampered[8] ^= 0xFF
        bad['header'] = bytes(tampered)
        with pytest.raises(InvalidSignature):
            verifier.verify(bad)

    def test_wrong_signature_raises(
        self, verifier, val_packet
    ):
        pkt, _                 = val_packet
        bad                    = dict(pkt)
        bad['signature_bytes'] = os.urandom(64)
        bad['signature']       = bad['signature_bytes'].hex()
        with pytest.raises(InvalidSignature):
            verifier.verify(bad)

    def test_missing_signature_raises(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        bad    = dict(pkt)
        bad.pop('signature',       None)
        bad.pop('signature_bytes', None)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(bad)

    def test_missing_payload_raises(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        bad    = dict(pkt)
        bad.pop('payload_bytes', None)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(bad)

    def test_missing_header_raises(
        self, verifier, val_packet
    ):
        pkt, _ = val_packet
        bad    = dict(pkt)
        bad['header'] = b''
        with pytest.raises(SignatureVerificationError):
            verifier.verify(bad)

    def test_rejected_count_increments(
        self, verifier, val_packet
    ):
        pkt, _   = val_packet
        bad      = dict(pkt)
        tampered = bytearray(pkt['payload_bytes'])
        tampered[0] ^= 0xFF
        bad['payload_bytes'] = bytes(tampered)
        initial  = verifier.rejected_count
        try:
            verifier.verify(bad)
        except InvalidSignature:
            pass
        assert verifier.rejected_count > initial

    def test_unknown_count_increments(
        self, verifier, val_packet
    ):
        pkt, _               = val_packet
        bad                  = dict(pkt)
        bad['original_node'] = 'totally_unknown_node'
        initial              = verifier.unknown_count
        try:
            verifier.verify(bad)
        except SignatureVerificationError:
            pass
        assert verifier.unknown_count > initial


# ── Cross-team tests ──────────────────────────────────────────────

class TestCrossTeam:

    def test_mercedes_signature_rejected_by_redbull_verifier(
        self, val_packet
    ):
        pkt, _      = val_packet
        rbr_signer  = PacketSigner(node_id='redbull_car')
        rbr_verifier = ValidatorSignatureVerifier(
            node_id='test'
        )
        rbr_verifier.register_node(
            'redbull_car', rbr_signer.public_key_bytes
        )
        with pytest.raises(SignatureVerificationError):
            rbr_verifier.verify(pkt)

    def test_both_teams_verified_independently(
        self, full_pipeline
    ):
        p = full_pipeline

        # Mercedes signer
        merc_signer = p['signer']

        # Red Bull signer
        rbr_sim     = SensorSimulator(
            team='redbull', race='Bahrain', session='R',
            add_noise=False,
        )
        rbr_builder = PacketBuilder(
            team='redbull', session='R'
        )
        rbr_signer  = PacketSigner(node_id='redbull_car')

        rbr_car_eng   = CryptoEngine(node_id='redbull_car')
        rbr_relay_eng = CryptoEngine(node_id='relay_rbr')
        rbr_relay_val = CryptoEngine(node_id='relay_rbr_val')
        rbr_val_eng   = CryptoEngine(node_id='val_rbr')

        rcp = rbr_car_eng.new_session()
        rrp = rbr_relay_eng.new_session()
        rbr_car_eng.complete_handshake(rrp)
        rbr_relay_eng.complete_handshake(rcp)

        rrvp = rbr_relay_val.new_session()
        rvp  = rbr_val_eng.new_session()
        rbr_relay_val.complete_handshake(rvp)
        rbr_val_eng.complete_handshake(rrvp)

        rbr_enc   = PacketEncryptor(
            crypto_engine=rbr_car_eng,
            node_id='redbull_car',
        )
        rbr_dec   = RelayDecryptor(node_id='relay_rbr')
        rbr_dec.register_session('redbull_car', rbr_relay_eng)
        rbr_reenc = RelayReencryptor(node_id='relay_rbr')
        rbr_reenc.register_validator_session(rbr_relay_val)

        # Build Red Bull packet
        rbr_frame  = rbr_sim.get_next_frame()
        rbr_packet = rbr_builder.build(rbr_frame)
        rbr_signed = rbr_signer.sign_packet(rbr_packet)
        rbr_enc_p  = rbr_enc.encrypt_packet(rbr_signed)
        rbr_dec_p  = rbr_dec.decrypt(rbr_enc_p)
        rbr_reenc_p = rbr_reenc.reencrypt(rbr_dec_p)
        rbr_pt     = rbr_val_eng.decrypt(
            nonce=rbr_reenc_p['nonce_bytes'],
            ciphertext=rbr_reenc_p['ciphertext_bytes'],
            associated_data=rbr_reenc_p['header'],
        )
        rbr_val_pkt = dict(rbr_reenc_p)
        rbr_val_pkt['payload_bytes'] = rbr_pt
        rbr_val_pkt['original_node'] = 'redbull_car'

        # Verifier with both teams
        v = ValidatorSignatureVerifier(node_id='fia_val')
        v.register_node(
            'mercedes_car', merc_signer.public_key_bytes
        )
        v.register_node(
            'redbull_car', rbr_signer.public_key_bytes
        )

        # Build Mercedes packet
        merc_frame  = p['sim'].get_next_frame()
        merc_packet = p['builder'].build(merc_frame)
        merc_signed = merc_signer.sign_packet(merc_packet)
        merc_enc_p  = p['enc'].encrypt_packet(merc_signed)
        merc_dec_p  = p['dec'].decrypt(merc_enc_p)
        merc_reenc_p = p['reenc'].reencrypt(merc_dec_p)
        merc_pt     = p['val_eng'].decrypt(
            nonce=merc_reenc_p['nonce_bytes'],
            ciphertext=merc_reenc_p['ciphertext_bytes'],
            associated_data=merc_reenc_p['header'],
        )
        merc_val_pkt = dict(merc_reenc_p)
        merc_val_pkt['payload_bytes'] = merc_pt
        merc_val_pkt['original_node'] = 'mercedes_car'

        # Both should verify
        assert v.verify(merc_val_pkt)['verified'] is True
        assert v.verify(rbr_val_pkt)['verified']  is True


# ── Batch tests ───────────────────────────────────────────────────

class TestBatchVerification:

    def test_batch_all_valid(self, verifier, full_pipeline):
        p     = full_pipeline
        batch = []
        for _ in range(5):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            dec    = p['dec'].decrypt(enc)
            reenc  = p['reenc'].reencrypt(dec)
            pt     = p['val_eng'].decrypt(
                nonce=reenc['nonce_bytes'],
                ciphertext=reenc['ciphertext_bytes'],
                associated_data=reenc['header'],
            )
            pkt = dict(reenc)
            pkt['payload_bytes'] = pt
            pkt['original_node'] = 'mercedes_car'
            batch.append(pkt)

        ok, failed = verifier.verify_batch(batch)
        assert len(ok)     == 5
        assert len(failed) == 0

    def test_batch_with_tampered_packet(
        self, verifier, full_pipeline
    ):
        p     = full_pipeline
        batch = []
        for i in range(3):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            dec    = p['dec'].decrypt(enc)
            reenc  = p['reenc'].reencrypt(dec)
            pt     = p['val_eng'].decrypt(
                nonce=reenc['nonce_bytes'],
                ciphertext=reenc['ciphertext_bytes'],
                associated_data=reenc['header'],
            )
            pkt = dict(reenc)
            pkt['payload_bytes'] = pt
            pkt['original_node'] = 'mercedes_car'

            # Tamper middle packet
            if i == 1:
                tampered = bytearray(pt)
                tampered[3] ^= 0xFF
                pkt['payload_bytes'] = bytes(tampered)

            batch.append(pkt)

        ok, failed = verifier.verify_batch(batch)
        assert len(ok)     == 2
        assert len(failed) == 1

    def test_batch_total_equals_input(
        self, verifier, full_pipeline
    ):
        p     = full_pipeline
        batch = []
        for _ in range(4):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            dec    = p['dec'].decrypt(enc)
            reenc  = p['reenc'].reencrypt(dec)
            pt     = p['val_eng'].decrypt(
                nonce=reenc['nonce_bytes'],
                ciphertext=reenc['ciphertext_bytes'],
                associated_data=reenc['header'],
            )
            pkt = dict(reenc)
            pkt['payload_bytes'] = pt
            pkt['original_node'] = 'mercedes_car'
            batch.append(pkt)

        ok, failed = verifier.verify_batch(batch)
        assert len(ok) + len(failed) == 4