import os
import sys
import json
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
VAL_SRC = os.path.join(ROOT, 'validator-node', 'src')
CAR_SRC = os.path.join(ROOT, 'car-producer',   'src')
REL_SRC = os.path.join(ROOT, 'relay-node',     'src')

sys.path.insert(0, VAL_SRC)
sys.path.insert(0, CAR_SRC)
sys.path.insert(0, REL_SRC)

from zkp_verifier      import ZKPVerifier, CommitmentResult
from crypto_engine     import CryptoEngine
from sensor_simulator  import SensorSimulator
from packet_builder    import PacketBuilder
from signer            import PacketSigner
from encryptor         import PacketEncryptor
from decryptor         import RelayDecryptor
from reencryptor       import RelayReencryptor


# ── Pipeline fixture ──────────────────────────────────────────────

@pytest.fixture(scope='module')
def pipeline():
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False, inject_anomalies=False,
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    car_eng   = CryptoEngine(node_id='mercedes_car')
    relay_eng = CryptoEngine(node_id='relay_01')
    cp        = car_eng.new_session()
    rp        = relay_eng.new_session()
    car_eng.complete_handshake(rp)
    relay_eng.complete_handshake(cp)

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
        'sim':     sim,
        'builder': builder,
        'signer':  signer,
        'enc':     enc,
        'dec':     dec,
        'reenc':   reenc,
        'val_eng': val_eng,
    }


@pytest.fixture
def verifier():
    return ZKPVerifier(node_id='fia_validator_test')


def make_val_packet_with_commit(pipeline):
    """Full pipeline packet with ZKP commitment."""
    p      = pipeline
    frame  = p['sim'].get_next_frame()
    packet = p['builder'].build(frame)
    signed = p['signer'].sign_packet(packet)

    # Generate commitment on car side
    commit = ZKPVerifier.generate_commitment(
        signed['payload']
    )

    enc    = p['enc'].encrypt_packet(signed)
    dec    = p['dec'].decrypt(enc)
    reenc  = p['reenc'].reencrypt(dec)
    pt     = p['val_eng'].decrypt(
        nonce=reenc['nonce_bytes'],
        ciphertext=reenc['ciphertext_bytes'],
        associated_data=reenc['header'],
    )
    result = dict(reenc)
    result['payload_bytes']  = pt
    result['original_node']  = 'mercedes_car'
    result['zkp_commitment'] = commit['commitment']
    result['zkp_nonce']      = commit['nonce']
    return result


# ── CommitmentResult tests ────────────────────────────────────────

class TestCommitmentResult:

    def test_verified_true(self):
        r = CommitmentResult(
            verified=True, reason='commitment_valid'
        )
        assert r.verified is True

    def test_verified_false(self):
        r = CommitmentResult(
            verified=False, reason='mismatch'
        )
        assert r.verified is False

    def test_to_dict_structure(self):
        r = CommitmentResult(
            verified=True,
            reason='commitment_valid',
            commitment='abc123',
            computed='abc123',
        )
        d = r.to_dict()
        assert 'verified'    in d
        assert 'reason'      in d
        assert 'commitment'  in d
        assert 'computed'    in d
        assert 'verified_at' in d

    def test_has_timestamp(self):
        r = CommitmentResult(
            verified=True, reason='test'
        )
        assert r.verified_at is not None


# ── Commitment generation tests ───────────────────────────────────

class TestCommitmentGeneration:

    def test_generates_commitment_string(self):
        payload = b'{"Speed":287.4}'
        result  = ZKPVerifier.generate_commitment(payload)
        assert 'commitment' in result
        assert 'nonce'      in result
        assert len(result['commitment']) == 64  # SHA256 hex

    def test_generates_nonce(self):
        payload = b'test payload'
        result  = ZKPVerifier.generate_commitment(payload)
        assert len(result['nonce']) == 64   # 32 bytes hex

    def test_different_payloads_different_commitments(self):
        p1 = b'{"Speed":100}'
        p2 = b'{"Speed":200}'
        r1 = ZKPVerifier.generate_commitment(p1)
        r2 = ZKPVerifier.generate_commitment(p2)
        assert r1['commitment'] != r2['commitment']

    def test_same_payload_different_nonce(self):
        """Each call generates fresh nonce."""
        payload = b'{"Speed":287.4}'
        r1 = ZKPVerifier.generate_commitment(payload)
        r2 = ZKPVerifier.generate_commitment(payload)
        assert r1['nonce']      != r2['nonce']
        assert r1['commitment'] != r2['commitment']

    def test_custom_nonce_accepted(self):
        payload = b'test'
        nonce   = os.urandom(32)
        result  = ZKPVerifier.generate_commitment(
            payload, nonce_bytes=nonce
        )
        assert result['nonce'] == nonce.hex()

    def test_empty_payload_commits(self):
        result = ZKPVerifier.generate_commitment(b'')
        assert len(result['commitment']) == 64


# ── Commitment verification tests ─────────────────────────────────

class TestCommitmentVerification:

    def test_valid_commitment_verified(self, verifier):
        payload = b'{"Speed":287.4,"RPM":12500}'
        commit  = ZKPVerifier.generate_commitment(payload)
        result  = verifier.verify_commitment(
            payload_bytes=payload,
            commitment=commit['commitment'],
            nonce=commit['nonce'],
        )
        assert result.verified is True
        assert result.reason   == 'commitment_valid'

    def test_tampered_payload_fails(self, verifier):
        payload  = b'{"Speed":287.4}'
        commit   = ZKPVerifier.generate_commitment(payload)
        tampered = b'{"Speed":999.9}'
        result   = verifier.verify_commitment(
            payload_bytes=tampered,
            commitment=commit['commitment'],
            nonce=commit['nonce'],
        )
        assert result.verified is False
        assert result.reason   == 'commitment_mismatch'

    def test_wrong_nonce_fails(self, verifier):
        payload      = b'{"Speed":287.4}'
        commit       = ZKPVerifier.generate_commitment(payload)
        wrong_nonce  = os.urandom(32).hex()
        result       = verifier.verify_commitment(
            payload_bytes=payload,
            commitment=commit['commitment'],
            nonce=wrong_nonce,
        )
        assert result.verified is False

    def test_invalid_nonce_format_fails(self, verifier):
        payload = b'test'
        commit  = ZKPVerifier.generate_commitment(payload)
        result  = verifier.verify_commitment(
            payload_bytes=payload,
            commitment=commit['commitment'],
            nonce='not-valid-hex!!!',
        )
        assert result.verified is False
        assert result.reason   == 'invalid_nonce_format'

    def test_verified_count_increments(self, verifier):
        initial = verifier.verified_count
        payload = b'test payload'
        commit  = ZKPVerifier.generate_commitment(payload)
        verifier.verify_commitment(
            payload_bytes=payload,
            commitment=commit['commitment'],
            nonce=commit['nonce'],
        )
        assert verifier.verified_count == initial + 1

    def test_failed_count_increments(self, verifier):
        initial  = verifier.failed_count
        payload  = b'{"Speed":100}'
        commit   = ZKPVerifier.generate_commitment(payload)
        tampered = b'{"Speed":999}'
        verifier.verify_commitment(
            payload_bytes=tampered,
            commitment=commit['commitment'],
            nonce=commit['nonce'],
        )
        assert verifier.failed_count == initial + 1

    def test_commitment_matches_computed(self, verifier):
        payload = b'test'
        commit  = ZKPVerifier.generate_commitment(payload)
        result  = verifier.verify_commitment(
            payload_bytes=payload,
            commitment=commit['commitment'],
            nonce=commit['nonce'],
        )
        assert result.commitment == result.computed


# ── Packet verification tests ─────────────────────────────────────

class TestPacketVerification:

    def test_packet_with_valid_commitment(
        self, verifier, pipeline
    ):
        pkt    = make_val_packet_with_commit(pipeline)
        result = verifier.verify_packet(pkt)
        assert result.verified is True

    def test_packet_without_commitment_skipped(
        self, verifier, pipeline
    ):
        p      = pipeline
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
        # No zkp_commitment or zkp_nonce

        result = verifier.verify_packet(pkt)
        assert result.verified is True
        assert result.reason   == 'no_commitment_skipped'

    def test_skipped_count_increments(
        self, verifier, pipeline
    ):
        initial = verifier.skipped_count
        p       = pipeline
        frame   = p['sim'].get_next_frame()
        packet  = p['builder'].build(frame)
        signed  = p['signer'].sign_packet(packet)
        enc     = p['enc'].encrypt_packet(signed)
        dec     = p['dec'].decrypt(enc)
        reenc   = p['reenc'].reencrypt(dec)
        pt      = p['val_eng'].decrypt(
            nonce=reenc['nonce_bytes'],
            ciphertext=reenc['ciphertext_bytes'],
            associated_data=reenc['header'],
        )
        pkt = dict(reenc)
        pkt['payload_bytes'] = pt
        verifier.verify_packet(pkt)
        assert verifier.skipped_count == initial + 1

    def test_tampered_packet_fails(
        self, verifier, pipeline
    ):
        pkt      = make_val_packet_with_commit(pipeline)
        tampered = bytearray(pkt['payload_bytes'])
        tampered[5] ^= 0xFF
        pkt['payload_bytes'] = bytes(tampered)
        result = verifier.verify_packet(pkt)
        assert result.verified is False
        assert result.reason   == 'commitment_mismatch'

    def test_missing_payload_fails(
        self, verifier, pipeline
    ):
        pkt = make_val_packet_with_commit(pipeline)
        pkt.pop('payload_bytes', None)
        result = verifier.verify_packet(pkt)
        assert result.verified is False
        assert result.reason   == 'missing_payload_bytes'

    def test_packet_result_annotated(
        self, verifier, pipeline
    ):
        pkt    = make_val_packet_with_commit(pipeline)
        batch  = [pkt]
        ok, failed = verifier.verify_batch(batch)
        assert len(ok) == 1
        assert 'zkp_result' in ok[0]


# ── Batch tests ───────────────────────────────────────────────────

class TestBatchZKP:

    def test_batch_all_valid(self, verifier, pipeline):
        batch = [
            make_val_packet_with_commit(pipeline)
            for _ in range(5)
        ]
        ok, failed = verifier.verify_batch(batch)
        assert len(ok)     == 5
        assert len(failed) == 0

    def test_batch_with_tampered_packet(
        self, verifier, pipeline
    ):
        batch = []
        for i in range(3):
            pkt = make_val_packet_with_commit(pipeline)
            if i == 1:
                tampered = bytearray(pkt['payload_bytes'])
                tampered[3] ^= 0xFF
                pkt['payload_bytes'] = bytes(tampered)
            batch.append(pkt)

        ok, failed = verifier.verify_batch(batch)
        assert len(ok)     == 2
        assert len(failed) == 1

    def test_batch_total_equals_input(
        self, verifier, pipeline
    ):
        batch = [
            make_val_packet_with_commit(pipeline)
            for _ in range(4)
        ]
        ok, failed = verifier.verify_batch(batch)
        assert len(ok) + len(failed) == 4

    def test_batch_result_contains_zkp_result(
        self, verifier, pipeline
    ):
        batch  = [make_val_packet_with_commit(pipeline)]
        ok, _  = verifier.verify_batch(batch)
        assert 'zkp_result' in ok[0]

    def test_batch_empty_input(self, verifier):
        ok, failed = verifier.verify_batch([])
        assert len(ok)     == 0
        assert len(failed) == 0


# ── Stats tests ───────────────────────────────────────────────────

class TestZKPStats:

    def test_initial_counts_zero(self):
        v = ZKPVerifier(node_id='fresh')
        assert v.verified_count == 0
        assert v.failed_count   == 0
        assert v.skipped_count  == 0

    def test_counts_after_mixed_operations(
        self, pipeline
    ):
        v = ZKPVerifier(node_id='stats_test')

        # Valid commitment
        pkt1 = make_val_packet_with_commit(pipeline)
        v.verify_packet(pkt1)

        # Tampered
        pkt2 = make_val_packet_with_commit(pipeline)
        pkt2['payload_bytes'] = b'tampered'
        v.verify_packet(pkt2)

        # No commitment (skip)
        pkt3 = make_val_packet_with_commit(pipeline)
        pkt3.pop('zkp_commitment', None)
        pkt3.pop('zkp_nonce',      None)
        v.verify_packet(pkt3)

        assert v.verified_count == 1
        assert v.failed_count   == 1
        assert v.skipped_count  == 1