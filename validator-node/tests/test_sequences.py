import os
import sys
import time
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

from sequence_checker  import (
    ValidatorSequenceChecker,
    SequenceCheckResult,
)
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


def make_val_packet(pipeline, seq_override=None):
    """Build one validator packet, optionally override seq."""
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
    result = dict(reenc)
    result['payload_bytes'] = pt
    result['original_node'] = 'mercedes_car'
    if seq_override is not None:
        result['sequence_no'] = seq_override
    return result


# ── SequenceCheckResult tests ─────────────────────────────────────

class TestSequenceCheckResult:

    def test_initial_state_passed(self):
        r = SequenceCheckResult()
        assert r.passed is True

    def test_add_warning_does_not_fail(self):
        r = SequenceCheckResult()
        r.add_warning("test warning")
        assert r.passed   is True
        assert len(r.warnings) == 1

    def test_add_error_fails(self):
        r = SequenceCheckResult()
        r.add_error("test error")
        assert r.passed  is False
        assert len(r.errors) == 1

    def test_to_dict_structure(self):
        r = SequenceCheckResult()
        d = r.to_dict()
        assert 'passed'   in d
        assert 'warnings' in d
        assert 'errors'   in d

    def test_multiple_errors(self):
        r = SequenceCheckResult()
        r.add_error("error 1")
        r.add_error("error 2")
        assert r.passed is False
        assert len(r.errors) == 2


# ── Sequential ordering tests ─────────────────────────────────────

class TestSequentialOrdering:

    def test_sequential_packets_all_pass(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_seq',
            check_timestamps=False,
        )
        results = [
            checker.check(make_val_packet(pipeline))
            for _ in range(10)
        ]
        assert all(r.passed for r in results)

    def test_first_packet_passes(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_first',
            check_timestamps=False,
        )
        result = checker.check(make_val_packet(pipeline))
        assert result.passed is True

    def test_checked_count_increments(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_count',
            check_timestamps=False,
        )
        for _ in range(5):
            checker.check(make_val_packet(pipeline))
        assert checker.checked_count == 5

    def test_passed_count_increments(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_pass_count',
            check_timestamps=False,
        )
        for _ in range(5):
            checker.check(make_val_packet(pipeline))
        assert checker.passed_count == 5

    def test_last_sequence_updated(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_last_seq',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)
        stats = checker.get_node_stats('mercedes_car')
        assert stats['last_seq'] == pkt['sequence_no']


# ── Replay detection tests ────────────────────────────────────────

class TestReplayDetection:

    def test_replay_detected(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_replay',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)        # First — OK
        result = checker.check(pkt)   # Replay
        assert result.passed is False
        assert any('REPLAY' in e for e in result.errors)

    def test_replay_count_increments(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_replay_count',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)
        checker.check(pkt)   # Replay
        assert checker.replay_count >= 1

    def test_multiple_replays_detected(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_multi_replay',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)
        for _ in range(3):
            result = checker.check(pkt)
            assert not result.passed
        assert checker.replay_count >= 3

    def test_different_packets_not_replay(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_no_replay',
            check_timestamps=False,
        )
        p1 = make_val_packet(pipeline)
        p2 = make_val_packet(pipeline)
        r1 = checker.check(p1)
        r2 = checker.check(p2)
        assert r1.passed is True
        assert r2.passed is True


# ── Out-of-order detection tests ──────────────────────────────────

class TestOutOfOrder:

    def test_out_of_order_detected(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_ooo',
            check_timestamps=False,
            strict_ordering=True,
        )
        high = make_val_packet(pipeline, seq_override=100)
        low  = make_val_packet(pipeline, seq_override=50)
        checker.check(high)
        result = checker.check(low)
        assert result.passed is False
        assert any(
            'OUT OF ORDER' in e for e in result.errors
        )

    def test_failed_count_on_out_of_order(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_ooo_count',
            check_timestamps=False,
        )
        high = make_val_packet(pipeline, seq_override=200)
        low  = make_val_packet(pipeline, seq_override=100)
        checker.check(high)
        checker.check(low)
        assert checker.failed_count >= 1

    def test_equal_sequence_rejected(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_equal_seq',
            check_timestamps=False,
        )
        pkt1 = make_val_packet(pipeline, seq_override=5)
        pkt2 = make_val_packet(pipeline, seq_override=5)
        checker.check(pkt1)
        result = checker.check(pkt2)
        assert result.passed is False


# ── Gap detection tests ───────────────────────────────────────────

class TestGapDetection:

    def test_large_gap_adds_warning(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_gap',
            check_timestamps=False,
            max_sequence_gap=5,
        )
        p1 = make_val_packet(pipeline, seq_override=1)
        p2 = make_val_packet(pipeline, seq_override=200)
        checker.check(p1)
        result = checker.check(p2)
        assert len(result.warnings) > 0
        assert any('GAP' in w for w in result.warnings)

    def test_small_gap_no_warning(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_small_gap',
            check_timestamps=False,
            max_sequence_gap=100,
        )
        p1 = make_val_packet(pipeline, seq_override=1)
        p2 = make_val_packet(pipeline, seq_override=10)
        checker.check(p1)
        result = checker.check(p2)
        assert result.passed is True
        assert not any('GAP' in w for w in result.warnings)

    def test_gap_count_increments(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_gap_count',
            check_timestamps=False,
            max_sequence_gap=5,
        )
        p1 = make_val_packet(pipeline, seq_override=1)
        p2 = make_val_packet(pipeline, seq_override=1000)
        checker.check(p1)
        checker.check(p2)
        assert checker.gap_count >= 1


# ── Node state tests ──────────────────────────────────────────────

class TestNodeState:

    def test_reset_node_clears_state(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_reset',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)
        checker.reset_node('mercedes_car')
        # After reset same packet should pass
        result = checker.check(pkt)
        assert result.passed is True

    def test_node_stats_populated(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_stats',
            check_timestamps=False,
        )
        pkt = make_val_packet(pipeline)
        checker.check(pkt)
        stats = checker.get_node_stats('mercedes_car')
        assert stats['last_seq']   > 0
        assert stats['seen_count'] >= 1

    def test_annotate_packet(self, pipeline):
        checker = ValidatorSequenceChecker(
            node_id='test_annotate',
            check_timestamps=False,
        )
        pkt      = make_val_packet(pipeline)
        annotated = checker.check_and_annotate(pkt)
        assert 'sequence_result'   in annotated
        assert 'sequence_passed'   in annotated
        assert 'sequence_warnings' in annotated
        assert 'sequence_errors'   in annotated

    def test_annotate_passes_for_valid_packet(
        self, pipeline
    ):
        checker = ValidatorSequenceChecker(
            node_id='test_annotate_valid',
            check_timestamps=False,
        )
        pkt      = make_val_packet(pipeline)
        annotated = checker.check_and_annotate(pkt)
        assert annotated['sequence_passed'] is True

    def test_two_nodes_independent_state(self, pipeline):
        """Mercedes and Red Bull tracked independently."""
        checker = ValidatorSequenceChecker(
            node_id='test_two_nodes',
            check_timestamps=False,
        )
        merc = make_val_packet(
            pipeline, seq_override=100
        )
        merc['original_node'] = 'mercedes_car'

        rbr = make_val_packet(
            pipeline, seq_override=1
        )
        rbr['original_node'] = 'redbull_car'

        # Both should pass — independent state
        r1 = checker.check(merc)
        r2 = checker.check(rbr)
        assert r1.passed is True
        assert r2.passed is True