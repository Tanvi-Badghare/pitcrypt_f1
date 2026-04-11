import os
import sys
import json
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT    = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
SRC     = os.path.join(ROOT, 'relay-node',   'src')
CAR_SRC = os.path.join(ROOT, 'car-producer', 'src')

sys.path.insert(0, SRC)
sys.path.insert(0, CAR_SRC)

from anomaly_filters   import (
    AnomalyFilter,
    AnomalyResult,
    SEVERITY_PASS,
    SEVERITY_FLAG,
    SEVERITY_REJECT,
    PHYSICAL_LIMITS,
    CHANNELS,
)
from integrity_checker import IntegrityChecker
from crypto_engine     import CryptoEngine
from sensor_simulator  import SensorSimulator
from packet_builder    import PacketBuilder
from signer            import PacketSigner
from encryptor         import PacketEncryptor
from decryptor         import RelayDecryptor


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def relay_pipeline():
    """Minimal pipeline for producing decrypted packets."""
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False, inject_anomalies=False,
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car_af')

    car_e   = CryptoEngine(node_id='mercedes_car_af')
    relay_e = CryptoEngine(node_id='relay_af')
    cp      = car_e.new_session()
    rp      = relay_e.new_session()
    car_e.complete_handshake(rp)
    relay_e.complete_handshake(cp)

    enc = PacketEncryptor(
        crypto_engine=car_e, node_id='mercedes_car_af'
    )
    dec = RelayDecryptor(node_id='relay_af')
    dec.register_session('mercedes_car_af', relay_e)

    return {
        'sim':     sim,
        'builder': builder,
        'signer':  signer,
        'enc':     enc,
        'dec':     dec,
    }

@pytest.fixture(scope='module')
def anomaly_filter():
    return AnomalyFilter(node_id='relay_af_test')

@pytest.fixture
def clean_packet(relay_pipeline):
    """A normal decrypted packet with valid telemetry."""
    p      = relay_pipeline
    frame  = p['sim'].get_next_frame()
    packet = p['builder'].build(frame)
    signed = p['signer'].sign_packet(packet)
    enc    = p['enc'].encrypt_packet(signed)
    return p['dec'].decrypt(enc)

@pytest.fixture
def bad_speed_packet(clean_packet):
    """Packet with physically impossible speed."""
    bad = dict(clean_packet)
    bad['payload_json'] = dict(clean_packet['payload_json'])
    bad['payload_json']['Speed'] = 999.0
    return bad

@pytest.fixture
def high_speed_packet(clean_packet):
    """Packet with speed above threshold but below physical max."""
    bad = dict(clean_packet)
    bad['payload_json'] = dict(clean_packet['payload_json'])
    bad['payload_json']['Speed'] = 395.0   # Above threshold, below 400
    return bad

@pytest.fixture
def negative_rpm_packet(clean_packet):
    """Packet with impossible negative RPM."""
    bad = dict(clean_packet)
    bad['payload_json'] = dict(clean_packet['payload_json'])
    bad['payload_json']['RPM'] = -100.0
    return bad

@pytest.fixture
def impossible_gear_packet(clean_packet):
    """Packet with gear 9 — impossible in F1."""
    bad = dict(clean_packet)
    bad['payload_json'] = dict(clean_packet['payload_json'])
    bad['payload_json']['nGear'] = 9
    return bad


# ── AnomalyResult tests ───────────────────────────────────────────

class TestAnomalyResult:

    def test_initial_severity_is_pass(self):
        r = AnomalyResult()
        assert r.severity == SEVERITY_PASS

    def test_is_clean_initially(self):
        r = AnomalyResult()
        assert r.is_clean is True
        assert r.is_flagged is False
        assert r.is_rejected is False

    def test_add_flag_violation(self):
        r = AnomalyResult()
        r.add_violation(
            'Speed', 350.0, 'above_threshold',
            SEVERITY_FLAG
        )
        assert r.is_flagged is True
        assert r.severity   == SEVERITY_FLAG

    def test_add_reject_violation(self):
        r = AnomalyResult()
        r.add_violation(
            'Speed', 999.0, 'physical_bounds',
            SEVERITY_REJECT
        )
        assert r.is_rejected is True
        assert r.severity    == SEVERITY_REJECT

    def test_reject_overrides_flag(self):
        r = AnomalyResult()
        r.add_violation(
            'Speed', 350.0, 'above_threshold', SEVERITY_FLAG
        )
        r.add_violation(
            'RPM', 99999.0, 'physical_bounds', SEVERITY_REJECT
        )
        assert r.severity == SEVERITY_REJECT

    def test_flag_does_not_override_reject(self):
        r = AnomalyResult()
        r.add_violation(
            'Speed', 999.0, 'physical_bounds', SEVERITY_REJECT
        )
        r.add_violation(
            'RPM', 350.0, 'above_threshold', SEVERITY_FLAG
        )
        assert r.severity == SEVERITY_REJECT

    def test_multiple_violations_recorded(self):
        r = AnomalyResult()
        r.add_violation(
            'Speed', 999.0, 'physical', SEVERITY_REJECT
        )
        r.add_violation(
            'RPM', -100.0, 'physical', SEVERITY_REJECT
        )
        assert len(r.violations) == 2

    def test_to_dict_structure(self):
        r = AnomalyResult()
        d = r.to_dict()
        assert 'severity'   in d
        assert 'violations' in d
        assert 'clean'      in d


# ── Physical bounds tests ─────────────────────────────────────────

class TestPhysicalBounds:

    def test_impossible_speed_rejected(
        self, anomaly_filter, bad_speed_packet
    ):
        result = anomaly_filter.check(bad_speed_packet)
        assert result.is_rejected

    def test_impossible_rpm_rejected(
        self, anomaly_filter, negative_rpm_packet
    ):
        result = anomaly_filter.check(negative_rpm_packet)
        assert result.is_rejected

    def test_impossible_gear_rejected(
        self, anomaly_filter, impossible_gear_packet
    ):
        result = anomaly_filter.check(impossible_gear_packet)
        assert result.is_rejected

    def test_impossible_throttle_rejected(
        self, anomaly_filter, clean_packet
    ):
        bad = dict(clean_packet)
        bad['payload_json'] = dict(clean_packet['payload_json'])
        bad['payload_json']['Throttle'] = 150.0
        result = anomaly_filter.check(bad)
        assert result.is_rejected

    def test_impossible_brake_rejected(
        self, anomaly_filter, clean_packet
    ):
        bad = dict(clean_packet)
        bad['payload_json'] = dict(clean_packet['payload_json'])
        bad['payload_json']['Brake'] = 5
        result = anomaly_filter.check(bad)
        assert result.is_rejected

    def test_boundary_speed_zero_passes(
        self, anomaly_filter, clean_packet
    ):
        boundary = dict(clean_packet)
        boundary['payload_json'] = dict(
            clean_packet['payload_json']
        )
        boundary['payload_json']['Speed'] = 0.0
        result = anomaly_filter.check(boundary)
        assert not result.is_rejected

    def test_boundary_speed_max_passes(
        self, anomaly_filter, clean_packet
    ):
        boundary = dict(clean_packet)
        boundary['payload_json'] = dict(
            clean_packet['payload_json']
        )
        boundary['payload_json']['Speed'] = 380.0
        result = anomaly_filter.check(boundary)
        # Should pass physical bounds — may flag threshold
        assert not result.is_rejected

    def test_slight_negative_speed_passes(
        self, anomaly_filter, clean_packet
    ):
        """Pit lane rollback — slightly negative speed is valid."""
        boundary = dict(clean_packet)
        boundary['payload_json'] = dict(
            clean_packet['payload_json']
        )
        boundary['payload_json']['Speed'] = -0.05
        result = anomaly_filter.check(boundary)
        assert not result.is_rejected


# ── Statistical threshold tests ───────────────────────────────────

class TestStatisticalThresholds:

    def test_high_speed_flagged_not_rejected(
        self, anomaly_filter, high_speed_packet
    ):
        result = anomaly_filter.check(high_speed_packet)
        # Physical bounds pass, statistical threshold may flag
        assert not result.is_rejected

    def test_normal_values_not_rejected(
        self, anomaly_filter, clean_packet
    ):
        result = anomaly_filter.check(clean_packet)
        assert not result.is_rejected

    def test_thresholds_loaded(self, anomaly_filter):
        assert anomaly_filter.thresholds_loaded is True


# ── Annotation tests ──────────────────────────────────────────────

class TestAnnotation:

    def test_annotate_adds_anomaly_result(
        self, anomaly_filter, clean_packet
    ):
        annotated = anomaly_filter.check_and_annotate(
            clean_packet
        )
        assert 'anomaly_result'   in annotated
        assert 'anomaly_clean'    in annotated
        assert 'anomaly_flagged'  in annotated
        assert 'anomaly_rejected' in annotated

    def test_annotate_clean_packet(
        self, anomaly_filter, clean_packet
    ):
        annotated = anomaly_filter.check_and_annotate(
            clean_packet
        )
        assert not annotated['anomaly_rejected']

    def test_annotate_bad_packet_rejected(
        self, anomaly_filter, bad_speed_packet
    ):
        annotated = anomaly_filter.check_and_annotate(
            bad_speed_packet
        )
        assert annotated['anomaly_rejected'] is True

    def test_annotate_preserves_original_fields(
        self, anomaly_filter, clean_packet
    ):
        annotated = anomaly_filter.check_and_annotate(
            clean_packet
        )
        assert annotated['team']    == clean_packet['team']
        assert annotated['session'] == clean_packet['session']


# ── Batch tests ───────────────────────────────────────────────────

class TestBatchCheck:

    def test_batch_all_clean(
        self, relay_pipeline, anomaly_filter
    ):
        p      = relay_pipeline
        batch  = []
        for _ in range(5):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            dec    = p['dec'].decrypt(enc)
            batch.append(dec)

        clean, flagged, rejected = anomaly_filter.check_batch(
            batch
        )
        assert len(clean) + len(flagged) + len(rejected) == 5
        assert len(rejected) == 0

    def test_batch_with_bad_packet(
        self, anomaly_filter, clean_packet, bad_speed_packet
    ):
        batch = [
            clean_packet,
            clean_packet,
            bad_speed_packet,
            clean_packet,
            bad_speed_packet,
        ]
        clean, flagged, rejected = anomaly_filter.check_batch(
            batch
        )
        assert len(rejected) == 2

    def test_batch_total_equals_input(
        self, anomaly_filter, clean_packet, bad_speed_packet
    ):
        batch = [clean_packet, bad_speed_packet]
        c, f, r = anomaly_filter.check_batch(batch)
        assert len(c) + len(f) + len(r) == 2


# ── IntegrityChecker tests ────────────────────────────────────────

class TestIntegrityChecker:

    @pytest.fixture
    def checker(self):
        return IntegrityChecker(
            node_id='test_relay',
            check_timestamps=False,
            check_signatures=True,
        )

    @pytest.fixture
    def valid_packet(self, relay_pipeline):
        p      = relay_pipeline
        frame  = p['sim'].get_next_frame()
        packet = p['builder'].build(frame)
        signed = p['signer'].sign_packet(packet)
        enc    = p['enc'].encrypt_packet(signed)
        return p['dec'].decrypt(enc)

    def test_valid_packet_passes(self, checker, valid_packet):
        result = checker.check(valid_packet)
        assert result.passed is True

    def test_replay_detected(self, checker, valid_packet):
        checker.check(valid_packet)        # First — OK
        result = checker.check(valid_packet)  # Replay
        assert result.passed is False
        assert checker.replay_count >= 1

    def test_out_of_order_detected(
        self, checker, relay_pipeline
    ):
        p = relay_pipeline

        def make():
            f  = p['sim'].get_next_frame()
            pk = p['builder'].build(f)
            s  = p['signer'].sign_packet(pk)
            e  = p['enc'].encrypt_packet(s)
            return p['dec'].decrypt(e)

        checker2 = IntegrityChecker(
            node_id='ooo_test',
            check_timestamps=False,
        )
        high          = make()
        low           = make()
        high['sequence_no'] = 100
        low['sequence_no']  = 50

        checker2.check(high)
        result = checker2.check(low)
        assert result.passed is False

    def test_missing_signature_fails(
        self, checker, valid_packet
    ):
        bad = dict(valid_packet)
        bad.pop('signature',       None)
        bad.pop('signature_bytes', None)

        # Use fresh checker to avoid sequence conflicts
        c2     = IntegrityChecker(
            node_id='sig_test',
            check_timestamps=False,
            check_signatures=True,
        )
        result = c2.check(bad)
        assert result.passed is False

    def test_sequential_packets_all_pass(
        self, relay_pipeline
    ):
        p  = relay_pipeline
        c  = IntegrityChecker(
            node_id='seq_test',
            check_timestamps=False,
        )
        results = []
        for _ in range(10):
            f  = p['sim'].get_next_frame()
            pk = p['builder'].build(f)
            s  = p['signer'].sign_packet(pk)
            e  = p['enc'].encrypt_packet(s)
            d  = p['dec'].decrypt(e)
            results.append(c.check(d))

        passed = sum(1 for r in results if r.passed)
        assert passed == 10

    def test_large_gap_adds_warning(
        self, relay_pipeline
    ):
        p = relay_pipeline
        c = IntegrityChecker(
            node_id='gap_test',
            check_timestamps=False,
            max_sequence_gap=5,
        )
        f1 = p['sim'].get_next_frame()
        p1 = p['builder'].build(f1)
        s1 = p['signer'].sign_packet(p1)
        e1 = p['enc'].encrypt_packet(s1)
        d1 = p['dec'].decrypt(e1)
        d1['sequence_no'] = 1
        c.check(d1)

        f2 = p['sim'].get_next_frame()
        p2 = p['builder'].build(f2)
        s2 = p['signer'].sign_packet(p2)
        e2 = p['enc'].encrypt_packet(s2)
        d2 = p['dec'].decrypt(e2)
        d2['sequence_no'] = 200   # Large gap

        result = c.check(d2)
        assert len(result.warnings) > 0

    def test_reset_node_clears_state(
        self, relay_pipeline
    ):
        p = relay_pipeline
        c = IntegrityChecker(
            node_id='reset_test',
            check_timestamps=False,
        )
        f  = p['sim'].get_next_frame()
        pk = p['builder'].build(f)
        s  = p['signer'].sign_packet(pk)
        e  = p['enc'].encrypt_packet(s)
        d  = p['dec'].decrypt(e)

        c.check(d)      # First pass
        c.reset_node(d['node_id'])

        # After reset — same packet should pass again
        # (sequence state cleared)
        result = c.check(d)
        assert result.passed is True

    def test_stats_increment(self, relay_pipeline):
        p = relay_pipeline
        c = IntegrityChecker(
            node_id='stats_test',
            check_timestamps=False,
        )
        for _ in range(5):
            f  = p['sim'].get_next_frame()
            pk = p['builder'].build(f)
            s  = p['signer'].sign_packet(pk)
            e  = p['enc'].encrypt_packet(s)
            d  = p['dec'].decrypt(e)
            c.check(d)

        assert c.checked_count == 5
        assert c.passed_count  == 5