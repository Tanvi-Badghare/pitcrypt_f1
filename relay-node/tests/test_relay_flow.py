import os
import sys
import json
import pytest

# ── Path setup ───────────────────────────────────────────────────
ROOT     = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
SRC      = os.path.join(ROOT, 'relay-node',    'src')
CAR_SRC  = os.path.join(ROOT, 'car-producer',  'src')

sys.path.insert(0, SRC)
sys.path.insert(0, CAR_SRC)

from crypto_engine     import CryptoEngine
from sensor_simulator  import SensorSimulator
from packet_builder    import PacketBuilder
from signer            import PacketSigner, SignatureVerifier
from encryptor         import PacketEncryptor
from packet_parser     import PacketParser, PacketParseError
from decryptor         import RelayDecryptor, DecryptionError
from reencryptor       import RelayReencryptor, ReencryptionError
from anomaly_filters   import AnomalyFilter
from integrity_checker import IntegrityChecker
from cryptography.exceptions import InvalidTag


# ── Shared fixtures ───────────────────────────────────────────────

@pytest.fixture(scope='module')
def pipeline():
    """
    Full end-to-end pipeline fixture.
    Car → Relay → Validator (simulated).
    Shared across all tests in module.
    """
    # Sensor + builder + signer
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False, inject_anomalies=False,
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    # Car → Relay ECDH
    car_engine   = CryptoEngine(node_id='mercedes_car')
    relay_engine = CryptoEngine(node_id='relay_01')
    car_pub      = car_engine.new_session()
    relay_pub    = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Relay → Validator ECDH
    relay_val_e  = CryptoEngine(node_id='relay_01_val')
    val_engine   = CryptoEngine(node_id='validator_01')
    relay_val_p  = relay_val_e.new_session()
    val_pub      = val_engine.new_session()
    relay_val_e.complete_handshake(val_pub)
    val_engine.complete_handshake(relay_val_p)

    # Components
    enc  = PacketEncryptor(
        crypto_engine=car_engine,
        node_id='mercedes_car',
    )
    dec  = RelayDecryptor(node_id='relay_01')
    dec.register_session('mercedes_car', relay_engine)

    reenc = RelayReencryptor(node_id='relay_01')
    reenc.register_validator_session(relay_val_e)

    parser    = PacketParser(node_id='relay_01')
    integrity = IntegrityChecker(
        node_id='relay_01',
        check_timestamps=False,
        check_signatures=True,
    )
    anomaly   = AnomalyFilter(node_id='relay_01')

    return {
        'sim':          sim,
        'builder':      builder,
        'signer':       signer,
        'car_engine':   car_engine,
        'relay_engine': relay_engine,
        'val_engine':   val_engine,
        'enc':          enc,
        'dec':          dec,
        'reenc':        reenc,
        'parser':       parser,
        'integrity':    integrity,
        'anomaly':      anomaly,
    }


@pytest.fixture
def encrypted_packet(pipeline):
    """Build one encrypted packet from car side."""
    p      = pipeline
    frame  = p['sim'].get_next_frame()
    packet = p['builder'].build(frame)
    signed = p['signer'].sign_packet(packet)
    return p['enc'].encrypt_packet(signed)


@pytest.fixture
def decrypted_packet(pipeline, encrypted_packet):
    """Decrypt one packet at relay."""
    return pipeline['dec'].decrypt(encrypted_packet)


@pytest.fixture
def json_packet(encrypted_packet):
    """Serialize encrypted packet as JSON for network transit."""
    enc = encrypted_packet
    return json.dumps({
        'nonce':       enc['nonce'],
        'ciphertext':  enc['ciphertext'],
        'header_hex':  enc['header_hex'],
        'signature':   enc['signature'],
        'sequence_no': enc['sequence_no'],
        'timestamp':   enc['timestamp'],
        'team':        enc['team'],
        'session':     enc['session'],
        'node_id':     enc['node_id'],
    }).encode()


# ── PacketParser tests ────────────────────────────────────────────

class TestPacketParser:

    def test_parse_valid_json_packet(
        self, pipeline, json_packet
    ):
        parsed = pipeline['parser'].parse_json_packet(
            json_packet
        )
        assert parsed['team']    == 'mercedes'
        assert parsed['session'] == 'R'

    def test_parsed_packet_has_nonce_bytes(
        self, pipeline, json_packet
    ):
        parsed = pipeline['parser'].parse_json_packet(
            json_packet
        )
        assert len(parsed['nonce_bytes']) == 12

    def test_parsed_packet_has_header_bytes(
        self, pipeline, json_packet
    ):
        parsed = pipeline['parser'].parse_json_packet(
            json_packet
        )
        assert isinstance(parsed['header'], bytes)
        assert len(parsed['header']) > 0

    def test_parsed_packet_has_ciphertext_bytes(
        self, pipeline, json_packet
    ):
        parsed = pipeline['parser'].parse_json_packet(
            json_packet
        )
        assert isinstance(parsed['ciphertext_bytes'], bytes)
        assert len(parsed['ciphertext_bytes']) > 0

    def test_validate_valid_packet_no_errors(
        self, pipeline, json_packet
    ):
        parsed = pipeline['parser'].parse_json_packet(
            json_packet
        )
        errors = pipeline['parser'].validate_json_packet(parsed)
        assert errors == []

    def test_invalid_json_raises(self, pipeline):
        with pytest.raises(PacketParseError):
            pipeline['parser'].parse_json_packet(
                b'not valid json'
            )

    def test_missing_fields_raises(self, pipeline):
        bad = json.dumps({'nonce': 'abc'}).encode()
        with pytest.raises(PacketParseError):
            pipeline['parser'].parse_json_packet(bad)

    def test_unknown_team_flagged(
        self, pipeline, json_packet
    ):
        parsed             = pipeline['parser'].parse_json_packet(
            json_packet
        )
        parsed['team']     = 'ferrari'
        errors             = pipeline['parser'].validate_json_packet(
            parsed
        )
        assert any('team' in e.lower() for e in errors)

    def test_invalid_session_flagged(
        self, pipeline, json_packet
    ):
        parsed             = pipeline['parser'].parse_json_packet(
            json_packet
        )
        parsed['session']  = 'X'
        errors             = pipeline['parser'].validate_json_packet(
            parsed
        )
        assert any('session' in e.lower() for e in errors)

    def test_parsed_count_increments(
        self, pipeline, json_packet
    ):
        initial = pipeline['parser'].parsed_count
        pipeline['parser'].parse_json_packet(json_packet)
        assert pipeline['parser'].parsed_count == initial + 1


# ── RelayDecryptor tests ──────────────────────────────────────────

class TestRelayDecryptor:

    def test_decrypt_returns_payload_json(
        self, decrypted_packet
    ):
        assert 'payload_json' in decrypted_packet

    def test_decrypted_payload_has_speed(
        self, decrypted_packet
    ):
        assert 'Speed' in decrypted_packet['payload_json']

    def test_decrypted_payload_has_rpm(
        self, decrypted_packet
    ):
        assert 'RPM' in decrypted_packet['payload_json']

    def test_decrypted_flag_is_true(
        self, decrypted_packet
    ):
        assert decrypted_packet['decrypted'] is True

    def test_tampered_ciphertext_raises(
        self, pipeline, encrypted_packet
    ):
        tampered = bytearray(
            encrypted_packet['ciphertext_bytes']
        )
        tampered[5] ^= 0xFF
        bad             = dict(encrypted_packet)
        bad['ciphertext_bytes'] = bytes(tampered)
        bad['ciphertext']       = bytes(tampered).hex()

        with pytest.raises(InvalidTag):
            pipeline['dec'].decrypt(bad)

    def test_tampered_header_raises(
        self, pipeline, encrypted_packet
    ):
        tampered = bytearray(encrypted_packet['header'])
        tampered[8] ^= 0xFF
        bad          = dict(encrypted_packet)
        bad['header'] = bytes(tampered)

        with pytest.raises(InvalidTag):
            pipeline['dec'].decrypt(bad)

    def test_unknown_node_raises(
        self, pipeline, encrypted_packet
    ):
        bad             = dict(encrypted_packet)
        bad['node_id']  = 'unknown_node_xyz'
        with pytest.raises(DecryptionError):
            pipeline['dec'].decrypt(bad)

    def test_decrypted_count_increments(
        self, pipeline, encrypted_packet
    ):
        initial = pipeline['dec'].decrypted_count
        pipeline['dec'].decrypt(encrypted_packet)
        assert pipeline['dec'].decrypted_count > initial

    def test_batch_decrypt_all_succeed(self, pipeline):
        p      = pipeline
        batch  = []
        for _ in range(5):
            frame  = p['sim'].get_next_frame()
            packet = p['builder'].build(frame)
            signed = p['signer'].sign_packet(packet)
            enc    = p['enc'].encrypt_packet(signed)
            batch.append(enc)

        ok, failed = p['dec'].decrypt_batch(batch)
        assert len(ok)     == 5
        assert len(failed) == 0


# ── RelayReencryptor tests ────────────────────────────────────────

class TestRelayReencryptor:

    def test_reencrypt_returns_reencrypted_true(
        self, pipeline, decrypted_packet
    ):
        result = pipeline['reenc'].reencrypt(decrypted_packet)
        assert result['reencrypted'] is True

    def test_reencrypt_preserves_sequence(
        self, pipeline, decrypted_packet
    ):
        result = pipeline['reenc'].reencrypt(decrypted_packet)
        assert (
            result['sequence_no'] ==
            decrypted_packet['sequence_no']
        )

    def test_reencrypt_preserves_team(
        self, pipeline, decrypted_packet
    ):
        result = pipeline['reenc'].reencrypt(decrypted_packet)
        assert result['team'] == decrypted_packet['team']

    def test_reencrypt_preserves_signature(
        self, pipeline, decrypted_packet
    ):
        result = pipeline['reenc'].reencrypt(decrypted_packet)
        assert result['signature'] == decrypted_packet['signature']

    def test_reencrypt_has_new_nonce(
        self, pipeline, decrypted_packet
    ):
        r1 = pipeline['reenc'].reencrypt(decrypted_packet)
        r2 = pipeline['reenc'].reencrypt(decrypted_packet)
        assert r1['nonce'] != r2['nonce']

    def test_validator_can_decrypt_reencrypted(
        self, pipeline, decrypted_packet
    ):
        result    = pipeline['reenc'].reencrypt(decrypted_packet)
        plaintext = pipeline['val_engine'].decrypt(
            nonce=result['nonce_bytes'],
            ciphertext=result['ciphertext_bytes'],
            associated_data=result['header'],
        )
        payload = json.loads(plaintext.decode())
        assert 'Speed' in payload

    def test_no_validator_session_raises(
        self, decrypted_packet
    ):
        bad_reenc = RelayReencryptor(node_id='bad')
        with pytest.raises(ReencryptionError):
            bad_reenc.reencrypt(decrypted_packet)

    def test_missing_payload_raises(
        self, pipeline, decrypted_packet
    ):
        bad = dict(decrypted_packet)
        bad.pop('payload_bytes', None)
        with pytest.raises(ReencryptionError):
            pipeline['reenc'].reencrypt(bad)

    def test_reencrypted_size_info(
        self, pipeline, decrypted_packet
    ):
        result = pipeline['reenc'].reencrypt(decrypted_packet)
        assert result['size_original']  > 0
        assert result['size_encrypted'] > 0


# ── End-to-end flow tests ─────────────────────────────────────────

class TestEndToEndFlow:

    def test_full_pipeline_10_packets(self, pipeline):
        """All 10 packets travel car → relay → validator."""
        p       = pipeline
        success = 0

        for _ in range(10):
            frame     = p['sim'].get_next_frame()
            packet    = p['builder'].build(frame)
            signed    = p['signer'].sign_packet(packet)
            encrypted = p['enc'].encrypt_packet(signed)
            decrypted = p['dec'].decrypt(encrypted)
            reenc     = p['reenc'].reencrypt(decrypted)

            # Validator decrypts
            plaintext = p['val_engine'].decrypt(
                nonce=reenc['nonce_bytes'],
                ciphertext=reenc['ciphertext_bytes'],
                associated_data=reenc['header'],
            )
            payload = json.loads(plaintext.decode())

            if 'Speed' in payload:
                success += 1

        assert success == 10

    def test_pipeline_preserves_telemetry_values(
        self, pipeline
    ):
        """Telemetry values survive the full pipeline intact."""
        p      = pipeline
        frame  = p['sim'].get_next_frame()
        packet = p['builder'].build(frame)
        signed = p['signer'].sign_packet(packet)
        enc    = p['enc'].encrypt_packet(signed)
        dec    = p['dec'].decrypt(enc)
        reenc  = p['reenc'].reencrypt(dec)

        plaintext = p['val_engine'].decrypt(
            nonce=reenc['nonce_bytes'],
            ciphertext=reenc['ciphertext_bytes'],
            associated_data=reenc['header'],
        )
        payload = json.loads(plaintext.decode())

        # Original payload — from signed packet before encryption
        original = json.loads(signed['payload'].decode())

        assert payload['Speed']    == original['Speed']
        assert payload['RPM']      == original['RPM']
        assert payload['Throttle'] == original['Throttle']

    def test_car_signature_survives_relay(self, pipeline):
        """Ed25519 car signature intact after relay processing."""
        p      = pipeline
        frame  = p['sim'].get_next_frame()
        packet = p['builder'].build(frame)
        signed = p['signer'].sign_packet(packet)
        enc    = p['enc'].encrypt_packet(signed)
        dec    = p['dec'].decrypt(enc)
        reenc  = p['reenc'].reencrypt(dec)

        # Verify original car signature still present
        verifier = SignatureVerifier()
        verifier.register_node(
            'mercedes_car', p['signer'].public_key_bytes
        )
        verify_pkt = {
        'header':          signed['header'],
        'payload':         signed['payload'],
        'signature_bytes': signed['signature_bytes'],
        'signer_node_id':  'mercedes_car',
        }
        assert verifier.verify_packet(verify_pkt) is True

    def test_two_teams_independent_sessions(self):
        """Mercedes and Red Bull have separate sessions."""
        # Mercedes pipeline
        merc_sim = SensorSimulator(
            team='mercedes', race='Bahrain', session='R',
            add_noise=False,
        )
        merc_builder = PacketBuilder(
            team='mercedes', session='R'
        )
        merc_signer  = PacketSigner(node_id='mercedes_car')

        merc_car = CryptoEngine(node_id='mercedes_car_2t')
        merc_rel = CryptoEngine(node_id='relay_merc')
        mp = merc_car.new_session()
        rp = merc_rel.new_session()
        merc_car.complete_handshake(rp)
        merc_rel.complete_handshake(mp)

        # Red Bull pipeline
        rbr_sim = SensorSimulator(
            team='redbull', race='Bahrain', session='R',
            add_noise=False,
        )
        rbr_builder = PacketBuilder(
            team='redbull', session='R'
        )
        rbr_signer  = PacketSigner(node_id='redbull_car')

        rbr_car = CryptoEngine(node_id='redbull_car_2t')
        rbr_rel = CryptoEngine(node_id='relay_rbr')
        bp = rbr_car.new_session()
        brp = rbr_rel.new_session()
        rbr_car.complete_handshake(brp)
        rbr_rel.complete_handshake(bp)

        # Build packets for both teams
        merc_enc = PacketEncryptor(
            crypto_engine=merc_car,
            node_id='mercedes_car',
        )
        rbr_enc = PacketEncryptor(
            crypto_engine=rbr_car,
            node_id='redbull_car',
        )

        dec = RelayDecryptor(node_id='relay_multi')
        dec.register_session('mercedes_car', merc_rel)
        dec.register_session('redbull_car',  rbr_rel)

        # Mercedes packet
        mf  = merc_sim.get_next_frame()
        mp_ = merc_builder.build(mf)
        ms  = merc_signer.sign_packet(mp_)
        me  = merc_enc.encrypt_packet(ms)
        md  = dec.decrypt(me)
        assert md['team'] == 'mercedes'

        # Red Bull packet
        rf  = rbr_sim.get_next_frame()
        rp_ = rbr_builder.build(rf)
        rs  = rbr_signer.sign_packet(rp_)
        re  = rbr_enc.encrypt_packet(rs)
        rd  = dec.decrypt(re)
        assert rd['team'] == 'redbull'

        # Sessions are independent
        assert merc_car._session.session_key != \
               rbr_car._session.session_key