import os
import sys
import pytest

# ── Path setup ───────────────────────────────────────────────────
SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', 'src')
)
sys.path.insert(0, SRC)

from crypto_engine import CryptoEngine, ECDHSession
from cryptography.exceptions import InvalidTag


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def car_engine():
    return CryptoEngine(node_id='mercedes_car_test')

@pytest.fixture
def relay_engine():
    return CryptoEngine(node_id='relay_test')

@pytest.fixture
def established_pair(car_engine, relay_engine):
    """Returns (car, relay) with established ECDH session."""
    car_pub   = car_engine.new_session()
    relay_pub = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)
    return car_engine, relay_engine

@pytest.fixture
def sample_plaintext():
    return b'{"Speed":287.4,"RPM":12500,"Throttle":98.2}'

@pytest.fixture
def sample_header():
    return b'PITCRYPT_TEST_HEADER_BYTES'


# ── ECDH session tests ────────────────────────────────────────────

class TestECDHSession:

    def test_generates_32_byte_public_key(self):
        session = ECDHSession(node_id='test')
        assert len(session.get_public_key_bytes()) == 32

    def test_two_sessions_have_different_keys(self):
        s1 = ECDHSession(node_id='node1')
        s2 = ECDHSession(node_id='node2')
        assert s1.get_public_key_bytes() != s2.get_public_key_bytes()

    def test_not_established_before_handshake(self):
        session = ECDHSession(node_id='test')
        assert session.is_established is False

    def test_established_after_handshake(self):
        s1 = ECDHSession(node_id='node1')
        s2 = ECDHSession(node_id='node2')
        s1.derive_shared_secret(s2.get_public_key_bytes())
        assert s1.is_established is True

    def test_both_sides_derive_same_key(self):
        s1 = ECDHSession(node_id='node1')
        s2 = ECDHSession(node_id='node2')
        s1.derive_shared_secret(s2.get_public_key_bytes())
        s2.derive_shared_secret(s1.get_public_key_bytes())
        assert s1.session_key == s2.session_key

    def test_session_key_is_32_bytes(self):
        s1 = ECDHSession(node_id='node1')
        s2 = ECDHSession(node_id='node2')
        s1.derive_shared_secret(s2.get_public_key_bytes())
        assert len(s1.session_key) == 32

    def test_accessing_key_before_handshake_raises(self):
        session = ECDHSession(node_id='test')
        with pytest.raises(RuntimeError):
            _ = session.session_key

    def test_invalid_public_key_length_raises(self):
        session = ECDHSession(node_id='test')
        with pytest.raises(ValueError):
            session.derive_shared_secret(b'tooshort')

    def test_age_increases_over_time(self):
        import time
        session = ECDHSession(node_id='test')
        time.sleep(0.1)
        assert session.age_seconds >= 0.1

    def test_different_salts_different_keys(self):
        s1a = ECDHSession(node_id='a1')
        s1b = ECDHSession(node_id='a2')
        s2a = ECDHSession(node_id='b1')
        s2b = ECDHSession(node_id='b2')

        pub_b1 = s1b.get_public_key_bytes()
        pub_b2 = s2b.get_public_key_bytes()

        key1 = s1a.derive_shared_secret(pub_b1, salt=b'salt1')
        key2 = s2a.derive_shared_secret(pub_b2, salt=b'salt2')

        assert key1 != key2


# ── CryptoEngine tests ────────────────────────────────────────────

class TestCryptoEngine:

    def test_new_session_returns_32_bytes(self, car_engine):
        pub = car_engine.new_session()
        assert len(pub) == 32

    def test_not_established_before_handshake(self, car_engine):
        car_engine.new_session()
        assert car_engine.session_established is False

    def test_established_after_handshake(self, established_pair):
        car, relay = established_pair
        assert car.session_established is True
        assert relay.session_established is True

    def test_encrypt_without_session_raises(self, car_engine):
        with pytest.raises(RuntimeError):
            car_engine.encrypt(b'test')

    def test_decrypt_without_session_raises(self, car_engine):
        with pytest.raises(RuntimeError):
            car_engine.decrypt(b'nonce', b'ciphertext')

    def test_handshake_without_new_session_raises(
        self, car_engine
    ):
        with pytest.raises(RuntimeError):
            car_engine.complete_handshake(b'\x00' * 32)


# ── Encryption tests ──────────────────────────────────────────────

class TestEncryption:

    def test_encrypt_returns_nonce_and_ciphertext(
        self, established_pair, sample_plaintext
    ):
        car, _ = established_pair
        nonce, ct = car.encrypt(sample_plaintext)
        assert len(nonce) == 12
        assert len(ct) > 0

    def test_ciphertext_differs_from_plaintext(
        self, established_pair, sample_plaintext
    ):
        car, _ = established_pair
        _, ct = car.encrypt(sample_plaintext)
        assert ct != sample_plaintext

    def test_same_plaintext_different_nonces(
        self, established_pair, sample_plaintext
    ):
        """Each encryption produces different nonce."""
        car, _ = established_pair
        n1, _ = car.encrypt(sample_plaintext)
        n2, _ = car.encrypt(sample_plaintext)
        assert n1 != n2

    def test_decrypt_recovers_plaintext(
        self, established_pair, sample_plaintext
    ):
        car, relay = established_pair
        nonce, ct  = car.encrypt(sample_plaintext)
        decrypted  = relay.decrypt(nonce, ct)
        assert decrypted == sample_plaintext

    def test_decrypt_with_associated_data(
        self, established_pair, sample_plaintext, sample_header
    ):
        car, relay = established_pair
        nonce, ct  = car.encrypt(sample_plaintext, sample_header)
        decrypted  = relay.decrypt(nonce, ct, sample_header)
        assert decrypted == sample_plaintext

    def test_tampered_ciphertext_raises(
        self, established_pair, sample_plaintext
    ):
        car, relay  = established_pair
        nonce, ct   = car.encrypt(sample_plaintext)
        tampered    = bytearray(ct)
        tampered[5] ^= 0xFF
        with pytest.raises(InvalidTag):
            relay.decrypt(nonce, bytes(tampered))

    def test_tampered_associated_data_raises(
        self, established_pair, sample_plaintext, sample_header
    ):
        car, relay = established_pair
        nonce, ct  = car.encrypt(sample_plaintext, sample_header)
        with pytest.raises(InvalidTag):
            relay.decrypt(nonce, ct, b'WRONG_HEADER_DATA_')

    def test_wrong_nonce_raises(
        self, established_pair, sample_plaintext
    ):
        car, relay  = established_pair
        nonce, ct   = car.encrypt(sample_plaintext)
        wrong_nonce = os.urandom(12)
        with pytest.raises(InvalidTag):
            relay.decrypt(wrong_nonce, ct)

    def test_packets_encrypted_counter(
        self, established_pair, sample_plaintext
    ):
        car, _ = established_pair
        for _ in range(5):
            car.encrypt(sample_plaintext)
        assert car.packets_encrypted == 5

    def test_packets_decrypted_counter(
        self, established_pair, sample_plaintext
    ):
        car, relay = established_pair
        for _ in range(3):
            nonce, ct = car.encrypt(sample_plaintext)
            relay.decrypt(nonce, ct)
        assert relay.packets_decrypted == 3

    def test_failed_decryptions_counter(
        self, established_pair, sample_plaintext
    ):
        car, relay = established_pair
        nonce, ct  = car.encrypt(sample_plaintext)
        tampered   = bytearray(ct)
        tampered[0] ^= 0xFF
        try:
            relay.decrypt(nonce, bytes(tampered))
        except InvalidTag:
            pass
        assert relay.failed_decryptions == 1


# ── Key rotation tests ────────────────────────────────────────────

class TestKeyRotation:

    def test_rotation_generates_new_public_key(
        self, established_pair
    ):
        car, relay  = established_pair
        old_pub     = car.public_key_bytes
        new_pub     = car.rotate_session()
        assert old_pub != new_pub

    def test_rotation_invalidates_old_session(
        self, established_pair, sample_plaintext
    ):
        """After rotation without re-handshake, decrypt fails."""
        car, relay = established_pair

        # Encrypt before rotation
        nonce, ct  = car.encrypt(sample_plaintext)

        # Rotate car session
        new_car_pub = car.rotate_session()

        # Complete new handshake
        new_relay_pub = relay.rotate_session()
        car.complete_handshake(new_relay_pub)
        relay.complete_handshake(new_car_pub)

        # Old ciphertext fails with new key
        with pytest.raises(InvalidTag):
            relay.decrypt(nonce, ct)

    def test_new_session_works_after_rotation(
        self, established_pair, sample_plaintext
    ):
        car, relay    = established_pair
        new_car_pub   = car.rotate_session()
        new_relay_pub = relay.rotate_session()
        car.complete_handshake(new_relay_pub)
        relay.complete_handshake(new_car_pub)

        nonce, ct = car.encrypt(sample_plaintext)
        decrypted = relay.decrypt(nonce, ct)
        assert decrypted == sample_plaintext

    def test_rotated_keys_match_both_sides(
        self, established_pair
    ):
        car, relay    = established_pair
        new_car_pub   = car.rotate_session()
        new_relay_pub = relay.rotate_session()
        car.complete_handshake(new_relay_pub)
        relay.complete_handshake(new_car_pub)
        assert (
            car._session.session_key ==
            relay._session.session_key
        )