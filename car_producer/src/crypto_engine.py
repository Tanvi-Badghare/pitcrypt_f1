import os
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

"""
crypto_engine.py

Core cryptographic engine for PitCrypt-F1.

Implements:
    1. ECDH Key Exchange   — X25519 (Curve25519)
       Ephemeral keypair generated per session.
       Shared secret derived independently on both sides.
       Never transmitted over the wire.

    2. HKDF Key Derivation — HMAC-SHA256
       Raw ECDH output → uniform 256-bit session key.

    3. AEAD Encryption     — ChaCha20-Poly1305
       Encrypts payload. Auth tag covers ciphertext + header.
       Any modification to either detected on decryption.

    4. AEAD Decryption     — ChaCha20-Poly1305
       Raises InvalidTag if packet tampered with.

Why ChaCha20-Poly1305:
    - Constant-time — no timing side channels
    - No hardware dependency
    - Same author as Curve25519 (Bernstein)
    - RFC 8439 standardised
    See: architecture/adr/001-crypto-choice.md
"""

# ── Constants ────────────────────────────────────────────────────
NONCE_SIZE      = 12    # 96-bit nonce for ChaCha20-Poly1305
SESSION_KEY_LEN = 32    # 256-bit session key
HKDF_INFO_ENC   = b"pitcrypt-f1-encryption-v1"


class ECDHSession:
    """
    Single ECDH session between two nodes.
    Generates ephemeral X25519 keypair on init.
    Derives shared session key via HKDF-SHA256.
    """

    def __init__(self, node_id: str = 'node'):
        self.node_id      = node_id
        self._private_key = X25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()
        self._session_key: Optional[bytes] = None
        self._created_at  = time.time()
        self._derived_at: Optional[float]  = None

        print(f"  [ECDHSession] New keypair generated for {node_id}")

    def get_public_key_bytes(self) -> bytes:
        """32-byte X25519 public key — send this to peer."""
        return self._public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    def derive_shared_secret(
        self,
        peer_public_key_bytes: bytes,
        salt: Optional[bytes] = None,
    ) -> bytes:
        """
        ECDH exchange + HKDF derivation.

        Args:
            peer_public_key_bytes: 32-byte X25519 public key from peer
            salt: Optional HKDF salt for extra entropy

        Returns:
            32-byte session key — same on both sides
        """
        if len(peer_public_key_bytes) != 32:
            raise ValueError(
                f"Invalid public key length: "
                f"{len(peer_public_key_bytes)}. Expected 32."
            )

        peer_pub    = X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )
        raw_shared  = self._private_key.exchange(peer_pub)

        self._session_key = HKDF(
            algorithm=SHA256(),
            length=SESSION_KEY_LEN,
            salt=salt,
            info=HKDF_INFO_ENC,
        ).derive(raw_shared)

        self._derived_at = time.time()

        print(
            f"  [ECDHSession] Session key derived: "
            f"{self._session_key[:8].hex()}... (32 bytes)"
        )
        return self._session_key

    @property
    def session_key(self) -> bytes:
        if self._session_key is None:
            raise RuntimeError(
                "Session key not derived yet. "
                "Call derive_shared_secret() first."
            )
        return self._session_key

    @property
    def is_established(self) -> bool:
        return self._session_key is not None

    @property
    def age_seconds(self) -> float:
        return time.time() - self._created_at

    def __repr__(self) -> str:
        status = "established" if self.is_established else "pending"
        return (
            f"ECDHSession("
            f"node={self.node_id}, "
            f"status={status}, "
            f"age={self.age_seconds:.1f}s)"
        )


class CryptoEngine:
    """
    Main crypto engine — one instance per node.

    Manages ECDH session lifecycle and provides
    encrypt/decrypt using the derived session key.
    """

    def __init__(self, node_id: str):
        self.node_id            = node_id
        self._session: Optional[ECDHSession] = None
        self._packets_encrypted = 0
        self._packets_decrypted = 0
        self._failed_decryptions = 0

        print(f"\n[CryptoEngine] Initialised: {node_id}")

    # ── Session management ───────────────────────────────────────

    def new_session(self) -> bytes:
        """
        Start new ECDH session.
        Returns this node's public key to send to peer.
        """
        self._session = ECDHSession(node_id=self.node_id)
        return self._session.get_public_key_bytes()

    def complete_handshake(
        self,
        peer_public_key_bytes: bytes,
        salt: Optional[bytes] = None,
    ) -> None:
        """
        Complete handshake with peer's public key.
        Must call new_session() first.
        """
        if self._session is None:
            raise RuntimeError(
                "No active session. Call new_session() first."
            )
        self._session.derive_shared_secret(
            peer_public_key_bytes, salt
        )
        print(
            f"[CryptoEngine] Handshake complete — "
            f"{self.node_id} session established"
        )

    def rotate_session(self) -> bytes:
        """
        Rotate to fresh ECDH session.
        Old key discarded immediately.
        Called by key_scheduler.py on rotation events.

        Returns new public key to send to peer.
        """
        old_age = (
            self._session.age_seconds
            if self._session else 0
        )
        print(
            f"[CryptoEngine] Rotating session "
            f"(old age: {old_age:.1f}s)"
        )
        return self.new_session()

    # ── Encryption ───────────────────────────────────────────────

    def encrypt(
        self,
        plaintext:       bytes,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        ChaCha20-Poly1305 AEAD encryption.

        Auth tag covers ciphertext AND associated_data
        (packet header) — modification of either detected
        on decryption.

        Args:
            plaintext:       Packet payload bytes
            associated_data: Packet header bytes (authenticated
                             but NOT encrypted)

        Returns:
            (nonce, ciphertext_with_tag)
            nonce — 12 random bytes, send with every packet
            ciphertext — payload + 16-byte Poly1305 tag
        """
        if not self.session_established:
            raise RuntimeError(
                "No established session. "
                "Complete handshake before encrypting."
            )

        # Fresh random nonce per packet — NEVER reuse
        nonce  = os.urandom(NONCE_SIZE)
        chacha = ChaCha20Poly1305(self._session.session_key)

        ciphertext = chacha.encrypt(
            nonce,
            plaintext,
            associated_data,
        )

        self._packets_encrypted += 1
        return nonce, ciphertext

    def decrypt(
        self,
        nonce:           bytes,
        ciphertext:      bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        ChaCha20-Poly1305 AEAD decryption + verification.

        Raises InvalidTag if ciphertext OR associated_data
        has been modified — your tamper detection layer.

        Args:
            nonce:           12-byte nonce from packet
            ciphertext:      Encrypted payload with auth tag
            associated_data: Same header bytes used in encrypt

        Returns:
            Decrypted plaintext bytes

        Raises:
            InvalidTag: Packet has been tampered with
        """
        if not self.session_established:
            raise RuntimeError(
                "No established session. "
                "Complete handshake before decrypting."
            )

        chacha = ChaCha20Poly1305(self._session.session_key)

        try:
            plaintext = chacha.decrypt(
                nonce,
                ciphertext,
                associated_data,
            )
            self._packets_decrypted += 1
            return plaintext

        except InvalidTag:
            self._failed_decryptions += 1
            raise InvalidTag(
                "Authentication tag verification failed. "
                "Packet may have been tampered with in transit."
            )

    # ── Properties ───────────────────────────────────────────────

    @property
    def session_established(self) -> bool:
        return (
            self._session is not None and
            self._session.is_established
        )

    @property
    def session_age(self) -> float:
        return self._session.age_seconds if self._session else 0.0

    @property
    def public_key_bytes(self) -> bytes:
        if self._session is None:
            raise RuntimeError(
                "No active session. Call new_session() first."
            )
        return self._session.get_public_key_bytes()

    @property
    def packets_encrypted(self) -> int:
        return self._packets_encrypted

    @property
    def packets_decrypted(self) -> int:
        return self._packets_decrypted

    @property
    def failed_decryptions(self) -> int:
        return self._failed_decryptions


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':

    print("\n" + "="*55)
    print("  CryptoEngine — Self Test")
    print("="*55)

    # ── Test 1: ECDH Key Exchange ────────────────────────────────
    print("\n[Test 1] ECDH Key Exchange")

    car   = CryptoEngine(node_id='mercedes_car')
    relay = CryptoEngine(node_id='relay_01')

    car_pub   = car.new_session()
    relay_pub = relay.new_session()

    print(f"  Car pub key:   {car_pub.hex()[:16]}... (32 bytes)")
    print(f"  Relay pub key: {relay_pub.hex()[:16]}... (32 bytes)")

    car.complete_handshake(relay_pub)
    relay.complete_handshake(car_pub)

    assert car._session.session_key == relay._session.session_key, \
        "Session keys do not match!"
    print(f"  Session keys match: ✅")

    # ── Test 2: Encrypt + Decrypt ────────────────────────────────
    print("\n[Test 2] AEAD Encrypt + Decrypt")

    plaintext = b'{"Speed":287.4,"RPM":12500,"Throttle":98.2}'
    header    = b'PITCRYPT_HEADER'

    nonce, ciphertext = car.encrypt(plaintext, header)
    print(f"  Nonce:      {nonce.hex()} ({len(nonce)} bytes)")
    print(f"  Ciphertext: {ciphertext.hex()[:24]}... "
          f"({len(ciphertext)} bytes)")

    decrypted = relay.decrypt(nonce, ciphertext, header)
    assert decrypted == plaintext
    print(f"  Decrypted matches original: ✅")

    # ── Test 3: Tamper Detection ─────────────────────────────────
    print("\n[Test 3] Tamper Detection")

    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF

    try:
        relay.decrypt(nonce, bytes(tampered), header)
        print("  ❌ FAIL — tampered packet not detected")
    except InvalidTag:
        print("  Tampered ciphertext detected: ✅")

    try:
        relay.decrypt(nonce, ciphertext, b'TAMPERED_HEADER_')
        print("  ❌ FAIL — tampered header not detected")
    except InvalidTag:
        print("  Tampered header detected: ✅")

    # ── Test 4: Key Rotation ─────────────────────────────────────
    print("\n[Test 4] Key Rotation")

    old_key     = car._session.session_key
    new_car_pub = car.rotate_session()
    new_rel_pub = relay.rotate_session()

    car.complete_handshake(new_rel_pub)
    relay.complete_handshake(new_car_pub)

    new_key = car._session.session_key
    assert old_key != new_key, "Key rotation failed — same key!"
    print(f"  Keys differ after rotation: ✅")

    assert car._session.session_key == relay._session.session_key
    print(f"  New keys match both sides: ✅")

    # ── Test 5: Stats ────────────────────────────────────────────
    print("\n[Test 5] Stats")
    print(f"  Car   encrypted:        {car.packets_encrypted}")
    print(f"  Relay decrypted:        {relay.packets_decrypted}")
    print(f"  Relay failed decrypt:   {relay.failed_decryptions}")
    print(f"  Session age:            {car.session_age:.2f}s")

    print("\n✅ CryptoEngine self-test complete.")