import os
import sys
import logging
from typing import Optional

from cryptography.exceptions import InvalidTag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))

from crypto_engine import CryptoEngine

"""
reencryptor.py

Re-encryption layer at the relay node.

After decrypting a packet from the car producer,
the relay re-encrypts the payload for the validator
using a separate ECDH session key specific to the
relay → validator leg.

Why re-encrypt:
    - Car → Relay and Relay → Validator are separate
      cryptographic trust zones
    - The relay should not forward car session keys
    - Validator gets fresh encryption under relay identity
    - Compromising one leg doesn't compromise the other

What changes on re-encryption:
    - New nonce (fresh random per packet)
    - New session key (relay → validator ECDH)
    - New ciphertext
    - Original signature preserved (still car's Ed25519)
    - Original header preserved (sequence, timestamp, team)

What stays the same:
    - Plaintext payload content
    - Ed25519 signature from car
    - Sequence number
    - Timestamp
    - Team and session metadata
"""


class ReencryptionError(Exception):
    """Raised when re-encryption fails."""
    pass


class RelayReencryptor:
    """
    Re-encrypts decrypted packets for the validator leg.
    Uses a separate CryptoEngine session per validator node.
    """

    def __init__(self, node_id: str = 'relay'):
        self.node_id          = node_id
        self._validator_engine: Optional[CryptoEngine] = None
        self._reencrypted_count = 0
        self._failed_count      = 0

        print(f"  [RelayReencryptor] Initialised: {node_id}")

    # ── Session management ───────────────────────────────────────

    def register_validator_session(
        self,
        crypto_engine: CryptoEngine,
    ) -> None:
        """
        Register ECDH session with validator node.

        Args:
            crypto_engine: Established CryptoEngine for
                           relay → validator leg
        """
        if not crypto_engine.session_established:
            raise ValueError(
                "CryptoEngine has no established session. "
                "Complete ECDH handshake with validator first."
            )
        self._validator_engine = crypto_engine
        logging.info(
            f"  [RelayReencryptor] Validator session registered"
        )

    # ── Re-encryption ────────────────────────────────────────────

    def reencrypt(self, decrypted_packet: dict) -> dict:
        """
        Re-encrypt a decrypted packet for the validator.

        Args:
            decrypted_packet: dict from RelayDecryptor.decrypt()
                              Must contain 'payload_bytes',
                              'header', 'signature'

        Returns:
            Re-encrypted packet dict ready for validator:
                nonce           — new 12-byte nonce (hex)
                nonce_bytes     — nonce as bytes
                ciphertext      — re-encrypted payload (hex)
                ciphertext_bytes — ciphertext as bytes
                header          — original header bytes
                header_hex      — header as hex
                signature       — original car Ed25519 sig
                signature_bytes — sig as bytes
                sequence_no     — original sequence number
                timestamp       — original timestamp
                team            — team identifier
                session         — session type
                node_id         — relay node identifier
                original_node   — car node identifier
                reencrypted     — True
                reencrypted_by  — relay node_id

        Raises:
            ReencryptionError: No validator session or
                               missing payload
        """
        if self._validator_engine is None:
            raise ReencryptionError(
                "No validator session registered. "
                "Call register_validator_session() first."
            )

        payload_bytes = decrypted_packet.get('payload_bytes')
        if payload_bytes is None:
            raise ReencryptionError(
                "Decrypted packet missing 'payload_bytes'. "
                "Run RelayDecryptor.decrypt() first."
            )

        header = decrypted_packet.get('header')

        try:
            # Re-encrypt with validator session key
            # Header used as associated data — authenticated
            nonce, ciphertext = self._validator_engine.encrypt(
                plaintext=payload_bytes,
                associated_data=header,
            )

            self._reencrypted_count += 1

            # Preserve original signature and metadata
            sig_bytes = decrypted_packet.get(
                'signature_bytes', b''
            )
            sig_hex = decrypted_packet.get('signature', '')

            # Fallback conversions
            if not sig_bytes and sig_hex:
                sig_bytes = bytes.fromhex(sig_hex)
            if not sig_hex and sig_bytes:
                sig_hex = sig_bytes.hex()

            return {
                # New encryption fields
                'nonce':             nonce.hex(),
                'nonce_bytes':       nonce,
                'ciphertext':        ciphertext.hex(),
                'ciphertext_bytes':  ciphertext,

                # Original header — preserved unchanged
                'header':            header,
                'header_hex':        header.hex()
                                     if header else '',

                # Original car signature — preserved
                'signature':         sig_hex,
                'signature_bytes':   sig_bytes,

                # Metadata from original packet
                'sequence_no':  decrypted_packet.get(
                    'sequence_no', 0
                ),
                'timestamp':    decrypted_packet.get(
                    'timestamp', 0
                ),
                'team':         decrypted_packet.get(
                    'team', ''
                ),
                'session':      decrypted_packet.get(
                    'session', ''
                ),

                # Relay identity
                'node_id':       self.node_id,
                'original_node': decrypted_packet.get(
                    'node_id', ''
                ),

                # Re-encryption metadata
                'reencrypted':    True,
                'reencrypted_by': self.node_id,

                # Size info
                'size_original':  len(payload_bytes),
                'size_encrypted': len(ciphertext),
            }

        except Exception as e:
            self._failed_count += 1
            raise ReencryptionError(
                f"Re-encryption failed: {e}"
            )

    def reencrypt_batch(
        self, decrypted_packets: list
    ) -> tuple:
        """
        Re-encrypt a batch of decrypted packets.

        Returns:
            (reencrypted_list, failed_list)
        """
        reencrypted = []
        failed      = []

        for packet in decrypted_packets:
            try:
                result = self.reencrypt(packet)
                reencrypted.append(result)
            except ReencryptionError as e:
                failed.append({
                    'packet': packet,
                    'error':  str(e),
                })

        return reencrypted, failed

    # ── Properties ───────────────────────────────────────────────

    @property
    def reencrypted_count(self) -> int:
        return self._reencrypted_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    @property
    def validator_session_active(self) -> bool:
        return (
            self._validator_engine is not None and
            self._validator_engine.session_established
        )


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    sys.path.insert(
        0, os.path.join(ROOT, 'car-producer', 'src')
    )
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor
    from decryptor        import RelayDecryptor

    print("\n" + "="*55)
    print("  RelayReencryptor — Self Test")
    print("="*55)

    # ── Setup full pipeline ──────────────────────────────────────
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    # Car → Relay ECDH session
    car_engine   = CryptoEngine(node_id='mercedes_car')
    relay_engine = CryptoEngine(node_id='relay_01')
    car_pub      = car_engine.new_session()
    relay_pub    = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Relay → Validator ECDH session
    relay_val_engine = CryptoEngine(node_id='relay_01_val')
    validator_engine = CryptoEngine(node_id='validator_01')
    relay_val_pub    = relay_val_engine.new_session()
    val_pub          = validator_engine.new_session()
    relay_val_engine.complete_handshake(val_pub)
    validator_engine.complete_handshake(relay_val_pub)

    # Components
    encryptor   = PacketEncryptor(
        crypto_engine=car_engine,
        node_id='mercedes_car',
    )
    decryptor   = RelayDecryptor(node_id='relay_01')
    decryptor.register_session('mercedes_car', relay_engine)

    reencryptor = RelayReencryptor(node_id='relay_01')
    reencryptor.register_validator_session(relay_val_engine)

    def make_decrypted():
        frame     = sim.get_next_frame()
        packet    = builder.build(frame)
        signed    = signer.sign_packet(packet)
        encrypted = encryptor.encrypt_packet(signed)
        return decryptor.decrypt(encrypted)

    # ── Test 1: Re-encrypt packet ────────────────────────────────
    print("\n[Test 1] Re-encrypt decrypted packet")
    decrypted    = make_decrypted()
    reencrypted  = reencryptor.reencrypt(decrypted)

    print(f"  Re-encrypted:    {reencrypted['reencrypted']}")
    print(f"  Re-encrypted by: {reencrypted['reencrypted_by']}")
    print(f"  Original node:   {reencrypted['original_node']}")
    print(f"  Size original:   {reencrypted['size_original']}B")
    print(f"  Size encrypted:  {reencrypted['size_encrypted']}B")
    assert reencrypted['reencrypted'] is True
    print(f"  Re-encrypt: ✅")

    # ── Test 2: Validator can decrypt re-encrypted packet ────────
    print("\n[Test 2] Validator decrypts re-encrypted packet")
    plaintext = validator_engine.decrypt(
        nonce=reencrypted['nonce_bytes'],
        ciphertext=reencrypted['ciphertext_bytes'],
        associated_data=reencrypted['header'],
    )
    import json
    payload = json.loads(plaintext.decode())
    print(f"  Speed:  {payload['Speed']}")
    print(f"  RPM:    {payload['RPM']}")
    assert 'Speed' in payload
    print(f"  Validator decrypt: ✅")

    # ── Test 3: Original signature preserved ─────────────────────
    print("\n[Test 3] Original car signature preserved")
    assert reencrypted['signature'] == decrypted['signature']
    assert (
        reencrypted['sequence_no'] == decrypted['sequence_no']
    )
    assert reencrypted['team']     == decrypted['team']
    print(f"  Signature preserved: ✅")
    print(f"  Sequence preserved: ✅")
    print(f"  Team preserved: ✅")

    # ── Test 4: New nonce each time ──────────────────────────────
    print("\n[Test 4] Fresh nonce per re-encryption")
    d1 = make_decrypted()
    d2 = make_decrypted()
    r1 = reencryptor.reencrypt(d1)
    r2 = reencryptor.reencrypt(d2)
    assert r1['nonce'] != r2['nonce']
    print(f"  Unique nonces: ✅")

    # ── Test 5: No validator session raises ──────────────────────
    print("\n[Test 5] No validator session raises")
    bad_reenc = RelayReencryptor(node_id='bad_relay')
    try:
        bad_reenc.reencrypt(make_decrypted())
        print("  ❌ FAIL — should have raised")
    except ReencryptionError as e:
        print(f"  No session rejected: ✅ ({e})")

    # ── Test 6: Batch re-encryption ──────────────────────────────
    print("\n[Test 6] Batch re-encryption")
    batch = [make_decrypted() for _ in range(5)]
    ok, failed = reencryptor.reencrypt_batch(batch)
    print(f"  Re-encrypted: {len(ok)}")
    print(f"  Failed:       {len(failed)}")
    assert len(ok) == 5
    print(f"  Batch re-encrypt: ✅")

    print(f"\n  Total re-encrypted: {reencryptor.reencrypted_count}")
    print(f"\n✅ RelayReencryptor self-test complete.")