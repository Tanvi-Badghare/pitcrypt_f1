import os
import sys
import json
import logging
from typing import Optional, Dict

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
decryptor.py

AEAD decryption layer at the relay node.

Receives encrypted packets from the car producer and
decrypts them using the shared ECDH session key.

Responsibilities:
    1. Look up active session key for incoming node
    2. Decrypt payload using ChaCha20-Poly1305
    3. Verify AEAD authentication tag
       — detects any ciphertext or header tampering
    4. Return decrypted payload for anomaly filtering
    5. Track decryption failures for audit logging

What it does NOT do:
    - Re-encrypt for validator (reencryptor.py)
    - Check sequence ordering (integrity_checker.py)
    - Filter anomalies (anomaly_filters.py)

Session management:
    Each car node has its own ECDH session.
    Sessions are stored in _sessions dict keyed by node_id.
    Key rotation handled by key_scheduler.py callbacks.
"""


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


class RelayDecryptor:
    """
    Decrypts car producer packets at the relay node.
    Manages one CryptoEngine session per car node.
    """

    def __init__(self, node_id: str = 'relay'):
        self.node_id             = node_id
        self._sessions: Dict[str, CryptoEngine] = {}
        self._decrypted_count    = 0
        self._failed_count       = 0
        self._tamper_count       = 0

        print(f"  [RelayDecryptor] Initialised: {node_id}")

    # ── Session management ───────────────────────────────────────

    def register_session(
        self,
        car_node_id:       str,
        crypto_engine:     CryptoEngine,
    ) -> None:
        """
        Register an established CryptoEngine session
        for a car node.

        Args:
            car_node_id:   e.g. 'mercedes_car', 'redbull_car'
            crypto_engine: Established CryptoEngine instance
        """
        if not crypto_engine.session_established:
            raise ValueError(
                f"CryptoEngine for '{car_node_id}' "
                f"has no established session. "
                f"Complete ECDH handshake first."
            )

        self._sessions[car_node_id] = crypto_engine
        logging.info(
            f"  [RelayDecryptor] Session registered: "
            f"{car_node_id}"
        )

    def update_session(
        self,
        car_node_id:   str,
        crypto_engine: CryptoEngine,
    ) -> None:
        """
        Update session after key rotation.
        Called by key rotation callback.
        """
        self._sessions[car_node_id] = crypto_engine
        logging.info(
            f"  [RelayDecryptor] Session updated: "
            f"{car_node_id}"
        )

    def has_session(self, car_node_id: str) -> bool:
        return car_node_id in self._sessions

    # ── Decryption ───────────────────────────────────────────────

    def decrypt(self, packet: dict) -> dict:
        """
        Decrypt an encrypted packet from the car producer.

        Args:
            packet: Parsed encrypted packet dict containing:
                    nonce_bytes, ciphertext_bytes, header,
                    node_id, sequence_no, timestamp, team,
                    session, signature, signature_bytes

        Returns:
            Decrypted packet dict with added fields:
                payload_bytes  — raw decrypted bytes
                payload_json   — parsed JSON dict
                decrypted      — True
                decrypted_by   — relay node_id

        Raises:
            DecryptionError: Session not found or key mismatch
            InvalidTag:      Packet tampered with
        """
        node_id = packet.get('node_id')
        if not node_id:
            raise DecryptionError(
                "Packet missing 'node_id' field."
            )

        if node_id not in self._sessions:
            raise DecryptionError(
                f"No session for node '{node_id}'. "
                f"Register session first."
            )

        engine = self._sessions[node_id]

        # Get nonce and ciphertext
        nonce = packet.get('nonce_bytes')
        if nonce is None:
            nonce_hex = packet.get('nonce', '')
            if not nonce_hex:
                raise DecryptionError("Missing nonce.")
            nonce = bytes.fromhex(nonce_hex)

        ciphertext = packet.get('ciphertext_bytes')
        if ciphertext is None:
            ct_hex = packet.get('ciphertext', '')
            if not ct_hex:
                raise DecryptionError("Missing ciphertext.")
            ciphertext = bytes.fromhex(ct_hex)

        header = packet.get('header')
        if header is None:
            header_hex = packet.get('header_hex', '')
            if header_hex:
                header = bytes.fromhex(header_hex)

        try:
            plaintext = engine.decrypt(
                nonce=nonce,
                ciphertext=ciphertext,
                associated_data=header,
            )

            self._decrypted_count += 1

            result = dict(packet)
            result['payload_bytes'] = plaintext
            result['payload_json']  = json.loads(
                plaintext.decode('utf-8')
            )
            result['decrypted']    = True
            result['decrypted_by'] = self.node_id

            return result

        except InvalidTag:
            self._failed_count  += 1
            self._tamper_count  += 1
            logging.warning(
                f"[RelayDecryptor] ⚠️  TAMPER DETECTED — "
                f"node={node_id} seq={packet.get('sequence_no')}"
            )
            raise InvalidTag(
                f"Authentication tag failed for "
                f"node '{node_id}' — packet tampered."
            )

        except Exception as e:
            self._failed_count += 1
            raise DecryptionError(
                f"Decryption error: {e}"
            )

    def decrypt_batch(
        self, packets: list
    ) -> tuple:
        """
        Decrypt a batch of packets.

        Returns:
            (decrypted_list, failed_list)
        """
        decrypted = []
        failed    = []

        for packet in packets:
            try:
                result = self.decrypt(packet)
                decrypted.append(result)
            except (InvalidTag, DecryptionError) as e:
                failed.append({
                    'packet': packet,
                    'error':  str(e),
                })

        return decrypted, failed

    # ── Properties ───────────────────────────────────────────────

    @property
    def decrypted_count(self) -> int:
        return self._decrypted_count

    @property
    def failed_count(self) -> int:
        return self._failed_count

    @property
    def tamper_count(self) -> int:
        return self._tamper_count

    @property
    def registered_nodes(self) -> list:
        return list(self._sessions.keys())


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    sys.path.insert(
        0, os.path.join(ROOT, 'car-producer', 'src')
    )
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor

    print("\n" + "="*55)
    print("  RelayDecryptor — Self Test")
    print("="*55)

    # ── Setup ────────────────────────────────────────────────────
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')
    signer  = PacketSigner(node_id='mercedes_car')

    car_engine   = CryptoEngine(node_id='mercedes_car')
    relay_engine = CryptoEngine(node_id='relay_01')

    car_pub   = car_engine.new_session()
    relay_pub = relay_engine.new_session()
    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    encryptor = PacketEncryptor(
        crypto_engine=car_engine,
        node_id='mercedes_car',
    )
    decryptor = RelayDecryptor(node_id='relay_01')
    decryptor.register_session('mercedes_car', relay_engine)

    def make_encrypted():
        frame     = sim.get_next_frame()
        packet    = builder.build(frame)
        signed    = signer.sign_packet(packet)
        return encryptor.encrypt_packet(signed)

    # ── Test 1: Decrypt valid packet ─────────────────────────────
    print("\n[Test 1] Decrypt valid packet")
    enc       = make_encrypted()
    decrypted = decryptor.decrypt(enc)

    print(f"  Decrypted: {decrypted['decrypted']}")
    print(f"  Speed:     {decrypted['payload_json']['Speed']}")
    print(f"  RPM:       {decrypted['payload_json']['RPM']}")
    assert decrypted['decrypted'] is True
    print(f"  Decrypt valid packet: ✅")

    # ── Test 2: Tamper detection ─────────────────────────────────
    print("\n[Test 2] Tamper detection")
    enc2     = make_encrypted()
    tampered = bytearray(enc2['ciphertext_bytes'])
    tampered[5] ^= 0xFF
    enc2['ciphertext_bytes'] = bytes(tampered)
    enc2['ciphertext']       = bytes(tampered).hex()

    try:
        decryptor.decrypt(enc2)
        print("  ❌ FAIL — tamper not detected")
    except InvalidTag:
        print(f"  Tamper detected: ✅")
        print(f"  Tamper count: {decryptor.tamper_count}")

    # ── Test 3: Unknown node rejected ────────────────────────────
    print("\n[Test 3] Unknown node rejected")
    enc3             = make_encrypted()
    enc3['node_id']  = 'unknown_node'

    try:
        decryptor.decrypt(enc3)
        print("  ❌ FAIL — unknown node not rejected")
    except DecryptionError as e:
        print(f"  Unknown node rejected: ✅ ({e})")

    # ── Test 4: Batch decryption ─────────────────────────────────
    print("\n[Test 4] Batch decryption")
    batch = [make_encrypted() for _ in range(5)]
    ok, failed = decryptor.decrypt_batch(batch)
    print(f"  Decrypted: {len(ok)}")
    print(f"  Failed:    {len(failed)}")
    assert len(ok) == 5
    print(f"  Batch decryption: ✅")

    print(f"\n  Total decrypted: {decryptor.decrypted_count}")
    print(f"  Total failed:    {decryptor.failed_count}")
    print(f"\n✅ RelayDecryptor self-test complete.")