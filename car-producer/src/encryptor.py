import os
import sys
import logging
from typing import Optional, Tuple
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

"""
encryptor.py

Packet encryption layer for PitCrypt-F1.

Wraps crypto_engine.py's CryptoEngine to provide a
clean packet-level encryption interface for main.py.

Takes a signed packet dict from signer.py and returns
a transmission-ready encrypted packet dict containing:
    - nonce        — 12 random bytes, unique per packet
    - ciphertext   — encrypted payload + Poly1305 auth tag
    - header       — unencrypted but authenticated header
    - signature    — Ed25519 signature (over original data)
    - metadata     — sequence, timestamp, team, session

What gets encrypted:
    payload bytes only — the JSON telemetry data

What gets authenticated (but NOT encrypted):
    header bytes — sequence number, timestamp, team ID
    This means tampering with the header is detected
    even though it travels in plaintext.

Why encrypt payload only:
    Relay nodes need to read the header to route packets
    correctly without having the session key. This mirrors
    real network architecture where routers read headers
    but cannot read payload content.

Encryption order (correct):
    1. Build packet     (PacketBuilder)
    2. Sign packet      (PacketSigner)   ← sign before encrypt
    3. Encrypt payload  (PacketEncryptor) ← encrypt after sign

Signing before encrypting ensures the signature covers
the original plaintext — verifiable by anyone with the
public key even after decryption.
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)


class PacketEncryptor:
    """
    Encrypts signed packet payloads using CryptoEngine.

    Designed to sit between PacketSigner and the network
    transmitter in car-producer/src/main.py.
    """

    def __init__(
        self,
        crypto_engine,
        node_id: str = 'node',
    ):
        """
        Args:
            crypto_engine: Established CryptoEngine instance
                           Must have completed ECDH handshake
            node_id:       Node identifier for logging
        """
        self._engine             = crypto_engine
        self._node_id            = node_id
        self._packets_encrypted  = 0
        self._packets_decrypted  = 0
        self._failed_decryptions = 0

        print(f"\n[PacketEncryptor] Initialised: {node_id}")

    # ── Encryption ───────────────────────────────────────────────

    def encrypt_packet(self, signed_packet: dict) -> dict:
        """
        Encrypt a signed packet's payload.

        Takes output from PacketSigner.sign_packet() and
        encrypts the payload bytes using ChaCha20-Poly1305.
        Header bytes are used as associated data — authenticated
        but not encrypted.

        Args:
            signed_packet: dict from PacketSigner.sign_packet()
                           Must contain 'header' and 'payload'

        Returns:
            Encrypted packet dict with keys:
                nonce        — 12-byte hex string
                ciphertext   — encrypted payload hex string
                header       — original header bytes
                header_hex   — header as hex string
                signature    — Ed25519 signature hex
                sequence_no  — packet sequence number
                timestamp    — packet timestamp
                team         — team identifier
                session      — session type
                node_id      — source node
                encrypted_at — ISO timestamp
                size_original  — plaintext payload size
                size_encrypted — ciphertext size
        """
        if not self._engine.session_established:
            raise RuntimeError(
                "CryptoEngine session not established. "
                "Complete ECDH handshake first."
            )

        if 'header' not in signed_packet:
            raise ValueError(
                "Packet missing 'header'. "
                "Use PacketBuilder → PacketSigner pipeline."
            )

        if 'payload' not in signed_packet:
            raise ValueError(
                "Packet missing 'payload'. "
                "Use PacketBuilder → PacketSigner pipeline."
            )

        header  = signed_packet['header']
        payload = signed_packet['payload']

        # Encrypt payload — header is associated data
        nonce, ciphertext = self._engine.encrypt(
            plaintext=payload,
            associated_data=header,
        )

        self._packets_encrypted += 1

        return {
            # Cryptographic fields
            'nonce':           nonce.hex(),
            'nonce_bytes':     nonce,
            'ciphertext':      ciphertext.hex(),
            'ciphertext_bytes': ciphertext,

            # Header — travels in plaintext, authenticated
            'header':          header,
            'header_hex':      header.hex(),

            # Signature — from signer.py
            'signature':       signed_packet.get('signature', ''),
            'signature_bytes': signed_packet.get(
                'signature_bytes', b''
            ),

            # Metadata
            'sequence_no':     signed_packet.get('sequence_no', 0),
            'timestamp':       signed_packet.get('timestamp',   0),
            'team':            signed_packet.get('team',        ''),
            'session':         signed_packet.get('session',     ''),
            'node_id':         signed_packet.get(
                'signer_node_id', self._node_id
            ),
            'encrypted_at':    datetime.now(timezone.utc).isoformat(),

            # Size info
            'size_original':   len(payload),
            'size_encrypted':  len(ciphertext),
        }

    # ── Decryption ───────────────────────────────────────────────

    def decrypt_packet(self, encrypted_packet: dict) -> dict:
        """
        Decrypt an encrypted packet back to plaintext payload.

        Used by relay-node/src/decryptor.py with the same
        session key derived from ECDH.

        Args:
            encrypted_packet: dict from encrypt_packet()

        Returns:
            Decrypted packet dict with 'payload_bytes'
            and 'payload_json' fields added

        Raises:
            InvalidTag: Packet has been tampered with
        """
        if not self._engine.session_established:
            raise RuntimeError(
                "CryptoEngine session not established."
            )

        nonce      = encrypted_packet.get('nonce_bytes')
        ciphertext = encrypted_packet.get('ciphertext_bytes')
        header     = encrypted_packet.get('header')

        # Fallback to hex if bytes not present
        if nonce is None:
            nonce = bytes.fromhex(
                encrypted_packet['nonce']
            )
        if ciphertext is None:
            ciphertext = bytes.fromhex(
                encrypted_packet['ciphertext']
            )

        try:
            plaintext = self._engine.decrypt(
                nonce=nonce,
                ciphertext=ciphertext,
                associated_data=header,
            )
            self._packets_decrypted += 1

            import json
            result = dict(encrypted_packet)
            result['payload_bytes'] = plaintext
            result['payload_json']  = json.loads(
                plaintext.decode('utf-8')
            )
            return result

        except InvalidTag:
            self._failed_decryptions += 1
            raise InvalidTag(
                "Decryption failed — packet tampered with "
                "or wrong session key."
            )

    # ── Properties ───────────────────────────────────────────────

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
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner, SignatureVerifier
    from crypto_engine    import CryptoEngine
    from cryptography.exceptions import InvalidTag, InvalidSignature

    print("\n" + "="*55)
    print("  PacketEncryptor — Self Test")
    print("="*55)

    # ── Setup full pipeline ──────────────────────────────────────
    print("\n[Setup] Initialising full pipeline...")

    # Sensor + builder
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R'
    )
    builder = PacketBuilder(team='mercedes', session='R')

    # Identity keypairs
    signer   = PacketSigner(node_id='mercedes_car')
    verifier = SignatureVerifier()
    verifier.register_node(
        'mercedes_car', signer.public_key_bytes
    )

    # ECDH session — car side
    car_engine   = CryptoEngine(node_id='mercedes_car')
    relay_engine = CryptoEngine(node_id='relay_01')

    car_pub   = car_engine.new_session()
    relay_pub = relay_engine.new_session()

    car_engine.complete_handshake(relay_pub)
    relay_engine.complete_handshake(car_pub)

    # Encryptors — one per side
    car_enc   = PacketEncryptor(
        crypto_engine=car_engine,   node_id='mercedes_car'
    )
    relay_dec = PacketEncryptor(
        crypto_engine=relay_engine, node_id='relay_01'
    )

    # ── Test 1: Full pipeline ────────────────────────────────────
    print("\n[Test 1] Full pipeline: build → sign → encrypt")

    frame   = sim.get_next_frame()
    packet  = builder.build(frame)
    signed  = signer.sign_packet(packet)
    encrypted = car_enc.encrypt_packet(signed)

    print(f"  Original payload:  {encrypted['size_original']} bytes")
    print(f"  Encrypted payload: {encrypted['size_encrypted']} bytes")
    print(f"  Nonce:   {encrypted['nonce'][:16]}...")
    print(f"  Cipher:  {encrypted['ciphertext'][:16]}...")
    print(f"  Seq:     {encrypted['sequence_no']}")
    print(f"  Team:    {encrypted['team']}")

    # ── Test 2: Decrypt and verify ───────────────────────────────
    print("\n[Test 2] Decrypt → verify signature")

    decrypted = relay_dec.decrypt_packet(encrypted)

    print(f"  Decrypted payload: {decrypted['payload_json']}")

    # Verify signature on decrypted packet
    verify_packet = {
        'header':         encrypted['header'],
        'payload':        decrypted['payload_bytes'],
        'signature_bytes': encrypted['signature_bytes'],
        'signer_node_id': encrypted['node_id'],
    }
    result = verifier.verify_packet(verify_packet)
    print(f"  Signature valid: {result} ✅")

    # ── Test 3: Tamper detection ─────────────────────────────────
    print("\n[Test 3] Tamper detection")

    # Tamper with ciphertext
    tampered_ct = bytearray(
        bytes.fromhex(encrypted['ciphertext'])
    )
    tampered_ct[10] ^= 0xFF
    tampered_enc               = dict(encrypted)
    tampered_enc['ciphertext'] = bytes(tampered_ct).hex()
    tampered_enc['ciphertext_bytes'] = bytes(tampered_ct)

    try:
        relay_dec.decrypt_packet(tampered_enc)
        print("  ❌ FAIL — tampered ciphertext not detected")
    except InvalidTag:
        print("  Tampered ciphertext detected: ✅")

    # Tamper with header (associated data)
    tampered_hdr = bytearray(encrypted['header'])
    tampered_hdr[8] ^= 0xFF
    tampered_enc2           = dict(encrypted)
    tampered_enc2['header'] = bytes(tampered_hdr)

    try:
        relay_dec.decrypt_packet(tampered_enc2)
        print("  ❌ FAIL — tampered header not detected")
    except InvalidTag:
        print("  Tampered header detected: ✅")

    # ── Test 4: Encrypt 10 packets ───────────────────────────────
    print("\n[Test 4] Encrypt + decrypt 10 packets")

    for i in range(10):
        f  = sim.get_next_frame()
        p  = builder.build(f)
        s  = signer.sign_packet(p)
        e  = car_enc.encrypt_packet(s)
        d  = relay_dec.decrypt_packet(e)

    print(f"  Encrypted: {car_enc.packets_encrypted} ✅")
    print(f"  Decrypted: {relay_dec.packets_decrypted} ✅")
    print(f"  Failed:    {relay_dec.failed_decryptions}")

    print("\n✅ PacketEncryptor self-test complete.")