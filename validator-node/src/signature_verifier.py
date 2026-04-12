import os
import sys
import logging
from typing import Dict, Optional
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s — %(levelname)s — %(message)s"
)

# ── Path setup ───────────────────────────────────────────────────
ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')
)
sys.path.insert(0, os.path.join(ROOT, 'car-producer', 'src'))
sys.path.insert(0, os.path.join(ROOT, 'relay-node',   'src'))

"""
signature_verifier.py

Ed25519 signature verification at the FIA validator node.

This is the final authentication checkpoint in the pipeline.
Every packet arriving at the validator must carry a valid
Ed25519 signature from the originating car node.

Responsibilities:
    1. Maintain registry of known car node public keys
    2. Verify Ed25519 signature on every arriving packet
    3. Reject packets from unregistered nodes
    4. Reject packets with invalid or missing signatures
    5. Log all verification decisions for audit trail

Why verify at validator AND relay:
    - Relay checks structural integrity (checksum, sequence)
    - Validator checks cryptographic authenticity (Ed25519)
    - Compromising the relay does not bypass signature check
    - Defence in depth — two independent verification layers

What gets verified:
    The original header + payload bytes signed by the car.
    These travel through relay unchanged — the signature
    covers the original plaintext, not the re-encrypted form.
"""

PUBLIC_KEY_SIZE = 32   # Ed25519 public key — always 32 bytes
SIGNATURE_SIZE  = 64   # Ed25519 signature — always 64 bytes


class SignatureVerificationError(Exception):
    """Raised when signature verification fails."""
    pass


class ValidatorSignatureVerifier:
    """
    Ed25519 signature verifier at the FIA validator node.
    Maintains a registry of authorised car node public keys.
    """

    def __init__(self, node_id: str = 'validator'):
        self.node_id          = node_id
        self._registry:  Dict[str, Ed25519PublicKey] = {}
        self._verified_count  = 0
        self._rejected_count  = 0
        self._unknown_count   = 0

        print(f"  [ValidatorSignatureVerifier] "
              f"Initialised: {node_id}")

    # ── Registry ─────────────────────────────────────────────────

    def register_node(
        self,
        node_id:          str,
        public_key_bytes: bytes,
    ) -> None:
        """
        Register an authorised car node public key.

        Args:
            node_id:          e.g. 'mercedes_car', 'redbull_car'
            public_key_bytes: 32-byte Ed25519 public key
        """
        if len(public_key_bytes) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size: "
                f"{len(public_key_bytes)}. "
                f"Expected {PUBLIC_KEY_SIZE}."
            )

        self._registry[node_id] = (
            Ed25519PublicKey.from_public_bytes(public_key_bytes)
        )
        logging.info(
            f"  [ValidatorSignatureVerifier] Registered: "
            f"{node_id} "
            f"({public_key_bytes.hex()[:16]}...)"
        )

    def deregister_node(self, node_id: str) -> None:
        """Remove a node from the registry."""
        if node_id in self._registry:
            del self._registry[node_id]
            logging.info(
                f"  [ValidatorSignatureVerifier] "
                f"Deregistered: {node_id}"
            )

    def is_registered(self, node_id: str) -> bool:
        return node_id in self._registry

    @property
    def registered_nodes(self) -> list:
        return list(self._registry.keys())

    # ── Verification ─────────────────────────────────────────────

    def verify(self, packet: dict) -> dict:
        """
        Verify Ed25519 signature on a validator-bound packet.

        Args:
            packet: Re-encrypted packet from relay containing:
                    header, signature/signature_bytes,
                    original_node or node_id,
                    payload_bytes (if decrypted)

        Returns:
            Verification result dict:
                verified      — bool
                node_id       — signing node
                reason        — success or failure reason
                verified_at   — ISO timestamp

        Raises:
            SignatureVerificationError: Unknown node
            InvalidSignature:          Bad signature
        """
        # ── Resolve node identity ────────────────────────────────
        node_id = (
            packet.get('original_node') or
            packet.get('node_id',       '') or
            packet.get('signer_node_id', '')
        )

        if not node_id:
            self._rejected_count += 1
            raise SignatureVerificationError(
                "Packet missing node identity. "
                "Cannot verify signature."
            )

        # ── Check registry ───────────────────────────────────────
        if node_id not in self._registry:
            self._unknown_count  += 1
            self._rejected_count += 1
            raise SignatureVerificationError(
                f"Unknown node: '{node_id}'. "
                f"Register public key before accepting packets."
            )

        # ── Resolve signature bytes ──────────────────────────────
        sig = packet.get('signature_bytes')
        if sig is None:
            sig_hex = packet.get('signature', '')
            if not sig_hex:
                self._rejected_count += 1
                raise SignatureVerificationError(
                    f"Packet from '{node_id}' "
                    f"has no signature."
                )
            sig = bytes.fromhex(sig_hex)

        if len(sig) != SIGNATURE_SIZE:
            self._rejected_count += 1
            raise SignatureVerificationError(
                f"Invalid signature size: {len(sig)}. "
                f"Expected {SIGNATURE_SIZE}."
            )

        # ── Resolve signed data ──────────────────────────────────
        # Signature covers original header + payload
        header  = packet.get('header', b'')
        payload = packet.get('payload_bytes', b'')

        if not header:
            self._rejected_count += 1
            raise SignatureVerificationError(
                "Missing header bytes for verification."
            )

        if not payload:
            self._rejected_count += 1
            raise SignatureVerificationError(
                "Missing payload bytes for verification. "
                "Decrypt packet before verifying signature."
            )

        data_to_verify = header + payload

        # ── Verify ───────────────────────────────────────────────
        try:
            self._registry[node_id].verify(
                sig, data_to_verify
            )
            self._verified_count += 1

            return {
                'verified':    True,
                'node_id':     node_id,
                'reason':      'signature_valid',
                'verified_at': datetime.now(
                    timezone.utc
                ).isoformat(),
            }

        except InvalidSignature:
            self._rejected_count += 1
            logging.error(
                f"  [ValidatorSignatureVerifier] "
                f"🚨 INVALID SIGNATURE — node={node_id} "
                f"seq={packet.get('sequence_no', '?')}"
            )
            raise InvalidSignature(
                f"Invalid Ed25519 signature from "
                f"node '{node_id}'. "
                f"Packet may have been tampered with."
            )

    def verify_batch(
        self, packets: list
    ) -> tuple:
        """
        Verify signatures on a batch of packets.

        Returns:
            (verified_list, failed_list)
        """
        verified = []
        failed   = []

        for packet in packets:
            try:
                result = self.verify(packet)
                pkt    = dict(packet)
                pkt['signature_result'] = result
                verified.append(pkt)
            except (
                SignatureVerificationError, InvalidSignature
            ) as e:
                failed.append({
                    'packet': packet,
                    'error':  str(e),
                })

        return verified, failed

    # ── Properties ───────────────────────────────────────────────

    @property
    def verified_count(self) -> int:
        return self._verified_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    @property
    def unknown_count(self) -> int:
        return self._unknown_count


# ── Self Test ────────────────────────────────────────────────────
if __name__ == '__main__':
    from sensor_simulator import SensorSimulator
    from packet_builder   import PacketBuilder
    from signer           import PacketSigner
    from encryptor        import PacketEncryptor
    from crypto_engine    import CryptoEngine
    from decryptor        import RelayDecryptor
    from reencryptor      import RelayReencryptor

    print("\n" + "="*55)
    print("  ValidatorSignatureVerifier — Self Test")
    print("="*55)

    # ── Full pipeline setup ──────────────────────────────────────
    sim     = SensorSimulator(
        team='mercedes', race='Bahrain', session='R',
        add_noise=False,
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

    verifier = ValidatorSignatureVerifier(
        node_id='fia_validator'
    )
    verifier.register_node(
        'mercedes_car', signer.public_key_bytes
    )

    def make_pipeline_packet():
        """Full pipeline: car → relay → validator."""
        frame     = sim.get_next_frame()
        packet    = builder.build(frame)
        signed    = signer.sign_packet(packet)
        encrypted = enc.encrypt_packet(signed)
        decrypted = dec.decrypt(encrypted)
        reencrypted = reenc.reencrypt(decrypted)

        # Validator decrypts relay→validator leg
        plaintext = val_eng.decrypt(
            nonce=reencrypted['nonce_bytes'],
            ciphertext=reencrypted['ciphertext_bytes'],
            associated_data=reencrypted['header'],
        )

        # Build validator packet with all needed fields
        val_packet = dict(reencrypted)
        val_packet['payload_bytes'] = plaintext
        val_packet['original_node'] = 'mercedes_car'
        return val_packet, signed

    # ── Test 1: Valid signature passes ───────────────────────────
    print("\n[Test 1] Valid signature verification")
    val_pkt, signed = make_pipeline_packet()
    result = verifier.verify(val_pkt)
    print(f"  Verified:  {result['verified']}")
    print(f"  Node:      {result['node_id']}")
    print(f"  Reason:    {result['reason']}")
    assert result['verified'] is True
    print(f"  Valid signature: ✅")

    # ── Test 2: Tampered payload detected ────────────────────────
    print("\n[Test 2] Tampered payload detected")
    val_pkt2, _ = make_pipeline_packet()
    tampered     = bytearray(val_pkt2['payload_bytes'])
    tampered[5] ^= 0xFF
    val_pkt2['payload_bytes'] = bytes(tampered)

    try:
        verifier.verify(val_pkt2)
        print("  ❌ FAIL — tamper not detected")
    except InvalidSignature:
        print(f"  Tampered payload detected: ✅")

    # ── Test 3: Unknown node rejected ────────────────────────────
    print("\n[Test 3] Unknown node rejected")
    val_pkt3, _ = make_pipeline_packet()
    val_pkt3['original_node'] = 'unknown_car'

    try:
        verifier.verify(val_pkt3)
        print("  ❌ FAIL — unknown node not rejected")
    except SignatureVerificationError as e:
        print(f"  Unknown node rejected: ✅ ({e})")

    # ── Test 4: Missing signature rejected ───────────────────────
    print("\n[Test 4] Missing signature rejected")
    val_pkt4, _ = make_pipeline_packet()
    val_pkt4.pop('signature',       None)
    val_pkt4.pop('signature_bytes', None)

    try:
        verifier.verify(val_pkt4)
        print("  ❌ FAIL — missing sig not rejected")
    except SignatureVerificationError as e:
        print(f"  Missing signature rejected: ✅")

    # ── Test 5: Red Bull node registered separately ──────────────
    print("\n[Test 5] Two teams independent verification")
    rbr_signer = PacketSigner(node_id='redbull_car')
    verifier.register_node(
        'redbull_car', rbr_signer.public_key_bytes
    )
    assert 'mercedes_car' in verifier.registered_nodes
    assert 'redbull_car'  in verifier.registered_nodes
    print(f"  Registered nodes: {verifier.registered_nodes}")
    print(f"  Two teams: ✅")

    # ── Test 6: Batch verification ───────────────────────────────
    print("\n[Test 6] Batch verification")
    batch = []
    for _ in range(5):
        p, _ = make_pipeline_packet()
        batch.append(p)

    ok, failed = verifier.verify_batch(batch)
    print(f"  Verified: {len(ok)}")
    print(f"  Failed:   {len(failed)}")
    assert len(ok)     == 5
    assert len(failed) == 0
    print(f"  Batch verification: ✅")

    print(f"\n  Total verified: {verifier.verified_count}")
    print(f"  Total rejected: {verifier.rejected_count}")
    print(f"\n✅ ValidatorSignatureVerifier self-test complete.")