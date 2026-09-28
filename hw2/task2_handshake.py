from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters
import hashlib
import os
import struct


PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

DH_BYTES = 384
NONCE_BYTES = 16


def load_dh_group():
    with open("ffdhe3072.pem", "rb") as f:
        return load_pem_parameters(f.read())


def generate_rsa_signing_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


DH_PARAMS = load_dh_group()

GATEWAY_SIGNING_KEY = generate_rsa_signing_key()
NODE_SIGNING_KEY = generate_rsa_signing_key()


def generate_session_values():
    gateway_private = DH_PARAMS.generate_private_key()
    node_private = DH_PARAMS.generate_private_key()

    gateway_public = gateway_private.public_key()
    node_public = node_private.public_key()

    gateway_nonce = os.urandom(NONCE_BYTES)
    node_nonce = os.urandom(NONCE_BYTES)

    return (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )


def encode_dh_public(public_key):
    value = public_key.public_numbers().y
    return value.to_bytes(DH_BYTES, "big")


def encode_field(field):
    return struct.pack(">I", len(field)) + field


def build_transcript(
    gateway_public,
    node_public,
    gateway_nonce,
    node_nonce,
):
    fields = [
        PROTOCOL_LABEL,
        GROUP_ID,
        GATEWAY_ID,
        NODE_ID,
        encode_dh_public(gateway_public),
        encode_dh_public(node_public),
        gateway_nonce,
        node_nonce,
    ]

    return b"".join(encode_field(field) for field in fields)


def validate_transcript(transcript):
    offset = 0

    for _ in range(8):
        if offset + 4 > len(transcript):
            raise ValueError("Missing field length")

        declared_length = struct.unpack(
            ">I", transcript[offset:offset + 4]
        )[0]

        offset += 4

        if offset + declared_length > len(transcript):
            raise ValueError("Incorrect field length")

        offset += declared_length

    if offset != len(transcript):
        raise ValueError("Extra bytes in transcript")

    return True


def transcript_hash(transcript):
    validate_transcript(transcript)
    return hashlib.sha256(transcript).digest()


def sign_transcript(signing_key, role, transcript):
    th = transcript_hash(transcript)
    message = role + th

    return signing_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, role, transcript, signature):
    try:
        th = transcript_hash(transcript)
        message = role + th

        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)


def derive_keys(shared_secret, transcript):
    th = transcript_hash(transcript)

    # Z must be represented as exactly 384 bytes.
    z = int.from_bytes(shared_secret, "big").to_bytes(
        DH_BYTES, "big"
    )

    k_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + z + th
    ).digest()

    def hmac_sha256(label):
        h = hmac.HMAC(k_master, hashes.SHA256())
        h.update(label + th)
        return h.finalize()

    k_g2n_enc = hmac_sha256(
        b"gateway-to-node encryption"
    )

    k_g2n_mac = hmac_sha256(
        b"gateway-to-node MAC"
    )

    k_n2g_enc = hmac_sha256(
        b"node-to-gateway encryption"
    )

    k_n2g_mac = hmac_sha256(
        b"node-to-gateway MAC"
    )

    session_hmac = hmac.HMAC(
        k_master,
        hashes.SHA256()
    )
    session_hmac.update(
        b"session identifier" + th
    )
    session_id = session_hmac.finalize()[:8]

    return {
        "k_master": k_master,
        "k_g2n_enc": k_g2n_enc,
        "k_g2n_mac": k_g2n_mac,
        "k_n2g_enc": k_n2g_enc,
        "k_n2g_mac": k_n2g_mac,
        "session_id": session_id,
    }


def perform_handshake():
    print("=== Task 2 Handshake ===")

    # Generate fresh ephemeral DH values and fresh nonces.
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    # Build the canonical transcript.
    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    # Validate the transcript BEFORE hashing it.
    validate_transcript(transcript)

    th = transcript_hash(transcript)

    # Each party signs its role plus the transcript hash.
    gateway_signature = sign_transcript(
        GATEWAY_SIGNING_KEY,
        GATEWAY_ID,
        transcript,
    )

    node_signature = sign_transcript(
        NODE_SIGNING_KEY,
        NODE_ID,
        transcript,
    )

    # Verify expected identities.
    if GATEWAY_ID != b"gateway":
        raise ValueError("Unexpected gateway identity")

    if NODE_ID != b"node":
        raise ValueError("Unexpected node identity")

    # Verify peer signatures.
    gateway_valid = verify_signature(
        GATEWAY_SIGNING_KEY.public_key(),
        GATEWAY_ID,
        transcript,
        gateway_signature,
    )

    node_valid = verify_signature(
        NODE_SIGNING_KEY.public_key(),
        NODE_ID,
        transcript,
        node_signature,
    )

    if not gateway_valid:
        raise ValueError("Gateway signature rejected")

    if not node_valid:
        raise ValueError("Node signature rejected")

    # Compute the DH shared secret independently.
    gateway_secret = derive_shared_secret(
        gateway_private,
        node_public,
    )

    node_secret = derive_shared_secret(
        node_private,
        gateway_public,
    )

    if gateway_secret != node_secret:
        raise ValueError(
            "DH shared secrets do not match"
        )

    # Derive session keys independently.
    gateway_keys = derive_keys(
        gateway_secret,
        transcript,
    )

    node_keys = derive_keys(
        node_secret,
        transcript,
    )

    if gateway_keys != node_keys:
        raise ValueError(
            "Derived keys do not match"
        )

    print("Protocol:", PROTOCOL_LABEL.decode())
    print("Group:", GROUP_ID.decode())
    print("Gateway identity:", GATEWAY_ID.decode())
    print("Node identity:", NODE_ID.decode())
    print("Transcript length:", len(transcript))
    print("Transcript hash:", th.hex())
    print("Gateway signature: VALID")
    print("Node signature: VALID")
    print("Shared secret matches: True")
    print("Derived keys match: True")
    print("K_master:", gateway_keys["k_master"].hex())
    print("K_g2n_enc:", gateway_keys["k_g2n_enc"].hex())
    print("K_g2n_mac:", gateway_keys["k_g2n_mac"].hex())
    print("K_n2g_enc:", gateway_keys["k_n2g_enc"].hex())
    print("K_n2g_mac:", gateway_keys["k_n2g_mac"].hex())
    print("session_id:", gateway_keys["session_id"].hex())
    print("Handshake: SUCCESS")


def test_invalid_signature():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    signature = sign_transcript(
        GATEWAY_SIGNING_KEY,
        GATEWAY_ID,
        transcript,
    )

    # Change one byte of the signature.
    tampered_signature = bytearray(signature)
    tampered_signature[0] ^= 1
    tampered_signature = bytes(tampered_signature)

    return not verify_signature(
        GATEWAY_SIGNING_KEY.public_key(),
        GATEWAY_ID,
        transcript,
        tampered_signature,
    )


def test_changed_nonce():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    original_transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    changed_nonce = os.urandom(NONCE_BYTES)

    changed_transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        changed_nonce,
    )

    signature = sign_transcript(
        NODE_SIGNING_KEY,
        NODE_ID,
        original_transcript,
    )

    return not verify_signature(
        NODE_SIGNING_KEY.public_key(),
        NODE_ID,
        changed_transcript,
        signature,
    )


def test_changed_public_value():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    original_transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    (
        _,
        _,
        changed_gateway_public,
        _,
        _,
        _,
    ) = generate_session_values()

    changed_transcript = build_transcript(
        changed_gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    signature = sign_transcript(
        GATEWAY_SIGNING_KEY,
        GATEWAY_ID,
        original_transcript,
    )

    return not verify_signature(
        GATEWAY_SIGNING_KEY.public_key(),
        GATEWAY_ID,
        changed_transcript,
        signature,
    )


def test_unexpected_identity():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    unexpected_identity = b"attacker"

    signature = sign_transcript(
        NODE_SIGNING_KEY,
        unexpected_identity,
        transcript,
    )

    return not verify_signature(
        NODE_SIGNING_KEY.public_key(),
        NODE_ID,
        transcript,
        signature,
    )


def test_malformed_transcript():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    # Remove one byte to make the transcript malformed.
    malformed = transcript[:-1]

    signature = sign_transcript(
        GATEWAY_SIGNING_KEY,
        GATEWAY_ID,
        transcript,
    )

    return not verify_signature(
        GATEWAY_SIGNING_KEY.public_key(),
        GATEWAY_ID,
        malformed,
        signature,
    )


def test_bad_declared_length():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    # Change the first field's declared length.
    tampered = bytearray(transcript)
    tampered[3] ^= 1
    tampered = bytes(tampered)

    try:
        validate_transcript(tampered)
        return False
    except ValueError:
        return True


def test_reflected_handshake():
    (
        gateway_private,
        node_private,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    ) = generate_session_values()

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    # A gateway signature is valid only for the gateway role.
    gateway_signature = sign_transcript(
        GATEWAY_SIGNING_KEY,
        GATEWAY_ID,
        transcript,
    )

    # Try to use the gateway signature as a node signature.
    return not verify_signature(
        GATEWAY_SIGNING_KEY.public_key(),
        NODE_ID,
        transcript,
        gateway_signature,
    )


def run_rejection_tests():
    print("\n=== Rejection Tests ===")

    tests = [
        ("Invalid signature", test_invalid_signature),
        ("Changed nonce", test_changed_nonce),
        ("Changed public value", test_changed_public_value),
        ("Unexpected identity", test_unexpected_identity),
        ("Malformed transcript", test_malformed_transcript),
        ("Bad declared length", test_bad_declared_length),
        ("Reflected handshake", test_reflected_handshake),
    ]

    for name, test in tests:
        result = test()
        print(
            f"{name}: {'REJECTED' if result else 'ACCEPTED'}"
        )


if __name__ == "__main__":
    perform_handshake()
    run_rejection_tests()
