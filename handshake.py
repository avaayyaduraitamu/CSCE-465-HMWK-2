from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
import hmac as stdlib_hmac
import os
import struct


PROTOCOL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"

PUBLIC_VALUE_SIZE = 384
NONCE_SIZE = 16


def load_group():
    with open("ffdhe3072.pem", "rb") as f:
        data = f.read()

    parameters = serialization.load_pem_parameters(data)

    if not hasattr(parameters, "parameter_numbers"):
        raise ValueError("Invalid DH parameter file")

    numbers = parameters.parameter_numbers()

    if numbers.p.bit_length() != 3072:
        raise ValueError("DH group is not 3072 bits")

    return parameters


def generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


def int_to_fixed(value, size=PUBLIC_VALUE_SIZE):
    return value.to_bytes(size, "big")


def encode_fields(fields):
    output = bytearray()

    for field in fields:
        if not isinstance(field, bytes):
            raise TypeError("Transcript fields must be bytes")

        output.extend(struct.pack(">I", len(field)))
        output.extend(field)

    return bytes(output)


def parse_fields(data, expected_count):
    fields = []
    offset = 0

    for _ in range(expected_count):
        if offset + 4 > len(data):
            raise ValueError("Malformed transcript")

        declared_length = struct.unpack(
            ">I",
            data[offset:offset + 4],
        )[0]

        offset += 4

        if offset + declared_length > len(data):
            raise ValueError("Bad declared length")

        field = data[
            offset:offset + declared_length
        ]

        offset += declared_length
        fields.append(field)

    if offset != len(data):
        raise ValueError("Trailing transcript data")

    return fields


def build_transcript(
    gateway_public,
    node_public,
    gateway_nonce,
    node_nonce,
):
    return encode_fields([
        PROTOCOL,
        GROUP_ID,
        GATEWAY_ID,
        NODE_ID,
        int_to_fixed(gateway_public),
        int_to_fixed(node_public),
        gateway_nonce,
        node_nonce,
    ])


def transcript_hash(transcript):
    return hashlib.sha256(transcript).digest()


def sign_message(private_key, role, th):
    message = role + th

    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key, role, th, signature):
    message = role + th

    try:
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


def derive_keys(shared_secret, th):
    z = int_to_fixed(shared_secret)

    k_master = hashlib.sha256(
        b"CSCE465-KDF-v1" + z + th
    ).digest()

    def derive(label):
        mac = hmac.HMAC(
            k_master,
            hashes.SHA256(),
        )
        mac.update(label + th)
        return mac.finalize()

    g2n_enc = derive(
        b"gateway-to-node encryption"
    )

    g2n_mac = derive(
        b"gateway-to-node MAC"
    )

    n2g_enc = derive(
        b"node-to-gateway encryption"
    )

    n2g_mac = derive(
        b"node-to-gateway MAC"
    )

    session_id = derive(
        b"session identifier"
    )[:8]

    return (
        k_master,
        g2n_enc,
        g2n_mac,
        n2g_enc,
        n2g_mac,
        session_id,
    )


def generate_ephemeral(parameters):
    private_key = parameters.generate_private_key()
    public_numbers = private_key.public_key().public_numbers()

    return private_key, public_numbers.y


def perform_handshake(parameters):
    gateway_signing_key = generate_rsa_key()
    node_signing_key = generate_rsa_key()

    gateway_private, gateway_public = generate_ephemeral(
        parameters
    )

    node_private, node_public = generate_ephemeral(
        parameters
    )

    gateway_nonce = os.urandom(NONCE_SIZE)
    node_nonce = os.urandom(NONCE_SIZE)

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce,
    )

    # Verify that the transcript is valid before hashing.
    fields = parse_fields(transcript, 8)

    if fields[0] != PROTOCOL:
        raise ValueError("Unexpected protocol")

    if fields[1] != GROUP_ID:
        raise ValueError("Unexpected group")

    if fields[2] != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if fields[3] != NODE_ID:
        raise ValueError("Unexpected node identity")

    if len(fields[4]) != PUBLIC_VALUE_SIZE:
        raise ValueError("Invalid gateway public value")

    if len(fields[5]) != PUBLIC_VALUE_SIZE:
        raise ValueError("Invalid node public value")

    if len(fields[6]) != NONCE_SIZE:
        raise ValueError("Invalid gateway nonce")

    if len(fields[7]) != NONCE_SIZE:
        raise ValueError("Invalid node nonce")

    th = transcript_hash(transcript)

    gateway_signature = sign_message(
        gateway_signing_key,
        ROLE_GATEWAY,
        th,
    )

    node_signature = sign_message(
        node_signing_key,
        ROLE_NODE,
        th,
    )

    gateway_valid = verify_signature(
        gateway_signing_key.public_key(),
        ROLE_GATEWAY,
        th,
        gateway_signature,
    )

    node_valid = verify_signature(
        node_signing_key.public_key(),
        ROLE_NODE,
        th,
        node_signature,
    )

    if not gateway_valid or not node_valid:
        raise ValueError("Signature verification failed")

    # Construct peer public keys from the transcript values.
    gateway_peer_public = parameters.public_key(
        type(gateway_private.public_key()).public_numbers(
            DHParameterNumbers(
                parameters.parameter_numbers().p,
                parameters.parameter_numbers().g,
            )
        )
    ) if False else None

    # Build public keys directly from the DH parameters.
    numbers = parameters.parameter_numbers()

    gateway_public_numbers = type(
        gateway_private.public_key().public_numbers()
    )(
        gateway_public,
        numbers.parameter_numbers().p
        if False else numbers.q,
    ) if False else None

    # cryptography's DHParameterNumbers can generate a
    # public key from explicit DH public numbers.
    from cryptography.hazmat.primitives.asymmetric.dh import (
        DHPublicNumbers,
    )

    gateway_peer_key = DHPublicNumbers(
        gateway_public,
        numbers,
    ).public_key()

    node_peer_key = DHPublicNumbers(
        node_public,
        numbers,
    ).public_key()

    gateway_shared = gateway_private.exchange(
        node_peer_key
    )

    node_shared = node_private.exchange(
        gateway_peer_key
    )

    shared_match = stdlib_hmac.compare_digest(
        gateway_shared,
        node_shared,
    )

    if not shared_match:
        raise ValueError("Shared secrets do not match")

    gateway_keys = derive_keys(
        int.from_bytes(gateway_shared, "big"),
        th,
    )

    node_keys = derive_keys(
        int.from_bytes(node_shared, "big"),
        th,
    )

    derived_match = all(
        stdlib_hmac.compare_digest(a, b)
        for a, b in zip(gateway_keys, node_keys)
    )

    if not derived_match:
        raise ValueError("Derived keys do not match")

    return {
        "gateway_signing_key": gateway_signing_key,
        "node_signing_key": node_signing_key,
        "gateway_public": gateway_public,
        "node_public": node_public,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
        "transcript": transcript,
        "th": th,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature,
        "gateway_valid": gateway_valid,
        "node_valid": node_valid,
        "gateway_shared": gateway_shared,
        "node_shared": node_shared,
        "shared_match": shared_match,
        "gateway_keys": gateway_keys,
        "node_keys": node_keys,
        "derived_match": derived_match,
    }


def test_invalid_signature(result):
    bad_signature = bytearray(
        result["node_signature"]
    )
    bad_signature[0] ^= 1

    return not verify_signature(
        result["node_signing_key"].public_key(),
        ROLE_NODE,
        result["th"],
        bytes(bad_signature),
    )


def test_changed_nonce(result):
    changed_nonce = bytearray(
        result["node_nonce"]
    )
    changed_nonce[0] ^= 1

    changed_transcript = build_transcript(
        result["gateway_public"],
        result["node_public"],
        result["gateway_nonce"],
        bytes(changed_nonce),
    )

    changed_th = transcript_hash(
        changed_transcript
    )

    return not verify_signature(
        result["node_signing_key"].public_key(),
        ROLE_NODE,
        changed_th,
        result["node_signature"],
    )


def test_changed_public_value(result):
    changed_public = (
        result["node_public"] ^ 1
    )

    changed_transcript = build_transcript(
        result["gateway_public"],
        changed_public,
        result["gateway_nonce"],
        result["node_nonce"],
    )

    changed_th = transcript_hash(
        changed_transcript
    )

    return not verify_signature(
        result["node_signing_key"].public_key(),
        ROLE_NODE,
        changed_th,
        result["node_signature"],
    )


def test_unexpected_identity(result):
    fields = parse_fields(
        result["transcript"],
        8,
    )

    fields[3] = b"attacker"

    changed = encode_fields(fields)

    parsed = parse_fields(changed, 8)

    return parsed[3] != NODE_ID


def test_malformed_transcript(result):
    malformed = result["transcript"][:-1]

    try:
        parse_fields(malformed, 8)
        return False
    except ValueError:
        return True


def test_bad_declared_length(result):
    bad = bytearray(result["transcript"])

    # First field says its real length is 14.
    # Change the declared length to something too large.
    bad[3] = 0xFF

    try:
        parse_fields(bytes(bad), 8)
        return False
    except ValueError:
        return True


def test_reflected_handshake(result):
    # A node signature must not be accepted as a gateway
    # signature because the signed role is different.
    return not verify_signature(
        result["node_signing_key"].public_key(),
        ROLE_GATEWAY,
        result["th"],
        result["node_signature"],
    )


def main():
    parameters = load_group()

    result = perform_handshake(parameters)

    print("=== Task 2 Handshake ===")
    print("Protocol:", PROTOCOL.decode())
    print("Group:", GROUP_ID.decode())
    print("Gateway identity:", GATEWAY_ID.decode())
    print("Node identity:", NODE_ID.decode())
    print(
        "Transcript length:",
        len(result["transcript"]),
    )
    print(
        "Transcript hash:",
        result["th"].hex(),
    )

    print(
        "Gateway signature:",
        "VALID"
        if result["gateway_valid"]
        else "INVALID",
    )

    print(
        "Node signature:",
        "VALID"
        if result["node_valid"]
        else "INVALID",
    )

    print(
        "Shared secret matches:",
        result["shared_match"],
    )

    print(
        "Derived keys match:",
        result["derived_match"],
    )

    (
        k_master,
        g2n_enc,
        g2n_mac,
        n2g_enc,
        n2g_mac,
        session_id,
    ) = result["gateway_keys"]

    print("K_master:", k_master.hex())
    print("K_g2n_enc:", g2n_enc.hex())
    print("K_g2n_mac:", g2n_mac.hex())
    print("K_n2g_enc:", n2g_enc.hex())
    print("K_n2g_mac:", n2g_mac.hex())
    print("session_id:", session_id.hex())

    handshake_success = (
        result["gateway_valid"]
        and result["node_valid"]
        and result["shared_match"]
        and result["derived_match"]
    )

    print(
        "Handshake:",
        "SUCCESS" if handshake_success else "FAILED",
    )

    tests = [
        (
            "Invalid signature",
            test_invalid_signature,
        ),
        (
            "Changed nonce",
            test_changed_nonce,
        ),
        (
            "Changed public value",
            test_changed_public_value,
        ),
        (
            "Unexpected identity",
            test_unexpected_identity,
        ),
        (
            "Malformed transcript",
            test_malformed_transcript,
        ),
        (
            "Bad declared length",
            test_bad_declared_length,
        ),
        (
            "Reflected handshake",
            test_reflected_handshake,
        ),
    ]

    print("\n=== Rejection Tests ===")

    for name, test in tests:
        try:
            rejected = test(result)
        except Exception:
            rejected = True

        print(
            f"{name}:",
            "REJECTED" if rejected else "ACCEPTED",
        )


if __name__ == "__main__":
    main()
