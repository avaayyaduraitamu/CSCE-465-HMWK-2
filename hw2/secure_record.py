from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct


VERSION = 1

DIRECTION_GATEWAY_TO_NODE = 0
DIRECTION_NODE_TO_GATEWAY = 1

HEADER_SIZE = 15
IV_SIZE = 16
TAG_SIZE = 32

AES_KEY_SIZE = 32
MAC_KEY_SIZE = 32
SESSION_ID_SIZE = 8
SEQUENCE_SIZE = 8


def seal(
    version,
    direction,
    sequence,
    message_type,
    plaintext,
    session_id,
    k_enc,
    k_mac,
):
    if version != VERSION:
        raise ValueError("Unsupported version")

    if direction not in (
        DIRECTION_GATEWAY_TO_NODE,
        DIRECTION_NODE_TO_GATEWAY,
    ):
        raise ValueError("Invalid direction")

    if not 0 <= sequence < 2**64:
        raise ValueError("Invalid sequence number")

    if not 0 <= message_type < 256:
        raise ValueError("Invalid message type")

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError("session_id must be 8 bytes")

    if len(k_enc) != AES_KEY_SIZE:
        raise ValueError("Encryption key must be 32 bytes")

    if len(k_mac) != MAC_KEY_SIZE:
        raise ValueError("MAC key must be 32 bytes")

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    # IV = session_id || sequence
    iv = (
        session_id
        + sequence.to_bytes(
            SEQUENCE_SIZE,
            "big",
        )
    )

    # AES-256-CTR
    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(plaintext)
        + encryptor.finalize()
    )

    # Header:
    # version || direction || sequence ||
    # message_type || ciphertext_length
    header = (
        struct.pack(
            ">BBQB",
            version,
            direction,
            sequence,
            message_type,
        )
        + struct.pack(
            ">I",
            len(ciphertext),
        )
    )

    # Encrypt-then-MAC
    mac = hmac.HMAC(
        k_mac,
        hashes.SHA256(),
    )

    mac.update(
        header
        + iv
        + ciphertext
    )

    tag = mac.finalize()

    return (
        header
        + iv
        + ciphertext
        + tag
    )


def open_record(
    record,
    expected_version,
    expected_direction,
    expected_sequence,
    expected_message_type,
    session_id,
    k_enc,
    k_mac,
):
    if not isinstance(record, bytes):
        raise TypeError("record must be bytes")

    if len(record) < HEADER_SIZE + IV_SIZE + TAG_SIZE:
        raise ValueError("Record is too short")

    if expected_version != VERSION:
        raise ValueError("Unsupported version")

    if expected_direction not in (
        DIRECTION_GATEWAY_TO_NODE,
        DIRECTION_NODE_TO_GATEWAY,
    ):
        raise ValueError("Invalid direction")

    if not 0 <= expected_sequence < 2**64:
        raise ValueError("Invalid expected sequence")

    if not 0 <= expected_message_type < 256:
        raise ValueError("Invalid expected message type")

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError("session_id must be 8 bytes")

    if len(k_enc) != AES_KEY_SIZE:
        raise ValueError("Encryption key must be 32 bytes")

    if len(k_mac) != MAC_KEY_SIZE:
        raise ValueError("MAC key must be 32 bytes")

    # -------------------------
    # Parse header
    # -------------------------

    header = record[:HEADER_SIZE]

    version = header[0]
    direction = header[1]

    sequence = struct.unpack(
        ">Q",
        header[2:10],
    )[0]

    message_type = header[10]

    ciphertext_length = struct.unpack(
        ">I",
        header[11:15],
    )[0]

    # -------------------------
    # Validate header
    # -------------------------

    if version != expected_version:
        raise ValueError("Wrong version")

    if direction != expected_direction:
        raise ValueError("Wrong direction")

    if sequence != expected_sequence:
        raise ValueError("Unexpected sequence number")

    if message_type != expected_message_type:
        raise ValueError("Wrong message type")

    expected_length = (
        HEADER_SIZE
        + IV_SIZE
        + ciphertext_length
        + TAG_SIZE
    )

    if len(record) != expected_length:
        raise ValueError("Invalid record length")

    # -------------------------
    # Extract fields
    # -------------------------

    iv_start = HEADER_SIZE
    iv_end = iv_start + IV_SIZE

    ciphertext_start = iv_end
    ciphertext_end = (
        ciphertext_start
        + ciphertext_length
    )

    iv = record[
        iv_start:iv_end
    ]

    ciphertext = record[
        ciphertext_start:ciphertext_end
    ]

    received_tag = record[
        ciphertext_end:
    ]

    # -------------------------
    # Verify expected IV
    # -------------------------

    expected_iv = (
        session_id
        + expected_sequence.to_bytes(
            SEQUENCE_SIZE,
            "big",
        )
    )

    if iv != expected_iv:
        raise ValueError("Invalid IV")

    # -------------------------
    # VERIFY MAC BEFORE DECRYPTION
    # -------------------------

    mac = hmac.HMAC(
        k_mac,
        hashes.SHA256(),
    )

    mac.update(
        header
        + iv
        + ciphertext
    )

    try:
        mac.verify(received_tag)
    except Exception:
        raise ValueError("Invalid MAC")

    # -------------------------
    # Decrypt only after MAC succeeds
    # -------------------------

    cipher = Cipher(
        algorithms.AES(k_enc),
        modes.CTR(iv),
    )

    decryptor = cipher.decryptor()

    plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    return plaintext


class RecordSender:

    def __init__(
        self,
        version,
        direction,
        session_id,
        k_enc,
        k_mac,
    ):
        self.version = version
        self.direction = direction
        self.session_id = session_id
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.next_sequence = 0

    def seal(self, message_type, plaintext):

        sequence = self.next_sequence

        record = seal(
            self.version,
            self.direction,
            sequence,
            message_type,
            plaintext,
            self.session_id,
            self.k_enc,
            self.k_mac,
        )

        self.next_sequence += 1

        return record


class RecordReceiver:

    def __init__(
        self,
        version,
        direction,
        session_id,
        k_enc,
        k_mac,
    ):
        self.version = version
        self.direction = direction
        self.session_id = session_id
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.expected_sequence = 0

    def open_record(self, record, message_type):

        plaintext = open_record(
            record,
            self.version,
            self.direction,
            self.expected_sequence,
            message_type,
            self.session_id,
            self.k_enc,
            self.k_mac,
        )

        # Only advance after successful processing.
        self.expected_sequence += 1

        return plaintext


def expect_rejection(name, function):

    try:
        function()

        print(
            f"{name}: ACCEPTED  <-- ERROR"
        )

        return False

    except (ValueError, TypeError):

        print(
            f"{name}: REJECTED"
        )

        return True


def run_tests():

    print(
        "=== Task 3 Encrypt-Then-MAC Record Layer ==="
    )

    session_id = bytes.fromhex(
        "86003dbbbc7a756e"
    )

    # Gateway -> Node
    g2n_enc = bytes.fromhex(
        "eadbec73c1c4922f39531dd977d90089998f7c19"
        "bf94c17458424c7c611d56c4"
    )

    g2n_mac = bytes.fromhex(
        "6df62a473dc59b926316e6eaf7c7784050091129"
        "b580d467b50020c9edba927c"
    )

    # Node -> Gateway
    n2g_enc = bytes.fromhex(
        "90c647bbfd7ec607c9df881e3c17c4a68effa450"
        "248b45c2526d97033bfcd93d"
    )

    n2g_mac = bytes.fromhex(
        "063a24372d904d0b28e4a776371c3436dac21b48"
        "180e6f18406ba0181c30f952"
    )

    message_type = 1

    plaintext0 = (
        b'{"action":"READ","path":"notes.txt"}'
    )

    plaintext1 = (
        b'{"action":"WRITE","path":"notes.txt"}'
    )

    # ======================================================
    # 1. Normal record
    # ======================================================

    print(
        "\n1. Normal Gateway -> Node record"
    )

    sender = RecordSender(
        VERSION,
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        g2n_enc,
        g2n_mac,
    )

    receiver = RecordReceiver(
        VERSION,
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        g2n_enc,
        g2n_mac,
    )

    record0 = sender.seal(
        message_type,
        plaintext0,
    )

    recovered0 = receiver.open_record(
        record0,
        message_type,
    )

    normal_success = (
        recovered0 == plaintext0
    )

    print(
        "Sequence used:",
        0,
    )

    print(
        "Plaintext recovered:",
        recovered0.decode(),
    )

    print(
        "Normal record:",
        "SUCCESS"
        if normal_success
        else "FAILED",
    )

    # ======================================================
    # 2. Sequence 1
    # ======================================================

    print(
        "\n2. Second record / sequence progression"
    )

    record1 = sender.seal(
        message_type,
        plaintext1,
    )

    recovered1 = receiver.open_record(
        record1,
        message_type,
    )

    sequence_success = (
        recovered1 == plaintext1
        and sender.next_sequence == 2
        and receiver.expected_sequence == 2
    )

    print(
        "Sequence used:",
        1,
    )

    print(
        "Plaintext recovered:",
        recovered1.decode(),
    )

    print(
        "Sequence 0 -> 1:",
        "SUCCESS"
        if sequence_success
        else "FAILED",
    )

    # ======================================================
    # 3. Replay
    # ======================================================

    print("\n3. Replay")

    replay_rejected = expect_rejection(
        "Replay of sequence 0",
        lambda: receiver.open_record(
            record0,
            message_type,
        ),
    )

    # ======================================================
    # 4. Modified header
    # ======================================================

    print("\n4. Modified header")

    modified_header = bytearray(record0)

    modified_header[10] ^= 1

    header_rejected = expect_rejection(
        "Modified header",
        lambda: open_record(
            bytes(modified_header),
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            0,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 5. Modified ciphertext
    # ======================================================

    print("\n5. Modified ciphertext")

    modified_ciphertext = bytearray(record0)

    ciphertext_start = (
        HEADER_SIZE + IV_SIZE
    )

    modified_ciphertext[
        ciphertext_start
    ] ^= 1

    ciphertext_rejected = expect_rejection(
        "Modified ciphertext",
        lambda: open_record(
            bytes(modified_ciphertext),
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            0,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 6. Invalid MAC
    # ======================================================

    print("\n6. Invalid MAC")

    modified_tag = bytearray(record0)

    modified_tag[-1] ^= 1

    mac_rejected = expect_rejection(
        "Invalid MAC",
        lambda: open_record(
            bytes(modified_tag),
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            0,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 7. Wrong direction
    # ======================================================

    print("\n7. Wrong direction")

    direction_rejected = expect_rejection(
        "Wrong direction",
        lambda: open_record(
            record0,
            VERSION,
            DIRECTION_NODE_TO_GATEWAY,
            0,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 8. Wrong message type
    # ======================================================

    print("\n8. Wrong message type")

    type_rejected = expect_rejection(
        "Wrong message type",
        lambda: open_record(
            record0,
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            0,
            2,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 9. Wrong sequence
    # ======================================================

    print("\n9. Wrong sequence number")

    sequence_rejected = expect_rejection(
        "Unexpected sequence",
        lambda: open_record(
            record0,
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            99,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 10. Malformed record
    # ======================================================

    print("\n10. Malformed record")

    truncated = record0[:-1]

    malformed_rejected = expect_rejection(
        "Malformed record",
        lambda: open_record(
            truncated,
            VERSION,
            DIRECTION_GATEWAY_TO_NODE,
            0,
            message_type,
            session_id,
            g2n_enc,
            g2n_mac,
        ),
    )

    # ======================================================
    # 11. Node -> Gateway
    # ======================================================

    print(
        "\n11. Node -> Gateway separate direction/key test"
    )

    node_sender = RecordSender(
        VERSION,
        DIRECTION_NODE_TO_GATEWAY,
        session_id,
        n2g_enc,
        n2g_mac,
    )

    gateway_receiver = RecordReceiver(
        VERSION,
        DIRECTION_NODE_TO_GATEWAY,
        session_id,
        n2g_enc,
        n2g_mac,
    )

    node_record = node_sender.seal(
        message_type,
        plaintext0,
    )

    node_plaintext = gateway_receiver.open_record(
        node_record,
        message_type,
    )

    separate_direction_success = (
        node_plaintext == plaintext0
        and node_sender.next_sequence == 1
        and gateway_receiver.expected_sequence == 1
    )

    print(
        "Node -> Gateway sequence:",
        0,
    )

    print(
        "Plaintext recovered:",
        node_plaintext.decode(),
    )

    print(
        "Separate direction keys:",
        "SUCCESS"
        if separate_direction_success
        else "FAILED",
    )

    # ======================================================
    # Final result
    # ======================================================

    all_tests_passed = all([
        normal_success,
        sequence_success,
        replay_rejected,
        header_rejected,
        ciphertext_rejected,
        mac_rejected,
        direction_rejected,
        type_rejected,
        sequence_rejected,
        malformed_rejected,
        separate_direction_success,
    ])

    print(
        "\n=== Task 3 Test Result ==="
    )

    print(
        "All tests passed:",
        all_tests_passed,
    )

    if not all_tests_passed:
        print(
            "Task 3 test suite: FAILED"
        )
    else:
        print(
            "Task 3 test suite: SUCCESS"
        )


if __name__ == "__main__":
    run_tests()
