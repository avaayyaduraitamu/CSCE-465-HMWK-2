import handshake
from secure_record import (
    VERSION,
    DIRECTION_GATEWAY_TO_NODE,
    DIRECTION_NODE_TO_GATEWAY,
    RecordSender,
    RecordReceiver,
)


MESSAGE_TYPE = 1

PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'


def test_valid_handshake_and_bidirectional_messages():
    parameters = handshake.load_group()
    result = handshake.perform_handshake(parameters)

    assert result["gateway_valid"] is True
    assert result["node_valid"] is True
    assert result["shared_match"] is True
    assert result["derived_match"] is True

    (
        _k_master,
        g2n_enc,
        g2n_mac,
        n2g_enc,
        n2g_mac,
        session_id,
    ) = result["gateway_keys"]

    # Gateway -> Node
    gateway_sender = RecordSender(
        VERSION,
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        g2n_enc,
        g2n_mac,
    )

    node_receiver = RecordReceiver(
        VERSION,
        DIRECTION_GATEWAY_TO_NODE,
        session_id,
        g2n_enc,
        g2n_mac,
    )

    record = gateway_sender.seal(
        MESSAGE_TYPE,
        PLAINTEXT,
    )

    recovered = node_receiver.open_record(
        record,
        MESSAGE_TYPE,
    )

    assert recovered == PLAINTEXT

    # Node -> Gateway
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

    record_back = node_sender.seal(
        MESSAGE_TYPE,
        PLAINTEXT,
    )

    recovered_back = gateway_receiver.open_record(
        record_back,
        MESSAGE_TYPE,
    )

    assert recovered_back == PLAINTEXT
