import pytest

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


def test_reflected_record_is_rejected():
    parameters = handshake.load_group()
    result = handshake.perform_handshake(parameters)

    (
        _k_master,
        g2n_enc,
        g2n_mac,
        n2g_enc,
        n2g_mac,
        session_id,
    ) = result["gateway_keys"]

    # Legitimate Gateway -> Node sender.
    gateway_sender = RecordSender(
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

    # Attacker reflects the record toward the Gateway.
    gateway_receiver = RecordReceiver(
        VERSION,
        DIRECTION_NODE_TO_GATEWAY,
        session_id,
        n2g_enc,
        n2g_mac,
    )

    with pytest.raises(ValueError):
        gateway_receiver.open_record(
            record,
            MESSAGE_TYPE,
        )
