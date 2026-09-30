import pytest

import handshake
from secure_record import (
    VERSION,
    DIRECTION_GATEWAY_TO_NODE,
    RecordSender,
    RecordReceiver,
)


MESSAGE_TYPE = 1

PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'


def test_replayed_record_is_rejected():
    parameters = handshake.load_group()
    result = handshake.perform_handshake(parameters)

    (
        _k_master,
        g2n_enc,
        g2n_mac,
        _n2g_enc,
        _n2g_mac,
        session_id,
    ) = result["gateway_keys"]

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

    record = sender.seal(
        MESSAGE_TYPE,
        PLAINTEXT,
    )

    first = receiver.open_record(
        record,
        MESSAGE_TYPE,
    )

    assert first == PLAINTEXT

    # Deliver the exact same record again.
    with pytest.raises(ValueError):
        receiver.open_record(
            record,
            MESSAGE_TYPE,
        )
