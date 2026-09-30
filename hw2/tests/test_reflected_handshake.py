import handshake


def test_reflected_handshake_signature_is_rejected():
    parameters = handshake.load_group()
    result = handshake.perform_handshake(parameters)

    # The Node signature is valid for the Node role.
    node_valid = handshake.verify_signature(
        result["node_signing_key"].public_key(),
        handshake.ROLE_NODE,
        result["th"],
        result["node_signature"],
    )

    assert node_valid is True

    # Try to reflect the Node signature as if it were
    # a Gateway signature.
    reflected = handshake.verify_signature(
        result["node_signing_key"].public_key(),
        handshake.ROLE_GATEWAY,
        result["th"],
        result["node_signature"],
    )

    assert reflected is False
