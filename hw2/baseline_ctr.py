from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


COMMAND = b'{"action":"READ","path":"notes.txt"}'


def encrypt(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, nonce, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def relay_modify(ciphertext, original, modified):
    # CTR encryption has: C = P XOR keystream
    # Therefore, C' = C XOR P XOR P'
    delta = bytes(a ^ b for a, b in zip(original, modified))
    modified_ciphertext = bytes(
        c ^ d for c, d in zip(ciphertext, delta)
    )
    return modified_ciphertext, delta


def receiver_process(command):
    print(f"Receiver processed: {command.decode()}")


def main():
    key = os.urandom(32)
    nonce = os.urandom(16)

    original = COMMAND
    modified = b'{"action":"SAVE","path":"notes.txt"}'

    print("Original command:")
    print(original.decode())

    print("\nModified command:")
    print(modified.decode())

    print("\nLengths:")
    print("Original:", len(original))
    print("Modified:", len(modified))

    ciphertext = encrypt(key, nonce, original)

    modified_ciphertext, delta = relay_modify(
        ciphertext, original, modified
    )

    print("\nXOR delta (original plaintext XOR modified plaintext):")
    print(delta.hex())

    print("\nOriginal ciphertext:")
    print(ciphertext.hex())

    print("\nModified ciphertext:")
    print(modified_ciphertext.hex())

    recovered = decrypt(key, nonce, modified_ciphertext)

    print("\nReceiver decrypts modified ciphertext:")
    print(recovered.decode())

    print("\nReplay demonstration:")
    print("First delivery:")
    receiver_process(decrypt(key, nonce, ciphertext))

    print("Second delivery of the exact same ciphertext:")
    receiver_process(decrypt(key, nonce, ciphertext))


if __name__ == "__main__":
    main()
