# CSCE-465-HMWK-2

## Environment

This project was developed and tested on:

* Ubuntu 24.04
* Python 3.12.3
* OpenSSL 3.0+
* `cryptography==49.0.0`
* `pytest==9.1.1`

## Project Structure

```text
hw2/
├── baseline_ctr.py
├── handshake.py
├── secure_record.py
├── ffdhe3072.pem
├── tests/
│   ├── test_modified_ciphertext.py
│   ├── test_modified_header.py
│   ├── test_reflected_handshake.py
│   ├── test_reflected_record.py
│   ├── test_replay.py
│   └── test_valid_handshake.py
└── .gitignore
```

---

# Lab Preparation / Task 0

## 1. Navigate to the project

```bash
cd ~/Downloads/HW1/HW1/csce465-agentsec
```

## 2. Create the Python virtual environment

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

If Ubuntu reports that `ensurepip` is unavailable, the `python3.12-venv` package must be installed by an administrator.

## 3. Install required packages

With the virtual environment active:

```bash
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

## 4. Navigate to the homework directory

```bash
cd ~/Downloads/HW1/HW1/csce465-agentsec/hw2
```

## 5. Generate the Diffie–Hellman parameter file

The parameter file is required for Task 2.

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

Verify it:

```bash
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```

The output should indicate:

```text
DH Parameters: (3072 bit)
GROUP: ffdhe3072
```

## 6. Check the environment

Before running the tasks:

```bash
python3 --version
openssl version
pip show cryptography pytest
```

---

# Task 1 — AES-CTR Without Authentication

Task 1 demonstrates that encryption by itself does not provide integrity or replay protection.

Run:

```bash
python baseline_ctr.py
```

The program demonstrates:

* The original command.
* An equal-length modified command.
* The XOR difference between the plaintexts.
* The resulting ciphertexts.
* Successful decryption of the modified ciphertext.
* Replay of the same ciphertext.

A successful run should show the receiver processing the modified command and processing the original ciphertext twice during the replay demonstration.

---

# Task 2 — Authenticated Diffie–Hellman Handshake

Task 2 implements the authenticated finite-field Diffie–Hellman handshake using:

* `ffdhe3072`
* 3072-bit RSA signing keys
* RSA-PSS with SHA-256
* Fresh DH ephemeral values
* Fresh 16-byte nonces
* Length-prefixed transcript encoding
* SHA-256 transcript hashing
* HMAC-SHA-256 key derivation
* Separate keys for each communication direction

Run:

```bash
python handshake.py
```

A successful run should show:

```text
Gateway signature: VALID
Node signature: VALID
Shared secret matches: True
Derived keys match: True
Handshake: SUCCESS
```

The rejection tests should also show `REJECTED` for invalid signatures, changed nonces, changed public values, unexpected identities, malformed transcripts, bad declared lengths, and reflected handshake messages.

---

# Task 3 — Encrypt-Then-MAC Record Layer

Task 3 implements the secure record layer using:

* AES-256-CTR
* HMAC-SHA-256
* Separate keys for each direction
* Sequence numbers
* Session ID and sequence number for the IV
* Encrypt-then-MAC authentication
* Constant-time MAC verification

Run:

```bash
python secure_record.py
```

The test program checks:

1. Normal Gateway → Node record
2. Sequence number progression
3. Replay protection
4. Modified header
5. Modified ciphertext
6. Invalid MAC
7. Wrong direction
8. Wrong message type
9. Unexpected sequence number
10. Malformed record
11. Node → Gateway separate direction/key operation

A successful run ends with:

```text
=== Task 3 Test Result ===
All tests passed: True
Task 3 test suite: SUCCESS
```

---

# Task 4 — Adversarial Automated Tests

Task 4 contains separate automated pytest files in the `tests/` directory.

The tests cover:

1. Valid handshake and bidirectional messages
2. Modified ciphertext
3. Modified authenticated header
4. Replayed record
5. Reflected record
6. Reflected/invalid handshake signature

Because the tests import files from the parent `hw2` directory, run them with:

```bash
PYTHONPATH=. pytest -v tests
```

A successful test run should show:

```text
collected 6 items

tests/test_modified_ciphertext.py ... PASSED
tests/test_modified_header.py ... PASSED
tests/test_reflected_handshake.py ... PASSED
tests/test_reflected_record.py ... PASSED
tests/test_replay.py ... PASSED
tests/test_valid_handshake.py ... PASSED

6 passed
```

Each adversarial test uses assertions or `pytest.raises()` to verify that the attack results in a safe rejection.

---

# Running Everything

After activating the virtual environment:

```bash
cd ~/Downloads/HW1/HW1/csce465-agentsec
source .venv/bin/activate
cd hw2
```

Run Task 1:

```bash
python baseline_ctr.py
```

Run Task 2:

```bash
python handshake.py
```

Run Task 3:

```bash
python secure_record.py
```

Run Task 4:

```bash
PYTHONPATH=. pytest -v tests
```

## Notes

Do not commit generated Python cache files or the virtual environment. The following should be ignored by Git:

```text
__pycache__/
*.pyc
.venv/
.pytest_cache/
```

The `ffdhe3072.pem` file is required by the Task 2 implementation and should be included in the repository if required by the assignment submission instructions.
