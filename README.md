# Apate


Apate is a lightweight cryptographic file protection tool and container specification (`.veil`) implemented in Python. It provides hybrid encryption that combines modern authenticated symmetric ciphers with RSA-OAEP asymmetric key encapsulation.

---

## Features

- **Hybrid Encryption**: Combines high-speed authenticated symmetric encryption with RSA-OAEP 2048-bit key wrapping.
- **Multiple Cipher Suites**:
  - `AES-256-GCM + RSA-OAEP` (Algorithm ID: `1`)
  - `ChaCha20-Poly1305 + RSA-OAEP` (Algorithm ID: `2`)
- **VEIL Container Specification**: Custom binary serialization format storing magic bytes, versioning, metadata, ciphertext, nonce, algorithm ID, and encapsulated keys.
- **Interactive Terminal UI**: Built with `rich` for formatting, menus, and status alerts.
- **Automated Key Storage**: Automatically stores RSA private keys under `~/.apate/<file_stem>/private_key.pem`.

---

## Binary Container Format (`.veil`)

Files encrypted by Apate are packed into a structured binary format:

| Field | Size / Type | Description |
| :--- | :--- | :--- |
| **Magic Header** | 4 bytes (`<4s`) | Magic bytes `b"VEIL"` |
| **Format Version** | 1 byte (`<B`) | Container specification version (`1`) |
| **Filename Length** | 8 bytes (`<Q`) | Length of the original filename in bytes |
| **Original Filename** | Variable (`UTF-8`) | Original source filename |
| **Ciphertext Length**| 4 bytes (`<I`) | Length of the encrypted payload |
| **Ciphertext** | Variable bytes | AEAD encrypted file content with authentication tag |
| **Nonce / IV** | 12 bytes | Nonce used for AEAD encryption |
| **Algorithm ID** | 1 byte (`<B`) | `1` = AES-256-GCM, `2` = ChaCha20-Poly1305 |
| **RSA Key Length** | 4 bytes (`<I`) | Byte length of the encrypted symmetric key |
| **Encapsulated Key** | Variable bytes | Symmetric key encrypted with RSA-OAEP (SHA-256) |

---

## Installation

### Prerequisites

- Python `>= 3.14`
- [uv](https://docs.astral.sh/uv/) or standard `pip` / `venv`

### Setup with virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography rich pytest
```

Or using `uv`:

```bash
uv sync
```

---

## Usage

### Interactive CLI

Launch the interactive prompt:

```bash
PYTHONPATH=src python3 src/main.py
```

Follow the on-screen options:
1. **Encrypt a file**: Select algorithm (`AES-256-GCM` or `ChaCha20-Poly1305`) and provide the file path. The generated `.veil` container is saved to `~/.apate/<stem>/<stem>.veil`, and the RSA private key is stored in `~/.apate/<stem>/private_key.pem`.
2. **Decrypt a file**: Provide the path to the `.veil` container. Apate unpacks the header, identifies the algorithm, loads the corresponding private key, and writes `decrypted_<original_filename>` next to the `.veil` file.

---

## Project Structure

```
├── .gitignore
├── .python-version
├── README.md
├── icon.png
├── pyproject.toml
├── uv.lock
└── src/
    ├── main.py                 # CLI interface and workflow execution
    ├── register.json           # Algorithm metadata registry
    └── apate/
        ├── __init__.py         # Package entry & file logging setup
        ├── encrypt.py          # AES-256-GCM and ChaCha20-Poly1305 encryption
        ├── decrypt.py          # Symmetric and RSA key decryption routines
        ├── format.py           # VEIL container pack and unpack functions
        ├── ui.py               # Rich terminal user interface
        └── tests/
            ├── test_apate.py   # Comprehensive pytest test suite
            ├── test.py         # Timing decorator & standalone test runner
            └── test_file.md    # Test fixture sample
```

---

## Running Tests

Run the test suite using `pytest`:

```bash
PYTHONPATH=src pytest src/apate/tests -v
```

Or execute the test runner directly:

```bash
PYTHONPATH=src python3 src/apate/tests/test.py
```
