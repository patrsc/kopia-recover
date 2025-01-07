from dataclasses import dataclass
import hashlib
import json
import base64
import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt, HKDF
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF as Hkdf
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .util import read_bytes


@dataclass
class EncryptionData:
    """Encryption data."""

    hmac_secret: bytes
    master_key: bytes
    unique_id: bytes


def hkdf_sha256(input_key, salt, info, output_length=32):
    """Perform HKDF with SHA256."""
    return HKDF(input_key, output_length, salt, SHA256, context=info.encode())


def decrypt_kopia_repository(repo_data, verbose=False) -> EncryptionData:
    """Get decrypted kopia repository info."""
    # Step 1: Repo config
    if verbose:
        print("Repo config:")
        print(json.dumps(repo_data, indent=4))

    # Extract relevant information
    key_algo = repo_data["keyAlgo"]
    encryption = repo_data["encryption"]
    encrypted_block_format = repo_data["encryptedBlockFormat"]
    unique_id = base64.b64decode(repo_data["uniqueID"])

    if encryption != "AES256_GCM":
        raise ValueError("Unsupported encryption algorithm: Only AES256_GCM is supported.")

    # Step 2: Ask the user for the repository password
    repo_password = getpass.getpass("Enter kopia repository password: ")

    # Parse scrypt parameters
    if not key_algo.startswith("scrypt"):
        raise ValueError("Unsupported key algorithm: Only scrypt is supported.")

    _, n, r, p = key_algo.split('-')
    n, r, p = int(n), int(r), int(p)

    # Derive master key (Km) using scrypt with UniqueID as salt
    key_len = 32  # AES256 requires a 32-byte key
    master_key = scrypt(repo_password.encode(), unique_id, key_len, N=n, r=r, p=p)

    # Derive AES key (Ke) and additional data (AD) using HKDF
    aes_key = hkdf_sha256(master_key, unique_id, "AES", 32)
    additional_data = hkdf_sha256(master_key, unique_id, "CHECKSUM", 32)

    if verbose:
        print(f"Derived AES key (Ke): {aes_key.hex()}")  # Debugging
        print(f"Derived Additional Data (AD): {additional_data.hex()}")  # Debugging

    # Decode the encryptedBlockFormat
    encrypted_data = base64.b64decode(encrypted_block_format)

    # Extract IV and ciphertext from the encrypted data
    iv_len = 12  # GCM mode uses a 12-byte IV
    iv = encrypted_data[:iv_len]
    ciphertext = encrypted_data[iv_len:-16]  # Last 16 bytes are the GCM tag
    tag = encrypted_data[-16:]

    if verbose:
        print(f"IV: {iv.hex()}")  # Debugging
        print(f"Ciphertext: {ciphertext.hex()}")  # Debugging
        print(f"Tag: {tag.hex()}")  # Debugging

    # Decrypt the ciphertext using AES GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    cipher.update(additional_data)  # Use additional data for integrity check
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

    # Parse the decrypted JSON content
    decrypted_json = json.loads(decrypted_data)

    # Step 3: Pretty-print the decrypted JSON content
    if verbose:
        print(json.dumps(decrypted_json, indent=4))

    # Get HMAC secret
    secret_base64 = decrypted_json['format']['secret']
    secret = base64.b64decode(secret_base64)
    if verbose:
        print(f"HMAC Secret: {secret.hex()}")

    # Get Master key
    key_base64 = decrypted_json['format']['masterKey']
    key = base64.b64decode(key_base64)
    if verbose:
        print(f"Master Key: {key.hex()}")

    # Check requirements
    repo_format = decrypted_json["format"]
    required = {
        "hash": "BLAKE2B-256-128",
        "encryption": "AES256-GCM-HMAC-SHA256",
        "indexVersion": 2,
    }
    for k, value in required.items():
        val = repo_format[k]
        assert val == value, f"only {k}={value} is supported at the moment (got: {val})"

    d = EncryptionData(hmac_secret=secret, master_key=key, unique_id=unique_id)
    return d


def blake2b_hash(data, hmac_secret):
    h = hashlib.blake2b(data, key=hmac_secret, digest_size=32)
    return h.digest()[:16]


def blake2b_hash_file(file_path, hmac_secret):
    return blake2b_hash(read_bytes(file_path), hmac_secret)


def derive_key(master_secret: bytes, purpose: bytes, length: int) -> bytes:
    """Derive a key using HKDF with SHA-256."""
    hkdf = Hkdf(
        algorithm=hashes.SHA256(),
        length=length,
        salt=purpose,
        info=None,
    )
    return hkdf.derive(master_secret)


def get_aead_key(master_secret: bytes, content_id: bytes) -> bytes:
    """Derive the per-content AEAD key using HMAC-SHA256."""
    # Derive key for HMAC using HKDF
    derived_key = derive_key(master_secret, b'encryption', 32)

    # Create HMAC-SHA256 instance
    h = hmac.HMAC(derived_key, hashes.SHA256())

    # Update HMAC with content_id
    h.update(content_id)

    # Finalize and get the per-content key
    return h.finalize()


def decrypt(ciphertext: bytes, master_secret: bytes, content_id: bytes) -> bytes:
    """Decrypt using AES256-GCM."""
    # Validate master_secret and content_id lengths
    assert len(master_secret) == 32
    assert len(content_id) == 16

    # Ensure ciphertext is long enough to contain nonce and authentication tag
    nonce_size = 12  # AES-GCM standard nonce size
    overhead = 16    # AES-GCM authentication tag size

    if len(ciphertext) < nonce_size + overhead:
        raise ValueError("Error: Ciphertext is too short to contain nonce and authentication tag.")

    # Split nonce and actual ciphertext
    nonce = ciphertext[:nonce_size]
    actual_ciphertext = ciphertext[nonce_size:]

    # Derive AEAD key
    aead_key = get_aead_key(master_secret, content_id)

    # Initialize AESGCM with the derived key
    aesgcm = AESGCM(aead_key)

    # Decrypt the ciphertext
    # Associated data is the content_id
    plaintext = aesgcm.decrypt(nonce, actual_ciphertext, associated_data=content_id)
    return plaintext


def encrypt(plaintext: bytes, master_secret: bytes, content_id: bytes, nonce: bytes) -> bytes:
    """Encrypt using AES256-GCM."""
    # Validate master_secret and content_id lengths
    assert len(master_secret) == 32
    assert len(content_id) == 16

    # Validate nonce length
    nonce_size = 12  # AES-GCM standard nonce size
    assert len(nonce) == nonce_size, f"Nonce must be {nonce_size} bytes long."

    # Derive AEAD key
    aead_key = get_aead_key(master_secret, content_id)

    # Initialize AESGCM with the derived key
    aesgcm = AESGCM(aead_key)

    # Encrypt the plaintext
    # Associated data is the content_id
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=content_id)

    # Return the nonce prepended to the ciphertext
    return nonce + ciphertext
