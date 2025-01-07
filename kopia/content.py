"""Content related functions."""
import os

from .crypto import EncryptionData, blake2b_hash_file
from .util import RECOVERED_BLOCKS_DIR, read_bytes


def get_verified_block_data(block_id: str, p: EncryptionData) -> bytes:
    """Read and verify a recovered block file."""
    file = os.path.join(RECOVERED_BLOCKS_DIR, block_id)
    if not os.path.isfile(file):
        raise ValueError(f"File not found: {file}")
    h = blake2b_hash_file(file, p.hmac_secret)
    if h.hex() != block_id:
        raise ValueError(f"integrity check failed: hash mismatch for file {file}")
    data = read_bytes(file)
    return data
