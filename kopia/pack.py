"""Pack file related functions."""
import os
from secrets import token_bytes

from .postamble import decode_postamble, encode_postamble, generate_postamble
from .local_index import decode_index, encode_index, generate_local_index, verify_supported_index
from .crypto import encrypt, decrypt, blake2b_hash, EncryptionData
from .content import get_verified_block_data
from .util import DOWNLOADED_BLOBS_DIR, RECOVERED_BLOBS_DIR, get_index_by_blob, read_bytes

PADDING_UNIT = 4096
RANDOM_PREAMBLE_LENGTH = 32
NONCE_LENGTH = 12
INDEX_RANDOM_SUFFIX_LENGTH = 32


def empty_metadata():
    """Random metadata insde a pack file."""
    return {
        "random_header": None,
        "block_nonces": {},  # dict: offset -> nonce
        "padding_bytes": None,
        "local_index_random_suffix": None,
        "local_index_nonce": None,
    }


def get_pack_metadata(file: str, p: EncryptionData):
    """Attempt to extract the random metadata inside a pack file."""
    meta = empty_metadata()
    if os.path.isfile(file):
        header_len = RANDOM_PREAMBLE_LENGTH
        try:
            meta["random_header"] = read_bytes(file, length=header_len)
        except Exception:
            print("info: could not read random header in pack file")

        offsets = []
        index = None
        try:
            index, index_nonce, postamble = decode_pack_index(file, p)
        except Exception:
            print("info: could not decrypt and decode local index")
        if index is not None:
            verify_supported_index(index)
            meta['local_index_nonce'] = index_nonce
            meta['local_index_random_suffix'] = bytes.fromhex(index["random_suffix"])
            for entry in index['entries']:
                offsets.append(entry['pack_offset'])
            last_block_end = max(e['pack_offset'] + e['packed_length'] for e in index['entries'])
            pad_length = postamble['local_index_offset'] - last_block_end
            try:
                meta['padding_bytes'] = read_bytes(file, offset=last_block_end, length=pad_length)
            except Exception:
                print("info: could not read padding bytes")

        for offset in offsets:
            try:
                meta["block_nonces"][offset] = read_bytes(file, offset=offset, length=NONCE_LENGTH)
            except Exception:
                print(f"info: could not read nonce at offset {offset}")

    return meta


def decode_pack_index(pack_file: str, p: EncryptionData):
    """Decode the local index inside a pack BLOB file."""
    postamble = decode_postamble(pack_file)
    local_index_offset = postamble['local_index_offset']
    assert local_index_offset % PADDING_UNIT == 0, 'index not aligned'
    if not read_bytes(pack_file).endswith(encode_postamble(postamble)):
        raise ValueError('postamble mismatch')

    # Local index
    encrypted_local_index = read_bytes(
        pack_file, offset=postamble['local_index_offset'], length=postamble['local_index_length']
    )
    iv = bytes.fromhex(postamble['local_index_iv'])
    local_index = decrypt(encrypted_local_index, p.master_key, iv)

    # Verify re-encryption
    nonce = encrypted_local_index[:12]
    test = encrypt(local_index, p.master_key, iv, nonce)
    assert encrypted_local_index == test

    # Verify IV
    iv_test = blake2b_hash(local_index, p.hmac_secret)
    assert iv_test == iv

    # Decode the index data and verify
    decoded_index = decode_index(local_index)
    local_index_test = encode_index(decoded_index)
    assert local_index_test == local_index, "encoded index differs"

    return decoded_index, nonce, postamble


def rebuild_pack_content(blob_id, index, p: EncryptionData, metadata=None) -> list[bytes]:
    """Rebuild pack."""
    # Metadata (i.e. random data) of original pack file (if available)
    if metadata is None:
        metadata = empty_metadata()

    # Header
    fixed_header_len = RANDOM_PREAMBLE_LENGTH
    header_len = index[0][2]
    assert header_len == fixed_header_len, "only support fixed length random header (preamble)"

    # Random preamble
    preamble = metadata['random_header'] or token_bytes(RANDOM_PREAMBLE_LENGTH)
    to_write = [preamble]

    # Encrypted data blocks
    index_dict = {block_id: {
        'time': time, 'offset': offset, 'packed_length': length
    } for block_id, time, offset, length in index}
    for block_id, _, offset, length in index:
        block_data = get_verified_block_data(block_id, p)
        index_dict[block_id]['original_length'] = len(block_data)
        nonce = metadata['block_nonces'].get(offset, None) or token_bytes(NONCE_LENGTH)
        content_id = bytes.fromhex(block_id)

        ciphertext = encrypt(block_data, p.master_key, content_id, nonce)
        assert len(ciphertext) == length, (
            "ciphertext length differs. maybe data was compressed, "
            "but compression is currently not implemented."
        )

        to_write.append(ciphertext)

    # Add padding such that local index starts at an offset that is a multiple of PADDING_UNIT
    if PADDING_UNIT > 0:
        length = sum(len(item) for item in to_write)
        missing_bytes = PADDING_UNIT - length % PADDING_UNIT
        padding_bytes = metadata['padding_bytes']
        if padding_bytes is None or len(padding_bytes) != missing_bytes:
            padding_bytes = token_bytes(missing_bytes)
        to_write.append(padding_bytes)

    # Local index
    random_suffix = metadata['local_index_random_suffix'] or token_bytes(INDEX_RANDOM_SUFFIX_LENGTH)
    local_index = generate_local_index(blob_id, index_dict, random_suffix)
    encoded_index = encode_index(local_index)
    index_iv = blake2b_hash(encoded_index, p.hmac_secret)
    index_nonce = metadata['local_index_nonce'] or token_bytes(NONCE_LENGTH)
    encrypted_index = encrypt(encoded_index, p.master_key, index_iv, index_nonce)
    index_offset = sum(len(item) for item in to_write)
    to_write.append(encrypted_index)

    # Postamble
    postamble = generate_postamble(index_iv, index_offset, len(encrypted_index))
    postamble_encoded = encode_postamble(postamble)
    to_write.append(postamble_encoded)

    return to_write


def write_pack_content(to_write: list[bytes], file) -> None:
    """Write pack content to file."""
    with open(file, 'wb') as f:
        for item in to_write:
            f.write(item)


def rebuild_pack_file(output_file, blob_id, index, p: EncryptionData, metadata=None) -> None:
    """Rebuild pack and write to file."""
    to_write = rebuild_pack_content(blob_id, index, p, metadata=metadata)
    write_pack_content(to_write, output_file)


def rebuild_pack(blob_id: str, p: EncryptionData) -> str:
    """Rebuild pack file from global index and recovered blocks and save to default location."""
    # Parameters
    original_blob_file = os.path.join(DOWNLOADED_BLOBS_DIR, blob_id)
    output_file = os.path.join(RECOVERED_BLOBS_DIR, blob_id)

    # Read metadata of original file (if exists)
    metadata = get_pack_metadata(original_blob_file, p)

    # Read index
    index = get_index_by_blob(blob_id)
    assert len(index) > 0, f"BLOB {blob_id} not found in global index"

    # Rebuild pack
    rebuild_pack_file(output_file, blob_id, index, p, metadata)
    return output_file
