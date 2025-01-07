import struct
import zlib


def decode_postamble(pack_file_path):
    """Decode psotamble."""
    with open(pack_file_path, 'rb') as f:
        # Seek to the last byte to determine the postamble length
        f.seek(-1, 2)
        postamble_length = f.read(1)[0]

        # Seek to the start of the postamble
        f.seek(-postamble_length - 1, 2)
        postamble_data = f.read(postamble_length)

        # Decode the postamble
        offset = 0

        # Read the version flag
        version_flag, offset = read_varint(postamble_data, offset)
        assert version_flag == 1, "only version 1 postamble supported"

        # Read the length of localIndexIV
        iv_length, offset = read_varint(postamble_data, offset)

        # Read the localIndexIV
        local_index_iv = postamble_data[offset:offset + iv_length]
        offset += iv_length

        # Read the localIndexOffset
        local_index_offset, offset = read_varint(postamble_data, offset)

        # Read the localIndexLength
        local_index_length, offset = read_varint(postamble_data, offset)

        # Read and verify the checksum
        checksum = struct.unpack_from('>I', postamble_data, offset)[0]
        offset += 4
        computed_checksum = zlib.crc32(postamble_data[:offset - 4])
        if checksum != computed_checksum:
            raise ValueError(f"Checksum mismatch: expected {checksum}, got {computed_checksum}")

        result = {
            "local_index_iv": local_index_iv.hex(),
            "local_index_offset": local_index_offset,
            "local_index_length": local_index_length,
        }

        return result


def read_varint(data, offset):
    """Read a varint from data starting at offset."""
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return value, offset


def encode_postamble(data):
    """Generate the postamble bytes (including checksum and length) from a dictionary.

    :param data: Dictionary with keys `local_index_iv`,
                 `local_index_offset`, and `local_index_length`.
    :return: Bytes representing the postamble.
    """
    # Initialize buffer
    buf = bytearray()

    # Append version flag as varint
    version_flag = 1
    buf.extend(encode_varint(version_flag))

    # Append length of localIndexIV as varint
    iv = bytes.fromhex(data["local_index_iv"])
    buf.extend(encode_varint(len(iv)))

    # Append localIndexIV
    buf.extend(iv)

    # Append localIndexOffset as varint
    buf.extend(encode_varint(data["local_index_offset"]))

    # Append localIndexLength as varint
    buf.extend(encode_varint(data["local_index_length"]))

    # Compute and append checksum
    checksum = zlib.crc32(buf)
    buf.extend(struct.pack('>I', checksum))

    # Append length of the postamble
    if len(buf) > 255:
        raise ValueError(f"Postamble too long: {len(buf)} bytes")

    buf.append(len(buf))

    return bytes(buf)


def encode_varint(value):
    """Encode an integer as a varint.

    :param value: Integer to encode.
    :return: Bytes representing the varint.
    """
    buf = bytearray()
    while value > 0x7F:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)


def generate_postamble(index_iv: bytes, index_offset: int, index_length: int) -> dict:
    """Generate a new postamble."""
    return {
        "local_index_iv": index_iv.hex(),
        "local_index_offset": index_offset,
        "local_index_length": index_length,
    }
