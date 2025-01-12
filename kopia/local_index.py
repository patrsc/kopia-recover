"""Local index."""
import struct
from dataclasses import dataclass
from .util import to_unix_time

VERSION2 = 2
V2_INDEX_HEADER_SIZE = 17
V2_PACK_INFO_SIZE = 5
V2_MAX_FORMAT_COUNT = 0xFF
V2_DELETED_MARKER = 0x80000000
V2_MAX_ENTRY_SIZE = 256
V2_ENTRY_MIN_LENGTH = 16
V2_ENTRY_MAX_LENGTH = 19
V2_FORMAT_INFO_SIZE = 6


@dataclass
class ID:
    """Content ID."""

    prefix: str  # empty or 1 char between 'g' and 'z'
    hash: bytes

    def to_str(self) -> str:
        """To string."""
        return self.prefix + self.hash.hex()

    @staticmethod
    def from_str(s: str) -> 'ID':
        """From string."""
        if len(s) % 2 == 0:
            prefix = ''
            h = bytes.fromhex(s)
        else:
            prefix = s[0]
            h = bytes.fromhex(s[1:])
        return ID(prefix=prefix, hash=h)

    def to_key(self) -> bytes:
        """To key."""
        if self.prefix == "":
            return b'\x00' + self.hash
        return bytes(self.prefix, encoding='utf-8') + self.hash

    @staticmethod
    def from_key(k: bytes) -> 'ID':
        """From string."""
        p = k[0:1]
        h = k[1:]
        prefix = "" if p == b'\x00' else p.decode('utf-8')
        return ID(prefix=prefix, hash=h)

    def __repr__(self) -> str:
        """Repr."""
        return f"ID({self.to_str()})"


def decode_index(data: bytes) -> dict:
    """Decode index."""
    # Read header
    header = data[:V2_INDEX_HEADER_SIZE]
    (
        version, key_size, entry_size, entry_count, pack_count, format_count, base_timestamp
    ) = struct.unpack('>B B H I I B I', header)
    header_data = {
        'version': version,
        'key_size': key_size,
        'entry_size': entry_size,
        'entry_count': entry_count,
        'pack_count': pack_count,
        'format_count': format_count,
        'base_timestamp': base_timestamp
    }

    # Ensure the header is valid
    if version != VERSION2:
        raise ValueError(f"Unsupported index version: {version}")
    if (
        key_size <= 1 or entry_size < V2_ENTRY_MIN_LENGTH or entry_size > V2_ENTRY_MAX_LENGTH
        or entry_count < 0 or format_count > V2_MAX_FORMAT_COUNT
    ):
        raise ValueError("invalid header")

    fixed_key_size = 17
    allowed_entry_sizes = [16, 17]
    assert key_size == fixed_key_size, f"key size must be {fixed_key_size}"
    assert entry_size in allowed_entry_sizes, "only optional byte 16 currently supported."
    assert pack_count == 1, "we are only interested in local index for single pack file."
    assert base_timestamp == 0, "base timestamp must be 0"

    entry_stride = key_size + entry_size
    if entry_stride > V2_MAX_ENTRY_SIZE:
        raise ValueError("invalid header - entry stride too big")

    entries_offset = V2_INDEX_HEADER_SIZE
    packs_offset = entries_offset + entry_count * entry_stride
    formats_offset = packs_offset + pack_count * V2_PACK_INFO_SIZE
    extra_data_offset = formats_offset + format_count * V2_FORMAT_INFO_SIZE

    # pre-read formats section
    formats_buf = data[formats_offset:formats_offset + format_count * V2_FORMAT_INFO_SIZE]

    formats = []
    entries = []
    packs = []

    # Parse formats section
    for i in range(format_count):
        format_info = formats_buf[i * V2_FORMAT_INFO_SIZE:(i + 1) * V2_FORMAT_INFO_SIZE]
        (
            compression_header_id, format_version, encryption_key_id
        ) = struct.unpack('>I B B', format_info)
        assert format_version == 2
        formats.append({
            'compression_header_id': compression_header_id,
            'format_version': format_version,
            'encryption_key_id': encryption_key_id
        })

    # Parse entries section
    entries_buf = data[entries_offset:entries_offset + entry_count * entry_stride]
    for i in range(entry_count):
        key_entry_info = entries_buf[i * entry_stride:(i + 1) * entry_stride]
        key = key_entry_info[0:key_size]
        entry_info = key_entry_info[key_size:]
        cid = ID.from_key(key)

        # Decode entry
        timestamp, pack_offset_flags = struct.unpack('>I I', entry_info[0:8])
        original_length = int.from_bytes(entry_info[8:11], byteorder='big')
        packed_length = int.from_bytes(entry_info[11:14], byteorder='big')
        pack_id = int.from_bytes(entry_info[14:16], byteorder='big')

        flag_is_deleted = pack_offset_flags >= V2_DELETED_MARKER
        if flag_is_deleted:
            pack_offset = pack_offset_flags - V2_DELETED_MARKER
        else:
            pack_offset = pack_offset_flags

        format_id, = struct.unpack('B', entry_info[16:17]) if len(entry_info) > 16 else (0,)

        entries.append({
            'key': cid.to_str(),
            'timestamp': timestamp,
            'pack_offset': pack_offset,
            'flag_is_deleted': flag_is_deleted,
            'original_length': original_length,
            'packed_length': packed_length,
            'pack_id': pack_id,
            'format_id': format_id,
        })

    # Parse pack names in extra data
    pack_buf = data[packs_offset:packs_offset + pack_count * V2_PACK_INFO_SIZE]
    for i in range(pack_count):
        pack_info = pack_buf[i * V2_PACK_INFO_SIZE:(i + 1) * V2_PACK_INFO_SIZE]
        pack_name_length, pack_name_offset = struct.unpack('>B I', pack_info)
        packs.append({
            'pack_name_length': pack_name_length,
            'pack_name_offset': pack_name_offset,
        })

    # Extra data: contains pack names
    extra_data_length = sum(p['pack_name_length'] for p in packs)
    extra_data = data[extra_data_offset:extra_data_offset+extra_data_length]
    random_suffix_offset = extra_data_offset + extra_data_length
    for i in range(pack_count):
        p = packs[i]
        offset = p['pack_name_offset'] - extra_data_offset
        length = p['pack_name_length']
        # overwrite offset/length with actual name
        name = extra_data[offset:offset + length].decode('utf-8')
        packs[i] = name

    random_suffix = data[random_suffix_offset:]
    assert len(random_suffix) == 32, "random suffix length must be 32"

    return {
        'header': header_data,
        'formats': formats,
        'entries': entries,
        'packs': packs,
        'random_suffix': random_suffix.hex(),
    }


def encode_index(index_dict: dict) -> bytes:
    """Encode index."""
    header = index_dict['header']
    formats = index_dict['formats']
    entries = index_dict['entries']
    packs = index_dict['packs']
    random_suffix = bytes.fromhex(index_dict['random_suffix'])

    # Encode the header
    header_bytes = struct.pack(
        '>B B H I I B I',
        header['version'],
        header['key_size'],
        header['entry_size'],
        header['entry_count'],
        header['pack_count'],
        header['format_count'],
        header['base_timestamp']
    )

    # Ensure the header is valid
    allowed_entry_sizes = [16, 17]
    assert header['version'] == VERSION2, "Unsupported index version"
    assert header['key_size'] == 17, "Key size must be 17"
    assert header['entry_size'] in allowed_entry_sizes, "Entry size must be 16 or 17 for now"
    assert header['pack_count'] == 1, "Pack count must be 1"
    assert header['base_timestamp'] == 0, "Base timestamp must be 0"

    entries_bytes = bytearray()
    for entry in entries:
        # Convert key to binary
        cid = ID.from_str(entry['key'])
        key_bytes = cid.to_key()

        # Pack entry info
        pack_offset_flags = (
            entry['pack_offset'] + V2_DELETED_MARKER if entry['flag_is_deleted']
            else entry['pack_offset']
        )
        entry_info = struct.pack(
            '>I I',
            entry['timestamp'],
            pack_offset_flags
        )
        entry_info += entry['original_length'].to_bytes(3, byteorder='big')
        entry_info += entry['packed_length'].to_bytes(3, byteorder='big')
        entry_info += entry['pack_id'].to_bytes(2, byteorder='big')
        if header['entry_size'] > 16:
            entry_info += entry['format_id'].to_bytes(1)

        # Append to entries
        entries_bytes.extend(key_bytes + entry_info)

    # Offsets
    entry_stride = header['key_size'] + header['entry_size']
    entries_offset = V2_INDEX_HEADER_SIZE
    packs_offset = entries_offset + header['entry_count'] * entry_stride
    formats_offset = packs_offset + header['pack_count'] * V2_PACK_INFO_SIZE
    extra_data_offset = formats_offset + header['format_count'] * V2_FORMAT_INFO_SIZE

    # Encode the pack section
    packs_bytes = bytearray()
    extra_data = bytearray()
    current_offset = 0
    for pack in packs:
        name_bytes = pack.encode('utf-8')
        pack_info = struct.pack('>B I', len(name_bytes), current_offset + extra_data_offset)
        packs_bytes.extend(pack_info)
        extra_data.extend(name_bytes)
        current_offset += len(name_bytes)

    # Encode the formats section
    formats_bytes = bytearray()
    for fmt in formats:
        formats_bytes.extend(struct.pack(
            '>I B B',
            fmt['compression_header_id'],
            fmt['format_version'],
            fmt['encryption_key_id']
        ))

    # Concatenate all parts
    result = bytearray()
    result.extend(header_bytes)
    result.extend(entries_bytes)
    result.extend(packs_bytes)
    result.extend(formats_bytes)
    result.extend(extra_data)
    result.extend(random_suffix)

    return bytes(result)


def generate_local_index(blob_id, index_dict, random_suffix):
    entries = generate_entries(index_dict)
    return {
        "header": {
            "version": 2,
            "key_size": 17,
            "entry_size": 16,
            "entry_count": len(index_dict),
            "pack_count": 1,
            "format_count": 1,
            "base_timestamp": 0,
        },
        "entries": entries,
        "formats": [
            {
                "compression_header_id": 0,
                "format_version": 2,
                "encryption_key_id": 0
            },
        ],
        "packs": [blob_id],
        "random_suffix": random_suffix.hex()
    }


def verify_supported_index(index):
    """Verify restrictions of current implementation (e.g. no compression)."""
    assert index['header']['entry_size'] == 16, "only single format currently implemented"
    assert index['header']['pack_count'] == 1, "only single pack allowed"
    assert index['header']['format_count'] == 1, "only single format currently implemented"
    for f in index['formats']:
        assert f['compression_header_id'] == 0, "compression not implemented"
        assert f['format_version'] == 2, "format version must be 2"
        assert f['encryption_key_id'] == 0, "encryption_key_id must be 0"


def generate_entries(index_dict):
    keys_sorted = sorted(index_dict.keys())
    entries = []
    for key in keys_sorted:
        value = index_dict[key]
        entry = {
            "key": key,
            "timestamp": to_unix_time(value['time']),
            "pack_offset": value['offset'],
            "flag_is_deleted": False,
            "original_length": value['original_length'],
            "packed_length": value['packed_length'],
            "pack_id": 0,
            "format_id": 0
        }
        entries.append(entry)
    return entries
