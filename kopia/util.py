"""Utility functions."""
import json
import subprocess
from subprocess import PIPE
import os
from datetime import timezone
from dateutil import parser

TEMP_DIR = "temp"
DOWNLOADED_BLOBS_DIR = f"{TEMP_DIR}/downloaded-blobs"
RECOVERED_BLOBS_DIR = f"{TEMP_DIR}/recovered-blobs"
RECOVERED_BLOCKS_DIR = f"{TEMP_DIR}/recovered-blocks"
FOUND_BLOCKS_DIR = f"{TEMP_DIR}/found-blocks"
FULL_INDEX_FILE = f"{TEMP_DIR}/index_full.txt"
REPO_CONFIG = f"{TEMP_DIR}/repo.json"
PACK_BLOB_LIST_FILE = f"{TEMP_DIR}/pack-blobs.json"


def init():
    """Initialize directories."""
    create_temp_dirs()


def create_temp_dirs():
    """Initialize temporary directories."""
    dirs = [
        DOWNLOADED_BLOBS_DIR,
        RECOVERED_BLOBS_DIR,
        RECOVERED_BLOCKS_DIR,
        FOUND_BLOCKS_DIR,
    ]
    for d in dirs:
        if not os.path.isdir(d):
            os.makedirs(d)


def get_sub_path_id(root_id, path):
    """Get directory ID of a subpath."""
    if path == ".":
        return root_id
    sub_id = root_id
    for item in path.split('/'):
        c = get_content(sub_id)
        sub_id = get_object_by_name(c, item)
    return sub_id


def get_object_by_name(content, name):
    """Get object ID by name."""
    for entry in content['entries']:
        if entry['name'] == name:
            return entry['obj']
    raise ValueError(f'not found: {name}')


def get_content(cid):
    """Get content from kopia."""
    cmd = ["kopia", "content", "show", cid, "--json"]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=True, check=True)
    output_json = json.loads(result.stdout)
    return output_json


def get_raw_content(cid):
    """Get raw content from kopia."""
    cmd = ["kopia", "content", "show", cid]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=False, check=True)
    return bytes(result.stdout)


def fetch_all_contents(cids):
    """Fetch contents from kopia."""
    results = []
    cmd = ["kopia", "content", "show", *cids]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=True, check=True)
    items = result.stdout.split("\n")
    results = [json.loads(item) for item in items if item != ""]
    return results


def parse_index(raw_index_data):
    """Parse global index."""
    lines = raw_index_data.split('\n')
    pack = None
    index_items = []
    for line in lines:
        if line == "":
            continue
        t_d, t_t, t_tz, idx, obj, cr, ot_d, ot_t, ot_tz, p, offset, length = line.split(" ")
        assert cr == "created"
        if pack is None:
            pack = p
        else:
            assert p == pack
        item_data = (
            obj,
            " ".join([ot_d, ot_t, ot_tz]),
            int(offset),
            int(length),
        )
        index_items.append(item_data)

    # Unique items
    index_items = list(set(index_items))
    index_items = sorted(index_items, key=lambda x: x[2])
    return index_items


def download_full_index(file):
    """Download full global index from kopia."""
    print(f"Downloading repo index and save it to file {file}. This might take a while...")
    cmd = ["kopia", "index", "inspect", "--all"]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=True, check=True)
    with open(file, 'w', encoding='utf-8') as f:
        f.write(result.stdout)


def get_raw_index_by_blob(blob_id):
    """Get raw index entries related to given BLOB."""
    file = FULL_INDEX_FILE
    if not os.path.isfile(file):
        download_full_index(file)
    found_lines = []
    with open(file, encoding='utf-8') as f:
        for line in f:
            if blob_id in line:
                found_lines.append(line)
    return "".join(found_lines)


def get_index_by_blob(blob_id):
    """Get index entries related to given BLOB."""
    raw_index = get_raw_index_by_blob(blob_id)
    return parse_index(raw_index)


def download_blob(blob_id, file):
    """Download a BLOB."""
    cmd = ["kopia", "blob", "show", blob_id]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=False, check=True)
    with open(file, 'wb') as f:
        f.write(result.stdout)


def get_index_map() -> dict[str, str]:
    """Return a dict mapping from object/block ID (key) to pack ID (value).

    Object IDs start with the characters 0-9 or a-f if they are blocks, or with k, m, x.
    Pack IDs start with p or q.
    """
    obj_to_pack = {}
    obj_to_times: dict[str, int] = {}
    file = FULL_INDEX_FILE
    if not os.path.isfile(file):
        download_full_index(file)
    with open(file, encoding='utf-8') as f:
        for line in f:
            items = line.split(" ")
            obj = items[4]
            pack = items[9]
            t_d, t_t, t_tz = items[0:3]
            t = to_unix_time(" ".join([t_d, t_t, t_tz]))
            if t > obj_to_times.get(obj, 0):  # add only if index time is newer
                obj_to_pack[obj] = pack
                obj_to_times[obj] = t
    return obj_to_pack


def get_repo_config():
    """Get kopia repository config."""
    blob_id = 'kopia.repository'
    file = REPO_CONFIG
    if not os.path.isfile(file):
        download_blob(blob_id, file)
    return read_json(file)


def read_json(file):
    """Read JSON from file."""
    with open(file, encoding='utf-8') as f:
        return json.load(f)


def read_bytes(file: str, offset: int = 0, length: int = -1) -> bytes:
    """Read data from binary file."""
    with open(file, 'rb') as f:
        f.seek(offset)
        data = f.read(length)
        if length >= 0 and len(data) != length:
            raise ValueError("could not read all required bytes.")
        return data


def get_pack_blob_set() -> set[str]:
    """Return a set of pack blobs."""
    packs = get_pack_blob_list()
    return set(p['id'] for p in packs)


def get_pack_blob_list():
    """Return list of pack blobs."""
    file = PACK_BLOB_LIST_FILE
    if not os.path.isfile(file):
        download_pack_blob_list(file)
    return read_json(file)


def download_pack_blob_list(file):
    """Download list of pack blobs."""
    print(f"Downloading list of all pack files and save it to {file}. This might take a while...")
    cmd = ["kopia", "blob", "list", "--prefix=p", "--json"]
    result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE, text=True, check=True)
    with open(file, 'w', encoding='utf-8') as f:
        f.write(result.stdout)


def to_unix_time(timestamp_str: str) -> int:
    """Parse Unix time in seconds from a timestamp string with timezone."""
    # Parse the timestamp with timezone using dateutil.parser
    dt_with_tz = parser.parse(timestamp_str)

    # Convert to UTC
    utc_dt = dt_with_tz.astimezone(timezone.utc)

    # Get Unix timestamp (seconds since epoch)
    unix_timestamp = int(utc_dt.timestamp())
    return unix_timestamp


init()
