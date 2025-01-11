import json
import subprocess
import os

TEMP_DIR = "temp"
DOWNLOADED_BLOBS_DIR = f"{TEMP_DIR}/downloaded-blobs"
RECOVERED_BLOBS_DIR = f"{TEMP_DIR}/recovered-blobs"
RECOVERED_BLOCKS_DIR = f"{TEMP_DIR}/recovered-blocks"
FOUND_BLOCKS_DIR = f"{TEMP_DIR}/found-blocks"
FULL_INDEX_FILE = f"{TEMP_DIR}/index_full.txt"
REPO_CONFIG = f"{TEMP_DIR}/repo.json"


def init():
    create_temp_dirs()


def create_temp_dirs():
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
    if path == ".":
        return root_id
    sub_id = root_id
    for item in path.split('/'):
        c = get_content(sub_id)
        sub_id = get_object_by_name(c, item)
    return sub_id


def get_object_by_name(content, name):
    for entry in content['entries']:
        if entry['name'] == name:
            return entry['obj']
    raise ValueError(f'not found: {name}')


def get_content(cid):
    cmd = ["kopia", "content", "show", cid, "--json"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    output_json = json.loads(result.stdout)
    return output_json


def get_raw_content(cid):
    cmd = ["kopia", "content", "show", cid]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, check=True)
    return bytes(result.stdout)


def fetch_all_contents(cids):
    results = []
    cmd = ["kopia", "content", "show", *cids]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    items = result.stdout.split("\n")
    results = [json.loads(item) for item in items if item != ""]
    return results


def parse_index(raw_index_data):
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
    print(f"Downloading repo index and save it to file {file}. This might take a while...")
    cmd = ["kopia", "index", "inspect", "--all"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    with open(file, 'w', encoding='utf-8') as f:
        f.write(result.stdout)


def get_raw_index_by_blob(blob_id):
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
    raw_index = get_raw_index_by_blob(blob_id)
    return parse_index(raw_index)


def download_blob(blob_id, file):
    cmd = ["kopia", "blob", "show", blob_id]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, check=True)
    with open(file, 'wb') as f:
        f.write(result.stdout)


def get_repo_config():
    blob_id = 'kopia.repository'
    file = REPO_CONFIG
    if not os.path.isfile(file):
        download_blob(blob_id, file)
    return read_json(file)


def read_json(file):
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


init()
