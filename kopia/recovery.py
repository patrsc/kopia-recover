from dataclasses import dataclass, asdict
import os
import json

from .util import (
    get_content, get_sub_path_id, fetch_all_contents, FOUND_BLOCKS_DIR, RECOVERED_BLOCKS_DIR,
    DOWNLOADED_BLOBS_DIR, download_blob, get_index_by_blob, get_raw_content
)


@dataclass
class BlockInfo:
    block_id: str
    object_id: str
    object_path: str
    offset: int
    length: int


def find_blocks(root_dir_id, dirs, blocks_to_find):
    """Find blocks in saved blocks and in given dirs (saves them for future use)."""
    found_blocks = read_saved_blocks()
    for item in found_blocks:
        if item in blocks_to_find:
            blocks_to_find.remove(item)
    if len(blocks_to_find) > 0:
        new_found_blocks = find_blocks_in_dirs(root_dir_id, dirs, blocks_to_find)
        save_found_blocks(new_found_blocks)

    found_blocks = read_saved_blocks()
    if len(found_blocks) == 0:
        print("found all missing blocks.")
    return found_blocks


def find_blocks_in_dirs(root_dir_id, dir_paths, blocks_to_find):
    found_blocks = {}
    dir_paths = dir_paths if len(dir_paths) > 0 else ["."]
    for dir_path in dir_paths:
        if len(blocks_to_find) == 0:
            break
        dir_id = get_sub_path_id(root_dir_id, dir_path)
        found_blocks = find_blocks_in_dir(dir_path, dir_id, blocks_to_find, found_blocks)

    return found_blocks


def find_blocks_in_dir(dir_path, dir_id, blocks_to_find, found_blocks=None):
    if found_blocks is None:
        found_blocks = {}

    if len(blocks_to_find) == 0:
        return found_blocks

    n = len(blocks_to_find)
    content = get_content(dir_id)
    indirect = []

    print(f"looking for {n} missing blocks in: {dir_path}")
    dirs = []
    for item in content['entries']:
        name = item['name']
        obj = item['obj']
        path = os.path.join(dir_path, name)
        t = item['type']
        if t == "d":
            dirs.append((path, obj))
        elif obj.startswith('I'):
            indirect_id = obj[1:]
            indirect.append((indirect_id, path, obj))
        else:
            block_id = obj
            if block_id in blocks_to_find:
                print(f"found block {block_id}, required by object {obj}, file: {path}")
                found_blocks[block_id] = BlockInfo(
                    block_id=block_id,
                    object_id=obj,
                    object_path=path,
                    offset=0,
                    length=item['size'],
                )
                blocks_to_find.remove(block_id)
                if len(blocks_to_find) == 0:
                    break

    if len(blocks_to_find) == 0:
        return found_blocks
    c_all = fetch_all_contents([ind[0] for ind in indirect]) if len(indirect) > 0 else []
    for c, (indirect_id, path, obj) in zip(c_all, indirect):
        for indirect_entry in c['entries']:
            block_id = indirect_entry['o']
            offset = indirect_entry.get('s', 0)
            length = indirect_entry['l']
            if block_id in blocks_to_find:
                print(f"found block {block_id}, required by object {obj}, file: {path}")
                found_blocks[block_id] = BlockInfo(
                    block_id=block_id,
                    object_id=obj,
                    object_path=path,
                    offset=offset,
                    length=length,
                )
                blocks_to_find.remove(block_id)
        if len(blocks_to_find) == 0:
            break

    for dir_p, dir_obj in dirs:
        if len(blocks_to_find) == 0:
            break
        found_blocks = find_blocks_in_dir(dir_p, dir_obj, blocks_to_find, found_blocks=found_blocks)

    return found_blocks


def save_found_blocks(found_blocks):
    for block, value in found_blocks.items():
        file = os.path.join(FOUND_BLOCKS_DIR, f"{block}.json")
        with open(file, 'w', encoding='utf-8') as f:
            json.dump(asdict(value), f, indent=4)

def read_saved_blocks():
    d = FOUND_BLOCKS_DIR
    blocks = {}
    for file in os.listdir(d):
        path = os.path.join(d, file)
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            print(f'warning: could not read file {path}')
        b = BlockInfo(**data)
        blocks[b.block_id] = b
    return blocks


def put_found_blocks(source_dir, found_blocks: dict[str, BlockInfo]):
    """Put found blocks to recovered blocks directory using source files."""
    for block in found_blocks.values():
        src = os.path.join(source_dir, block.object_path)
        dst = os.path.join(RECOVERED_BLOCKS_DIR, block.block_id)
        with open(src, 'rb') as inp, open(dst, 'wb') as out:
            inp.seek(block.offset)
            out.write(inp.read(block.length))


def recover_blocks(blob_id, root_dir_id, source_dir, dirs):
    """Try to recover all blocks in a BLOB (without verification of block content)."""
    # Try to download BLOB
    blob_missing = False
    file = os.path.join(DOWNLOADED_BLOBS_DIR, blob_id)
    if not os.path.isfile(file):
        try:
            download_blob(blob_id, file)
        except Exception:
            print(f'info: could not download blob {blob_id}')
            blob_missing = True

    # Get objects in BLOB according to global index
    index_items = get_index_by_blob(blob_id)
    blocks_to_get = [item[0] for item in index_items]
    index_dict = {}
    for block_id, time, offset, length in index_items:
        index_dict[block_id] = {
            'time': time,
            'offset': offset,
            'length': length,
        }

    # Get blocks from recovered blocks directory
    blocks_to_get = list(set(blocks_to_get) - set(os.listdir(RECOVERED_BLOCKS_DIR)))

    # Try to get blocks from kopia
    if not blob_missing:
        for block_id in blocks_to_get:
            # try get from kopia
            try:
                b = get_raw_content(block_id)
                with open(os.path.join(RECOVERED_BLOCKS_DIR, block_id), 'wb') as f:
                    f.write(b)
            except Exception:
                print(f"info: could not get block via kopia: {block_id}")

    # Try to find missing blocks using source directories
    blocks_to_get = list(set(blocks_to_get) - set(os.listdir(RECOVERED_BLOCKS_DIR)))
    if len(blocks_to_get) > 0:
        blocks_to_find = blocks_to_get
        found_blocks = find_blocks(root_dir_id, dirs, blocks_to_find)
        put_found_blocks(source_dir, found_blocks)

    # Check if all blocks were obtained
    blocks_to_get = list(set(blocks_to_get) - set(os.listdir(RECOVERED_BLOCKS_DIR)))
    if len(blocks_to_get) != 0:
        print("could not recover all blocks in BLOB")
    else:
        print("success: recovered all blocks.")
