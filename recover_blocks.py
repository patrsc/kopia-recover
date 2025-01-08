"""Recover blocks inside BLOB.

Usage: recover_blocks.py <your-blob-id> <source-dir> <root-dir-id> <subpaths>...
"""
import sys

from kopia.recovery import recover_blocks


def main():
    """Run block recovery."""
    blob_id = sys.argv[1]
    source_dir = sys.argv[2]  # source dir of snapshot
    root_dir_id = sys.argv[3]  # root object of snapshot
    dirs = sys.argv[4:]  # sub-dirs to search within snapshot root dir

    print(f"BLOB ID: {blob_id}")
    print(f"Snapshot source directory: {source_dir}")
    print(f"Snapshot root object ID: {root_dir_id}")
    if len(dirs) == 0:
        print("Search in: all snapshot subdirectories")
    else:
        print("Search in subdirectories:")
        for d in dirs:
            print(f" - {d}")

    recover_blocks(blob_id, root_dir_id, source_dir, dirs)


main()
