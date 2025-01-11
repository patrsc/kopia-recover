"""Find missing pack BLOB files in repository by going through all objects of one snapshot.

Usage: find_missing_packs.py <snapshot-root-dir-id> [<sub-dir-path>]

This can be helpful because `kopia snapshot verify --verify-files-percent=100` reports only one
missing BLOB pack file at a time. This will report all missing BLOB pack files at once in a given
snapshot.
"""

import sys
from kopia.recovery import find_missing_packs_in_dir
from kopia.util import get_sub_path_id


def main():
    """Run."""
    root_dir_id = sys.argv[1]
    dir_path = sys.argv[2] if len(sys.argv) > 2 else "."

    dir_id = get_sub_path_id(root_dir_id, dir_path)
    missing_packs = find_missing_packs_in_dir(dir_path, dir_id)
    print(f"Found {len(missing_packs)} missing packs.")


main()
