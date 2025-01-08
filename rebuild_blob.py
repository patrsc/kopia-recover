"""Rebuild BLOB (pack file).

Usage: rebuild_blob.py blob_id
"""

import sys

from kopia import encryption_parameters
from kopia.pack import rebuild_pack


def main():
    """Run blob recovery."""
    blob_id = sys.argv[1]
    p = encryption_parameters()
    file = rebuild_pack(blob_id, p)
    print(f'Recovered BLOB saved to: {file}')


main()
