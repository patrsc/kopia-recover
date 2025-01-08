# kopia-recover

Python tool to recover broken or missing kopia pack file BLOBs.

> [!CAUTION]
> **Experimental!**
> This tool is highly experimental! Be cautious when using it!
> Make backups of any files that you replace in your kopia repository!

> [!WARNING]
> This is a proof of concept, the code is quick and dirty.

Limitations:
* Compression feature not implemented: will not work for pack file BLOBs that have compressed blocks inside
* Only hash BLAKE2B-256-128 implemented
* Only encryption algorithm AES256-GCM-HMAC-SHA256 implemented

## Usage

### Step 1: Installation

1. Clone this repo
2. Install Python 3.11
3. Install Poetry
4. Run `poetry install`
5. Kopia-CLI must be installed and available via the `kopia` command

### Step 2: Recover blocks

Recover all blocks contained in pack BLOB according to the global index.

Edit the variables in `recover_blocks.py` according to your needs.

Run:

```
poetry run python recover_blocks.py
```

### Step 3: Rebuild pack file (BLOB)

Rebuild the blob by running:

```
poetry run python rebuild_blob.py <your-blob-id>
```

The file will be saved to `temp/recovered-blobs`. You can now upload this file to your kopia repo.
**Make a backup of any file that you might overwrite**.
