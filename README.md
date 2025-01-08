# kopia-recover

Python tool to recover broken or missing kopia pack file BLOBs.

> [!CAUTION]
> **Experimental tool.** Be cautious when using this!
> Make backups of any files that you replace in your kopia repository!

> [!WARNING]
> This is a proof of concept, the code is quick and dirty.

#### Limitations

* Compression not implemented: will not work for pack file BLOBs containing compressed blocks
* Only hash BLAKE2B-256-128 implemented
* Only encryption algorithm AES256-GCM-HMAC-SHA256 implemented

## Usage

### Step 1: Installation

1. Clone this repository
2. Install [Python](https://www.python.org/) 3.11 and the [Poetry](https://python-poetry.org/) package manager
3. Open this folder and run `poetry install`
4. Kopia CLI must be installed and available via the `kopia` command
5. Connect to the repository where you want to restore the blobs on a computer that has the source files of the backup snapshots, check with `kopia repository status`

### Step 2: Recover blocks

To recover all blocks contained in pack BLOB according to the global index of the kopia repository, run:

```
poetry run python recover_blocks.py <your-blob-id> <source-dir> <root-dir-id> \
  <subpaths>...
```

where
* `<your-blob-id>` is the BLOB you want to recover, e.g. `p737530c3e328c15957c7ab4abd1cd0a7-s4449481459c2ea6a21f`
* `<source-dir>` is the snapshot source directory path, e.g. `/home/user`
* `<root-dir-id>` is the ID of the latest snapshot's root object (visible in Kopia UI), e.g. `kb1d60ad62d9f988465616b4f583c5a8d`
* `<subpaths>` (multiple optional arguments) are subpaths within the source directory path where the missing files should be looked for (will look in complete snapshot if omitted)

Example:

```
poetry run python recover_blocks.py p737530c3e328c15957c7ab4abd1cd0a7-s4449481459c2ea6a21f \
  /home/user kb1d60ad62d9f988465616b4f583c5a8d \
  Documents Pictures/Personal
```

Recovered blocks are saved to `temp/recovered-blocks`. Your kopia repository will not be modified.

### Step 3: Rebuild pack file (BLOB)

To rebuild the BLOB (pack file), run:

```
poetry run python rebuild_blob.py <your-blob-id>
```

The file will be saved to `temp/recovered-blobs`. Your kopia repository will not be modified.
You can now upload this file to your kopia repo, but **make a backup copy of any file that you might overwrite**.

Note: You will be asked to enter the repository password, which is required to rebuild the pack file
correctly (since it needs to encrypt blocks). If you feel uncomfortable entering the password in an
unknown tool, don't enter it, or review its source code.

Afterwards you should verify the repository consistency:

```
kopia snapshot verify --verify-files-percent=100
```

## See also

* [Recover missing or invalid BLOBs in the repository](https://github.com/kopia/kopia/issues/4332):
  Feature request to add this functionality directly in Kopia
