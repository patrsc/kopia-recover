# kopia-recover

Python tool to recover broken or missing kopia pack file BLOBs.

**EXPERIMENTAL!!!** Be cautious when using this! Make backups of any BLOBs that you replace in your kopia repository! This is a proof of concept, code is quick and dirty.

Limitations:
* Compression feature not implemented: will not work for pack file BLOBs that have compressed blocks inside
* Only hash BLAKE2B-256-128 implemented
* Only encryptio algorithm AES256-GCM-HMAC-SHA256 implemented

## Usage

### Step 1: Installation

1. Clone this repo
2. Install Python 3.11
3. Install Poetry
4. Run `poetry install`

### Step 2: Recover blocks

TODO

### Step 3: Rebuild pack file (BLOB)

TODO
