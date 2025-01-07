from kopia.recovery import recover_blocks

# Edit these values
blob_id = "p737530c3e328c15957c7ab4abd1cd0a7-s4449481459c2ea6a21f"
root_dir_id = "kb1d60ad62d9f988465616b4f583c5a8d"  # root object of snapshot
source_dir = "/Users/patrick"  # source dir of snapshot
# sub-dirs to search within snapshot root dir
dirs = [
    "Documents",
    "Pictures",
]

recover_blocks(blob_id, root_dir_id, source_dir, dirs)
