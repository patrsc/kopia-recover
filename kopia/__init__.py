"""Restore missing or broken kopia pack files."""
from .util import get_repo_config
from .crypto import decrypt_kopia_repository, EncryptionData


def encryption_parameters() -> EncryptionData:
    """Get repo encryption parameters."""
    return decrypt_kopia_repository(get_repo_config())
