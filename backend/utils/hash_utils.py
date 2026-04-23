import hashlib


def compute_hashes(file_bytes: bytes) -> dict:
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    md5 = hashlib.md5(file_bytes).hexdigest()
    return {"sha256": sha256, "md5": md5}
