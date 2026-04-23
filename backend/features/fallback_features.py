"""
Heuristic feature extraction for non-PE files.
Returns a threat score (0–100) and a list of warning signs.
"""
import math
import re
import struct
import numpy as np

MAGIC_SIGNATURES = {
    b"\x25\x50\x44\x46": "PDF",
    b"\x50\x4b\x03\x04": "ZIP/DOCX/XLSX/JAR",
    b"\x4d\x5a": "PE/EXE",
    b"\x7f\x45\x4c\x46": "ELF",
    b"\xca\xfe\xba\xbe": "Mach-O",
    b"\xd0\xcf\x11\xe0": "MS Office (OLE)",
    b"\x1f\x8b": "GZIP",
    b"\x52\x61\x72\x21": "RAR",
    b"\x37\x7a\xbc\xaf": "7-Zip",
}

SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"WScript", b"eval(", b"exec(",
    b"base64_decode", b"CreateRemoteThread", b"VirtualAlloc",
    b"ShellExecute", b"RegSetValue", b"HKEY_", b"socket(",
    b"urllib", b"requests.get", b"wget ", b"curl ",
    b"<script", b"javascript:", b"document.write",
]

EXTENSION_MIME_MAP = {
    ".pdf": "PDF",
    ".docx": "ZIP/DOCX/XLSX/JAR",
    ".xlsx": "ZIP/DOCX/XLSX/JAR",
    ".zip": "ZIP/DOCX/XLSX/JAR",
    ".jar": "ZIP/DOCX/XLSX/JAR",
    ".exe": "PE/EXE",
    ".dll": "PE/EXE",
    ".elf": "ELF",
    ".gz": "GZIP",
    ".rar": "RAR",
    ".7z": "7-Zip",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / len(data)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def detect_magic(data: bytes) -> str:
    for sig, name in MAGIC_SIGNATURES.items():
        if data[:len(sig)] == sig:
            return name
    return "Unknown"


def analyze_fallback(file_bytes: bytes, filename: str) -> dict:
    """
    Returns:
        score: 0–100 heuristic threat score
        warning_signs: list of strings
        metadata: dict with entropy, magic, size info
    """
    warnings = []
    score = 0

    entropy = _entropy(file_bytes)
    file_size = len(file_bytes)
    magic = detect_magic(file_bytes)
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # Extension vs magic mismatch
    expected_magic = EXTENSION_MIME_MAP.get(ext)
    if expected_magic and magic != expected_magic:
        warnings.append(f"Extension/magic byte mismatch: {ext} vs {magic}")
        score += 20

    # High entropy (packed/encrypted content)
    if entropy > 7.2:
        warnings.append(f"Very high file entropy ({entropy:.2f}) — possible encryption or packing")
        score += 25
    elif entropy > 6.5:
        warnings.append(f"Elevated file entropy ({entropy:.2f}) — possible obfuscation")
        score += 12

    # Suspicious strings
    found_strings = []
    for s in SUSPICIOUS_STRINGS:
        if s in file_bytes:
            found_strings.append(s.decode("utf-8", errors="replace"))
    if found_strings:
        warnings.append(f"Suspicious strings detected: {', '.join(found_strings[:4])}")
        score += min(len(found_strings) * 8, 30)

    # Embedded PE in non-PE file
    if ext not in (".exe", ".dll") and b"\x4d\x5a" in file_bytes[2:]:
        warnings.append("Embedded PE executable detected inside non-PE file")
        score += 20

    # Embedded script in binary
    if b"<script" in file_bytes.lower() and ext not in (".html", ".htm", ".js"):
        warnings.append("Embedded script tag detected in non-HTML file")
        score += 15

    # Very small or suspiciously large
    if file_size < 512:
        warnings.append(f"Unusually small file size ({file_size} bytes)")
        score += 5

    score = min(score, 100)

    return {
        "score": score,
        "warning_signs": warnings,
        "metadata": {
            "entropy": round(entropy, 3),
            "magic": magic,
            "file_size": file_size,
            "extension": ext,
        },
    }
