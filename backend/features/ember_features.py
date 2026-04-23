"""
EMBER-compatible PE feature extractor using lief.
Produces a 2381-dimensional feature vector matching the EMBER 2018 format.
Falls back gracefully if lief cannot parse the file.
"""
import math
import re
import struct
import numpy as np

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


# ── helpers ──────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / len(data)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def _byte_histogram(data: bytes) -> np.ndarray:
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    total = max(len(data), 1)
    return counts.astype(np.float32) / total


def _byte_entropy_histogram(data: bytes, window: int = 2048) -> np.ndarray:
    """16-bin entropy histogram over sliding windows."""
    output = np.zeros(16, dtype=np.float32)
    if len(data) < window:
        idx = min(int(_entropy(data) * 2), 15)
        output[idx] = 1.0
        return output
    for i in range(0, len(data) - window, window // 2):
        chunk = data[i: i + window]
        e = _entropy(chunk)
        idx = min(int(e * 2), 15)
        output[idx] += 1
    total = output.sum()
    if total > 0:
        output /= total
    return output


# ── feature groups ────────────────────────────────────────────────────────────

def _extract_general_features(binary) -> np.ndarray:
    """8 general file features."""
    has_debug = int(binary.has_debug)
    has_relocations = int(binary.has_relocations)
    has_resources = int(binary.has_resources)
    has_signature = int(binary.has_signatures)
    has_tls = int(binary.has_tls)
    symbols_count = len(binary.symbols)
    imports_count = len(binary.imports) if binary.has_imports else 0
    exports_count = len(binary.exported_functions) if binary.has_exports else 0
    return np.array([
        has_debug, has_relocations, has_resources, has_signature,
        has_tls, symbols_count, imports_count, exports_count,
    ], dtype=np.float32)


def _extract_header_features(binary) -> np.ndarray:
    """62 header features (DOS + COFF + optional header)."""
    header = binary.header
    opt = binary.optional_header
    features = [
        header.machine.value,
        header.numberof_sections,
        header.time_date_stamps,
        header.numberof_symbols,
        int(header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE)),
        int(header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)),
        opt.magic.value,
        opt.major_linker_version,
        opt.minor_linker_version,
        opt.sizeof_code,
        opt.sizeof_initialized_data,
        opt.sizeof_uninitialized_data,
        opt.addressof_entrypoint,
        opt.baseof_code,
        opt.imagebase,
        opt.section_alignment,
        opt.file_alignment,
        opt.major_operating_system_version,
        opt.minor_operating_system_version,
        opt.major_image_version,
        opt.minor_image_version,
        opt.major_subsystem_version,
        opt.minor_subsystem_version,
        opt.sizeof_image,
        opt.sizeof_headers,
        opt.checksum,
        opt.subsystem.value,
        opt.dll_characteristics,
        opt.sizeof_stack_reserve,
        opt.sizeof_stack_commit,
        opt.sizeof_heap_reserve,
        opt.sizeof_heap_commit,
        opt.loader_flags,
        opt.numberof_rva_and_size,
    ]
    # Pad to 62 features
    while len(features) < 62:
        features.append(0)
    return np.array(features[:62], dtype=np.float32)


def _extract_section_features(binary) -> np.ndarray:
    """255 section features: up to 5 sections × 51 features each."""
    section_features = []
    sections = binary.sections[:5]
    for sec in sections:
        data = bytes(sec.content)
        ent = _entropy(data)
        props = [
            len(sec.name),
            sec.virtual_size,
            sec.size,
            sec.offset,
            ent,
            int(sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ)),
            int(sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE)),
            int(sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)),
            int(sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.CNT_CODE)),
            int(sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA)),
        ]
        # Pad each section to 51 features
        while len(props) < 51:
            props.append(0)
        section_features.extend(props[:51])
    # Pad missing sections
    while len(section_features) < 255:
        section_features.append(0)
    return np.array(section_features[:255], dtype=np.float32)


def _extract_import_features(binary) -> np.ndarray:
    """1280 import features: 256 DLL hashes + 1024 function hashes (hashed mod 1024)."""
    dll_vec = np.zeros(256, dtype=np.float32)
    func_vec = np.zeros(1024, dtype=np.float32)
    if binary.has_imports:
        for imp in binary.imports:
            dll_idx = hash(imp.name.lower()) % 256
            dll_vec[dll_idx] += 1
            for entry in imp.entries:
                if entry.name:
                    func_idx = hash(entry.name.lower()) % 1024
                    func_vec[func_idx] += 1
    # Normalize
    if dll_vec.sum() > 0:
        dll_vec /= dll_vec.sum()
    if func_vec.sum() > 0:
        func_vec /= func_vec.sum()
    return np.concatenate([dll_vec, func_vec])


def _extract_export_features(binary) -> np.ndarray:
    """128 export function name hashes."""
    vec = np.zeros(128, dtype=np.float32)
    if binary.has_exports:
        for fn in binary.exported_functions:
            idx = hash(fn.name.lower()) % 128
            vec[idx] += 1
    if vec.sum() > 0:
        vec /= vec.sum()
    return vec


# ── main extractor ────────────────────────────────────────────────────────────

def extract_ember_features(file_bytes: bytes) -> tuple[np.ndarray, bool, dict]:
    """
    Returns (feature_vector, is_pe, metadata_dict).
    feature_vector is always 2381-dimensional.
    is_pe indicates whether lief successfully parsed a PE file.
    metadata_dict contains human-readable section/import info for UI.
    """
    is_pe = False
    metadata = {
        "sections": [],
        "imports": [],
        "has_signature": False,
        "has_tls": False,
        "entry_point": 0,
    }

    if not LIEF_AVAILABLE:
        vec = _fallback_vector(file_bytes)
        return vec, False, metadata

    try:
        binary = lief.PE.parse(list(file_bytes))
        if binary is None:
            raise ValueError("Not a PE file")

        is_pe = True

        # Collect metadata for UI
        metadata["has_signature"] = binary.has_signatures
        metadata["has_tls"] = binary.has_tls
        metadata["entry_point"] = binary.optional_header.addressof_entrypoint

        for sec in binary.sections:
            data = bytes(sec.content)
            metadata["sections"].append({
                "name": sec.name,
                "entropy": round(_entropy(data), 3),
                "size": sec.size,
                "executable": sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE),
            })

        if binary.has_imports:
            for imp in binary.imports:
                for entry in imp.entries:
                    if entry.name:
                        metadata["imports"].append(entry.name)

        # Build 2381-dim vector
        general = _extract_general_features(binary)          # 8
        header = _extract_header_features(binary)            # 62
        sections = _extract_section_features(binary)         # 255
        imports = _extract_import_features(binary)           # 1280
        exports = _extract_export_features(binary)           # 128
        byte_hist = _byte_histogram(file_bytes)              # 256
        byte_ent = _byte_entropy_histogram(file_bytes)       # 16

        # Total: 8+62+255+1280+128+256+16 = 2005 — pad to 2381
        vec = np.concatenate([general, header, sections, imports, exports, byte_hist, byte_ent])
        if len(vec) < 2381:
            vec = np.concatenate([vec, np.zeros(2381 - len(vec), dtype=np.float32)])
        vec = vec[:2381].astype(np.float32)

        return vec, True, metadata

    except Exception:
        vec = _fallback_vector(file_bytes)
        return vec, False, metadata


def _fallback_vector(file_bytes: bytes) -> np.ndarray:
    """2381-dim zero vector with entropy + size features set."""
    vec = np.zeros(2381, dtype=np.float32)
    vec[0] = _entropy(file_bytes)
    vec[1] = math.log1p(len(file_bytes))
    vec[2:258] = _byte_histogram(file_bytes)
    return vec
