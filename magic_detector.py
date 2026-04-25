# magic_detector.py
# Core detection engine — fixed version
# Fixes applied:
#   1. Entropy reads only first 1MB (not full file)
#   2. Magic bytes treated as one signal, not ground truth
#   3. Entropy whitelist for naturally high-entropy formats
#   4. SHA256 hashing for known-malware lookup
#   5. Suspicious string extraction
#   6. Verdict is "INVESTIGATE" not "MALWARE"

import os
import math
import re
import hashlib

from magic_db import MAGIC_DB, HIGH_ENTROPY_EXTENSIONS, SUSPICIOUS_STRINGS


# ──────────────────────────────────────────────
# FILE READING
# ──────────────────────────────────────────────

def read_header(filepath, num_bytes=32):
    """Read first N bytes for magic number matching."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(num_bytes)
    except (IOError, PermissionError):
        return None


def read_sample(filepath, num_bytes=1_000_000):
    """Read first 1MB sample — enough for entropy + strings, avoids memory issues on large files."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(num_bytes)
    except (IOError, PermissionError):
        return None


# ──────────────────────────────────────────────
# DETECTION FUNCTIONS
# ──────────────────────────────────────────────

def detect_type(header):
    """Match file header against magic number database."""
    for magic, (filetype, extensions) in MAGIC_DB.items():
        if header.startswith(magic):
            return filetype, extensions
    return None, []


def calculate_entropy(data):
    """
    Shannon entropy over a byte sample.
    Returns float 0.0–8.0. Above 7.2 is high.
    Only call this with pre-read sample data, not a filepath.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def get_sha256(filepath):
    """Stream SHA256 hash — safe for large files."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, PermissionError):
        return None


def extract_suspicious_strings(data):
    """
    Extract printable ASCII strings (min 6 chars) from sample.
    Then flag any that match known suspicious patterns.
    """
    all_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
    hits = []
    for pattern in SUSPICIOUS_STRINGS:
        for s in all_strings:
            if pattern.lower() in s.lower() and s not in hits:
                hits.append(s.decode('ascii', errors='replace'))
    return hits


# ──────────────────────────────────────────────
# MAIN ANALYSIS
# ──────────────────────────────────────────────

def analyze_file(filepath):
    """
    Full file analysis. Returns a result dict with signals and flags.
    Verdict language: INVESTIGATE / SUSPICIOUS / CLEAN — never "MALWARE".
    """
    header = read_header(filepath)
    if header is None:
        return None

    sample = read_sample(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    filename = os.path.basename(filepath)
    size = os.path.getsize(filepath)

    detected_type, valid_extensions = detect_type(header)
    entropy = calculate_entropy(sample) if sample else 0.0
    sha256 = get_sha256(filepath)
    suspicious_strings = extract_suspicious_strings(sample) if sample else []

    result = {
        'path': filepath,
        'filename': filename,
        'extension': ext if ext else '(none)',
        'size_bytes': size,
        'sha256': sha256,
        'detected_type': detected_type or 'Unknown',
        'entropy': entropy,
        'suspicious_strings': suspicious_strings[:10],  # cap at 10 for readability
        'flags': [],
        'verdict': 'CLEAN',
    }

    # ── SIGNAL 1: Extension mismatch
    if detected_type and valid_extensions:
        if ext not in valid_extensions:
            result['flags'].append(
                f"Extension mismatch — claims '{ext}' but header matches '{detected_type}'"
            )

    # ── SIGNAL 2: Entropy — only flag if not a naturally high-entropy format
    if entropy > 7.2 and ext not in HIGH_ENTROPY_EXTENSIONS:
        result['flags'].append(
            f"High entropy ({entropy}/8.0) in non-archive file — possible packed/encrypted content"
        )

    # ── SIGNAL 3: Executable disguised as media/doc
    executable_types = ('Windows PE Executable', 'ELF Executable', 'Android DEX', 'Java Class File')
    benign_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.docx', '.xlsx', '.mp4', '.mp3'}
    if detected_type in executable_types and ext in benign_extensions:
        result['flags'].append(
            f"CRITICAL — Executable ({detected_type}) disguised as '{ext}'"
        )

    # ── SIGNAL 4: Suspicious strings found
    if suspicious_strings:
        result['flags'].append(
            f"Suspicious strings found: {', '.join(suspicious_strings[:5])}"
        )

    # ── SIGNAL 5: Zero-byte or suspiciously tiny file
    if size == 0:
        result['flags'].append("Empty file (0 bytes)")
    elif size < 10 and detected_type in executable_types:
        result['flags'].append("Suspiciously small for an executable")

    # ── VERDICT — based on signal count and severity
    critical_flags = [f for f in result['flags'] if 'CRITICAL' in f or 'mismatch' in f]
    if critical_flags:
        result['verdict'] = 'INVESTIGATE'
    elif result['flags']:
        result['verdict'] = 'SUSPICIOUS'
    else:
        result['verdict'] = 'CLEAN'

    return result


# ──────────────────────────────────────────────
# DISPLAY
# ──────────────────────────────────────────────

VERDICT_ICON = {
    'CLEAN':       '✓',
    'SUSPICIOUS':  '⚠',
    'INVESTIGATE': '✗',
}

def print_result(result):
    if result is None:
        return

    icon = VERDICT_ICON.get(result['verdict'], '?')
    print(f"\n[{icon}] {result['filename']}")
    print(f"    Path      : {result['path']}")
    print(f"    Extension : {result['extension']}")
    print(f"    Detected  : {result['detected_type']}")
    print(f"    Entropy   : {result['entropy']}/8.0")
    print(f"    Size      : {result['size_bytes']:,} bytes")
    print(f"    SHA256    : {result['sha256']}")
    print(f"    Verdict   : {result['verdict']}")

    if result['flags']:
        for flag in result['flags']:
            print(f"    >> {flag}")
