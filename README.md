# Magic Detector

A file triage tool that identifies real file types using magic numbers — regardless of extension.

Built for malware analysis workflows and incident response triage.

---

## How it works

Every file format has a unique byte signature at the start of the file called a **magic number**.  
For example:
- JPEG always starts with `FF D8 FF`
- Windows EXE starts with `4D 5A` (ASCII: `MZ`)
- ELF Linux binary starts with `7F 45 4C 46`

Attackers rename malware as `image.jpg` or `document.pdf` to evade basic extension checks.  
This tool reads the actual header bytes and compares them to a database of known signatures.

---

## Signals analyzed

| Signal | What it checks |
|---|---|
| Extension vs magic bytes | Does the file claim to be what it actually is? |
| Shannon entropy | Is the content packed, encrypted, or obfuscated? |
| Suspicious strings | Does it contain shell commands, URLs, or API calls? |
| SHA256 hash | For manual lookup on MalwareBazaar |

**Verdict language:**
- `CLEAN` — no anomalies detected
- `SUSPICIOUS` — one or more soft signals
- `INVESTIGATE` — extension mismatch or executable disguised as media

The tool never says "MALWARE". It surfaces signals — you investigate.

---

## Usage

```bash
# Scan a single file
python3 scanner.py suspicious_file.jpg

# Scan a directory
python3 scanner.py /path/to/folder

# Save only flagged results to report.json
python3 scanner.py /path/to/folder --flagged-only

# Skip saving report
python3 scanner.py /path/to/folder --no-report
```

---

## Output example

```
[✗] fake_image.jpg
    Path      : ./test_files/fake_image.jpg
    Extension : .jpg
    Detected  : Windows PE Executable
    Entropy   : 6.21/8.0
    Size      : 142,512 bytes
    SHA256    : a3f1c2...
    Verdict   : INVESTIGATE
    >> Extension mismatch — claims '.jpg' but header matches 'Windows PE Executable'
    >> CRITICAL — Executable (Windows PE Executable) disguised as '.jpg'
```

---

## Planned upgrades (v2)

- [ ] VirusTotal API integration for hash lookup
- [ ] YARA rule support for pattern matching
- [ ] PE header analysis (imports, sections, imphash)
- [ ] MalwareBazaar API auto-lookup for INVESTIGATE verdicts
- [ ] HTML report output

---

## Test it

```bash
# Create a fake JPEG (actually an ELF binary)
cp /bin/ls test_files/totally_a_photo.jpg

# Run the scanner
python3 scanner.py test_files/
```

---

## References

- [Gary Kessner's Magic Numbers List](https://www.garykessler.net/library/file_sigs.html)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [any.run sandbox](https://any.run)
