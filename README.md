# file-sniff

A file triage tool that identifies real file types using magic numbers — regardless of extension.

Built for malware analysis workflows and incident response triage.

---

## How it works

Every file format has a unique byte signature at the start of the file called a **magic number**.

| File Type | Magic Bytes | ASCII |
|---|---|---|
| JPEG | `FF D8 FF` | — |
| Windows EXE | `4D 5A` | `MZ` |
| ELF Binary | `7F 45 4C 46` | `.ELF` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK` |

Attackers rename malware as `image.jpg` or `document.pdf` to evade basic extension checks.  
file-sniff reads the actual header bytes and compares them against a database of known signatures — the extension means nothing here.

---

## Signals analyzed

| Signal | What it checks |
|---|---|
| Magic bytes vs extension | Does the file claim to be what it actually is? |
| Shannon entropy | Is the content packed, encrypted, or obfuscated? |
| Suspicious strings | Shell commands, IPs, API calls hidden inside the file? |
| SHA256 + VirusTotal | Is this hash known malware? |

---

## Verdict language

| Verdict | Meaning |
|---|---|
| `CLEAN` | No anomalies detected |
| `SUSPICIOUS` | One or more soft signals present |
| `INVESTIGATE` | Extension mismatch or executable disguised as media |

The tool never says "MALWARE" — it surfaces signals, you investigate.

---

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/file-sniff
cd file-sniff
pip install requests --break-system-packages
```

Set your VirusTotal API key (free at virustotal.com):

```bash
echo 'export VT_KEY="your_key_here"' >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

```bash
# Scan a single file
python3 scanner.py suspicious_file.jpg

# Scan a directory
python3 scanner.py /path/to/folder

# Only save flagged results to report.json
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
    [VT] ⚠ MALICIOUS — 43/76 engines flagged
         Name : trojan.agent/generic
         Type : Win32 EXE
```

---

## Test it

```bash
# Create a fake JPEG (actually a Linux binary)
cp /bin/ls test_files/totally_a_photo.jpg

# Run the scan
python3 scanner.py test_files/
```

---

## Completed
- [x] Magic number detection across 30+ file types
- [x] Shannon entropy analysis with format-aware whitelisting
- [x] Suspicious string extraction
- [x] SHA256 hashing
- [x] VirusTotal API auto-lookup for INVESTIGATE verdicts
- [x] JSON report export

## Planned (v2)
- [ ] YARA rule support
- [ ] PE header analysis (imports, sections, imphash)
- [ ] HTML report output
- [ ] MalwareBazaar fallback lookup

---

## References

- [Gary Kessler's File Signatures Table](https://www.garykessler.net/library/file_sigs.html)
- [VirusTotal](https://www.virustotal.com)
- [any.run sandbox](https://any.run)
- [MalwareBazaar](https://bazaar.abuse.ch/)
