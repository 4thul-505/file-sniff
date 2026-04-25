# magic_db.py
# Magic number database — maps byte signatures to (file type, valid extensions)
# Extensions that are naturally high entropy — don't flag these for entropy alone

HIGH_ENTROPY_EXTENSIONS = {
    '.gz', '.zip', '.rar', '.7z', '.bz2', '.xz', '.zst',
    '.mp4', '.mkv', '.avi', '.mov', '.webm', '.mpg', '.mpeg',
    '.mp3', '.flac', '.aac', '.ogg',
    '.jpg', '.jpeg', '.png', '.gif', '.webp',
    '.apk', '.jar', '.docx', '.xlsx', '.pptx',
}

# Suspicious strings to look for inside file content
SUSPICIOUS_STRINGS = [
    b'cmd.exe', b'powershell', b'CreateRemoteThread',
    b'VirtualAlloc', b'WinExec', b'ShellExecute',
    b'http://', b'https://', b'/bin/sh', b'/bin/bash',
    b'base64', b'eval(', b'exec(', b'socket',
    b'reverse', b'payload', b'shellcode',
]

MAGIC_DB = {
    b'\xff\xd8\xff':             ('JPEG Image',                ['.jpg', '.jpeg']),
    b'\x89PNG\r\n\x1a\n':       ('PNG Image',                 ['.png']),
    b'GIF87a':                   ('GIF Image',                 ['.gif']),
    b'GIF89a':                   ('GIF Image',                 ['.gif']),
    b'%PDF':                     ('PDF Document',              ['.pdf']),
    b'MZ':                       ('Windows PE Executable',     ['.exe', '.dll', '.sys', '.scr']),
    b'\x7fELF':                  ('ELF Executable',            ['.elf', '.so', '']),
    b'PK\x03\x04':              ('ZIP Archive',               ['.zip', '.docx', '.xlsx', '.pptx', '.apk', '.jar']),
    b'\x1f\x8b':                ('GZIP Archive',              ['.gz', '.tgz']),
    b'BZh':                      ('BZIP2 Archive',             ['.bz2']),
    b'\xfd7zXZ\x00':            ('XZ Archive',                ['.xz']),
    b'Rar!\x1a\x07':            ('RAR Archive',               ['.rar']),
    b'\xd0\xcf\x11\xe0':        ('MS Office Legacy',          ['.doc', '.xls', '.ppt']),
    b'RIFF':                     ('WAV/AVI Media',             ['.wav', '.avi']),
    b'ID3':                      ('MP3 Audio',                 ['.mp3']),
    b'\x42\x4d':                ('BMP Image',                 ['.bmp']),
    b'%!PS':                     ('PostScript',                ['.ps', '.eps']),
    b'\xca\xfe\xba\xbe':        ('Java Class File',           ['.class']),
    b'dex\n':                    ('Android DEX',               ['.dex']),
    b'\x7fSELF':                 ('PS4 Executable',            ['']),
    b'OggS':                     ('OGG Audio',                 ['.ogg', '.ogv']),
    b'fLaC':                     ('FLAC Audio',                ['.flac']),
    b'\x00\x00\x00\x18ftyp':    ('MP4 Video',                 ['.mp4', '.m4v', '.m4a']),
    b'\x00\x00\x00\x20ftyp':    ('MP4 Video',                 ['.mp4']),
    b'\x1a\x45\xdf\xa3':        ('MKV/WebM Video',            ['.mkv', '.webm']),
    b'<?xml':                    ('XML Document',              ['.xml', '.svg', '.xhtml']),
    b'<!DOCTYPE':                ('HTML Document',             ['.html', '.htm']),
    b'#!/':                      ('Script/Shebang',            ['.sh', '.py', '.rb', '.pl']),
    b'\x28\xb5\x2f\xfd':        ('Zstandard Archive',         ['.zst']),
    b'SQLite format 3':          ('SQLite Database',           ['.db', '.sqlite', '.sqlite3']),
    b'\x7fBSD':                  ('BSD Archive',               ['.a']),
}
