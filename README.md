# CTF Toolkit

All-in-one CLI helper for CTF competitions — Forensics, Cryptography, Pwn (binary exploitation),
and Reverse Engineering — built as an interactive `FLAG>` shell.

## Install

Works out of the box with just Python 3 standard library. A few modules unlock extra power
if you install these optional libraries:

```bash
pip install pillow capstone pyelftools
```

| Library     | Unlocks                                              |
|-------------|-------------------------------------------------------|
| Pillow      | Full EXIF reading, LSB steganography preview          |
| capstone    | Real disassembly output (`reverse disasm`)             |
| pyelftools  | Accurate NX/PIE/RELRO/Canary detection (`pwn checksec`)|

Without them, the tool still works using manual fallbacks (raw byte scanning, manual ELF header
parsing, hex dump instead of disassembly).

## Run

**Interactive mode** (recommended — matches the `FLAG>` shell style):

```bash
python3 flag.py
```

Then inside the shell:

```
FLAG> modules
FLAG> forensic strings ./challenge.png
FLAG> forensic hidden ./challenge.png
FLAG> forensic entropy ./challenge.bin
FLAG> crypto identify 5d41402abc4b2a76b9719d911017c592
FLAG> crypto caesar synt{uryyb} 13
FLAG> crypto xor 1a2b3c4d
FLAG> pwn pattern_create 100
FLAG> pwn pattern_offset aaadaaa
FLAG> pwn checksec ./chall
FLAG> reverse fileinfo ./chall
FLAG> reverse disasm ./chall
FLAG> exit
```

**One-shot CLI mode** (for scripting / piping into other tools):

```bash
python3 ctf_toolkit.py forensic strings ./challenge.png
python3 ctf_toolkit.py crypto caesar "synt{uryyb}"
python3 ctf_toolkit.py pwn pattern_create 200
python3 ctf_toolkit.py reverse fileinfo ./chall
```

## Modules

### forensic
- `metadata <file>` — file signature detection, magic bytes, extension mismatch warning
- `exif <file>` — EXIF metadata (full via Pillow, raw scan fallback otherwise)
- `strings <file> [min_len]` — extract printable strings, auto-highlights flag-looking strings
- `hidden <file>` — trailing data after EOF markers, embedded file signatures, LSB stego quick-check,
  zero-width unicode detection
- `entropy <file> [chunk_size]` — Shannon entropy + visual entropy map to spot encrypted/compressed regions

### crypto
- `base64 encode|decode <text>`
- `hex encode|decode <text>`
- `rot13 <text>`
- `caesar <text> [shift]` — brute-forces all 26 shifts if no shift given
- `xor <hex> [key]` — single-byte XOR brute-force with printable-text scoring if no key given
- `identify <text>` — guesses encoding/hash type from format and length

### pwn
- `pattern_create <length>` — De Bruijn cyclic pattern generator (like pwntools' `cyclic()`)
- `pattern_offset <value>` — find offset of a crash value (hex/decimal/substring) in the pattern
- `checksec <file>` — NX / PIE / Stack Canary / RELRO check for ELF binaries

### reverse
- `fileinfo <file>` — parses ELF/PE headers (architecture, entry point, type)
- `strings <file> [min_len]` — same as forensic strings
- `disasm <file_or_hexbytes> [arch]` — disassembly via capstone (x86, x86_64, arm, arm64, mips)

## Notes

- This is a helper/triage tool, not a replacement for dedicated tools like `binwalk`, `zsteg`,
  `stegsolve`, `pwntools`, `ghidra`/`IDA`, or `hashcat`/`john` — use it to quickly narrow down
  where to look, then go deep with the specialized tool.
- Built for CTF COMPFEST 18 prep (forensic / crypto / pwn / reverse categories).
