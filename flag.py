#!/usr/bin/env python3
"""
CTF Toolkit - all-in-one helper for CTF competitions
(Forensics / Crypto / Pwn / Reverse Engineering)

Usage:
    Interactive mode:
        python3 ctf_toolkit.py

    One-shot CLI mode:
        python3 ctf_toolkit.py <module> <command> [args...]

Author: built for Gus (GusLab) - CTF COMPFEST 18 prep
"""

import sys
import os
import re
import cmd
import math
import base64
import string
import struct
import shlex
import codecs
import argparse
from collections import Counter

# ----------------------------------------------------------------------
# Optional dependencies - toolkit still works without them, just with
# reduced functionality in a few commands.
# ----------------------------------------------------------------------
try:
    from PIL import Image, ExifTags
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile
    HAVE_PYELFTOOLS = True
except ImportError:
    HAVE_PYELFTOOLS = False


# ----------------------------------------------------------------------
# Colors (ANSI) - matches the blue/orange CTF-shell aesthetic
# ----------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    ORANGE = "\033[38;5;208m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"


def cprint(text, color=C.RESET, bold=False):
    prefix = C.BOLD if bold else ""
    print(f"{prefix}{color}{text}{C.RESET}")


def hr(char="-", n=60):
    print(C.DIM + (char * n) + C.RESET)


# ========================================================================
# FORENSIC MODULE
# ========================================================================
class Forensic:
    """Forensics analysis tools: metadata, exif, strings, hidden, entropy"""

    SIGNATURES = {
        b"\x89PNG\r\n\x1a\n": "PNG image",
        b"\xff\xd8\xff": "JPEG image",
        b"GIF87a": "GIF image (87a)",
        b"GIF89a": "GIF image (89a)",
        b"%PDF": "PDF document",
        b"PK\x03\x04": "ZIP archive (also docx/xlsx/pptx/apk/jar)",
        b"Rar!\x1a\x07": "RAR archive",
        b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
        b"\x7fELF": "ELF executable",
        b"MZ": "PE executable (Windows)",
        b"BM": "BMP image",
        b"\x1f\x8b": "GZIP archive",
        b"ID3": "MP3 audio (ID3 tag)",
        b"OggS": "OGG media",
        b"RIFF": "RIFF container (WAV/AVI/WEBP)",
        b"\x00\x00\x00\x18ftyp": "MP4 video",
        b"\x00\x00\x00\x20ftyp": "MP4 video",
    }

    @staticmethod
    def _read(path):
        with open(path, "rb") as f:
            return f.read()

    @classmethod
    def metadata(cls, path):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        data = cls._read(path)
        size = len(data)
        cprint(f"\n=== METADATA: {path} ===", C.CYAN, bold=True)
        print(f"Size        : {size} bytes ({size/1024:.2f} KB)")
        print(f"MD5-like    : (use `crypto identify` on a hash if you have one)")

        # File signature detection
        detected = "Unknown"
        for sig, desc in cls.SIGNATURES.items():
            if data.startswith(sig):
                detected = desc
                break
        print(f"Signature   : {detected}")
        print(f"First bytes : {data[:16].hex(' ')}")
        print(f"Last bytes  : {data[-16:].hex(' ')}")

        # Extension vs signature mismatch check
        ext = os.path.splitext(path)[1].lower()
        print(f"Extension   : {ext or '(none)'}")
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip") and detected == "Unknown":
            cprint("  -> Extension doesn't match any known signature! Possibly disguised file.", C.YELLOW)

    @classmethod
    def exif(cls, path):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        cprint(f"\n=== EXIF: {path} ===", C.CYAN, bold=True)
        if HAVE_PIL:
            try:
                img = Image.open(path)
                exif_data = img.getexif()
                if not exif_data:
                    cprint("No EXIF data found via PIL.", C.YELLOW)
                else:
                    for tag_id, value in exif_data.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        print(f"{tag:25s}: {value}")
                print(f"\nFormat: {img.format}, Size: {img.size}, Mode: {img.mode}")
            except Exception as e:
                cprint(f"PIL failed to read image: {e}", C.RED)
        else:
            cprint("Pillow not installed - falling back to raw EXIF byte scan.", C.YELLOW)
            cls._raw_exif_scan(path)

    @classmethod
    def _raw_exif_scan(cls, path):
        data = cls._read(path)
        idx = data.find(b"Exif\x00\x00")
        if idx == -1:
            cprint("No 'Exif' marker found in file.", C.RED)
            return
        cprint(f"Found EXIF marker at offset {idx}", C.GREEN)
        # dump some printable strings around it as a crude fallback
        chunk = data[idx: idx + 512]
        printable = re.findall(rb"[ -~]{4,}", chunk)
        for p in printable[:20]:
            print(" ", p.decode(errors="replace"))

    @classmethod
    def strings(cls, path, min_len=4, encoding="ascii"):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        data = cls._read(path)
        cprint(f"\n=== STRINGS ({encoding}, min_len={min_len}): {path} ===", C.CYAN, bold=True)
        if encoding == "ascii":
            pattern = re.compile(rb"[ -~]{%d,}" % min_len)
            results = [m.decode() for m in pattern.findall(data)]
        else:  # utf-16le, common for Windows binaries
            pattern = re.compile(rb"(?:[ -~]\x00){%d,}" % min_len)
            results = [m.decode("utf-16le") for m in pattern.findall(data)]

        cprint(f"Found {len(results)} strings.", C.GREEN)
        for s in results[:500]:
            print(s)
        if len(results) > 500:
            cprint(f"... ({len(results)-500} more truncated, redirect to file to see all)", C.DIM)

        # Highlight interesting strings (flags, urls, base64-looking, etc.)
        interesting = [s for s in results if re.search(r"flag\{|FLAG\{|CTF\{|https?://|[A-Za-z0-9+/]{20,}={0,2}$", s)]
        if interesting:
            cprint("\n[+] Interesting strings:", C.ORANGE, bold=True)
            for s in interesting[:50]:
                print(" ", s)

    @classmethod
    def hidden(cls, path):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        data = cls._read(path)
        cprint(f"\n=== HIDDEN DATA CHECK: {path} ===", C.CYAN, bold=True)

        # 1. Trailing data after known EOF markers
        checks = [
            (b"\xff\xd9", "JPEG", data.rfind(b"\xff\xd9")),
            (b"IEND\xaeB`\x82", "PNG", data.find(b"IEND\xaeB`\x82")),
        ]
        found_trailing = False
        for marker, fmt, pos in checks:
            if pos != -1:
                end = pos + len(marker)
                trailing = data[end:]
                if trailing.strip(b"\x00"):
                    found_trailing = True
                    cprint(f"[+] Trailing data after {fmt} EOF marker ({len(trailing)} bytes)!", C.GREEN, bold=True)
                    print(f"    Offset: {end}")
                    print(f"    Preview: {trailing[:64]!r}")
        if not found_trailing:
            print("No trailing data found after common EOF markers.")

        # 2. LSB steganography quick check (images only)
        if HAVE_PIL:
            try:
                img = Image.open(path)
                cls._lsb_check(img)
            except Exception:
                pass
        else:
            cprint("Install Pillow for LSB steganography preview (pip install pillow).", C.DIM)

        # 3. Zero-width unicode steganography check (text-like content)
        zw_chars = re.findall(r"[\u200b\u200c\u200d\ufeff]", data.decode("utf-8", errors="ignore"))
        if zw_chars:
            cprint(f"[+] Found {len(zw_chars)} zero-width unicode characters - possible steganography!", C.GREEN, bold=True)

        # 4. Embedded file signature scan (look for other file sigs inside)
        cprint("\n[*] Scanning for embedded file signatures...", C.CYAN)
        embedded_found = False
        for sig, desc in cls.SIGNATURES.items():
            positions = [m.start() for m in re.finditer(re.escape(sig), data)]
            # Ignore the signature if it's right at offset 0 (that's just the file itself)
            positions = [p for p in positions if p != 0]
            if positions:
                embedded_found = True
                cprint(f"  -> {desc} signature found at offset(s): {positions[:10]}", C.YELLOW)
        if not embedded_found:
            print("No embedded file signatures found elsewhere in the file.")

    @staticmethod
    def _lsb_check(img):
        img = img.convert("RGB")
        w, h = img.size
        pixels = list(img.getdata())
        bits = []
        for px in pixels[: min(len(pixels), 8000)]:
            for channel in px:
                bits.append(channel & 1)
        # try to decode as ascii bytes
        byte_chunks = [bits[i:i+8] for i in range(0, len(bits) - 8, 8)]
        chars = []
        for chunk in byte_chunks:
            val = int("".join(map(str, chunk)), 2)
            if 32 <= val <= 126:
                chars.append(chr(val))
            else:
                chars.append(None)
        text = "".join(c if c else " " for c in chars)
        printable_runs = re.findall(r"[ -~]{6,}", text)
        if printable_runs:
            cprint("[+] LSB extraction found printable runs (possible stego):", C.GREEN, bold=True)
            for r in printable_runs[:10]:
                print("   ", r.strip())
        else:
            print("LSB quick-check: no obvious printable ASCII pattern found (try zsteg/stegsolve for deeper analysis).")

    @classmethod
    def entropy(cls, path, chunk_size=256):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        data = cls._read(path)
        cprint(f"\n=== ENTROPY ANALYSIS: {path} ===", C.CYAN, bold=True)

        overall = cls._shannon_entropy(data)
        print(f"Overall entropy: {overall:.4f} / 8.0 bits/byte")
        if overall > 7.5:
            cprint("  -> Very high entropy: likely encrypted or compressed data.", C.YELLOW)
        elif overall < 3.0:
            cprint("  -> Low entropy: likely plain text or structured/repetitive data.", C.YELLOW)

        # chunked entropy map (ascii bar chart) to spot regions of interest
        print(f"\nEntropy map (chunk size = {chunk_size} bytes):")
        n_chunks = min(len(data) // chunk_size + 1, 100)  # cap output length
        for i in range(n_chunks):
            chunk = data[i*chunk_size:(i+1)*chunk_size]
            if not chunk:
                continue
            e = cls._shannon_entropy(chunk)
            bar_len = int((e / 8.0) * 40)
            bar = "#" * bar_len
            color = C.RED if e > 7.5 else (C.YELLOW if e > 5 else C.GREEN)
            print(f"{color}{i*chunk_size:8d} | {bar:<40s} {e:.2f}{C.RESET}")

    @staticmethod
    def _shannon_entropy(data):
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy


# ========================================================================
# CRYPTO MODULE
# ========================================================================
class Crypto:
    """Cryptography tools: base64, hex, rot13, caesar, xor, identify"""

    @staticmethod
    def b64(mode, text):
        try:
            if mode == "encode":
                result = base64.b64encode(text.encode()).decode()
            else:
                # pad if necessary
                padded = text + "=" * (-len(text) % 4)
                result = base64.b64decode(padded).decode(errors="replace")
            cprint(f"\n=== BASE64 {mode.upper()} ===", C.CYAN, bold=True)
            print(result)
        except Exception as e:
            cprint(f"[!] Error: {e}", C.RED)

    @staticmethod
    def hexconv(mode, text):
        try:
            cprint(f"\n=== HEX {mode.upper()} ===", C.CYAN, bold=True)
            if mode == "encode":
                print(text.encode().hex())
            else:
                clean = text.replace(" ", "").replace("0x", "")
                print(bytes.fromhex(clean).decode(errors="replace"))
        except Exception as e:
            cprint(f"[!] Error: {e}", C.RED)

    @staticmethod
    def rot13(text):
        cprint("\n=== ROT13 ===", C.CYAN, bold=True)
        print(codecs.encode(text, "rot_13"))

    @staticmethod
    def caesar(text, shift=None):
        cprint("\n=== CAESAR CIPHER ===", C.CYAN, bold=True)
        if shift is not None:
            print(Crypto._caesar_shift(text, int(shift)))
            return
        # brute-force all shifts
        print("Bruteforcing all 26 shifts:\n")
        for s in range(26):
            result = Crypto._caesar_shift(text, s)
            print(f"  shift {s:2d}: {result}")

    @staticmethod
    def _caesar_shift(text, shift):
        out = []
        for ch in text:
            if ch.isupper():
                out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            elif ch.islower():
                out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def xor(hex_data, key=None):
        cprint("\n=== XOR ===", C.CYAN, bold=True)
        try:
            data = bytes.fromhex(hex_data.replace(" ", ""))
        except ValueError:
            cprint("[!] Input must be hex-encoded bytes.", C.RED)
            return

        if key:
            key_bytes = key.encode()
            result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
            print(f"Key: {key!r}")
            print(f"Result (raw)   : {result}")
            print(f"Result (ascii) : {result.decode(errors='replace')}")
            return

        # single-byte key bruteforce, score by printable ratio
        cprint("No key given - bruteforcing single-byte XOR key (top 15 by printable score):\n", C.YELLOW)
        scored = []
        for k in range(256):
            result = bytes(b ^ k for b in data)
            printable = sum(1 for b in result if 32 <= b <= 126)
            score = printable / len(result) if result else 0
            scored.append((score, k, result))
        scored.sort(key=lambda x: -x[0])
        for score, k, result in scored[:15]:
            preview = result[:60].decode(errors="replace")
            print(f"  key=0x{k:02x} ({chr(k) if 32<=k<=126 else '.'})  score={score:.2f}  {preview!r}")

    @staticmethod
    def identify(text):
        cprint(f"\n=== IDENTIFY: {text[:50]}{'...' if len(text) > 50 else ''} ===", C.CYAN, bold=True)
        text = text.strip()
        candidates = []

        hash_lengths = {
            32: "MD5 / NTLM / MD4",
            40: "SHA1",
            56: "SHA224",
            64: "SHA256 / SHA3-256 / Keccak-256",
            96: "SHA384",
            128: "SHA512 / SHA3-512",
        }
        if re.fullmatch(r"[a-fA-F0-9]+", text):
            length = len(text)
            if length in hash_lengths:
                candidates.append(f"Hex string, length {length} -> possibly {hash_lengths[length]}")
            else:
                candidates.append(f"Hex string, length {length} (not a common hash length)")

        if text.startswith("$2a$") or text.startswith("$2b$") or text.startswith("$2y$"):
            candidates.append("bcrypt hash")
        if text.startswith("$1$"):
            candidates.append("MD5 crypt (Unix)")
        if text.startswith("$6$"):
            candidates.append("SHA512 crypt (Unix)")
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
            candidates.append("Likely Base64 encoded")
        if re.fullmatch(r"[A-Za-z2-7]+=*", text) and len(text) % 8 == 0:
            candidates.append("Possibly Base32 encoded")
        if re.fullmatch(r"[01]+", text) and len(text) % 8 == 0:
            candidates.append("Possibly raw binary (bit string)")
        if re.fullmatch(r"[a-zA-Z ]+", text):
            candidates.append("Plain alphabetic text - try Caesar/ROT13/Vigenere")

        if not candidates:
            cprint("No confident match found. Try `crypto base64`, `crypto hex`, or a hash cracker (hashcat/john).", C.YELLOW)
        else:
            for c in candidates:
                print(" -", c)


# ========================================================================
# PWN MODULE
# ========================================================================
class Pwn:
    """Binary exploitation helpers: cyclic pattern, ELF checksec, offset finder"""

    @staticmethod
    def _de_bruijn(alphabet, n):
        """Generate a De Bruijn sequence (like pwntools' cyclic())."""
        k = len(alphabet)
        a = [0] * k * n
        sequence = []

        def db(t, p):
            if t > n:
                if n % p == 0:
                    sequence.extend(a[1:p + 1])
            else:
                a[t] = a[t - p]
                db(t + 1, p)
                for j in range(a[t - p] + 1, k):
                    a[t] = j
                    db(t + 1, t)

        db(1, 1)
        return "".join(alphabet[i] for i in sequence)

    @classmethod
    def pattern_create(cls, length):
        length = int(length)
        alphabet = string.ascii_lowercase
        seq = cls._de_bruijn(alphabet, 4)
        pattern = (seq * (length // len(seq) + 1))[:length]
        cprint(f"\n=== CYCLIC PATTERN (length={length}) ===", C.CYAN, bold=True)
        print(pattern)
        return pattern

    @classmethod
    def pattern_offset(cls, value):
        alphabet = string.ascii_lowercase
        seq = cls._de_bruijn(alphabet, 4)
        # extend pattern generously to search within
        full_pattern = seq * 200

        # value can be given as ascii substring, hex little-endian, or decimal
        needle = None
        if re.fullmatch(r"0x[0-9a-fA-F]+", value):
            raw = int(value, 16)
            try:
                needle = struct.pack("<I", raw).decode("latin1")
            except struct.error:
                needle = struct.pack("<Q", raw).decode("latin1")
        elif value.isdigit():
            raw = int(value)
            try:
                needle = struct.pack("<I", raw).decode("latin1")
            except struct.error:
                needle = struct.pack("<Q", raw).decode("latin1")
        else:
            needle = value

        offset = full_pattern.find(needle)
        cprint(f"\n=== PATTERN OFFSET SEARCH: {value!r} ===", C.CYAN, bold=True)
        if offset == -1:
            cprint("Value not found in pattern (try a shorter substring or check endianness).", C.RED)
        else:
            cprint(f"Offset found: {offset}", C.GREEN, bold=True)

    @classmethod
    def checksec(cls, path):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        cprint(f"\n=== CHECKSEC: {path} ===", C.CYAN, bold=True)

        with open(path, "rb") as f:
            data = f.read()

        if not data.startswith(b"\x7fELF"):
            cprint("Not an ELF file (PE/Mach-O checksec not implemented; use `reverse fileinfo`).", C.YELLOW)
            return

        if HAVE_PYELFTOOLS:
            cls._checksec_pyelftools(path)
        else:
            cls._checksec_manual(data)

    @staticmethod
    def _checksec_pyelftools(path):
        with open(path, "rb") as f:
            elf = ELFFile(f)
            is_pie = elf.header["e_type"] == "ET_DYN"
            nx = True
            relro = "No RELRO"
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_GNU_STACK":
                    nx = not (seg["p_flags"] & 0x1)  # execute flag
                if seg["p_type"] == "PT_GNU_RELRO":
                    relro = "Partial RELRO"

            dynamic = elf.get_section_by_name(".dynamic")
            bind_now = False
            if dynamic:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
            if relro == "Partial RELRO" and bind_now:
                relro = "Full RELRO"

            canary = False
            symtab = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
            if symtab:
                for sym in symtab.iter_symbols():
                    if "stack_chk" in sym.name:
                        canary = True
                        break

        cls_print_checksec(is_pie, nx, relro, canary)

    @staticmethod
    def _checksec_manual(data):
        # Manual ELF header parse (works even without pyelftools)
        ei_class = data[4]  # 1=32bit, 2=64bit
        e_type = struct.unpack("<H", data[16:18])[0]  # 2=EXEC, 3=DYN(PIE)
        is_pie = (e_type == 3)

        canary = b"__stack_chk_fail" in data
        relro = "GNU_RELRO segment" if b"GNU_RELRO" in data else "unknown (install pyelftools for accuracy)"
        nx = "unknown (install pyelftools for accurate NX check)"

        cprint("[Note: pyelftools not installed - showing best-effort manual parse]", C.DIM)
        print(f"Architecture : {'64-bit' if ei_class == 2 else '32-bit'}")
        print(f"PIE          : {'Yes (ET_DYN)' if is_pie else 'No (ET_EXEC)'}")
        print(f"Stack Canary : {'Yes' if canary else 'No / Not found'}")
        print(f"RELRO        : {relro}")
        print(f"NX           : {nx}")


def cls_print_checksec(is_pie, nx, relro, canary):
    def yn(val, good_is_true=True):
        good = val if good_is_true else not val
        return (C.GREEN + "Yes" if good else C.RED + "No") + C.RESET

    print(f"PIE          : {yn(is_pie)}")
    print(f"NX (stack)   : {yn(nx)}")
    print(f"Stack Canary : {yn(canary)}")
    color = C.GREEN if relro == "Full RELRO" else (C.YELLOW if relro == "Partial RELRO" else C.RED)
    print(f"RELRO        : {color}{relro}{C.RESET}")


# ========================================================================
# REVERSE MODULE
# ========================================================================
class Reverse:
    """Reverse engineering helpers: fileinfo, strings, disasm, opcode"""

    @staticmethod
    def fileinfo(path):
        if not os.path.isfile(path):
            cprint(f"[!] File not found: {path}", C.RED)
            return
        with open(path, "rb") as f:
            data = f.read()

        cprint(f"\n=== FILE INFO: {path} ===", C.CYAN, bold=True)
        if data.startswith(b"\x7fELF"):
            Reverse._elf_info(data)
        elif data.startswith(b"MZ"):
            Reverse._pe_info(data)
        else:
            cprint("Unknown binary format (not ELF or PE).", C.YELLOW)

    @staticmethod
    def _elf_info(data):
        ei_class = data[4]
        ei_data = data[5]
        e_type = struct.unpack("<H", data[16:18])[0]
        e_machine = struct.unpack("<H", data[18:20])[0]
        if ei_class == 2:
            e_entry = struct.unpack("<Q", data[24:32])[0]
        else:
            e_entry = struct.unpack("<I", data[24:28])[0]

        type_names = {1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (PIE/shared)", 4: "CORE"}
        machine_names = {0x3: "x86", 0x3e: "x86-64", 0x28: "ARM", 0xb7: "AArch64", 0x8: "MIPS"}

        print("Format       : ELF")
        print(f"Class        : {'ELF64' if ei_class == 2 else 'ELF32'}")
        print(f"Endianness   : {'Little' if ei_data == 1 else 'Big'}")
        print(f"Type         : {type_names.get(e_type, e_type)}")
        print(f"Machine      : {machine_names.get(e_machine, hex(e_machine))}")
        print(f"Entry point  : {hex(e_entry)}")

    @staticmethod
    def _pe_info(data):
        try:
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
            machine_names = {0x14c: "x86", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64"}
            print("Format       : PE (Windows)")
            print(f"Machine      : {machine_names.get(machine, hex(machine))}")
        except Exception as e:
            cprint(f"Failed to parse PE header: {e}", C.RED)

    @staticmethod
    def strings(path, min_len=4):
        Forensic.strings(path, min_len=min_len)

    @staticmethod
    def disasm(hexbytes_or_file, arch="x86_64", offset=0):
        cprint(f"\n=== DISASSEMBLY (arch={arch}) ===", C.CYAN, bold=True)
        if os.path.isfile(hexbytes_or_file):
            with open(hexbytes_or_file, "rb") as f:
                code = f.read()
        else:
            clean = hexbytes_or_file.replace(" ", "").replace("0x", "")
            try:
                code = bytes.fromhex(clean)
            except ValueError:
                cprint("[!] Input must be a filepath or hex bytes.", C.RED)
                return

        if not HAVE_CAPSTONE:
            cprint("capstone not installed - showing raw hex only.", C.YELLOW)
            cprint("Install with: pip install capstone", C.DIM)
            print(code.hex(" "))
            return

        arch_map = {
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
        }
        cs_arch, cs_mode = arch_map.get(arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(cs_arch, cs_mode)
        for instr in md.disasm(code, offset):
            print(f"  0x{instr.address:08x}:  {instr.mnemonic:8s} {instr.op_str}")


# ========================================================================
# MODULE REGISTRY (for the `modules` command / table display)
# ========================================================================
MODULE_INFO = {
    "forensic": ("Forensics analysis tools", "metadata, exif, strings, hidden, entropy"),
    "crypto":   ("Cryptography tools", "base64, hex, rot13, caesar, xor, identify"),
    "pwn":      ("Binary exploitation tools", "pattern, offset, checksec"),
    "reverse":  ("Reverse engineering tools", "fileinfo, strings, disasm"),
}


def print_modules_table():
    hr("=")
    cprint("  CTF TOOLKIT - MODULES", C.CYAN, bold=True)
    hr("=")
    col1, col2, col3 = 12, 28, 40
    print(f"{C.BLUE}{'Module':<{col1}}{'Description':<{col2}}{'Commands'}{C.RESET}")
    hr()
    for name, (desc, cmds) in MODULE_INFO.items():
        print(f"{C.ORANGE}{name:<{col1}}{C.RESET}{desc:<{col2}}{C.DIM}{cmds}{C.RESET}")
    hr("=")


# ========================================================================
# INTERACTIVE SHELL
# ========================================================================
class CTFShell(cmd.Cmd):
    intro = None
    prompt = f"{C.BLUE}FLAG>{C.RESET} "

    def preloop(self):
        hr("=")
        cprint("  Welcome to CTF Toolkit", C.CYAN, bold=True)
        cprint("  Type 'modules' to see available modules, 'help' for commands, 'exit' to quit.", C.DIM)
        hr("=")

    # ---- meta commands ----
    def do_modules(self, arg):
        """List all available modules and their commands."""
        print_modules_table()

    def do_exit(self, arg):
        """Exit the toolkit."""
        cprint("Bye! Good luck with the CTF 🚩", C.GREEN)
        return True

    def do_quit(self, arg):
        """Exit the toolkit."""
        return self.do_exit(arg)

    def do_clear(self, arg):
        """Clear the screen."""
        os.system("cls" if os.name == "nt" else "clear")

    # ---- forensic ----
    def do_forensic(self, arg):
        """forensic <metadata|exif|strings|hidden|entropy> <file> [options]"""
        args = shlex.split(arg)
        if not args:
            cprint("Usage: forensic <metadata|exif|strings|hidden|entropy> <file>", C.YELLOW)
            return
        sub, rest = args[0], args[1:]
        try:
            if sub == "metadata":
                Forensic.metadata(rest[0])
            elif sub == "exif":
                Forensic.exif(rest[0])
            elif sub == "strings":
                min_len = int(rest[1]) if len(rest) > 1 else 4
                Forensic.strings(rest[0], min_len=min_len)
            elif sub == "hidden":
                Forensic.hidden(rest[0])
            elif sub == "entropy":
                chunk = int(rest[1]) if len(rest) > 1 else 256
                Forensic.entropy(rest[0], chunk_size=chunk)
            else:
                cprint(f"Unknown forensic command: {sub}", C.RED)
        except IndexError:
            cprint("[!] Missing arguments. Example: forensic metadata ./image.png", C.RED)

    # ---- crypto ----
    def do_crypto(self, arg):
        """crypto <base64|hex|rot13|caesar|xor|identify> <text/data> [options]"""
        args = shlex.split(arg)
        if not args:
            cprint("Usage: crypto <base64|hex|rot13|caesar|xor|identify> <text> [options]", C.YELLOW)
            return
        sub, rest = args[0], args[1:]
        try:
            if sub == "base64":
                mode = rest[0] if rest[0] in ("encode", "decode") else "encode"
                text = rest[1] if rest[0] in ("encode", "decode") else rest[0]
                Crypto.b64(mode, text)
            elif sub == "hex":
                mode = rest[0] if rest[0] in ("encode", "decode") else "encode"
                text = rest[1] if rest[0] in ("encode", "decode") else rest[0]
                Crypto.hexconv(mode, text)
            elif sub == "rot13":
                Crypto.rot13(" ".join(rest))
            elif sub == "caesar":
                if len(rest) > 1 and rest[-1].lstrip("-").isdigit():
                    Crypto.caesar(" ".join(rest[:-1]), shift=rest[-1])
                else:
                    Crypto.caesar(" ".join(rest))
            elif sub == "xor":
                key = rest[1] if len(rest) > 1 else None
                Crypto.xor(rest[0], key=key)
            elif sub == "identify":
                Crypto.identify(" ".join(rest))
            else:
                cprint(f"Unknown crypto command: {sub}", C.RED)
        except IndexError:
            cprint("[!] Missing arguments.", C.RED)

    # ---- pwn ----
    def do_pwn(self, arg):
        """pwn <pattern_create|pattern_offset|checksec> <args>"""
        args = shlex.split(arg)
        if not args:
            cprint("Usage: pwn <pattern_create|pattern_offset|checksec> <args>", C.YELLOW)
            return
        sub, rest = args[0], args[1:]
        try:
            if sub == "pattern_create":
                Pwn.pattern_create(rest[0])
            elif sub == "pattern_offset":
                Pwn.pattern_offset(rest[0])
            elif sub == "checksec":
                Pwn.checksec(rest[0])
            else:
                cprint(f"Unknown pwn command: {sub}", C.RED)
        except IndexError:
            cprint("[!] Missing arguments.", C.RED)

    # ---- reverse ----
    def do_reverse(self, arg):
        """reverse <fileinfo|strings|disasm> <file/hex> [options]"""
        args = shlex.split(arg)
        if not args:
            cprint("Usage: reverse <fileinfo|strings|disasm> <file/hex> [arch]", C.YELLOW)
            return
        sub, rest = args[0], args[1:]
        try:
            if sub == "fileinfo":
                Reverse.fileinfo(rest[0])
            elif sub == "strings":
                min_len = int(rest[1]) if len(rest) > 1 else 4
                Reverse.strings(rest[0], min_len=min_len)
            elif sub == "disasm":
                arch = rest[1] if len(rest) > 1 else "x86_64"
                Reverse.disasm(rest[0], arch=arch)
            else:
                cprint(f"Unknown reverse command: {sub}", C.RED)
        except IndexError:
            cprint("[!] Missing arguments.", C.RED)

    def default(self, line):
        cprint(f"Unknown command: {line}. Type 'modules' or 'help'.", C.RED)

    def emptyline(self):
        pass


# ========================================================================
# CLI (non-interactive) MODE
# ========================================================================
def build_cli_parser():
    parser = argparse.ArgumentParser(description="CTF Toolkit - all-in-one CTF helper")
    sub = parser.add_subparsers(dest="module")

    # forensic
    p = sub.add_parser("forensic")
    p.add_argument("command", choices=["metadata", "exif", "strings", "hidden", "entropy"])
    p.add_argument("file")
    p.add_argument("extra", nargs="?", default=None)

    # crypto
    p = sub.add_parser("crypto")
    p.add_argument("command", choices=["base64", "hex", "rot13", "caesar", "xor", "identify"])
    p.add_argument("text")
    p.add_argument("extra", nargs="?", default=None)

    # pwn
    p = sub.add_parser("pwn")
    p.add_argument("command", choices=["pattern_create", "pattern_offset", "checksec"])
    p.add_argument("value")

    # reverse
    p = sub.add_parser("reverse")
    p.add_argument("command", choices=["fileinfo", "strings", "disasm"])
    p.add_argument("target")
    p.add_argument("extra", nargs="?", default=None)

    sub.add_parser("modules")
    return parser


def run_cli(args):
    if args.module == "modules" or args.module is None:
        print_modules_table()
        return

    if args.module == "forensic":
        if args.command == "metadata":
            Forensic.metadata(args.file)
        elif args.command == "exif":
            Forensic.exif(args.file)
        elif args.command == "strings":
            Forensic.strings(args.file, min_len=int(args.extra) if args.extra else 4)
        elif args.command == "hidden":
            Forensic.hidden(args.file)
        elif args.command == "entropy":
            Forensic.entropy(args.file, chunk_size=int(args.extra) if args.extra else 256)

    elif args.module == "crypto":
        if args.command == "base64":
            mode = args.text if args.text in ("encode", "decode") else "encode"
            text = args.extra if args.text in ("encode", "decode") else args.text
            Crypto.b64(mode, text)
        elif args.command == "hex":
            mode = args.text if args.text in ("encode", "decode") else "encode"
            text = args.extra if args.text in ("encode", "decode") else args.text
            Crypto.hexconv(mode, text)
        elif args.command == "rot13":
            Crypto.rot13(args.text)
        elif args.command == "caesar":
            Crypto.caesar(args.text, shift=args.extra)
        elif args.command == "xor":
            Crypto.xor(args.text, key=args.extra)
        elif args.command == "identify":
            Crypto.identify(args.text)

    elif args.module == "pwn":
        if args.command == "pattern_create":
            Pwn.pattern_create(args.value)
        elif args.command == "pattern_offset":
            Pwn.pattern_offset(args.value)
        elif args.command == "checksec":
            Pwn.checksec(args.value)

    elif args.module == "reverse":
        if args.command == "fileinfo":
            Reverse.fileinfo(args.target)
        elif args.command == "strings":
            Reverse.strings(args.target, min_len=int(args.extra) if args.extra else 4)
        elif args.command == "disasm":
            Reverse.disasm(args.target, arch=args.extra or "x86_64")


def main():
    if len(sys.argv) > 1:
        parser = build_cli_parser()
        args = parser.parse_args()
        run_cli(args)
    else:
        try:
            CTFShell().cmdloop()
        except KeyboardInterrupt:
            print()
            cprint("Bye! Good luck with the CTF 🚩", C.GREEN)


if __name__ == "__main__":
    main()
