#!/usr/bin/env python3
"""
Simple Polymorphic Virus Detector
----------------------------------
A lightweight, zero-dependency tool to detect polymorphic malware characteristics:
1. High Shannon Entropy (encrypted/scrambled payload with 256-byte sliding window)
2. Decryptor Stub Heuristics (loops enclosing XOR/ADD/SUB operations, Group 1 opcodes)
3. Abnormal PE Section Permissions (Writable + Executable memory)
"""

import sys
import os
import math
import struct

def calculate_entropy(data: bytes) -> float:
    """
    Calculates Shannon Entropy (0.0 to 8.0 bits/byte).
    - Plain text or normal code: ~3.5 to 6.5
    - Encrypted or compressed data: > 7.0
    """
    if not data:
        return 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def calculate_sliding_window_entropy(data: bytes, window_size: int = 256, step: int = 64) -> tuple[float, int, int]:
    """
    Slides a 256-byte window across the file to detect local pockets of encrypted code.
    Returns: (peak_entropy, peak_offset, first_high_entropy_offset)
    Note: For N=256 uniform random bytes, expected entropy is ~7.28 bits/byte.
    """
    if len(data) < window_size:
        ent = calculate_entropy(data)
        return ent, 0, (0 if ent >= 7.0 else -1)

    max_entropy = 0.0
    max_offset = 0
    first_high_offset = -1

    for offset in range(0, len(data) - window_size + 1, step):
        chunk = data[offset : offset + window_size]
        ent = calculate_entropy(chunk)
        if ent >= 7.0 and first_high_offset == -1:
            first_high_offset = offset
        if ent > max_entropy:
            max_entropy = ent
            max_offset = offset

    return round(max_entropy, 2), max_offset, first_high_offset


def parse_pe_sections(data: bytes):
    """
    Parses Windows PE headers directly from memory buffer using standard struct.
    Extracts section names, entropy, Writable/Executable flags, and entry point bytes.
    """
    sections = []
    entry_point_bytes = b""
    is_pe = False

    if len(data) < 64 or data[:2] != b"MZ":
        return False, sections, data[:256]

    try:
        # Offset to PE Header (e_lfanew at 0x3C)
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if len(data) < pe_offset + 24 or data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return False, sections, data[:256]

        is_pe = True
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        opt_header_offset = pe_offset + 24

        entry_point_rva = 0
        if opt_header_size >= 20:
            entry_point_rva = struct.unpack_from("<I", data, opt_header_offset + 16)[0]

        # Section Headers start right after Optional Header
        section_offset = opt_header_offset + opt_header_size

        for _ in range(num_sections):
            hdr = data[section_offset : section_offset + 40]
            if len(hdr) < 40:
                break
            
            name = hdr[:8].decode("latin-1", errors="ignore").strip("\x00")
            virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", hdr, 8)
            characteristics = struct.unpack_from("<I", hdr, 36)[0]

            sec_data = data[raw_ptr : raw_ptr + raw_size]
            entropy = calculate_entropy(sec_data)

            # Check flags: 0x20000000 = Execute, 0x80000000 = Write
            is_exec = bool(characteristics & 0x20000000)
            is_write = bool(characteristics & 0x80000000)

            # Check if entry point falls into this section (use consistent 256-byte slice)
            if virt_addr <= entry_point_rva < (virt_addr + virt_size):
                ep_offset_in_sec = entry_point_rva - virt_addr
                file_ep = raw_ptr + ep_offset_in_sec
                entry_point_bytes = data[file_ep : file_ep + 256]

            sections.append({
                "name": name,
                "entropy": entropy,
                "size": raw_size,
                "is_writable": is_write,
                "is_executable": is_exec,
                "w_and_x": is_write and is_exec
            })

            section_offset += 40

    except (struct.error, IndexError):
        pass

    if not entry_point_bytes and len(data) >= 256:
        entry_point_bytes = data[:256]

    return is_pe, sections, entry_point_bytes


def detect_decryption_loop(code_bytes: bytes) -> tuple[bool, str]:
    """
    Heuristically scans code bytes for backward loops enclosing in-memory arithmetic:
    1. In-memory primary XOR (0x30: xor r/m8, r8; 0x31: xor r/m32, r32) with mod != 3.
       (0x32-0x35 are omitted as they target registers; plain ADD/SUB 0x00-0x05 are omitted
       because 0x00 0x00 ('add [eax], al') causes false positives on zero padding).
    2. Group 1 immediate arithmetic (0x80, 0x82, 0x83) with ADD(0), SUB(5), or XOR(6)
       extensions targeting memory (mod != 3).
    3. Backward relative jumps/loops (0xEB, 0x75, 0x74, 0xE2) whose displacement specifically
       encloses at least one of the above memory arithmetic instructions.
    """
    if not code_bytes:
        return False, "No code bytes to inspect"

    math_map = {}  # offset -> description

    # Identify all in-memory arithmetic/crypto instruction offsets
    i = 0
    while i < len(code_bytes):
        b = code_bytes[i]

        # 1. Primary XOR with memory destination (0x30: xor r/m8, r8; 0x31: xor r/m32, r32)
        if b in (0x30, 0x31) and (i + 1) < len(code_bytes):
            modrm = code_bytes[i + 1]
            mod = (modrm >> 6) & 3
            if mod != 3:  # mod == 3 is register-to-register (e.g. xor eax, eax); mod != 3 is memory
                math_map[i] = f"Primary XOR memory opcode 0x{b:02X}"

        # 2. Group 1 immediate arithmetic opcodes (0x80, 0x82, 0x83) targeting memory
        elif b in (0x80, 0x82, 0x83) and (i + 1) < len(code_bytes):
            modrm = code_bytes[i + 1]
            mod = (modrm >> 6) & 3
            reg_op = (modrm >> 3) & 7
            # In polymorphic decryptors, payload modification writes to memory (mod != 3)
            # 0=ADD, 5=SUB, 6=XOR. (mod == 3 is pure register math like 'sub esp, 28h')
            if mod != 3 and reg_op in (0, 5, 6):
                op_names = {0: "ADD", 5: "SUB", 6: "XOR"}
                math_map[i] = f"Group 1 {op_names[reg_op]} opcode 0x{b:02X}"
        i += 1

    # Check for backward branches and strictly verify if math is enclosed within the loop body
    for i in range(len(code_bytes) - 1):
        b = code_bytes[i]
        if b in (0xEB, 0x75, 0x74, 0xE2):
            offset = struct.unpack("b", bytes([code_bytes[i + 1]]))[0]
            if offset < 0 and abs(offset) < 60:
                loop_len = abs(offset)
                loop_start = max(0, (i + 2) - loop_len)
                loop_end = i
                # Enclosed math verification: math instruction must reside inside [loop_start, loop_end]
                enclosed = [m for m in math_map if loop_start <= m <= loop_end]
                if enclosed:
                    enclosed_desc = [f"{math_map[m]} at +{m}" for m in enclosed]
                    loop_str = f"Backward loop (opcode 0x{b:02X}, offset {offset}) encloses [{'; '.join(enclosed_desc)}]"
                    return True, f"Detected backward loop containing XOR/arithmetic operations [{loop_str}]"

    if math_map:
        return False, "Arithmetic/XOR operations found, but no enclosing loop detected"

    return False, "No decryptor loop patterns identified"


def scan_file(file_path: str):
    """Performs the full polymorphic detection analysis on a file."""
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        return

    print("=" * 60)
    print(f"[*] Scanning: {os.path.basename(file_path)}")
    print(f"[*] Path:     {os.path.abspath(file_path)}")
    print("=" * 60)

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
    except OSError as e:
        print(f"[-] Error reading file: {e}")
        return

    overall_entropy = calculate_entropy(file_bytes)
    peak_sliding_entropy, peak_offset, first_high_offset = calculate_sliding_window_entropy(
        file_bytes, window_size=256, step=64
    )

    is_pe, sections, ep_bytes = parse_pe_sections(file_bytes)

    # 1. Evaluate Entropy
    print(f"\n[1] ENTROPY ANALYSIS")
    print(f"    - Overall File Entropy:         {overall_entropy} / 8.0")
    print(f"    - Peak 256-Byte Window Entropy: {peak_sliding_entropy} / 8.0 (Offset: 0x{peak_offset:04X})")

    # Dilution evaluation: calibrated against random window expectation (~7.28)
    is_diluted = False
    if not is_pe and overall_entropy < 6.5 and peak_sliding_entropy >= 7.15:
        is_diluted = True
        print(f"    [!] DILUTION DETECTED: 256-byte window found local encrypted pocket despite low overall entropy!")
    elif is_pe and overall_entropy < 6.5 and peak_sliding_entropy >= 7.45:
        is_diluted = True
        print(f"    [!] DILUTION DETECTED: Local high-entropy pocket (>= 7.45) detected in PE!")

    high_entropy_sections = []
    wx_sections = []

    if is_pe:
        print(f"    - Format: Windows PE Executable ({len(sections)} sections)")
        for sec in sections:
            status = "NORMAL"
            if sec["entropy"] >= 7.15:
                status = "HIGH (Encrypted/Compressed)"
                high_entropy_sections.append(sec["name"])
            if sec["w_and_x"]:
                status += " [WARNING: Writable+Executable]"
                wx_sections.append(sec["name"])
            print(f"      * Section '{sec['name']:<8}' | Entropy: {sec['entropy']:<4} | W: {sec['is_writable']} | X: {sec['is_executable']} -> {status}")
    else:
        print(f"    - Format: Raw Binary / Non-PE Data")
        if peak_sliding_entropy >= 7.15:
            print("    - WARNING: File contains high-entropy payload (likely encrypted).")

    # 2. Evaluate Decryptor Stub (at Entry Point or at padding transition boundary)
    print(f"\n[2] DECRYPTOR STUB ANALYSIS")
    has_loop, loop_desc = detect_decryption_loop(ep_bytes)

    # Heuristic transition search: For raw non-PE binaries, inspects 64 bytes before the first high-entropy window.
    # Note: If an attacker inserts >64 bytes of junk code between stub and payload, this heuristic will miss the stub.
    if not is_pe and not has_loop and first_high_offset > 0:
        check_start = max(0, first_high_offset - 64)
        check_chunk = file_bytes[check_start : check_start + 256]
        alt_loop, alt_desc = detect_decryption_loop(check_chunk)
        if alt_loop:
            has_loop = True
            loop_desc = f"{alt_desc} (located at transition boundary 0x{check_start:04X})"

    print(f"    - Analysis: {loop_desc}")

    # 3. Calculate Suspicion Score
    score = 0
    reasons = []

    # Reason 1: High entropy
    has_high_entropy = (
        high_entropy_sections or
        (not is_pe and peak_sliding_entropy >= 7.15) or
        (is_pe and peak_sliding_entropy >= 7.45) or
        overall_entropy >= 7.15
    )
    if has_high_entropy:
        score += 35
        if is_diluted:
            reasons.append(f"Local high-entropy pocket detected via 256-byte sliding window (Offset 0x{peak_offset:04X})")
        else:
            reasons.append("High entropy detected (suggests encrypted/compressed payload)")

    # Reason 2: W+X memory section
    if wx_sections:
        score += 30
        reasons.append(f"Section(s) {wx_sections} are both Writable and Executable (W^X violation)")

    # Reason 3: Decryptor loop
    if has_loop:
        score += 35
        reasons.append("Decryptor stub detected (tight backward loop enclosing arithmetic/crypto math)")

    # 4. Final Verdict
    print(f"\n[3] FINAL VERDICT & RISK ASSESSMENT")
    print(f"    - Suspicion Score: {score} / 100")

    if score >= 65:
        print(f"    - VERDICT: [!] HIGH RISK - LIKELY POLYMORPHIC MALWARE")
    elif score >= 30:
        print(f"    - VERDICT: [?] SUSPICIOUS - Packed or Obfuscated Binary")
    else:
        print(f"    - VERDICT: [OK] CLEAN - Normal binary patterns")

    if reasons:
        print("    - Key Indicators:")
        for r in reasons:
            print(f"      * {r}")
    print("=" * 60 + "\n")


def create_demo_files():
    """Generates safe demo files to show standard and zero-padded/diluted polymorphic detection."""
    print("[*] Generating demonstration files in current directory...")

    # 1. Clean file: regular repetitive code/text
    benign_data = b"Hello, this is a normal standard application text file. " * 50
    with open("sample_clean.bin", "wb") as f:
        f.write(benign_data)
    print("    [+] Created 'sample_clean.bin' (Normal clean file)")

    # 2. Mock polymorphic sample:
    # x86 decryptor stub with correct jump displacement (-6 = 0xFA, landing on offset 8)
    stub = bytes([
        0xB9, 0xC8, 0x00, 0x00, 0x00, # mov ecx, 200
        0x8D, 0x70, 0x08,             # lea esi, [eax+8]
        0x80, 0x36, 0x5A,             # xor byte ptr [esi], 0x5A (Offset 8)
        0x46,                         # inc esi
        0xE2, 0xFA                    # loop -6 (EIP=14; 14-6 = 8 -> accurately jumps to 0x80)
    ])

    import random
    random.seed(42)
    fake_encrypted_payload = bytes([random.randint(0, 255) for _ in range(500)])

    mock_poly_data = stub + fake_encrypted_payload
    with open("sample_polymorphic.bin", "wb") as f:
        f.write(mock_poly_data)
    print("    [+] Created 'sample_polymorphic.bin' (Standard polymorphic sample)")

    # 3. Diluted polymorphic sample:
    # 5,000 zeroes + the polymorphic payload.
    # Tests sliding-window entropy and first-high-entropy transition stub detection.
    diluted_data = (b"\x00" * 5000) + mock_poly_data
    with open("sample_diluted.bin", "wb") as f:
        f.write(diluted_data)
    print("    [+] Created 'sample_diluted.bin' (Padded with 5,000 zeroes to test transition boundary stub detection!)\n")


def main():
    if len(sys.argv) < 2:
        print("Simple Polymorphic Virus Detector")
        print("Usage:")
        print("  python poly_detector.py <file_to_scan>")
        print("  python poly_detector.py --demo   (Generates & scans safe test files)")
        sys.exit(0)

    arg = sys.argv[1]
    if arg == "--demo":
        create_demo_files()
        print("[*] Running scan on 'sample_clean.bin':")
        scan_file("sample_clean.bin")
        print("[*] Running scan on 'sample_polymorphic.bin':")
        scan_file("sample_polymorphic.bin")
        print("[*] Running scan on 'sample_diluted.bin' (Diluted / Zero-Padded Sample):")
        scan_file("sample_diluted.bin")
    else:
        scan_file(arg)

if __name__ == "__main__":
    main()
