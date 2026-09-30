#!/usr/bin/env python3
"""
Simple Polymorphic Virus Detector
----------------------------------
A lightweight, zero-dependency tool to detect polymorphic malware characteristics:
1. High Shannon Entropy (encrypted/scrambled payload)
2. Decryptor Stub Heuristics (loops with XOR/ADD/SUB operations)
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
    - Encrypted or compressed data: > 7.2
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


def calculate_sliding_window_entropy(data: bytes, window_size: int = 256, step: int = 64) -> tuple[float, int]:
    """
    Slides a 256-byte window across the file to detect local pockets of encrypted code,
    defeating entropy dilution/padding evasion techniques.
    Returns: (peak_entropy, offset_of_peak)
    """
    if len(data) < window_size:
        return calculate_entropy(data), 0

    max_entropy = 0.0
    max_offset = 0

    for offset in range(0, len(data) - window_size + 1, step):
        chunk = data[offset : offset + window_size]
        ent = calculate_entropy(chunk)
        if ent > max_entropy:
            max_entropy = ent
            max_offset = offset
            if max_entropy >= 7.95:  # Near mathematical theoretical maximum
                break

    return round(max_entropy, 2), max_offset


def parse_pe_sections(file_path: str):
    """
    Parses Windows PE headers using standard struct (no external dependencies).
    Extracts section names, entropy, and Writable/Executable flags.
    """
    sections = []
    entry_point_bytes = b""
    is_pe = False

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 64 or data[:2] != b"MZ":
            return False, sections, data[:256]

        # Offset to PE Header
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

        for i in range(num_sections):
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

            # Check if entry point falls into this section
            if virt_addr <= entry_point_rva < (virt_addr + virt_size):
                ep_offset_in_sec = entry_point_rva - virt_addr
                file_ep = raw_ptr + ep_offset_in_sec
                entry_point_bytes = data[file_ep : file_ep + 128]

            sections.append({
                "name": name,
                "entropy": entropy,
                "size": raw_size,
                "is_writable": is_write,
                "is_executable": is_exec,
                "w_and_x": is_write and is_exec
            })

            section_offset += 40

    except Exception:
        pass

    if not entry_point_bytes and len(data) >= 128:
        entry_point_bytes = data[:128]

    return is_pe, sections, entry_point_bytes


def detect_decryption_loop(code_bytes: bytes) -> tuple[bool, str]:
    """
    Scans the initial code bytes for x86/x64 decryptor loop signatures:
    1. Arithmetic/XOR instructions (e.g. 0x30..0x35 for XOR, 0x80..0x83 with XOR/ADD/SUB)
    2. Backward jumps/loops (0xEB, 0x75, 0xE2 with negative offset)
    """
    if not code_bytes:
        return False, "No code bytes to inspect"

    has_xor_or_math = False
    has_backward_jump = False
    details = []

    # Look for common x86 opcodes
    # XOR opcodes: 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x83/0x80 with XOR digit
    # ADD/SUB: 0x00..0x05, 0x28..0x2D
    # Loops/Jumps: 0xE2 (LOOP), 0x75 (JNZ), 0x74 (JZ), 0xEB (JMP short)
    
    for i in range(len(code_bytes) - 1):
        b = code_bytes[i]

        # Check for XOR (0x30-0x35)
        if 0x30 <= b <= 0x35:
            has_xor_or_math = True

        # Check for short backward jump: Opcode + negative signed 8-bit offset
        if b in (0xEB, 0x75, 0x74, 0xE2):
            offset = struct.unpack("b", bytes([code_bytes[i + 1]]))[0]
            if offset < 0 and abs(offset) < 60:
                has_backward_jump = True
                details.append(f"Backward loop found (opcode 0x{b:02X}, offset {offset})")

    if has_xor_or_math and has_backward_jump:
        return True, "Detected backward loop containing XOR/arithmetic operations (Classic Decryptor Stub)"
    elif has_backward_jump:
        return False, "Backward loop found, but no obvious arithmetic/XOR instructions"
    elif has_xor_or_math:
        return False, "XOR operations found, but no tight loop detected"

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

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    file_size = len(file_bytes)
    overall_entropy = calculate_entropy(file_bytes)
    peak_sliding_entropy, peak_offset = calculate_sliding_window_entropy(file_bytes, window_size=256, step=64)

    is_pe, sections, ep_bytes = parse_pe_sections(file_path)

    # 1. Evaluate Entropy
    print(f"\n[1] ENTROPY ANALYSIS")
    print(f"    - Overall File Entropy:         {overall_entropy} / 8.0")
    print(f"    - Peak 256-Byte Window Entropy: {peak_sliding_entropy} / 8.0 (Offset: 0x{peak_offset:04X})")

    is_diluted = (overall_entropy < 6.5 and peak_sliding_entropy >= 7.35)
    if is_diluted:
        print(f"    [!] DILUTION DETECTED: 256-byte window found local encrypted pocket despite low overall entropy!")

    high_entropy_sections = []
    wx_sections = []

    if is_pe:
        print(f"    - Format: Windows PE Executable ({len(sections)} sections)")
        for sec in sections:
            status = "NORMAL"
            if sec["entropy"] >= 7.2:
                status = "HIGH (Encrypted/Compressed)"
                high_entropy_sections.append(sec["name"])
            if sec["w_and_x"]:
                status += " [WARNING: Writable+Executable]"
                wx_sections.append(sec["name"])
            print(f"      * Section '{sec['name']:<8}' | Entropy: {sec['entropy']:<4} | W: {sec['is_writable']} | X: {sec['is_executable']} -> {status}")
    else:
        print(f"    - Format: Raw Binary / Non-PE Data")
        if peak_sliding_entropy >= 7.35:
            print("    - WARNING: File contains high-entropy payload (likely encrypted).")

    # 2. Evaluate Entry Point / Decryptor Stub
    print(f"\n[2] DECRYPTOR STUB ANALYSIS")
    has_loop, loop_desc = detect_decryption_loop(ep_bytes)
    print(f"    - Analysis: {loop_desc}")

    # 3. Calculate Suspicion Score
    score = 0
    reasons = []

    # Reason 1: High entropy (overall, per-section, or local sliding window)
    if peak_sliding_entropy >= 7.35 or high_entropy_sections or overall_entropy >= 7.2:
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
        reasons.append("Decryptor stub detected (tight backward loop with XOR/crypto math)")

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
    """Generates two safe demo files to show how the detector works."""
    print("[*] Generating demonstration files in current directory...")
    
    # 1. Clean file: regular repetitive code/text
    benign_data = b"Hello, this is a normal standard application text file. " * 50
    with open("sample_clean.bin", "wb") as f:
        f.write(benign_data)
    print("    [+] Created 'sample_clean.bin' (Normal file)")

    # 2. Mock polymorphic sample:
    # A tiny real x86 decryptor loop prepended to a randomly encrypted buffer
    # x86 assembly for decryptor loop:
    #   mov ecx, 200      ; length (B9 C8 00 00 00)
    #   lea esi, [eip+8]  ; pointer to encrypted data (8D 70 08)
    # loop_start:
    #   xor byte [esi], 0x5A ; decrypt byte (80 36 5A)
    #   inc esi              ; next byte (46)
    #   loop loop_start      ; loop backward (E2 FB) -> 0xE2 followed by -5
    
    stub = bytes([
        0xB9, 0xC8, 0x00, 0x00, 0x00, # mov ecx, 200
        0x8D, 0x70, 0x08,             # lea esi, [eax+8]
        0x80, 0x36, 0x5A,             # xor byte ptr [esi], 0x5A
        0x46,                         # inc esi
        0xE2, 0xFB                    # loop -5 (jumps back to 0x80)
    ])
    
    # Encrypted random payload (high entropy)
    import random
    random.seed(42)
    fake_encrypted_payload = bytes([random.randint(0, 255) for _ in range(500)])
    
    mock_poly_data = stub + fake_encrypted_payload
    with open("sample_polymorphic.bin", "wb") as f:
        f.write(mock_poly_data)
    print("    [+] Created 'sample_polymorphic.bin' (Standard polymorphic sample)")

    # 3. Diluted polymorphic sample:
    # 5,000 zeroes (drags overall entropy down to ~3.0) + the polymorphic payload
    # A naive whole-file scanner is FOOLED, but our 256-byte sliding window catches it!
    diluted_data = (b"\x00" * 5000) + mock_poly_data
    with open("sample_diluted.bin", "wb") as f:
        f.write(diluted_data)
    print("    [+] Created 'sample_diluted.bin' (Padded with 5,000 zeroes to test 256-byte sliding window!)\n")


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
