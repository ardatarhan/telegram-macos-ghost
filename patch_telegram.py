#!/usr/bin/env python3
import os
import shutil
import struct
import subprocess
import sys

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
TG_APP     = "/Applications/Telegram.app"
TG_BIN     = os.path.join(TG_APP, "Contents/MacOS/Telegram")
TG_ORIG    = os.path.join(BACKUP_DIR, "Telegram.orig")
TG_CS      = os.path.join(TG_APP, "Contents/_CodeSignature/CodeResources")
TG_CS_ORIG = os.path.join(BACKUP_DIR, "CodeResources.orig")
TG_FW      = os.path.join(TG_APP, "Contents/Frameworks/libTelegramGhost.dylib")
LOCAL_DYLIB = os.path.join(BASE_DIR, "build/libTelegramGhost.dylib")
ENTITLEMENTS_PLIST = os.path.join(BASE_DIR, "build/entitlements.plist")

DYLIB_PATH = b"@rpath/libTelegramGhost.dylib\x00"


def encode_adrp(pc, target):
    diff = (target & ~0xfff) - (pc & ~0xfff)
    pages = diff >> 12
    immlo = pages & 3
    immhi = (pages >> 2) & 0x7ffff
    return 0x90000000 | (immlo << 29) | (immhi << 5) | 16  # x16


def encode_ldr_x16(offset):
    assert offset % 8 == 0
    imm12 = (offset >> 3) & 0xfff
    return 0xf9400000 | (imm12 << 10) | (16 << 5) | 16


def encode_b(pc, target):
    diff = target - pc
    assert diff % 4 == 0
    imm26 = (diff >> 2) & 0x3ffffff
    assert -(1 << 25) <= (diff >> 2) < (1 << 25), f"Out of B range: {hex(diff)}"
    return 0x14000000 | imm26


def patch_binary(src_path, dst_path):
    with open(src_path, "rb") as f:
        data = bytearray(f.read())

    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<IIIIIIII", data, 0)
    assert magic == 0xfeedfacf, f"Unexpected Mach-O magic: {hex(magic)}"

    # 1. Locate load commands and check if already patched
    offset = 32
    insert_offset = None
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[offset + 8 : offset + 24].split(b'\x00', 1)[0].decode('latin1')
            if segname == "__TEXT":
                # First section of __TEXT is __text at offset + 72
                s_addr, s_size, s_off = struct.unpack_from("<QQI", data, offset + 72 + 32)
                if s_addr == 0x100011380:
                    struct.pack_into("<QQI", data, offset + 72 + 32, 0x100011200, s_size + 0x180, 0x11200)
        elif cmd in (0xc, 0x80000018):  # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
            str_off = struct.unpack_from("<I", data, offset + 8)[0]
            name = bytes(data[offset + str_off : offset + cmdsize]).split(b'\x00', 1)[0]
            if b"libTelegramGhost.dylib" in name:
                raise RuntimeError("Binary already contains LC_LOAD_DYLIB for libTelegramGhost.dylib")
            insert_offset = offset + cmdsize
        offset += cmdsize

    assert insert_offset is not None, "Could not find LC_LOAD_DYLIB insertion point"
    end_of_cmds = 32 + sizeofcmds

    # Build new LC_LOAD_DYLIB command (24-byte header + padded path, 8-byte aligned)
    raw_len = 24 + len(DYLIB_PATH)
    cmd_len = (raw_len + 7) & ~7
    lc_dylib = bytearray(cmd_len)
    struct.pack_into("<IIIIII", lc_dylib, 0,
                     0xc,        # LC_LOAD_DYLIB
                     cmd_len,    # cmdsize
                     24,         # name offset
                     2,          # timestamp
                     0x00010000, # current_version 1.0.0
                     0x00010000) # compatibility_version 1.0.0
    lc_dylib[24 : 24 + len(DYLIB_PATH)] = DYLIB_PATH

    # Shift trailing load commands (LC_RPATH, LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_CODE_SIGNATURE)
    trailing = bytes(data[insert_offset:end_of_cmds])
    data[insert_offset : insert_offset + cmd_len] = lc_dylib
    data[insert_offset + cmd_len : end_of_cmds + cmd_len] = trailing

    # Update Mach-O header ncmds and sizeofcmds
    struct.pack_into("<II", data, 16, ncmds + 1, sizeofcmds + cmd_len)

    # 2. Write trampolines in __TEXT cave (0x100011200..0x100011260) and patch hook sites
    hooks = [
        ("sendReadRequests", 0x10573950c, 0x100011200, 0x10f9c3f00, 0xd10383ff),
        ("mtpSendRequest",   0x107c726d0, 0x100011220, 0x10f9c3f08, 0xd10183ff),
        ("sessionSendPrep",  0x107c8b388, 0x100011240, 0x10f9c3f10, 0xd10243ff),
    ]

    for name, fn_va, cave_va, ptr_va, expected_orig in hooks:
        fn_foff   = fn_va - 0x100000000
        cave_foff = cave_va - 0x100000000
        orig_insn = struct.unpack_from("<I", data, fn_foff)[0]
        assert orig_insn == expected_orig, (
            f"{name} at {hex(fn_va)}: expected {hex(expected_orig)}, got {hex(orig_insn)}"
        )

        stub = [
            encode_adrp(cave_va + 0, ptr_va),
            encode_ldr_x16(ptr_va & 0xfff),
            0xb4000050,  # cbz x16, +8
            0xd61f0200,  # br x16
            orig_insn,   # displaced instruction at cave_va + 0x10
            encode_b(cave_va + 0x14, fn_va + 4),
        ]
        for j, w in enumerate(stub):
            struct.pack_into("<I", data, cave_foff + j * 4, w)

        b_to_cave = encode_b(fn_va, cave_va)
        struct.pack_into("<I", data, fn_foff, b_to_cave)
        print(f"  [+] Patched {name} @ {hex(fn_va)} -> stub {hex(cave_va)}")

    with open(dst_path, "wb") as f:
        f.write(data)
    os.chmod(dst_path, 0o755)


def write_entitlements():
    plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
"""
    with open(ENTITLEMENTS_PLIST, "w") as f:
        f.write(plist)


def install():
    if not os.path.exists(LOCAL_DYLIB):
        print(f"[-] Missing {LOCAL_DYLIB}. Build it first.")
        sys.exit(1)

    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.exists(TG_ORIG):
        print(f"[*] Backing up original binary to {TG_ORIG} ...")
        shutil.copy2(TG_BIN, TG_ORIG)
    else:
        print(f"[*] Using clean backup {TG_ORIG} as base ...")

    if os.path.exists(TG_CS) and not os.path.exists(TG_CS_ORIG):
        shutil.copy2(TG_CS, TG_CS_ORIG)

    print(f"[*] Copying libTelegramGhost.dylib to {TG_FW} ...")
    shutil.copy2(LOCAL_DYLIB, TG_FW)
    os.chmod(TG_FW, 0o755)

    tmp_bin = TG_BIN + ".patched"
    print("[*] Patching Mach-O binary ...")
    patch_binary(TG_ORIG, tmp_bin)
    os.replace(tmp_bin, TG_BIN)

    write_entitlements()
    print("[*] Signing dylib and Telegram.app bundle ...")
    subprocess.check_call(["codesign", "-f", "-s", "-", TG_FW])
    subprocess.check_call([
        "codesign", "-f", "-s", "-",
        "--entitlements", ENTITLEMENTS_PLIST,
        TG_BIN
    ])
    subprocess.check_call([
        "codesign", "-f", "-s", "-",
        "--entitlements", ENTITLEMENTS_PLIST,
        TG_APP
    ])
    print("[+] Installation complete!")


def uninstall():
    if os.path.exists(TG_ORIG):
        print(f"[*] Restoring original binary from {TG_ORIG} ...")
        shutil.copy2(TG_ORIG, TG_BIN)
    if os.path.exists(TG_CS_ORIG):
        shutil.copy2(TG_CS_ORIG, TG_CS)
    if os.path.exists(TG_FW):
        print(f"[*] Removing {TG_FW} ...")
        os.remove(TG_FW)
    print("[+] Uninstalled cleanly.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        uninstall()
    else:
        install()
