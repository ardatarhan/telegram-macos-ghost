#!/usr/bin/env python3
import os
import shutil
import struct
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, "backup")
TG_APP = "/Applications/Telegram.app"
TG_BIN = os.path.join(TG_APP, "Contents/MacOS/Telegram")
TG_ORIG = os.path.join(BACKUP_DIR, "Telegram.orig")
TG_CS = os.path.join(TG_APP, "Contents/_CodeSignature/CodeResources")
TG_CS_ORIG = os.path.join(BACKUP_DIR, "CodeResources.orig")
TG_FW = os.path.join(TG_APP, "Contents/Frameworks/libTelegramGhost.dylib")
LOCAL_DYLIB = os.path.join(BASE_DIR, "build/libTelegramGhost.dylib")
ENTITLEMENTS_PLIST = os.path.join(BASE_DIR, "build/entitlements.plist")

DYLIB_PATH = b"@rpath/libTelegramGhost.dylib\x00"


def encode_adrp(pc, target):
    diff = (target & ~0xFFF) - (pc & ~0xFFF)
    pages = diff >> 12
    immlo = pages & 3
    immhi = (pages >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | 16  # x16


def encode_ldr_x16(offset):
    assert offset % 8 == 0
    imm12 = (offset >> 3) & 0xFFF
    return 0xF9400000 | (imm12 << 10) | (16 << 5) | 16


def encode_b(pc, target):
    diff = target - pc
    assert diff % 4 == 0
    imm26 = (diff >> 2) & 0x3FFFFFF
    return 0x14000000 | imm26


def encode_bl(pc, target):
    diff = target - pc
    assert diff % 4 == 0
    imm26 = (diff >> 2) & 0x3FFFFFF
    return 0x94000000 | imm26


def build_stub(stub_va, fn_va, orig_insn, data_slot_va, is_callsite=False):
    i0 = encode_adrp(stub_va + 0, data_slot_va)
    i1 = encode_ldr_x16(data_slot_va & 0xFFF)
    i2 = 0xB4000050  # cbz x16, +8 (to stub_va + 16)
    i3 = 0xD61F0200  # br x16
    if is_callsite:
        i4 = 0xD503201F  # nop
        i5 = encode_b(stub_va + 20, fn_va)
    else:
        i4 = orig_insn
        i5 = encode_b(stub_va + 20, fn_va + 4)
    return struct.pack("<6I", i0, i1, i2, i3, i4, i5)


HOOKS_SPEC = [
    # (name, fn_va, orig_insn, stub_va, slot_va, kind)
    ("SendReadRequests", 0x10573950C, 0xD10383FF, 0x100011200, 0x10F840400, "entry"),
    ("MtpSendRequest",   0x107C726D0, 0xD10183FF, 0x100011218, 0x10F840408, "entry"),
    ("SessionSendPrep",  0x107C8B388, 0xD10243FF, 0x100011230, 0x10F840410, "entry"),
    ("BeforeDestroy",    0x1059244F8, 0xD10243FF, 0x100011248, 0x10F840418, "callsite"),
    ("AntiDelete",       0x106890D74, 0xD104C3FF, 0x100011260, 0x10F840420, "callsite"),
    ("ApplyEdition",     0x10690B3B4, 0xD10783FF, 0x100011278, 0x10F840428, "entry"),
    ("MediaPhotoTtl",    0x10577BEC8, 0xF9401000, 0x100011290, 0x10F840430, "entry"),
    ("MediaFileTtl",     0x105781DB8, 0xF9401000, 0x1000112A8, 0x10F840430, "entry"),
    ("ItemAllowsFwd",    0x1069119D4, 0xA9BF7BFD, 0x1000112C0, 0x10F840438, "entry"),
    ("ItemAllowsSave",   0x10691261C, 0xA9BE4FF4, 0x1000112D8, 0x10F840440, "entry"),
    ("CopyRestrType",    0x10664D5B4, 0xA9BE4FF4, 0x1000112F0, 0x10F840448, "entry"),
    ("InnerCopyRestr",   0x10695DEBC, 0xF9406C09, 0x100011308, 0x10F840450, "entry"),
    ("InnerMediaRestr",  0x106961444, 0xA9BE4FF4, 0x100011320, 0x10F840458, "entry"),
    ("OverlayCanSave",   0x107AEAA98, 0xD10103FF, 0x100011338, 0x10F840460, "entry"),
    ("OverlayShowRestr", 0x107B0B048, 0xA9BD6FFC, 0x100011350, 0x10F840468, "entry"),
    ("PeerAllowsFwd",    0x1057D445C, 0x39403808, 0x100011368, 0x10F840470, "entry"),
]

BEFORE_DESTROY_CALLSITES = [
    0x1039C5360,
    0x1039C557C,
    0x1056F9110,
    0x10575223C,
    0x10592437C,
]

ANTI_DELETE_CALLSITES = [
    0x1039C5384,
    0x1039C55A0,
    0x1056F9138,
    0x105752264,
    0x1059243A0,
]


def patch_macho(bin_path):
    with open(bin_path, "r+b") as f:
        data = bytearray(f.read())

        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = (
            struct.unpack_from("<IIIIIIII", data, 0)
        )
        assert magic == 0xFEEDFACF, "Not a 64-bit Mach-O binary"

        # 1. Verify and install all 16 hook stubs in __TEXT padding (0x11200..0x11380)
        for name, fn_va, orig_insn, stub_va, slot_va, kind in HOOKS_SPEC:
            fn_off = fn_va - 0x100000000
            stub_off = stub_va - 0x100000000
            current_insn = struct.unpack_from("<I", data, fn_off)[0]

            if kind == "entry":
                expected_b = encode_b(fn_va, stub_va)
                if current_insn not in (orig_insn, expected_b):
                    raise RuntimeError(
                        f"Unexpected instruction at {name} ({hex(fn_va)}): "
                        f"{hex(current_insn)} (expected {hex(orig_insn)})"
                    )
                stub_bytes = build_stub(stub_va, fn_va, orig_insn, slot_va, is_callsite=False)
                data[stub_off : stub_off + 24] = stub_bytes
                struct.pack_into("<I", data, fn_off, expected_b)
            else:
                stub_bytes = build_stub(stub_va, fn_va, orig_insn, slot_va, is_callsite=True)
                data[stub_off : stub_off + 24] = stub_bytes
            print(f"[+] Patched {name:16s} @ {hex(fn_va)} -> stub {hex(stub_va)}")

        # 2. Patch BeforeDestroy and AntiDelete BL call sites
        for cs_va in BEFORE_DESTROY_CALLSITES:
            cs_off = cs_va - 0x100000000
            struct.pack_into("<I", data, cs_off, encode_bl(cs_va, 0x100011248))
        print(f"[+] Patched {len(BEFORE_DESTROY_CALLSITES)} BeforeDestroy BL call sites -> 0x100011248")

        for cs_va in ANTI_DELETE_CALLSITES:
            cs_off = cs_va - 0x100000000
            struct.pack_into("<I", data, cs_off, encode_bl(cs_va, 0x100011260))
        print(f"[+] Patched {len(ANTI_DELETE_CALLSITES)} AntiDelete BL call sites    -> 0x100011260")

        # 3. Check if LC_LOAD_DYLIB for libTelegramGhost.dylib already exists
        offset = 32
        has_dylib = False
        code_sig_cmd_off = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd in (0xC, 0x80000018):  # LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB
                str_off = struct.unpack_from("<I", data, offset + 8)[0]
                raw_name = bytes(data[offset + str_off : offset + cmdsize]).split(b"\x00", 1)[0]
                if b"libTelegramGhost.dylib" in raw_name:
                    has_dylib = True
            elif cmd == 0x1D:  # LC_CODE_SIGNATURE
                code_sig_cmd_off = offset
            offset += cmdsize

        if not has_dylib:
            assert code_sig_cmd_off is not None, "LC_CODE_SIGNATURE not found"
            lc_header_size = 24
            total_len = lc_header_size + len(DYLIB_PATH)
            cmdsize = (total_len + 7) & ~7
            lc_bytes = bytearray(cmdsize)
            struct.pack_into(
                "<IIIIII",
                lc_bytes,
                0,
                0xC,  # LC_LOAD_DYLIB
                cmdsize,
                24,  # name offset
                2,  # timestamp
                0x10000,  # current_version 1.0.0
                0x10000,  # compatibility_version 1.0.0
            )
            lc_bytes[24 : 24 + len(DYLIB_PATH)] = DYLIB_PATH

            cs_cmd_bytes = bytes(data[code_sig_cmd_off : code_sig_cmd_off + 16])
            data[code_sig_cmd_off : code_sig_cmd_off + cmdsize] = lc_bytes
            data[code_sig_cmd_off + cmdsize : code_sig_cmd_off + cmdsize + 16] = cs_cmd_bytes

            struct.pack_into("<II", data, 16, ncmds + 1, sizeofcmds + cmdsize)
            print(f"[+] Injected LC_LOAD_DYLIB ({cmdsize} bytes) before LC_CODE_SIGNATURE")
        else:
            print("[*] LC_LOAD_DYLIB for libTelegramGhost.dylib already present")

        f.seek(0)
        f.write(data)
        f.truncate()


def write_entitlements():
    plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
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
        shutil.copy2(TG_ORIG, TG_BIN)

    if os.path.exists(TG_CS) and not os.path.exists(TG_CS_ORIG):
        shutil.copy2(TG_CS, TG_CS_ORIG)

    print(f"[*] Copying libTelegramGhost.dylib to {TG_FW} ...")
    shutil.copy2(LOCAL_DYLIB, TG_FW)

    print(f"[*] Patching Mach-O binary {TG_BIN} ...")
    patch_macho(TG_BIN)

    write_entitlements()
    print("[*] Signing dylib and Telegram.app bundle ...")
    subprocess.check_call(["codesign", "-f", "-s", "-", TG_FW])
    subprocess.check_call(["codesign", "-f", "-s", "-", "--entitlements", ENTITLEMENTS_PLIST, TG_BIN])
    subprocess.check_call(["codesign", "-f", "-s", "-", "--entitlements", ENTITLEMENTS_PLIST, TG_APP])
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
