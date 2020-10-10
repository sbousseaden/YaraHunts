rule TDL_loader_bootstrap_shellcode {
meta:
 author = "SBousseaden"
 reference = "https://github.com/hfiref0x/TDL"
strings: 
 $shc1 = {41 B8 54 64 6C 53 48 63 6B 3C 48 03 EB 44 8B 7D 50 41 8D 97 00 10 00 00 41 FF D1}
 $shc2 = {41 B8 54 64 6C 53 4C 63 73 3C 4C 03 F3 45 8B 7E 50 41 8D 97 00 10 00 00 41 FF D1 45 33 C9}
condition: uint16(0) == 0x5a4d and any of ($shc*)
}