rule hunt_susp_vhd {
meta:
 description = "Virtual hard disk file with embedded PE"
 author = "SBousseaden"
 date = "13/07/2020"
strings:
 $hvhd = {636F6E6563746978}
 $s1 = {4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00}
 $s2 = "!This program cannot be run in DOS mode." base64
 $s3 = "!This program cannot be run in DOS mode." xor
condition: $hvhd at 0 and any of ($s*) and filesize <= 10MB
}
