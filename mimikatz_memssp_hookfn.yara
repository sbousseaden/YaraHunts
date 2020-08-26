rule mimikatz_memssp_hookfn {
meta:
 description = "hunt for default mimikatz memssp module both ondisk and in memory artifacts"
 author = "SBousseaden"
 date = "2020-08-26"
strings: 
 $s1 = {44 30 00 38 00}
 $s2 = {48 78 00 3A 00}
 $s3 = {4C 25 00 30 00}
 $s4 = {50 38 00 78 00}
 $s5 = {54 5D 00 20 00}
 $s6 = {58 25 00 77 00}
 $s7 = {5C 5A 00 5C 00}
 $s8 = {60 25 00 77 00}
 $s9 = {64 5A 00 09 00}
 $s10 = {6C 5A 00 0A 00}
 $s11 = {68 25 00 77 00}
 $s12 = {68 25 00 77 00}
 $s13 = {6C 5A 00 0A 00}
 $B = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67} // mimilsa.log
condition: all of ($s*) or $B // you can set condition to A and not B to detect non lazy memssp users 
}
