rule mimikatz_memssp_hookfn {
meta:
 description = "hunt for default mimikatz memssp module"
 author = "SBousseaden"
 date = "2020-08-26"
strings: 
 $A = {48 81 EC A8 00 00 00 C7 84 24 88 00 00 00 ?? ?? ?? ?? C7 84 24 8C 00 00 00 ?? ?? ?? ?? C7 84 24 90 00 00 00 ?? ?? ?? 00 C7 84 24 80 00 00 00 61 00 00 00 C7 44 24 40 5B 00 25 00 C7 44 24 44 30 00 38 00 C7 44 24 48 78 00 3A 00 C7 44 24 4C 25 00 30 00 C7 44 24 50 38 00 78 00 C7 44 24 54 5D 00 20 00 C7 44 24 58 25 00 77 00 C7 44 24 5C 5A 00 5C 00 C7 44 24 60 25 00 77 00 C7 44 24 64 5A 00 09 00 C7 44 24 68 25 00 77 00 C7 44 24 6C 5A 00 0A 00 C7 44 24 70 00 00 00 00 48 8D 94 24 80 00 00 00 48 8D 8C 24 88 00 00 00 48 B8 A0 7D ?? ?? ?? ?? 00 00 FF D0} // memssp creds logging function
 $B = {6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67} // mimilsa.log
condition: $A and $B // you can set condition to A and not B to detect non lazy memssp users 
}