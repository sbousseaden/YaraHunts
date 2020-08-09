rule mimikatz_kiwikey {
meta:
 description = "hunt for default mimikatz kiwikey"
 author = "SBousseaden"
 date = "2020-08-08"
strings: 
 $A = {60 BA 4F CA C7 44 24 ?? DC 46 6C 7A C7 44 24 ?? 03 3C 17 81 C7 44 24 ?? 94 C0 3D F6}
 $B = {C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ?? ?? ?? ?? ?? C7 44 24 ??}
condition: $A and #B>10
}