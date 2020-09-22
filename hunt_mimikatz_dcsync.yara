rule DCSync_Mimikatz {
meta:
 description = "Hunting rule for Mimikatz Implementation of DCSync Attack"
 author = "SBousseaden"
 date = "22/09/2020"
 reference = "https://github.com/gentilkiwi/mimikatz"
strings:
 $DRS1 = "DRSGetNCChanges"
 $DRS2 = "DRSReplicaAdd"
 $DRS3 = "DRSAddEntry"
 $DRSW1 = "DRSGetNCChanges" wide
 $DRSW2 = "DRSReplicaAdd" wide
 $DRSW3 = "DRSAddEntry" wide
 $rpc1 = {35 42 51 E3 06 4B D1 11 AB 04 00 C0 4F C2 DC D2 04 00 00 00 04 5D 88 8A EB 1C C9 11 9F E8 08 00 2B 10 48 60 02}
 $rpc2 = {34 05 50 21 18 00 08 00 13 81 20 00 8A 05 70 00 28}
 $rpc3 = {0B 01 10 00 DC 05 50 21 18 00 08 00 13 21 20 00 2E 06 70 00 28}
 $rpc4 = {48 06 50 21 18 00 08 00 13 41 20 00 72 06 70 00 28}
 $rpc5 = {78 03 0B 00 10 00 7C 03 13 20 18 00 A4 03 10 01 20 00 AC 03 70 00 28}
 $rpc6 = {C0 03 50 21 18 00 08 00 13 01 20 00 74 04 70 00 28}
 $rpc7 = {8C 06 50 21 18 00 08 00 13 A1 20 00 C6 06 70 00 28}
 $def1 = "mimikatz"
 $def2 = "mimikatz" wide
condition: uint16(0) == 0x5a4d and (all of ($DRS*) or all of ($DRSW*)) and all of ($rpc*)  and not (any of ($def*))
}