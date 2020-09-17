rule ZerloLogon_Mimikatz {
meta:
 description = "Hunting rule for Mimikatz Implementation of ZeroLogon PrivEsc Exploit"
 author = "SBousseaden"
 date = "17/07/2020"
 reference1 = "https://github.com/SecuraBV/CVE-2020-1472"
 reference2 = "https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20200916"
strings:
 $rch1 = "NetrServerReqChallenge"
 $rch2 = "NetrServerReqChallenge" wide
 $auth1 = "NetrServerAuthenticate2"
 $auth2 = "NetrServerAuthenticate2" wide
 $pwd1 = "NetrServerPasswordSet2"
 $pwd2 = "NetrServerPasswordSet2" wide
 $rpc1 = {78 56 34 12 34 12 CD AB EF 00 01 23 45 67 CF FB}
 $rpc2 = {00 00 12 08 25 5C 11 08 25 5C 11 00 08 00 1D 00 08 00 02 5B 15 00 08 00 4C 00 F4 FF 5C 5B 11 04 F4 FF 11 08 08 5C 11 00 02 00 15 03 0C 00 4C 00 E4 FF 08 5B 11 04 F4 FF 11 00 08 00 1D 01 00 02 05 5B 15 03 04 02 4C 00 F4 FF 08 5B 11 04 0C 00 1D 00 10 00 4C 00 BE FF 5C 5B 15 00 10 00 4C 00 F0 FF 5C 5B 00}
 $rpc3 = {00 48 00 00 00 00 04 00 28 00 31 08 00 00 00 5C 3C 00 44 00 46 05 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 0A 01 10 00 14 00 12 21 18 00 14 00 70 00 20 00 08 00 00 48 00 00 00 00 0F 00 40 00 31 08 00 00 00 5C 5E 00 60 00 46 08 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 14 00 12 21 28 00 14 00 58 01 30 00 08 00 70 00 38 00 08 00 00 48 00 00 00 00 1E 00 40 00 31 08 00 00 00 5C 8E 02 58 00 46 08 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 2A 00 12 41 28 00 2A 00 0A 01 30 00 42 00 70 00 38 00 08 00 00 48 00 00 00 00 2A 00 48 00 31 08 00 00 00 5C 56 00 40 01 46 09 0A 01 00 00 00 00 00 00 00 00 0B 00 00 00 02 00 0B 01 08 00 08 00 48 00 10 00 0D 00 0B 01 18 00 08 00 0A 01 20 00 2A 00 12 41 28 00 2A 00 12 41 30 00 5A 00 12 41 38 00 5A 00 70 00 40 00 08 00 00 00}
condition: uint16(0) == 0x5a4d and (1 of ($rch*) and 1 of ($auth*) and 1 of ($pwd*)) and 2 of ($rpc*) 
}