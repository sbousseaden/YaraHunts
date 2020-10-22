rule hunt_slub_backdoor {
meta:
 author = "SBousseaden"
 date = "22-10-2020"
 reference = "https://documents.trendmicro.com/assets/white_papers/wp-operation-earth-kitsune.pdf"
 hash = "93bb93d87cedb0a99976c18a37d65f816dc904942a0fb39cc177d49372ed54e5"
 hash = "59e4510b7b15011d67eb2f80484589f7211e67756906a87ce466a7bb68f2095b"
 hash = "c7788c015244e12e4c8cc69a2b1344d589284c84102c2f1871bbb4f4c32c2936"
 hash = "6678a5964db74d477b39bd0a8c18adf02844bed8b112c7bcca6984032918bdfb"
strings:
 $s1 = "file_infos" ascii wide
 $s2 = "%ws\\%u_cmd_out.tmp" ascii wide
 $s3 = "%ws\\%u_cmd_out.zip" ascii wide
 $s4 = "[was netstat]" ascii wide
 $s5 = {63 3A 5C 77 6F 72 6B 2E 76 63 70 6B 67 5C 69 6E 73 74 61 6C 6C 65 64 5C 78 36 34 2D 77 69 6E 64 6F 77 73 2D 73 74 61 74 69 63 5C}
 $s6 = "LoadFileToMemory" ascii wide
 $s7 = "setStartupExec" ascii wide
 $s8 = "%04u-%02u-%02u %02u:%02u:%02u" ascii wide
 $s9 = "goto del_one" ascii wide
 $s10 = "goto del_two" ascii wide
condition: uint16(0) == 0x5a4d and 3 of them
}