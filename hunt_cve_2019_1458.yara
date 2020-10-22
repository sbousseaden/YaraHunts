rule cve_2019_1458 {
meta:
 author = "SBousseaden"
 reference = "https://github.com/unamer/CVE-2019-1458"
strings:
 $s1 = "RtlGetVersion"
 $s2 = {45 33 C9 BA 03 80 00 00 33 C9}	
 $s3 = "SploitWnd"
 $s4 = "CreateWindowExW"
 $s5 = "GetKeyboardState"
 $s6 = "SetKeyboardState"
 $s7 = "SetWindowLongPtrW"
 $s9 = "SetClassLongPtrW"
 $s10 = "DestroyWindow"
 $s11 = "CreateProcess"
 $s12 = {4C 8B D1 8B 05 ?? ?? ?? 00 0F 05 C3}
 $s13 = {80 10 00 00 09 10}
 $s14 = "NtUserMessageCall"
 $s15 = "HMValidateHandle"
 $s16 = "IsMenu"
condition: uint16(0) == 0x5a4d and all of them
}
