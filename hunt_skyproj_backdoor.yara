rule hunt_skyproj_backdoor {
meta:
 author = "SBousseaden"
 date = "24-10-2020"
 reference = "https://twitter.com/SBousseaden/status/1320005809695264769"
 hash = "9F64EC0C41623E5162E51D7631B1D29934B76984E9993083BDBDABFCCBA4D300"
 hash = "F48CC6F80A0783867D2F4F0E76A6B2C29D993A2D5072AA10319B48FC398D8B7A"
 hash = "7ac73f2e5ea0ca430cf21738d3854b8a5b6a25ae4a85d140fc7e96cb87f7e2ea"
strings:
 $s1 = "rundll32.exe" ascii wide
 $s2 = "data.enc" ascii wide
 $s3 = "data.bak" ascii wide
 $s4 = "did.dat" ascii wide
 $s5 = "config.xml" ascii wide 
 $s6 = "dfserv.exe" ascii wide
 $s7 = "ShellExecuteW" ascii wide
 $s8 = "Software\\temp" ascii wide
 $s9 = "getElementById" wide
 $s10 = "getElementsByTagNameNS" ascii wide
 $s11 = "TMSDOMNode5"
 $s12 = "schtasks /Create /f /XML" wide
 $s13 = "schtasks /Create /sc onstart /tr" wide
 $s14 = "/ru system /TN"  wide
 $s15 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted" wide
 $s16 = "<Command>Rundll32.exe</Command>" wide
 $s17 = "<Arguments>shell32.dll,Control_RunDLL" wide
 $s18 = "\\All Users\\Start Menu\\Programs\\\\Startup\\" wide
 $s19 = "Kaspersky Lab" ascii wide
condition: uint16(0) == 0x5a4d and 5 of them
}
